# OBP Tier-1 — Account "Views" / Field-Level Delegation + Entitlement Requests (prefix `VEW`)

Derived from `docs/openbankproject/OBP_GAP_ANALYSIS.md` — Tier-1 "Account **Views** /
field-level delegation" (~2 tickets) + "**Entitlement-request workflow**" (~1 ticket),
expanded to 5 implementable tickets. Open Bank Project's signature primitive is the
**View**: a named, field-level data-sharing delegation (`owner` / `accountant` / `auditor`
/ `public` / custom) that grants a *subset* of a financial resource's fields
(`can_see_balance`, `can_see_transaction_amount`, `can_see_counterparty`,
`can_add_comment`, …) to another party — including an **unauthenticated public view**.

testlogon already owns a *module-coarse* delegation primitive
(`app/services/delegates.py`): a creator grants a delegate a set of whole-feature
permissions (`chat_read`, `feed_post`, …) with pending/active acceptance, a per-creator
limit, presets, and an audit log. **VEW generalizes that grant/revoke pattern down to
per-field granularity over an arbitrary financial resource**, adds a field-projection
filter applied to reads, an unauthenticated public-view path, and a self-service
**entitlement-request → admin-approval** queue that grants roles through the *planned* STU
ACL (`docs/suitecrm/specs/STU-002.md` / `STU-003.md`).

The gap analysis is explicit that this is net-new: *"Views (named field-level access
delegation: owner/accountant/auditor/public; `can_see_*` per-field grants) — MISSING;
OBP's signature; closest is module-coarse `delegates.py` — net-new"* and *"Entitlement
REQUESTS (user requests role → admin approves) — MISSING; no self-service request/approval
queue"* (`OBP_GAP_ANALYSIS.md` §A, §C).

---

## Cross-cutting constraints (apply to every VEW ticket)

1. **Additive + flag-gated, default-OFF.** Two master flags in `app/core/settings.py`,
   both `os.environ.get("...", "false").lower() == "true"` (the canonical default-OFF idiom
   matching `inventory_reservations_enabled`, `app/core/settings.py:839`):
   - `account_views_enabled` (env `ACCOUNT_VIEWS_ENABLED`) — gates VEW-001..VEW-003.
   - `entitlement_requests_enabled` (env `ENTITLEMENT_REQUESTS_ENABLED`) — gates VEW-004.
   With a flag OFF the router is **not registered** in `app/main.py` (paths return 404, not
   403 — same conditional-import pattern STU-002 §6.2 uses), and any service helper that
   could be called from an always-on path (e.g. a projection filter invoked from an
   existing read) short-circuits to a no-op / returns the resource unchanged. Flipping a
   flag OFF restores byte-for-byte prior behavior; DDB rows are retained.

2. **Reuse, never fork, the delegate grant/revoke pattern.** VEW-001/002 mirror
   `app/services/delegates.py` exactly: per-resource owner partition
   (`pk=RESOURCE#{resource_type}#{resource_id}`, cf. delegates' `pk=CREATOR#{creator_id}`),
   `sk=VIEWGRANT#{grantee_id}` rows (cf. `sk=DELEGATE#{delegate_id}`), pending/active status
   with `respond_to_invite`-style acceptance (`delegates.py:112`), a `by-grantee` GSI
   mirroring delegates' `GSI1` (`delegates.py:97-98`, `list_managed_creators`
   `delegates.py:216`), a per-owner grant limit (`_enforce_delegate_limit`,
   `delegates.py:370`), `_require_not_self` / `_require_not_already_*` guards
   (`delegates.py:359-367`), and an in-table audit log (`_write_audit`,
   `delegates.py:386`). The **net-new** dimension vs. delegates is field-level granularity:
   a per-view boolean grant-map over the resource's fields, plus a projection filter.

3. **Audit every mutation** through the canonical
   `app/services/alerts.py:644` `audit_event(event, user_sub, request=None, **fields)` (the
   single audit write-path; fields flatten to top-level on the `T.alerts` item; imported by
   `app/routers/admin_roles.py:19`, `app/auth/policy.py:10`). Event names namespaced
   `account_view.*` and `entitlement_request.*`. VEW also keeps the delegates-style
   in-table `AUDIT#{ts}#{event_id}` rows for resource-scoped history reads.

4. **Roles / scopes / approval gates** use the existing primitives only:
   - `app/auth/roles.py:8` `Role` (`ROOT`/`ADMIN`/`USER`); `AdminScope` (4 values,
     `:14-19`); `AdminProfile` (`:34`).
   - `app/auth/policy.py` deps: `require_root` (`:63`), `require_admin_or_root` (`:67`),
     `require_admin_or_root_csrf` (`:100`), `require_admin_scope(scope)` (`:122`),
     `enforce_cookie_csrf` (`:71`), `require_self_or_admin` (`:172`).
   - User-facing cookie endpoints use `Depends(require_ui_session)`
     (`app/services/sessions.py`, per `app/routers/admin_roles.py:21`) and send
     `x-csrf-token` on non-GET; ROOT/ADMIN admin endpoints use the `policy.py` deps.

5. **Entitlement grants ride the PLANNED STU ACL** (`docs/suitecrm/specs/STU-002.md`,
   `STU-003.md`). VEW-004 is the *request/approval queue* mirroring the
   KYC-case-assignment approval pattern (`app/services/kyc_case_assignment.py`:
   `claim`/`manual_reassign` `:438-498`, `_write_audit_event` `:606`,
   `get_assignment_history` `:635`, scan-active loop with `LastEvaluatedKey`
   `:136-157`); on **approve** it calls `crm_acl.assign_role_to_user(...)` (STU-002 §4.1,
   `assign_role_to_user(actor_sub, role_id, user_sub)`) — *adapter-gated*: if the STU ACL
   service is not present (`account_views`/`entitlement_requests` may ship before STU), the
   grant step is wrapped in `try/except ImportError` and the request is still marked
   `approved` with a `grant_pending_acl=true` marker, never raising. Never invents its own
   role store.

6. **SECOPS-007 dev/prod parity.** All persistence goes through `T.*` `_FloatSafeTable`
   handles (`app/core/tables.py`) — DynamoDB Local (port 8001) in dev, real DynamoDB in
   prod, **no `if S.dev_mode` branch** in any VEW service. Numeric GSI sort keys
   (`created_at`, `assigned_at`) MUST declare `attr_types={"...": "N"}` in
   `scripts/local-ddb-init.py` (CLAUDE.md "DynamoDB numeric GSI sort keys" gotcha). Any
   sparse-attribute query loops `LastEvaluatedKey` (CLAUDE.md "DDB FilterExpression doesn't
   reduce page size").

7. **Public-view signed token (VEW-002)** reuses the HMAC scheme already used for cart
   recovery / WS tokens: `app/core/crypto.py:35` `mint_ws_token` /
   `verify_ws_token` (`:44`, `hmac.compare_digest` constant-time, `:52`), with a
   dedicated secret resolver `account_view_public_secret` → `ui_access_token_secret`
   fallback (same fallback shape as `CART_RECOVERY_LINK_SECRET`, CLAUDE.md cart-recovery
   note). No predictable literal tokens.

8. **Pydantic** request/response models live in `app/models.py`; numeric timestamps use
   `app/core/time.py:2` `now_ts()` (integer Unix seconds). IDs are `uuid4().hex`
   (cf. `delegates.py:7`, `kyc_case_assignment.py` `uuid.uuid4().hex[:10]` `:618`).

9. **Tests** are hermetic/offline: `moto` in-memory tables bound to the frozen `T.*`
   handles via `object.__setattr__`, frozen `S` flags flipped via `object.__setattr__`,
   route handlers called directly on a fresh `asyncio.new_event_loop()`, `audit_event`
   patched at the service module. **No FastAPI `TestClient`** (broken in this project),
   **no real AWS**. Pattern: `tests/test_gap_0220_0221_ssh_stored_key.py`,
   `tests/test_stu_002_acl_roles.py` (planned).

---

### VEW-001: Account **View** entity — DDB model, field-grant catalog, view CRUD

**Type:** Feature · **Priority:** P1 · **Estimate:** 3 d · **Flag:** `account_views_enabled`

### Description

Introduce the **View** entity: a named, owner-defined view over a financial resource that
declares a per-field boolean grant-map. A view is a *template of visibility* — it does not
yet grant anyone access (that is VEW-002); it defines *which fields a holder of this view
may see/do*. This is the field-level generalization of a `delegates.py` permission preset
(`PERMISSION_PRESETS`, `delegates.py:30`): where delegates have one flat
`VALID_PERMISSIONS` set of whole-feature actions (`delegates.py:20-28`), a View carries a
`grants` map over the **resource's individual fields**.

**Field-grant catalog (the View analogue of `delegates.VALID_PERMISSIONS`).** Define
`VIEW_FIELD_GRANTS: set[str]` in the new `app/services/account_views.py`, modeled on OBP's
`can_see_*` / `can_add_*` vocabulary and on testlogon's actual financial-resource shape
(per-user wallet/ledger, `app/services/billing_shared.py`; payout destinations,
`app/services/creator_payouts.py`):
- read grants — `can_see_balance`, `can_see_available_balance`, `can_see_transaction_list`,
  `can_see_transaction_amount`, `can_see_transaction_description`, `can_see_counterparty`,
  `can_see_counterparty_name`, `can_see_owners`, `can_see_account_label`,
  `can_see_payout_destination_masked`.
- write/enrichment grants (OBP transaction-metadata parity, `OBP_GAP_ANALYSIS.md` §A) —
  `can_add_comment`, `can_add_tag`, `can_add_narrative`, `can_delete_comment`.
A `VIEW_PRESETS` dict (mirrors `PERMISSION_PRESETS`, `delegates.py:30`) seeds the four
canonical OBP views: `owner` (all grants), `accountant` (balance + amounts + counterparty,
no enrichment), `auditor` (read-only: all `can_see_*`, no `can_add_*`/`can_delete_*`),
`public` (a minimal safe subset — label + masked balance only; this is the template the
public path in VEW-002 exposes). `_detect_preset` (cf. `delegates.py:378`) labels a
grant-map that exactly matches a preset.

**DDB model** — new table `account_views` (single-table, owner-partitioned, mirrors the
`delegates` table layout). Add the `TableDef` to `scripts/local-ddb-init.py` and the handle
`T.account_views` to `app/core/tables.py`:
- **View definition row** — `pk=RESOURCE#{resource_type}#{resource_id}`,
  `sk=VIEW#{view_id}`. Attributes: `view_id` (`uuid4().hex`), `resource_type`
  (`"wallet"` / `"ledger_account"` / `"payout_destination"` — an allowlist), `resource_id`,
  `owner_sub`, `name`, `description`, `is_system_alias` (bool; the auto-provisioned
  `owner` view), `grants` (Map of `{field: bool}` restricted to `VIEW_FIELD_GRANTS`),
  `preset` (str | None), `metadata_visibility` (`"counterparty_blur"` flag for the
  blurring OBP supports), `created_at` (N), `updated_at` (N), `created_by_sub`.
- A `by-owner` GSI (`GSI1PK=OWNER#{owner_sub}`, `GSI1SK=created_at` N — `attr_types={"GSI1SK":"N"}`,
  per constraint #6) so an owner can list every view they defined across resources (cf.
  delegates `GSI1`, `list_managed_creators` `delegates.py:216`).

**Resource-ownership guard.** A pluggable `_assert_owns_resource(owner_sub, resource_type,
resource_id)` validates the caller actually owns the underlying financial resource before
creating a view (e.g. wallet resource_id == owner_sub for the per-user wallet model;
payout-destination ownership via `creator_payouts` `Key={user_id, sk}`). Unknown
`resource_type` → `HTTPException(400)`; not-owned → `403`.

**Service — `app/services/account_views.py`** (signatures mirror `delegates.py` public
API):
- `create_view(owner_sub, resource_type, resource_id, name, grants, *, preset=None,
  description="") -> dict` — validates grants ⊆ `VIEW_FIELD_GRANTS`
  (`_validate_grants`, cf. `_validate_permissions` `delegates.py:353`), asserts ownership,
  enforces a per-resource view limit (`_enforce_view_limit`, cf. `delegates.py:370`),
  `put_item`s the row, `audit_event("account_view.created", owner_sub, ...)` +
  in-table `_write_audit`.
- `get_view(resource_type, resource_id, view_id) -> dict | None`.
- `list_views(resource_type, resource_id) -> list[dict]` — `Key("pk").eq(...) &
  Key("sk").begins_with("VIEW#")` (cf. `list_delegates` `delegates.py:207`).
- `list_views_by_owner(owner_sub) -> list[dict]` — `by-owner` GSI query.
- `update_view(owner_sub, resource_type, resource_id, view_id, *, name=None,
  grants=None, description=None) -> dict` — `update_item` of provided fields only,
  re-validates grants, recomputes `preset`, `account_view.updated`.
- `delete_view(owner_sub, resource_type, resource_id, view_id) -> None` — also cascade-
  deletes any VIEWGRANT rows for that view (VEW-002), `account_view.deleted`.
- `ensure_owner_view(owner_sub, resource_type, resource_id) -> dict` — idempotent
  auto-provision of the `owner` system view (`is_system_alias=True`); the `owner` view's
  grant-map is the full `VIEW_FIELD_GRANTS` and cannot be edited/deleted (raises 409 on
  attempted mutation — OBP parity).

**Router — `app/routers/account_views.py`** (prefix `/ui/views`, registered in
`app/main.py` only inside `if S.account_views_enabled:`). All user endpoints
`Depends(require_ui_session)` + CSRF on non-GET:
```
GET    /ui/views/grant-catalog                                  → field catalog + presets (any auth)
POST   /ui/views/{resource_type}/{resource_id}                  → create_view
GET    /ui/views/{resource_type}/{resource_id}                  → list_views (owner only)
GET    /ui/views/{resource_type}/{resource_id}/{view_id}        → get_view
PATCH  /ui/views/{resource_type}/{resource_id}/{view_id}        → update_view
DELETE /ui/views/{resource_type}/{resource_id}/{view_id}        → delete_view
```
Route ordering: literal `/grant-catalog` is declared **before** the dynamic
`/{resource_type}/...` routes (FastAPI matches in declaration order — same constraint as
STU-002 §4.3 `/my-permissions` ordering).

**Pydantic** (`app/models.py`): `ViewGrantsMatrix` (one bool per `VIEW_FIELD_GRANTS`
field, all default `False`), `ViewCreateIn` (`name`, `grants: ViewGrantsMatrix`,
`preset: str | None`, `description`), `ViewUpdateIn` (all optional), `ViewOut`
(full row projection), `ViewGrantCatalogOut` (`fields: list[str]`,
`presets: list[{key,label,grants}]`).

### Acceptance Criteria
- With `ACCOUNT_VIEWS_ENABLED=0`, `/ui/views/*` returns 404 and `T.account_views` is never
  touched; flipping ON registers the router with no other behavior change.
- `create_view` rejects a grant key not in `VIEW_FIELD_GRANTS` with `400`; rejects a
  resource the caller does not own with `403`; rejects unknown `resource_type` with `400`;
  enforces the per-resource view limit.
- The four `VIEW_PRESETS` (`owner`/`accountant`/`auditor`/`public`) are returned by
  `GET /grant-catalog`; `auditor` preset contains every `can_see_*` and zero
  `can_add_*`/`can_delete_*`; `public` preset is the minimal label+masked-balance subset.
- `ensure_owner_view` is idempotent and the resulting `owner` view (`is_system_alias`) is
  non-editable / non-deletable (409).
- Every mutating call emits the matching `account_view.*` `audit_event` and an in-table
  `AUDIT#` row; `delete_view` cascade-removes VIEWGRANT rows.
- `by-owner` GSI sort key `created_at` declared `attr_types={"GSI1SK":"N"}` in
  `local-ddb-init.py`; no `ValidationException` on `list_views_by_owner`.
- `tests/test_vew_001_views.py` covers: create/validate/list/update/delete, preset
  detection, ownership guard, limit, owner-view immutability, flag-off no-op — moto-bound
  `T.account_views`, `audit_event` patched.

### Dependencies
- **None hard.** New table + service + router + flag are self-contained. Reuses
  `delegates.py` patterns (#2), `alerts.audit_event` (#3), `now_ts` (#8) — all present.

---

### VEW-002: Grant / revoke a View to a grantee + **unauthenticated public view**

**Type:** Feature · **Priority:** P1 · **Estimate:** 3 d · **Flag:** `account_views_enabled`

### Description

Make a View *grantable*: the owner grants a named view (VEW-001) to another user, with the
same pending/active acceptance, GSI-indexed reverse lookup, and audit trail as
`delegates.py` — plus a **public view** path that exposes the view's granted field-subset
**without authentication** via a signed link.

**Authenticated grant — VIEWGRANT rows** on the `account_views` table (mirrors the
DELEGATE rows in `delegates.py:81-100`):
- `pk=RESOURCE#{resource_type}#{resource_id}`, `sk=VIEWGRANT#{grantee_sub}#{view_id}`
  (a grantee may hold multiple distinct views over one resource). Attributes:
  `grant_id`, `view_id`, `grantee_sub`, `owner_sub`, `status`
  (`pending`/`active`/`revoked` — cf. `delegates.py:79`), `invited_at`, `accepted_at`,
  `updated_at`, plus `GSI1PK=GRANTEE#{grantee_sub}`, `GSI1SK=accepted_at` (N) for the
  reverse "views shared **with** me" lookup (exact analogue of delegates' `GSI1` +
  `list_managed_creators`, `delegates.py:97-98,216`).
- `respond_to_view_grant(owner_sub, resource_type, resource_id, grantee_sub, view_id,
  accept)` mirrors `respond_to_invite` (`delegates.py:112`): accept → status `active` +
  `accepted_at`; decline → delete row. A per-resource `require_acceptance` setting
  (cf. `get_creator_settings` `delegates.py:273`) lets the owner auto-activate.

**Service additions to `app/services/account_views.py`:**
- `grant_view(owner_sub, resource_type, resource_id, view_id, grantee_sub) -> dict` —
  `_require_not_self` (cf. `delegates.py:359`), `_require_not_already_granted` (cf.
  `delegates.py:364`), view must exist (404), `put_item`, `audit_event("account_view.granted",
  ...)`. Returns the (possibly pending) grant.
- `revoke_view_grant(owner_sub, resource_type, resource_id, view_id, grantee_sub) -> None`
  — sets `status=revoked` (soft, for audit) then deletes the row (cf. `revoke_delegate`
  `delegates.py:196`); cache-invalidate; `account_view.revoked`.
- `list_grants_for_resource(resource_type, resource_id) -> list[dict]`,
  `list_views_shared_with_me(grantee_sub) -> list[dict]` (GSI1 query, active only — cf.
  `list_managed_creators`).
- `resolve_active_grant(grantee_sub, resource_type, resource_id, view_id) -> dict | None` —
  the authorization primitive consumed by VEW-003's read path: returns the active grant +
  its View's `grants` map, or None.

**Public view — unauthenticated signed-link path.** OBP's `public` view is readable by
anyone with the link.
- `create_public_view_link(owner_sub, resource_type, resource_id, view_id, *,
  ttl_days=None) -> {url, token, expires_at}` — the view must have `preset=="public"` OR
  be explicitly marked `is_public=True` (owner opt-in; never auto-public). Mints an
  HMAC-signed, time-limited token over `resource_type|resource_id|view_id|exp` using the
  `mint_ws_token`-style scheme (`app/core/crypto.py:35`, secret resolver
  `account_view_public_secret` → `ui_access_token_secret` fallback — constraint #7).
  Returns `{S.public_base_url}/ui/views/public/{token}`.
- `resolve_public_view(token) -> {resource_type, resource_id, view_id, grants}` — verifies
  the token with `verify_ws_token`-style constant-time compare (`crypto.py:44-52`); expired
  / tampered / wrong-resource → `HTTPException(400/403)`. Public links can be revoked by the
  owner (a `PUBLIC_REVOKED#{jti}` marker row + conditional check, mirroring the cart-recovery
  one-time-use marker, CLAUDE.md cart-recovery note).

**Router additions** (`app/routers/account_views.py`):
```
POST   /ui/views/{resource_type}/{resource_id}/{view_id}/grants            → grant_view        (owner)
GET    /ui/views/{resource_type}/{resource_id}/{view_id}/grants            → list grants        (owner)
DELETE /ui/views/{resource_type}/{resource_id}/{view_id}/grants/{grantee}  → revoke_view_grant  (owner)
POST   /ui/views/{resource_type}/{resource_id}/{view_id}/grants/{grantee}/respond → respond     (grantee, CSRF)
GET    /ui/views/shared-with-me                                            → list_views_shared_with_me
POST   /ui/views/{resource_type}/{resource_id}/{view_id}/public-link       → create_public_view_link (owner)
DELETE /ui/views/public/{token}                                            → revoke public link      (owner)
```
Plus a **separate unauthenticated** router (no `require_ui_session`, registered alongside
the public cart-recovery / public-event routers in `app/main.py`):
```
GET    /ui/views/public/{token}   → resolve_public_view → VEW-003 projected resource (no auth)
```
`/shared-with-me` and `/public/*` literal segments declared **before** the dynamic
`/{resource_type}/...` routes.

**Pydantic** (`app/models.py`): `ViewGrantIn` (`grantee_sub`), `ViewGrantOut`
(`grant_id`, `view_id`, `grantee_sub`, `status`, `invited_at`, `accepted_at`),
`PublicViewLinkIn` (`ttl_days: int | None`), `PublicViewLinkOut`
(`url`, `token`, `expires_at`).

### Acceptance Criteria
- `grant_view` rejects self-grant (`400`), duplicate grant (`409`), and a missing view
  (`404`); creates a `pending` row when `require_acceptance` is on, `active` otherwise.
- `respond_to_view_grant(accept=True)` flips to `active` + sets `accepted_at`;
  `accept=False` deletes the row. Only `pending` rows are respondable (`400` otherwise) —
  mirrors `delegates.respond_to_invite`.
- `revoke_view_grant` removes the grant and the grantee immediately loses access via
  `resolve_active_grant` (returns None).
- `list_views_shared_with_me` returns only `active` grants for the grantee via the GSI1
  reverse lookup; `GSI1SK=accepted_at` declared `N`.
- A public link is mintable **only** for a `public`-preset / `is_public` view; the token is
  HMAC-signed (not a predictable literal), verified constant-time, honors expiry, and is
  revocable; a tampered/expired/wrong-resource token is rejected `400/403`.
- `GET /ui/views/public/{token}` requires **no** session/Bearer auth and returns the
  VEW-003-projected resource.
- Every grant/revoke/public-link op emits the matching `account_view.*` `audit_event`.
- `tests/test_vew_002_grants.py`: grant/accept/decline/revoke lifecycle, GSI reverse
  lookup, self/duplicate guards, public-link mint+verify+expiry+revoke+tamper (pure HMAC),
  flag-off 404 — moto-bound table, `audit_event` patched, no real crypto network.

### Dependencies
- **VEW-001** (View entity, `account_views` table/service/flag, `resolve`-able
  `grants` map). Reuses `delegates.py` grant/revoke/accept/GSI patterns (#2),
  `crypto.mint_ws_token`/`verify_ws_token` + secret-fallback (#7), `audit_event` (#3).

---

### VEW-003: Field-level **projection enforcement** when reading through a View

**Type:** Feature · **Priority:** P1 · **Estimate:** 2 d · **Flag:** `account_views_enabled`

### Description

The enforcement layer: when a resource is read **through a view** (an authenticated grantee
or the public-link path), return **only the fields the view's `grants` map permits** — a
deterministic projector/filter applied to the assembled resource dict. This is the piece
that makes Views meaningful; without it a grant is just metadata. It is the field-level
analogue of `delegates.check_delegate_permission` / `require_delegate_permission`
(`delegates.py:243-270`), but instead of gating a whole action it **shapes the response
body**.

**Field-map registry.** For each `resource_type` define, in `app/services/account_views.py`,
a pure `FIELD_TO_GRANT: dict[resource_type, dict[response_field, grant_key]]` mapping each
serializable response field to the `VIEW_FIELD_GRANTS` key that unlocks it. Example for
`wallet`: `{"balance_cents": "can_see_balance", "available_cents":
"can_see_available_balance", "label": "can_see_account_label", ...}`; for a transaction
row inside `transaction_list`: `{"amount_cents": "can_see_transaction_amount",
"description": "can_see_transaction_description", "counterparty": "can_see_counterparty",
"counterparty_name": "can_see_counterparty_name"}`. Fields **not** in the map are always
stripped under a view (deny-by-default — the safe direction); the owner's full-fidelity
read path (no view) is unaffected.

**The projector — pure, deterministic, side-effect-free:**
```python
def project_resource(resource: dict, grants: dict[str, bool], resource_type: str) -> dict
```
- Walks `FIELD_TO_GRANT[resource_type]`; keeps a field iff its grant key is truthy in
  `grants`; drops every unmapped field.
- Recurses into list-valued sub-resources (e.g. each entry of `transaction_list`) applying
  the sub-resource field map; if `can_see_transaction_list` is false the whole list key is
  dropped.
- Honors `metadata_visibility=="counterparty_blur"` (VEW-001): when set, a present
  `counterparty`/`counterparty_name` is **masked** (e.g. `"••••"`) rather than dropped —
  OBP's blurring behavior.
- Never raises; an unknown `resource_type` → returns `{}` (deny-all, fail-closed). Pure, so
  it is trivially unit-testable with no I/O.

**Read endpoint — `GET /ui/views/{resource_type}/{resource_id}/{view_id}/data`**
(`account_views.py`, `require_ui_session`):
1. `resolve_active_grant(caller.sub, resource_type, resource_id, view_id)` (VEW-002) — owner
   is implicitly granted the `owner` view (full grants); else 403 if no active grant.
2. Assemble the **full** resource dict via the existing builders (e.g. wallet/balance from
   `app/services/billing_shared.py` / `billing.py` `wallet`/`balance` endpoints; payout
   destination masked via `creator_payouts._payout_to_dict` `creator_payouts.py:66`).
   VEW does NOT re-implement resource assembly — it calls the existing read path, then
   projects.
3. `return project_resource(full, grant.view.grants, resource_type)` + a `_view`
   provenance block (`{view_id, view_name, granted_fields: [...]}`).
4. `audit_event("account_view.read", caller.sub, resource_type=..., resource_id=...,
   view_id=...)` (read auditing — OBP logs view access).

**Public path wiring (VEW-002).** `GET /ui/views/public/{token}` resolves the public
view, assembles the resource, and returns `project_resource(...)` with the public view's
(minimal) grants — the **same projector**, so the public response can never leak a field the
public view doesn't grant.

### Acceptance Criteria
- `project_resource` is pure (no DDB/network); given the same `(resource, grants,
  resource_type)` it returns the same dict; an unmapped field is always absent; an unknown
  `resource_type` returns `{}`.
- A grantee holding the `accountant` view sees `balance`/`amount`/`counterparty` but **not**
  enrichment-only or unmapped fields; an `auditor` view sees all `can_see_*` fields and no
  write affordances; the `public` view's projection is the minimal label+masked-balance
  subset.
- `metadata_visibility=="counterparty_blur"` masks (not drops) the counterparty fields when
  those grants are on.
- Reading with no active grant (and not the owner) → `403`; the owner reading their own
  resource without a view is unchanged (full fidelity).
- The public-link read returns exactly the public view's projected subset and **cannot**
  expose a non-granted field (regression: assert a field outside the public grant-map is
  absent).
- Each authenticated view-read emits `account_view.read`.
- `tests/test_vew_003_projection.py`: pure-projector matrix over all four presets +
  blur + unknown-type fail-closed + recursion into `transaction_list`; one end-to-end
  handler test (grantee read → projected body) and one public-path test — moto-bound,
  resource builder stubbed, `audit_event` patched.

### Dependencies
- **VEW-001** (`grants` map, `metadata_visibility`), **VEW-002**
  (`resolve_active_grant`, public-link resolution). Calls existing resource read paths
  (`billing_shared.py`, `creator_payouts.py`) read-only; never forks them.

---

### VEW-004: **Entitlement-request workflow** — self-service request → admin approval queue → STU-ACL grant

**Type:** Feature · **Priority:** P1 · **Estimate:** 3 d · **Flag:** `entitlement_requests_enabled`

### Description

The gap analysis flags *"Entitlement REQUESTS (user requests role → admin approves) —
MISSING; no self-service request/approval queue"* (`OBP_GAP_ANALYSIS.md` §C). VEW-004 adds
exactly that: a user **requests** a role/entitlement, the request lands in an **admin
approval queue** with claim/approve/reject lifecycle and full audit, and on approval the
grant is applied through the **planned STU ACL** (`STU-002`/`STU-003`). The lifecycle
machine and queue mechanics mirror `app/services/kyc_case_assignment.py` (the canonical
admin-approval-queue pattern in this codebase) and the role-audit shape of
`app/routers/admin_roles.py`.

**DDB model** — new table `entitlement_requests` (single-table). `TableDef` in
`scripts/local-ddb-init.py`; handle `T.entitlement_requests` in `app/core/tables.py`:
- **Request row** — `pk=ENTREQ#{request_id}`, `sk=META`. Attributes: `request_id`
  (`uuid4().hex`), `requester_sub`, `entitlement_kind` (`"acl_role"` | `"admin_scope"` —
  allowlist), `target_ref` (the `role_id` for STU ACL, or an `AdminScope` value),
  `justification` (free text), `status` (`pending`/`under_review`/`approved`/`rejected`/
  `cancelled` — cf. KYC statuses `kyc_case_assignment.py:138`), `claimed_by_sub`,
  `claimed_at`, `decided_by_sub`, `decided_at`, `decision_reason`, `grant_pending_acl`
  (bool, set when the STU ACL service is absent at approval — constraint #5),
  `created_at` (N), `updated_at` (N).
  GSIs (numeric SKs `attr_types` per #6): `by-status` (`GSI1PK=STATUS#{status}`,
  `GSI1SK=created_at`) for the admin queue (cf. KYC `gsi_status_pk` queue,
  `kyc_case_assignment.py:146`); `by-requester` (`GSI2PK=REQUESTER#{requester_sub}`,
  `GSI2SK=created_at`) for "my requests".
- **Audit rows** — `pk=ENTREQ#{request_id}`, `sk=AUDIT#{ts:013d}#{event_id}` (cf.
  `kyc_case_assignment._write_audit_event` `:606`, delegates `_write_audit` `:386`),
  read newest-first by `get_request_history` (cf. `get_assignment_history` `:635`).

**Service — `app/services/entitlement_requests.py`:**
- `create_request(requester_sub, entitlement_kind, target_ref, justification) -> dict` —
  validates `entitlement_kind`/`target_ref` (for `acl_role`, target role must exist —
  `try` `crm_acl.get_acl_role`, adapter-gated #5); rejects a duplicate **open** request for
  the same `(requester, kind, target)` (`409`); `put_item` `pending`;
  `audit_event("entitlement_request.created", requester_sub, ...)` + in-table audit row.
- `list_queue(status="pending", *, cursor=None, limit=50) -> dict` — `by-status` GSI query,
  newest-first, `LastEvaluatedKey`-looped (#6); admin queue.
- `list_my_requests(requester_sub) -> list[dict]` — `by-requester` GSI.
- `get_request(request_id) -> dict` (404 if absent).
- `claim_request(request_id, admin_sub) -> dict` — compare-and-swap `pending → under_review`
  with `ConditionExpression` on current status + `claimed_by_sub` (mirrors KYC `claim`
  conflict guard, `kyc_case_assignment.py:478`; 409 if already claimed by another admin).
- `approve_request(request_id, admin_sub, *, reason="") -> dict` — transitions to
  `approved`, then **applies the grant through STU ACL**:
  `crm_acl.assign_role_to_user(admin_sub, target_ref, requester_sub)` for `acl_role`
  (STU-002 §4.1). Adapter-gated: `try: from app.services.crm_acl import assign_role_to_user`
  / `except ImportError:` → set `grant_pending_acl=True` and proceed (the request is still
  `approved`; the grant is replayable once STU lands). Never raises out of the approval.
  `audit_event("entitlement_request.approved", admin_sub, requester_sub=..., target_ref=...)`.
- `reject_request(request_id, admin_sub, reason) -> dict` → `rejected` + reason;
  `entitlement_request.rejected`.
- `cancel_request(request_id, requester_sub) -> dict` — requester self-cancels an open
  request (`cancelled`); `require_self` (only the requester).
- `get_request_history(request_id) -> list[dict]`.

**Router — `app/routers/entitlement_requests.py`** (registered in `app/main.py` only inside
`if S.entitlement_requests_enabled:`):
```
# user-facing (require_ui_session + CSRF on non-GET)
POST   /ui/entitlement-requests                         → create_request
GET    /ui/entitlement-requests/mine                    → list_my_requests
POST   /ui/entitlement-requests/{request_id}/cancel     → cancel_request (requester)

# admin queue (require_admin_or_root_csrf / require_root for approve)
GET    /ui/admin/entitlement-requests                   → list_queue (?status=)    [ADMIN/ROOT]
GET    /ui/admin/entitlement-requests/{request_id}      → get_request              [ADMIN/ROOT]
GET    /ui/admin/entitlement-requests/{request_id}/history → get_request_history   [ADMIN/ROOT]
POST   /ui/admin/entitlement-requests/{request_id}/claim   → claim_request         [ADMIN/ROOT]
POST   /ui/admin/entitlement-requests/{request_id}/approve → approve_request       [ROOT]
POST   /ui/admin/entitlement-requests/{request_id}/reject  → reject_request        [ADMIN/ROOT]
```
**Approve is ROOT-only** (`Depends(require_root)`, `app/auth/policy.py:63`) — same posture
as `admin_roles.grant_role` (`admin_roles.py:202`), since approval mints a privilege grant.
Claim/reject/queue are `require_admin_or_root` (`policy.py:67`). Literal `/mine` declared
before dynamic `/{request_id}`; the `/ui/admin/...` and `/ui/...` namespaces are distinct so
no path-capture collision.

**Pydantic** (`app/models.py`): `EntitlementRequestCreateIn`
(`entitlement_kind`, `target_ref`, `justification`), `EntitlementDecisionIn` (`reason`),
`EntitlementRequestOut` (full projection incl. `status`, `grant_pending_acl`),
`EntitlementQueueOut` (`requests: list[EntitlementRequestOut]`, `next_cursor: str | None`).

### Acceptance Criteria
- With `ENTITLEMENT_REQUESTS_ENABLED=0`, all `/ui/entitlement-requests*` and
  `/ui/admin/entitlement-requests*` routes return 404.
- `create_request` rejects an unknown `entitlement_kind`/`target_ref` (`400`) and a
  duplicate open request (`409`); writes a `pending` row + `entitlement_request.created`
  audit.
- `claim_request` is a CAS: a second admin claiming a now-`under_review` request gets `409`;
  status/claimer persisted.
- `approve_request` (ROOT only — ADMIN gets 403) transitions to `approved` and calls
  `crm_acl.assign_role_to_user(admin_sub, target_ref, requester_sub)` for `acl_role`; when
  the STU ACL module is absent it sets `grant_pending_acl=True`, still marks `approved`, and
  **does not raise**. Emits `entitlement_request.approved`.
- `reject_request` → `rejected` + reason + audit; `cancel_request` self-cancel restricted to
  the requester (`403` otherwise) and only on open requests.
- `list_queue` is `by-status` GSI-backed, newest-first, cursor-paginated, `LastEvaluatedKey`-
  looped; `by-requester` powers `/mine`; both numeric GSI SKs declared `attr_types` `N`.
- `get_request_history` returns the in-table audit rows newest-first.
- `tests/test_vew_004_entitlement_requests.py`: full lifecycle (create→claim→approve with
  ACL adapter stubbed AND absent→`grant_pending_acl`; reject; cancel; duplicate-409;
  claim-conflict-409; ROOT-only approve 403 for admin; queue pagination; flag-off 404) —
  moto-bound `T.entitlement_requests`, `crm_acl.assign_role_to_user` patched/absent,
  `audit_event` patched, handlers called directly.

### Dependencies
- **None hard for the queue itself** (table/service/router/flag self-contained). The
  approval **grant step soft-depends on the planned STU ACL** (`STU-002.md`
  `assign_role_to_user`; `STU-003.md` group propagation) — wired through an `ImportError`-
  guarded adapter so VEW-004 ships and functions before STU lands (constraint #5). Reuses
  the KYC approval-queue/CAS/audit pattern (`kyc_case_assignment.py`) and the role-audit
  posture of `admin_roles.py`.

---

### VEW-005: Tests, table init, docs, and flag wiring (consolidation)

**Type:** Chore/Test · **Priority:** P2 · **Estimate:** 2 d · **Flags:** both

### Description

Consolidation ticket: land the DDB table definitions, settings flags, `app/main.py`
registration blocks, and the cross-cutting / integration tests that span VEW-001..VEW-004,
so the feature is shippable end-to-end behind its two default-OFF flags.

**Table init (`scripts/local-ddb-init.py`).** Add `TableDef`s for `account_views`
(VEW-001/002) and `entitlement_requests` (VEW-004) with their GSIs, each numeric GSI sort
key declared in `attr_types` (`GSI1SK`/`GSI2SK` = `"N"`) per constraint #6 — guarding the
"DynamoDB numeric GSI sort keys" `ValidationException` gotcha. Wire both handles in
`app/core/tables.py` (`T.account_views`, `T.entitlement_requests`).

**Settings (`app/core/settings.py`).** Add `account_views_enabled`,
`entitlement_requests_enabled`, `account_view_public_secret`
(env `ACCOUNT_VIEW_PUBLIC_SECRET`, default `""` → falls back to `ui_access_token_secret`),
`account_view_public_link_ttl_days` (default 7), `account_views_max_per_resource`
(default 25), `entitlement_request_max_open_per_user` (default 10) — all via
`os.environ.get(...)`, default-OFF/safe (#1). Add the env keys to `.env.local.example`.

**Registration (`app/main.py`).** Two conditional-import blocks
(`if S.account_views_enabled:` → authed + public `account_views` routers;
`if S.entitlement_requests_enabled:` → `entitlement_requests` router), each mirroring the
existing optional-router include pattern (STU-002 §6.2). The public `account_views` router
is registered next to the other unauthenticated public routers (cart-recovery / public-event).

**Integration / cross-feature tests (`tests/test_vew_005_integration.py`):**
- **End-to-end View flow:** owner creates an `accountant` view (VEW-001) → grants it to Bob
  (VEW-002) → Bob accepts → Bob reads via `/data` and gets exactly the projected subset
  (VEW-003) → owner revokes → Bob's next read is `403`.
- **Public flow:** owner creates a `public` view → mints a public link → unauthenticated
  `GET /ui/views/public/{token}` returns the minimal projected subset → owner revokes link →
  next fetch `400/403`; assert no non-public field ever appears.
- **Entitlement flow:** Alice requests an `acl_role` (VEW-004) → admin claims → ROOT approves
  → `crm_acl.assign_role_to_user` invoked (stub) → request `approved`; and the
  ACL-absent branch sets `grant_pending_acl`.
- **Flag-matrix:** with both flags OFF, every VEW route returns 404 and the projector /
  resolve helpers are no-ops / fail-closed.
- **Audit coverage:** assert the expected `account_view.*` / `entitlement_request.*`
  `audit_event` names fire for each mutation.

**Docs.** Add a `docs/file-reference.md` entry for the new service/router/table files; add a
short "Account Views + Entitlement Requests" section to `docs/dynamodb.md` (the two table
schemas + GSIs) and a CLAUDE.md "Common gotchas" note summarizing the field-projection
fail-closed rule and the public-link signed-token reuse.

### Acceptance Criteria
- `just restart` recreates `account_views` + `entitlement_requests` with correct GSIs and no
  `ValidationException` on any list query.
- Both flags default OFF; with both ON the full end-to-end and public flows pass; with both
  OFF every VEW route is 404 and helpers are inert.
- `tests/test_vew_005_integration.py` passes offline/hermetic (moto, no `TestClient`, no real
  AWS); the four prior VEW test files plus this one constitute the suite.
- `.env.local.example`, `docs/file-reference.md`, `docs/dynamodb.md`, and the CLAUDE.md
  gotchas note are updated.

### Dependencies
- **VEW-001, VEW-002, VEW-003, VEW-004** (all four feature tickets land first; this ticket
  wires their tables/flags/registration and adds the spanning tests + docs).
