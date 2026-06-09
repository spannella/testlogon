# Party / CRM — Implementation Tickets

This backlog delivers **Phase 1 — Party / CRM (OFBiz Party Manager, application A)** of the full OFBiz commerce/ERP buildout (`docs/ofbiz-full-buildout-plan.md`). It introduces an OFBiz-style Party model (PERSON / PARTY_GROUP) with roles, party relationships, unified contact mechanisms (email / phone / postal), and B2B organization accounts — layered **additively and flag-gated** on top of the existing `contacts` (`app/routers/contacts.py`), `addresses` (`app/services/addresses.py`), and `profile`/`users` subsystems so that with the flag off the legacy contact and address surfaces are byte-for-byte unchanged. Everything is single-table DynamoDB, dev/prod parity (SECOPS-007), deterministic-id idempotent on write paths, and hermetically tested offline.

## Milestone 1 — Scaffolding & Data Model

### PTY-001: Party/CRM feature flag & settings keys
**Type:** Chore  
**Priority:** P0  
**Estimate:** 1 day

**Description**
- Add a default-off feature flag group to `app/core/settings.py` following the exact boolean-env pattern already used (e.g. `browser_ssh_terminal_enabled` at `app/core/settings.py:124`): `party_crm_enabled: bool = os.environ.get("PARTY_CRM_ENABLED", "0") not in ("0", "false", "False")`, plus sub-flags `party_crm_contacts_migration_enabled` and `party_crm_org_accounts_enabled`, all defaulting **off**.
- Add the table-name setting key alongside the existing `contacts_table_name` (`app/core/settings.py:498`) and `addresses_table_name` keys: `party_table_name: str = os.environ.get("DDB_PARTY_TABLE", "party")`.
- Document the flags in `.env.local.example` and the feature-flag table in `CLAUDE.md`.

**Acceptance Criteria**
- `S.party_crm_enabled` reads through the `S` singleton and defaults to `False` with no env set.
- No existing flag value or table name is changed.
- A pytest asserts all three new flags default off.

**Dependencies**
- None.

---

### PTY-002: Party single-table DynamoDB definition + handle
**Type:** Chore  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add the `party` single-table `TableDef` to `scripts/local-ddb-init.py` next to the existing `addresses`/`Contacts` defs (`scripts/local-ddb-init.py:98`, `:691`), using `_resolve_table_name(S.party_table_name, "party")`, `PK`/`SK` keys, and GSIs:
  - `GSI1` (`GSI1PK` / `GSI1SK`) — role/type lookup (e.g. `ROLE#ORG_ADMIN`, `TYPE#PARTY_GROUP`).
  - `GSI2` (`GSI2PK` / `GSI2SK`) — contact-mech reverse lookup (e.g. `EMAIL#alice@x.com` → party).
  - `GSI3` (`GSI3PK` / `GSI3SK`) — owner/legacy-contact migration index (e.g. `OWNER#{user_sub}`).
  - `GSI_CREATED` (`type` partition / `created_at` sort) for newest-first listing.
- Declare numeric GSI sort keys with `attr_types={"created_at": "N", ...}` per the CLAUDE.md "DynamoDB numeric GSI sort keys" gotcha so `created_at` is stored as `N`.
- Wire the handle `party=_safe_table(S.party_table_name)` into `app/core/tables.py` next to `contacts=_safe_table(S.contacts_table_name)` (`app/core/tables.py:354`) and declare `party: Any` in the table-handles dataclass (next to `contacts: Any` at `app/core/tables.py:102`).

**Acceptance Criteria**
- `just restart` recreates the `party` table locally with no `ValidationException` (numeric sort keys correct).
- `app.core.tables.T.party` resolves to a live handle in a smoke pytest.
- Existing tables are unmodified.

**Dependencies**
- PTY-001.

---

### PTY-003: Party / role / relationship / contact-mech Pydantic models
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add OFBiz-shaped Pydantic models to `app/models.py` (mirroring the request/response style already there): `Party` (`party_id`, `party_type` ∈ {`PERSON`, `PARTY_GROUP`}, `status`, `created_at`, `updated_at`, optional `user_sub` link for PERSON parties), `PartyRole` (`party_id`, `role_type` from a `PartyRoleType` enum — e.g. `CUSTOMER`, `SUPPLIER`, `EMPLOYEE`, `ORG_ADMIN`, `BILL_TO`, `SHIP_TO`, `CONTACT`), `PartyRelationship` (`from_party_id`, `to_party_id`, `relationship_type` — e.g. `EMPLOYMENT`, `GROUP_MEMBER`, `CONTACT_REL`, `OWNER`), and `ContactMech` (`mech_id`, `party_id`, `mech_type` ∈ {`EMAIL`, `PHONE`, `POSTAL`}, `value`, `purposes` list — e.g. `PRIMARY_EMAIL`, `BILLING`, `SHIPPING`, `verified` flag).
- Reuse `app/core/normalize.py` (`normalize_email`, `normalize_phone`, imported in `app/services/profile.py:9`) for `ContactMech` value normalization, and the address shape from `app/services/addresses.py:39` `normalize_address_payload` for `POSTAL` mechs.
- Add the request/response IO models: `CreatePartyIn`, `PartyOut`, `AddRoleIn`, `CreateRelationshipIn`, `AddContactMechIn`, `ContactMechOut`, `OrgAccountOut`.

**Acceptance Criteria**
- All models validate the enum constraints and reject unknown `party_type` / `role_type` / `mech_type`.
- `ContactMech` EMAIL/PHONE values are normalized through the shared normalizers; POSTAL reuses the address normalizer (max-len guards preserved).
- pytest covers model validation success + rejection per field.

**Dependencies**
- PTY-001.

---

## Milestone 2 — Party Service Core

### PTY-004: Party CRUD service (PERSON / PARTY_GROUP)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Create `app/services/party.py` with the single-table access layer: `create_party(party_type, *, user_sub=None, correlation_id=None) -> dict` writing `PK=PARTY#{party_id}`, `SK=META`, plus the `GSI_CREATED` keys (`type=TYPE#{party_type}`, numeric `created_at` via `now_ts()` per `app/core/time.py`), `get_party(party_id)`, `list_parties(party_type=None, cursor=None)` (paginate via `app/core/cursor.py` like other services), and `update_party_status(party_id, status)`.
- Use **deterministic-id idempotency** for the write path per the plan ("`order_id = sha256(correlation_id)`"): `party_id = sha256(correlation_id).hexdigest()[:32]` when `correlation_id` is supplied, else a fresh `uuid4().hex`; a conditional `attribute_not_exists(PK)` put makes replays a no-op.
- Emit audit events via `app.services.alerts.audit_event` (the same pattern `commerce_order_service` uses) for create/status-change.

**Acceptance Criteria**
- Creating a PERSON and a PARTY_GROUP persists rows queryable by `get_party` and by `list_parties(party_type=...)` via `GSI_CREATED` (newest-first).
- Re-calling `create_party` with the same `correlation_id` returns the existing party (no duplicate row).
- Status transitions are validated and audited.
- Hermetic pytest (moto-bound frozen `T.party`) covers create / get / list / idempotent replay.

**Dependencies**
- PTY-002, PTY-003.

---

### PTY-005: Party role assignment service
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Extend `app/services/party.py` with `add_role(party_id, role_type)`, `remove_role(party_id, role_type)`, `list_roles(party_id)`, and `parties_with_role(role_type)`.
- Store roles as child rows `PK=PARTY#{party_id}`, `SK=ROLE#{role_type}` with `GSI1PK=ROLE#{role_type}`, `GSI1SK=PARTY#{party_id}` so `parties_with_role` is an O(1) GSI query (no scan).
- Validate `role_type` against the `PartyRoleType` enum (PTY-003); adding a duplicate role is idempotent.

**Acceptance Criteria**
- A party can hold multiple roles; `list_roles` returns all of them.
- `parties_with_role("SUPPLIER")` returns exactly the parties holding that role via `GSI1`.
- Duplicate `add_role` is a no-op; removing a non-existent role does not error.
- pytest covers add / list / reverse-lookup / dedup.

**Dependencies**
- PTY-004.

---

### PTY-006: Party relationship service
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Add `create_relationship(from_party_id, to_party_id, relationship_type, *, correlation_id=None)`, `list_relationships(party_id, *, direction="from"|"to"|"both")`, and `delete_relationship(...)` to `app/services/party.py`.
- Store as `PK=PARTY#{from}`, `SK=REL#{relationship_type}#{to}` plus a mirror `GSI3` entry (`GSI3PK=REL_TO#{to}`, `GSI3SK=REL#{relationship_type}#{from}`) so the inbound side is queryable without a scan.
- Deterministic-id idempotency on the relationship key prevents duplicate edges.

**Acceptance Criteria**
- Outbound and inbound relationship queries both resolve the same edge.
- `relationship_type` is validated; self-relationships (`from == to`) are rejected with 400.
- Deleting a relationship removes both the primary and mirror rows.
- pytest covers create / list-both-directions / dedup / delete.

**Dependencies**
- PTY-004.

---

### PTY-007: Unified contact-mechanism service (email / phone / postal)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Add `add_contact_mech(party_id, mech_type, value, purposes)`, `list_contact_mechs(party_id, mech_type=None)`, `update_contact_mech(...)`, `remove_contact_mech(...)`, and `find_party_by_contact(mech_type, value)` to `app/services/party.py`.
- Store as `PK=PARTY#{party_id}`, `SK=MECH#{mech_type}#{mech_id}`, plus a normalized reverse-lookup row on `GSI2` (`GSI2PK=EMAIL#{normalized}` / `PHONE#{e164}` / `POSTAL#{hash}`, `GSI2SK=PARTY#{party_id}`) for `find_party_by_contact`.
- Normalize EMAIL/PHONE via `app/core/normalize.py` (as `app/services/profile.py:9` does); POSTAL values reuse `addresses.normalize_address_payload` (`app/services/addresses.py:39`). Purposes are validated against an allowlist (`PRIMARY_EMAIL`, `BILLING`, `SHIPPING`, `PRIMARY_PHONE`, etc.).

**Acceptance Criteria**
- A party can carry multiple mechs across all three types; `list_contact_mechs(mech_type="EMAIL")` filters by type.
- `find_party_by_contact("EMAIL", "Alice@X.com ")` matches the normalized stored value.
- POSTAL mechs persist the full normalized address shape (line1 required, max-len guards enforced).
- pytest covers add / normalize / reverse-lookup / purpose validation / remove.

**Dependencies**
- PTY-004, PTY-003.

---

## Milestone 3 — B2B Organizations & Legacy Migration

### PTY-008: B2B organization account service
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Add org-account helpers to `app/services/party.py` (gated by `S.party_crm_org_accounts_enabled`): `create_org_account(name, *, owner_user_sub, correlation_id=None)` creates a `PARTY_GROUP` party (PTY-004), assigns it the `CUSTOMER` + `BILL_TO` roles (PTY-005), and links the creating PERSON party via an `EMPLOYMENT`/`OWNER` relationship (PTY-006) with the `ORG_ADMIN` role.
- `add_member(org_party_id, member_party_id, role_type)` / `remove_member(...)` / `list_members(org_party_id)` manage org membership via `GROUP_MEMBER` relationships, mirroring the membership semantics in `app/services/user_groups.py` (`create_group:24`, `join_group:156`) but on the party graph.
- Org membership/role mutations require the actor to hold `ORG_ADMIN` on that org (authorization check in the service, enforced by the router).

**Acceptance Criteria**
- Creating an org provisions the PARTY_GROUP + roles + owner relationship in one idempotent call (replay-safe via `correlation_id`).
- `list_members` returns all GROUP_MEMBER parties with their org roles.
- A non-admin member cannot add/remove members (raises the authorization error the router maps to 403).
- pytest covers org create / add-member / role-guard / idempotent replay.

**Dependencies**
- PTY-005, PTY-006.

---

### PTY-009: Additive contacts→party migration (back-compatible)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Add `app/services/party_contacts_migration.py` that **additively** projects existing `contacts` rows (`app/routers/contacts.py:62` `list_contacts`, table `owner_id`/`contact_id` at `scripts/local-ddb-init.py:691`) onto the party graph: for each `(owner_id, contact_id)`, ensure a PERSON party exists for both, and create a `CONTACT_REL` relationship (PTY-006) plus a `CONTACT` role, carrying over `display_name`, `is_favorite`, `is_blocked`, `profile_photo_url`.
- Migration is **read-only against the `contacts` table** — it never mutates or deletes legacy rows, so the existing `app/routers/contacts.py` surface keeps working byte-for-byte with the flag off (gated by `S.party_crm_contacts_migration_enabled`).
- Deterministic-id idempotency keys the projected party on the `contact_id` (a PERSON party already linked to that `user_sub` is reused), so the migration is replay-safe and incremental.
- Provide a backfill entrypoint `run_contacts_backfill(*, owner_id=None)` (all owners or one) plus a forward hook that `add_contact` (`app/routers/contacts.py:84`) calls best-effort when the flag is on (never breaking the legacy write).

**Acceptance Criteria**
- Backfill projects every legacy contact into a `CONTACT_REL` edge + `CONTACT` role without touching the source rows.
- Re-running the backfill creates no duplicates (idempotent per `(owner, contact)`).
- With the flag **off**, `list_contacts`/`add_contact`/`update_contact`/`remove_contact` behave identically to today (regression test).
- pytest covers backfill, idempotent re-run, favorite/blocked carry-over, and legacy-surface no-op when flag off.

**Dependencies**
- PTY-004, PTY-006, PTY-007.

---

### PTY-010: Link PERSON parties to users/profiles/addresses
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Add `ensure_person_party(user_sub) -> party_id` to `app/services/party.py`: idempotently creates (or returns) the PERSON party for a platform user, back-filling EMAIL/PHONE/POSTAL contact mechs (PTY-007) from `get_profile_identity` (`app/services/profile.py:305`) and `list_addresses` (`app/services/addresses.py:64`).
- Map each `is_primary_mailing` address (`app/services/addresses.py:114` `set_primary_address`) to a POSTAL mech with the `SHIPPING`/`BILLING` purposes, and `displayed_email`/`displayed_telephone_number` profile fields (`app/services/profile.py:16` PROFILE_FIELDS) to PRIMARY_EMAIL/PRIMARY_PHONE mechs — **read-through only**, leaving `profiles`/`addresses` tables unchanged.
- Wire a best-effort, flag-gated hook so `apply_profile_update` (`app/services/profile.py:336`) and `set_primary_address` re-sync the linked party's mechs when those fields change (never blocking the legacy write).

**Acceptance Criteria**
- `ensure_person_party` is idempotent (one PERSON party per `user_sub`) and back-fills mechs from profile + addresses.
- A profile email/phone change re-syncs the corresponding party mech when the flag is on; with the flag off, profile/address writes are unchanged (regression test).
- `profiles` and `addresses` tables are never written by the party layer.
- pytest covers ensure/back-fill/idempotency and the flag-off no-op.

**Dependencies**
- PTY-007, PTY-009.

---

## Milestone 4 — Router

### PTY-011: Party/CRM router (parties, roles, relationships, mechs)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Create `app/routers/party.py` with prefix `/ui/party` under `Depends(require_ui_session)` (the auth dep used by `app/routers/contacts.py:14`/`:63`), exposing: `POST/GET /parties`, `GET /parties/{party_id}`, `PATCH /parties/{party_id}` (status); `POST/DELETE /parties/{party_id}/roles`, `GET /parties/{party_id}/roles`; `POST/GET/DELETE /parties/{party_id}/relationships`; `POST/GET/PATCH/DELETE /parties/{party_id}/mechs`; and `GET /parties/lookup` (by contact mech).
- Declare static segments (`/parties/lookup`) **before** dynamic `/{party_id}` so FastAPI's declaration-order matching doesn't capture the literal (per the CLAUDE.md `/schedules` before `/{export_id}` gotcha).
- The whole router is no-op-registered: register it in `app/main.py` next to `contacts_router` (`app/main.py:82` import, `app/main.py:549+` include block), but every handler returns **404/disabled** when `S.party_crm_enabled` is off, so the API surface is inert with the flag off.

**Acceptance Criteria**
- All CRUD endpoints round-trip against the service layer with cookie auth + CSRF (non-GET requires `x-csrf-token` per CLAUDE.md).
- With `party_crm_enabled` off, every `/ui/party/*` route returns the disabled response and no service code runs.
- Foreign-party access (a party the caller has no relationship/role to) is denied.
- pytest exercises each route's success + flag-off + authz path.

**Dependencies**
- PTY-004, PTY-005, PTY-006, PTY-007.

---

### PTY-012: B2B org-account router + migration admin endpoints
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Add to `app/routers/party.py`: `POST /orgs` (create org), `GET /orgs`, `GET /orgs/{org_party_id}`, `POST/DELETE /orgs/{org_party_id}/members`, `GET /orgs/{org_party_id}/members` (PTY-008), all `ORG_ADMIN`-gated where they mutate.
- Add ROOT/admin migration endpoints `POST /ui/admin/party/migrate-contacts` and `POST /ui/admin/party/ensure-person/{user_sub}` (under `require_admin_session` per the CLAUDE.md admin convention) driving PTY-009/PTY-010 backfills.
- Org/admin routes are also flag-gated (`S.party_crm_org_accounts_enabled` / `S.party_crm_enabled`).

**Acceptance Criteria**
- Org owner can create an org and manage members; non-admin members get 403.
- Admin migration endpoints trigger the backfills and report a count; non-admin callers are denied.
- All routes inert with their flags off.
- pytest covers org lifecycle, member authz, and the admin migration trigger.

**Dependencies**
- PTY-008, PTY-009, PTY-010, PTY-011.

---

## Milestone 5 — Frontend

### PTY-013: Frontend types + endpoint wrappers
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Add TypeScript interfaces mirroring the Pydantic models (PTY-003) to `frontend/src/api/types.ts`: `Party`, `PartyRole`, `PartyRelationship`, `ContactMech`, `OrgAccount`.
- Add `frontend/src/api/endpoints/party.ts` (the per-domain wrapper convention, alongside `contacts.ts`) using the shared axios instance (`frontend/src/api/client.ts`) for the party / role / relationship / mech / org endpoints.

**Acceptance Criteria**
- Endpoint wrappers cover every PTY-011/PTY-012 route and attach CSRF for non-GET (handled by `client.ts`).
- Types compile and match the backend response shapes.
- A vitest unit test asserts the wrapper builds the right URLs/payloads.

**Dependencies**
- PTY-011, PTY-012.

---

### PTY-014: Party/CRM page, route & nav entry
**Type:** Feature  
**Priority:** P1  
**Estimate:** 3 days

**Description**
- Add `frontend/src/pages/party/PartyPage.tsx` (a directory under `frontend/src/pages/`, mirroring `pages/contacts/ContactsPage.tsx`) using React Query + shadcn/ui: party list with role badges, a party detail drawer (roles, relationships, contact mechs with add/edit), and an "Organizations" tab for B2B accounts (create org, manage members).
- Lazy-load and route it in `frontend/src/App.tsx` (next to the `contacts` route at `frontend/src/App.tsx:322`) as `/party`, and add a flag-gated nav entry to `frontend/src/components/layout/Sidebar.tsx` next to the existing "Contacts" item (`Sidebar.tsx:107`).
- The page + nav entry render only when a `party_crm_enabled` capability flag (surfaced via the existing settings/feature endpoint) is on, so the UI is invisible with the flag off.

**Acceptance Criteria**
- Admin/user can view parties, drill into a detail drawer, add/edit a contact mech, and create + manage a B2B org from the UI.
- With the flag off, neither the `/party` route nor the nav entry is reachable; the existing Contacts page is untouched.
- React Query caches invalidate correctly after mutations (no stale list).

**Dependencies**
- PTY-013.

---

## Milestone 6 — Tests

### PTY-015: Party/CRM hermetic pytest + E2E suite
**Type:** Chore  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Add hermetic offline pytest `tests/test_party_crm.py` (moto-bound `T.party` patched onto the frozen handle via `object.__setattr__`, `S` flags toggled via `object.__setattr__`, no real AWS — the project's standard test-isolation pattern) covering: party CRUD + deterministic-id idempotency (PTY-004), roles + reverse lookup (PTY-005), relationships both directions (PTY-006), contact-mech normalize + find-by-contact (PTY-007), org account lifecycle + member authz (PTY-008), contacts backfill idempotency + legacy no-op (PTY-009), and `ensure_person_party` back-fill (PTY-010).
- Add a **flag-off regression test** asserting `list_contacts`/`add_contact`/`update_contact`/`remove_contact` (`app/routers/contacts.py`) and `create_address`/`set_primary_address` (`app/services/addresses.py`) are byte-for-byte unchanged when `party_crm_*` flags are off.
- Add `frontend/e2e/party-crm.spec.ts` (seeded sessions + CSRF per CLAUDE.md/MEMORY.md) covering: create party, add role, add a contact mech, create a B2B org + add a member, and a flag-off check that `/party` is unreachable. Run under the standard 1-worker Playwright config.

**Acceptance Criteria**
- pytest suite covers every service path (CRUD, roles, relationships, mechs, orgs, migration, idempotency) and passes offline with no AWS calls.
- The flag-off regression test proves the legacy contacts + addresses surfaces are unchanged.
- E2E suite passes under the standard Playwright config and includes the flag-off unreachable-route assertion.

**Dependencies**
- PTY-011, PTY-012, PTY-014.

---
