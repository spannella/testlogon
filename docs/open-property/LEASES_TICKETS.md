# Leases / Tenancy — Implementation Tickets (prefix `LSE`)

Source gap analysis: `docs/open-property/OPEN_PROPERTY_GAP_ANALYSIS.md` §B
("Tenants + Leases + Rent Ledger"). The **Lease/tenancy entity** is flagged
**MISSING**, with the explicit note: *"QUO-004 CRM contract is the closest planned
scaffold"* and *"mirror QUO-004 list pattern"* for the list + status-filter + inline-edit
surface (gap matrix rows 55–56).

This file specs the Lease entity for the open-property property-management vertical.
A lease is a **time-bounded tenancy agreement** binding a **tenant** (TEN) to a
**unit** of a **property** (PROP), carrying the property-specific economic terms
(monthly rent, security deposit, rent due-day, late-fee structure). It is built on the
**QUO-004 CRM-contract scaffold** (`docs/suitecrm/specs/QUO-004.md`) — a
time-bounded agreement with monotonic numbering, a stage state-machine
(`draft → active → expired | terminated | renewed`), and a background
renewal-notification loop — but **replaces the generic `value_cents` body with the
property-specific lease economics** and a property-domain status vocabulary
(`active | upcoming | ended`).

---

## Cross-cutting constraints (apply to every LSE ticket)

1. **Additive + flag-gated, default OFF.** All work is gated behind a new
   `LEASES_ENABLED` setting (env `LEASES_ENABLED`, default `"0"` → OFF). Follow the
   **default-OFF negation polarity** verified in QUO-004 §6 / Verification Log:
   `os.environ.get("LEASES_ENABLED", "0") not in ("0", "false", "False")`
   (absent → `"0"` → `False` → OFF). With the flag off, every new endpoint returns
   404, the renewal/expiration background loop does not start, and no existing surface
   changes by a single byte (QUO-004 §1).

2. **No `dev_mode` branch (SECOPS-007 parity).** Services call `T.leases` (boto3 → DDB
   Local via moto in dev, real DynamoDB in prod — one code path). Email goes through
   `app/services/alerts.py:459 send_alert_email`, which owns the dev(log)/prod(SES)
   divergence internally (QUO-004 §7). No lease service or router contains an
   `if S.dev_mode:` branch.

3. **Reuse, never fork.** The following primitives are reused verbatim (all verified
   present):
   | Primitive | Location | Used for |
   |---|---|---|
   | `_next_invoice_number` counter pattern (`Key={"pk":"COUNTER","sk":...}` atomic `ADD`) | `app/services/invoices.py:82` (cited via QUO-004 §2) | `_next_lease_number()` → `LSE-{year}-{seq:05d}` |
   | `_STATUS_TRANSITIONS` allowlist + `update_status` conditional-write state-machine | `app/services/tickets.py:30`, `:913` | lease status machine (`_LEASE_TRANSITIONS`) |
   | `encode_cursor` / `decode_cursor` | `app/core/cursor.py:94`, `:103` | all list endpoint pagination |
   | `audit_event(event, user_sub, request=None, **fields)` | `app/services/alerts.py:644` | every state-change event |
   | `send_alert_email(to_emails, subject, body_text)` | `app/services/alerts.py:459` | expiration/renewal notifications |
   | `get_profile_identity(user_sub)` | `app/services/profile.py:305` | resolve owner email for notifications |
   | `run_compute_billing_timer` / `start_compute_billing_timer_task` (`asyncio.ensure_future`, gated) | `app/services/compute_billing.py:653`, `:669` | background expiration loop pattern |
   | startup hook registration | `app/main.py:302` import, `app.add_event_handler("startup", ...)` (~`:649`) | register the lease loop |
   | `TableDef` + `attr_types` for numeric GSI keys | `scripts/local-ddb-init.py:28`, canonical `attr_types={"created_at":"N"}` at `:84` | `leases` table definition |

4. **DynamoDB numeric GSI sort keys MUST declare `attr_types={...: "N"}`** in the
   `TableDef`, or DynamoDB stores them as strings → `ValidationException` at query time
   (CLAUDE.md gotcha; QUO-004 §3.3). Every `LSE` GSI in this file with a numeric sort
   key (`start_date`, `end_date`, `created_at`) carries this declaration.

5. **`FilterExpression` does not reduce page size** — any cross-partition scan
   (e.g. the upcoming-expiration sweep) must loop on `LastEvaluatedKey` (CLAUDE.md
   gotcha; QUO-004 §4.1 `check_expiring_contracts` follows this).

6. **Money movement is out of scope here.** The lease entity stores `monthly_rent_cents`
   / `security_deposit_cents` as **informational integer cents** (mirroring QUO-004's
   `value_cents` having no ledger interaction, §5). The **RNT rent-ledger cluster
   consumes active leases** to post monthly charges via `billing_shared.new_ledger_entry`
   (`app/services/billing_shared.py:224`); LSE never writes ledger rows. Any future
   deposit refund / fee reversal must reuse `settle_or_reverse_ledger`
   (`app/services/billing_shared.py:262`) — never a custom deduction.

7. **Ownership isolation.** All user-scoped reads/writes are keyed under
   `USER#{user_sub}`; a lease owned by another landlord simply does not exist in that
   partition → 404, leaking no information (QUO-004 §7).

---

### LSE-001: Lease entity — DDB model, table, flag, and state-machine service

**Type:** Feature
**Priority:** P1
**Estimate:** 3 d

**Description**

Introduce the Lease entity: a tenancy agreement binding a tenant to a property unit,
carrying property-specific economic terms, with a `draft → active | upcoming → ended`
style status machine. This is the QUO-004 contract scaffold specialized for real estate.

**Feature flag & settings** (`app/core/settings.py`, default-OFF negation polarity per
QUO-004 §6):
```python
leases_enabled: bool = os.environ.get("LEASES_ENABLED", "0") not in ("0", "false", "False")
leases_table_name: str = os.environ.get("LEASES_TABLE_NAME", "leases")
```
`.env.local.example`: `LEASES_ENABLED=0`.

**DDB table `leases`** (env `LEASES_TABLE_NAME`, default `"leases"`). Single-table,
mirrors QUO-004 §3.1 key shape:
```
PK = USER#{user_sub}                  # landlord/owner
SK = LEASE#{lease_id}                 # lease_id = "lse_" + uuid4().hex[:16]
COUNTER row: PK="COUNTER", SK="LEASE_SEQ"  (atomic ADD, invoices.py:82 pattern)
```

Item attributes (QUO-004 fields **minus** `value_cents` and the AOS party fields,
**plus** the property-specific spine):

| Attribute | Type | Notes |
|---|---|---|
| `pk` / `sk` | S | as above |
| `lease_id` | S | bare id |
| `lease_number` | S | `LSE-{year}-{seq:05d}` from atomic counter (invoices.py:82) |
| `user_sub` | S | denormalized owner for GSI queries (QUO-004 §3.1) |
| `tenant_id` | S | FK → TEN tenant; stored verbatim, no FK validation in this ticket (QUO-004 §2 treats `contact_id` as opaque string) |
| `property_id` | S | FK → PROP property |
| `unit_id` | S | FK → PROP unit (the occupied unit) |
| `status` | S | `draft` \| `upcoming` \| `active` \| `ended` |
| `start_date` | N | Unix ts; required |
| `end_date` | N | Unix ts; `None`/absent = open-ended/month-to-month |
| `monthly_rent_cents` | N | integer cents; `ge=0` |
| `security_deposit_cents` | N | integer cents; `ge=0`; default 0 |
| `rent_due_day` | N | day-of-month rent is due (1–28; `ge=1, le=28` to avoid short-month gaps) |
| `late_fee_type` | S | `none` \| `flat` \| `percent` |
| `late_fee_cents` | N | flat fee in cents when `late_fee_type="flat"` |
| `late_fee_percent_bps` | N | basis points when `late_fee_type="percent"` (e.g. 500 = 5%) |
| `late_fee_grace_days` | N | grace days after `rent_due_day` before a late fee applies; default 0 |
| `currency` | S | ISO 4217 lowercase, default `"usd"` |
| `notes` | S | free text; `""` when absent |
| `renewal_notice_days` | N | days before `end_date` to trigger expiration notice; default 30 (QUO-004 §3.1) |
| `renewal_notified_at` | N | ts when notice sent; absent = not yet sent (idempotency marker, QUO-004 §5) |
| `created_at` / `updated_at` | N | Unix ts |

**GSIs** (QUO-004 §3.2 shape, specialized):
- **GSI1 — admin/all + RNT consumption:** `GSI1PK="LEASES#ALL"` (literal), `GSI1SK=created_at` (N). Index `leases-all-index`. Used by `admin_list_leases()` and by the RNT rent-run / expiration sweep cross-user scans.
- **GSI2 — per-owner status + expiry filter:** `GSI2PK=USER#{user_sub}#STATUS#{status}`, `GSI2SK=end_date` (N, sparse — open-ended leases omit it). Index `leases-by-status-index`. Used by `list_leases(status=...)` and the upcoming-expiration query (LSE-003).

`scripts/local-ddb-init.py` — new `TableDef` (mirror QUO-004 §3.3, `attr_types`
**mandatory**):
```python
TableDef(
    _resolve_table_name(S.leases_table_name, "leases"),
    "pk", "sk",
    gsi=[
        {"index_name": "leases-all-index",       "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
        {"index_name": "leases-by-status-index", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
    ],
    attr_types={"GSI1SK": "N", "GSI2SK": "N"},  # numeric or ValidationException (constraint 4)
),
```
`app/core/tables.py`: add `leases: Any` to `Tables` (end of field list) + `_safe_table(S.leases_table_name)` to `T` (QUO-004 §3.4).

**Service `app/services/leases.py`** (every public fn short-circuits on
`if not S.leases_enabled: return None`, QUO-004 §4.1):
- `_next_lease_number() -> str` — clone of `invoices.py:82` against `T.leases`, `Key={"pk":"COUNTER","sk":"LEASE_SEQ"}` → `f"LSE-{year}-{seq:05d}"`.
- `create_lease(user_sub, *, tenant_id, property_id, unit_id, start_date, end_date=None, monthly_rent_cents, security_deposit_cents=0, rent_due_day, late_fee_type="none", late_fee_cents=0, late_fee_percent_bps=0, late_fee_grace_days=0, currency="usd", notes="") -> dict` — validates `start_date>0`, `end_date>start_date` when present (QUO-004 §4.1 step 1); mints id + number; initial `status` = `"upcoming"` if `start_date > now_ts()` else `"active"` (real-estate domain: a lease whose term hasn't begun is `upcoming`, one in its term is `active` — replaces QUO-004's `draft` default); writes GSI1/GSI2 keys; `put_item`; `audit_event("lease.created", user_sub, lease_id=..., lease_number=...)`.
- `get_lease(user_sub, lease_id) -> dict | None` — `get_item` + ownership check (QUO-004 §4.1).
- `transition_status(user_sub, lease_id, new_status) -> dict` — the property-domain state machine. Allowlist (mirrors `tickets.py:30 _STATUS_TRANSITIONS` + QUO-004 §5 `_ALLOWED_TRANSITIONS`):
  ```python
  _LEASE_TRANSITIONS = {
      "draft":    {"upcoming", "active"},
      "upcoming": {"active", "ended"},   # signed-but-future → starts, or cancelled before move-in
      "active":   {"ended"},             # term ended / terminated early
  }
  ```
  Terminal: `ended` (no outbound edges → 400 `invalid_status_transition`). Uses a **conditional `update_item` `ConditionExpression="status = :old"`** (QUO-004 §5 race-prevention / `tickets.py:913` `_apply_header_update_once`); `ConditionalCheckFailedException` → HTTP 409 `concurrent_update`. Rewrites `GSI2PK` to `USER#{user_sub}#STATUS#{new_status}`. Emits `audit_event("lease.status_changed", user_sub, from_status=..., to_status=..., ...)`.

**Unit occupancy side-effect (PROP integration):** transitioning a lease **to `active`**
sets the occupied unit's `occupancy_status="occupied"`; transitioning **to `ended`** sets
it back to `vacant` (per gap analysis §B note: *"a lease occupies a unit"*). This is a
best-effort call into the PROP unit service wrapped in `try/except` so a PROP failure
never rolls back the lease transition (mirrors EC2/K8s host-inventory best-effort pattern,
CLAUDE.md). When `PROP` is not yet deployed the call is a no-op.

**Acceptance Criteria**
- With `LEASES_ENABLED=0` every lease service fn returns `None`; `leases` table & router absent from runtime behavior.
- `create_lease` mints sequential `LSE-{year}-00001`, `LSE-{year}-00002`; sets `status="upcoming"` for a future `start_date`, `"active"` for a current one.
- `transition_status` enforces `_LEASE_TRANSITIONS`; `active → upcoming` and any out-of-`ended` transition → 400 `invalid_status_transition`; a racing second writer → 409 `concurrent_update`.
- `GSI2PK` always reflects the current status after a transition; numeric GSI sort keys query without `ValidationException`.
- Transition to `active`/`ended` flips the unit `occupancy_status` (or no-ops if PROP absent) without ever failing the lease write.
- No `if S.dev_mode` branch anywhere in `app/services/leases.py`.

**Dependencies**
- **PROP** (property + unit entities) — `property_id`/`unit_id` FKs + the unit `occupancy_status` side-effect. FKs stored opaquely if PROP lands later (QUO-004 §2 opaque-string precedent); the occupancy side-effect is a best-effort no-op until PROP exists.
- **TEN** (tenant entity) — `tenant_id` FK (opaque string, no validation this ticket).
- Reuses QUO-004 scaffold patterns + the primitives in cross-cutting constraint 3.

---

### LSE-002: Lease list, status filter, and inline editing (service + Pydantic + router)

**Type:** Feature
**Priority:** P1
**Estimate:** 2 d

**Description**

Add the list/filter/edit surface, mirroring the **QUO-004 list pattern** explicitly
called for in the gap matrix (§B row 56: *"Lease table + status filter + inline edit …
mirror QUO-004 list pattern"*).

**Service additions** (`app/services/leases.py`):
- `list_leases(user_sub, *, status=None, limit=50, cursor=None) -> dict` — QUO-004 §4.1 `list_contracts` clone:
  - `status` given → query `GSI2` `Key("GSI2PK").eq(f"USER#{user_sub}#STATUS#{status}")`, `ScanIndexForward=False`, `Limit=min(limit, 200)`.
  - `status` absent → base-table query `Key("pk").eq(f"USER#{user_sub}")` filtered `begins_with(SK, "LEASE#")`.
  - cursor via `decode_cursor`/`encode_cursor` (`app/core/cursor.py:103,94`); returns `{"leases":[...], "count":int, "next_cursor":str|None}`.
- `update_lease(user_sub, lease_id, *, <mutable fields>) -> dict | None` — QUO-004 §4.1 `update_contract` clone. Mutable: `end_date`, `monthly_rent_cents`, `security_deposit_cents`, `rent_due_day`, `late_fee_type`, `late_fee_cents`, `late_fee_percent_bps`, `late_fee_grace_days`, `currency`, `notes`. **Immutable** (rejected if present, raising 400): `tenant_id`, `property_id`, `unit_id`, `start_date`, `status` (status changes go through `transition_status` only, QUO-004 §4.3 PATCH note). Builds a partial `UpdateExpression` over non-None args + `updated_at=now_ts()`; if `end_date` changes, rewrites `GSI2SK`. 404 via `get_lease` first; emits `audit_event("lease.updated", ...)`.
- `admin_list_leases(*, limit=50, cursor=None) -> dict` — `GSI1` `Key("GSI1PK").eq("LEASES#ALL")`, `ScanIndexForward=False` (QUO-004 §4.1 `admin_list_contracts`).

**Pydantic models** (`app/models.py`, additive — QUO-004 §4.4 shape):
`LeaseCreateIn`, `LeasePatchIn` (mutable fields only, all `Optional`), `LeaseOut`
(all item fields), `LeaseListOut` (`{leases, count, next_cursor}`). Cent/day fields
carry validators: `monthly_rent_cents`/`security_deposit_cents` `ge=0`, `rent_due_day`
`ge=1, le=28`, `late_fee_percent_bps` `ge=0, le=10000`, `renewal_notice_days`
`ge=1, le=365`.

**Router `app/routers/leases.py`**, prefix `/ui/leases`, registered in `app/main.py`
near the AOS/invoices routers. Every handler begins with the 404 flag-guard
(QUO-004 §4.3):
```python
if not S.leases_enabled:
    raise HTTPException(status_code=404, detail="leases not enabled")
```
- `POST /ui/leases` → `create_lease` (`require_ui_session`).
- `GET  /ui/leases?status=&limit=&cursor=` → `list_leases` (`limit` `Query(ge=1, le=200)`).
- `GET  /ui/leases/{lease_id}` → `LeaseOut` | 404.
- `PATCH /ui/leases/{lease_id}` → `update_lease`; 400 if patch carries `status` or any immutable field (QUO-004 §4.3).
- `POST /ui/leases/{lease_id}/status` (`{"status": "..."}`) → `transition_status`.
- `GET  /ui/admin/leases` → `admin_list_leases`, `Depends(require_admin_or_root)` (`app/auth/policy.py:67`).

**Acceptance Criteria**
- `GET /ui/leases?status=active` returns only `active` leases via GSI2; no-filter list returns all of the owner's leases via the base-table path.
- Pagination: `limit=2` over 5 leases returns a `next_cursor`; following it returns the remainder with no overlap/omission (HMAC-signed cursor round-trips).
- `PATCH` updates a mutable field (e.g. `monthly_rent_cents`), advances `updated_at`, leaves `lease_number` unchanged; `PATCH` with `status` or `start_date`/`tenant_id` → 400.
- `GET /ui/admin/leases` returns leases across multiple owners (GSI1) for ROOT/ADMIN; 403 for a plain user session.
- All endpoints 404 when `LEASES_ENABLED=0`.

**Dependencies**
- **LSE-001** (entity, table, status machine).

---

### LSE-003: Lease history per tenant + upcoming-expiration query + renewal-notice loop

**Type:** Feature
**Priority:** P2
**Estimate:** 2 d

**Description**

Two read views the dashboard and tenant profile consume, plus the background
expiration-notification loop (the QUO-004 §4.1–§4.2 renewal machinery specialized to
leases). Gap matrix §B: *"Tenant historical lease records … depends on Lease"* and the
portfolio dashboard's *"upcoming lease expirations"* priority items (gap analysis §A/§C).

**Per-tenant lease history** (`app/services/leases.py`):
- `list_leases_for_tenant(user_sub, tenant_id, *, limit=50, cursor=None) -> dict` —
  returns all leases (any status) for one tenant, newest-first, so a tenant profile shows
  current + historical tenancies. Implementation: query the owner partition
  (`Key("pk").eq(f"USER#{user_sub}")`, `begins_with(SK,"LEASE#")`) with
  `FilterExpression=Attr("tenant_id").eq(tenant_id)`, looping on `LastEvaluatedKey`
  (constraint 5 — FilterExpression doesn't reduce page size). Returns
  `{"leases":[...], "count":int, "next_cursor":str|None}`.
  *(A `GSI3PK=USER#{user_sub}#TENANT#{tenant_id}` / `GSI3SK=start_date` index is a viable
  optimization if profiles grow hot; deferred — the filtered query is sufficient at
  expected per-landlord volumes and avoids a third GSI.)*

**Upcoming-expiration query** (feeds the dashboard, gap analysis §A):
- `list_upcoming_expirations(user_sub, *, within_days=60, limit=50) -> list[dict]` —
  per-owner query on `GSI2`:
  `Key("GSI2PK").eq(f"USER#{user_sub}#STATUS#active") & Key("GSI2SK").between(now_ts(), now_ts() + within_days*86400)`
  (QUO-004 §4.1 `check_expiring_contracts` GSI2 `.between` pattern), newest-due-first.
  Open-ended leases (no `end_date` → sparse GSI2) are correctly excluded
  (QUO-004 §5 open-ended note). This is a single-partition query (no cross-user scan)
  and powers the per-landlord "leases expiring soon" dashboard dashlet.

**Background expiration/renewal loop** (QUO-004 §4.2 clone, sub-flag-gated):
- New settings: `leases_renewal_notifications_enabled`
  (`LEASES_RENEWAL_NOTIFICATIONS_ENABLED`, default `"0"`) and
  `leases_renewal_check_interval_seconds` (`LEASES_RENEWAL_CHECK_INTERVAL_SECONDS`,
  default `3600`).
- `check_expiring_leases() -> int` — cross-user sweep (QUO-004 §4.1 algorithm):
  scan `GSI1` (`GSI1PK="LEASES#ALL"`) with
  `FilterExpression=Attr("status").eq("active") & Attr("end_date").between(now_ts(), now_ts()+90*86400)`,
  **looping on `LastEvaluatedKey`** (constraint 5). For each match with
  `renewal_notified_at` absent and `end_date - now_ts() <= renewal_notice_days*86400`:
  resolve owner email via `get_profile_identity(user_sub)` (`app/services/profile.py:305`);
  `send_alert_email([email], f"Lease {lease_number} expires in {days} days", body)`
  (`app/services/alerts.py:459`); write `renewal_notified_at=now_ts()` (idempotency
  marker — never re-sends, QUO-004 §5); `audit_event("lease.renewal_notified", ...)`;
  increment count. Returns total sent. Short-circuits to `0` when
  `not S.leases_renewal_notifications_enabled` (QUO-004 §4.1).
- `run_leases_renewal_check_loop(*, poll_interval=None)` + `start_leases_renewal_check_task()`
  — exact clone of `compute_billing.py:653/:669` (`asyncio.ensure_future`, gated on
  `S.leases_enabled and S.leases_renewal_notifications_enabled`), registered via
  `app.add_event_handler("startup", start_leases_renewal_check_task)` in `app/main.py`
  alongside the existing compute-billing hook (QUO-004 §4.2, `app/main.py:302/~:649`).

**Endpoints** (router from LSE-002):
- `GET /ui/leases/expiring?within_days=` → `list_upcoming_expirations`.
- `GET /ui/tenants/{tenant_id}/leases` → `list_leases_for_tenant` (lease history for the
  tenant profile; lives in the leases router to keep the lease access pattern owned here —
  the TEN profile page calls it).

**Acceptance Criteria**
- `list_leases_for_tenant` returns current + ended leases for one tenant, newest-first, across multiple pages without omission.
- `list_upcoming_expirations(within_days=60)` returns only `active` leases ending within 60 days; open-ended leases (no `end_date`) never appear.
- `check_expiring_leases` sends exactly one email per qualifying lease, sets `renewal_notified_at`, and a second sweep sends nothing (idempotent, QUO-004 §5); returns 0 when the renewal sub-flag is off.
- The renewal loop starts only when **both** `LEASES_ENABLED` and `LEASES_RENEWAL_NOTIFICATIONS_ENABLED` are `1`.
- `GET /ui/leases/expiring` and `GET /ui/tenants/{id}/leases` 404 when `LEASES_ENABLED=0`.

**Dependencies**
- **LSE-001**, **LSE-002**.
- **TEN** — `tenant_id` is the key for lease history (opaque; TEN profile page is the consumer).
- Feeds the portfolio dashboard (gap analysis §A) and the **RNT** rent-ledger cluster, which iterates `status=active` leases (GSI2/GSI1) to post monthly charges — RNT *consumes* this query surface; no RNT code lives here.

---

### LSE-004: Frontend lease table, status filter, inline edit, and tenant lease history

**Type:** Feature
**Priority:** P2
**Estimate:** 3 d

**Description**

The React surface for leases, following the repo frontend conventions (CLAUDE.md
"Frontend conventions": React Query for server state, axios via `api/client.ts`, shadcn/ui
primitives, React Hook Form + Zod) and mirroring the QUO-004 list-pattern intent
(gap matrix §B row 56).

**API layer:**
- `frontend/src/api/types.ts` — `Lease`, `LeaseCreateInput`, `LeasePatchInput`,
  `LeaseListResponse` (mirror the LSE-002 Pydantic models).
- `frontend/src/api/endpoints/leases.ts` — wrappers over the LSE-002/003 endpoints:
  `listLeases({status?, cursor?})`, `getLease(id)`, `createLease(body)`,
  `updateLease(id, patch)`, `transitionLeaseStatus(id, status)`, `listExpiringLeases(withinDays)`,
  `listTenantLeases(tenantId)`, `adminListLeases({cursor?})`.

**Pages/components** (`frontend/src/pages/leases/`):
- **`LeasesPage.tsx`** — lease table (shadcn `DataTable`) with a **status filter** segmented
  control (`all | upcoming | active | ended`) backed by `useQuery(["leases", status])`;
  columns: lease number, tenant, property/unit, term (start–end), monthly rent, status badge,
  next-due day. Cursor pagination via `useInfiniteQuery` (or load-more) over `next_cursor`.
  A row whose `end_date` is within the expiring window is flagged.
- **Inline editing** — editable cells for the mutable fields (`monthly_rent_cents`,
  `rent_due_day`, late-fee fields, `end_date`, `notes`) committing via a `useMutation`
  → `updateLease`, invalidating `["leases"]` on success. Immutable fields
  (tenant/property/unit/start_date/status) are read-only; **status** is changed through a
  dedicated status-transition control (dropdown of legal next-states from
  `_LEASE_TRANSITIONS`) calling `transitionLeaseStatus`, surfacing the 400
  `invalid_status_transition` / 409 `concurrent_update` errors as toasts.
- **`LeaseCreateDialog.tsx`** — React Hook Form + Zod create form (tenant + unit pickers,
  term dates, rent, deposit, due-day, late-fee structure).
- **Tenant lease history** — a `TenantLeasesPanel` (consumed by the TEN tenant-profile page)
  using `listTenantLeases(tenantId)` to render current + historical tenancies newest-first.

**Routing:** add `/leases` (and the create/detail surfaces) to
`frontend/src/App.tsx` as a lazy-loaded route, behind the same flag awareness used by other
gated pages (the page degrades to an empty/"not enabled" state when the backend returns 404).

**E2E** `frontend/e2e/leases.spec.ts` (mirror QUO-004 §9.2 / the repo AOS suite, using
`injectAuth(page, "alice")` + the `x-csrf-token` header pattern from CLAUDE.md): sections
for (1) lease CRUD API, (2) status-filter list + pagination, (3) inline edit + status
transition (incl. 400 on illegal transition), (4) tenant lease history, (5) admin list 403
for a user session / 200 for root, (6) flag-off 404 guard.

**Acceptance Criteria**
- LeasesPage renders the lease table, status-filter switches the query and shows only matching leases, and pagination loads further pages via `next_cursor`.
- Inline editing a mutable field persists via `updateLease` and refetches; immutable fields are not editable; the status control offers only legal next-states and surfaces 400/409 errors as toasts.
- The tenant lease-history panel lists a tenant's current + ended leases newest-first.
- E2E spec passes for CRUD, filter+pagination, inline edit + transition, tenant history, admin-list authz, and the flag-off 404 guard.

**Dependencies**
- **LSE-002** (list/filter/edit endpoints), **LSE-003** (expiring + tenant-history endpoints).
- **TEN** frontend (tenant picker + tenant-profile page that mounts `TenantLeasesPanel`); **PROP** frontend (unit picker). Degrade gracefully (plain id inputs) if those pickers aren't yet available.

---

## Dependency order (build sequence)

```
LSE-001  (entity + table + flag + status machine)        ← depends on PROP, TEN
   └─ LSE-002  (list / filter / inline-edit service+router)
         └─ LSE-003  (tenant history + expiration query + renewal loop)   → feeds RNT, dashboard
               └─ LSE-004  (frontend table + edit + tenant history)
```

**External:** PROP (property/unit + unit `occupancy_status` side-effect), TEN (tenant FK +
profile page). **Downstream consumer:** RNT (rent ledger iterates `status=active` leases to
post monthly `new_ledger_entry` charges — consumes LSE, no LSE code).

ticket_count: 4
