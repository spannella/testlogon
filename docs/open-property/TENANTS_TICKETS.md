# Tenants — Implementation Tickets (prefix **TEN**)

Property-management vertical, **Tenant entity** cluster (open-property gap analysis
§B "Tenants"). Source gap matrix:
`docs/open-property/OPEN_PROPERTY_GAP_ANALYSIS.md` (§B, lines 48–62; recommended
**Tenant** cluster at line 85).

This file covers the **net-new tenant delta** only: a property-scoped Tenant entity +
directory, employment / income-verification / emergency-contact profile fields, and
historical lease records. Today the codebase has only a thin contacts address book
(`app/routers/contacts.py`) and the **planned** PTY PERSON party
(`docs/ofbiz/specs/PTY-004`); neither models a property tenant, employment, income, or
emergency contacts — that is the genuinely net-new surface these tickets build.

The OpenBankProject **CUS-001** customer entity
(`docs/openbankproject/specs/CUS-001`) is the closest analogue for "a person record
with KYC-ish profile fields (employment, income) hanging off it"; we mirror its
shape (person + structured employment/income sub-records) but scope it to the
landlord/property domain rather than banking.

---

## Cross-cutting constraints (apply to every TEN ticket)

1. **Additive + flag-gated, default-off.** All work lives behind a new
   `S.property_tenants_enabled` setting (env `PROPERTY_TENANTS_ENABLED`, default
   `False`), added in TEN-001 following the boolean-env pattern at
   `app/core/settings.py:124`
   (`os.environ.get("PROPERTY_TENANTS_ENABLED", "0") not in ("0", "false", "False")`).
   With the flag off, every router endpoint returns **HTTP 503** (flag-guard pattern
   from `app/routers/collaborations.py:88-90` / `app/routers/bot_auto_reply.py:62`,
   reused by PTY-004 §4.2) and no new table is read or written. Zero impact on
   existing contacts, profile, billing, files, or any other subsystem.

2. **Reuse the PTY party PERSON spine, do not fork it.** A Tenant is a **property-domain
   projection over a PTY `PERSON` party** (`docs/ofbiz/specs/PTY-004`). TEN-001 creates
   (or links to) a `PERSON` party via `party.create_party("PERSON", user_sub=…,
   correlation_id=…)` and stores the returned `party_id` on the tenant record. Tenant
   profile sub-records (employment/income/emergency contacts) are **net-new** and live
   on the tenant's own single-table partition — NOT on the party table — to keep the
   shared PTY module untouched. Emergency contacts reuse the PTY-006 relationship model
   conceptually (`docs/ofbiz/specs/PTY-006`, `CONTACT_REL`) but, because PTY-006 is
   flag-coupled to `party_crm_enabled` and an emergency contact is frequently a
   non-party free-text person, we store them as a small embedded list on the tenant
   profile (see TEN-002 §rationale).

3. **Single-table + established primitives.** New `property_tenants` table follows the
   `PK`/`SK` single-table convention. Numeric GSI sort keys (`created_at`) MUST declare
   `attr_types={"created_at": "N"}` in `scripts/local-ddb-init.py` (CLAUDE.md "DynamoDB
   numeric GSI sort keys" gotcha; same as PTY-002/PTY-004). Pagination uses
   `encode_cursor`/`decode_cursor` from `app/core/cursor.py:94,103` (PTY-004 §2.5
   precedent). Timestamps are integer Unix seconds from `app/core/time.now_ts()`.
   Idempotent writes use `ConditionExpression="attribute_not_exists(PK)"`
   (PTY-004 §2.3). Audit events go through
   `app/services/alerts.py:644` `audit_event(event, user_sub, request=None, **fields)`
   (PTY-004 §2.4 precedent).

4. **Auth.** All endpoints use `Depends(require_ui_session)` from
   `app/services/sessions` (the exact import at `app/routers/contacts.py:12`). Non-GET
   cookie-auth requests require the `x-csrf-token` header (standard CSRF rule). No
   money-out path exists in this cluster, so the GL/ledger cross-cutting constraint does
   not apply.

5. **SECOPS-007 dev/prod parity.** No `S.dev_mode` branch in any tenant service.
   Income-document attachments go through the existing file-manager
   (`app/services/filemanager.py` `upload_file` at `:2110`, which already forks
   dev moto-S3 vs prod S3 internally), so the tenant code stays env-agnostic. The
   `/mock/s3/...` dev URL injection is handled by filemanager, not by tenant code.

6. **Dependency order.** TEN-001 → TEN-002 → TEN-003 → TEN-004. TEN-001 has no
   intra-cluster dependency (only PTY + flag). TEN-003 (lease history) depends on the
   **LSE lease cluster** and **PROP unit cluster**; TEN-002's active-unit link depends
   on the **PROP unit cluster**. The frontend (TEN-004) depends on all three.

---

### TEN-001: Tenant entity, table, flag & directory CRUD service

**Type:** Feature | **Priority:** P0 | **Estimate:** 3 days

**Description**

Establish the net-new **Tenant** entity as a property-domain projection over a PTY
`PERSON` party, plus its DynamoDB table, feature flag, and CRUD/directory service.

- **Feature flag (new):** add `S.property_tenants_enabled`
  (`PROPERTY_TENANTS_ENABLED`, default `False`) to `app/core/settings.py` following the
  `:124` boolean-env pattern, and `S.property_tenants_table_name`
  (`DDB_PROPERTY_TENANTS_TABLE`, default `"property_tenants"`).

- **DDB table (new):** `property_tenants` in `scripts/local-ddb-init.py`:
  - `PK = TENANT#{tenant_id}` (S, hash), `SK = META` (S, range) for the tenant-meta row;
    sub-records (TEN-002/TEN-003) reuse the same `PK` with other `SK` prefixes.
  - `GSI_OWNER`: partition `owner_id` (S, the landlord/PM `user_sub`), sort `created_at`
    (N) — newest-first directory listing per owner. Declare
    `attr_types={"created_at": "N"}`.
  - `GSI_PARTY`: partition `party_id` (S), sort `SK` (S) — resolve a tenant from its
    linked PTY party (O(1), no scan).
  - Tenant-meta row fields: `tenant_id`, `owner_id`, `party_id`, `display_name`,
    `email` (normalized via `app/core/normalize.normalize_email`), `phone`
    (`normalize_phone`), `status ∈ {prospect, active, past}`,
    `active_unit_id` (nullable — wired in TEN-002), `created_at`, `updated_at`.

- **Service (new):** `app/services/property_tenant.py` (works with plain `dict`,
  matching the PTY-004 service pattern to avoid `app/models.py` circular imports):
  - `create_tenant(owner_id, *, display_name, email=None, phone=None, party_id=None,
    correlation_id=None) -> dict` — if `party_id` is None, mint a PTY `PERSON` party via
    `party.create_party("PERSON", user_sub=owner_id, correlation_id=…)`
    (`docs/ofbiz/specs/PTY-004` §4.1) and store its id; derive `tenant_id` as
    `sha256(correlation_id)[:32]` when supplied else `uuid4().hex`; conditional
    `put_item(..., ConditionExpression="attribute_not_exists(PK)")` (PTY-004 §2.3) for
    idempotent replay; emit `audit_event("tenant_created", owner_id, …)`.
  - `get_tenant(tenant_id) -> dict | None`.
  - `list_tenants(owner_id, *, status=None, q=None, cursor=None, limit=50) -> dict` —
    query `GSI_OWNER` newest-first with `decode_cursor`/`encode_cursor`; optional
    in-memory `status` filter and case-insensitive `q` substring match on
    `display_name`/`email` (same loose-search posture as `contacts.list_contacts`
    sorting at `app/routers/contacts.py:52-57`); returns
    `{"tenants": [...], "next_cursor": str|None, "count": int}`.
  - `update_tenant(tenant_id, **patch) -> dict` — patch `display_name`/`email`/`phone`/
    `status`; version-guarded `update_item`; emit `audit_event("tenant_updated", …)`.

- **Reuse citations:** PTY-004 PERSON party (`docs/ofbiz/specs/PTY-004` — party spine,
  idempotency, audit, cursor patterns); thin existing contacts directory
  (`app/routers/contacts.py` — listing/sort posture, `require_ui_session` import);
  `app/services/profile.get_profile_identity` (`app/services/profile.py`) to seed
  `display_name`/photo when the tenant maps to a platform user; CUS-001 customer-entity
  shape (`docs/openbankproject/specs/CUS-001`).

**Acceptance Criteria**

- `S.property_tenants_enabled` + `S.property_tenants_table_name` exist, default off.
- `property_tenants` table created by `just restart` with both GSIs and
  `attr_types={"created_at": "N"}`.
- `create_tenant` with no `party_id` mints exactly one `PERSON` party and stores its
  `party_id`; replay with the same `correlation_id` is a no-op (one META row, no second
  audit event).
- `list_tenants(owner_id)` returns only that owner's tenants, newest-first, paginated
  via signed cursor; `status` + `q` filters narrow the result set.
- `get_tenant` / `update_tenant` behave; `update_tenant` bumps `updated_at` and emits an
  audit event.
- Hermetic pytest `tests/test_ten_001_tenant_crud.py` (moto, frozen `T`/`S` patched via
  `object.__setattr__`; `party.create_party` patched/bound to moto — same isolation
  recipe as `tests/test_gap_0223_0224_ec2_host_inventory.py` and PTY-004 §9.1).

**Dependencies:** PTY-004 (PERSON party service + `T.party`). No intra-cluster
dependency.

---

### TEN-002: Tenant profile — employment, income verification (+ doc attachments), emergency contacts, active-unit link

**Type:** Feature | **Priority:** P0 | **Estimate:** 3 days

**Description**

Add the **net-new tenant profile fields** that no current model carries: employment
data, income verification with optional document attachments, a small emergency-contact
list, and the active-unit link. These are the genuine delta over both `contacts.py` and
the PTY PERSON party.

- **DDB (same `property_tenants` table, new `SK` rows under the tenant's `PK`):**
  - `SK = PROFILE` — single profile row holding:
    - `employment`: `{employer_name, job_title, employment_type ∈
      {full_time, part_time, self_employed, contract, unemployed, retired, student},
      start_date, employer_phone}`.
    - `income`: `{annual_income_cents, income_currency, pay_frequency ∈
      {weekly, biweekly, monthly, annual}, verification_status ∈
      {unverified, pending, verified, rejected}, verified_at, verified_by}`.
    - `emergency_contacts`: a small embedded list (cap **5**) of
      `{name, relationship, phone, email}`.
  - `SK = INCOMEDOC#{doc_id}` — one row per income-verification attachment:
    `{doc_id, file_node_path, file_name, content_type, size_bytes, uploaded_at,
    doc_kind ∈ {pay_stub, tax_return, bank_statement, offer_letter, other}}`.

- **Income-document attachments:** files are stored through the existing file-manager
  (`app/services/filemanager.py` `upload_file` at `:2110`) into the owner's namespace
  (e.g. a `Tenant Documents/{tenant_id}/` folder). The tenant service stores only the
  **node path + metadata** (a record-link), never the bytes — mirroring the EVT-011
  record-link approach (`docs/open-property/OPEN_PROPERTY_GAP_ANALYSIS.md:72`, "Documents
  linked to … tenant — EVT-011 record-link"). Dev `/mock/s3/...` URLs are produced by
  filemanager, keeping tenant code env-agnostic (SECOPS-007).

- **Active-unit link:** `set_active_unit(tenant_id, unit_id)` validates the unit exists
  via the **PROP unit service** (PROP cluster), sets `active_unit_id` on the META row,
  and flips tenant `status → active`; clearing it (`unit_id=None`) sets `status → past`
  when no active lease remains.

- **Service additions** (`app/services/property_tenant.py`):
  `get_profile(tenant_id)`, `update_profile(tenant_id, *, employment=None, income=None,
  emergency_contacts=None)` (read-merge-write of the `PROFILE` row so partial updates
  never clobber sibling sub-objects — same read-merge posture as KYC
  `create-packets` in CLAUDE.md), `add_income_doc(...)`, `list_income_docs(tenant_id)`,
  `remove_income_doc(tenant_id, doc_id)`, `set_income_verification(tenant_id, status,
  verifier_sub)`, `set_active_unit(tenant_id, unit_id)`. Emergency-contact list is
  validated for the size cap and required `name` before write. All mutations emit an
  `audit_event` (`tenant_profile_updated`, `tenant_income_doc_added`,
  `tenant_income_verified`).

- **Reuse citations:** PTY-006 relationship model for the emergency-contact concept
  (`docs/ofbiz/specs/PTY-006`, `CONTACT_REL`) — embedded list chosen over party edges
  because PTY-006 is gated on `party_crm_enabled` and emergency contacts are often
  non-party free-text people (rationale, not a fork); `app/services/filemanager.py`
  `upload_file` for attachments; EVT-011 record-link pattern for doc linkage;
  `app/core/normalize` for phone/email on emergency contacts.

**Acceptance Criteria**

- `update_profile` partial updates merge (updating `income` leaves `employment` and
  `emergency_contacts` intact).
- `emergency_contacts` rejects a 6th entry (cap 5) and entries missing `name`.
- `add_income_doc` uploads via filemanager and persists an `INCOMEDOC#` record-link row
  (path + metadata only); `list_income_docs` returns them; `remove_income_doc` deletes
  the row (and best-effort the file node).
- `set_income_verification(..., "verified", verifier)` stamps
  `verification_status="verified"`, `verified_at`, `verified_by`.
- `set_active_unit` validates against the PROP unit service, sets `active_unit_id`, and
  transitions tenant `status`.
- Hermetic pytest `tests/test_ten_002_tenant_profile.py` (moto + filemanager `upload_file`
  patched/stubbed; PROP unit lookup patched).

**Dependencies:** TEN-001; **PROP unit cluster** (active-unit validation); EVT-011
record-link fields (doc linkage); PTY-006 (relationship concept, cited not hard-required).

---

### TEN-003: Tenant historical lease records (LSE integration) + router

**Type:** Feature | **Priority:** P1 | **Estimate:** 2 days

**Description**

Surface a tenant's **historical lease records** and expose the whole cluster over HTTP.

- **Lease history (read-projection over the LSE cluster):** a tenant's leases are NOT
  re-stored on the tenant table — they are owned by the **LSE lease cluster** (each lease
  carries a `tenant_id` ↔ `unit_id` link). The tenant service adds
  `list_tenant_leases(tenant_id, *, cursor=None, limit=50) -> dict` which queries the
  LSE lease service's by-tenant index (LSE cluster GSI) and returns lease summaries
  (`{lease_id, unit_id, status ∈ {upcoming, active, ended}, start_date, end_date,
  monthly_rent_cents, deposit_cents}`) newest-first. If the LSE flag/cluster is absent at
  runtime, the call returns an empty list (graceful, never raises) so TEN can ship ahead
  of, or independently of, a partial LSE rollout.

- **Router (new):** `app/routers/property_tenant.py`, prefix `/ui/property/tenants`,
  tags `["property-tenants"]`, registered in `app/main.py` next to the contacts router.
  Every endpoint applies the `if not S.property_tenants_enabled: raise
  HTTPException(503, …)` guard. **Route-order caution** (FastAPI first-match-wins, same
  caution as PTY-006 §8 and the KYC `/templates`-before-`/{id}` gotcha in CLAUDE.md):
  declare literal-segment routes before `/{tenant_id}` dynamic routes.

  | Method | Path | Body | Notes |
  |---|---|---|---|
  | POST   | `/ui/property/tenants` | `CreateTenantIn` | 201; mints/links PERSON party |
  | GET    | `/ui/property/tenants` | query `status?,q?,cursor?,limit?` | directory list |
  | GET    | `/ui/property/tenants/{tenant_id}` | — | 404 if absent |
  | PATCH  | `/ui/property/tenants/{tenant_id}` | `UpdateTenantIn` | meta patch |
  | GET    | `/ui/property/tenants/{tenant_id}/profile` | — | profile sub-record |
  | PUT    | `/ui/property/tenants/{tenant_id}/profile` | `TenantProfileIn` | merge update |
  | POST   | `/ui/property/tenants/{tenant_id}/income-docs` | multipart file + `doc_kind` | attach |
  | GET    | `/ui/property/tenants/{tenant_id}/income-docs` | — | list |
  | DELETE | `/ui/property/tenants/{tenant_id}/income-docs/{doc_id}` | — | 204 |
  | PUT    | `/ui/property/tenants/{tenant_id}/active-unit` | `{unit_id}` | link/clear |
  | GET    | `/ui/property/tenants/{tenant_id}/leases` | query `cursor?,limit?` | lease history |

- **Models (new, `app/models.py`):** `CreateTenantIn`, `UpdateTenantIn`,
  `TenantProfileIn` (employment/income/emergency-contacts), `TenantOut`, `TenantListOut`,
  `TenantLeaseSummaryOut`, `TenantLeaseListOut`. Service-layer stays dict-based;
  conversions happen in router helpers (`_item_to_tenant_out`, PTY-004 §4.3 pattern).

- **Reuse citations:** LSE lease cluster (lease-by-tenant index, lease summary fields);
  PTY-004 §4.2 router + flag-guard + `_item_to_*_out` helper patterns;
  `app/routers/contacts.py:12` for the `require_ui_session` import + 404/CSRF conventions.

**Acceptance Criteria**

- All endpoints return 503 with the flag off; 200/201/204 with it on (cookie auth +
  CSRF on writes).
- `GET …/{tenant_id}/leases` returns the tenant's leases newest-first from the LSE
  cluster; returns `[]` (no error) when LSE is unavailable.
- Route order verified: `GET /ui/property/tenants` (list) and the literal sub-paths are
  not shadowed by `/{tenant_id}`.
- `POST …/income-docs` accepts multipart and round-trips via the TEN-002 service.
- Hermetic pytest `tests/test_ten_003_tenant_router.py` (route handlers called directly,
  collaborators + LSE lease lookup patched — KYC-router-test style from CLAUDE.md).

**Dependencies:** TEN-001, TEN-002; **LSE lease cluster** (lease-by-tenant history);
PROP unit cluster (transitively, via active-unit + lease unit refs).

---

### TEN-004: Frontend — tenant directory + tenant profile page

**Type:** Feature | **Priority:** P1 | **Estimate:** 3 days

**Description**

Build the landlord/PM-facing UI for the tenant cluster.

- **Types + API wrappers:** add tenant interfaces to `frontend/src/api/types.ts`
  (mirroring the TEN-003 Pydantic models) and an endpoint module
  `frontend/src/api/endpoints/propertyTenants.ts` using the shared axios instance
  (`frontend/src/api/client.ts`, which attaches CSRF + handles 401), with React Query
  hooks (`useQuery`/`useMutation`/`useInfiniteQuery`) per the frontend conventions in
  CLAUDE.md.

- **Tenant directory page** (`frontend/src/pages/property/tenants/TenantsPage.tsx`):
  searchable/filterable table of tenants (`status` chips prospect/active/past, text
  search `q`), cursor-based "load more", and a "New Tenant" dialog (React Hook Form +
  Zod) that posts `CreateTenantIn`. Empty/loading/error states. Route
  `/property/tenants` added to `frontend/src/App.tsx` (lazy-loaded).

- **Tenant profile page**
  (`frontend/src/pages/property/tenants/TenantProfilePage.tsx`, route
  `/property/tenants/:tenantId`): tabbed/sectioned view —
  (1) **Identity** (name/email/phone, linked party, status, active unit);
  (2) **Employment** (employer, title, type, start date);
  (3) **Income** (annual income, frequency, verification badge +
  "Mark verified" action) with an **income-document** uploader
  (reuse the file-upload UX; lists `INCOMEDOC#` attachments with download + delete);
  (4) **Emergency contacts** (add/remove rows, cap 5);
  (5) **Lease history** (read-only table from `…/leases`, status badges, rent/deposit,
  links into the LSE lease detail page when present).

- **Reuse citations:** shadcn/ui primitives + `DataTable` pattern used by existing
  directory pages (e.g. contacts/files pages under `frontend/src/pages/`);
  `FilePickerDialog`/upload UX precedent from the messaging/newsfeed file-share work
  (MEMORY.md "File share messaging"); the contacts page as the closest existing
  directory analogue.

**Acceptance Criteria**

- `/property/tenants` lists tenants with working search, status filter, pagination, and
  a New-Tenant create flow.
- `/property/tenants/:tenantId` renders all five sections; employment/income/emergency
  edits persist via PUT `…/profile`; income-doc upload/list/delete works; "Mark
  verified" flips the income verification badge.
- Lease-history section renders the tenant's leases (empty state when none / LSE off).
- With `PROPERTY_TENANTS_ENABLED` off, the API returns 503 and the pages show a clean
  "feature disabled" state (no crash).
- E2E spec `frontend/e2e/property-tenants.spec.ts`: directory CRUD + filter/search,
  profile edit, income-doc attach, emergency-contact add/remove, lease-history render
  (cookie-auth + CSRF via `injectAuth`/`page.request`, per CLAUDE.md E2E patterns).

**Dependencies:** TEN-001, TEN-002, TEN-003; **PROP** (unit picker for active-unit),
**LSE** (lease-history links).
