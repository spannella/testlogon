# OBP Tier-2 — Customer Entity + Cards + Financial Products (prefix `CUS`)

Derived from `docs/openbankproject/OBP_GAP_ANALYSIS.md` (Tier 2, §C/§D). Open Bank
Project models a **first-class Customer** (`customer_number`, legal name, dob, mobile,
email, KYC status, branch) plus typed **customer attributes**, a **user↔customer link**,
bidirectional **customer messages** (staff↔customer), **Cards** as a managed resource
(list/create/status/attributes), and **financial Products / Product Collections** —
none of which exist as standalone entities in testlogon today.

What testlogon already owns and these tickets reuse (never fork):
- **Identity / case lifecycle** lives only inside a KYC *case*: `app/services/kyc_cases.py`
  (`KycCaseStore`, optimistic-`version` conditional `update_item`, `OWNER#`/`STATUS#` GSIs,
  `_emit_kyc_event_safe`) + `app/routers/kyc_cases.py` (prefix `/v1/kyc/cases`,
  `_require_admin_or_root`). The case carries identity but is **not** a reusable customer
  object, and its "request more info" message (`request_more_info` →
  `_ensure_request_info_ticket_message`, `kyc.case.needs_info`, `app/routers/kyc_cases.py:710-731,1588`)
  is **one-way admin→user**. KYC docs/checks/media/status are HAVE
  (`app/routers/kyc_documents.py`) — these tickets **depend on** them for the customer's
  `kyc_status`, they do not re-implement them.
- **Payment methods (cards) already stored** as `PM#{pm_id}` rows on the `billing` table
  (`app/routers/billing.py:765` `pm_sk`, `:769` `list_payment_methods_ddb`, `:928` the
  `brand/last4/exp_month/exp_year/priority` card item, `:784` `set_default_pm`). These are
  Stripe-attached and have **no status lifecycle and no attributes** — the cards-as-resource
  delta layers status + attributes over these same `PM#` rows, never duplicating them.
- **Catalog / SKU analogue** for products: `app/routers/catalog.py` (prefix `/ui/catalog`,
  `T.catalog` single-table `PK`/`SK`, `CAT#`/`ITEM#`/`REVIEW#`, `cat_pk`/`item_pk`,
  `create_item` at `:352`, reorder/stock/search). Financial Products + Collections reuse
  these patterns (single-table, position/reorder, search) on a new `financial_products` table.
- **Messages / notifications**: `app/services/alerts.py` — `write_alert(user_sub, event=,
  outcome=, title=, details=, ...)` (`:356`, writes `T.alerts` + SSE), `audit_event` (`:644`),
  `send_alert_email` (`:459`). Bidirectional customer messages reuse `write_alert` for the
  staff→customer notification leg (dev logs / prod SES via SECOPS-007 parity).
- **Ledger / wallet primitives** for any money math: `app/services/billing_shared.py`
  (`user_pk`, `ddb_get`/`ddb_put`/`ddb_query_pk`/`ddb_update`).

This file authors **5 tickets, CUS-001..CUS-005**, in dependency order.

---

## Cross-cutting constraints

- **Additive + flag-gated, default OFF.** New flag `CUSTOMER_ENTITY_ENABLED`
  (`S.customer_entity_enabled`, env `CUSTOMER_ENTITY_ENABLED`, default `false`) gates the
  customer/messages/cards surface; financial products get their own
  `FINANCIAL_PRODUCTS_ENABLED` (`S.financial_products_enabled`, default `false`). With a flag
  off, every new endpoint 404/503s, no startup task runs, and the existing KYC/billing/catalog
  endpoints are untouched.
- **SECOPS-007 dev/prod parity.** One code path for dev (DynamoDB Local + moto + mock KMS) and
  prod (real DynamoDB/SES). No `if S.dev_mode` business-logic branches in the customer/card/
  product engines — only the existing provider abstractions (Stripe in `billing.py`, SES in
  `alerts.send_alert_email`) decide mock-vs-real underneath, exactly as they do today.
- **New feature checklist** (per CLAUDE.md "Adding a new feature"): Pydantic models in
  `app/models.py`; services `app/services/customers.py`, `app/services/cards_resource.py`,
  `app/services/financial_products.py`; routers `app/routers/customers.py`,
  `app/routers/financial_products.py` registered in `app/main.py`; `TableDef` entries in
  `scripts/local-ddb-init.py` (**numeric GSI sort keys need `attr_types={...:"N"}`** —
  CLAUDE.md gotcha); FE types/endpoints/page; pytest; `docs/file-reference.md`.
- **Auth.** Customer self-service endpoints use `Depends(require_ui_session)` (cookie + CSRF,
  the same dep `catalog.py`/`billing.py` use). Staff/admin customer-management + message-send
  endpoints reuse `_require_admin_or_root` semantics from `app/routers/kyc_cases.py:2212`
  (admin/root only). Card mutation is owner-scoped (the `PM#` row's `user_sub`).
- **Optimistic concurrency.** Mutable entities (customer META, card status, product META) carry
  an integer `version` and use conditional `update_item` (`version = :expected_version`) exactly
  as `KycCaseStore.update_case_status` (`app/services/kyc_cases.py:209-233`) does — a stale write
  raises a `*ConflictError` → 409.
- **Audit everything.** Every state change emits `audit_event(event, actor_sub, request, ...)`
  to `T.alerts` (`from app.services.alerts import audit_event`): `customer.created`,
  `customer.updated`, `customer.attribute_set`, `customer.linked`, `customer.message_sent`,
  `card.created`, `card.status_changed`, `card.attribute_set`, `product.created`,
  `product.collection_updated`.
- **PII / no plaintext on the wire.** Customer mobile/email/dob are stored as-is (these are
  contact fields, not secrets) but never logged; card numbers are **never** introduced — the
  card resource keys off the existing `PM#` rows which only hold `brand/last4/exp_*` (no PAN),
  preserving the current no-PAN invariant.

---

### CUS-001: Customer entity — DDB model, table, flag + CRUD + typed attributes
**Type**: Backend (data model + endpoints)
**Priority**: P1 (foundation — everything else hangs off the customer)
**Estimate**: 3 days

**Description**
Introduce a first-class **Customer** decoupled from any single KYC case, plus a typed
attribute KV store. Identity today lives only inside a KYC case (`app/services/kyc_cases.py`);
this lifts the durable customer fields into a reusable entity that a case (and cards, messages,
products) can reference.

- **Pydantic models** (`app/models.py`):
  - `CustomerCreateIn { legal_name:str, date_of_birth:str|None, mobile_phone:str|None,
    email:str|None, branch_id:str|None }` (no `customer_number` — server-minted).
  - `CustomerPatchIn` (all optional, same fields + `kyc_status:str|None`).
  - `CustomerOut { customer_id, customer_number, legal_name, date_of_birth, mobile_phone,
    email, kyc_status, branch_id, created_at, updated_at, version }`.
  - `CustomerAttributeSetIn { name:str, type:Literal["STRING","INTEGER","DOUBLE","DATE_WITH_DAY"],
    value:str }` (mirrors OBP's attribute types) and `CustomerAttributeOut { attribute_id, name,
    type, value, created_at }`.
- **Service** `app/services/customers.py` — a `CustomerStore` dataclass (default `_table=T.customers`)
  mirroring `KycCaseStore`'s shape (`app/services/kyc_cases.py:116`):
  - `create_customer(...)` mints `customer_id = f"cust_{uuid4().hex[:12]}"` and a human
    `customer_number` (zero-padded monotonic-ish, e.g. `now_ts()`-seeded), writes META, returns item.
  - `get_customer`, `update_customer(... expected_version)` (conditional `update_item` on
    `version`, raising `CustomerConflictError` on mismatch — copy `kyc_cases.py:209-233`).
  - `set_attribute` / `list_attributes` / `delete_attribute` writing `ATTR#{attribute_id}` rows.
  - `kyc_status` defaults to `"none"`; CUS-005-adjacent: it is **set from** the linked KYC case's
    status (CUS-002), not recomputed here.
- **DDB table** `customers` (`TableDef` in `scripts/local-ddb-init.py`), single-table like
  `T.kyc_cases`:
  - PK `pk = CUST#{customer_id}`, SK `sk` ∈ `{ "META", "ATTR#{attribute_id}" }`.
  - GSI `GSI_NUMBER` on `gsi_number_pk = "CUSTNUM"` (S) / `customer_number` (S) — lookup by number.
  - GSI `GSI_BRANCH` on `gsi_branch_pk = BRANCH#{branch_id}` (S) / `created_at` (N) —
    **declare `attr_types={"created_at":"N"}`** (CLAUDE.md numeric-GSI gotcha) — list by branch.
- **Router** `app/routers/customers.py` (prefix `/ui/customers`, registered in `app/main.py`,
  gated by `S.customer_entity_enabled` → 404 when off):
  - `POST /ui/customers` (admin/root, `_require_admin_or_root`) → create.
  - `GET /ui/customers/{customer_id}`, `GET /ui/customers?branch_id=&cursor=` (admin/root).
  - `PATCH /ui/customers/{customer_id}` (admin/root, requires `If-Match`/`expected_version`).
  - `PUT /ui/customers/{customer_id}/attributes` (set), `GET .../attributes`,
    `DELETE .../attributes/{attribute_id}`.
  - **Route ordering:** static segments (`/attributes`) declared so they cannot be captured by a
    `/{customer_id}` dynamic param (CLAUDE.md FastAPI declaration-order gotcha).
- Every mutation emits `audit_event("customer.created"|"customer.updated"|"customer.attribute_set",
  actor_sub, request, customer_id=...)`.

**Acceptance Criteria**
- Flag off → all `/ui/customers*` routes 404; no `customers` table access; KYC/billing/catalog
  endpoints unchanged.
- Create returns a unique `customer_id` + `customer_number`; `GET` by id and lookup-by-number
  (via `GSI_NUMBER`) both resolve it.
- `PATCH` with a stale `expected_version` → 409 (`CustomerConflictError`); correct version bumps
  `version` by 1 and `updated_at`.
- Attribute set/list/delete round-trips for all four `type` values; value persisted as a string,
  `type` preserved.
- Non-admin caller → 403 on all admin endpoints.
- Pytest `tests/test_cus_001_customer_entity.py` (offline; moto `customers` table bound to frozen
  `T.customers` via `object.__setattr__`; frozen `S.customer_entity_enabled` toggled; route handlers
  called directly).

**Dependencies**: none (foundation).

---

### CUS-002: User↔customer link + bidirectional customer messages thread
**Type**: Backend (link + threaded messaging)
**Priority**: P1
**Estimate**: 3 days

**Description**
Link a platform `user_sub` to a customer record, and add a **two-way** customer message thread
(staff↔customer). The KYC case's "request more info" message is one-way admin→user today
(`app/routers/kyc_cases.py:710-731`, `request_more_info` → `kyc.case.needs_info`); this adds a
durable thread where the customer can reply.

- **User↔customer link** (in `app/services/customers.py`):
  - `link_user(customer_id, user_sub, actor_sub)` writes `LINK#USER#{user_sub}` on the customer
    PK **and** a reverse pointer row `pk=CUSTLINK#{user_sub}, sk=META` → `{customer_id}` on the
    `customers` table (so a logged-in user resolves *their* customer in one `get_item`).
  - `resolve_customer_for_user(user_sub)` reads the reverse pointer.
  - Linking back-fills `customer.kyc_status` from the user's latest KYC case (read via
    `KycCaseStore` / `OWNER#{user_sub}` GSI — see `app/services/kyc_cases.py:67`,
    `gsi_owner_pk`), wiring the HAVE KYC status onto the customer (one-directional read,
    no KYC fork).
- **Threaded messages** (new `app/services/customer_messages.py`):
  - Storage on the `customers` table (single-table): `pk=CUST#{customer_id},
    sk=MSG#{ts:013d}#{message_id}` — chronologically ordered, query-by-PK gives the thread.
  - `post_message(customer_id, *, author_sub, author_role:Literal["STAFF","CUSTOMER"], body)`
    writes the row, then (staff→customer leg) fires `write_alert(user_sub=<linked user>,
    event="customer.message", outcome="info", title="New message from support",
    details={customer_id, message_id, preview})` — reusing `app/services/alerts.py:356`
    (dev logs / prod SES + SSE, SECOPS-007 parity). Customer→staff leg emits
    `audit_event("customer.message_sent", author_sub, ...)` and (optionally) a staff alert via
    the same helper.
  - `list_messages(customer_id, cursor=, limit=)` — newest-first, cursor via
    `app/core/cursor.py`.
- **Models** (`app/models.py`): `CustomerLinkIn { user_sub }`, `CustomerMessageCreateIn { body }`,
  `CustomerMessageOut { message_id, author_sub, author_role, body, created_at }`,
  `CustomerMessageListOut { messages, cursor }`.
- **Router** (`app/routers/customers.py`):
  - `POST /ui/customers/{customer_id}/link` (admin/root) → link a user.
  - `GET /ui/customers/me` (`require_ui_session`) → the caller's linked customer via
    `resolve_customer_for_user` (404 if unlinked).
  - `POST /ui/customers/{customer_id}/messages` — **dual auth**: admin/root posts as `STAFF`;
    the linked user (cookie session) posts as `CUSTOMER` (ownership checked against the link).
  - `GET /ui/customers/{customer_id}/messages` — same dual-auth ownership gate.

**Acceptance Criteria**
- Flag off → all routes 404.
- `link_user` makes both `GET /ui/customers/me` (as the user) and the customer's `LINK#` row
  resolve; double-link is idempotent (same pointer).
- Linking sets `customer.kyc_status` from the user's latest KYC case status (verified against a
  seeded case).
- A staff message creates an alert for the linked user (assert `write_alert` invoked /
  `T.alerts` row written); a customer reply is stored and visible to staff; thread lists
  newest-first and paginates via cursor.
- A user who is **not** linked to the customer → 403 on that customer's messages.
- Pytest `tests/test_cus_002_customer_messages.py` (offline; moto `customers` + frozen
  `T.alerts`; `KycCaseStore` read stubbed or seeded; handlers called directly).

**Dependencies**: CUS-001.

---

### CUS-003: Cards as a managed resource — list/create/status lifecycle + attributes
**Type**: Backend (resource layer over `PM#` rows)
**Priority**: P2
**Estimate**: 2.5 days

**Description**
Expose **Cards** as a managed resource with a status lifecycle and typed attributes, layered
over the **existing** `PM#{pm_id}` payment-method rows on the `billing` table
(`app/routers/billing.py:765` `pm_sk`, `:769` `list_payment_methods_ddb`, `:928` the card item
with `brand/last4/exp_month/exp_year`). The current store has **no status and no attributes** —
this adds them without duplicating the card row or ever introducing a PAN.

- **Card status lifecycle** `CardStatus ∈ {ACTIVE, INACTIVE, FROZEN, CANCELLED}` (default
  `ACTIVE` for existing/new `PM#` rows that lack a status). Allowed transitions:
  `ACTIVE↔FROZEN`, `ACTIVE↔INACTIVE`, `{ACTIVE,INACTIVE,FROZEN}→CANCELLED` (terminal).
  Status + attributes are stored **on the same `PM#` row** (additive fields `card_status`,
  `card_status_at`, `card_version`) and in sibling `pk=USER#{user_id}, sk=CARDATTR#{pm_id}#{name}`
  rows on the `billing` table — so the billing table stays single-table and no new card table is
  needed.
- **Service** `app/services/cards_resource.py`:
  - `list_cards(user_id)` → wraps `list_payment_methods_ddb` (`billing.py:769`), projecting
    `card_id (=payment_method_id), brand, last4, exp_month, exp_year, label, is_default
    (== current_default_pm), card_status (default "ACTIVE")`.
  - `create_card(...)` is a **thin delegate** — it does NOT re-implement Stripe attach; it calls
    the existing add-card flow (`billing.py:add_card`) semantics / returns the created `PM#`
    projection, then stamps `card_status="ACTIVE"`. (No second Stripe `PaymentMethod.attach`,
    mirroring the "ONE mechanism" rule.)
  - `set_card_status(user_id, card_id, new_status, *, expected_version, actor_sub)` —
    conditional `ddb_update` on `card_version` (copy the optimistic pattern), validates the
    transition table, emits `audit_event("card.status_changed", ...)`. A `FROZEN`/`INACTIVE`/
    `CANCELLED` card is excluded from being auto-selected as a default and (follow-up hook)
    rejected by charge paths.
  - `set_card_attribute` / `list_card_attributes`.
- **Models** (`app/models.py`): `CardOut { card_id, brand, last4, exp_month, exp_year, label,
  is_default, card_status, card_version }`, `CardStatusUpdateIn { status, expected_version }`,
  `CardAttributeSetIn { name, type, value }`, `CardAttributeOut`.
- **Router** (extend `app/routers/customers.py` or a small `cards` sub-router, gated by
  `S.customer_entity_enabled`, all `require_ui_session`, owner-scoped):
  - `GET /ui/cards` → list.
  - `POST /ui/cards` → create (delegate to add-card).
  - `PATCH /ui/cards/{card_id}/status` → lifecycle transition (409 on stale version, 422 on
    illegal transition).
  - `PUT /ui/cards/{card_id}/attributes`, `GET /ui/cards/{card_id}/attributes`.
- **No PAN, ever:** the resource only reads/writes `brand/last4/exp_*/status/attributes` already
  present on (or additive to) the `PM#` row.

**Acceptance Criteria**
- Flag off → `/ui/cards*` routes 404.
- `GET /ui/cards` returns existing `PM#` rows for the user with `card_status` defaulting to
  `ACTIVE` for rows lacking it; `is_default` matches `current_default_pm` (`billing.py:779`).
- `PATCH .../status`: a legal transition bumps `card_version` + sets `card_status`/`card_status_at`;
  an illegal transition (e.g. `CANCELLED→ACTIVE`) → 422; a stale `expected_version` → 409.
- Card attribute set/list round-trips all four `type`s.
- A card the caller does not own → 404/403 (ownership via `user_pk(user_id)` partition).
- No code path introduces a PAN; the original `PM#` row's billing fields are untouched except the
  additive `card_*` fields.
- Pytest `tests/test_cus_003_cards_resource.py` (offline; moto `billing` table bound to frozen
  `T.billing`; Stripe attach not exercised — create path stubbed/seeded `PM#` row; frozen `S` flag).

**Dependencies**: CUS-001 (flag + audit conventions). Independent of CUS-002.

---

### CUS-004: Financial Products + Product Collections (catalog-pattern reuse)
**Type**: Backend (product model + collections)
**Priority**: P2
**Estimate**: 3 days

**Description**
Add a **financial-product** model (with typed attributes) and **product collections**, reusing
the catalog single-table patterns in `app/routers/catalog.py` (`T.catalog` `PK`/`SK`,
`cat_pk`/`item_pk`, `create_item` at `:352`, reorder at `:421`, search at `:465`). A financial
product is the bank-product analogue of a catalog SKU (e.g. a savings account product, a card
product), and a collection is an ordered grouping (analogous to a catalog category).

- **Pydantic models** (`app/models.py`):
  - `FinancialProductCreateIn { product_code:str, name:str, parent_product_code:str|None,
    category:str|None, family:str|None, super_family:str|None, more_info_url:str|None,
    description:str|None }` (`product_code` is the OBP product key).
  - `FinancialProductPatchIn` (optional fields).
  - `FinancialProductOut { product_id, product_code, name, parent_product_code, category, family,
    super_family, more_info_url, description, created_at, updated_at, version }`.
  - `ProductAttributeSetIn { name, type, value }` + `ProductAttributeOut`.
  - `ProductCollectionUpsertIn { collection_code:str, name:str, product_codes:list[str] }` +
    `ProductCollectionOut { collection_code, name, product_codes, updated_at }`.
- **Service** `app/services/financial_products.py` on a new `financial_products` table
  (single-table, `PK`/`SK` like `T.catalog`):
  - Product META: `PK=PRODUCT#{product_code}, SK=META` (keyed by the natural `product_code`, so
    `parent_product_code` references resolve directly).
  - Attributes: `PK=PRODUCT#{product_code}, SK=ATTR#{attribute_id}`.
  - Collections: `PK=COLLECTION#{collection_code}, SK=META` holding the ordered `product_codes`
    list (upsert = read-merge-write of the list, deduped, order-preserving — mirrors the
    KYC `template_packets` read-merge-write in CLAUDE.md).
  - `create_product` / `get_product` / `update_product(... expected_version)` (conditional
    `version` update) / `list_products(category=, family=, cursor=)`.
  - `set_attribute` / `list_attributes`; `upsert_collection` / `get_collection` /
    `list_collections`; `add_to_collection` / `remove_from_collection`.
  - GSI `GSI_CATEGORY` on `gsi_cat_pk = CATEGORY#{category}` (S) / `created_at` (N) —
    **`attr_types={"created_at":"N"}`** — to list products by category without scanning.
- **Router** `app/routers/financial_products.py` (prefix `/ui/financial-products`, registered in
  `app/main.py`, gated by `S.financial_products_enabled` → 404 when off):
  - `POST /ui/financial-products` (admin/root), `GET /ui/financial-products`,
    `GET /ui/financial-products/{product_code}`, `PATCH /ui/financial-products/{product_code}`.
  - `PUT /ui/financial-products/{product_code}/attributes`, `GET .../attributes`.
  - `PUT /ui/financial-products/collections/{collection_code}` (upsert),
    `GET /ui/financial-products/collections`, `GET .../collections/{collection_code}`.
  - **Route ordering:** the static `/collections` segment is declared **before**
    `/{product_code}` so the literal isn't captured as a path param (CLAUDE.md FastAPI gotcha,
    same lesson as KYC `/schedules` before `/{export_id}`).

**Acceptance Criteria**
- Flag off → all `/ui/financial-products*` routes 404; the catalog (`/ui/catalog`) is unaffected.
- Create/get/patch/list products round-trip; `PATCH` honors optimistic `version` (409 on stale);
  `category` filter lists via `GSI_CATEGORY` (no scan).
- Product attributes set/list round-trip all four `type`s.
- Collection upsert is order-preserving + deduped; `add_to_collection`/`remove_from_collection`
  mutate the ordered list; listing collections returns each with its `product_codes`.
- `GET /ui/financial-products/collections` resolves to the collections handler, not the
  `/{product_code}` handler (route-ordering verified).
- Non-admin caller → 403 on write endpoints.
- Pytest `tests/test_cus_004_financial_products.py` (offline; moto `financial_products` table
  bound to frozen `T.financial_products`; frozen `S.financial_products_enabled`; handlers called
  directly).

**Dependencies**: CUS-001 (shared attribute-type enum, audit conventions, flag pattern).
Independent of CUS-002/003.

---

### CUS-005: Frontend surface + DDB init + end-to-end tests + docs
**Type**: Full-stack (frontend + wiring + tests)
**Priority**: P3
**Estimate**: 3.5 days

**Description**
Wire the customer/cards/products backend into the React app, finalize the DynamoDB table
declarations + main-app registration, and add the test + doc deliverables that the
per-feature tickets stub.

- **DDB init** (`scripts/local-ddb-init.py`): finalize `TableDef`s for `customers` and
  `financial_products` with all GSIs and **`attr_types={"created_at":"N"}`** on every numeric
  GSI sort key (CLAUDE.md gotcha — missing this → `ValidationException` at query time). Add
  `S.customers_table_name` / `S.financial_products_table_name` to `app/core/settings.py` and the
  `T.customers` / `T.financial_products` handles to `app/core/tables.py`. Register the
  `customers` and `financial_products` routers in `app/main.py`.
- **Frontend** (`frontend/src/`):
  - Types in `api/types.ts` mirroring the new models; endpoint wrappers in
    `api/endpoints/customers.ts` + `api/endpoints/financialProducts.ts` (axios via
    `api/client.ts`, CSRF handled).
  - `pages/customers/CustomersPage.tsx` (admin: list/create/edit a customer, attributes panel,
    link a user, the **two-way message thread** UI reusing the messaging component patterns),
    plus a customer-facing `GET /ui/customers/me` view with their message thread.
  - `pages/cards/CardsPage.tsx` — list cards with status badges + a status-transition control
    (Freeze / Unfreeze / Cancel) and attributes; reuse the billing payment-method components.
  - `pages/financial-products/ProductsPage.tsx` (admin: products + collections CRUD).
  - Routes in `App.tsx` (lazy-loaded); nav entries gated on the feature flags surfaced via
    config so they hide when the backend flags are off.
- **E2E tests** `frontend/e2e/customers-cards-products.spec.ts` covering: customer CRUD +
  attributes API, user-link + `GET /ui/customers/me`, bidirectional message thread (staff post →
  customer alert → customer reply → staff sees it), card status lifecycle + attributes, financial
  product + collection CRUD, and route-ordering (`/collections` not captured by `/{product_code}`).
  Reuse the admin/cookie + CSRF helpers from `e2e_admin_session_setup.py` (root/charlie_admin/alice).
- **Docs**: update `docs/file-reference.md` (new services/routers/pages) and `docs/dynamodb.md`
  (new `customers` + `financial_products` schemas + GSIs).

**Acceptance Criteria**
- `just restart` recreates the `customers` + `financial_products` tables with all declared GSIs;
  no `ValidationException` on any numeric-GSI query.
- With flags **on**, all CUS-001..004 API flows work end-to-end through the UI; with flags
  **off**, the nav entries are hidden and the routes 404.
- The bidirectional thread works in the browser: a staff message raises an in-app alert for the
  linked user, and the user's reply appears in the staff thread view.
- Card status badges reflect `card_status`; Freeze/Cancel transitions update the badge and persist.
- E2E spec `customers-cards-products.spec.ts` passes under `just e2e` (1 worker, Chromium);
  route-ordering assertion green.
- `docs/file-reference.md` + `docs/dynamodb.md` updated.

**Dependencies**: CUS-001, CUS-002, CUS-003, CUS-004.
