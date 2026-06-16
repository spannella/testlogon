# OBP Tier-2 — Banking Data Model: Banks, Accounts & Transactions (prefix `ACC`)

Derived from `docs/openbankproject/OBP_GAP_ANALYSIS.md` (Tier 2, §A/§B). Open Bank
Project's core data model is **Bank → Account → Transaction**, with field-level
**Views** delegating who can see what, and **transaction metadata** (tags/comments/
narrative/geotag/images) layered on top of immutable transaction rows.

**testlogon has NO bank-account model today.** Money is a single-entry billing ledger
plus a per-user wallet row (`app/services/billing_shared.py:173` `WALLET_SK`,
`get_wallet_balance`, `apply_wallet_delta`; `app/services/billing_shared.py:224`
`new_ledger_entry` / `ledger_sk`), surfaced by per-user endpoints
(`app/routers/billing.py:840` `GET /billing/balance`, `app/routers/billing.py:2448`
`GET /billing/ledger`). The gap analysis is explicit: *"money is a per-user `WALLET`
row (`billing_shared.py:173`), not an account"* and *"single-entry ledger
(`new_ledger_entry`); no per-account view / date-range pagination / running balance"*
(§A/§B rows).

So **ACC adds the bank/account/transaction abstraction ADDITIVELY, layered OVER the
existing wallet/ledger** — it never forks billing. The central design decision: **one
default Account per user is a thin projection of that user's existing wallet + ledger
rows** (the account holds metadata and ownership; the money still lives in
`T.billing`). Banks are a tiny lookup catalog. The per-account transaction list is a
**read-side projection** of the EXISTING `LEDGER#` rows into a typed, date-ranged,
cursor-paginated shape with a running `new_balance`. Metadata enrichment and co-access
are net-new sub-rows / grants that hang off the account + transaction ids.

This file authors **5 tickets, ACC-001..ACC-005**, in dependency order.

---

## Cross-cutting constraints (apply to every ACC ticket)

1. **Additive + flag-gated, default OFF.** New settings on `app/core/settings.py`
   (`S`), all default `false`:
   - `banking_accounts_enabled` (env `BANKING_ACCOUNTS_ENABLED`) — gates ACC-001/002/003.
   - `banking_account_metadata_enabled` (env `BANKING_ACCOUNT_METADATA_ENABLED`) —
     gates ACC-003 (sub-gate; requires accounts enabled).
   - `banking_account_views_enabled` (env `BANKING_ACCOUNT_VIEWS_ENABLED`) — gates the
     ACC-004 co-access read path (and depends on the VEW `account_views_enabled` flag;
     see Dependencies).
   With a flag off, the new router(s) 404 and the new tables are never read/written.
   **Every existing billing/wallet/ledger endpoint is untouched** — ACC is read-mostly
   over them.

2. **Never fork billing — the wallet/ledger is the source of truth for money.** The
   Account entity carries NO balance of its own for the default (wallet-backed) account:
   `GET /ui/banking/accounts/{id}/balance` reads through to
   `billing_shared.get_wallet_balance(T.billing, user_pk(owner_sub))`
   (`billing_shared.py:176`). Transaction rows are NEVER re-written into a second store —
   the projection (ACC-002) reads the live `LEDGER#` rows. No money math is duplicated;
   ACC has no debit/credit code.

3. **SECOPS-007 dev/prod parity.** One code path for dev (DynamoDB Local + moto +
   in-process S3) and prod (real DynamoDB / S3), with NO `if S.dev_mode` business-logic
   branches. S3 image writes (ACC-003) go through the centralized factory
   `app.core.aws_clients.s3_client()` (`app/core/aws_clients.py:114`), which already
   handles dev (moto in-process) vs prod (real S3) transparently — the dev mock URL
   shape (`/mock/s3/...`) mirrors the existing messaging/file-share pattern.

4. **New-feature checklist** (per CLAUDE.md "Adding a new feature"): Pydantic models in
   `app/models.py`; service in `app/services/banking_accounts.py` (+ `banking_banks.py`
   if cleaner); router `app/routers/banking_accounts.py` registered in `app/main.py`
   (inside `if S.banking_accounts_enabled:`); `TableDef` entries in
   `scripts/local-ddb-init.py` (numeric GSI sort keys MUST declare
   `attr_types={...: "N"}` or queries throw `ValidationException`); FE types/endpoints/
   page; pytest; update `docs/file-reference.md` + `docs/dynamodb.md`.

5. **Cursor pagination is the existing signed scheme.** All list endpoints encode/decode
   their `LastEvaluatedKey` via `app.core.cursor.encode_cursor` / `decode_cursor`
   (`app/core/cursor.py:94,103`) — the HMAC-signed `v2` envelope, NOT a raw base64 key.
   Date-range pagination (ACC-002) loops on `LastEvaluatedKey` because a
   `FilterExpression` does NOT reduce the 1MB page (CLAUDE.md gotcha).

6. **Audit + ownership.** Account mutations emit `audit_event(...)` to `T.alerts`
   (`from app.services.alerts import audit_event`, same helper billing uses). Ownership
   is enforced by the DDB access pattern: account rows are partitioned by the OWNING
   user, and co-owners/co-access are explicit grant rows (ACC-004) — there is no
   cross-user scan that could leak another user's account.

---

### ACC-001: Bank + Account entities — DDB model, table, flag + default-account bootstrap
**Type**: Backend (data model + CRUD endpoints)
**Priority**: P1 (foundation)
**Estimate**: 3 days

**Description**
Introduce the two banking entities as new DynamoDB rows, additively over the
wallet/ledger. Be explicit: testlogon has no bank-account model today — this ticket
creates it.

- **Bank entity** — a tiny lookup catalog. `bank_id` (slug, e.g. `testlogon`),
  `name`, `logo_url`, `short_name`, `website`. For a single-tenant SaaS there is
  effectively ONE seeded "house" bank, but the entity exists so account rows can carry
  a `bank_id` (OBP shape parity). Seed one default bank at startup / via
  `scripts/local-ddb-seed.py`.
- **Account entity** — `account_id` (`uuid4().hex`), `bank_id`, `label`
  (user-editable, e.g. "Wallet"), `account_type` (enum: `WALLET` | `SAVINGS` |
  `EXTERNAL`; default `WALLET`), optional `iban` / `routing_number` /
  `account_number_masked` (free-form, NOT validated as a real IBAN — string only,
  honestly cosmetic for this SaaS), `product_code` (free string, e.g. `default`),
  `currency` (default `usd`, matching the single-currency ledger), `owners` (list of
  user_subs — multi-owner; ACC-004 manages additions), and typed **account
  attributes** as a `list[{name, type, value}]` (OBP "account attributes" shape —
  arbitrary typed key/values like `{"name":"nickname","type":"STRING","value":"…"}`).
- **Default-account mapping (the load-bearing additive design).** Each user gets ONE
  auto-provisioned default account of `account_type=WALLET` whose money is the user's
  EXISTING wallet — i.e. the account is a *projection*, it stores NO balance.
  `ensure_default_account(user_sub)` is idempotent: it creates the `WALLET` account row
  the first time the user touches any banking endpoint (lazy bootstrap), tagging it
  `is_default=True` + `wallet_backed=True` so the balance/transaction projections
  (ACC-002) know to read through to `T.billing`. Non-default accounts (`SAVINGS`/
  `EXTERNAL`) are pure metadata containers (no money path in this tier — explicitly out
  of scope; they exist for OBP shape and future tickets).

**DDB model** — new table `banking_accounts` (single-table). Add `T.banking_accounts`
+ `T.banking_banks` (or fold banks into the same table) to `app/core/tables.py`.
- **Account rows**: `pk=USER#{owner_sub}`, `sk=ACCOUNT#{account_id}`. A GSI
  `GSI_ACCOUNT_BY_ID` keyed `account_id` (S) → enables resolving an account id without
  knowing the owner (needed by co-access reads, ACC-004). Co-owner reverse-index rows
  (`pk=USER#{co_owner_sub}`, `sk=ACCOUNT_REF#{account_id}`) are written by ACC-004 so a
  co-owner can list accounts they share.
- **Bank rows**: `pk=BANK`, `sk=BANK#{bank_id}` (or its own small table).
- Reuse `billing_shared.user_pk` (`billing_shared.py:23`) for the partition value so the
  account partition matches the wallet/ledger partition (both `USER#{sub}`) — making the
  read-through in ACC-002 a same-key sibling query, not a cross-table join.

**Service — `app/services/banking_accounts.py`**:
- `list_banks() -> list[Bank]`; `get_bank(bank_id)`.
- `ensure_default_account(owner_sub) -> Account` (idempotent lazy bootstrap above).
- `create_account(owner_sub, *, label, account_type, bank_id, product_code, currency,
  attributes, iban=None, routing_number=None) -> Account` (non-default only).
- `list_accounts(viewer_sub) -> list[Account]` — owned (`ACCOUNT#`) + shared
  (`ACCOUNT_REF#` → resolve via `GSI_ACCOUNT_BY_ID`).
- `get_account(account_id, *, requester_sub) -> Account` — resolves via
  `GSI_ACCOUNT_BY_ID`, asserts requester is an owner/co-owner (else 404, no leak).
- `update_account(account_id, owner_sub, *, label=None, attributes=None, …)` — owner
  only; conditional update; `account.updated` audit.
- `delete_account` — owner only, refuses the default/wallet-backed account (409:
  "Cannot delete the default wallet account").

**Router — `app/routers/banking_accounts.py`** (prefix `/ui/banking`, registered in
`app/main.py` only inside `if S.banking_accounts_enabled:`). Cookie auth
(`Depends(require_ui_session)`):
```
GET    /ui/banking/banks                       → list_banks
GET    /ui/banking/accounts                     → list_accounts (auto-bootstraps default)
POST   /ui/banking/accounts                     → create_account
GET    /ui/banking/accounts/{account_id}        → get_account
PATCH  /ui/banking/accounts/{account_id}        → update_account
DELETE /ui/banking/accounts/{account_id}        → delete_account
GET    /ui/banking/accounts/{account_id}/balance→ read-through to get_wallet_balance
```
The `/balance` handler returns, for a wallet-backed account, exactly
`billing_shared.get_wallet_balance(T.billing, user_pk(owner_sub))` reshaped as OBP
`{currency, value}` (value = dollars from `wallet_balance_cents`), plus `available` ==
`current` (no holds model in this tier).

**Acceptance Criteria**
- `BANKING_ACCOUNTS_ENABLED=0` → all `/ui/banking/*` routes 404; tables never touched.
- `GET /ui/banking/accounts` for a brand-new user returns exactly one account
  (`is_default=True`, `account_type=WALLET`, `wallet_backed=True`); a second call
  returns the same `account_id` (idempotent bootstrap, no duplicate rows).
- `/balance` for the default account equals the live wallet balance; depositing to the
  wallet (existing flow) is immediately reflected (proves read-through, not a copy).
- Account stores typed `attributes` round-trip; `iban`/`routing_number` persist as
  opaque strings (no validation).
- A non-owner `GET /ui/banking/accounts/{id}` → 404 (ownership enforced via
  `GSI_ACCOUNT_BY_ID` lookup + owner check, no cross-user leak).
- Deleting the default account → 409.
- Numeric GSI sort keys (none required here; `account_id` GSI is `S`) — but if any
  numeric GSI is added, `attr_types` is declared in `local-ddb-init.py`.

**Dependencies**: none (foundation). Cites `billing_shared.py` wallet primitives.

---

### ACC-002: Per-account transaction list — project the EXISTING ledger (running `new_balance`, date-range + cursor)
**Type**: Backend (read-side projection + endpoint)
**Priority**: P1
**Estimate**: 3 days

**Description**
Project the EXISTING single-entry ledger rows into a per-account, date-range-filterable,
**cursor-paginated** transaction list with a **running `new_balance`** and a typed
`amount{currency, value}` — the core OBP "get transactions for account" shape. **No new
money rows are written**; this reads the live `LEDGER#{ts}#{entry_id}` rows
(`billing_shared.py:220-259` `ledger_sk` / `new_ledger_entry`) that already exist in
`T.billing` under `pk=USER#{owner_sub}`.

- **Source rows.** For a wallet-backed account, the transactions ARE that user's ledger
  entries: `T.billing` query `pk=USER#{owner_sub}` + `sk begins_with "LEDGER#"`
  (mirrors `app/routers/billing.py:2451-2453`, which filters `sk.startswith("LEDGER#")`).
  Because `ledger_sk` embeds the timestamp first (`LEDGER#{ts}#{entry_id}`), the natural
  sort key IS chronological — so a DynamoDB range query on `sk` between
  `LEDGER#{from_ts}` and `LEDGER#{to_ts}~` does the date-range filter in the key
  condition (no client-side filter, no missed-page bug). `ScanIndexForward` controls
  newest-first vs oldest-first.
- **Projection** — each ledger item → a `Transaction`:
  - `transaction_id` = the ledger `entry_id`.
  - `account_id` = the (default) account.
  - `type` = ledger `type` (deposit/tip/payout/refund/adjustment/…).
  - `amount` = `{currency: row.currency|"usd", value: cents_to_dollars(amount_cents)}`
    (typed `amount{currency,value}` per scope; sign follows ledger `type`/`state`).
  - `status` = ledger `state` (pending/settled/reversed).
  - `posted_at` = `row.ts`; `description` = `row.reason`; `provider` passthrough.
  - `new_balance` = **running balance** (see below).
- **Running `new_balance` (the real work).** OBP's `new_balance` is the account balance
  *after* each transaction. Compute it deterministically by anchoring on the CURRENT
  wallet balance (`billing_shared.get_wallet_balance`, the authoritative "now") and
  walking the settled ledger **backwards** from newest: `new_balance(newest)` = current
  balance; each older row's `new_balance` = `newer.new_balance − newer.signed_amount`.
  This avoids re-summing from zero and stays consistent with the wallet even if early
  history predates the account. Document that only `state=settled` rows move the running
  balance; `pending`/`reversed` are shown with the carried balance (no movement).
- **Pagination.** Cursor via `encode_cursor(LastEvaluatedKey)` /
  `decode_cursor(cursor)` (`app/core/cursor.py:94,103`). Loop on `LastEvaluatedKey`
  until the requested `limit` of in-range rows is filled (the date range is in the key
  condition, but if any sparse client-side predicate is added it must loop — CLAUDE.md
  "FilterExpression doesn't reduce page size" gotcha). Returns
  `{transactions: [...], cursor: <next|null>}`.

**Service** (in `banking_accounts.py`):
- `list_account_transactions(account_id, *, requester_sub, from_ts=None, to_ts=None,
  limit=50, cursor=None, order="desc") -> {transactions, cursor}` — resolves+authorizes
  the account (ACC-001 `get_account`), queries `T.billing` ledger rows in range, computes
  running `new_balance`, projects, paginates.
- `get_account_transaction(account_id, transaction_id, *, requester_sub) -> Transaction`
  — single-row fetch (needed by ACC-003 metadata).

**Router** (prefix `/ui/banking`):
```
GET /ui/banking/accounts/{account_id}/transactions
      ?from=<unix|iso>&to=<unix|iso>&limit=&cursor=&order=desc|asc
GET /ui/banking/accounts/{account_id}/transactions/{transaction_id}
```

**Acceptance Criteria**
- For the default account, the transaction list == the user's `GET /billing/ledger`
  rows reshaped (same `entry_id`s), proving it's a projection, not a copy.
- `new_balance` of the newest settled transaction equals the live wallet balance; each
  older settled row's `new_balance` chains correctly (`newer − newer.signed_amount`).
- `from`/`to` correctly bound the result set via the `sk` key condition (a row outside
  the range never appears).
- Cursor round-trips through `encode_cursor`/`decode_cursor`; paging the full history in
  pages of N yields every row exactly once, no dup/skip across page boundaries.
- A tampered/foreign cursor (`decode_cursor` returns `None`) → treated as page-1, never
  500.
- Non-owner request → 404 (ownership via ACC-001).

**Dependencies**: **ACC-001** (account resolution/ownership + default-account mapping).
Cites `billing_shared.new_ledger_entry`/`ledger_sk`, `billing.py:2448`, `cursor.py`.

---

### ACC-003: Transaction metadata enrichment — tags / comments / narrative / geotag / image
**Type**: Backend (metadata sub-rows + S3 image + endpoints)
**Priority**: P2
**Estimate**: 3 days

**Description**
Layer OBP "transaction metadata" — user-added **tags, comments, narrative, geotag, and
an image** — on top of the immutable ledger transactions. Ledger rows are NEVER mutated
(they're the money record); metadata lives in NEW sub-rows keyed to the account +
transaction id. Gated by `banking_account_metadata_enabled` (and accounts enabled).

- **Why sub-rows:** the source `LEDGER#` rows are owned by billing and must stay
  immutable. Metadata is additive, user-authored, and per-account-scoped (so it doesn't
  bleed into the billing dashboard).
- **DDB model** — reuse the `banking_accounts` table:
  `pk=ACCOUNT#{account_id}`, with sort keys:
  - `META#{transaction_id}#NARRATIVE` — singleton narrative `{text, author_sub,
    updated_at}` (PUT-replaces).
  - `META#{transaction_id}#GEOTAG` — singleton `{lat, lon, label, author_sub}`.
  - `META#{transaction_id}#IMAGE` — singleton `{s3_key, bucket, url, author_sub}`.
  - `META#{transaction_id}#TAG#{tag_id}` — one row per tag `{value, author_sub}`
    (multi).
  - `META#{transaction_id}#COMMENT#{comment_id}` — one row per comment `{text,
    author_sub, created_at}` (multi).
  A `begins_with("META#{transaction_id}#")` query returns all metadata for a transaction
  in one call.
- **Image upload via S3.** Reuse `app.core.aws_clients.s3_client()`
  (`app/core/aws_clients.py:114`) — same factory messaging/file-share use. Key:
  `banking-metadata/{account_id}/{transaction_id}/{image_id}`. In dev, return a
  `/mock/s3/...` URL (mirrors `_message_out_from_item`'s dev image URL pattern noted in
  project memory); in prod, a presigned GET URL. **No `if S.dev_mode` in business
  logic** — the s3_client factory handles dev (moto in-process) vs prod (SECOPS-007).
- **Authorization.** Only an owner/co-owner of the account (ACC-001/ACC-004) — and, for
  view-based co-access, a viewer whose View grants metadata visibility (ACC-004) — may
  read/write metadata. Writing requires write-capable access (owner/co-owner); read may
  be allowed to a viewer per ACC-004's projection. The transaction must exist
  (`get_account_transaction`, ACC-002) before metadata can attach (404 otherwise).

**Service** (in `banking_accounts.py`):
- `put_transaction_narrative / put_geotag / set_transaction_image`,
  `add_transaction_tag / remove_transaction_tag`,
  `add_transaction_comment / delete_transaction_comment`,
  `get_transaction_metadata(account_id, transaction_id, requester_sub) -> {narrative,
  geotag, image, tags, comments}` (single `begins_with` query).
- The ACC-002 `Transaction` projection gains an additive
  `metadata: {...}` block (or a `has_metadata` flag + lazy fetch) so list views can show
  tag/comment badges.

**Router** (prefix `/ui/banking/accounts/{account_id}/transactions/{transaction_id}`):
```
GET    .../metadata                  → get_transaction_metadata
PUT    .../narrative                 → put_transaction_narrative
PUT    .../geotag                    → put_geotag
POST   .../image    (multipart)      → set_transaction_image (S3 upload)
POST   .../tags                      → add_transaction_tag
DELETE .../tags/{tag_id}             → remove_transaction_tag
POST   .../comments                  → add_transaction_comment
DELETE .../comments/{comment_id}     → delete_transaction_comment
```

**Acceptance Criteria**
- `BANKING_ACCOUNT_METADATA_ENABLED=0` → metadata routes 404; ledger rows never read for
  metadata.
- Adding a narrative/tag/comment/geotag/image does NOT mutate the underlying `LEDGER#`
  row (verify the billing item is byte-identical before/after).
- Image upload stores to S3 via `s3_client()`; `GET .../metadata` returns a usable URL
  (dev `/mock/s3/...`, prod presigned); no `dev_mode` branch in service logic.
- Tags/comments are multi (N rows); narrative/geotag/image are singletons
  (PUT-replaces).
- Metadata attaches only to a transaction that exists in the account (404 on unknown
  `transaction_id`); a non-owner cannot read/write metadata (403/404).
- All metadata for a transaction is fetched in ONE `begins_with` query.

**Dependencies**: **ACC-002** (transaction resolution), **ACC-001** (account/ownership).
Cites `aws_clients.s3_client`.

---

### ACC-004: Account-holder co-access — multi-owner + view-based co-access on the account
**Type**: Backend (ownership grants + view binding)
**Priority**: P2
**Estimate**: 3 days

**Description**
Make an account shareable two ways, mirroring OBP's "account holders + Views": (1)
**multi-owner** — add a second full account-holder (read/write everything); (2)
**view-based co-access** — grant a scoped, field-level *read* of the account + its
transactions to another user via the planned **VEW Account-Views** primitive (tax/
auditor/public), without making them an owner. Gated by
`banking_account_views_enabled`.

- **Multi-owner (co-holders).** `add_account_owner(account_id, owner_sub, new_owner_sub)`
  (owner only) appends `new_owner_sub` to the account's `owners` list AND writes the
  reverse-index row `pk=USER#{new_owner_sub}`, `sk=ACCOUNT_REF#{account_id}` (so
  ACC-001 `list_accounts` surfaces it). `remove_account_owner` reverses it; the last
  owner cannot be removed (409). Reuse the org-membership role pattern as precedent for
  "who may grant" — `org_service.assert_org_membership(... min_role=...)`
  (`app/services/org_service.py:165`, `ROLE_ORDER` at `:20`) is the established
  grant-authorization shape; account co-holders are simpler (single `owner` role) but
  follow the same "assert the caller is privileged before mutating membership" rule.
  Optionally, if the account is org-owned, org members at/above a configured role inherit
  access via `assert_org_membership` (additive, behind the same flag).
- **View-based co-access (the field-level path).** Bind the account to the **VEW
  Account-View** entity from `OBP_VIEWS_ENTITLEMENTS_TICKETS.md`. VEW keys views by
  `resource_type` + `resource_id` (see that file: `pk=RESOURCE#{resource_type}#
  {resource_id}`, `sk=VIEW#{view_id}` / `VIEWGRANT#{grantee}#{view_id}`), so an ACC
  account plugs in directly with `resource_type="account"`,
  `resource_id=account_id`. ACC-004 does NOT reimplement view CRUD/grant/projection — it
  **consumes** VEW:
  - The account owner creates/grants a View on `("account", account_id)` via the
    existing VEW endpoints (`/ui/views/...`).
  - ACC's read endpoints, when the caller is NOT an owner, call VEW's
    `resolve_active_grant(caller_sub, "account", account_id, view_id)` (VEW-002) and run
    the account + transaction + metadata responses through VEW's field-level
    **projection** (VEW-003) — so an "auditor" view can hide `iban`, a "public" view can
    show only `label`+`amount`, and `metadata_visibility=="counterparty_blur"`
    blurs/omits per VEW-003. ACC supplies the full resource dict; VEW decides which
    fields survive.
  - The unauthenticated **public view** (VEW-002 signed-token path,
    `GET /ui/views/public/{token}`) therefore works for accounts for free.
- **Honesty / fit.** This is the additive co-access OBP expects. It depends on the VEW
  tickets shipping; ACC-004's read path is gated so it no-ops cleanly if VEW isn't
  deployed (see Dependencies).

**Service** (in `banking_accounts.py`):
- `add_account_owner` / `remove_account_owner` / `list_account_holders(account_id)`.
- `resolve_account_access(caller_sub, account_id) -> {role: "owner"|"viewer"|None,
  view_id?}` — owner check first (ACC-001), else delegate to VEW
  `resolve_active_grant`. Used by ACC-001/002/003 read handlers to gate + to pick the
  projection.
- The ACC-001/002/003 GET handlers are updated: if `role=="viewer"`, the response is
  passed through VEW's projection helper before serialization.

**Router** (prefix `/ui/banking/accounts/{account_id}`):
```
GET    .../holders                       → list_account_holders
POST   .../holders        {user_sub}     → add_account_owner   (owner only)
DELETE .../holders/{user_sub}            → remove_account_owner(owner only)
```
(View CRUD/grant lives in the VEW router, keyed `("account", account_id)` — not
duplicated here.)

**Acceptance Criteria**
- `add_account_owner` makes the account appear in the new owner's `list_accounts`
  (via the `ACCOUNT_REF#` reverse-index row) with full read/write; `remove_account_owner`
  reverses it; removing the last owner → 409.
- A non-owner with an active VEW grant on `("account", account_id)` can GET the account /
  transactions / metadata, but ONLY the fields the View permits (verify a hidden field
  like `iban` is absent for an "auditor" view; `counterparty_blur` is honored).
- A non-owner with NO grant and NO ownership → 404 (no leak).
- Owner responses are unprojected (full fields); viewer responses are VEW-projected.
- With `BANKING_ACCOUNT_VIEWS_ENABLED=0` (or VEW disabled), the co-access read path is
  skipped — only true owners/co-owners get access; multi-owner still works
  independently.

**Dependencies**: **ACC-001** (account entity/ownership), **ACC-002/003** (the resources
being projected). **Soft dependency on the VEW tickets**
(`OBP_VIEWS_ENTITLEMENTS_TICKETS.md`: VEW-001 view entity, VEW-002
grant/`resolve_active_grant`, VEW-003 projection). Cites `org_service.py` membership
pattern as precedent.

---

### ACC-005: Tests — pytest unit coverage for banks/accounts/transactions/metadata/co-access
**Type**: Testing
**Priority**: P1 (ships with the feature)
**Estimate**: 2.5 days

**Description**
Offline, hermetic pytest coverage for ACC-001..ACC-004, following the repo's
moto-bound, frozen-handle test conventions (no live stack, no real AWS/network).

- **Harness.** moto in-memory DynamoDB tables for `banking_accounts`/`banking_banks`
  bound to the exact frozen `T.banking_accounts`/`T.banking_banks` handles via
  `object.__setattr__` (restored on teardown), plus `T.billing` (wallet + a few seeded
  `LEDGER#` rows) and `T.alerts` (audit) bound the same way. S3 for ACC-003 patched to an
  in-memory fake (or moto S3) so image upload never hits real AWS. Frozen `S` flags
  toggled via `object.__setattr__`. `now_ts` patched where deterministic timestamps are
  needed. Async route handlers (if any) invoked on a fresh
  `asyncio.new_event_loop()`. VEW collaborators (`resolve_active_grant`, projection)
  are stubbed/patched at the source so ACC-004 tests don't require the VEW tables.

- **ACC-001 — `tests/test_acc_001_accounts.py`**: default-account bootstrap is
  idempotent (one row, stable `account_id` across calls); `/balance` reads through to the
  wallet (mutate wallet → balance changes, proving projection); typed `attributes` /
  `iban` round-trip as opaque strings; non-owner `get_account` → 404; delete-default →
  409; flag-off → routes absent.

- **ACC-002 — `tests/test_acc_002_transactions.py`**: projection equals the seeded
  `LEDGER#` rows (same `entry_id`s); newest settled `new_balance` == live wallet; running
  balance chains backwards correctly (assert each `newer − signed_amount`); `from`/`to`
  bound the result via the `sk` key condition; cursor round-trips through
  `encode_cursor`/`decode_cursor` and full pagination yields every row once (no
  dup/skip); a tampered cursor → page-1, not 500.

- **ACC-003 — `tests/test_acc_003_metadata.py`**: the underlying `LEDGER#` billing item
  is byte-identical before/after metadata writes (immutability proof); tags/comments are
  multi, narrative/geotag/image singleton (PUT-replaces); image upload stores via the
  patched S3 and `GET .../metadata` returns a URL; one `begins_with` query returns all
  metadata; metadata on unknown `transaction_id` → 404; non-owner → 403/404; flag-off →
  routes absent.

- **ACC-004 — `tests/test_acc_004_coaccess.py`**: `add_account_owner` surfaces the
  account in the new owner's `list_accounts` (reverse-index) with full access;
  remove-last-owner → 409; with VEW stubbed to return an active grant, a non-owner gets a
  VEW-projected response (hidden `iban` absent; `counterparty_blur` honored via the
  stubbed projection); no grant + no ownership → 404; flag-off skips the view path but
  multi-owner still works.

**Acceptance Criteria**
- All ACC tests are offline/hermetic (no dev stack, no real AWS/network) and pass under
  `.venv/bin/pytest tests/test_acc_*.py`.
- Frozen `T.*`/`S` handles are restored on teardown (no cross-test leakage).
- The wallet/ledger read-through and the ledger-immutability invariants are explicitly
  asserted (these are the load-bearing "additive over billing" guarantees).
- Coverage spans every new service function + every router happy-path and the key
  403/404/409/flag-off branches.

**Dependencies**: **ACC-001..ACC-004** (tests the code they add). Mirrors the
moto-bound/frozen-handle pattern used by `tests/test_gap_0223_0224_ec2_host_inventory.py`
and the KYC GAP tests.

---

## Ticket summary

| Ticket | Title | Type | Priority | Est. | Depends on |
|---|---|---|---|---|---|
| ACC-001 | Bank + Account entities (DDB, flag, default-account bootstrap) | Backend | P1 | 3d | — |
| ACC-002 | Per-account transaction list (ledger projection, running `new_balance`, date-range + cursor) | Backend | P1 | 3d | ACC-001 |
| ACC-003 | Transaction metadata enrichment (tags/comments/narrative/geotag/image via S3) | Backend | P2 | 3d | ACC-002, ACC-001 |
| ACC-004 | Account-holder co-access (multi-owner + VEW view-based co-access) | Backend | P2 | 3d | ACC-001/002/003, VEW (soft) |
| ACC-005 | Tests (pytest, moto-bound, hermetic) | Testing | P1 | 2.5d | ACC-001..004 |

All additive, flag-gated default-OFF, reusing the existing wallet/ledger
(`billing_shared.py`), signed cursor (`cursor.py`), S3 factory (`aws_clients.py`),
org-membership precedent (`org_service.py`), and the planned VEW Account-Views — never
forking billing. testlogon has no bank-account model today; **ACC adds it as a thin
projection over the wallet/ledger.**
