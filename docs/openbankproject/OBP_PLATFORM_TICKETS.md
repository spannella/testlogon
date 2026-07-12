# OBP Platform Tickets (prefix `PLT`)

These tickets close the **Open Bank Project Tier-1 platform gaps** identified in
`docs/openbankproject/OBP_GAP_ANALYSIS.md` (§D "Metrics, Rate-limiting, Webhooks" + the
Tier-1 recommendation bullet "Per-consumer rate-limit middleware + top-N metrics leaderboard
+ glossary endpoint + sandbox JSON import"). Every PLT ticket is a **thin extension of the
existing API-platform plumbing** — the metering, rate-limit, webhook, and seed services that
testlogon already owns. **Nothing here forks an existing primitive.**

OBP ships banks/accounts/balances/transactions on top of a per-call **metrics** layer, a
per-consumer **rate-limiter** with minute/hour/day/week/month windows, an HMAC **webhook**
event bus, an admin **metrics leaderboard**, a **glossary**, and a **sandbox data import**.
testlogon already HAS the metering aggregates (`api_usage_metering.py`), the DDB bucket
limiter (`rate_limit.py:_bucket_limit`), the per-key self-limits (`api_keys.py`), the webhook
taxonomy + dispatcher (`webhook_service.py`), and the seed script (`scripts/local-ddb-seed.py`).
The five gaps below are the **last-mile wiring** that turns those primitives into the
OBP-equivalent platform surface.

Concretely the five tickets cover:

1. **PLT-001** — a **per-consumer rate-limit middleware** with configurable
   minute/hour/day/week/month windows, applied to all metered routes, extending the existing
   `_bucket_limit` beyond its current KYC-partner-only wiring and honouring the per-key
   self-limits (`api_keys.set_api_key_self_limits`).
2. **PLT-002** — an admin **top-N metrics leaderboard** (top consumers / top endpoints) built
   purely from the existing `api_usage_metering` `by_key` / `by_route` aggregates.
3. **PLT-003** — a DDB-backed, admin-editable **glossary** endpoint (`GET /v1/glossary`).
4. **PLT-004** — a dev-only/flag-gated **sandbox JSON import** admin endpoint that bulk-seeds
   accounts/transactions/customers, reusing the `local-ddb-seed.py` + KYC-sandbox patterns.
5. **PLT-005** — **`account.*` / `transaction.created` / `balance.threshold`** webhook event
   types added to `WEBHOOK_EVENT_TYPES_V2` and fired from the ledger/account write paths.

---

## Cross-cutting constraints (apply to every PLT ticket)

- **Additive + flag-gated, default-off.** Each new code path is gated by its own env flag
  (`API_CONSUMER_RATE_LIMIT_ENABLED`, `METRICS_LEADERBOARD_ENABLED`, `GLOSSARY_ENABLED`,
  `SANDBOX_IMPORT_ENABLED`, `ACCOUNT_LEDGER_WEBHOOKS_ENABLED`) which defaults **off**. With
  every flag off the platform is byte-for-byte unchanged — the middleware short-circuits, the
  endpoints 404/return-empty, the webhook taxonomy/dispatch is unaffected.
- **Extend the existing service — never reimplement it.** PLT-001 reuses
  `app/services/rate_limit.py:_bucket_limit` (the same DDB-backed sliding bucket used by
  `rate_limit_kyc_partner_api`) and reads per-key caps via `api_keys.get_api_key_item` /
  `set_api_key_self_limits` (`app/services/api_keys.py:285`). PLT-002 reuses
  `api_usage_metering.query_api_key_period_totals` / `query_api_route_period_totals` +
  `_apply_breakdown_query` (`app/services/api_usage_metering.py:429,463,502`). PLT-003 reuses
  the standard `T.*` + `audit_event` CRUD pattern. PLT-004 reuses `scripts/local-ddb-seed.py`'s
  `_table(ddb, name)` helper + `T.*` handles and the KYC sandbox-seed shape. PLT-005 reuses
  `webhook_service.WEBHOOK_EVENT_TYPES_V2` + `dispatch_webhook_event`
  (`app/services/webhook_service.py:60,556`) and hooks `billing_shared.new_ledger_entry`
  (`app/services/billing_shared.py:224`) call sites.
- **SECOPS-007 dev/prod parity.** No `if S.dev_mode:` branch in any new code path **except**
  PLT-004, whose sandbox-import endpoint is explicitly dev/flag-gated per the OBP sandbox model
  (the gate is the feature, not an environment shortcut) and writes the same `T.*` handles in
  both envs. All other DDB reads/writes go through the frozen `T.*` handles (DynamoDB Local in
  dev, real DynamoDB in prod).
- **`now_ts()` integer Unix seconds** for all numeric timestamps; any new numeric GSI/SK field
  declares `attr_types={"...": "N"}` in `scripts/local-ddb-init.py`.
- **`audit_event(event, user_sub, request=None, **fields)`** (`app/services/alerts.py`) on
  every successful mutating/admin call (glossary upsert/delete, sandbox import, leaderboard
  view per the existing `admin_usage.py` pattern at `app/routers/admin_usage.py:454`).
- **Admin auth** reuses the existing `_require_admin_user` dependency style from
  `app/routers/admin_usage.py:35` (allowlist via `S.filemgr_admin_users`) — no new role system.
- **Tests are hermetic + offline** (moto in-memory DDB bound to the frozen `T.*` handle via
  `object.__setattr__`, frozen `S` flags toggled via `object.__setattr__`, async handlers
  driven on a fresh `asyncio.new_event_loop()`, collaborators patched at source). E2E specs
  require the parent flags enabled in the local stack.
- **429 shape parity.** Every new rate-limit denial mirrors the existing
  `rate_limit_kyc_partner_api` contract (`app/services/rate_limit.py:385`): HTTP 429 with
  `detail.code` + `detail.limit` + `detail.window_seconds` and a `Retry-After` header.

---

### PLT-001: Per-consumer rate-limit middleware — configurable minute/hour/day/week/month windows on all metered routes

**Type:** Feature | **Priority:** P1 | **Estimate:** 3d
**Flags:** `API_CONSUMER_RATE_LIMIT_ENABLED` (new, default off).

#### Description — what it extends + reuse citations

The gap matrix (§D) marks "Per-key rate limiting" as **HAVE/PARTIAL**: *"`rate_limit.py`
buckets; not a uniform all-route per-consumer throttle."* Today the DDB bucket limiter
(`app/services/rate_limit.py:60 _bucket_limit`) is wired to specific flows only — login, MFA,
share-links, file-mount onboarding, and (the closest analogue) `rate_limit_kyc_partner_api`
(`rate_limit.py:385`), which already keys on `apikey:{api_key_id}` per-hour. OBP's rate-limiter
applies **per-consumer** windowed caps (per-minute / -hour / -day / -week / -month) to *every*
metered API call. This ticket generalizes the KYC-partner pattern into an all-route middleware.

Implementation:
- Add `rate_limit_api_consumer(api_key_id: str, route_id: str) -> dict` to
  `app/services/rate_limit.py`, modelled directly on `rate_limit_kyc_partner_api`. It calls
  `_bucket_limit(key=f"apikey:{api_key_id}", sid=f"rl#api#{window}", max_n, win)` once **per
  window** for the windows `minute` (60s), `hour` (3600s), `day` (86400s), `week` (604800s),
  `month` (2592000s). Default caps come from new `S.api_consumer_rate_limit_*` settings (env
  `API_CONSUMER_RATE_LIMIT_{MINUTE,HOUR,DAY,WEEK,MONTH}`); a cap of `0` disables that window.
- **Per-key override:** resolve the consumer's API-key item via
  `api_keys.get_api_key_item(api_key_id)` and, if the key carries a `rate_limit_overrides` map
  (a new optional field on `set_api_key_self_limits`, `app/services/api_keys.py:285`, normalized
  alongside `route_caps`), use those caps in place of the account defaults — mirroring how
  self-limits already layer on top of `api_usage_account_monthly_calls_limit`.
- Wire it into a new pre-request middleware `_api_consumer_rate_limit_middleware()` in
  `app/main.py`, registered **before** `_api_usage_metering_middleware()`
  (`app/main.py:333,542`) so a 429 is itself metered as a denial (matching the existing
  `classify_api_call(..., is_rate_limited=status==429)` path at `api_usage_metering.py:161`).
  The middleware resolves `api_key_id` via the existing `_extract_api_key_id(request)`
  (`api_usage_metering.py:119`) and `route_id` via `route_id_from_request`; requests with no
  resolvable API key are skipped (cookie/session UI traffic is unaffected).
- On denial, return the standard 429 JSON (`code="api_consumer_rate_limited"`, `window`,
  `limit`, `window_seconds`, `Retry-After`) via `JSONResponse`, same shape as the KYC limiter.

#### Acceptance Criteria

- With `API_CONSUMER_RATE_LIMIT_ENABLED=0` the middleware is a no-op (registered but
  short-circuits) — no behaviour change, no extra DDB reads.
- With the flag on, a bearer/API-key consumer exceeding any configured window cap receives
  HTTP 429 with `detail.code="api_consumer_rate_limited"`, `detail.window`, `detail.limit`,
  `detail.window_seconds`, and a `Retry-After` header equal to the breached window seconds.
- Each window (minute/hour/day/week/month) is enforced independently; a `0` cap disables that
  window. Separate API keys have separate budgets (keyed on `apikey:{api_key_id}`).
- A per-key `rate_limit_overrides` entry (set via `set_api_key_self_limits`) supersedes the
  account default for that key, and is rejected by the existing guardrail style if it exceeds a
  configured account ceiling.
- Cookie/session (UI) requests with no API key are never throttled by this middleware.
- A 429 from this limiter is recorded as a denied call in `api_usage_metering` aggregates.
- Hermetic offline unit test (`tests/test_plt_001_api_consumer_rate_limit.py`): moto-backed
  `sessions` table bound to frozen `T.sessions`, `now_ts` patched to advance windows, asserts
  per-window allow→deny transitions + override precedence + flag-off no-op.

#### Dependencies

- Extends `app/services/rate_limit.py` (`_bucket_limit`, `rate_limit_kyc_partner_api` pattern),
  `app/services/api_keys.py` (`get_api_key_item`, `set_api_key_self_limits`),
  `app/services/api_usage_metering.py` (`_extract_api_key_id`, `route_id_from_request`),
  `app/main.py` (middleware registration). New `S.api_consumer_rate_limit_*` settings.

---

### PLT-002: Top-N metrics leaderboard — admin ranking of top consumers / top endpoints

**Type:** Feature | **Priority:** P2 | **Estimate:** 2d
**Flags:** `METRICS_LEADERBOARD_ENABLED` (new, default off).

#### Description — what it extends + reuse citations

The gap matrix (§D) marks "Top-N consumers/endpoints leaderboard" as **PARTIAL**: *"aggregates
exist; no ranked leaderboard endpoint."* OBP's metrics surface exposes a ranked top-N of
busiest consumers and busiest endpoints. testlogon already computes the underlying per-period
aggregates — `query_api_key_period_totals` and `query_api_route_period_totals`
(`app/services/api_usage_metering.py:429,463`) — and already has a generic ranking/paging
helper `_apply_breakdown_query` (`api_usage_metering.py:502`) that sorts by `calls_total` /
`cost_subtotal_micros` / `request_units_total` with search + cursor. This ticket is purely a
new admin endpoint over those primitives — **no new aggregation math**.

Implementation:
- Add `GET /v1/admin/api-usage/leaderboard` to `app/routers/admin_usage.py` (the file that
  already owns `_require_admin_user` at `admin_usage.py:35` and the `_api_usage_table()`
  pattern). Query params: `period_id` (YYYY-MM, default current via
  `usage_metering.period_id_for_datetime`), `dimension` (`consumers` | `endpoints`),
  `metric` (`calls_total` | `cost_subtotal_micros` | `request_units_total`, default
  `cost_subtotal_micros`), `top_n` (default 10, cap 100).
- For `dimension=consumers`: rank rows from `query_api_key_period_totals`; for
  `dimension=endpoints`: rank rows from `query_api_route_period_totals`. Reuse
  `_apply_breakdown_query(..., sort_by=metric, order="desc", limit=top_n)` for the sort/limit so
  ordering is identical to the existing breakdown endpoints.
- Cross-user (platform-wide) ranking: a new `aggregate_leaderboard(table, *, period_id,
  dimension, metric, top_n)` helper in `api_usage_metering.py` that scans the per-user
  `API_USAGE#KEY#` / `API_USAGE#ROUTE#` aggregate rows (reusing the `_scan_api_usage_events`
  scan idiom at `api_usage_metering.py:864`, filtered by `entity_type`) and merges duplicate
  keys/routes across users before ranking. Per-user (`user_sub`-scoped) ranking simply passes a
  `user_sub` through to the existing query helpers.
- Audit the view via `audit_event("api_usage_leaderboard_view", admin_user, req, ...)` exactly
  like `admin_usage.py:454`'s `api_key_rollout_state_view`.

#### Acceptance Criteria

- With `METRICS_LEADERBOARD_ENABLED=0` the route is not registered (or returns 404) and no scan
  runs.
- `GET /v1/admin/api-usage/leaderboard?dimension=consumers&period_id=YYYY-MM` returns the top-N
  API keys for that period ranked by the requested metric, descending; `dimension=endpoints`
  returns the top-N route_ids.
- The `metric` param accepts `calls_total` / `cost_subtotal_micros` / `request_units_total`;
  ordering matches the existing `/ui/api-usage/keys` and `/routes` breakdown endpoints (same
  `_apply_breakdown_query` key functions).
- `top_n` is clamped to `[1, 100]`; the response includes `period_id`, `dimension`, `metric`,
  and `items` (each item carries its id + the metric totals).
- Non-admin callers receive 403 via `_require_admin_user`; a successful view emits an
  `api_usage_leaderboard_view` audit event.
- Hermetic offline unit test (`tests/test_plt_002_metrics_leaderboard.py`): seed
  `API_USAGE#KEY#`/`API_USAGE#ROUTE#` aggregate rows in a moto table bound to the frozen API-usage
  table handle, assert ranking order, top_n clamp, dimension switch, and flag-off 404.

#### Dependencies

- Extends `app/services/api_usage_metering.py` (`query_api_key_period_totals`,
  `query_api_route_period_totals`, `_apply_breakdown_query`, `_scan_api_usage_events`) and
  `app/routers/admin_usage.py` (`_require_admin_user`, `_api_usage_table`). No schema change
  (reads existing aggregate rows).

---

### PLT-003: Glossary endpoint — `GET /v1/glossary` serving admin-editable term/definition entries

**Type:** Feature | **Priority:** P3 | **Estimate:** 2d
**Flags:** `GLOSSARY_ENABLED` (new, default off).

#### Description — what it extends + reuse citations

The gap matrix (§D) marks "Glossary endpoint" as **MISSING (net-new)**. OBP serves a
`/glossary` of term→description entries (markdown definitions) used by its API Explorer. This is
a small DDB-backed, admin-editable CRUD with a public read — no new infrastructure, just the
standard `T.*` + `audit_event` pattern this codebase uses everywhere.

Implementation:
- New service `app/services/glossary.py` with `list_glossary()`, `get_glossary_term(term_id)`,
  `upsert_glossary_term(term, definition, *, term_id=None, tags=None)`,
  `delete_glossary_term(term_id)`. Storage reuses an existing general-purpose table (the
  `glossary` rows can live on a single-table handle such as the alerts/config table, or a new
  `glossary` `TableDef` in `scripts/local-ddb-init.py` with PK `term_id` (S) and a numeric
  `updated_at` declared `attr_types={"updated_at": "N"}`). Each row: `term_id`, `term`,
  `definition` (markdown, capped), `tags: [str]`, `updated_at` (`now_ts()`), `updated_by`.
- New router `app/routers/glossary.py`:
  - `GET /v1/glossary` — public list (read-only), optional `?search=` (case-insensitive contains
    on `term`) and cursor paging via `app/core/cursor.py`.
  - `GET /v1/glossary/{term_id}` — public single-term read (404 if absent).
  - `POST /v1/admin/glossary` / `PATCH /v1/admin/glossary/{term_id}` /
    `DELETE /v1/admin/glossary/{term_id}` — admin-only via the `_require_admin_user` dependency
    (reuse `admin_usage.py:35` style), each emitting `audit_event("glossary_upsert" /
    "glossary_delete", admin_user, req, term_id=...)`.
- Register the router in `app/main.py` (gated on `S.glossary_enabled`); add
  `GET:/v1/glossary` + `GET:/v1/glossary/{term_id}` to the API-key route exemptions if needed
  (public reads, same exemption mechanism used for `/feed/for-you`).

#### Acceptance Criteria

- With `GLOSSARY_ENABLED=0` the router is not registered (404 on all glossary paths).
- `GET /v1/glossary` returns all terms (term/definition/tags/updated_at), ordered
  deterministically (by `term`), with `?search=` filtering by case-insensitive substring and
  cursor paging.
- `POST /v1/admin/glossary {term, definition, tags?}` creates a term (server-generated
  `term_id`); `PATCH` partial-updates; `DELETE` removes it — all admin-only (403 for non-admin)
  and each emits the corresponding audit event.
- `GET /v1/glossary/{term_id}` returns 404 for an unknown id.
- `definition` is length-capped; `updated_at` is integer `now_ts()`; `updated_by` records the
  admin sub.
- Hermetic offline unit test (`tests/test_plt_003_glossary.py`): moto-backed glossary table
  bound to the frozen handle, exercises list/get/upsert/patch/delete + admin-403 + flag-off.

#### Dependencies

- New `app/services/glossary.py`, `app/routers/glossary.py`; `scripts/local-ddb-init.py`
  TableDef (or reuse of an existing config table); `app/main.py` registration;
  `_require_admin_user` (`app/routers/admin_usage.py:35`), `audit_event`, `app/core/cursor.py`.

---

### PLT-004: Sandbox JSON import — admin endpoint bulk-seeding accounts/transactions/customers (dev/flag-gated)

**Type:** Feature | **Priority:** P2 | **Estimate:** 3d
**Flags:** `SANDBOX_IMPORT_ENABLED` (new, default off) **and** `S.dev_mode` (both required).

#### Description — what it extends + reuse citations

The gap matrix (§D) marks "Sandbox JSON data import" as **PARTIAL**: *"seed scripts exist; no
admin import endpoint."* OBP ships a sandbox `/sandbox/data-import` accepting a JSON payload of
banks/accounts/transactions/customers/users to bulk-seed a test environment. testlogon already
has the offline seed primitive `scripts/local-ddb-seed.py` (its `_table(ddb, name)` helper +
direct `put_item` against `T.*` handles, `local-ddb-seed.py:14`) and the KYC sandbox-seed shape.
This ticket exposes an **admin, dev-only, flag-gated** HTTP endpoint that performs the same
writes from an uploaded JSON document — it is explicitly a sandbox feature, so the dev gate is
the feature itself (NOT a SECOPS-007 environment shortcut), and the writes go through the same
`T.*` handles in dev and (if ever enabled) prod.

Implementation:
- New service `app/services/sandbox_import.py` with
  `import_sandbox_payload(payload: dict, *, actor_sub: str) -> dict`. Accepts a JSON document
  with optional arrays `accounts`, `transactions`, `customers` (and `users`). For each:
  - **customers** → write user/profile rows mirroring `local-ddb-seed.py:43-61`'s users/profile
    puts (display_name, bio, created_at).
  - **accounts** → write a wallet/balance row per the `billing_shared.ensure_balance_row` /
    `apply_wallet_delta` primitives (`billing_shared.py:69,185`) so seeded balances are
    consistent with the real ledger model (no bespoke account table — reuse the wallet row).
  - **transactions** → write ledger rows via `billing_shared.new_ledger_entry`
    (`billing_shared.py:224`) so seeded transactions carry `ledger_date` and appear in the
    existing dashboards/aggregates; never bypass `new_ledger_entry`.
  - Validate caps (max N items per array, per a new `S.sandbox_import_max_items`); return a
    per-section count + any per-row errors (best-effort, partial-success).
- New router `app/routers/sandbox.py`: `POST /v1/admin/sandbox/data-import` — admin-only via
  `_require_admin_user`, additionally guarded by `if not (S.sandbox_import_enabled and
  S.dev_mode): raise HTTPException(404)`. Emits
  `audit_event("sandbox_data_import", admin_user, req, counts=...)`.
- Register the router in `app/main.py` gated on `S.sandbox_import_enabled`.

#### Acceptance Criteria

- The endpoint returns 404 unless **both** `SANDBOX_IMPORT_ENABLED=1` and `DEV_MODE=1`.
- `POST /v1/admin/sandbox/data-import` with `{customers:[...], accounts:[...],
  transactions:[...]}` creates the corresponding user/profile rows, wallet/balance rows (via
  `ensure_balance_row`/`apply_wallet_delta`), and ledger rows (via `new_ledger_entry`), and
  returns a per-section created-count.
- Seeded transactions appear in the existing per-user ledger queries and carry `ledger_date`
  (i.e. they are written through `new_ledger_entry`, not a bespoke writer).
- Item counts above `S.sandbox_import_max_items` per array are rejected/clamped; malformed rows
  produce per-row errors without aborting the whole import (partial success), and the response
  reports them.
- Non-admin callers receive 403; a successful import emits a `sandbox_data_import` audit event
  with the per-section counts.
- Hermetic offline unit test (`tests/test_plt_004_sandbox_import.py`): moto tables bound to the
  frozen `T.users`/`T.profile`/`T.billing` handles, frozen `S.dev_mode`+flag toggled via
  `object.__setattr__`, asserts the three section writers + 404-when-disabled + partial-success.

#### Dependencies

- New `app/services/sandbox_import.py`, `app/routers/sandbox.py`; reuses
  `scripts/local-ddb-seed.py` write idiom, `app/services/billing_shared.py`
  (`ensure_balance_row`, `apply_wallet_delta`, `new_ledger_entry`),
  `_require_admin_user` (`admin_usage.py:35`), `audit_event`. New
  `S.sandbox_import_enabled` / `S.sandbox_import_max_items` settings.

---

### PLT-005: `account.*` / `transaction.created` / `balance.threshold` webhook events — taxonomy + ledger/account firing

**Type:** Feature | **Priority:** P2 | **Estimate:** 3d
**Flags:** `ACCOUNT_LEDGER_WEBHOOKS_ENABLED` (new, default off).

#### Description — what it extends + reuse citations

The gap matrix (§D) marks "account.* / transaction.created / balance.threshold webhook events"
as **PARTIAL**: *"event taxonomy is billing/messaging, not account/ledger events."* OBP fires
account-balance and transaction webhooks from its ledger write path. testlogon already has the
full HMAC webhook bus — `WEBHOOK_EVENT_TYPES_V2` (`app/services/webhook_service.py:60`),
`is_valid_event_type` (`webhook_service.py:203`), and `dispatch_webhook_event`
(`webhook_service.py:556`) — plus an existing `wallet.deposit` / `wallet.withdrawal` event. This
ticket adds the account/transaction/threshold event types to the taxonomy and fires them from
the ledger/balance write paths.

Implementation:
- **Taxonomy:** add to `WEBHOOK_EVENT_TYPES_V2` (`webhook_service.py:60`):
  - `transaction.created` — "A new ledger transaction was recorded"
  - `balance.threshold` — "An account balance crossed a configured threshold"
  - `account.balance_low` (and reuse the existing `account.*` block) — "Account balance fell
    below the low-balance threshold"
  These validate via the existing `is_valid_event_type` automatically (they are members of
  `WEBHOOK_EVENT_TYPES_V2`).
- **Firing — transaction.created:** add a best-effort `_emit_transaction_webhook(user_sub,
  item)` helper called immediately after each `new_ledger_entry` persist. Rather than touching
  all ~18 `new_ledger_entry` call sites (`app/routers/billing.py`, `paypal.py`,
  `billing_ccbill.py`, `app/services/ad_placement.py`), fire from a single chokepoint: a thin
  `record_ledger_entry(table, *, key_name, key_value, ...)` wrapper in `billing_shared.py` that
  calls `new_ledger_entry` + `table.put_item` + the webhook emit, and migrate the call sites to
  it incrementally (the emit is gated by `ACCOUNT_LEDGER_WEBHOOKS_ENABLED`, so un-migrated sites
  simply don't emit — zero behaviour change). The emit builds a payload `{transaction_id,
  type, amount_cents, currency, reason, ledger_date}` and calls
  `dispatch_webhook_event("transaction.created", user_sub, payload)`.
- **Firing — balance.threshold / account.balance_low:** after `apply_wallet_delta` /
  `apply_balance_delta` (`billing_shared.py:83,185`), compare the new balance against a
  per-account threshold (a new optional `balance_threshold_cents` field on the balance row,
  settable via a small admin/account setter) and, on a downward crossing, dispatch
  `balance.threshold` / `account.balance_low` with `{balance_cents, threshold_cents,
  currency}`. Use a stored `last_threshold_state` on the balance row to fire only on the
  *crossing* edge (no repeat events while below).
- All dispatch calls are wrapped in `try/except` (a webhook failure must never roll back a
  ledger write — same best-effort discipline as the existing KYC/decision emits) and are no-ops
  when `S.webhooks_enabled` is false (`dispatch_webhook_event` already short-circuits at
  `webhook_service.py:565`) or `ACCOUNT_LEDGER_WEBHOOKS_ENABLED` is off.

#### Acceptance Criteria

- `transaction.created`, `balance.threshold`, and `account.balance_low` are members of
  `WEBHOOK_EVENT_TYPES_V2` and pass `is_valid_event_type(...)` so endpoints can subscribe to
  them; subscriptions are rejected when the v2 flag is off exactly like other v2-only types.
- With `ACCOUNT_LEDGER_WEBHOOKS_ENABLED=0` (or `WEBHOOKS_ENABLED=0`) no account/ledger event is
  dispatched and ledger/balance writes are byte-for-byte unchanged.
- With both flags on, a ledger write through the new `record_ledger_entry` chokepoint creates a
  `pending` `transaction.created` delivery for every subscribed endpoint, carrying
  `{transaction_id, type, amount_cents, currency, reason, ledger_date}`.
- A balance crossing its configured `balance_threshold_cents` (downward) dispatches exactly one
  `balance.threshold` / `account.balance_low` event on the crossing edge; staying below it does
  not re-fire until the balance recovers above and crosses again.
- A webhook-dispatch exception never rolls back or fails the underlying ledger/balance write
  (best-effort `try/except`).
- Hermetic offline unit test (`tests/test_plt_005_account_ledger_webhooks.py`): moto-backed
  `billing` + `webhook_endpoints`/`webhook_deliveries` tables bound to frozen handles, a
  subscribed endpoint seeded, asserts a `transaction.created` delivery is created on ledger
  write, the threshold edge-trigger semantics, taxonomy membership, and flag-off no-op.

#### Dependencies

- Extends `app/services/webhook_service.py` (`WEBHOOK_EVENT_TYPES_V2`, `dispatch_webhook_event`,
  `is_valid_event_type`), `app/services/billing_shared.py` (`new_ledger_entry`,
  `apply_wallet_delta`, `apply_balance_delta`, balance-row schema), and the `new_ledger_entry`
  call sites in `app/routers/billing.py` / `paypal.py` / `billing_ccbill.py` /
  `app/services/ad_placement.py`. New `S.account_ledger_webhooks_enabled` setting + optional
  `balance_threshold_cents` balance-row field.

---

## Summary

| Ticket | Title | Extends | Flag |
|--------|-------|---------|------|
| PLT-001 | Per-consumer rate-limit middleware | `rate_limit.py:_bucket_limit`, `api_keys` self-limits | `API_CONSUMER_RATE_LIMIT_ENABLED` |
| PLT-002 | Top-N metrics leaderboard | `api_usage_metering` `by_key`/`by_route` aggregates | `METRICS_LEADERBOARD_ENABLED` |
| PLT-003 | Glossary endpoint | `T.*` CRUD + `audit_event` pattern | `GLOSSARY_ENABLED` |
| PLT-004 | Sandbox JSON import | `local-ddb-seed.py` + `billing_shared` ledger/wallet | `SANDBOX_IMPORT_ENABLED` (+ `DEV_MODE`) |
| PLT-005 | account.* / transaction.created / balance.threshold webhooks | `webhook_service` taxonomy + `new_ledger_entry` paths | `ACCOUNT_LEDGER_WEBHOOKS_ENABLED` |

All five are additive, flag-gated default-off, and reuse the existing metering / rate-limit /
webhook / seed primitives — never forking them (OBP Tier-1 platform enhancements per
`docs/openbankproject/OBP_GAP_ANALYSIS.md` §D + the Tier-1 recommendation).
