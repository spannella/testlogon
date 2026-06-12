# OBP Tier-2 — Counterparties, Recurring Payments & FX (prefix `PAY`)

Derived from `docs/openbankproject/OBP_GAP_ANALYSIS.md` (Tier 2, §B). Open Bank
Project's outbound-payment surface is built from four primitives that testlogon is
currently missing as first-class user-owned entities: **counterparties / beneficiaries**
(a stored third-party payee with bank routing), **standing orders** (user-defined
recurring outbound payments), **direct-debit mandates** (a counterparty authorized to
*pull* up to a cap), and **FX rates** (currency-pair conversion for cross-currency
transfers). testlogon already owns every primitive these reuse — the closest existing
"stored destination" model is `app/services/creator_payouts.py` (payout methods: a
single-key table, `record_kind`-tagged co-located rows, last-4-only masking, a per-user
GSI); money-out flows through the single-entry ledger + per-user wallet in
`app/services/billing_shared.py`; recurring jobs reuse the unified-scheduler /
`scheduled_actions` pattern (`app/services/scheduled_actions.py`,
`app/services/unified_scheduler.py`, `app/services/schedule_executors.py`); and tip-style
paired ledger writes come from `app/services/tip_ledger.py`. These tickets add the
**banking entities + a recurring-payment executor on top of those primitives** — never
forking billing, the scheduler, or the SCA stack.

**The actual money-movement is owned by the TXR cluster** (`OBP_TXN_REQUESTS_SCA_TICKETS.md`):
every outbound payment these tickets emit is a `type=COUNTERPARTY` **Transaction Request**
that walks the `INITIATED → PENDING → COMPLETED | FAILED` machine, is fraud-gated and
SCA-gated, and settles through the ONE money-movement path. PAY tickets create/store the
*entities* and *schedule* the requests; they never move money directly.

This file authors **5 tickets, PAY-001..PAY-005**, in dependency order.

---

## Cross-cutting constraints

- **Additive + flag-gated, default OFF.** New flag `PAYMENTS_COUNTERPARTIES_ENABLED`
  (`S.payments_counterparties_enabled`, default `false`). With the flag off every new
  router 404s and the recurring-payment executor is not registered, so no background
  job runs. Existing payout/tip/billing/scheduler behavior is untouched.
- **TXR-cluster is the only money-out rail (money-safety).** Standing orders and mandates
  **do not** call `apply_wallet_delta` / `new_ledger_entry` / `settle_or_reverse_ledger`
  themselves. They emit a `type=COUNTERPARTY` Transaction Request via the TXR service
  (`app/services/txn_requests.py:create_request`, `OBP_TXN_REQUESTS_SCA_TICKETS.md` TXR-001/004)
  and let TXR execute it. There is exactly ONE place that debits a wallet for an outbound
  payment, and it is `TXR`'s execution dispatch (which itself reuses
  `billing_shared.apply_wallet_delta` + `tip_ledger.write_tip_ledger`). PAY never
  re-implements settlement or refunds and never issues a second debit for the same request.
- **SECOPS-007 dev/prod parity.** One code path for dev (DynamoDB Local + moto + mock KMS)
  and prod (real DynamoDB / SES / KMS). No `if S.dev_mode` business-logic branches; FX
  fetch and any external rail go through existing provider abstractions which already decide
  mock-vs-real underneath.
- **New feature checklist** (per CLAUDE.md "Adding a new feature"): Pydantic models in
  `app/models.py`; services `app/services/counterparties.py`, `app/services/standing_orders.py`,
  `app/services/direct_debit_mandates.py`, `app/services/fx_rates.py`; routers under
  `app/routers/` registered (flag-gated) in `app/main.py`; `TableDef`s in
  `scripts/local-ddb-init.py` (numeric GSI sort keys need `attr_types={...:"N"}` per the
  CLAUDE.md gotcha); FE types/endpoints/page; pytest; `docs/file-reference.md`.
- **Audit everything.** Every create/update/delete and every recurring execution emits
  `audit_event(...)` to `T.alerts` (same helper `billing.py` / `ui_mfa.py` use:
  `from app.services.alerts import audit_event`): `counterparty.created|updated|deleted`,
  `standing_order.created|paused|resumed|executed|skipped`,
  `mandate.created|revoked|debited`, `fx_rate.set`.

## Money-safety constraints (binding on every ticket)

1. **ONE money-out path.** Any outbound payment (standing-order tick, mandate pull) is
   realized as a TXR `type=COUNTERPARTY` Transaction Request. PAY code calls
   `txn_requests.create_request(...)` (+ `execute_request(...)` for scheduler-initiated
   server-side runs) and NEVER calls `apply_wallet_delta`, `new_ledger_entry`, or
   `settle_or_reverse_ledger` directly. TXR's execution reuses the wallet-delta condition
   (`wallet_balance_cents >= :needed`, `billing_shared.py:209`) as the single
   insufficient-funds guard.
2. **Idempotent recurring emission.** Each standing-order / mandate execution is keyed by a
   deterministic `idempotency_key` (`{standing_order_id|mandate_id}#{occurrence_ts}`) passed
   into `create_request` (TXR-001's `idempotency_key` collapses duplicate creates). A
   scheduler retry of the same occurrence reuses the same key → at most ONE Transaction
   Request, hence at most one debit, per occurrence (mirrors `scheduled_actions.claim_action`
   conditional-claim + TXR idempotency).
3. **`next_run` advance is conditional.** A standing order / mandate advances `next_run_at`
   only after the occurrence's request is created, via a conditional `update_item` asserting
   the expected current `next_run_at` (mirrors the `ConditionExpression "#status = :pending"`
   slot-claim in `scheduled_actions.claim_action`, `scheduled_actions.py:380`). Two
   concurrent ticks for the same occurrence: exactly one advances; the loser is a no-op.
4. **Mandate cap is enforced server-side.** A direct-debit pull's `amount_cents` must be
   `<= mandate.max_amount_cents` AND the cadence window's cumulative pulled total must not
   exceed the cap; over-cap → the request is NOT created and the mandate is marked
   `skipped`/`exceeded` (explicit, never a silent partial pull).
5. **FX is read-only against the ledger.** The ledger is single-currency `usd` today
   (`billing_shared.get_wallet_balance` returns `currency="usd"`, `billing_shared.py:181`).
   FX conversion produces a `usd`-denominated `amount_cents` + a recorded `fx_rate` /
   `source_currency` on the request `meta`; it NEVER writes a non-usd ledger row. Settlement
   stays single-currency until a multi-currency ledger lands.

---

### PAY-001: Counterparty / beneficiary entity — DDB model, table, flag + CRUD
**Type**: Backend (data model + endpoints)
**Priority**: P1 (foundation)
**Estimate**: 2.5 days

**Description**
Introduce the stored third-party payee as a first-class user-owned entity and a full CRUD
surface — the destination that COUNTERPARTY Transaction Requests, standing orders, and
mandates all point at.

- **Pydantic models** (`app/models.py`): `CounterpartyCreateIn{ name:str, is_beneficiary:bool=True,
  routing:CounterpartyRouting, description:str|None, bespoke:dict|None }` where
  `CounterpartyRouting{ scheme: Literal["IBAN","ACCOUNT_SORT_CODE","ACCOUNT_NUMBER","BANK"],
  iban:str|None, account_number:str|None, sort_code:str|None, bank_code:str|None,
  bank_name:str|None, account_holder:str|None, currency:str="usd" }`,
  `CounterpartyUpdateIn` (mutable subset), and `CounterpartyOut` (routing returned with
  **last-4-only masking** for `iban`/`account_number` — same SEC-004 masking discipline as
  `creator_payouts.add_payout_method`, `creator_payouts.py:681`, which persists only
  `account_last4`/`routing_last4`). `bespoke` is an opaque user metadata map (OBP's
  "bespoke" counterparty metadata).
- **DDB table** `counterparties` (`TableDef` in `scripts/local-ddb-init.py`):
  PK `user_sub` (S), SK `counterparty_id` (S, `cp_{uuid4().hex}`). GSI `ByUserCreatedAt`
  on `user_sub` (S) / `created_at` (N) — **declare `attr_types={"created_at":"N"}`**
  (CLAUDE.md numeric-GSI gotcha) — for ordered listing. Item carries `name`,
  `is_beneficiary`, the routing fields (only `*_last4` for sensitive numbers, full `iban`/
  `account_number` NOT persisted in clear unless explicitly required by a later rail —
  default last-4 only), `bank_code`/`bank_name`/`account_holder`, `currency`, `bespoke`
  (map), `created_at`/`updated_at` (`now_ts()`). The single-table + `record_kind` discipline
  is not needed (dedicated table), but the access pattern mirrors
  `creator_payouts.list_payout_methods` (per-user GSI query) verbatim.
- **Service** `app/services/counterparties.py`: `create_counterparty`, `get_counterparty`
  (`Key={user_sub, counterparty_id}` ownership → foreign id 404), `list_counterparties`
  (per-user GSI, cursor pagination via `app/core/cursor.py`), `update_counterparty`
  (mutable fields only, conditional on existence), `delete_counterparty` (refuses delete
  if referenced by an active standing order / mandate — checked in PAY-002/003;
  for PAY-001 a simple delete). id helper mirrors `creator_payouts._method_id()`
  (`creator_payouts.py:633`); timestamps via `app/core/time.now_ts()`.
- **Router** `app/routers/counterparties.py` (prefix `/ui/counterparties`,
  `Depends(require_ui_session)`, CSRF enforced for non-GET per CLAUDE.md):
  `POST /ui/counterparties`, `GET /ui/counterparties`, `GET /ui/counterparties/{id}`,
  `PATCH /ui/counterparties/{id}`, `DELETE /ui/counterparties/{id}`. Flag-gate the router
  registration in `app/main.py` on `S.payments_counterparties_enabled` (404 when off).
- **Reuse / cite**: masking + per-user GSI from `creator_payouts.py:651,681`; audit via
  `app.services.alerts.audit_event`; cursor pagination from `app/core/cursor.py`.

**Acceptance Criteria**
- `POST /ui/counterparties` with valid routing returns `201` + a `counterparty_id`; the item
  persists to `counterparties`; sensitive account/IBAN numbers are stored last-4-only and
  returned masked in `CounterpartyOut`.
- All four routing schemes accepted; a malformed routing (e.g. `scheme="IBAN"` with no
  `iban`) → `400`.
- `GET`/`PATCH`/`DELETE` enforce `{user_sub, counterparty_id}` ownership; a foreign id → `404`.
- `GET /ui/counterparties` lists the caller's counterparties newest-first via `ByUserCreatedAt`,
  cursor-paginated.
- Flag OFF → all routes `404`. `audit_event("counterparty.created|updated|deleted", ...)` fired.

**Dependencies**: none (foundation). *(Soft: COUNTERPARTY Transaction Requests in TXR-001
consume this `counterparty_id` as their `target.counterparty_ref`; PAY-001 is the entity
TXR's free-form opaque ref resolves to once both land.)*

---

### PAY-002: Standing orders — recurring outbound payment entity + scheduler executor
**Type**: Backend (entity + recurring job)
**Priority**: P1
**Estimate**: 3.5 days

**Description**
Add the user-defined recurring outbound payment (a "standing order": pay counterparty X,
amount Y, every cadence Z) plus a scheduler executor that, on each due tick, emits a
COUNTERPARTY Transaction Request — reusing the unified-scheduler pattern, not a new loop.

- **Pydantic models** (`app/models.py`): `StandingOrderCreateIn{ counterparty_id:str,
  amount_cents:int>0, currency:str="usd", cadence: Literal["weekly","biweekly","monthly"],
  start_at:int, end_at:int|None, reason:str|None }`, `StandingOrderUpdateIn` (amount/cadence/
  end_at/pause), `StandingOrderOut{ standing_order_id, counterparty_id, amount_cents, currency,
  cadence, status, next_run_at, last_run_at|None, runs_count, created_at, updated_at }`.
  `status ∈ {active, paused, completed, cancelled}`.
- **DDB table** `standing_orders` (`TableDef`): PK `user_sub` (S), SK `standing_order_id`
  (S, `so_{uuid4().hex}`). GSI `ByDue` with `GSI_DUE_PK="DUE"` (S) / `next_run_at` (N) —
  **`attr_types={"next_run_at":"N"}`** — so the scheduler can range-query due orders exactly
  like `scheduled_actions` does with `GSI_DUE_PK`/`GSI_DUE_SK`
  (`scheduled_actions.py:357`). On pause/complete/cancel, `GSI_DUE_PK`/`next_run_at` are
  `REMOVE`d from the index so the runner never selects them (mirrors
  `scheduled_actions.cancel_action`'s `REMOVE GSI_DUE_PK, GSI_DUE_SK`,
  `scheduled_actions.py:251`).
- **Service** `app/services/standing_orders.py`: CRUD (validates `counterparty_id` resolves
  to an owned counterparty via `counterparties.get_counterparty`); `_next_occurrence(cadence,
  from_ts)` computes the next run; `pause`/`resume` (toggle `status` + add/remove the due-GSI
  keys); `cancel`. **`execute_due_standing_order(user_sub, standing_order_id)`**:
  1. Build the deterministic `idempotency_key = f"{standing_order_id}#{next_run_at}"`
     (money-safety #2).
  2. Resolve the counterparty + its `currency`; if `currency != "usd"`, convert via
     `fx_rates.convert(...)` (PAY-004) and stamp `fx_rate`/`source_currency` on the request
     `meta` (money-safety #5).
  3. Emit the payment as a TXR `type=COUNTERPARTY` request:
     `txn_requests.create_request(user_sub, TxnRequestCreateIn(type="COUNTERPARTY",
     amount_cents=..., currency="usd", target={"counterparty_ref": counterparty_id},
     reason="standing_order", idempotency_key=...))` then, for the server-initiated run,
     `txn_requests.execute_request(user_sub, request_id, req=None)` — TXR owns the wallet
     debit, fraud gate, and (if it crosses the SCA threshold) the PENDING/SCA hold.
     **PAY never debits the wallet itself** (money-safety #1).
  4. **Advance `next_run_at` conditionally** to `_next_occurrence(cadence, prev_next_run_at)`
     via a conditional `update_item` asserting the old `next_run_at` (money-safety #3); if the
     new occurrence is past `end_at`, set `status="completed"` and remove the due-GSI keys.
     Bump `runs_count`, set `last_run_at`.
- **Scheduler integration — reuse the unified scheduler, don't fork it.** Register a new
  action executor by adding `"standing_order_tick"` to the `_EXECUTORS` map in
  `app/services/unified_scheduler.py:28` (executor signature `async def execute(user_sub,
  payload)` matches `schedule_executors.execute_scheduled_post`,
  `schedule_executors.py:15`). The standing-order service is driven by a thin polling helper
  that queries the `standing_orders` `ByDue` GSI for `next_run_at <= now` (same query shape as
  `scheduled_actions.query_due_actions`, `scheduled_actions.py:355`) and calls
  `execute_due_standing_order` per order. Wire it into the existing
  `run_unified_scheduler_loop` cycle (a new step alongside "process due actions"), gated on
  `S.payments_counterparties_enabled` so it's inert when the flag is off — **no second
  asyncio loop / startup task** (reuses `start_unified_scheduler_task`,
  `unified_scheduler.py:185`, already registered in `app/main.py:973`).
- **Reuse / cite**: due-GSI range query + conditional claim + REMOVE-from-index from
  `scheduled_actions.py:357,380,251`; executor registry from `unified_scheduler.py:28`;
  money-out exclusively via TXR (`txn_requests.create_request`/`execute_request`).

**Acceptance Criteria**
- `POST /ui/standing-orders` with a valid owned `counterparty_id` returns `201` with
  `status="active"` and a computed `next_run_at`; an unknown/foreign `counterparty_id` → `400`/`404`.
- On a due tick, exactly one COUNTERPARTY Transaction Request is created with
  `idempotency_key="{standing_order_id}#{next_run_at}"`; the standing order's `next_run_at`
  advances by one cadence and `runs_count` increments.
- A scheduler **retry of the same occurrence** (same `next_run_at`) reuses the idempotency key
  and produces **no second** Transaction Request and **no second** debit (money-safety #2/#3).
- Reaching `end_at` flips `status="completed"` and removes the order from the `ByDue` GSI;
  `pause` removes it from the GSI; `resume` re-adds it.
- Flag OFF → routes `404` and the standing-order step in the scheduler loop is skipped.
- `audit_event("standing_order.created|executed|paused|resumed|skipped", ...)` fired.

**Dependencies**: PAY-001 (counterparty), TXR-001/TXR-004 (COUNTERPARTY request + execution),
PAY-004 (FX, only for non-usd counterparties — soft).

---

### PAY-003: Direct-debit mandates — pull authorization, cap enforcement + execution hook
**Type**: Backend (entity + recurring pull)
**Priority**: P1
**Estimate**: 3 days

**Description**
Add the direct-debit mandate: an authorization for a counterparty to *pull* up to a capped
amount on a cadence (the inverse direction of a standing order — initiated on the payee's
behalf but always bounded by the payer's stored authorization). Reuse the same scheduler +
TXR rail; the only new logic is cap enforcement.

- **Pydantic models** (`app/models.py`): `MandateCreateIn{ counterparty_id:str,
  max_amount_cents:int>0, currency:str="usd", cadence: Literal["weekly","monthly"],
  start_at:int, end_at:int|None, reference:str|None }`, `MandateOut{ mandate_id,
  counterparty_id, max_amount_cents, currency, cadence, status, next_run_at, last_run_at|None,
  pulled_this_window_cents, runs_count, created_at, updated_at }`. `status ∈ {active, paused,
  revoked, completed}`.
- **DDB table** `direct_debit_mandates` (`TableDef`): PK `user_sub` (S), SK `mandate_id`
  (S, `dd_{uuid4().hex}`). GSI `ByDue` `GSI_DUE_PK="DUE"` (S) / `next_run_at` (N) —
  **`attr_types={"next_run_at":"N"}`** — same due-index discipline as PAY-002. Item carries
  `max_amount_cents`, `currency`, `cadence`, `pulled_this_window_cents`, `window_started_at`,
  `runs_count`, `status`, timestamps.
- **Service** `app/services/direct_debit_mandates.py`: CRUD (validates owned
  `counterparty_id`); **`revoke`** (the user's kill switch — sets `status="revoked"`, removes
  the due-GSI keys so no further pulls occur). **`execute_mandate_pull(user_sub, mandate_id,
  pull_amount_cents)`**:
  1. **Cap enforcement (money-safety #4)**: reject (mark `skipped`/`exceeded`, no request
     created) when `pull_amount_cents > max_amount_cents` OR
     `pulled_this_window_cents + pull_amount_cents > max_amount_cents` for the current cadence
     window. The window resets (`pulled_this_window_cents=0`, new `window_started_at`) when the
     cadence window rolls over.
  2. Emit a TXR `type=COUNTERPARTY` request (same `create_request` + server-side
     `execute_request` path as PAY-002), with `idempotency_key=f"{mandate_id}#{next_run_at}"`
     and `reason="direct_debit"` — **TXR owns the debit** (money-safety #1).
  3. On a created request, conditionally advance `next_run_at` and add `pull_amount_cents` to
     `pulled_this_window_cents` (conditional `update_item`, money-safety #3).
- **Scheduler integration**: register `"direct_debit_tick"` in the `_EXECUTORS` map
  (`unified_scheduler.py:28`) and query `direct_debit_mandates` `ByDue` for due pulls in the
  same `run_unified_scheduler_loop` cycle, gated on `S.payments_counterparties_enabled`. Same
  no-new-loop reuse as PAY-002.
- **Reuse / cite**: due-GSI + conditional advance from `scheduled_actions.py:357,251`; TXR
  money-out rail (`txn_requests.create_request`/`execute_request`); revoke mirrors
  `standing_orders.pause` (PAY-002) which mirrors `scheduled_actions.cancel_action`.

**Acceptance Criteria**
- `POST /ui/mandates` with an owned `counterparty_id` returns `201`, `status="active"`,
  `next_run_at`; foreign counterparty → `400`/`404`.
- A pull within cap creates exactly one COUNTERPARTY Transaction Request and increments
  `pulled_this_window_cents`; the mandate's `next_run_at` advances by one cadence.
- A pull whose `amount` (or cumulative window total) exceeds `max_amount_cents` creates **no**
  request, debits **nothing**, and marks the occurrence `skipped`/`exceeded` (money-safety #4).
- `revoke` removes the mandate from the `ByDue` GSI and prevents all further pulls.
- A scheduler retry of the same occurrence reuses the idempotency key → no double pull
  (money-safety #2/#3).
- Flag OFF → routes `404`. `audit_event("mandate.created|revoked|debited|skipped", ...)` fired.

**Dependencies**: PAY-001 (counterparty), TXR-001/TXR-004, PAY-004 (FX for non-usd — soft).

---

### PAY-004: FX rate store + convert helper for cross-currency requests
**Type**: Backend (data model + helper)
**Priority**: P1
**Estimate**: 2 days

**Description**
Add an FX-rate store (currency-pair → rate, admin-set or fetched) and a pure `convert`
helper that cross-currency standing orders / mandates / COUNTERPARTY requests call to express
a non-usd amount in the ledger's single `usd` currency. The ledger stays single-currency;
FX only annotates the request.

- **Pydantic models** (`app/models.py`): `FxRateSetIn{ source_currency:str, target_currency:str,
  rate: float>0, source: Literal["admin","fetched"]="admin" }`, `FxRateOut{ pair, source_currency,
  target_currency, rate, source, as_of:int, set_by:str }`, `FxConvertOut{ source_currency,
  target_currency, source_amount_cents, target_amount_cents, rate, as_of }`.
- **DDB table** `fx_rates` (`TableDef`): PK `pair` (S, `"{SRC}_{TGT}"`, e.g. `EUR_USD`),
  SK `as_of` (N) — **`attr_types={"as_of":"N"}`** — so historical rates are retained and the
  newest is read with `ScanIndexForward=False, Limit=1`. Item carries `source_currency`,
  `target_currency`, `rate` (stored as a string/Decimal-safe scaled int to avoid float drift —
  e.g. `rate_micros` = `round(rate * 1_000_000)`), `source`, `set_by`, `as_of` (`now_ts()`).
- **Service** `app/services/fx_rates.py`:
  - `set_rate(source_currency, target_currency, rate, *, source, set_by)` — admin-set; writes
    a new `as_of` row (append-only history). Identity pair (`USD_USD`) is implicitly `1.0` and
    never stored.
  - `get_rate(source_currency, target_currency) -> FxRateOut|None` — newest row for the pair
    (`Limit=1, ScanIndexForward=False`); `USD_USD` → synthetic `1.0`.
  - `convert(amount_cents:int, source_currency, target_currency) -> FxConvertOut` — pure
    helper: `target_amount_cents = round(amount_cents * rate)` using the scaled-int rate
    (integer math; no float accumulation), returns the rate + `as_of` used so callers can
    persist it on the request `meta`. Missing pair → raises `LookupError("fx_rate_missing")`
    (the caller decides whether to fail the occurrence). **`convert` writes no ledger row**
    (money-safety #5).
  - (Optional, behind the same provider abstraction) `refresh_fetched_rates()` for a
    fetched-source update — dev returns a deterministic mock table, prod hits the configured
    FX provider; no `if S.dev_mode` in business logic (SECOPS-007).
- **Router** `app/routers/fx_rates.py`: `GET /ui/fx/rates` + `GET /ui/fx/convert?amount_cents=
  &from=&to=` (`Depends(require_ui_session)`, read-only, any user); `POST /ui/admin/fx/rates`
  (`Depends(require_admin_session)`, admin-set, CSRF). Flag-gate registration on
  `S.payments_counterparties_enabled`.
- **Reuse / cite**: newest-row-by-numeric-SK pattern mirrors the day-bucketed ledger GSI
  reads (`billing_shared.ledger_date_for_ts`, `billing_shared.py:10`); admin gate from
  `Depends(require_admin_session)` per CLAUDE.md router conventions; scaled-int money math
  keeps parity with the `amount_cents` integer discipline used throughout
  `billing_shared.py` / `tip_ledger.py`.

**Acceptance Criteria**
- `POST /ui/admin/fx/rates` (admin) sets a pair; `GET /ui/fx/rates` returns the newest rate
  per pair; a non-admin POST → `403`.
- `GET /ui/fx/convert?amount_cents=10000&from=EUR&to=USD` returns the converted
  `target_amount_cents` computed with integer (scaled-rate) math and echoes `rate`/`as_of`.
- `convert(USD→USD)` is identity (rate `1.0`); a missing pair → `LookupError`/`404`.
- `convert` writes **no** ledger or wallet row; rate history is append-only (each `set_rate`
  adds a new `as_of` row, prior rates retained).
- Flag OFF → routes `404`.

**Dependencies**: none (used by PAY-002/PAY-003 for non-usd counterparties; independently
shippable). Build before/with PAY-002/003.

---

### PAY-005: Tests + frontend
**Type**: Tests + Frontend
**Priority**: P2
**Estimate**: 3 days

**Description**
Lock the counterparty/standing-order/mandate/FX surface behind regression tests and expose a
typed frontend client + page.

- **Pytest** (offline/hermetic, matching the repo pattern in
  `tests/test_gap_0286_0287_kyc_partner_api.py` / `tests/test_compute_billing_timer_gap0228.py`:
  moto in-memory tables bound to the frozen `T.*` handles via `object.__setattr__`, `S` flags
  flipped via `object.__setattr__`, `now_ts` patched, route handlers invoked directly; the TXR
  `txn_requests.create_request`/`execute_request` collaborator and FX provider patched — no
  real AWS/network):
  - `tests/test_pay_counterparties.py`: CRUD + ownership (`404` foreign id) + last-4 masking +
    routing-scheme validation.
  - `tests/test_pay_standing_orders.py`: create computes `next_run_at`; a due tick emits exactly
    one COUNTERPARTY request with the deterministic idempotency key; **retry of the same
    occurrence emits no second request** (assert `create_request` call count == 1 for the
    occurrence); `next_run_at` advances conditionally (two concurrent ticks → one advances);
    `end_at` → `completed` + removed from `ByDue`; pause/resume toggle the due-GSI keys.
  - `tests/test_pay_mandates.py`: within-cap pull emits one request + increments
    `pulled_this_window_cents`; **over-cap pull emits no request and debits nothing**
    (money-safety #4); `revoke` stops further pulls; window rollover resets the counter.
  - `tests/test_pay_fx_rates.py`: admin set + newest-rate read; integer convert math
    (no float drift); `USD_USD` identity; missing pair raises; `convert` writes no ledger row.
- **Frontend types** (`frontend/src/api/types.ts`): `Counterparty`, `CounterpartyRouting`,
  `StandingOrder`, `Mandate`, `FxRate`, plus the `*CreateIn` shapes. **Endpoints**
  (`frontend/src/api/endpoints/counterparties.ts`, `standingOrders.ts`, `mandates.ts`,
  `fx.ts`) via the axios instance in `api/client.ts` (CSRF cookie header attached
  automatically).
- **Frontend page** under `frontend/src/pages/payments/` (route added to
  `frontend/src/App.tsx`, flag-aware): a Beneficiaries tab (counterparty CRUD with masked
  routing), a Standing Orders tab (create against a counterparty, pause/resume/cancel, show
  `next_run_at`/`runs_count`), a Mandates tab (create with cap, revoke, show
  `pulled_this_window_cents`), and an FX panel (view rates, convert preview). React Query
  (`useQuery`/`useMutation`) per CLAUDE.md frontend conventions; forms via React Hook Form +
  Zod. When a standing-order/mandate execution returns a TXR request in `PENDING` (SCA
  required), surface the existing TXR/MFA SCA dialog (reuse from `OBP_TXN_REQUESTS_SCA_TICKETS.md`
  TXR-005) rather than building a new one.
- **E2E** `frontend/e2e/payments-counterparties.spec.ts` (flag-gated; seed via session-auth
  `page.request` with `x-csrf-token` per CLAUDE.md): create counterparty → create standing
  order → manually trigger a due tick (or fast-forward `next_run_at`) → assert exactly one
  COUNTERPARTY request appears; create mandate → over-cap pull skipped, within-cap pull
  succeeds; admin sets an FX rate and convert preview reflects it.
- **Docs**: update `docs/file-reference.md` with the new services/routers/tables/FE files and
  add a CLAUDE.md "Common gotchas" entry (flag, TXR-is-the-only-money-out-path,
  deterministic-idempotency-key, conditional next_run advance, mandate cap, single-currency
  ledger / FX-annotates-only).

**Acceptance Criteria**
- All four pytest modules pass offline (no live stack), covering CRUD/ownership/masking,
  one-request-per-occurrence idempotency (single money emission), conditional `next_run`
  advance, mandate cap enforcement (no over-cap debit), and integer FX convert math.
- FE page drives counterparty CRUD → standing-order/mandate creation → (optional SCA via the
  existing TXR/MFA dialog) and reflects live status; E2E spec green with the flag on.
- `docs/file-reference.md` + CLAUDE.md updated.

**Dependencies**: PAY-001, PAY-002, PAY-003, PAY-004.

---

## Dependency graph (build order)

```
PAY-001 (counterparty entity + CRUD)
   ├─> PAY-004 (FX store + convert)        [independently shippable; needed by PAY-002/003 for non-usd]
   ├─> PAY-002 (standing orders → COUNTERPARTY TXR on schedule)
   │        (consumes PAY-001 + PAY-004; money-out via TXR-001/TXR-004)
   └─> PAY-003 (direct-debit mandates → capped COUNTERPARTY TXR on schedule)
            (consumes PAY-001 + PAY-004; money-out via TXR-001/TXR-004)
                 └─> PAY-005 (tests + frontend)   [depends on PAY-001..004]
```

**External dependency:** the entire money-out rail is the **TXR cluster**
(`OBP_TXN_REQUESTS_SCA_TICKETS.md`, TXR-001 create + TXR-004 execute, `type=COUNTERPARTY`).
PAY entities/schedulers create and trigger Transaction Requests; they never settle money
themselves. ACC (accounts) is a soft dependency — counterparties attach to a user today and
can be re-keyed to an account_id when the ACC entity lands.
