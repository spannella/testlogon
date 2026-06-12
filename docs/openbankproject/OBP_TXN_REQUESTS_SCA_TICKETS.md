# OBP Tier-1 — Transaction Requests + Step-Up SCA on Payments (prefix `TXR`)

Derived from `docs/openbankproject/OBP_GAP_ANALYSIS.md` (Tier 1, §B/§C). Open Bank
Project's signature money-movement primitive is the **Transaction Request**: a single
*typed* payment-initiation object that walks a status machine
(`INITIATED → PENDING → COMPLETED | FAILED`) and, on high-value/sensitive transfers,
is **held PENDING behind a step-up SCA (OTP) challenge** before the underlying money
moves. testlogon already owns every primitive this needs — a single-entry ledger +
per-user wallet (`app/services/billing_shared.py`), the full SCA challenge/answer stack
(`app/services/mfa.py`, `app/routers/ui_mfa.py`, `app/services/sessions.py`), tip/payout
ledger flows, a fraud gate, and the atomic `transact_write_items` escrow pattern in
`app/services/group_treasury.py`. These tickets add a **unified typed request object as a
thin orchestration layer over those primitives** — never forking billing.

This file authors **5 tickets, TXR-001..TXR-005**, in dependency order.

---

## Cross-cutting constraints

- **Additive + flag-gated, default OFF.** New flag `TXN_REQUESTS_ENABLED` (`S.txn_requests_enabled`,
  default `false`). With the flag off, every new endpoint 404/503s and no startup task runs.
  Existing billing/tip/payout/refund endpoints are untouched.
- **SECOPS-007 dev/prod parity.** One code path for dev (DynamoDB Local + moto + mock KMS +
  the dev-mode mock OTP branches already in `mfa.py`) and prod (real DynamoDB/SES/Twilio/KMS).
  No `if S.dev_mode` business-logic branches in the request engine — only the existing
  provider abstractions decide mock-vs-real underneath.
- **New feature checklist** (per CLAUDE.md "Adding a new feature"): models in `app/models.py`,
  service in `app/services/txn_requests.py`, router `app/routers/txn_requests.py` registered in
  `app/main.py`, `TableDef` in `scripts/local-ddb-init.py` (numeric GSI sort keys need
  `attr_types={...:"N"}`), FE types/endpoints/hook, pytest, `docs/file-reference.md`.
- **Audit everything.** Every transition emits `audit_event(...)` to `T.alerts`
  (same helper `app/routers/billing.py` / `app/routers/ui_mfa.py` use:
  `from app.services.alerts import audit_event`): `txn_request.created`,
  `txn_request.sca_required`, `txn_request.sca_passed`, `txn_request.executed`,
  `txn_request.failed`.

## Money-safety constraints (binding on every ticket)

1. **ONE refund mechanism.** `type=REFUND` execution calls the EXISTING `refund_payment`
   path semantics in `app/routers/billing.py:1287` (Stripe `Refund.create` + `new_ledger_entry`
   `adjustment/refund` + `settle_or_reverse_ledger(... "reversed")` + `update_payment_status` +
   `mark_reverted`). The request engine does NOT re-implement refunds and never issues a second
   `Refund.create` for the same `payment_intent_id`.
2. **No double-charge / no double-spend.** Wallet debits go through
   `billing_shared.apply_wallet_delta(table, pk, -amount)` whose `ConditionExpression`
   (`wallet_balance_cents >= :needed`) is the single source of truth for "sufficient funds";
   a failed condition → `FAILED`, never a partial move. Execution is **idempotent** (TXR-004):
   the same `request_id` executed twice moves money exactly once.
3. **Status is the lock.** Money moves only on the `PENDING → COMPLETED` transition, guarded by
   a conditional `update_item` (`attribute current status == PENDING`), mirroring the atomic
   slot-claim in `creator_payouts.claim_payout_sentinel` / `group_treasury._batch_transact`.
   A losing concurrent caller sees `ConditionalCheckFailedException` and returns the already-
   terminal request — never a re-execution.
4. **Fraud gate on EXECUTE, not just create.** Before the underlying money movement, execution
   calls `billing._fraud_gate(user_id, amount_cents, entry_type, req=req)` (freeze check always
   runs; `block` → 403; `flag` → logged-through) exactly as the live charge endpoints do.
5. **SCA gates value, not the engine.** The OTP challenge is reused verbatim from the MFA stack
   (no new crypto). PEM/OTP secrets never leave the server; the client only ever sees a
   `challenge_id` + `required_factors`.

---

### TXR-001: TransactionRequest entity — DDB model, table, flag + create endpoint (records INITIATED)
**Type**: Backend (data model + endpoint)
**Priority**: P1 (foundation)
**Estimate**: 2.5 days

**Description**
Introduce the unified typed money-movement request object as a new DynamoDB entity and a
single create endpoint that records an `INITIATED` request (no money moves yet).

- **Type enum** `TxnRequestType ∈ {WALLET_TRANSFER, COUNTERPARTY, PAYOUT, REFUND, FREE_FORM}`.
  - `WALLET_TRANSFER` → internal wallet→wallet move (debit sender wallet, credit recipient wallet).
  - `PAYOUT` → creator payout to an external method.
  - `REFUND` → reverse a settled payment.
  - `COUNTERPARTY` → push to a third-party payee (target carries a counterparty ref; until the
    Tier-2 Counterparties entity lands, `target` is a free-form opaque ref persisted as-is).
  - `FREE_FORM` → narrative-only request with `target.to_user_sub` optional (maps to a tip-style
    wallet credit / `tip_ledger` entry).
- **Pydantic models** (`app/models.py`): `TxnRequestCreateIn{ type, amount_cents:int>0, currency="usd",
  target:dict, reason:str|None, idempotency_key:str|None }`, `TxnRequestOut{ request_id, type,
  amount_cents, currency, target, status, sca_challenge_id|None, ledger_refs:list, created_at,
  updated_at, failure_reason|None }`. `target` shape is per-type: `{to_user_sub}` (WALLET_TRANSFER/
  FREE_FORM), `{payout_method_id}` (PAYOUT), `{payment_intent_id}` (REFUND), `{counterparty_ref}`
  (COUNTERPARTY).
- **DDB table** `txn_requests` (`TableDef` in `scripts/local-ddb-init.py`):
  PK `user_sub` (S), SK `request_id` (S, `txr_{uuid4().hex}`). GSI `GSI_STATUS` on
  `status` (S) / `created_at` (N) — **declare `attr_types={"created_at":"N"}`** (CLAUDE.md numeric
  GSI gotcha) — for the sweep in TXR-003 and status listings. Item carries `type`, `amount_cents`,
  `currency`, `target` (map), `status`, `reason`, `idempotency_key`, `created_at`/`updated_at`
  (`now_ts()`), and (later) `sca_challenge_id`, `ledger_refs`, `failure_reason`.
- **Service** `app/services/txn_requests.py`: `create_request(user_sub, body, req)`:
  validates `amount_cents > 0` and per-type `target` shape; writes the item with `status="INITIATED"`;
  returns `TxnRequestOut`. **No money moves here** — INITIATED is the durable record only.
- **Router** `app/routers/txn_requests.py` (prefix `/ui/txn-requests`, `Depends(require_ui_session)`,
  CSRF enforced for the POST per CLAUDE.md): `POST /ui/txn-requests` → create. Flag-gate the router
  registration in `app/main.py` on `S.txn_requests_enabled` (404 when off).
- **Reuse / cite**: timestamps via `app/core/time.now_ts()`; id helper mirrors
  `billing_shared.ulidish()` / `creator_payouts._method_id()`; audit via
  `app.services.alerts.audit_event` (as in `billing.py`/`ui_mfa.py`). Single-table item shape
  follows the `LEDGER#{ts}#{id}` convention in `billing_shared.ledger_sk`.

**Acceptance Criteria**
- `POST /ui/txn-requests` with a valid body returns `201` with `status="INITIATED"` and a
  `request_id`; the item is persisted to `txn_requests`.
- All 5 types accepted; per-type `target` validation rejects a malformed target with `400`.
- `amount_cents <= 0` → `400`. Flag OFF → route returns `404`. No ledger/wallet row is written on create.
- `audit_event("txn_request.created", ...)` fired. `created_at` queryable via `GSI_STATUS`.

**Dependencies**: none (foundation).

---

### TXR-002: Status state-machine + get-status endpoint + per-type amount-limit config
**Type**: Backend (state machine + config)
**Priority**: P1
**Estimate**: 2 days

**Description**
Formalize the lifecycle and expose read + limits.

- **State machine** in `txn_requests.py`: legal transitions
  `INITIATED → PENDING` (SCA required, TXR-003), `INITIATED → COMPLETED` (no SCA needed, TXR-004),
  `PENDING → COMPLETED` (SCA passed → execute, TXR-004), `{INITIATED,PENDING} → FAILED`. Terminal:
  `COMPLETED`, `FAILED`. Every write uses a **conditional `update_item`** asserting the expected
  current `status` (CLAUDE.md: "status is the lock") — an illegal/concurrent transition raises
  `ConditionalCheckFailedException` and is mapped to `409 invalid_transition` (mirrors the
  conditional-update guard in `tickets._conditional_update_meta` and the
  `group_treasury._batch_transact` atomic pattern). Helper `_transition(user_sub, request_id,
  expected_status, new_status, **patch)`.
- **Get-status endpoint**: `GET /ui/txn-requests/{request_id}` → current `TxnRequestOut`
  (incl. `status`, `sca_challenge_id`, `ledger_refs`, `failure_reason`). `GET /ui/txn-requests`
  lists the caller's requests (optional `?status=` filter via `GSI_STATUS`, cursor pagination via
  `app/core/cursor.py`). Both `Depends(require_ui_session)`; ownership enforced by the
  `Key={user_sub, request_id}` access pattern (foreign id → `404`).
- **Per-type amount limits** (`app/core/settings.py`, env-configurable, sensible defaults):
  `TXN_REQUEST_LIMIT_WALLET_TRANSFER_CENTS`, `..._COUNTERPARTY_CENTS`, `..._PAYOUT_CENTS`,
  `..._REFUND_CENTS`, `..._FREE_FORM_CENTS`, plus the SCA threshold `TXN_REQUEST_SCA_THRESHOLD_CENTS`
  (default e.g. `5000` = $50) consumed by TXR-003. `enforce_amount_limit(type, amount_cents)`:
  amount over the per-type ceiling → `400 amount_over_limit` at create time (called from TXR-001's
  `create_request`, so it gates BEFORE INITIATED is recorded). Limits read live from `S` so an env
  change takes effect without code change (mirrors `creator_payouts` reading
  `billing_config.get_min_payout_cents()`).

**Acceptance Criteria**
- `GET /ui/txn-requests/{id}` returns the live status; a foreign/unknown id → `404`.
- An attempted illegal transition (e.g. `COMPLETED → PENDING`) → `409 invalid_transition`; the
  persisted status is unchanged.
- `amount_cents` above the per-type ceiling → `400 amount_over_limit` at create, no item written.
- Two concurrent transitions on the same request: exactly one succeeds, the other gets `409`
  and reads the already-terminal state.
- Limits are env-driven (changing the env var changes the ceiling with no code change).

**Dependencies**: TXR-001.

---

### TXR-003: Step-up SCA challenge — mint OTP on threshold, hold request PENDING
**Type**: Backend (SCA integration)
**Priority**: P1
**Estimate**: 3 days

**Description**
On create, decide whether the request needs step-up SCA; if so, mint an OTP challenge reusing the
MFA stack and hold the request `PENDING` until the user answers.

- **SCA decision** `_sca_required(user_sub, type, amount_cents) -> (bool, required_factors)`:
  require SCA when `amount_cents >= S.txn_request_sca_threshold_cents` **OR** `type` is in a
  sensitive set (`{PAYOUT, REFUND, COUNTERPARTY}` — money leaving the platform / reversing a
  charge). `required_factors` comes from `sessions.compute_required_factors(user_sub)`
  (`app/services/sessions.py:571` — reads enrolled+enabled TOTP/SMS/EMAIL devices). If the user has
  **no** enrolled factor and SCA is required, fall back to an email OTP to the account email via the
  existing `mfa.email_begin_enroll`-style send (or reject with `409 sca_enrollment_required` if no
  verified email — decide per security review; default: require at least one factor).
- **Mint the challenge** by reusing `sessions.create_action_challenge(req, user_sub,
  purpose="txn_request_sca", send_to=[...], payload={"request_id": request_id, "amount_cents": ...,
  "type": ...}, ttl_seconds=300)` (`app/services/sessions.py:626`). This is the SAME challenge item
  type the `/ui/mfa/*` verify endpoints load via `sessions.load_challenge_or_401` and mark via
  `sessions.mark_factor_passed`. The `purpose` field keeps it out of the login-finalize path
  (`maybe_finalize` returns `None` for purposeful challenges — `sessions.py:657`).
- **Hold PENDING**: `create_request` (TXR-001) now, when `_sca_required` is true, transitions
  `INITIATED → PENDING`, stamps `sca_challenge_id` onto the request item, and returns
  `TxnRequestOut` with `status="PENDING"`, `sca_challenge_id`, and `required_factors`. When SCA is
  NOT required, the request stays `INITIATED` and is immediately eligible for execution (TXR-004).
- **OTP delivery / answer reuses the existing routes verbatim** — the client drives
  `POST /ui/mfa/sms/begin`, `/ui/mfa/email/begin` and `/ui/mfa/{totp,sms,email}/verify`
  (`app/routers/ui_mfa.py`) with the returned `challenge_id`. Each verify calls
  `mark_factor_passed`; `sessions.challenge_done(chal)` (`sessions.py:566`) tells TXR-004 when all
  `required_factors` are satisfied. **No new OTP code, send path, or crypto is added** — dev-mode
  mock OTP (`mfa.py`) and prod Twilio/SES are inherited unchanged (SECOPS-007).
- **Audit**: `txn_request.sca_required` on mint; the MFA verify routes already audit
  `mfa_*_verify`. Rate-limiting on OTP attempts is inherited from
  `rate_limit_mfa_verify` in `ui_mfa.py`.

**Acceptance Criteria**
- A request `>= S.txn_request_sca_threshold_cents` (or a sensitive type) returns `status="PENDING"`
  with a non-null `sca_challenge_id` + `required_factors`; the underlying `T.sessions` challenge
  item exists with `purpose="txn_request_sca"` and `passed` map seeded `false`.
- A sub-threshold non-sensitive request returns `status="INITIATED"` and **no** challenge.
- Driving the existing `/ui/mfa/*/verify` routes with the returned `challenge_id` flips the
  matching `passed.<factor>` to `true`; `challenge_done` is `true` only when every required factor
  passes.
- The challenge expires per its TTL (default 300s); an expired/revoked challenge is rejected by the
  existing `load_challenge_or_401` guard (`sessions.py:517`).
- `audit_event("txn_request.sca_required", ...)` fired with `request_id` + `challenge_id`.

**Dependencies**: TXR-001, TXR-002.

---

### TXR-004: Execution — money movement via existing primitives, fraud-gated, idempotent → COMPLETED
**Type**: Backend (execution engine)
**Priority**: P1
**Estimate**: 3.5 days

**Description**
Execute the underlying money movement once SCA (if any) is satisfied, dispatching by `type` to the
**existing** ledger/wallet/payout/refund primitives. Flip to `COMPLETED` (or `FAILED`). Idempotent.

- **Endpoint** `POST /ui/txn-requests/{request_id}/execute` (`require_ui_session`, CSRF). Preconditions:
  - Request must be `INITIATED` (no SCA) or `PENDING` (SCA). If `PENDING`, load the challenge via
    `sessions.load_challenge_or_401(user_sub, sca_challenge_id)` and require
    `sessions.challenge_done(chal)` → else `403 sca_incomplete`. Optionally revoke the challenge
    on success (`sessions.revoke_challenge`, `sessions.py:530`) so it can't be reused.
  - **Fraud gate**: call `billing._fraud_gate(user_id, amount_cents, entry_type, req=req)`
    (`app/routers/billing.py:118`) — freeze check always runs (`403`), `block` → `403`,
    `flag` → logged-through. (`entry_type` mapped per type: `debit` for transfers/payout/counterparty,
    `adjustment` for refund.)
- **Idempotency** — the `PENDING|INITIATED → COMPLETED` transition is a single conditional
  `update_item` (expected status `PENDING` or `INITIATED`). A second `execute` finds a terminal
  status, short-circuits, and returns the existing `TxnRequestOut` (money moved exactly once —
  money-safety #2/#3). The optional `idempotency_key` from TXR-001 additionally collapses
  duplicate *creates* (look up by key before INITIATED).
- **Dispatch by type — reuse, never fork billing**:
  - `WALLET_TRANSFER` / `FREE_FORM`: debit sender wallet via
    `billing_shared.apply_wallet_delta(T.billing, user_pk(sender), -amount)` (its
    `ConditionExpression wallet_balance_cents >= :needed`, `billing_shared.py:185`, is the
    insufficient-funds guard → on `ConditionalCheckFailedException` flip to `FAILED
    insufficient_funds`), then credit recipient via `apply_wallet_delta(..., +amount)`, and record
    paired ledger rows via `tip_ledger.write_tip_ledger(TipLedgerEntry(...))`
    (`app/services/tip_ledger.py:89`) which already writes the debit+credit + platform-fee split.
    For atomicity of the two wallet legs, build the debit/credit as a single
    `transact_write_items` batch using the low-level client pattern in
    `group_treasury._transact_client` / `_batch_transact` (`group_treasury.py:716,743`) — the
    bounty-escrow atomic move.
  - `PAYOUT`: delegate to `creator_payouts.request_payout(user_id, amount_cents, method_id=...)`
    (`app/services/creator_payouts.py:282`) — it already validates min/available-balance and
    atomically claims the per-user payout slot (`claim_payout_sentinel`, GAP-0309). Persist the
    returned `payout_id` into the request's `ledger_refs`.
  - `REFUND`: invoke the EXISTING refund semantics from `billing.refund_payment`
    (`billing.py:1287`) for `target.payment_intent_id` — `Stripe Refund.create` +
    `new_ledger_entry(entry_type="adjustment", reason="refund", state="settled")` +
    `apply_balance_delta(...negative...)` + `settle_or_reverse_ledger(... "reversed")` +
    `update_payment_status("refunded")` + `mark_reverted`. **ONE refund mechanism** (money-safety #1):
    factor the body of `refund_payment` into a reusable `billing._do_refund(...)` callable from both
    the legacy endpoint and the engine, so there is exactly one place that calls
    `stripe.Refund.create`. Never refund the same `payment_intent_id` twice.
  - `COUNTERPARTY`: until the Tier-2 Counterparties entity exists, route through the wallet-debit +
    `new_ledger_entry(entry_type="debit", reason="counterparty_payment", extra={...counterparty_ref})`
    path and mark `FAILED counterparty_unsupported` if no settlement primitive is wired (explicit,
    not silent). (A follow-up wires the real outbound rail.)
- **Finalize**: on success, `_transition(... PENDING/INITIATED → COMPLETED)` with `ledger_refs`;
  on any primitive error, `_transition(... → FAILED, failure_reason=...)`. Both terminal writes are
  conditional (status lock). `audit_event("txn_request.executed" | "txn_request.failed", ...)`.

**Acceptance Criteria**
- A `PENDING` request with an incomplete challenge → `403 sca_incomplete`; with a complete challenge,
  execute succeeds and `status` becomes `COMPLETED` with populated `ledger_refs`.
- `WALLET_TRANSFER` with insufficient sender balance → `status="FAILED"`,
  `failure_reason="insufficient_funds"`, and **no** partial move (the `apply_wallet_delta` condition
  fails before any credit; the transact batch is all-or-nothing).
- Calling `execute` twice on the same `request_id` moves money exactly once; the second call returns
  the terminal `TxnRequestOut` unchanged (idempotent).
- `REFUND` execution issues exactly one `stripe.Refund.create` for a given `payment_intent_id` and
  produces the same ledger effect as the legacy `POST /billing/refund` path (shared `_do_refund`);
  a duplicate refund request for an already-refunded intent → `FAILED`/`409`, never a second refund.
- A frozen account or fraud `block` → `403` and the request is `FAILED`/untouched (no money moves).
- `PAYOUT` routes through `creator_payouts.request_payout` and respects its min/available/active-slot
  guards (no second payout slot).

**Dependencies**: TXR-001, TXR-002, TXR-003.

---

### TXR-005: Tests + frontend hook
**Type**: Tests + Frontend
**Priority**: P2
**Estimate**: 3 days

**Description**
Lock the engine behind regression tests and expose a typed frontend client + hook.

- **Pytest** `tests/test_txr_txn_requests.py` (offline/hermetic, matching the repo pattern: moto
  in-memory tables bound to the frozen `T.*` handles via `object.__setattr__`, `S` flags flipped via
  `object.__setattr__`, `now_ts` patched, route handlers invoked directly; Stripe/Twilio/SES and the
  `tip_ledger`/`creator_payouts`/`refund` collaborators patched or run against moto — no real AWS/network):
  - State machine: every legal transition succeeds; every illegal one → `409`; conditional-update
    concurrency (two transitions, one wins).
  - Per-type limits: over-ceiling create → `400`; threshold/sensitive-type → PENDING + challenge;
    sub-threshold non-sensitive → INITIATED.
  - SCA: challenge minted with `purpose="txn_request_sca"`; `execute` before `challenge_done` → `403`;
    after marking the required factors passed → executes.
  - Execution per type: WALLET_TRANSFER happy path moves wallet balances exactly once and writes
    paired tip-ledger rows; insufficient funds → FAILED with no partial move; **idempotency** (double
    execute → one move); REFUND calls the shared `_do_refund` exactly once (assert `stripe.Refund.create`
    call count == 1) and never twice for one intent; fraud `block`/frozen → `403`, request untouched.
- **Frontend types** (`frontend/src/api/types.ts`): `TxnRequestType`, `TxnRequest`,
  `TxnRequestCreateIn`. **Endpoints** (`frontend/src/api/endpoints/txnRequests.ts`):
  `createTxnRequest`, `getTxnRequest`, `listTxnRequests`, `executeTxnRequest` via the axios instance
  in `api/client.ts` (CSRF cookie header attached automatically).
- **Hook** `frontend/src/hooks/useTxnRequest.ts` (React Query): `useCreateTxnRequest` (mutation),
  `useTxnRequest(requestId)` (`useQuery`, polls while `status ∈ {INITIATED, PENDING}`),
  `useExecuteTxnRequest`. When the create response is `PENDING` with `sca_challenge_id`, the hook
  surfaces `{ challengeId, requiredFactors }` so the page can drive the **existing** MFA verify UI/
  endpoints (reuse the SCA dialog already wired for `/ui/mfa/*`), then call `executeTxnRequest`.
- **E2E** `frontend/e2e/txn-requests.spec.ts` (flag-gated; seed via session-auth `page.request` with
  `x-csrf-token` per CLAUDE.md): create sub-threshold → INITIATED → execute → COMPLETED; create
  high-value → PENDING → verify OTP (dev mock code) → execute → COMPLETED; double-execute idempotency.
- **Docs**: update `docs/file-reference.md` with the new service/router/table/FE files and add a
  CLAUDE.md "Common gotchas" entry (flag, one-refund-mechanism, status-as-lock, fraud-on-execute).

**Acceptance Criteria**
- `tests/test_txr_txn_requests.py` passes offline (no live stack), covering state machine, limits,
  SCA gating, per-type execution, idempotency (single money move), one-refund-mechanism (single
  `Refund.create`), and fraud/freeze blocking.
- FE hook drives create → (optional SCA via existing MFA routes) → execute and reflects live status;
  E2E spec is green with the flag on.
- `docs/file-reference.md` + CLAUDE.md updated.

**Dependencies**: TXR-001, TXR-002, TXR-003, TXR-004.

---

## Dependency graph (build order)

```
TXR-001 (entity + create/INITIATED)
   └─> TXR-002 (state machine + get-status + limits)
          └─> TXR-003 (step-up SCA → PENDING)
                 └─> TXR-004 (execute → COMPLETED, fraud-gated, idempotent)
                        └─> TXR-005 (tests + FE hook)
```
