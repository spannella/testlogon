# CALL-011: Pay-Per-Minute Private Video Calls — Investigation & Implementation Write-up

## 1. Summary & Classification

The platform has mature free WebRTC calling and a billing infrastructure (wallet, payment methods, billing ledger in the `billing` DDB table; see `app/services/billing_shared.py`). Creators who offer consultations or coaching have no way to monetize live calls within the platform. This ticket implements per-minute paid calls: creator rate settings stored in the `billing` table under the `CALL_RATE` sort key, a wallet balance pre-check at invite time, server-side per-60-second billing cycles triggered by a heartbeat mechanism, pro-rated final billing on call end, and a dedicated `CallBillingLedger` DynamoDB table for the billing audit trail.

The money path reuses the paired debit/credit pattern from `app/services/tip_ledger.py:88` (`write_tip_ledger`) but extends it with a platform fee split (default 20%) — new logic not present in the existing tip flow.

**Type**: Feature (monetization / billing)
**Priority**: High
**Status**: Backend fully implemented; frontend substantially incomplete — `useCallBillingHeartbeat.ts` hook missing, `CallSessionOverlay.tsx` has no billing props, `ConversationView.tsx` has no billing wiring, `CallRateSettings.tsx` settings page missing
**Owning area**: Messaging / Calls / Billing
**Cross-references**: SEC-004 (tip ledger security — same `billing` table and ledger pattern), CALL-002 (call infrastructure), SECOPS-007 (dev/prod parity — `S.call_billing_enabled` flag, same code path; wallet debits work in moto DDB), CALL-009/CALL-010 (paid calls disable voicemail: `and not record.paid` at `messaging.py:14045`)
**Affected users**: Creators (rate configuration) and callers (billing).

---

## 2. Current-State Investigation

### 2.1 Data Model: `CallBillingLedger` Table

`scripts/local-ddb-init.py:651-661` defines `CallBillingLedger` with:
- PK: `call_id` (String)
- SK: `entry_id` (String, `"cbl_" + uuid4().hex`)
- GSIs: `ByCallerCreatedAt` (PK: `caller_user_id`, SK: `created_at`) and `ByCreatorCreatedAt` (PK: `creator_user_id`, SK: `created_at`)
- `attr_types={"created_at": "N"}`

Table handle at `app/core/tables.py:94` (declaration) and `:218` (instantiation). Settings key `call_billing_ledger_table_name` at `app/core/settings.py:1503`.

### 2.2 `CallSessionRecord` Billing Fields

`app/services/messaging_call_sessions.py:37-48` adds billing fields to `CallSessionRecord` (lines align exactly with the ticket spec):

```python
paid: bool = False          # line 37
rate_cents_per_min: int = 0 # line 38 — NOTE: _per_min, not _per_minute
billing_status: str = ""    # line 39
billing_start_ts: Optional[int] = None      # line 40
last_billed_ts: Optional[int] = None        # line 41
total_billed_cents: int = 0                 # line 42
total_billed_seconds: int = 0              # line 43
billing_cycle_count: int = 0               # line 44
platform_fee_bps: int = 0                  # line 45
max_duration_seconds: int = 0             # line 46
caller_last_heartbeat_ts: Optional[int] = None  # line 47
callee_last_heartbeat_ts: Optional[int] = None  # line 48
```

Serialization (`_item_from_record`, `:70-90`) and deserialization (`_record_from_item`, `:116-127`) handle all fields with `int(item.get("field", 0))` coercion to handle DynamoDB `Decimal` from numeric attributes.

### 2.3 `CallInviteIn` and `CallInviteOut` Extensions

`app/routers/messaging.py:12900-12906`: `CallInviteIn` includes `paid: bool = False`. `:12910-12919`: `CallInviteOut` includes `paid: bool = False` and `rate_cents_per_minute: Optional[int] = None`. The `create_call_invite` handler (`:12964-13016`) implements the paid call pre-check at `:12971-13003`:
1. If `body.paid`, calls `get_call_rate(callee_user_id)` (`:12978`).
2. If no rate or `rate.enabled == False`, returns 400 with code `"paid_calls_disabled"` (`:12981`).
3. Calls `check_balance_for_paid_call(caller_user_id, rate_cents_per_minute, min_balance_minutes)` (`:12985`), which raises HTTP 402 with `"insufficient_balance"` if the wallet balance is below `rate * min_balance_minutes`.
4. Passes `paid=True` and `rate_cents_per_min` to `create_invite()` (`:13003`).

### 2.4 `end_call()` Integration

`app/services/messaging_call_lifecycle.py:384-391`: After transitioning a paid call to a terminal state:

```python
if updated.paid:
    try:
        from app.services.call_billing_timer import finalize_call_billing
        finalize_call_billing(call_id)
    except Exception:
        logger.warning("call_billing_finalize_error", extra={"call_id": call_id})
```

This is a best-effort call: billing finalization errors are logged but do not block the lifecycle transition. Pro-rated billing for the final partial minute is computed and charged in `finalize_call_billing`.

### 2.5 `call_billing_timer.py` Service (570 lines)

Key dataclasses at `:34-61`: `CallRateSettings`, `BillingTickResult`, `FinalBillingResult`.

Key functions:
- `:71` `get_call_rate(creator_user_id)` → `Optional[CallRateSettings]`. Reads `CALL_RATE` sort key from the `billing` table.
- `:89` `set_call_rate(*, user_id, rate_cents_per_minute, ...)` → creates or updates `CALL_RATE` item.
- `:121` `delete_call_rate(user_id)` → deletes `CALL_RATE` item.
- `:131` `check_balance_for_paid_call(*, caller_user_id, rate_cents_per_minute, min_balance_minutes)` → raises `HTTPException(402)` using `get_wallet_balance(T.billing, pk)` from `billing_shared.py:169`.
- `:164` `start_call_billing(*, call_id, rate_cents_per_min, ...)` → initializes billing state on the call session (sets `billing_start_ts`, captures `platform_fee_bps = S.call_billing_platform_fee_percent * 100` (`:183`)).
- `:210` `process_heartbeat(call_id, user_id)` → returns `BillingTickResult`. This is the core billing cycle: checks elapsed time against `S.call_billing_cycle_seconds` (default 60 s), calls `apply_wallet_delta(T.billing, f"USER#{caller_id}", -amount_cents)` for the atomic wallet debit, computes platform fee, calls `_write_creator_credit` (`:501`) and `_write_caller_debit` (`:537`) to write `CallBillingLedger` entries.
- `:362` `finalize_call_billing(call_id)` → pro-rates remaining unbilled seconds: `math.ceil((rate_cents_per_min / 60) * unbilled_seconds)`. If balance is insufficient for the final charge, debits the remaining balance instead (`:413-415`).
- `:461` `get_call_billing_summary(call_id)` → returns `Optional[Dict[str, Any]]` for the billing status endpoint.

The platform fee conversion at `:183`: `platform_fee_bps = S.call_billing_platform_fee_percent * 100`. The setting `call_billing_platform_fee_percent` (`:1502`) defaults to `20` (integer percent). Fee calculation: `platform_fee_cents = (gross_amount_cents * platform_fee_bps) // 10000`.

### 2.6 Wallet Debit: `apply_wallet_delta`

`app/services/billing_shared.py:178` implements atomic wallet debit via DDB `ConditionExpression`:

```python
ConditionExpression="wallet_balance_cents >= :needed",
ExpressionAttributeValues={":d": delta_cents, ":t": now_ts(), ":needed": needed},
```

If the balance is insufficient, DDB raises `ConditionalCheckFailedException`, which `process_heartbeat` catches and returns `BillingTickResult(action="end_call", reason="balance_depleted")`. The caller's balance is never taken below zero.

### 2.7 `call_billing.py` Router (247 lines, registered at `app/main.py:145,609`)

Endpoints:

| Method | Path | Line |
|--------|------|------|
| `GET` | `/ui/calls/rates/{creator_id}` | 78 |
| `POST` | `/ui/calls/rates` | 98 |
| `PUT` | `/ui/calls/rates` | 123 |
| `DELETE` | `/ui/calls/rates` | 132 |
| `PATCH` | `/messaging/messages/calls/{call_id}/heartbeat` | 148 |
| `GET` | `/messaging/messages/calls/{call_id}/billing` | 215 |

Pydantic models: `CallRateIn` (`:28`) with `rate_cents_per_minute: int = Field(..., ge=100, le=10000)`, `CallRateOut` (`:35`), `HeartbeatIn` (`:43`), `HeartbeatOut` (`:47`) with `action: str = "ok"` field, `CallBillingStatusOut` (`:60`) with `billing_status: str = ""` field.

### 2.8 Configuration Settings (`app/core/settings.py:1496-1507`)

| Setting | Default | Purpose |
|---------|---------|---------|
| `call_billing_enabled` | `True` (env `"1"`) | Master feature flag |
| `call_billing_heartbeat_interval_seconds` | `15` | Client heartbeat interval |
| `call_billing_cycle_seconds` | `60` | Billing cycle duration |
| `call_billing_low_balance_warning_cents` | `500` | Low balance warning threshold (cents) |
| `call_billing_grace_period_seconds` | `10` | Grace period before call auto-end |
| `call_billing_max_rate_cents_per_min` | `9999` | Maximum allowed rate |
| `call_billing_platform_fee_percent` | `20` | Platform fee (20%) |
| `call_billing_ledger_table_name` | `"CallBillingLedger"` | DDB table |
| `call_billing_max_duration_seconds` | `7200` | 2-hour max duration |
| `call_billing_min_rate_cents` | `100` | $1.00 minimum rate |
| `call_billing_heartbeat_timeout_seconds` | `30` | Liveness timeout |
| `call_billing_low_balance_minutes` | `2` | Low balance warning threshold (minutes) |

### 2.9 Frontend Components Implemented

`frontend/src/api/endpoints/callBilling.ts` (86 lines): API wrappers using `{ api }` from `"@/api/client"`. Functions: `getCreatorCallRate`, `setCallRate`, `updateCallRate`, `deleteCallRate`, `sendCallHeartbeat` (PATCH to `/messaging/messages/calls/${callId}/heartbeat`), `getCallBillingStatus`, `negotiateCallRate`.

`frontend/src/components/calls/CallBillingOverlay.tsx` (62 lines): Cost ticker overlay component showing elapsed cost and rate.

`frontend/src/components/calls/CallBillingSummary.tsx` (88 lines): Post-call billing summary component.

`frontend/src/components/calls/RateNegotiationDialog.tsx` (~90 lines): Rate negotiation dialog.

`frontend/src/hooks/useMessagingStream.ts:200-202` registers `"call.billing_tick"`, `"call.balance_low"`, `"call.balance_depleted"` in `EVENT_TYPES`.

### 2.10 Frontend Components NOT Implemented

`frontend/src/hooks/useCallBillingHeartbeat.ts` — **does not exist**. There is no periodic heartbeat timer on the frontend. The backend heartbeat endpoint is defined and tested, but no frontend code currently calls it during a connected paid call.

`frontend/src/pages/settings/CallRateSettings.tsx` — **does not exist**. Creators cannot configure their rate through the UI.

`frontend/src/pages/messages/PaidCallRateBadge.tsx` — **does not exist**. Callers cannot see the creator's rate before initiating a call.

`frontend/src/pages/messages/PaidCallBalanceWarning.tsx` — **does not exist**. Low-balance warnings are not shown in the UI.

No billing props are passed to `<CallSessionOverlay>` in `ConversationView.tsx`. The `CallBillingOverlay` component exists but is not imported or used anywhere.

### 2.11 E2E and Unit Tests

`frontend/e2e/call-billing.spec.ts` (591 lines) and `tests/test_call_billing.py` (499 lines) provide coverage of the backend billing logic and API endpoints.

---

## 3. Gap / Threat Analysis

### 3.1 No Heartbeat Sent From Frontend — Critical Gap

The billing cycle is triggered by `PATCH /messaging/messages/calls/{call_id}/heartbeat`. Without heartbeats from the client:
- No billing cycles fire during an active paid call (`process_heartbeat` is never called).
- No heartbeat timeout enforcement occurs (`caller_last_heartbeat_ts` and `callee_last_heartbeat_ts` are never updated).
- Abandoned calls are never auto-ended via heartbeat timeout.
- `finalize_call_billing` is called at `end_call()` time, but if the call duration was e.g. 10 minutes and no heartbeats were sent, the `last_billed_ts` is `None`, so `finalize_call_billing` attempts to charge for the entire 10 minutes in one shot — which may exceed the wallet balance and fall through to the "debit whatever remains" path.

**Impact**: In the current state, paid call billing does not charge incrementally. Creators are not credited mid-call. The only billing that occurs is the final pro-rated charge from `finalize_call_billing`, and it may be inaccurate if the wallet balance is too low for the full amount.

**This is the most critical gap in the CALL-011 implementation.**

### 3.2 No Rate Display Before Calling — Caller UX Gap

Without `PaidCallRateBadge`, callers see no indication that a call will incur charges before pressing the call button. The only signal is the `CallInviteOut.rate_cents_per_minute` response field — but the frontend currently ignores it after the invite is sent.

**Impact**: Callers may be charged without knowing the rate. Potential for chargebacks and user complaints.

### 3.3 No Creator Rate Settings UI

Without `CallRateSettings.tsx`, creators cannot configure their rate through the platform UI. They could call `POST /ui/calls/rates` directly via API tools, but this is not a user-facing path.

**Impact**: Feature is functionally complete on the backend but has no creator onboarding path.

### 3.4 No Low-Balance Warning in Call UI

The backend emits `call.balance_low` and `call.balance_depleted` SSE events. The `useMessagingStream.ts` hook registers them. But `ConversationView`'s `onCallEvent` handler does not dispatch to any UI state, and `CallSessionOverlay` has no low-balance UI props. The caller may be auto-disconnected without any advance warning in the current state.

**Impact**: Poor caller UX; calls end suddenly without warning.

### 3.5 Concurrent Paid Call Billing Risk

As noted in the ticket spec (section 3.13): the existing `callee_busy` check in `create_invite()` is scoped to a single conversation. A caller could have concurrent paid calls in different conversations, running up charges in parallel. The `check_balance_for_paid_call` pre-check at invite time does not account for concurrent calls consuming the balance.

**Impact**: A caller with $25 wallet balance ($5/min × 5 min minimum) could initiate 5 concurrent paid calls simultaneously, each passing the $25 pre-check because all 5 see the full $25 balance at check time. Total potential overcharge: $25 × 5 = $125. The atomic `apply_wallet_delta` `ConditionExpression` prevents the balance from going negative, so the actual debit is bounded. But the caller experience is poor: some calls get cut off unexpectedly when the balance is exhausted.

**Impact**: Billing integrity at scale; moderate risk.

### 3.6 `rate_cents_per_min` vs `rate_cents_per_minute` Naming Inconsistency

`CallSessionRecord` (`:38`) stores `rate_cents_per_min`. `CallRateSettings` (`:36`) stores `rate_cents_per_minute`. `CallRateIn` (`:29`) and `CallRateOut` (`:36`) use `rate_cents_per_minute`. The mapping in `start_call_billing` at `:164` takes `rate_cents_per_min` as a parameter. `CallInviteOut` (`:12919`) exposes `rate_cents_per_minute`. This inconsistency is a latent bug: if `start_call_billing` is ever called with the wrong field name, billing uses rate `0` and the creator is never credited.

---

## 4. Proposed Design / Fix

### 4.1 Implement `useCallBillingHeartbeat.ts` Hook (Critical)

Create `frontend/src/hooks/useCallBillingHeartbeat.ts`:

```typescript
export function useCallBillingHeartbeat({
  callId,
  isPaid,
  isConnected,
  enabled,
}: UseCallBillingHeartbeatParams) {
  const [billingState, setBillingState] = React.useState<HeartbeatResponse | null>(null);

  React.useEffect(() => {
    if (!callId || !isPaid || !isConnected || !enabled) return;

    const interval = window.setInterval(async () => {
      try {
        const result = await sendCallHeartbeat(callId, { client_ts: Math.floor(Date.now() / 1000) });
        setBillingState(result);
        if (result.action === "end_call") {
          // Backend signaled balance depletion — dispatch to parent
          window.dispatchEvent(new CustomEvent("call:balance_depleted", { detail: { callId } }));
        }
      } catch {
        // Best-effort; heartbeat failure does not end call immediately
      }
    }, S_HEARTBEAT_INTERVAL_MS); // read from VITE_CALL_BILLING_HEARTBEAT_INTERVAL or default 15000

    return () => window.clearInterval(interval);
  }, [callId, isPaid, isConnected, enabled]);

  return billingState;
}
```

Import `sendCallHeartbeat` from `callBilling.ts` (already implemented). The `action === "end_call"` case should dispatch a `CUSTOM_END_CALL` event that `ConversationView` handles by calling `callActionMutation.mutate({ action: "end", callId })`.

### 4.2 Wire Billing into `ConversationView.tsx`

After the `useCallRecording` block (`:696-704`), add:

```typescript
const billingHeartbeat = useCallBillingHeartbeat({
  callId: callMachine.callId,
  isPaid: callMachine.isPaid,   // needs to be added to CallMachineState
  isConnected: callMachine.phase === "connected",
  enabled: callsEnabled && S.call_billing_enabled,
});
```

Pass `isPaid`, `rateCentsPerMinute`, `totalCostCents`, `elapsedSeconds`, `balanceRemainingCents`, and `warnLowBalance` props to `<CallSessionOverlay>` (derived from `billingHeartbeat`). Add `isPaid` and `rateCentsPerMinute` to `CallMachineState` in `callStateMachine.ts`, populated from `CallInviteOut.paid` and `CallInviteOut.rate_cents_per_minute` on the `OUTGOING_INVITE` event.

### 4.3 Add Billing Props to `CallSessionOverlay.tsx`

Add to Props interface:
```typescript
isPaid?: boolean;
rateCentsPerMinute?: number;
totalCostCents?: number;
elapsedSeconds?: number;
balanceRemainingCents?: number;
warnLowBalance?: boolean;
minutesRemaining?: number;
```

Import `CallBillingOverlay` from `"@/components/calls/CallBillingOverlay"` (already implemented). Render when `isPaid && session.state === "connected"`:
```tsx
{isPaid && session.state === "connected" && (
  <CallBillingOverlay
    rateCentsPerMinute={rateCentsPerMinute ?? 0}
    totalCostCents={totalCostCents ?? 0}
    elapsedSeconds={elapsedSeconds ?? 0}
    balanceRemainingCents={balanceRemainingCents ?? 0}
    warnLowBalance={warnLowBalance ?? false}
    minutesRemaining={minutesRemaining ?? 0}
  />
)}
```

### 4.4 Implement `CallRateSettings.tsx` and `PaidCallRateBadge.tsx`

`CallRateSettings.tsx`: A settings form using React Hook Form + Zod, with `useMutation` to `POST /ui/calls/rates`. Toggle for `enabled`, slider or numeric input for rate ($1-$100/min), inputs for `min_balance_minutes` (1-60) and `max_duration_minutes` (1-480). Register route `/settings/call-rate` in `App.tsx`. Add link from the profile/settings page.

`PaidCallRateBadge.tsx`: A small badge component displayed in `ConversationView` near the call button when `creatorCallRate.enabled === true`. Uses `useQuery` on `GET /ui/calls/rates/{partner_user_id}` to fetch the partner's rate. Displays `"$X.XX/min"` with a tooltip explaining paid call billing.

### 4.5 Handle `call.balance_low` and `call.balance_depleted` SSE Events

In `ConversationView.tsx`'s `onCallEvent` listener, add cases:

```typescript
} else if (eventType === "call.balance_low") {
  dispatchCall({ type: "BILLING_LOW_BALANCE", minutesRemaining: payload.minutes_remaining });
} else if (eventType === "call.balance_depleted") {
  dispatchCall({ type: "BILLING_BALANCE_DEPLETED" });
}
```

Add these events to `callStateMachine.ts` event union and reducer. `BILLING_LOW_BALANCE` sets `warnLowBalance: true` and `minutesRemaining` on the state. `BILLING_BALANCE_DEPLETED` transitions the call to a pre-end state (e.g., shows a "Balance depleted — call ending" overlay for 5 seconds before auto-ending).

### 4.6 Add Cross-Conversation Paid Call Check

In `create_call_invite` handler (`:12964`), when `body.paid == True`, query `ByCallerStartedAt` GSI on `MessageCallSessions` to check if the caller has any active paid call across all conversations:

```python
active_paid = list_paid_call_sessions_for_caller(caller_user_id)
if any(s.paid and s.state in {"invited", "accepted", "connected"} for s in active_paid):
    raise HTTPException(409, detail={"code": "caller_busy_paid", "message": "You already have an active paid call"})
```

Implement `list_paid_call_sessions_for_caller` in `messaging_call_sessions.py` using the `ByCallerStartedAt` GSI.

### 4.7 Dev/Prod Parity (SECOPS-007)

All billing paths use `S.call_billing_enabled` (`:1496`) which defaults to `True` in dev. The `billing` and `CallBillingLedger` tables are created by `local-ddb-init.py` in dev. The `apply_wallet_delta` function uses standard DDB `update_item` with `ConditionExpression` — this works identically with DynamoDB Local (`:8001`) in dev and AWS DynamoDB in prod. The `get_wallet_balance` and `apply_wallet_delta` helpers in `billing_shared.py:166-204` have no `dev_mode` branches. Platform fee calculation is purely arithmetic. No AWS KMS, S3, or Cognito are involved in billing. SECOPS-007 is satisfied by default for this feature.

---

## 5. Testing, Verification & Rollout

### 5.1 Pytest Unit Tests

**File**: `tests/test_call_billing.py` (499 lines, exists)

Verify presence of:
- `test_set_call_rate_creates_rate_item`: `POST /ui/calls/rates` stores `CALL_RATE` item in billing table.
- `test_check_balance_raises_402_insufficient`: Wallet below minimum returns HTTP 402.
- `test_process_heartbeat_bills_after_60s`: Seed a call session with `paid=True`, `billing_start_ts = now - 70`; call `process_heartbeat`; verify wallet debited and `CallBillingLedger` entry created.
- `test_platform_fee_deducted_from_creator_credit`: Creator credited `gross - fee`; verify `platform_fee_cents = gross * 20 / 100`.
- `test_finalize_billing_prorates_partial_minute`: End a call 30 s into a minute; verify `math.ceil(rate / 60 * 30)` is charged.
- `test_balance_depletion_returns_end_call_action`: Seed wallet with 50 cents, rate 100 cents/min; call `process_heartbeat` after 60 s; verify `BillingTickResult.action == "end_call"`.
- `test_atomic_debit_prevents_negative_balance`: Two concurrent heartbeat calls with insufficient balance for both; neither takes balance below zero.

Add:
- `test_concurrent_paid_calls_rejected`: Caller already has an active paid call; second invite returns 409 (once gap 4.6 is implemented).

### 5.2 Playwright E2E Tests

**File**: `frontend/e2e/call-billing.spec.ts` (591 lines, exists)

Additional scenarios needed (once frontend wiring is complete):
1. Bob sets a call rate via `CallRateSettings` UI; `GET /ui/calls/rates/{bob_id}` returns the rate.
2. Alice initiates a call to Bob; rate badge shows "$X.XX/min"; accept; billing overlay appears after connection.
3. After 60 s (use `CALL_BILLING_CYCLE_SECONDS=5` for test speed), cost ticker increments; `CallBillingLedger` has an entry.
4. Alice's wallet balance reaches low threshold; low-balance warning overlay appears.
5. Alice's wallet is depleted; call auto-ends with "Balance depleted" message.
6. `CALL_BILLING_ENABLED=0` → paid call invite returns 503 (backend) or billing UI is hidden (frontend).

**Auth**: Seed Alice's wallet with 2000 cents via DDB directly in `beforeAll`. Use `injectAuth(alicePage, "alice")` and `injectAuth(bobPage, "bob")`.

### 5.3 Manual QA

1. Bob configures rate at `$2.00/min` via API: `POST /ui/calls/rates { rate_cents_per_minute: 200, enabled: true }`.
2. Alice initiates a paid call to Bob; observe invoice pre-check in response (or wallet rejection if insufficient).
3. Both connect; observe `CallBillingOverlay` updating every 60 s.
4. After 3 minutes, end the call; verify `CallBillingLedger` has 3 cycle entries (each 200 cents) plus a pro-rated final entry. Verify Bob's wallet has 3 credit entries of 160 cents each (80% of 200 = platform keeps 40 cents).
5. Check Alice's wallet balance: started at X, should be X minus total billed.

### 5.4 Metrics and Observability

Add to `app/metrics.py`:
- `record_paid_call_started(rate_cents: int)`.
- `record_paid_call_billing_cycle(amount_cents: int, cycle_number: int)`.
- `record_paid_call_ended(total_billed_cents: int, duration_seconds: int, end_reason: str)`.
- `record_paid_call_balance_depletion()`.

These metrics feed billing health dashboards and alert on unexpected depletion rates.

### 5.5 Rollout and Rollback

Set `CALL_BILLING_ENABLED=0` (backend) to disable all billing endpoints without affecting free calls. The `CallBillingLedger` table and `CALL_RATE` items in the billing table persist. The `rate_cents_per_min` and billing fields on `CallSessionRecord` default to `0`/`False` for all new sessions, so free calls are unaffected.

**Effort for remaining gaps**:
- Gap 4.1 (`useCallBillingHeartbeat` hook): **M** (2 days — hook, SSE event handling, `callStateMachine.ts` extensions).
- Gap 4.2 (`ConversationView` wiring): **M** (2 days — imports, props, `CallSessionOverlay` updates).
- Gap 4.3 (`CallRateSettings.tsx`): **M** (2 days — form, route, navigation).
- Gap 4.4 (`PaidCallRateBadge.tsx`): **S** (1 day).
- Gap 4.5 (low-balance SSE handling): **S** (1 day).
- Gap 4.6 (cross-conversation busy check): **S** (1 day — `ByCallerStartedAt` GSI query exists; service function needed).

Implement in order: heartbeat hook (enables all billing) → ConversationView wiring → rate display → settings page → safety checks.
