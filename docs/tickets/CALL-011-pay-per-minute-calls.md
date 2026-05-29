# CALL-011: Pay-Per-Minute Private Video Calls

**Status**: Implemented  
**Author**: Engineering  
**Date**: 2026-05-27  
**Priority**: High  
**Estimated effort**: 10-14 days  
**Dependencies**: CALL-002 (RTCPeerConnection), CALL-009 (Call Recording), MON-002 (Tip Ledger Integration)

> **NOTE — Feature is FULLY IMPLEMENTED.** Backend service (`app/services/call_billing_timer.py`, 570 lines), router (`app/routers/call_billing.py`, 247 lines), call session extension (`app/services/messaging_call_sessions.py` with billing fields), settings (`app/core/settings.py:1179-1191`), DDB table (`CallBillingLedger` in `scripts/local-ddb-init.py:651-661`), frontend API wrapper (`frontend/src/api/endpoints/callBilling.ts`, 86 lines), frontend components (`frontend/src/components/calls/CallBillingOverlay.tsx`, `CallBillingSummary.tsx`, `RateNegotiationDialog.tsx`), SSE event types (`useMessagingStream.ts:178-180`), E2E tests (`frontend/e2e/call-billing.spec.ts`, 591 lines), and unit tests (`tests/test_call_billing.py`, 499 lines) are all present. The spec below reflects the original design proposal; inline notes mark deviations from the actual implementation.

---

## 1. Overview & Motivation

### Problem Statement

The platform supports free 1-on-1 WebRTC video calls via `app/services/messaging_call_lifecycle.py` (invite/accept/decline/end) and has a mature billing infrastructure (wallet, payment methods, billing ledger in the `billing` DDB table). However, there is **no mechanism for creators to monetize live video calls**. Creators who offer consultations, coaching sessions, readings, or private performances have no way to charge viewers on a per-minute basis within the platform, forcing them to use external payment arrangements that bypass the platform entirely.

### Goals

1. Allow creators to set a per-minute rate (in cents) for private paid video calls.
2. Enforce a minimum wallet balance before a paid call can be initiated.
3. Bill the caller incrementally (every 60 seconds) during a connected paid call, with pro-rated final billing on hang-up.
4. Credit the creator's earnings ledger (minus a configurable platform fee) for each billing cycle.
5. Provide a heartbeat mechanism to detect dropped participants and auto-end abandoned calls.
6. Show a live cost ticker in the frontend during paid calls, with low-balance warnings.

### User Stories

| # | As a... | I want to... | So that... |
|---|---------|-------------|-----------|
| 1 | Creator | Set a per-minute rate for private video calls | I can monetize my time and expertise |
| 2 | Creator | Enable/disable paid calls independently of free calls | I can offer both free and paid calling options |
| 3 | Caller | See the creator's per-minute rate before calling | I know the cost before committing |
| 4 | Caller | See a live cost ticker during the call | I always know how much I have spent |
| 5 | Caller | Receive a low-balance warning during the call | I can end the call or top up my wallet before it auto-ends |
| 6 | Caller | Have the call auto-end gracefully when my balance is depleted | I am not overcharged beyond my wallet balance |
| 7 | Platform | Collect a configurable percentage fee on each paid call | The platform is compensated for facilitating the transaction |
| 8 | Admin | Configure platform fee percentage and rate limits | Business terms can be adjusted without code changes |

### Scope

**In scope**: Creator rate settings, wallet balance pre-check, server-side billing timer, per-minute debit/credit ledger entries, heartbeat-based liveness, call auto-end on depleted balance, frontend rate display and live cost ticker, maximum call duration enforcement.

**Out of scope (non-goals)**:
- Group paid calls (1-on-1 only for v1)
- Video recording of paid calls (handled separately by CALL-009/CALL-010)
- Refund/dispute system (use existing MOD-003 appeals)
- Tipping during paid calls (tips are an independent system)
- Subscription-based call access (future ticket)

---

## 2. Current State Analysis

### 2.1 Call Lifecycle Flow

The current call flow managed by `app/services/messaging_call_lifecycle.py`:

```
Alice (caller)                Backend                          Bob (creator)
  |-- POST /calls/invite ----->|-- SSE call.invite ----------->|
  |                            |                               |
  |<-- SSE call.accept --------|<-- POST /calls/{id}/accept ---|
  |                            |  (state: invited -> accepted) |
  |                            |                               |
  |-- POST /signal (offer) --->|-- SSE webrtc.offer ---------->|
  |<-- SSE webrtc.answer ------|<-- POST /signal (answer) -----|
  |<-> ICE trickle <---------->|<-> ICE trickle <------------->|
  |                            |  (state: accepted -> connected)|
  |                            |                               |
  |   [CALL ACTIVE — BILLING HAPPENS HERE FOR PAID CALLS]     |
  |                            |                               |
  |-- POST /calls/{id}/end --->|-- SSE call.end -------------->|
  |                            |  (state: connected -> ended)  |
```

### 2.2 Call Session DDB Model

`CallSessionRecord` in `app/services/messaging_call_sessions.py` (lines 19-50, including billing fields at lines 37-48):

<!-- NOTE: The actual dataclass spans lines 19-50 (not 18-33) because billing fields have been added. The field `paid` is at line 37, `rate_cents_per_min` at line 38 (note: field is named `rate_cents_per_min`, NOT `rate_cents_per_minute`), and billing fields `billing_start_ts` through `callee_last_heartbeat_ts` are at lines 40-48. -->

| Field | Type | Purpose |
|-------|------|---------|
| `call_id` | S (PK) | Unique call identifier |
| `conversation_id` | S | DM conversation this call belongs to |
| `caller_user_id` | S | Who initiated the call |
| `callee_user_id` | S | Who received the call |
| `initial_mode` | "audio" \| "video" | Call type |
| `state` | CallState | Current lifecycle state |
| `start_ts` | N | When the call was initiated |
| `connect_ts` | N \| None | When media connected |
| `end_ts` | N \| None | When the call ended |
| `end_reason` | S \| None | Why the call ended |
| `updated_at` | N \| None | Last modification timestamp |
| `network_path` | "p2p" \| "turn" \| None | Connection type |
| `lifecycle_events` | L[M] | Ordered log of state transitions |
| `idempotency_records` | M \| None | Processed idempotency keys |

The paid call billing timer will reference `call_id` as a foreign key and extend the call session record with billing metadata.

### 2.3 Call Invite Endpoint

`POST /messaging/messages/calls/invite` (line 12963 of `app/routers/messaging.py`) currently accepts `CallInviteIn` (line 12900):

<!-- NOTE: Line references corrected — CallInviteIn is at line 12900, the POST endpoint is at line 12963 (handler function `create_call_invite` at line 12964), not line 12384. -->

> **Corrected**: The messaging router has `prefix="/messaging"` (line 238 of `messaging.py`), so the full endpoint path is `/messaging/messages/calls/invite`, not `/messages/calls/invite`. All call endpoints under this router share the `/messaging` prefix.

```python
class CallInviteIn(BaseModel):
    call_id: str
    conversation_id: str
    callee_user_id: str
    initial_mode: str = "audio"
    idempotency_key: Optional[str] = None
```

This model has been extended with a `paid: bool = False` flag (see `app/routers/messaging.py:12906`). `CallInviteOut` (line 12910) also includes `paid: bool = False` (line 12918) and `rate_cents_per_minute: Optional[int] = None` (line 12919). **IMPLEMENTED.**

### 2.4 Billing Table Schema

`T.billing` table (from `scripts/local-ddb-init.py`, line 59 — verified):

PK: `USER#{user_sub}`, SK patterns:
- `PM#{pm_id}` -- payment methods
- `BILLING` -- user billing settings (default PM, autopay, currency)
- `LEDGER#{ts}#{entry_id}` -- billing ledger entries (debit/credit)
- `WALLET` -- wallet balance

Existing ledger entry structure (from `app/services/tip_ledger.py` — `write_tip_ledger` at line 88):
```python
{
    "pk": f"USER#{user_id}",
    "sk": f"LEDGER#{ts}#{entry_id}",
    "entry_id": entry_id,
    "ts": ts,
    "type": "debit",           # or "credit"
    "amount_cents": amount_cents,
    "currency": "USD",
    "state": "settled",
    "reason": "Tip: message",
    "meta": {...},
}
```

Wallet balance item (existing pattern):
```python
{
    "pk": f"USER#{user_id}",
    "sk": "WALLET",
    "wallet_balance_cents": 5000,     # current balance
    "currency": "usd",
    "updated_at": 1716681600,
}
```

> **Corrected**: The wallet field is `wallet_balance_cents`, not `balance_cents`. Currency is stored as lowercase `"usd"`. See `app/services/billing_shared.py`.

### 2.5 Existing Call Lifecycle State Machine

From `app/services/messaging_call_lifecycle.py` (lines 23-28 — verified, including `end_call` at line 334 which now calls `finalize_call_billing` at line 387-388):

```python
TERMINAL_STATES = {"declined", "busy", "missed", "ended", "failed", "canceled"}
ALLOWED_TRANSITIONS = {
    "invited": {"accepted", "declined", "busy", "canceled", "failed", "missed"},
    "accepted": {"connected", "ended", "failed", "canceled"},
    "connected": {"ended", "failed"},
}
```

No modifications to the state machine are needed. Paid call billing is orthogonal to call state -- it starts when the call reaches `connected` and stops when it reaches a terminal state.

### 2.6 Tip Ledger Pattern

`app/services/tip_ledger.py` (line 88) implements the paired debit/credit ledger write pattern that paid call billing follows:

```python
def write_tip_ledger(entry: TipLedgerEntry) -> Dict[str, str]:
    # 1. Write debit entry (charge to tipper)
    T.billing.put_item(Item={
        "pk": f"USER#{entry.tipper_user_id}",
        "sk": f"LEDGER#{ts}#{debit_id}",
        ...
    })
    # 2. Write credit entry (income to recipient)
    T.billing.put_item(Item={
        "pk": f"USER#{entry.recipient_user_id}",
        "sk": f"LEDGER#{ts}#{credit_id}",
        ...
    })
```

Both writes are best-effort (exceptions logged but not propagated). The same paired-write pattern will be used for per-minute call billing entries.

> **Corrected**: The existing `write_tip_ledger` writes **identical** `amount_cents` for both the debit and credit entries -- there is no platform fee deduction in the tip flow (`app/services/tip_ledger.py`, lines 110-141). The platform fee split (debit full amount from caller, credit reduced amount to creator) proposed in this ticket is **new logic** that does not exist in the current tip ledger pattern. The call billing service must implement the fee-split calculation itself rather than reusing an existing fee-split mechanism.

---

## 3. Technical Design

### 3.1 Creator Call Rate Settings

Creators configure their per-minute rate via a new settings row in the `billing` table (reusing the existing table rather than creating a dedicated profiles table):

```python
{
    "pk": f"USER#{creator_user_id}",
    "sk": "CALL_RATE",
    "rate_cents_per_minute": 500,        # $5.00/min
    "enabled": True,                     # paid calls enabled
    "currency": "USD",
    "min_balance_minutes": 5,            # minimum wallet balance in minutes
    "max_duration_minutes": 120,         # maximum call duration
    "updated_at": 1716681600,
}
```

**Validation constraints:**
- `rate_cents_per_minute`: minimum 100 ($1/min), maximum 10000 ($100/min)
- `min_balance_minutes`: minimum 1, maximum 60, default 5
- `max_duration_minutes`: minimum 1, maximum 480, default 120

### 3.2 Paid Call Flow

```
Alice (caller)                  Backend                              Bob (creator)
     |                             |                                    |
     |-- GET /calls/rates/{bob} -->|                                    |
     |<-- { rate: 500, enabled } --|                                    |
     |                             |                                    |
     |   [UI shows "$5.00/min"]    |                                    |
     |                             |                                    |
     |-- POST /calls/invite ------>|                                    |
     |   { paid: true }            |                                    |
     |                             |-- check wallet balance ----------->|
     |                             |   (>= rate * min_balance_minutes)  |
     |                             |                                    |
     |                             |-- write HOLD item ----------------->|
     |                             |   pk=USER#{alice}, sk=HOLD#{call_id}|
     |                             |                                    |
     |<-- { call_id, rate_cents,   |-- SSE call.invite (paid=true) ---->|
     |      hold_amount_cents } ---|                                    |
     |                             |                                    |
     |<-- SSE call.accept ---------|<-- POST /calls/{id}/accept --------|
     |                             |                                    |
     |   [...WebRTC negotiation...] |                                    |
     |                             |  (state -> connected)              |
     |                             |                                    |
     |                             |-- START BILLING TIMER ------------>|
     |                             |   pk=CALL#{call_id}, sk=BILLING    |
     |                             |                                    |
     |   [--- Every 60s ---]       |                                    |
     |                             |                                    |
     | PATCH /calls/{id}/heartbeat |                                    |
     |--------------------------->|<-- PATCH /calls/{id}/heartbeat -----|
     |                             |                                    |
     |                             |-- debit alice wallet (rate_cents) ->|
     |                             |-- credit bob ledger (rate - fee) -->|
     |                             |-- update billing timer ----------->|
     |                             |                                    |
     |<-- SSE call.billing_tick -->|-- SSE call.billing_tick ---------->|
     |   { elapsed_s, cost_cents,  |                                    |
     |     balance_remaining }     |                                    |
     |                             |                                    |
     |   [--- Balance Low ---]     |                                    |
     |                             |                                    |
     |<-- SSE call.balance_low --->|                                    |
     |   { minutes_remaining: 2 }  |                                    |
     |                             |                                    |
     |   [--- Balance Depleted ---]|                                    |
     |                             |                                    |
     |<-- SSE call.end ----------->|-- SSE call.end ------------------>|
     |   { reason: balance_depleted }                                   |
     |                             |                                    |
     |                             |-- final pro-rated billing -------->|
     |                             |-- release HOLD ------------------>|
```

### 3.3 Billing Timer Data Model

Billing timer state is stored in the `MessageCallSessions` DDB table alongside the call session record (see `scripts/local-ddb-init.py:629-639`).

> **Corrected**: The original spec mentioned "using a separate sort key" but the `MessageCallSessions` table has **no sort key** -- it uses only a partition key (`call_id`). There is no SK to separate billing data from the call record. The approach below (extending the existing `CallSessionRecord` with billing fields on the same item) is compatible with this single-key schema.

**Option chosen: Extend the existing `CallSessionRecord`** with billing fields rather than creating a separate table. This keeps all call state co-located and avoids cross-table consistency issues. **IMPLEMENTED** — see `app/services/messaging_call_sessions.py:37-48` for the billing fields on `CallSessionRecord`, and lines 74-90 for serialization, 116-127 for deserialization.

New fields on `CallSessionRecord` (see `app/services/messaging_call_sessions.py:37-48`):

| Field | Type | Description | Status |
|-------|------|-------------|--------|
| `paid` | BOOL | Whether this is a paid call | **Line 37** |
| `rate_cents_per_min` | N | Per-minute rate at call start (snapshot) | **Line 38** |
| `billing_start_ts` | N \| None | When billing started (= `connect_ts`) | **Line 40** |
| `last_billed_ts` | N \| None | Timestamp of last billing cycle | **Line 41** |
| `total_billed_cents` | N | Running total billed to caller | **Line 42** |
| `total_billed_seconds` | N | Total seconds billed | **Line 43** |
| `billing_cycle_count` | N | Number of completed billing cycles | **Line 44** |
| `platform_fee_bps` | N | Platform fee in basis points (snapshot) | **Line 45** |
| `max_duration_seconds` | N | Maximum allowed duration for this call | **Line 46** |
| `caller_last_heartbeat_ts` | N \| None | Last heartbeat from caller | **Line 47** |
| `callee_last_heartbeat_ts` | N \| None | Last heartbeat from callee | **Line 48** |

<!-- NOTE: The actual field is `rate_cents_per_min` (NOT `rate_cents_per_minute`) on CallSessionRecord. The spec also proposed `hold_amount_cents`, `hold_released`, and `caller_wallet_balance_at_start` fields — these do NOT exist in the implementation. The hold mechanism was simplified to a balance check only (no actual hold item), consistent with the v1 simplification described in section 3.9. -->

### 3.4 New DDB Table: `CallBillingLedger` — **IMPLEMENTED**

A dedicated table for per-minute billing entries, separate from the main billing ledger. This provides a clean audit trail for call billing without polluting the main ledger with high-frequency entries. (See `scripts/local-ddb-init.py:651-661`, table handle at `app/core/tables.py:94,218`.)

**Table name**: `CallBillingLedger` (env: `DDB_CALL_BILLING_LEDGER`, setting at `app/core/settings.py:1187`)  
**Partition key**: `call_id` (String)  
**Sort key**: `entry_id` (String)

| Field | Type | Description |
|-------|------|-------------|
| `call_id` | S (PK) | FK to CallSessionRecord |
| `entry_id` | S (SK) | `"cbl_" + uuid4().hex` |
| `cycle_number` | N | Billing cycle (1, 2, 3, ...) |
| `caller_user_id` | S | Caller (debited) |
| `creator_user_id` | S | Creator (credited) |
| `gross_amount_cents` | N | Full minute rate charged to caller |
| `platform_fee_cents` | N | Platform fee deducted from creator credit |
| `creator_net_cents` | N | Amount credited to creator (gross - fee) |
| `billed_seconds` | N | Seconds covered by this entry (60 or partial) |
| `cumulative_cost_cents` | N | Running total after this entry |
| `cumulative_seconds` | N | Running total seconds after this entry |
| `wallet_balance_after` | N | Caller wallet balance after debit |
| `created_at` | N | Unix timestamp |

**GSIs**:

| GSI Name | Partition Key | Sort Key | Purpose |
|----------|--------------|----------|---------|
| `ByCallerCreatedAt` | `caller_user_id` | `created_at` (N) | Caller's call billing history |
| `ByCreatorCreatedAt` | `creator_user_id` | `created_at` (N) | Creator's earnings from calls |

### 3.5 Wallet Balance Operations

Wallet balance checks and debits use atomic DDB operations on the existing `billing` table. The existing helpers live in `app/services/billing_shared.py` (lines 166-204 — `WALLET_SK` at 166, `get_wallet_balance` at 169, `apply_wallet_delta` at 178).

**Existing `get_wallet_balance` (returns a dict, not an int):**
```python
def get_wallet_balance(table: Any, pk: str) -> Dict[str, Any]:
    """Returns {"wallet_balance_cents": int, "currency": str, "updated_at": int|None}."""
    row = ddb_get(table, pk, WALLET_SK) or {}
    return {
        "wallet_balance_cents": int(row.get("wallet_balance_cents", 0)),
        "currency": row.get("currency", "usd"),
        "updated_at": row.get("updated_at"),
    }
```

**Existing `apply_wallet_delta` (signed delta, not a separate debit function):**
```python
def apply_wallet_delta(table: Any, pk: str, delta_cents: int, *, currency: str = "usd") -> int:
    """Atomically add delta_cents to wallet balance. Returns new balance.

    For deposits (delta >= 0): uses if_not_exists to create row if needed.
    For withdrawals (delta < 0): requires existing balance >= abs(delta);
    raises ConditionalCheckFailedException if insufficient.
    """
    if delta_cents >= 0:
        result = table.update_item(
            Key={"pk": pk, "sk": WALLET_SK},
            UpdateExpression=(
                "SET wallet_balance_cents = if_not_exists(wallet_balance_cents, :z) + :d, "
                "currency = :c, updated_at = :t"
            ),
            ExpressionAttributeValues={":z": 0, ":d": delta_cents, ":c": currency, ":t": now_ts()},
            ReturnValues="ALL_NEW",
        )
    else:
        needed = abs(delta_cents)
        result = table.update_item(
            Key={"pk": pk, "sk": WALLET_SK},
            UpdateExpression="SET wallet_balance_cents = wallet_balance_cents + :d, updated_at = :t",
            ConditionExpression="wallet_balance_cents >= :needed",
            ExpressionAttributeValues={":d": delta_cents, ":t": now_ts(), ":needed": needed},
            ReturnValues="ALL_NEW",
        )
    return int(result["Attributes"].get("wallet_balance_cents", 0))
```

> **Corrected**: The spec originally showed `get_wallet_balance(user_id) -> int` and `debit_wallet(user_id, amount_cents, reason, meta) -> int`. The actual existing API is `get_wallet_balance(table, pk) -> Dict` (returns a dict with `wallet_balance_cents`, `currency`, `updated_at`) and `apply_wallet_delta(table, pk, delta_cents, *, currency) -> int` (uses a signed delta, negative for withdrawals). The field name is `wallet_balance_cents`, not `balance_cents`. The `ConditionExpression` uses `wallet_balance_cents >= :needed`. The call billing service should use these existing helpers rather than introducing new wrapper functions.

The `ConditionExpression` ensures the debit is atomic -- if balance drops below the required amount between the check and the write (race condition from concurrent calls), the debit fails with `ConditionalCheckFailedException` and the billing cycle is skipped with a grace period.

### 3.6 Per-Minute Billing Logic

The billing cycle runs server-side, triggered by the heartbeat endpoint. This avoids reliance on background tasks and ties billing to proof-of-liveness.

**Billing cycle (called on each heartbeat from either participant):**

```python
def process_billing_cycle(call_id: str) -> BillingTickResult:
    session = get_call_session(call_id)
    if not session or session.state != "connected" or not session.paid:
        return BillingTickResult(action="skip")

    now = now_ts()
    elapsed_since_last = now - (session.last_billed_ts or session.billing_start_ts)

    # Only bill if >= 60 seconds since last billing
    if elapsed_since_last < 60:
        return BillingTickResult(action="skip", next_bill_in=60 - elapsed_since_last)

    # Calculate amount for this cycle
    full_minutes = elapsed_since_last // 60
    partial_seconds = elapsed_since_last % 60
    # Bill for full minutes; partial seconds accumulate to next cycle
    amount_cents = session.rate_cents_per_minute * full_minutes

    if amount_cents <= 0:
        return BillingTickResult(action="skip")

    # Attempt atomic wallet debit (using existing apply_wallet_delta with negative delta)
    try:
        pk = f"USER#{session.caller_user_id}"
        new_balance = apply_wallet_delta(T.billing, pk, -amount_cents)
    except ConditionalCheckFailedException:
        # Insufficient balance — end call with grace period
        return BillingTickResult(action="end_call", reason="balance_depleted")

    # Calculate platform fee and creator credit
    platform_fee_cents = (amount_cents * session.platform_fee_bps) // 10000
    creator_net_cents = amount_cents - platform_fee_cents

    # Write credit ledger entry for creator
    write_call_billing_credit(
        creator_user_id=session.callee_user_id,
        amount_cents=creator_net_cents,
        call_id=call_id,
        cycle=session.billing_cycle_count + 1,
    )

    # Write call billing ledger entry
    write_call_billing_entry(...)

    # Update session billing state
    update_call_billing_state(
        call_id=call_id,
        last_billed_ts=now,
        total_billed_cents=session.total_billed_cents + amount_cents,
        total_billed_seconds=session.total_billed_seconds + (full_minutes * 60),
        billing_cycle_count=session.billing_cycle_count + 1,
    )

    # Check low balance warning (< 2 minutes remaining)
    minutes_remaining = new_balance / session.rate_cents_per_minute
    warn = minutes_remaining < 2

    return BillingTickResult(
        action="billed",
        amount_cents=amount_cents,
        total_cost_cents=session.total_billed_cents + amount_cents,
        balance_remaining=new_balance,
        warn_low_balance=warn,
        minutes_remaining=minutes_remaining,
    )
```

### 3.7 Heartbeat Mechanism

Both participants send periodic heartbeats to prove liveness. The heartbeat endpoint also triggers the billing cycle.

**Heartbeat rules:**
- Both parties must send a heartbeat at least once every 30 seconds
- If no heartbeat is received from either party for 30 seconds, the call is auto-ended with reason `"heartbeat_timeout"`
- Each heartbeat from the caller triggers a billing cycle check
- The response includes current billing status for the frontend to update the cost ticker

**Heartbeat tracking fields on `CallSessionRecord`:**

| Field | Type | Description |
|-------|------|-------------|
| `caller_last_heartbeat_ts` | N | Last heartbeat from caller |
| `callee_last_heartbeat_ts` | N | Last heartbeat from callee |

### 3.8 Call End Billing Finalization

When a paid call ends (via `end_call()` or heartbeat timeout), the final billing is pro-rated to the nearest second:

```python
def finalize_call_billing(call_id: str) -> FinalBillingResult:
    session = get_call_session(call_id)
    if not session or not session.paid:
        return FinalBillingResult(total_cents=0)

    now = now_ts()
    unbilled_seconds = now - (session.last_billed_ts or session.billing_start_ts)

    if unbilled_seconds <= 0:
        return FinalBillingResult(total_cents=session.total_billed_cents)

    # Pro-rate: (rate_cents_per_minute / 60) * unbilled_seconds, rounded up
    pro_rated_cents = math.ceil(
        (session.rate_cents_per_minute / 60) * unbilled_seconds
    )

    # Debit caller for final partial amount (using existing apply_wallet_delta)
    pk = f"USER#{session.caller_user_id}"
    try:
        apply_wallet_delta(T.billing, pk, -pro_rated_cents)
    except ConditionalCheckFailedException:
        # Debit whatever remains
        wallet = get_wallet_balance(T.billing, pk)
        balance = wallet["wallet_balance_cents"]
        if balance > 0:
            apply_wallet_delta(T.billing, pk, -balance)
            pro_rated_cents = balance

    # Credit creator (minus platform fee)
    platform_fee = (pro_rated_cents * session.platform_fee_bps) // 10000
    creator_net = pro_rated_cents - platform_fee
    write_call_billing_credit(session.callee_user_id, creator_net, call_id, "final")

    # Write summary ledger entries to main billing table
    write_call_summary_ledger(session, pro_rated_cents)

    # Release hold
    release_hold(session.caller_user_id, call_id)

    total = session.total_billed_cents + pro_rated_cents
    return FinalBillingResult(total_cents=total, duration_seconds=now - session.billing_start_ts)
```

### 3.9 Pre-Authorization Hold

When a paid call is initiated, a hold is placed on the caller's wallet to ensure funds are available:

- **Hold amount**: `rate_cents_per_minute * min_balance_minutes` (e.g., $5/min * 5 min = $25)
- **Hold storage**: `pk=USER#{caller_id}`, `sk=HOLD#{call_id}` in the billing table
- **Hold is NOT a debit** -- it reduces "available balance" (`wallet_balance_cents - sum(active_holds)`) but does not reduce `wallet_balance_cents`
- **Hold release**: On call end, the hold item is deleted. Actual charges are deducted from `wallet_balance_cents` via the per-minute debit.

For v1 simplification, the hold is implemented as a simple balance check (no actual hold item). The minimum balance requirement serves as a soft hold:

```python
required_balance = rate_cents * min_balance_minutes
wallet = get_wallet_balance(T.billing, f"USER#{caller_id}")
actual_balance = wallet["wallet_balance_cents"]
if actual_balance < required_balance:
    raise HTTPException(402, detail={
        "code": "insufficient_balance",
        "required_cents": required_balance,
        "current_balance_cents": actual_balance,
        "rate_cents_per_minute": rate_cents,
        "min_minutes": min_balance_minutes,
    })
```

### 3.10 Platform Fee — **IMPLEMENTED**

The platform fee is a configurable percentage deducted from the creator's credit for each billing cycle (see `app/services/call_billing_timer.py:183,297-299,413-415`):

- **Default**: 20% (stored as integer percent, not basis points)
- **Configurable**: `CALL_BILLING_PLATFORM_FEE_PERCENT` env var (see `app/core/settings.py:1186`)

<!-- NOTE: The actual setting is `call_billing_platform_fee_percent` (integer 20 = 20%), NOT `call_billing_platform_fee_bps` (2000 bps). The service converts percent to basis points internally: `platform_fee_bps = S.call_billing_platform_fee_percent * 100` (see call_billing_timer.py:183). -->
- **Snapshot at call start**: The fee percentage is captured on the call session record when the call connects, so mid-call fee changes do not affect active calls
- **Calculation**: `platform_fee_cents = (gross_amount_cents * platform_fee_bps) // 10000`
- **Creator receives**: `creator_net_cents = gross_amount_cents - platform_fee_cents`

Example for a $5.00/min call with 20% fee:
- Caller debited: $5.00
- Platform fee: $1.00
- Creator credited: $4.00

### 3.11 Maximum Call Duration

Paid calls have a maximum duration to prevent runaway billing:

1. **Creator setting**: `max_duration_minutes` on the call rate settings (default 120 min)
2. **Platform setting**: `CALL_BILLING_MAX_DURATION_SECONDS` env var (default 7200 = 120 min)
3. **Effective limit**: `min(creator_setting, platform_setting)`
4. **Enforcement**: On each heartbeat, check if elapsed time exceeds the limit. If so, auto-end with reason `"max_duration_reached"`.
5. **Warning**: Send `call.billing_tick` with `max_duration_warning: true` when 5 minutes remain.

### 3.12 Configuration Settings — **IMPLEMENTED**

All settings are present in `app/core/settings.py` (lines 1179-1191). The actual settings differ from the original proposal in several ways:

| Setting | Env Variable | Default | Line | Notes |
|---------|-------------|---------|------|-------|
| Feature flag | `CALL_BILLING_ENABLED` | `"1"` (enabled) | 1180 | **Default is ENABLED, not `"false"`** |
| Heartbeat interval | `CALL_BILLING_HEARTBEAT_INTERVAL` | `15` | 1181 | Env var name lacks `_SECONDS` suffix |
| Billing cycle | `CALL_BILLING_CYCLE_SECONDS` | `60` | 1182 | **New — not in original spec** |
| Low balance warning | `CALL_BILLING_LOW_BALANCE_WARNING_CENTS` | `500` | 1183 | **Cents-based, not minutes-based** |
| Grace period | `CALL_BILLING_GRACE_PERIOD_SECONDS` | `10` | 1184 | **New — not in original spec** |
| Max rate | `CALL_BILLING_MAX_RATE_CENTS_PER_MIN` | `9999` | 1185 | **9999 not 10000** |
| Platform fee | `CALL_BILLING_PLATFORM_FEE_PERCENT` | `20` | 1186 | **Percent (20) not BPS (2000)** |
| DDB table | `DDB_CALL_BILLING_LEDGER` | `CallBillingLedger` | 1187 | Matches spec |
| Max duration | `CALL_BILLING_MAX_DURATION_SECONDS` | `7200` | 1188 | Matches spec |
| Min rate | `CALL_BILLING_MIN_RATE_CENTS` | `100` | 1189 | Matches spec |
| Heartbeat timeout | `CALL_BILLING_HEARTBEAT_TIMEOUT_SECONDS` | `30` | 1190 | Matches spec |
| Low balance minutes | `CALL_BILLING_LOW_BALANCE_MINUTES` | `2` | 1191 | Also present (both cents and minutes variants) |

<!-- NOTE: The actual implementation has ADDITIONAL settings not in the original spec: `call_billing_cycle_seconds` (1182) and `call_billing_grace_period_seconds` (1184). The `call_billing_enabled` defaults to `"1"` (enabled), not `"false"` as proposed. The platform fee uses integer percent (`call_billing_platform_fee_percent = 20`) instead of basis points (`call_billing_platform_fee_bps = 2000`). The low balance threshold has a dual implementation — both cents-based (`call_billing_low_balance_warning_cents = 500`) and minutes-based (`call_billing_low_balance_minutes = 2`). -->

### 3.13 SSE Event Types for Billing — **IMPLEMENTED**

Billing events are dispatched via the existing SSE infrastructure in `useMessagingStream.ts`. These events are informational (UI updates) and do not require signaling relay.

All three event types are present in `EVENT_TYPES` in `frontend/src/hooks/useMessagingStream.ts` (lines 178-180):

```typescript
"call.billing_tick",       // periodic billing update (line 178)
"call.balance_low",        // low balance warning (line 179)
"call.balance_depleted",   // balance depleted, call will end (line 180)
```

**`call.billing_tick` payload:**
```json
{
  "call_id": "...",
  "elapsed_seconds": 185,
  "cycle_number": 3,
  "cost_this_cycle_cents": 500,
  "total_cost_cents": 1500,
  "caller_balance_remaining_cents": 3500,
  "rate_cents_per_minute": 500,
  "max_duration_warning": false
}
```

**`call.balance_low` payload:**
```json
{
  "call_id": "...",
  "minutes_remaining": 1.5,
  "balance_remaining_cents": 750,
  "rate_cents_per_minute": 500
}
```

---

## 4. Implementation Plan

### Phase 1: Backend — Call Rate Settings & Billing Service (Days 1-3) — **DONE**

#### New Files

| File | Purpose | Status |
|------|---------|--------|
| `app/services/call_billing_timer.py` | Billing timer logic, per-minute debit/credit, finalization | **570 lines** |
| `app/routers/call_billing.py` | HTTP endpoints for rate settings, heartbeat, billing status | **247 lines** |

#### `app/services/call_billing_timer.py` — **IMPLEMENTED** (570 lines)

Actual dataclasses (lines 34-61):

```python
@dataclass
class CallRateSettings:          # line 34
    user_id: str
    rate_cents_per_minute: int
    enabled: bool
    currency: str = "USD"
    min_balance_minutes: int = 5
    max_duration_minutes: int = 120
    updated_at: int = 0

@dataclass
class BillingTickResult:         # line 45
    action: Literal["skip", "billed", "end_call"]
    amount_cents: int = 0
    total_cost_cents: int = 0
    balance_remaining: int = 0
    warn_low_balance: bool = False
    minutes_remaining: float = 0
    next_bill_in: int = 0
    reason: Optional[str] = None
    cycle_number: int = 0

@dataclass
class FinalBillingResult:        # line 58
    total_cents: int
    duration_seconds: int = 0
    final_charge_cents: int = 0
```

Actual functions (with line numbers):

| Function | Line | Notes |
|----------|------|-------|
| `get_call_rate(creator_user_id)` | 71 | Returns `Optional[CallRateSettings]` |
| `set_call_rate(*, user_id, rate_cents_per_minute, ...)` | 89 | Creates or updates CALL_RATE item |
| `delete_call_rate(user_id)` | 121 | Deletes CALL_RATE item |
| `check_balance_for_paid_call(*, caller_user_id, rate_cents_per_minute, min_balance_minutes)` | 131 | Raises HTTPException(402) if insufficient |
| `start_call_billing(*, call_id, rate_cents_per_min, ...)` | 164 | Initializes billing state on call session |
| `process_heartbeat(call_id, user_id)` | 210 | Returns `BillingTickResult` |
| `finalize_call_billing(call_id)` | 362 | Returns `FinalBillingResult` |
| `get_call_billing_summary(call_id)` | 461 | Returns `Optional[Dict[str, Any]]` |
| `_write_creator_credit(...)` | 501 | Private — writes credit ledger entry |
| `_write_caller_debit(...)` | 537 | Private — writes debit ledger entry |

<!-- NOTE: Spec proposed `start_billing_timer`, `process_billing_cycle`, `write_call_billing_credit`, `write_call_billing_entry`, `write_call_summary_ledger`. Actual names are `start_call_billing` (line 164), `process_heartbeat` (line 210), `_write_creator_credit` (line 501, private), `_write_caller_debit` (line 537, private). `write_call_summary_ledger` and `write_call_billing_entry` do not exist as separate functions; their logic is inlined in `finalize_call_billing` and `process_heartbeat`. Also, `start_call_billing` takes `rate_cents_per_min` (not `rate_cents_per_minute`). -->

#### `app/routers/call_billing.py` — **IMPLEMENTED** (247 lines, registered in `app/main.py:103,426`)

| Method | Path | Line | Notes |
|--------|------|------|-------|
| `GET` | `/ui/calls/rates/{creator_id}` | 78 | Matches spec |
| `POST` | `/ui/calls/rates` | 98 | Matches spec |
| `PUT` | `/ui/calls/rates` | 123 | Delegates to `set_own_rate` |
| `DELETE` | `/ui/calls/rates` | 132 | Matches spec |
| `PATCH` | `/messaging/messages/calls/{call_id}/heartbeat` | 148 | **Path differs from spec** |
| `GET` | `/messaging/messages/calls/{call_id}/billing` | 215 | **Path differs from spec** |

<!-- NOTE: The spec proposed heartbeat at `/messages/calls/{call_id}/heartbeat` and billing at `/messages/calls/{call_id}/billing`. The actual paths are `/messaging/messages/calls/{call_id}/heartbeat` (line 148) and `/messaging/messages/calls/{call_id}/billing` (line 215) — both prefixed with `/messaging/messages/` instead of just `/messages/`. The `HeartbeatOut` model at line 47 also has an extra `action: str = "ok"` field not in the spec, and `CallBillingStatusOut` at line 60 has an extra `billing_status: str = ""` field. -->

**Pydantic models** (all verified in `app/routers/call_billing.py`):

- `CallRateIn` (line 28) — matches spec: `rate_cents_per_minute: Field(..., ge=100, le=10000)`, `enabled`, `min_balance_minutes`, `max_duration_minutes`
- `CallRateOut` (line 35) — matches spec
- `HeartbeatIn` (line 43) — matches spec
- `HeartbeatOut` (line 47) — matches spec plus extra fields: `action: str = "ok"` (line 57), all numeric fields default to `0`
- `CallBillingStatusOut` (line 60) — matches spec plus extra field: `billing_status: str = ""` (line 71), all numeric fields default to `0`

#### Modify: `app/routers/messaging.py` — **DONE**

`CallInviteIn` (line 12900) now includes `paid: bool = False` (line 12906).

`CallInviteOut` (line 12910) now includes `paid: bool = False` (line 12918) and `rate_cents_per_minute: Optional[int] = None` (line 12919).

<!-- NOTE: `hold_amount_cents` is NOT in `CallInviteOut` — it was proposed but not implemented (consistent with the v1 simplification that uses a balance check instead of holds). -->

`create_call_invite` handler (line 12964) implements the paid call flow at lines 12971-13003:
1. Checks `body.paid` (line 12971)
2. If paid, looks up callee's rate via `get_call_rate` (line 12978)
3. If no rate or not enabled, returns 400 `"paid_calls_disabled"` (line 12981)
4. Calls `check_balance_for_paid_call` (line 12985)
5. Passes `paid=True` and `rate_cents_per_min` to `create_invite()` (line 13003)

#### Modify: `app/services/messaging_call_lifecycle.py` — **DONE**

- `create_invite()` accepts `paid` and `rate_cents_per_min` kwargs and passes them to `create_call_session()`
- `end_call()` (line 334) calls `finalize_call_billing(call_id)` at lines 387-388 after transitioning to terminal state if the session is paid

#### Modify: `app/services/messaging_call_sessions.py` — **DONE**

Billing fields added to `CallSessionRecord` dataclass (lines 37-48). Serialization at lines 74-90, deserialization at lines 116-127. The `create_call_session` function (line 139) accepts `paid`, `rate_cents_per_min`, and `max_duration_seconds` kwargs (lines 142-144).

```python
@dataclass
class CallSessionRecord:  # line 19
    # ... existing fields (lines 20-36) ...
    paid: bool = False  # line 37
    rate_cents_per_min: int = 0         # line 38 — NOTE: field name is rate_cents_per_min, NOT rate_cents_per_minute
    billing_start_ts: Optional[int] = None  # line 40
    last_billed_ts: Optional[int] = None    # line 41
    total_billed_cents: int = 0             # line 42
    total_billed_seconds: int = 0           # line 43
    billing_cycle_count: int = 0            # line 44
    platform_fee_bps: int = 0               # line 45
    max_duration_seconds: int = 0           # line 46
    caller_last_heartbeat_ts: Optional[int] = None   # line 47
    callee_last_heartbeat_ts: Optional[int] = None   # line 48
```

Serialization (`_item_from_record`, lines 70-90) and deserialization (`_record_from_item`, lines 108-127) handle all billing fields with safe coercion patterns (`int(item.get("field", 0))`).

<!-- NOTE: The spec proposed `hold_amount_cents` as a CallSessionRecord field — it is NOT present in the actual implementation. The spec also proposed a separate `update_call_billing_state()` function — this does NOT exist. Billing state updates are done inline within `process_heartbeat` (call_billing_timer.py:210) and `start_call_billing` (call_billing_timer.py:164) using direct DDB `update_item` calls. -->

#### Modify: `scripts/local-ddb-init.py` — **DONE**

`CallBillingLedger` table definition at lines 651-661 — matches spec exactly (PK `call_id`, SK `entry_id`, GSIs `ByCallerCreatedAt` and `ByCreatorCreatedAt`, `attr_types={"created_at": "N"}`).

#### Modify: `app/core/tables.py` — **DONE**

Table handle `call_billing_ledger` at line 94 (declaration) and line 218 (instantiation).

#### Modify: `app/main.py` — **DONE**

Router imported at line 103 (`from app.routers.call_billing import router as call_billing_router`) and registered at line 426 (`app.include_router(call_billing_router)`).

### Phase 2: Frontend — Rate Display & Cost Ticker (Days 4-7) — **PARTIALLY DONE**

#### Files

| File | Purpose | Status |
|------|---------|--------|
| `frontend/src/api/endpoints/callBilling.ts` | API wrappers for rate and billing endpoints | **IMPLEMENTED** (86 lines) |
| `frontend/src/components/calls/CallBillingOverlay.tsx` | Cost ticker overlay during call | **IMPLEMENTED** (62 lines) |
| `frontend/src/components/calls/CallBillingSummary.tsx` | Post-call billing summary | **IMPLEMENTED** (88 lines) |
| `frontend/src/components/calls/RateNegotiationDialog.tsx` | Rate negotiation dialog | **IMPLEMENTED** (RateNegotiationDialog, 3230 bytes) |
| `frontend/src/pages/messages/PaidCallRateBadge.tsx` | Rate display before calling | **NOT IMPLEMENTED** |
| `frontend/src/pages/messages/PaidCallCostTicker.tsx` | Live cost ticker during call | **NOT IMPLEMENTED** (replaced by CallBillingOverlay) |
| `frontend/src/pages/messages/PaidCallBalanceWarning.tsx` | Low balance warning dialog | **NOT IMPLEMENTED** |
| `frontend/src/pages/settings/CallRateSettings.tsx` | Creator call rate configuration UI | **NOT IMPLEMENTED** |
| `frontend/src/hooks/useCallBillingHeartbeat.ts` | Heartbeat timer + billing state sync | **NOT IMPLEMENTED** |

<!-- NOTE: The actual frontend components are in `frontend/src/components/calls/` (NOT `frontend/src/pages/messages/`). Three components exist: CallBillingOverlay.tsx (replaces the proposed PaidCallCostTicker), CallBillingSummary.tsx (not in original spec), and RateNegotiationDialog.tsx (not in original spec). However, PaidCallRateBadge, PaidCallBalanceWarning, CallRateSettings settings page, and useCallBillingHeartbeat hook do NOT exist. The billing components are NOT imported in ConversationView.tsx or CallSessionOverlay.tsx — they are defined but not yet wired into the call UI. -->

#### `frontend/src/api/endpoints/callBilling.ts` — **IMPLEMENTED** (86 lines)

Key differences from spec:
- Import is `{ api } from "@/api/client"` (not `client from "../client"`)
- API calls use `api.get(...)`, `api.post(...)`, `api.patch(...)`, `api.put(...)`, `api.del(...)` (not `client.get(...).then(r => r.data)`)
- `HeartbeatResponse` has extra `action: string` field (line 32)
- Extra `CallBillingStatus` interface (lines 35-47) with `billing_status` field
- Extra `CallRateIn` interface (lines 15-20)
- Extra functions: `updateCallRate` (line 62, PUT), `deleteCallRate` (line 66, DELETE), `negotiateCallRate` (line 83)
- Heartbeat path: `/messaging/messages/calls/${callId}/heartbeat` (not `/messages/calls/...`)
- Billing path: `/messaging/messages/calls/${callId}/billing`

#### `frontend/src/hooks/useCallBillingHeartbeat.ts`

<!-- NOTE: This hook file does NOT exist. The heartbeat mechanism has not been implemented as a standalone hook. The billing overlay components exist (CallBillingOverlay.tsx, CallBillingSummary.tsx) but are not wired into ConversationView or CallSessionOverlay, and there is no automatic heartbeat interval. This is a gap in the frontend implementation. -->

#### Modify: `frontend/src/pages/messages/CallSessionOverlay.tsx`

<!-- NOTE: CallSessionOverlay.tsx (671 lines) does NOT currently import or use CallBillingOverlay, CallBillingSummary, or any billing-related props. The billing overlay integration is NOT DONE. -->

Proposed additions to Props:
```typescript
isPaid?: boolean;
rateCentsPerMinute?: number;
totalCostCents?: number;
elapsedSeconds?: number;
balanceRemainingCents?: number;
warnLowBalance?: boolean;
```

Add cost ticker display (top-left of overlay, beside call timer):
```tsx
{isPaid && session.state === "connected" && (
  <div className="absolute top-4 left-4 flex flex-col gap-1 bg-black/70 text-white px-3 py-2 rounded-lg text-sm">
    <div className="flex items-center gap-2">
      <DollarSign className="h-3 w-3" />
      <span className="font-mono">${(totalCostCents / 100).toFixed(2)}</span>
    </div>
    <div className="text-xs text-gray-300">
      ${(rateCentsPerMinute / 100).toFixed(2)}/min
    </div>
  </div>
)}
```

Add low-balance warning overlay:
```tsx
{isPaid && warnLowBalance && (
  <div className="absolute top-16 left-1/2 -translate-x-1/2 bg-yellow-600/90 text-white px-4 py-2 rounded-full text-sm font-medium animate-pulse">
    Low balance — {minutesRemaining.toFixed(1)} minutes remaining
  </div>
)}
```

#### Modify: `frontend/src/pages/messages/ConversationView.tsx`

<!-- NOTE: ConversationView.tsx (1461 lines) does NOT currently import or reference any call billing components, hooks, or API calls. The paid call rate badge and heartbeat integration are NOT DONE. -->

Before the call invite button, show the creator's rate if set:
```tsx
{creatorCallRate && creatorCallRate.enabled && (
  <PaidCallRateBadge rateCents={creatorCallRate.rate_cents_per_minute} />
)}
```

When initiating a call, pass `paid: true` to the invite payload if the creator has a rate set and the user selects "Paid Call".

#### New Page: `frontend/src/pages/settings/CallRateSettings.tsx`

<!-- NOTE: This component does NOT exist. No call rate settings page has been implemented. -->

A settings panel for creators to configure their per-minute rate:
- Toggle: Enable/disable paid calls
- Input: Rate per minute ($1.00 - $100.00 slider or input)
- Input: Minimum balance (1-60 minutes)
- Input: Maximum call duration (1-480 minutes)
- Save button with `useMutation` to `POST /ui/calls/rates`

#### Modify: `frontend/src/hooks/useMessagingStream.ts` — **DONE**

Billing event types already present in `EVENT_TYPES` at lines 178-180.

#### Modify: `frontend/src/App.tsx`

<!-- NOTE: No call rate settings route has been added to App.tsx. The CallRateSettings page does not exist. -->

### Phase 3: Integration, Edge Cases & Polish (Days 8-10) — **PARTIALLY DONE**

#### Call-end summary message

When a paid call ends, insert a system message into the conversation timeline:

```python
system_message = {
    "kind": "system",
    "system_event": "paid_call_summary",
    "metadata": {
        "call_id": call_id,
        "duration_seconds": duration,
        "total_cost_cents": total_cost,
        "rate_cents_per_minute": rate,
        "platform_fee_cents": total_platform_fee,
        "end_reason": end_reason,
    },
}
```

Frontend renders as:
```
  +--------------------------------------+
  |  [Phone icon] Paid Call Ended        |
  |  Duration: 12:34                     |
  |  Total: $62.83 at $5.00/min          |
  +--------------------------------------+
```

#### Graceful balance depletion

When balance is depleted during a billing cycle:
1. Send `call.balance_depleted` SSE event to both parties
2. Start a 30-second grace period timer
3. If caller tops up wallet within 30 seconds (detected on next heartbeat), continue the call
4. If grace period expires, auto-end with reason `"balance_depleted"`

#### Concurrent call prevention

> **Corrected**: The original spec claimed that the existing busy check in `create_invite()` (lines 148-159 of `messaging_call_lifecycle.py`) prevents concurrent paid calls globally. In reality, the busy check only calls `list_call_sessions_for_conversation(conversation_id)`, which queries the `ByConversationStartedAt` GSI scoped to a **single conversation**. It does NOT prevent a caller from having concurrent active calls in **different** conversations. For paid calls, this is a billing integrity risk (a caller could run up charges across multiple simultaneous paid calls).

**Proposed fix**: Add a cross-conversation busy check for paid calls by querying the `ByCallerStartedAt` GSI (PK: `caller_user_id`) and the `ByCalleeStartedAt` GSI (PK: `callee_user_id`) on the `MessageCallSessions` table. If any active (invited/accepted/connected) paid call exists for the caller across any conversation, reject the new paid invite with `caller_busy`. This check is only needed for paid calls; free calls can continue using the per-conversation check.

---

## Testing Strategy

### Unit Tests (pytest)

**Test file**: `tests/test_call_11.py`

**Mock setup**: moto mock for DynamoDB (call session tables). Mock RTCPeerConnection for frontend unit tests. Chromium fake media devices for E2E.

| Test Function | Description |
|---|---|
| `test_create_resource` | Create primary resource; verify stored correctly |
| `test_lifecycle_transitions` | Verify allowed state transitions succeed |
| `test_invalid_transition_rejected` | Invalid transition returns 409 |
| `test_authorization_check` | Non-participant returns 403 |
| `test_idempotent_operation` | Repeated call returns same result |
| `test_cleanup_on_end` | Resources cleaned up after call ends |

### Integration Tests

Cross-service tests with real DynamoDB Local:

1. Full call lifecycle through real DDB (invite -> accept -> connect -> end)
2. Signaling relay: offer/answer/ICE exchange between two sessions
3. State machine transitions verified end-to-end

### E2E Tests (Playwright)

**Test file**: `frontend/e2e/call-11.spec.ts`

**Auth pattern**: `injectAuth(page, "alice")` for caller; `injectAuth(page, "bob")` for callee; separate browser contexts for two-peer tests

| # | Test Name | Assertion |
|---|---|---|
| 1 | Call invite creates session | POST invite -> 200 with call_id |
| 2 | Call accept transitions state | POST accept -> state = accepted |
| 3 | Signaling relay delivers events | POST signal -> SSE event received by peer |
| 4 | Connected state shows overlay | Both peers reach connected; overlay visible |
| 5 | End call cleans up resources | POST end -> state = ended; tracks stopped |
| 6 | Call overlay shows correct UI | Ringing/connected/ended states render correctly |
| 7 | Feature flag gates functionality | Disabled flag -> call button hidden |
| 8 | Unauthenticated returns 401 | No session -> 401 |
| 9 | Non-participant returns 403 | Third party -> 403 |
| 10 | Non-existent call returns 404 | Invalid call_id -> 404 |
| 11 | Invalid transition returns 409 | End already-ended call -> 409 |

**Negative tests**: 401 unauthenticated, 403 non-participant, 404 non-existent call, 409 invalid transition, 422 invalid payload

**Edge cases**: Concurrent accept/decline, call timeout (30s), ICE restart during connected state, tab backgrounding, network offline

### Test Data Requirements

Create DM conversation between Alice and Bob in `beforeAll`. Use `--use-fake-device-for-media-stream` Chromium flag for media tests.

**Test users**: Alice (USER, caller), Bob (USER, callee), Root (ROOT, admin for feature flags)

### CI/Pipeline

Serial execution (WebRTC requires sequential peer setup). `VITE_MESSAGING_WEBRTC_DIRECT_CALL_ENABLED=true`. Retry-safe.

---

## Dependencies & Merge Safety

### Depends On

| Ticket | What's Needed | Status | Can Overlap? |
|---|---|---|---|
| CALL-002 | RTCPeerConnection for call infrastructure | Implemented | Yes |
| MON-002 | Billing ledger for per-minute charges | Implemented | Yes |

### Depended On By

No downstream dependents identified.

### Merge Strategy

Independent. New billing timer service + DDB table. Parallel-safe with CALL-009.

### Merge Checklist

- [ ] Backend endpoint/service changes registered in `app/main.py`
- [ ] Frontend hooks and components created/modified
- [ ] Settings and feature flags configured
- [ ] DDB tables added if needed (`scripts/local-ddb-init.py`)
- [ ] E2E tests pass in CI
- [ ] No breaking changes to existing call endpoints

---

## Codebase References

| # | File | Lines | What |
|---|------|-------|------|
| 1 | `app/services/call_billing_timer.py` | 1-570 | Billing timer service: rate CRUD, heartbeat, finalization |
| 2 | `app/services/call_billing_timer.py` | 34, 45, 58 | `CallRateSettings`, `BillingTickResult`, `FinalBillingResult` dataclasses |
| 3 | `app/services/call_billing_timer.py` | 71, 89, 121, 131, 164, 210, 362, 461 | Public functions: get/set/delete rate, check balance, start billing, process heartbeat, finalize, get summary |
| 4 | `app/services/call_billing_timer.py` | 183, 297-299, 413-415 | Platform fee calculation (percent to BPS conversion) |
| 5 | `app/services/call_billing_timer.py` | 501, 537 | Private helpers: `_write_creator_credit`, `_write_caller_debit` |
| 6 | `app/routers/call_billing.py` | 1-247 | HTTP endpoints for rate settings, heartbeat, billing status |
| 7 | `app/routers/call_billing.py` | 28, 35, 43, 47, 60 | Pydantic models: CallRateIn, CallRateOut, HeartbeatIn, HeartbeatOut, CallBillingStatusOut |
| 8 | `app/routers/call_billing.py` | 78, 98, 123, 132, 148, 215 | Endpoint handlers |
| 9 | `app/services/messaging_call_sessions.py` | 19-50 | `CallSessionRecord` with billing fields (37-48) |
| 10 | `app/services/messaging_call_sessions.py` | 74-90, 116-127 | Serialization/deserialization of billing fields |
| 11 | `app/services/messaging_call_sessions.py` | 139-157 | `create_call_session` with paid/rate/max_duration kwargs |
| 12 | `app/services/messaging_call_lifecycle.py` | 334, 387-388 | `end_call()` calls `finalize_call_billing()` |
| 13 | `app/routers/messaging.py` | 12900-12906 | `CallInviteIn` with `paid: bool = False` |
| 14 | `app/routers/messaging.py` | 12910-12919 | `CallInviteOut` with `paid`, `rate_cents_per_minute` |
| 15 | `app/routers/messaging.py` | 12964-13016 | `create_call_invite` handler with paid call flow |
| 16 | `app/core/settings.py` | 1179-1191 | 13 call billing settings |
| 17 | `app/core/tables.py` | 94, 218 | `call_billing_ledger` table handle |
| 18 | `app/main.py` | 103, 426 | Router import and registration |
| 19 | `scripts/local-ddb-init.py` | 651-661 | `CallBillingLedger` table definition |
| 20 | `scripts/local-ddb-init.py` | 59 | `billing` table definition |
| 21 | `app/services/billing_shared.py` | 166-204 | `WALLET_SK`, `get_wallet_balance`, `apply_wallet_delta` |
| 22 | `app/services/tip_ledger.py` | 88 | `write_tip_ledger` (paired debit/credit pattern) |
| 23 | `frontend/src/api/endpoints/callBilling.ts` | 1-86 | API wrappers for call billing |
| 24 | `frontend/src/components/calls/CallBillingOverlay.tsx` | 1-62 | Cost ticker overlay component |
| 25 | `frontend/src/components/calls/CallBillingSummary.tsx` | 1-88 | Post-call billing summary component |
| 26 | `frontend/src/components/calls/RateNegotiationDialog.tsx` | 1-~90 | Rate negotiation dialog component |
| 27 | `frontend/src/hooks/useMessagingStream.ts` | 178-180 | SSE billing event types |
| 28 | `frontend/e2e/call-billing.spec.ts` | 1-591 | E2E tests for call billing |
| 29 | `tests/test_call_billing.py` | 1-499 | Unit tests for call billing |
