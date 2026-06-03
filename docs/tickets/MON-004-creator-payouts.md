# MON-004: Creator Payout System — Withdrawal Requests, Hold Periods, and Admin Approval

**Status**: Implemented  
**Author**: Engineering  
**Date**: 2026-05-26  
**Priority**: Medium  
**Estimated effort**: 6-9 days

---

## 1. Overview & Motivation

### The Gap

Creators earn revenue from multiple sources (subscriptions, tips, locked content unlocks, VOD purchases), and after MON-002 and MON-003, these earnings are accurately recorded as credit entries in the billing ledger. However, there is **no mechanism for creators to withdraw these earnings**. Money flows in but never flows out.

The platform has a wallet system (`WALLET` SK in the billing table, `apply_wallet_delta()` in `app/services/billing_shared.py` line 178), but it represents a **buyer's wallet** (prepaid balance for purchases), not a creator's earnings account. There is no concept of a creator balance, payout threshold, hold period, or withdrawal workflow.

### Why This Is Needed

1. **Creator retention**: If creators cannot withdraw earnings, the platform is functionally useless as a monetization tool. Payouts are table-stakes for any creator economy platform.

2. **Regulatory compliance**: Holding creator funds without a withdrawal mechanism may create money transmitter licensing issues. Funds must be disbursable.

3. **Trust**: Transparent payout workflows with clear status tracking (requested, processing, completed, failed) build creator confidence.

4. **Hold period for fraud prevention**: A configurable hold period (default 7 days) between earning and payout eligibility prevents chargebacks from becoming irrecoverable losses. If a subscriber disputes a charge within the hold period, the platform can claw back the creator's credit before payout.

### Architecture After This Change

```
Creator Flow:
+---------------------------------------------------------------------+
|                                                                     |
|  Tip/Sub/Unlock/VOD credit  -->  Earnings Balance (ledger credits)  |
|                                       |                             |
|                                       | hold_period (7d default)    |
|                                       v                             |
|                              Available for Payout                   |
|                                       |                             |
|                          POST /payouts/request                      |
|                                       |                             |
|                                       v                             |
|                         +---- Payout Request ----+                  |
|                         |  status: "requested"    |                  |
|                         |  amount_cents: X        |                  |
|                         |  method: bank_account   |                  |
|                         +--------+----------------+                  |
|                                  |                                   |
|                        Admin reviews queue                           |
|                                  |                                   |
|                    +-------------+-------------+                    |
|                    v             v              v                    |
|               "approved"    "rejected"    (auto-approve              |
|                    |                       if < threshold)           |
|                    v                                                 |
|              "processing"                                           |
|                    |                                                 |
|              External transfer                                      |
|              (Stripe Connect / manual)                              |
|                    |                                                 |
|              +-----+-----+                                          |
|              v           v                                           |
|         "completed"  "failed"                                       |
|                          |                                           |
|                    (retry or                                         |
|                     refund to balance)                               |
+---------------------------------------------------------------------+

Admin Flow:
+-------------------------------------------------------------+
|  GET /admin/payouts/queue                                    |
|  --> List pending payout requests                            |
|                                                              |
|  POST /admin/payouts/{id}/approve                            |
|  POST /admin/payouts/{id}/reject                             |
|  --> Transition payout state                                 |
|                                                              |
|  GET /admin/payouts/stats                                    |
|  --> Queue depth, total pending, avg processing time         |
+-------------------------------------------------------------+
```

**Payout state machine diagram:**
```
              +-- "cancelled" (by creator)
              |
"requested" --+-- "approved" --+-- "processing" --+-- "completed"
              |                |                   |
              +-- "rejected"   +-- "cancelled"     +-- "failed"
                  (by admin)       (by creator)        |
                                                       +-- "processing" (retry)
                                                       +-- "cancelled"
```

---

## 2. Current State Analysis

### 2.1 Wallet System (`app/services/billing_shared.py`)

The existing wallet operates on the `WALLET` SK under the billing table:

```python
# Line 166
WALLET_SK = "WALLET"

# Line 169
def get_wallet_balance(table: Any, pk: str) -> Dict[str, Any]:
    row = ddb_get(table, pk, WALLET_SK) or {}
    return {
        "wallet_balance_cents": int(row.get("wallet_balance_cents", 0)),
        ...
    }

# Line 178
def apply_wallet_delta(table: Any, pk: str, delta_cents: int, *, currency: str = "usd") -> int:
    # Deposits: unconditional add
    # Withdrawals (delta < 0): conditional on sufficient balance
```

This wallet is for **buyer deposits** (prepaid balance for purchases). Creators need a separate **earnings balance** concept computed from ledger credits minus completed payouts.

### 2.2 Billing Table Ledger Entries

Credit entries for creators use `PK=USER#{creator_id}, SK=LEDGER#{ts}#{entry_id}` with `type="credit"`. The earnings service (MON-003) aggregates these.

The **payout-available balance** must be computed as:
```
available = SUM(credit entries where ts <= now - hold_period)
          - SUM(completed payout amounts)
          - SUM(pending/processing payout amounts)
```

### 2.3 Admin System (`app/auth/deps.py` and `app/routers/billing.py`)

The admin auth system supports role-based access:
- `require_admin_session` — requires `role >= ADMIN`
- `require_root_session` — requires `role == ROOT`
- `AdminProfile` dataclass with scopes (e.g., `BILLING_SUPPORT`)

The billing router (`app/routers/billing.py`) already has `require_billing_admin_operator()` (line 423) which checks for `AdminScope.BILLING_SUPPORT`:
```python
async def require_billing_admin_operator(user: AuthenticatedUser = Depends(get_authenticated_user), request: Request = None) -> AuthenticatedUser:
```

This can be reused for payout admin endpoints.

### 2.4 Billing Configuration

The billing table stores per-user settings at `sk=BILLING`:
```python
{"pk": pk, "sk": "BILLING", "autopay_enabled": False, "currency": "usd", "default_payment_method_id": pm_id}
```

No payout-related settings exist (bank account, payout threshold preference, etc.).

### 2.5 Payment Methods (`app/routers/billing.py`)

Payment methods are stored at `sk=PM#{pm_id}` in the billing table. These represent **inbound** payment methods (cards, bank accounts for charging). Payout destinations (bank accounts for receiving payouts) are a different concept and need separate storage.

### 2.6 KMS Encryption (`app/core/crypto.py`)

The crypto module provides `kms_encrypt()` (line 16) and `kms_decrypt()` (line 22) for sensitive data encryption. Bank account numbers and routing numbers for payout destinations must be encrypted at rest using these functions.

---

## 3. Technical Design

### 3.1 Payout DDB Table

New table for payout request records:

```python
TableDef(
    "payouts",
    "pk",       # PAYOUT#{payout_id}
    "sk",       # META (main record) or EVENT#{ts}#{event_id} (audit trail)
    gsi=[
        {
            "index_name": "ByCreator",
            "partition_key": "creator_id",
            "sort_key": "requested_at",
        },
        {
            "index_name": "ByStatus",
            "partition_key": "status",
            "sort_key": "requested_at",
        },
    ],
    attr_types={"requested_at": "N"},
)
```

**DDB partition key distribution:**
```
payouts table
  PK = PAYOUT#{payout_id}      SK = META | EVENT#{ts}#{event_id}
  ──────────────────────────────────────────────────────────────
  PAYOUT#po_abc123               META
  PAYOUT#po_abc123               EVENT#1716681600#evt_001
  PAYOUT#po_abc123               EVENT#1716681700#evt_002
  PAYOUT#po_def456               META
  PAYOUT#po_def456               EVENT#1716681800#evt_003

  GSI: ByCreator
    PK = creator_id             SK = requested_at (N)
    ──────────────────────────────────────────────────────────
    creator_alice                1716681600
    creator_alice                1716768000

  GSI: ByStatus
    PK = status                  SK = requested_at (N)
    ──────────────────────────────────────────────────────────
    requested                    1716681600
    approved                     1716768000
    completed                    1716854400
```

Hot partition risk on ByStatus GSI: The "requested" partition will receive all new payout requests. At scale (>100 creators requesting payouts simultaneously), this could hit the 1000 WCU per-partition limit. Mitigation: use on-demand billing mode; at extreme scale, consider sharding the status key (e.g., `requested#shard_{hash % 10}`).

#### Payout Record Item (`sk=META`)

```python
{
    "pk": f"PAYOUT#{payout_id}",
    "sk": "META",
    "payout_id": payout_id,
    "creator_id": creator_user_id,
    "amount_cents": amount_cents,
    "currency": "USD",
    "status": "requested",              # requested | approved | processing | completed | failed | rejected | cancelled
    "payout_method_type": "bank_account",  # bank_account | paypal | manual
    "payout_method_id": payout_method_id,  # reference to stored payout destination
    "requested_at": ts,
    "approved_at": None,
    "approved_by": None,
    "processing_at": None,
    "completed_at": None,
    "failed_at": None,
    "failed_reason": None,
    "rejected_at": None,
    "rejected_by": None,
    "rejected_reason": None,
    "cancelled_at": None,
    "external_transfer_id": None,       # Stripe transfer/payout ID
    "hold_period_expires_at": ts,       # earliest eligible credit timestamp
    "ledger_entry_id": None,            # debit entry ID when completed
    "notes": None,                      # admin notes
}
```

#### Payout Event Item (`sk=EVENT#{ts}#{event_id}`)

Immutable audit trail for every state transition:

```python
{
    "pk": f"PAYOUT#{payout_id}",
    "sk": f"EVENT#{ts}#{event_id}",
    "event_id": event_id,
    "ts": ts,
    "from_status": "requested",
    "to_status": "approved",
    "actor_id": admin_user_id,          # or "system" for auto-transitions
    "reason": "Approved by admin",
    "metadata": {},
}
```

### 3.2 Payout Destination Storage

Extend the billing table to store payout destinations:

```python
# New SK pattern in billing table:
# PK: USER#{creator_id}, SK: PAYOUT_DEST#{dest_id}
{
    "pk": f"USER#{creator_id}",
    "sk": f"PAYOUT_DEST#{dest_id}",
    "dest_id": dest_id,
    "type": "bank_account",             # bank_account | paypal
    "label": "Chase ***4567",
    "is_default": True,
    "bank_name": "Chase",
    "account_last_four": "4567",
    "routing_number_last_four": "0021",
    "country": "US",
    "currency": "USD",
    "status": "verified",               # pending_verification | verified | failed
    "created_at": ts,
    "updated_at": ts,
    # Encrypted fields (stored via KMS):
    "encrypted_account_number": "...",   # kms_encrypt(account_number)
    "encrypted_routing_number": "...",   # kms_encrypt(routing_number)
}
```

### 3.3 Payout Service: `app/services/creator_payouts.py`

```python
"""Creator payout request management.

Handles payout request creation, state transitions, balance calculation,
and admin approval workflows.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key, Attr
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# -- Configuration -------------------------------------------------------

DEFAULT_HOLD_PERIOD_SECONDS = 7 * 24 * 3600   # 7 days
DEFAULT_MIN_PAYOUT_CENTS = 50_00               # $50.00
DEFAULT_MAX_PAYOUT_CENTS = 100_000_00          # $100,000.00
AUTO_APPROVE_THRESHOLD_CENTS = 500_00          # $500.00 -- auto-approve below this


def _hold_period() -> int:
    return int(getattr(S, "payout_hold_period_seconds", DEFAULT_HOLD_PERIOD_SECONDS))


def _min_payout() -> int:
    return int(getattr(S, "payout_min_amount_cents", DEFAULT_MIN_PAYOUT_CENTS))


def _max_payout() -> int:
    return int(getattr(S, "payout_max_amount_cents", DEFAULT_MAX_PAYOUT_CENTS))


def _auto_approve_threshold() -> int:
    return int(getattr(S, "payout_auto_approve_threshold_cents", AUTO_APPROVE_THRESHOLD_CENTS))


# -- Balance Calculation -------------------------------------------------

def compute_available_balance(creator_id: str) -> Dict[str, int]:
    """Compute creator's available payout balance.

    available = total_credits_past_hold - completed_payouts - pending_payouts

    Data flow:
      1. Query T.billing for PK=USER#{creator_id}, SK begins_with LEDGER#
         Filter: type = "credit"
         Sum amounts where ts <= (now - hold_period)
      2. Query T.payouts via ByCreator GSI for creator_id
         Filter: sk = "META" (ignore EVENT items)
         Sum amounts by status category
      3. available = credits_past_hold - completed - pending
    """
    now = now_ts()
    hold_cutoff = now - _hold_period()
    pk = f"USER#{creator_id}"

    # 1. Sum credit entries older than hold period
    total_credits = 0
    total_credits_all = 0
    last_key = None
    for _ in range(50):
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("pk").eq(pk) & Key("sk").begins_with("LEDGER#"),
            "FilterExpression": Attr("type").eq("credit"),
            "Limit": 500,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.billing.query(**kwargs)
        for item in resp.get("Items", []):
            amount = int(item.get("amount_cents", 0))
            ts = int(item.get("ts", 0))
            # Skip reversed entries
            if item.get("state") == "reversed":
                continue
            total_credits_all += amount
            if ts <= hold_cutoff:
                total_credits += amount
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    # 2. Sum completed + pending payouts
    completed_payouts = 0
    pending_payouts = 0
    last_key = None
    for _ in range(20):
        kwargs = {
            "IndexName": "ByCreator",
            "KeyConditionExpression": Key("creator_id").eq(creator_id),
            "Limit": 500,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.payouts.query(**kwargs)
        for item in resp.get("Items", []):
            if item.get("sk") != "META":
                continue
            status = item.get("status", "")
            amount = int(item.get("amount_cents", 0))
            if status == "completed":
                completed_payouts += amount
            elif status in ("requested", "approved", "processing"):
                pending_payouts += amount
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    available = max(0, total_credits - completed_payouts - pending_payouts)
    held = max(0, total_credits_all - total_credits)

    return {
        "total_earned_cents": total_credits_all,
        "available_cents": available,
        "held_cents": held,
        "pending_payout_cents": pending_payouts,
        "completed_payout_cents": completed_payouts,
        "currency": "USD",
    }


# -- Payout Request Lifecycle -------------------------------------------

def request_payout(
    *,
    creator_id: str,
    amount_cents: int,
    payout_method_id: str,
) -> Dict[str, Any]:
    """Create a new payout request.

    Validates: amount thresholds, available balance, payout destination.
    Auto-approves if amount is below the auto-approve threshold.
    """
    # Validate amount
    if amount_cents < _min_payout():
        raise HTTPException(400, f"Minimum payout is ${_min_payout() / 100:.2f}")
    if amount_cents > _max_payout():
        raise HTTPException(400, f"Maximum payout is ${_max_payout() / 100:.2f}")

    # Verify available balance
    balance = compute_available_balance(creator_id)
    if amount_cents > balance["available_cents"]:
        raise HTTPException(400, "Insufficient available balance")

    # Verify payout destination exists and is verified
    dest = T.billing.get_item(
        Key={"pk": f"USER#{creator_id}", "sk": f"PAYOUT_DEST#{payout_method_id}"}
    ).get("Item")
    if not dest:
        raise HTTPException(400, "Payout destination not found")
    if dest.get("status") != "verified":
        raise HTTPException(400, "Payout destination not verified")

    # Create payout record
    ts = now_ts()
    payout_id = f"po_{uuid.uuid4().hex}"
    hold_cutoff = ts - _hold_period()

    payout_item = {
        "pk": f"PAYOUT#{payout_id}",
        "sk": "META",
        "payout_id": payout_id,
        "creator_id": creator_id,
        "amount_cents": amount_cents,
        "currency": "USD",
        "status": "requested",
        "payout_method_type": dest.get("type", "bank_account"),
        "payout_method_id": payout_method_id,
        "requested_at": ts,
        "hold_period_expires_at": hold_cutoff,
    }
    T.payouts.put_item(Item=payout_item)

    # Write initial event
    _write_event(payout_id, from_status="", to_status="requested", actor_id=creator_id)

    # Auto-approve if below threshold
    if amount_cents <= _auto_approve_threshold():
        _transition_payout(payout_id, to_status="approved", actor_id="system", reason="Auto-approved (below threshold)")

    return payout_item


def _transition_payout(
    payout_id: str,
    *,
    to_status: str,
    actor_id: str,
    reason: str = "",
) -> Dict[str, Any]:
    """Transition payout to a new status with audit trail."""
    item = T.payouts.get_item(Key={"pk": f"PAYOUT#{payout_id}", "sk": "META"}).get("Item")
    if not item:
        raise HTTPException(404, "Payout not found")

    current_status = item["status"]
    _validate_transition(current_status, to_status)

    ts = now_ts()
    update_expr = f"SET #status = :s, {to_status}_at = :ts"
    expr_names = {"#status": "status"}
    expr_values: Dict[str, Any] = {":s": to_status, ":ts": ts}

    if to_status in ("approved", "rejected"):
        update_expr += f", {to_status}_by = :actor"
        expr_values[":actor"] = actor_id
    if reason and to_status in ("rejected", "failed"):
        update_expr += f", {to_status}_reason = :reason"
        expr_values[":reason"] = reason

    T.payouts.update_item(
        Key={"pk": f"PAYOUT#{payout_id}", "sk": "META"},
        UpdateExpression=update_expr,
        ExpressionAttributeNames=expr_names,
        ExpressionAttributeValues=expr_values,
    )

    _write_event(payout_id, from_status=current_status, to_status=to_status, actor_id=actor_id, reason=reason)

    # On completion: write ledger debit entry
    if to_status == "completed":
        _write_payout_ledger_debit(item)

    item["status"] = to_status
    return item


def _write_payout_ledger_debit(payout_item: Dict[str, Any]) -> None:
    """Write a debit entry to the creator's ledger when payout is completed.

    This debit reduces the creator's available balance in future calculations.
    """
    ts = now_ts()
    entry_id = uuid.uuid4().hex
    creator_id = payout_item["creator_id"]
    try:
        T.billing.put_item(Item={
            "pk": f"USER#{creator_id}",
            "sk": f"LEDGER#{ts}#{entry_id}",
            "entry_id": entry_id,
            "ts": ts,
            "type": "debit",
            "amount_cents": int(payout_item["amount_cents"]),
            "currency": payout_item.get("currency", "USD"),
            "state": "settled",
            "reason": "Payout",
            "meta": {
                "payout_id": payout_item["payout_id"],
                "payout_method_id": payout_item.get("payout_method_id"),
                "payout_method_type": payout_item.get("payout_method_type"),
            },
        })
        # Update payout record with ledger entry ID
        T.payouts.update_item(
            Key={"pk": f"PAYOUT#{payout_item['payout_id']}", "sk": "META"},
            UpdateExpression="SET ledger_entry_id = :eid",
            ExpressionAttributeValues={":eid": entry_id},
        )
    except Exception:
        logger.warning("payout_ledger_debit_failed", extra={"payout_id": payout_item["payout_id"]})


def _validate_transition(from_status: str, to_status: str) -> None:
    """Validate state machine transition.

    Valid transitions:
      requested  -> approved, rejected, cancelled
      approved   -> processing, cancelled
      processing -> completed, failed
      failed     -> processing (retry), cancelled
    """
    valid_transitions = {
        "requested": {"approved", "rejected", "cancelled"},
        "approved": {"processing", "cancelled"},
        "processing": {"completed", "failed"},
        "failed": {"processing", "cancelled"},       # retry or cancel
    }
    allowed = valid_transitions.get(from_status, set())
    if to_status not in allowed:
        raise HTTPException(409, f"Cannot transition from '{from_status}' to '{to_status}'")


def _write_event(
    payout_id: str,
    *,
    from_status: str,
    to_status: str,
    actor_id: str,
    reason: str = "",
) -> None:
    """Write an immutable audit event for a payout state transition."""
    ts = now_ts()
    event_id = uuid.uuid4().hex
    T.payouts.put_item(Item={
        "pk": f"PAYOUT#{payout_id}",
        "sk": f"EVENT#{ts}#{event_id}",
        "event_id": event_id,
        "ts": ts,
        "from_status": from_status,
        "to_status": to_status,
        "actor_id": actor_id,
        "reason": reason,
    })


# -- Query functions ---------------------------------------------------

def list_creator_payouts(*, creator_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    """List payout requests for a creator, newest first."""
    resp = T.payouts.query(
        IndexName="ByCreator",
        KeyConditionExpression=Key("creator_id").eq(creator_id),
        FilterExpression=Attr("sk").eq("META"),
        Limit=limit,
        ScanIndexForward=False,
    )
    return resp.get("Items", [])


def list_pending_payouts(*, status: str = "requested", limit: int = 100) -> List[Dict[str, Any]]:
    """List pending payouts across all creators (admin queue)."""
    resp = T.payouts.query(
        IndexName="ByStatus",
        KeyConditionExpression=Key("status").eq(status),
        FilterExpression=Attr("sk").eq("META"),
        Limit=limit,
        ScanIndexForward=True,  # oldest first (FIFO queue)
    )
    return resp.get("Items", [])


def get_payout_events(*, payout_id: str) -> List[Dict[str, Any]]:
    """Get audit trail events for a payout."""
    resp = T.payouts.query(
        KeyConditionExpression=Key("pk").eq(f"PAYOUT#{payout_id}") & Key("sk").begins_with("EVENT#"),
        ScanIndexForward=True,
    )
    return resp.get("Items", [])
```

### 3.4 API Endpoints

#### 3.4.1 Creator Endpoints (require_ui_session)

**GET /ui/payouts/balance** -- Available payout balance

```python
class PayoutBalanceOut(BaseModel):
    total_earned_cents: int
    available_cents: int
    held_cents: int
    pending_payout_cents: int
    completed_payout_cents: int
    currency: str = "USD"
    min_payout_cents: int
    hold_period_days: int
```

**POST /ui/payouts/request** -- Create payout request

```python
class PayoutRequestIn(BaseModel):
    amount_cents: int = Field(..., ge=1, le=100_000_00)
    payout_method_id: str = Field(..., min_length=1, max_length=128)

class PayoutRequestOut(BaseModel):
    payout_id: str
    amount_cents: int
    currency: str
    status: str
    requested_at: int
```

**GET /ui/payouts/history** -- List creator's payout requests

```python
class PayoutHistoryOut(BaseModel):
    items: List[PayoutItemOut]
    next_cursor: Optional[str] = None

class PayoutItemOut(BaseModel):
    payout_id: str
    amount_cents: int
    currency: str
    status: str
    payout_method_type: str
    requested_at: int
    completed_at: Optional[int] = None
    failed_reason: Optional[str] = None
    rejected_reason: Optional[str] = None
```

**POST /ui/payouts/{payout_id}/cancel** -- Cancel a pending request

**GET /ui/payouts/destinations** -- List payout destinations

**POST /ui/payouts/destinations** -- Add payout destination

```python
class PayoutDestinationIn(BaseModel):
    type: str = Field(..., pattern=r"^(bank_account|paypal)$")
    label: str = Field(..., min_length=1, max_length=100)
    # Bank account fields (conditional on type)
    bank_name: Optional[str] = None
    account_number: Optional[str] = None     # encrypted at rest via kms_encrypt()
    routing_number: Optional[str] = None     # encrypted at rest via kms_encrypt()
    country: str = "US"
    currency: str = "USD"
    # PayPal fields
    paypal_email: Optional[str] = None

    @model_validator(mode="after")
    def _validate_type_fields(self) -> "PayoutDestinationIn":
        if self.type == "bank_account":
            if not self.account_number or not self.routing_number:
                raise ValueError("bank_account requires account_number and routing_number")
            if not self.bank_name:
                raise ValueError("bank_account requires bank_name")
        elif self.type == "paypal":
            if not self.paypal_email:
                raise ValueError("paypal requires paypal_email")
        return self
```

**DELETE /ui/payouts/destinations/{dest_id}** -- Remove payout destination

#### 3.4.2 Admin Endpoints (require_billing_admin_operator)

**GET /admin/payouts/queue** -- List pending payout requests across all creators

```python
class AdminPayoutQueueOut(BaseModel):
    items: List[AdminPayoutItemOut]
    next_cursor: Optional[str] = None

class AdminPayoutItemOut(BaseModel):
    payout_id: str
    creator_id: str
    creator_email: Optional[str] = None
    amount_cents: int
    currency: str
    status: str
    payout_method_type: str
    requested_at: int
    hold_period_expires_at: int
```

**POST /admin/payouts/{payout_id}/approve** -- Approve a payout request

```python
class AdminPayoutActionIn(BaseModel):
    notes: Optional[str] = Field(default=None, max_length=500)
```

**POST /admin/payouts/{payout_id}/reject** -- Reject a payout request

```python
class AdminPayoutRejectIn(BaseModel):
    reason: str = Field(..., min_length=1, max_length=500)
    notes: Optional[str] = Field(default=None, max_length=500)
```

**GET /admin/payouts/stats** -- Queue statistics

```python
class AdminPayoutStatsOut(BaseModel):
    pending_count: int
    pending_total_cents: int
    processing_count: int
    processing_total_cents: int
    completed_today_count: int
    completed_today_cents: int
    rejected_today_count: int
```

### 3.5 Payout Completion Flow

When a payout moves to `processing`, an external transfer is initiated:

1. **Stripe Connect** (if configured): Create a Stripe Transfer to the creator's connected account
2. **Manual**: Admin marks as processing, initiates bank transfer externally, then marks completed
3. **PayPal**: Create PayPal payout to the stored email

On completion:
- Write a **debit** entry to the creator's billing ledger with reason `"Payout"` and `meta.payout_id`
- Transition status to `"completed"`
- This debit is subtracted from available balance in future calculations

On failure:
- Transition status to `"failed"` with `failed_reason`
- No debit entry (funds remain available)
- Creator can retry or cancel

### 3.6 Hold Period Implementation

The hold period prevents payouts of recently earned credits:

```python
hold_cutoff = now_ts() - _hold_period()  # e.g., now - 7 days

# Only credits with ts <= hold_cutoff count toward available balance
for entry in credit_entries:
    if int(entry["ts"]) <= hold_cutoff:
        available += int(entry["amount_cents"])
```

This means a tip earned today is not payout-eligible until 7 days later. The `held_cents` field in the balance response shows how much is in the hold period.

### 3.7 Error Handling

| Scenario | HTTP Status | Error |
|----------|-------------|-------|
| Below minimum payout | 400 | `below_minimum` |
| Above maximum payout | 400 | `above_maximum` |
| Insufficient balance | 400 | `insufficient_balance` |
| Payout dest not found | 400 | `destination_not_found` |
| Payout dest not verified | 400 | `destination_not_verified` |
| Invalid state transition | 409 | `invalid_transition` |
| Payout not found | 404 | `payout_not_found` |
| Not payout owner | 403 | `forbidden` |

---

## 4. Implementation Plan

### Step 1: Create Payouts DDB Table

**File**: `scripts/local-ddb-init.py`

Add table definition with ByCreator and ByStatus GSIs. Remember `attr_types={"requested_at": "N"}` to ensure the sort key is stored as a Number.

**File**: `app/core/settings.py` -- Add `payouts_table_name` setting:
```python
payouts_table_name: str = os.environ.get("PAYOUTS_TABLE_NAME", "payouts")
```

**File**: `app/core/tables.py` -- Add `payouts` table handle:
```python
# In Tables dataclass:
payouts: Any

# In T = Tables(...):
payouts=ddb.Table(S.payouts_table_name),
```

### Step 2: Create Payout Service

**File**: `app/services/creator_payouts.py` (new, ~350 lines)

Core functions: `compute_available_balance()`, `request_payout()`, `_transition_payout()`, `_write_payout_ledger_debit()`, `_validate_transition()`, `_write_event()`, `list_creator_payouts()`, `list_pending_payouts()`, `get_payout_events()`.

### Step 3: Create Payout Router (Creator Endpoints)

**File**: `app/routers/payouts.py` (new, ~200 lines)

Endpoints: balance, request, history, cancel, destinations CRUD.

### Step 4: Create Admin Payout Router

**File**: `app/routers/admin_payouts.py` (new, ~150 lines)

Endpoints: queue, approve, reject, stats. Uses `require_billing_admin_operator`.

### Step 5: Register Routers

**File**: `app/main.py`

```python
from app.routers.payouts import router as payouts_router
from app.routers.admin_payouts import router as admin_payouts_router
app.include_router(payouts_router)
app.include_router(admin_payouts_router)
```

### Step 6: Frontend Types and API

**File**: `frontend/src/api/types.ts` -- Add payout-related types  
**File**: `frontend/src/api/endpoints/payouts.ts` (new) -- API wrappers

### Step 7: Frontend Payout UI

**File**: `frontend/src/pages/earnings/PayoutsSection.tsx` (new, ~250 lines)

Integrate into the EarningsPage (from MON-003):
- Available balance card with "Request Payout" button
- Payout destination management (add/remove bank accounts)
- Payout history table

### Step 8: Admin Payout UI

**File**: `frontend/src/pages/admin/PayoutsAdmin.tsx` (new, ~200 lines)

Admin page with:
- Pending payout queue table
- Approve/reject buttons with confirmation dialogs
- Queue statistics dashboard

### Step 9: Configuration Settings

**File**: `app/core/settings.py`

```python
# Payout configuration
payout_hold_period_seconds: int = int(os.environ.get("PAYOUT_HOLD_PERIOD_SECONDS", str(7 * 24 * 3600)))
payout_min_amount_cents: int = int(os.environ.get("PAYOUT_MIN_AMOUNT_CENTS", "5000"))
payout_max_amount_cents: int = int(os.environ.get("PAYOUT_MAX_AMOUNT_CENTS", "10000000"))
payout_auto_approve_threshold_cents: int = int(os.environ.get("PAYOUT_AUTO_APPROVE_THRESHOLD_CENTS", "50000"))
```

### Summary of Files Modified

| File | Change Type | Estimated Lines |
|------|-------------|-----------------|
| `app/services/creator_payouts.py` | New service | ~350 |
| `app/routers/payouts.py` | New creator router | ~200 |
| `app/routers/admin_payouts.py` | New admin router | ~150 |
| `app/main.py` | Register routers | ~5 |
| `app/core/settings.py` | Add payout settings | ~10 |
| `app/core/tables.py` | Add table handle | ~5 |
| `scripts/local-ddb-init.py` | Add table definition | ~15 |
| `frontend/src/api/types.ts` | Add types | ~50 |
| `frontend/src/api/endpoints/payouts.ts` | New API file | ~60 |
| `frontend/src/pages/earnings/PayoutsSection.tsx` | New section | ~250 |
| `frontend/src/pages/admin/PayoutsAdmin.tsx` | New admin page | ~200 |
| `frontend/src/App.tsx` | Add admin route | ~5 |
| **Total** | | **~1300** |

---

## 5. Testing Strategy

### 5.1 Unit Tests (`tests/test_creator_payouts.py`)

New file, ~600 lines. Moto-mocked DynamoDB.

**Balance Calculation (8 tests):**

```python
def test_no_earnings_available_zero(ddb_tables):
    """No earnings: available=0."""
    result = compute_available_balance("creator_empty")
    assert result["available_cents"] == 0
    assert result["total_earned_cents"] == 0

def test_all_credits_within_hold_period(ddb_tables):
    """All credits within hold period: available=0, held=total."""
    # Seed credits at now_ts() (within 7-day hold)
    result = compute_available_balance("creator_held")
    assert result["available_cents"] == 0
    assert result["held_cents"] == result["total_earned_cents"]

def test_credits_past_hold_period(ddb_tables):
    """Credits past hold period: available=total."""
    # Seed credits at now_ts() - 8 days
    result = compute_available_balance("creator_available")
    assert result["available_cents"] == result["total_earned_cents"]

def test_mix_held_and_available(ddb_tables):
    """Mix of held and available credits."""
    result = compute_available_balance("creator_mixed")
    assert result["available_cents"] > 0
    assert result["held_cents"] > 0
    assert result["available_cents"] + result["held_cents"] == result["total_earned_cents"]

def test_completed_payout_reduces_available(ddb_tables):
    result = compute_available_balance("creator_completed")
    # available = total_past_hold - completed
    assert result["available_cents"] == result["total_earned_cents"] - result["completed_payout_cents"]

def test_pending_payout_reduces_available(ddb_tables):
    result = compute_available_balance("creator_pending")
    assert result["available_cents"] < result["total_earned_cents"]

def test_failed_payout_does_not_reduce(ddb_tables):
    result = compute_available_balance("creator_failed")
    # Failed payouts release funds
    assert result["pending_payout_cents"] == 0

def test_cancelled_payout_does_not_reduce(ddb_tables):
    result = compute_available_balance("creator_cancelled")
    assert result["pending_payout_cents"] == 0
```

**Payout Request (7 tests):**

```python
def test_happy_path_create_payout(ddb_tables):
    result = request_payout(creator_id="alice", amount_cents=5000, payout_method_id="dest_1")
    assert result["payout_id"].startswith("po_")
    assert result["status"] == "requested"

def test_below_minimum_threshold(ddb_tables):
    with pytest.raises(HTTPException) as exc:
        request_payout(creator_id="alice", amount_cents=100, payout_method_id="dest_1")
    assert exc.value.status_code == 400

def test_above_maximum_threshold(ddb_tables):
    with pytest.raises(HTTPException) as exc:
        request_payout(creator_id="alice", amount_cents=200_000_00, payout_method_id="dest_1")
    assert exc.value.status_code == 400

def test_insufficient_balance(ddb_tables):
    with pytest.raises(HTTPException) as exc:
        request_payout(creator_id="alice", amount_cents=999_999, payout_method_id="dest_1")
    assert exc.value.status_code == 400

def test_destination_not_found(ddb_tables):
    with pytest.raises(HTTPException) as exc:
        request_payout(creator_id="alice", amount_cents=5000, payout_method_id="nonexistent")
    assert exc.value.status_code == 400

def test_unverified_destination(ddb_tables):
    with pytest.raises(HTTPException) as exc:
        request_payout(creator_id="alice", amount_cents=5000, payout_method_id="dest_unverified")
    assert exc.value.status_code == 400

def test_auto_approve_below_threshold(ddb_tables):
    result = request_payout(creator_id="alice", amount_cents=100_00, payout_method_id="dest_1")
    # Refresh to get updated status
    item = T.payouts.get_item(Key={"pk": f"PAYOUT#{result['payout_id']}", "sk": "META"})["Item"]
    assert item["status"] == "approved"
```

**State Transitions (6 tests) + Invalid Transitions (4 tests) + Audit Trail (3 tests):**

```python
def test_requested_to_approved():
    result = _transition_payout(payout_id, to_status="approved", actor_id="admin_1")
    assert result["status"] == "approved"

def test_requested_to_rejected():
    result = _transition_payout(payout_id, to_status="rejected", actor_id="admin_1", reason="Suspicious activity")
    assert result["status"] == "rejected"

def test_completed_writes_ledger_debit(ddb_tables):
    """processing -> completed writes ledger debit."""
    _transition_payout(payout_id, to_status="completed", actor_id="system")
    entries = query_billing_ledger(user_id=creator_id)
    debits = [e for e in entries if e["reason"] == "Payout"]
    assert len(debits) == 1

def test_completed_to_anything_fails():
    with pytest.raises(HTTPException) as exc:
        _transition_payout(completed_payout_id, to_status="processing", actor_id="admin")
    assert exc.value.status_code == 409

def test_each_transition_creates_event():
    events = get_payout_events(payout_id=payout_id)
    assert len(events) >= 2  # initial "requested" + transition

def test_event_contains_actor_and_reason():
    events = get_payout_events(payout_id=payout_id)
    assert events[-1]["actor_id"] == "admin_1"
```

### 5.2 E2E Tests (`frontend/e2e/creator-payouts.spec.ts`)

New file, ~500 lines.

**Section 96: Payout Balance API (5 tests)**:

1. `No earnings returns zero balance`
2. `Credits within hold period shown as held`
3. `Credits past hold period shown as available`
4. `Balance reflects pending payouts`
5. `Balance reflects completed payouts`

**Section 97: Payout Destinations API (5 tests)**:

1. `Add bank account destination`
2. `List destinations returns added account`
3. `Delete destination removes it`
4. `Cannot use deleted destination for payout`
5. `Cannot add destination with invalid type`

**Section 98: Payout Request API (6 tests)**:

1. `Request payout with valid amount and destination`
2. `Below minimum returns 400`
3. `Insufficient balance returns 400`
4. `Small payout auto-approved`
5. `List payout history shows request`
6. `Cancel pending payout`

**Section 99: Admin Payout Queue API (5 tests)**:

1. `Admin sees pending payouts in queue`
2. `Admin approves payout`
3. `Admin rejects payout with reason`
4. `Non-admin cannot access queue`
5. `Queue stats reflect current state`

**Section 100: Payout UI (4 tests)**:

1. `Earnings page shows available balance and payout button`
2. `Request payout dialog shows destinations`
3. `After payout request, history table updates`
4. `Cancel button removes pending payout`

**Test Setup (beforeAll)**:
- Seed sessions for Alice (creator), Root (admin)
- Seed credit entries in billing table for Alice (some within hold period, some older)
- Add payout destination for Alice
- Hold period set to 1 second via env var override for test speed

### 5.3 Edge Cases to Cover

1. **Concurrent payout requests**: Two requests submitted simultaneously could both pass the balance check. Solution: use DDB conditional writes with a version counter on a "payout lock" item. If the second request's condition fails, return 409.

2. **Creator deletes destination while payout is processing**: The payout record stores the destination details at request time. The external transfer uses stored details, not a live lookup.

3. **Hold period change**: If the admin changes the hold period from 7 to 14 days, existing available balances decrease. The balance calculation always uses the current setting.

4. **Chargeback during hold period**: If a subscription charge is reversed, the credit entry should be marked as `state="reversed"` in the billing ledger. The `_query_credit_entries` function should filter out reversed entries.

5. **Zero-amount credits**: Some platform actions may generate $0 credits (e.g., free trial subscriptions). These should be excluded from available balance.

6. **Currency mismatch**: All current transactions are USD. The payout system should validate that the creator's earnings currency matches the payout destination currency.

7. **Rapid successive requests**: A creator requesting multiple payouts quickly could drain balance beyond available. The balance check + payout write should be atomic or use optimistic concurrency.

8. **Admin impersonation context**: Admin payout actions should use the admin's own user ID for `approved_by`/`rejected_by`, not an impersonated user ID.

---

## 6. Security Considerations

### 6.1 Bank Account Encryption

Account numbers and routing numbers must be encrypted at rest using KMS. The `app/core/crypto.py` module provides `kms_encrypt()` (line 16) and `kms_decrypt()` (line 22).

```python
# When storing a payout destination:
from app.core.crypto import kms_encrypt
encrypted_account = kms_encrypt(inp.account_number)
encrypted_routing = kms_encrypt(inp.routing_number)

# Only store last 4 digits in cleartext for display:
account_last_four = inp.account_number[-4:]
```

The `kms_encrypt()` function uses the KMS key specified by `S.kms_key_id` in `app/core/settings.py` (line 176). The mock KMS server runs on port 7999 in dev mode.

### 6.2 PII in Audit Trail

Payout events should not contain bank account details -- only the `payout_method_id` reference. The event `metadata` field should never include account numbers, routing numbers, or full names.

### 6.3 Admin Authorization

Payout approval requires `AdminScope.BILLING_SUPPORT` scope, consistent with existing billing admin operations. The admin's user_sub (not impersonated user) is recorded in `approved_by`/`rejected_by`.

```python
# In admin_payouts router:
@router.post("/{payout_id}/approve")
def approve_payout(payout_id: str, inp: AdminPayoutActionIn, user=Depends(require_billing_admin_operator)):
    admin_id = user["user_sub"]  # Not impersonated user
    # ...
```

### 6.4 Rate Limiting

- Payout requests: Max 5 requests per day per creator. Prevents abuse and reduces admin queue volume.
- Destination additions: Max 3 per day per creator. Prevents bulk destination creation for money laundering.
- Admin actions: Subject to existing `admin_action_max_per_window` (120 per 15 minutes, settings.py line 157).

### 6.5 Fraud Prevention

- The hold period (default 7 days) prevents chargebacks from becoming irrecoverable.
- Auto-approve threshold ($500) limits exposure for small payouts.
- Admin review queue for larger payouts provides human oversight.
- Audit trail (EVENT items) provides forensic evidence for dispute resolution.

### 6.6 OWASP Considerations

- **Insecure Direct Object References**: Payout cancel endpoint validates `creator_id` matches the authenticated user before allowing cancellation.
- **Mass Assignment**: Pydantic models with explicit fields prevent unexpected input. `status` is never settable via API.
- **Sensitive Data Exposure**: Bank account numbers are KMS-encrypted. Only last-4 digits are exposed in API responses.

---

## 7. Migration & Rollback Plan

### 7.1 DDB Table Creation

The `payouts` table is new. Creation script in `scripts/local-ddb-init.py`:

```python
TableDef(
    "payouts", "pk", "sk",
    gsi=[
        {"index_name": "ByCreator", "partition_key": "creator_id", "sort_key": "requested_at"},
        {"index_name": "ByStatus", "partition_key": "status", "sort_key": "requested_at"},
    ],
    attr_types={"requested_at": "N"},
),
```

The `PAYOUT_DEST#` items are stored in the existing billing table (no schema change needed).

### 7.2 Feature Flag

```python
payout_system_enabled: bool = os.environ.get("PAYOUT_SYSTEM_ENABLED", "0") not in ("0", "false", "False")
```

### 7.3 Rollback Steps

1. Set `PAYOUT_SYSTEM_ENABLED=0`.
2. Any in-progress payouts must be manually completed or cancelled by the operations team.
3. The payouts table can be retained (no data loss risk) or deleted.
4. Creator earnings remain unaffected -- only the withdrawal mechanism is disabled.

### 7.4 Zero-Downtime

- New table, new routers, new service. No existing code is modified.
- The billing table gets new `PAYOUT_DEST#` items but these do not affect existing SK patterns.

---

## 8. Operational Runbook

### 8.1 Metrics

| Metric | Type | Labels |
|--------|------|--------|
| `payout_request_total` | Counter | `status={success,failure,insufficient,below_min}` |
| `payout_transition_total` | Counter | `from_status`, `to_status` |
| `payout_amount_cents` | Histogram | `status={requested,completed,failed}` |
| `payout_balance_compute_latency` | Histogram | |
| `admin_payout_queue_depth` | Gauge | |

### 8.2 Alerting

| Alert | Condition | Severity |
|-------|-----------|----------|
| Payout queue depth > 50 | `admin_payout_queue_depth > 50` | Medium |
| Failed payout rate > 10% | `rate(payout_transition_total{to_status=failed}) > 0.1` | High |
| Balance computation > 5s | Histogram p99 | Medium |
| Zero payouts completed in 24h (weekdays) | `increase(payout_transition_total{to_status=completed}[24h]) == 0` | Low |

### 8.3 Common Debugging Scenarios

**Scenario: Creator's available balance is lower than expected**
1. Run `compute_available_balance(creator_id)` manually.
2. Check `held_cents` -- recent earnings are still in the hold period.
3. Check `pending_payout_cents` -- existing pending payouts reduce availability.
4. Check for `state=reversed` credit entries (chargebacks).

**Scenario: Payout stuck in "processing" status**
1. Check external transfer status (Stripe dashboard, bank records).
2. If transfer succeeded, manually transition to "completed" via admin API.
3. If transfer failed, transition to "failed" with reason.

**Scenario: Creator cannot add payout destination**
1. Check rate limit (max 3 destinations per day).
2. Check KMS availability (mock KMS on port 7999 in dev).
3. Verify `KMS_KEY_ID` is set in `.env.local`.

---

## 9. Performance & Capacity Planning

### 9.1 Balance Computation Cost

The `compute_available_balance()` function performs two expensive operations:
1. Full scan of creator's LEDGER entries (up to 50 pages)
2. Full scan of creator's payouts via ByCreator GSI (up to 20 pages)

For a creator with 1000 ledger entries and 10 payouts: ~5-10 RCUs, ~200ms latency.

For a high-volume creator with 10,000 entries: ~50-100 RCUs, ~1-2s latency.

**Optimization**: Cache the balance result for 30 seconds. Invalidate on payout request or completion.

### 9.2 Admin Queue Query

The ByStatus GSI query for `status=requested` scans all pending payouts. At scale (1000+ pending payouts), pagination is needed. The admin UI should paginate with limit=50.

### 9.3 Latency Budget

| Operation | Target p99 |
|-----------|-----------|
| GET /payouts/balance | 2000ms (full scan) |
| POST /payouts/request | 3000ms (balance check + write) |
| GET /payouts/history | 200ms (single GSI query) |
| POST /admin/payouts/{id}/approve | 100ms (single update + event write) |

---

## 10. Dependency Analysis

### 10.1 Blocked By

| Ticket | Dependency |
|--------|-----------|
| MON-002 | Accurate credit entries for tips |
| MON-003 | Earnings summary for balance display on payout page |

### 10.2 Blocks

None. MON-004 is a leaf ticket.

### 10.3 Integration Points

- **Billing table (`T.billing`)**: Reads LEDGER credits, writes PAYOUT_DEST items and payout completion debit.
- **Payouts table (`T.payouts`)**: New table for payout records and events.
- **KMS (`app/core/crypto.py`)**: Encrypts bank account details.
- **Admin auth (`app/routers/billing.py`)**: Uses `require_billing_admin_operator` (line 423) for admin endpoints.
- **Earnings page (MON-003)**: PayoutsSection integrates into EarningsPage.

---

## 11. Acceptance Criteria

1. A creator can add a bank account or PayPal payout destination.
2. Bank account numbers are KMS-encrypted at rest.
3. `GET /ui/payouts/balance` returns correct `available_cents` accounting for hold period, completed payouts, and pending payouts.
4. A creator can request a payout via `POST /ui/payouts/request` with a valid amount and destination.
5. Payouts below the auto-approve threshold are automatically approved.
6. Payouts above the threshold appear in the admin queue.
7. An admin with `BILLING_SUPPORT` scope can approve or reject payouts.
8. Rejected payouts include a reason visible to the creator.
9. Completed payouts write a debit LEDGER entry with `reason: "Payout"`.
10. The audit trail records every state transition with actor and timestamp.
11. Invalid state transitions return HTTP 409.
12. A creator can cancel a pending (requested or approved) payout.
13. All 28 unit tests and 25 E2E tests pass.

---

## 12. Error Handling Matrix

| Endpoint | Condition | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|----------|-----------|-------------|------------|---------------------|-----------------|
| GET /payouts/balance | DDB scan timeout | 500 | `internal_error` | "Unable to compute balance" | Retry |
| POST /payouts/request | Below minimum ($50) | 400 | `below_minimum` | "Minimum payout is $50.00" | Increase amount |
| POST /payouts/request | Above maximum ($100K) | 400 | `above_maximum` | "Maximum payout is $100,000.00" | Decrease amount |
| POST /payouts/request | Insufficient balance | 400 | `insufficient_balance` | "Insufficient available balance" | Wait for hold period |
| POST /payouts/request | Destination not found | 400 | `destination_not_found` | "Payout destination not found" | Add destination |
| POST /payouts/request | Destination not verified | 400 | `destination_not_verified` | "Payout destination not verified" | Wait for verification |
| POST /payouts/{id}/cancel | Not owner | 403 | `forbidden` | "Not authorized" | N/A |
| POST /payouts/{id}/cancel | Already completed | 409 | `invalid_transition` | "Cannot cancel completed payout" | N/A |
| POST /admin/payouts/{id}/approve | Not admin | 403 | `forbidden` | "Admin access required" | N/A |
| POST /admin/payouts/{id}/reject | No reason provided | 422 | `validation_error` | "Reason is required" | Provide reason |
| POST /payouts/destinations | Invalid type | 422 | `validation_error` | "Type must be bank_account or paypal" | Fix type |
| POST /payouts/destinations | Missing bank fields | 422 | `validation_error` | "bank_account requires account_number..." | Provide fields |
| POST /payouts/destinations | KMS encrypt failure | 500 | `encryption_error` | "Unable to securely store account" | Check KMS |

---

## 13. Frontend Component Specifications

### 13.1 PayoutsSection Component

```typescript
interface PayoutsSectionProps {
  // Embedded in EarningsPage -- no props needed
}
```

**Component tree:**
```
PayoutsSection
  ├── BalanceCard
  │     ├── Available: $XXX.XX
  │     ├── Held: $XX.XX (in hold period)
  │     ├── Pending: $XX.XX (awaiting payout)
  │     └── Button: "Request Payout"
  ├── PayoutDestinations
  │     ├── DestinationCard[] (bank name, last 4, status badge)
  │     └── Button: "Add Destination"
  ├── PayoutHistory
  │     ├── Table: payout_id | amount | status | date | actions
  │     └── CancelButton (for pending payouts)
  └── RequestPayoutDialog
        ├── AmountInput (with min/max validation)
        ├── DestinationSelector (radio group)
        └── ConfirmButton
```

**State management:**
- Balance: `useQuery(["payouts", "balance"], getPayoutBalance)`
- Destinations: `useQuery(["payouts", "destinations"], getPayoutDestinations)`
- History: `useQuery(["payouts", "history"], getPayoutHistory)`
- Request mutation: `useMutation(requestPayout, { onSuccess: invalidate all })`

### 13.2 AdminPayoutsPage Component

```typescript
interface AdminPayoutsPageProps {
  // Top-level admin page
}
```

**Accessible at**: `/admin/payouts`  
**Auth**: Requires admin role with BILLING_SUPPORT scope

**Component tree:**
```
AdminPayoutsPage
  ├── QueueStatsCards
  │     ├── Pending: X ($X,XXX)
  │     ├── Processing: X ($X,XXX)
  │     └── Completed Today: X ($X,XXX)
  ├── PayoutQueueTable
  │     ├── Columns: Creator | Amount | Method | Requested | Hold Expires | Actions
  │     ├── ApproveButton (with notes dialog)
  │     └── RejectButton (with reason dialog)
  └── RejectDialog
        ├── TextArea: "Reason for rejection"
        └── ConfirmButton
```

---

## 14. Related Tickets

- **MON-002**: Tip credits (required for accurate balance)
- **MON-003**: Earnings dashboard (shows available balance, integrates payout section)
- **MON-001**: VOD purchase credits (included in payout-eligible balance)
- **MON-005**: Subscription credits (included in payout-eligible balance)

---

## Codebase References

| File | Line(s) | What was verified |
|------|---------|-------------------|
| `app/services/creator_payouts.py` | 27-393 | ALREADY EXISTS (443 lines): `get_available_balance` (55), `request_payout` (164), `cancel_payout` (208), `list_user_payouts` (235), `list_payouts_admin` (256), `approve_payout` (292), `reject_payout` (321), `complete_payout` (351), `get_payout_stats` (393) |
| `app/routers/creator_payouts.py` | 32, 35, 50, 79, 95 | ALREADY EXISTS: router with prefix `/ui/payouts`, `GET /balance` (35), `POST /request` (50), `POST /{id}/cancel` (79), `GET /` list (95) |
| `app/routers/admin_payouts.py` | — | ALREADY EXISTS: admin payout management router |
| `app/main.py` | 111-112, 434-435 | EXISTS: `creator_payouts_router` and `admin_payouts_router` imported and registered |
| `scripts/local-ddb-init.py` | 762 | EXISTS: `CreatorPayouts` table definition |
| `app/core/settings.py` | 1175-1177 | EXISTS: `creator_payouts_table_name`, `payout_hold_period_seconds` (604800), `payout_minimum_cents` (1000) |
| `app/core/tables.py` | 86, 210 | EXISTS: `T.creator_payouts` table handle |
| `app/services/billing_shared.py` | 178 | EXISTS: `apply_wallet_delta()` for wallet operations |
<!-- NOTE: The payout system (service, router, admin router, DDB table, settings) is FULLY IMPLEMENTED. The frontend page may still need implementation. -->

---

## Testing Strategy

### Unit Tests (`tests/test_creator_payouts.py`)
**Framework**: pytest + moto (DynamoDB/S3 mock)

| # | Test Function | What It Verifies |
|---|--------------|-----------------|
| 1 | `test_create_payout_request` | Create payout request |
| 2 | `test_hold_period_enforcement` | Hold period enforcement |
| 3 | `test_approve_payout_debits_balance` | Approve payout debits balance |
| 4 | `test_reject_payout_with_reason` | Reject payout with reason |
| 5 | `test_minimum_payout_threshold` | Minimum payout threshold |
| 6 | `test_payout_history_paginated` | Payout history paginated |
| 7 | `test_admin_list_pending_payouts` | Admin list pending payouts |
| 8 | `test_insufficient_balance_rejected` | Insufficient balance rejected |

### Integration Tests

1. Full endpoint flow: create, read, update, delete with FastAPI TestClient + mocked DDB
2. Auth enforcement: verify 401 without session, 403 for wrong role
3. Validation: 422 for malformed requests, 404 for missing resources
4. Cross-service: verify DDB writes are consistent across tables
5. SSE/real-time: verify events published on mutations (where applicable)

### E2E Tests (`frontend/e2e/creator-payouts.spec.ts`)
**Auth**: `injectAuth(page, identity)` for cookie auth; `apiPost(page, identity, path, body)` for CSRF-protected requests.

**Total**: ~14 tests covering API CRUD, auth enforcement (401/403), validation (422), negative cases (404/409), and UI interactions.

**Negative/Edge Tests**: 401 without auth, 403 for wrong role, 404 for missing resources, 409 for conflicts, 422 for validation errors.

### Test Data Requirements
- Test users: Alice (USER), Bob (USER), Root (ROOT), Charlie (ADMIN) from `e2e_admin_session_setup.py`
- Session seeding: `python3 e2e_admin_session_setup.py` before test run

### CI/Pipeline
- Feature flags: `CREATOR_PAYOUTS_ENABLED=true`
- Tests run serially (single Playwright worker, `workers: 1`)
- Retry safety: 1 retry configured; tests use unique timestamps (`Date.now()`) for isolation
- Run: `cd frontend && npx playwright test e2e/<spec-file>`

---

## Dependencies & Merge Safety

### Depends On

| Ticket | What It Provides | Hard/Soft |
|--------|-----------------|-----------|
| MON-003 | Creator Earnings Dashboard for available balance | Hard |
| MON-002 | Tip Ledger for complete credit entries | Hard |

### Depended On By

No downstream dependents identified.

### Merge Strategy
**Sequential -- requires MON-002 and MON-003 merged first. Payout request validates available balance from earnings aggregation.**

### Merge Checklist
- [ ] Feature flags configured in `.env.local`: CREATOR_PAYOUTS_ENABLED=true
- [ ] Service file created/modified: `app/services/creator_payouts.py`
- [ ] No endpoint prefix conflicts with existing routers
- [ ] E2E tests pass: `cd frontend && npx playwright test frontend/e2e/creator-payouts.spec.ts`
- [ ] Unit tests pass: `.venv/bin/pytest tests/test_creator_payouts.py`
