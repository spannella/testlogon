"""Server-side billing timer for pay-per-minute calls (CALL-011).

Manages:
  - Creator call rate settings (CRUD on T.billing CALL_RATE items)
  - Per-minute billing cycles (triggered by heartbeat)
  - Wallet debit / creator credit with platform fee
  - Call finalization with pro-rated final billing
  - Balance pre-check for paid call initiation
"""
from __future__ import annotations

import logging
import math
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Literal, Optional

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.billing_config import get_fee_bps
from app.services.billing_shared import (
    apply_wallet_delta,
    get_wallet_balance,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class CallRateSettings:
    user_id: str
    rate_cents_per_minute: int
    enabled: bool
    currency: str = "USD"
    min_balance_minutes: int = 5
    max_duration_minutes: int = 120
    updated_at: int = 0


@dataclass
class BillingTickResult:
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
class FinalBillingResult:
    total_cents: int
    duration_seconds: int = 0
    final_charge_cents: int = 0


# ---------------------------------------------------------------------------
# Call rate CRUD
# ---------------------------------------------------------------------------

CALL_RATE_SK = "CALL_RATE"


def get_call_rate(creator_user_id: str) -> Optional[CallRateSettings]:
    """Fetch a creator's per-minute call rate from the billing table."""
    pk = f"USER#{creator_user_id}"
    resp = T.billing.get_item(Key={"pk": pk, "sk": CALL_RATE_SK})
    item = resp.get("Item")
    if not item:
        return None
    return CallRateSettings(
        user_id=creator_user_id,
        rate_cents_per_minute=int(item.get("rate_cents_per_minute", 0)),
        enabled=bool(item.get("enabled", False)),
        currency=str(item.get("currency", "USD")),
        min_balance_minutes=int(item.get("min_balance_minutes", 5)),
        max_duration_minutes=int(item.get("max_duration_minutes", 120)),
        updated_at=int(item.get("updated_at", 0)),
    )


def set_call_rate(
    *,
    user_id: str,
    rate_cents_per_minute: int,
    enabled: bool = True,
    min_balance_minutes: int = 5,
    max_duration_minutes: int = 120,
) -> CallRateSettings:
    """Create or update a creator's per-minute call rate."""
    pk = f"USER#{user_id}"
    ts = now_ts()
    T.billing.put_item(Item={
        "pk": pk,
        "sk": CALL_RATE_SK,
        "rate_cents_per_minute": rate_cents_per_minute,
        "enabled": enabled,
        "currency": "USD",
        "min_balance_minutes": min_balance_minutes,
        "max_duration_minutes": max_duration_minutes,
        "updated_at": ts,
    })
    return CallRateSettings(
        user_id=user_id,
        rate_cents_per_minute=rate_cents_per_minute,
        enabled=enabled,
        currency="USD",
        min_balance_minutes=min_balance_minutes,
        max_duration_minutes=max_duration_minutes,
        updated_at=ts,
    )


def delete_call_rate(user_id: str) -> None:
    """Delete a creator's call rate (disable paid calls)."""
    pk = f"USER#{user_id}"
    T.billing.delete_item(Key={"pk": pk, "sk": CALL_RATE_SK})


# ---------------------------------------------------------------------------
# Balance check
# ---------------------------------------------------------------------------

def check_balance_for_paid_call(
    *,
    caller_user_id: str,
    rate_cents_per_minute: int,
    min_balance_minutes: int,
) -> Dict[str, Any]:
    """Verify that the caller has sufficient wallet balance.

    Returns a dict with balance info.
    Raises ValueError with detail dict if insufficient.
    """
    required = rate_cents_per_minute * min_balance_minutes
    pk = f"USER#{caller_user_id}"
    wallet = get_wallet_balance(T.billing, pk)
    actual = wallet["wallet_balance_cents"]
    if actual < required:
        raise ValueError({
            "code": "insufficient_balance",
            "required_cents": required,
            "current_balance_cents": actual,
            "rate_cents_per_minute": rate_cents_per_minute,
            "min_minutes": min_balance_minutes,
        })
    return {
        "wallet_balance_cents": actual,
        "required_cents": required,
    }


# ---------------------------------------------------------------------------
# Billing timer operations
# ---------------------------------------------------------------------------

def start_call_billing(
    *,
    call_id: str,
    rate_cents_per_min: int,
    caller_id: str,
    callee_id: str,
) -> None:
    """Initialize billing state on a call session record.

    Called when the call transitions to 'connected'.
    Updates the existing CallSessionRecord with billing fields.
    """
    from app.services.messaging_call_sessions import get_call_session

    session = get_call_session(call_id)
    if not session or not session.paid:
        return

    ts = now_ts()
    # Read the live platform fee from billing config (FIN-018 / GAP-0215),
    # falling back to the env-var default. Locked into the session record so
    # the rate is stable for the lifetime of the call.
    platform_fee_bps = get_fee_bps("call")

    table = _call_table()
    table.update_item(
        Key={"call_id": call_id},
        UpdateExpression=(
            "SET billing_start_ts = :bst, "
            "last_billed_ts = :lbt, "
            "platform_fee_bps = :pfb, "
            "billing_cycle_count = :zero, "
            "total_billed_cents = :zero, "
            "total_billed_seconds = :zero, "
            "caller_last_heartbeat_ts = :ts, "
            "callee_last_heartbeat_ts = :ts, "
            "billing_status = :active"
        ),
        ExpressionAttributeValues={
            ":bst": ts,
            ":lbt": ts,
            ":pfb": platform_fee_bps,
            ":zero": 0,
            ":ts": ts,
            ":active": "active",
        },
    )


def process_heartbeat(call_id: str, user_id: str) -> BillingTickResult:
    """Process a heartbeat from a participant and trigger billing if due.

    Returns billing tick result with current state.
    """
    from app.services.messaging_call_sessions import get_call_session

    session = get_call_session(call_id)
    if not session:
        return BillingTickResult(action="skip", reason="call_not_found")
    if not session.paid:
        return BillingTickResult(action="skip", reason="not_paid_call")
    if session.state != "connected":
        return BillingTickResult(action="skip", reason="not_connected")

    ts = now_ts()
    table = _call_table()

    # Update heartbeat timestamp for this participant
    if user_id == session.caller_user_id:
        table.update_item(
            Key={"call_id": call_id},
            UpdateExpression="SET caller_last_heartbeat_ts = :ts",
            ExpressionAttributeValues={":ts": ts},
        )
    elif user_id == session.callee_user_id:
        table.update_item(
            Key={"call_id": call_id},
            UpdateExpression="SET callee_last_heartbeat_ts = :ts",
            ExpressionAttributeValues={":ts": ts},
        )

    # Check max duration
    billing_start = session.billing_start_ts or session.connect_ts or session.start_ts
    elapsed_total = ts - billing_start
    max_dur = session.max_duration_seconds or (S.call_billing_max_rate_cents_per_min * 60)
    # Use a sensible default max duration if 0
    if max_dur <= 0:
        max_dur = 7200  # 2 hours default

    if elapsed_total >= max_dur:
        return BillingTickResult(action="end_call", reason="max_duration_reached")

    # Check if billing cycle is due
    last_billed = session.last_billed_ts or billing_start
    elapsed_since_last = ts - last_billed
    cycle_seconds = S.call_billing_cycle_seconds

    if elapsed_since_last < cycle_seconds:
        # Not time to bill yet — return current state
        pk = f"USER#{session.caller_user_id}"
        wallet = get_wallet_balance(T.billing, pk)
        balance = wallet["wallet_balance_cents"]
        rate = session.rate_cents_per_min
        mins_remaining = balance / rate if rate > 0 else 999
        return BillingTickResult(
            action="skip",
            total_cost_cents=session.total_billed_cents,
            balance_remaining=balance,
            next_bill_in=cycle_seconds - elapsed_since_last,
            minutes_remaining=mins_remaining,
            warn_low_balance=mins_remaining < 2,
            cycle_number=session.billing_cycle_count,
        )

    # Bill for full minutes elapsed since last billing
    full_minutes = elapsed_since_last // 60
    if full_minutes < 1:
        full_minutes = 1  # minimum 1 minute per cycle
    amount_cents = session.rate_cents_per_min * full_minutes

    if amount_cents <= 0:
        return BillingTickResult(action="skip")

    # Attempt wallet debit
    pk = f"USER#{session.caller_user_id}"
    try:
        new_balance = apply_wallet_delta(T.billing, pk, -amount_cents)
    except Exception:
        # Insufficient balance
        logger.warning(
            "call_billing_depleted",
            extra={"call_id": call_id, "caller": session.caller_user_id, "amount": amount_cents},
        )
        return BillingTickResult(action="end_call", reason="balance_depleted")

    # Calculate platform fee and creator credit. Prefer the rate locked into
    # the session at call-start; fall back to live billing config (GAP-0215).
    platform_fee_bps = session.platform_fee_bps or get_fee_bps("call")
    platform_fee_cents = (amount_cents * platform_fee_bps) // 10000
    creator_net_cents = amount_cents - platform_fee_cents
    new_cycle = session.billing_cycle_count + 1
    new_total = session.total_billed_cents + amount_cents
    new_billed_seconds = session.total_billed_seconds + (full_minutes * 60)

    # Credit creator
    _write_creator_credit(
        creator_user_id=session.callee_user_id,
        amount_cents=creator_net_cents,
        call_id=call_id,
        cycle=new_cycle,
    )

    # Write debit ledger entry for caller
    _write_caller_debit(
        caller_user_id=session.caller_user_id,
        amount_cents=amount_cents,
        call_id=call_id,
        cycle=new_cycle,
    )

    # Update billing state on the session
    table.update_item(
        Key={"call_id": call_id},
        UpdateExpression=(
            "SET last_billed_ts = :lbt, "
            "total_billed_cents = :tbc, "
            "total_billed_seconds = :tbs, "
            "billing_cycle_count = :bcc"
        ),
        ExpressionAttributeValues={
            ":lbt": ts,
            ":tbc": new_total,
            ":tbs": new_billed_seconds,
            ":bcc": new_cycle,
        },
    )

    logger.info(
        "call_billing_cycle",
        extra={
            "call_id": call_id,
            "cycle": new_cycle,
            "amount_cents": amount_cents,
            "balance_after": new_balance,
        },
    )

    rate = session.rate_cents_per_min
    mins_remaining = new_balance / rate if rate > 0 else 999

    return BillingTickResult(
        action="billed",
        amount_cents=amount_cents,
        total_cost_cents=new_total,
        balance_remaining=new_balance,
        warn_low_balance=mins_remaining < 2,
        minutes_remaining=mins_remaining,
        next_bill_in=cycle_seconds,
        cycle_number=new_cycle,
    )


def finalize_call_billing(call_id: str) -> FinalBillingResult:
    """Finalize billing on call end with pro-rated charge for partial minute."""
    from app.services.messaging_call_sessions import get_call_session

    session = get_call_session(call_id)
    if not session or not session.paid:
        return FinalBillingResult(total_cents=0)

    ts = now_ts()
    billing_start = session.billing_start_ts or session.connect_ts or session.start_ts
    duration = ts - billing_start if billing_start else 0

    last_billed = session.last_billed_ts or billing_start
    unbilled_seconds = ts - last_billed if last_billed else 0

    if unbilled_seconds <= 0:
        return FinalBillingResult(
            total_cents=session.total_billed_cents,
            duration_seconds=duration,
        )

    # Pro-rate: (rate / 60) * unbilled_seconds, rounded up
    rate = session.rate_cents_per_min
    pro_rated_cents = math.ceil((rate / 60) * unbilled_seconds)

    if pro_rated_cents <= 0:
        return FinalBillingResult(
            total_cents=session.total_billed_cents,
            duration_seconds=duration,
        )

    pk = f"USER#{session.caller_user_id}"
    actual_charge = pro_rated_cents

    try:
        apply_wallet_delta(T.billing, pk, -pro_rated_cents)
    except Exception:
        # Insufficient balance — debit whatever remains
        wallet = get_wallet_balance(T.billing, pk)
        balance = wallet["wallet_balance_cents"]
        if balance > 0:
            try:
                apply_wallet_delta(T.billing, pk, -balance)
                actual_charge = balance
            except Exception:
                actual_charge = 0
        else:
            actual_charge = 0

    if actual_charge > 0:
        # Credit creator (minus platform fee). Prefer the session-locked rate;
        # fall back to live billing config (GAP-0215).
        platform_fee_bps = session.platform_fee_bps or get_fee_bps("call")
        platform_fee = (actual_charge * platform_fee_bps) // 10000
        creator_net = actual_charge - platform_fee
        _write_creator_credit(
            creator_user_id=session.callee_user_id,
            amount_cents=creator_net,
            call_id=call_id,
            cycle="final",
        )
        _write_caller_debit(
            caller_user_id=session.caller_user_id,
            amount_cents=actual_charge,
            call_id=call_id,
            cycle="final",
        )

    # Update session billing totals
    total = session.total_billed_cents + actual_charge
    table = _call_table()
    table.update_item(
        Key={"call_id": call_id},
        UpdateExpression=(
            "SET total_billed_cents = :tbc, "
            "billing_status = :done"
        ),
        ExpressionAttributeValues={
            ":tbc": total,
            ":done": "finalized",
        },
    )

    logger.info(
        "call_billing_finalized",
        extra={
            "call_id": call_id,
            "total_cents": total,
            "duration_s": duration,
            "pro_rated_cents": actual_charge,
        },
    )

    return FinalBillingResult(
        total_cents=total,
        duration_seconds=duration,
        final_charge_cents=actual_charge,
    )


def get_call_billing_summary(call_id: str) -> Optional[Dict[str, Any]]:
    """Return billing totals for a call."""
    from app.services.messaging_call_sessions import get_call_session

    session = get_call_session(call_id)
    if not session:
        return None

    ts = now_ts()
    billing_start = session.billing_start_ts or session.connect_ts or session.start_ts
    elapsed = ts - billing_start if billing_start and session.state == "connected" else 0
    if session.state in ("ended", "failed", "canceled") and session.end_ts and billing_start:
        elapsed = session.end_ts - billing_start

    pk = f"USER#{session.caller_user_id}"
    wallet = get_wallet_balance(T.billing, pk)

    return {
        "call_id": call_id,
        "paid": session.paid,
        "rate_cents_per_minute": session.rate_cents_per_min,
        "total_cost_cents": session.total_billed_cents,
        "total_billed_seconds": session.total_billed_seconds,
        "billing_cycle_count": session.billing_cycle_count,
        "caller_balance_remaining_cents": wallet["wallet_balance_cents"],
        "platform_fee_bps": session.platform_fee_bps,
        "max_duration_seconds": session.max_duration_seconds,
        "elapsed_seconds": elapsed,
        "billing_status": session.billing_status or "",
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _call_table():
    return T.message_call_sessions


def _write_creator_credit(
    *,
    creator_user_id: str,
    amount_cents: int,
    call_id: str,
    cycle: int | str,
) -> None:
    """Write a credit ledger entry for the creator."""
    if amount_cents <= 0:
        return
    ts = now_ts()
    entry_id = uuid.uuid4().hex
    try:
        T.billing.put_item(Item={
            "pk": f"USER#{creator_user_id}",
            "sk": f"LEDGER#{ts}#{entry_id}",
            "entry_id": entry_id,
            "ts": ts,
            "type": "credit",
            "amount_cents": amount_cents,
            "currency": "USD",
            "state": "settled",
            "reason": "Private call earnings",
            "meta": {
                "call_id": call_id,
                "cycle": str(cycle),
                "creator_user_id": creator_user_id,
            },
        })
    except Exception:
        logger.warning(
            "call_billing_credit_failed",
            extra={"creator": creator_user_id, "call_id": call_id, "amount": amount_cents},
        )


def _write_caller_debit(
    *,
    caller_user_id: str,
    amount_cents: int,
    call_id: str,
    cycle: int | str,
) -> None:
    """Write a debit ledger entry for the caller."""
    if amount_cents <= 0:
        return
    ts = now_ts()
    entry_id = uuid.uuid4().hex
    try:
        T.billing.put_item(Item={
            "pk": f"USER#{caller_user_id}",
            "sk": f"LEDGER#{ts}#{entry_id}",
            "entry_id": entry_id,
            "ts": ts,
            "type": "debit",
            "amount_cents": amount_cents,
            "currency": "USD",
            "state": "settled",
            "reason": "Private call",
            "meta": {
                "call_id": call_id,
                "cycle": str(cycle),
                "caller_user_id": caller_user_id,
            },
        })
    except Exception:
        logger.warning(
            "call_billing_debit_failed",
            extra={"caller": caller_user_id, "call_id": call_id, "amount": amount_cents},
        )
