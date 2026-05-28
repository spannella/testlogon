"""Call billing endpoints for pay-per-minute calls (CALL-011).

Endpoints:
  GET  /ui/calls/rates/{creator_id}  - Get creator's per-minute call rate
  POST /ui/calls/rates               - Set own call rate (creator)
  PUT  /ui/calls/rates               - Update own call rate
  DELETE /ui/calls/rates             - Disable paid calls (delete rate)
  PATCH /messaging/messages/calls/{call_id}/heartbeat - Billing heartbeat
  GET   /messaging/messages/calls/{call_id}/billing   - Billing summary
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.services.sessions import require_ui_session
from app.core.settings import S

router = APIRouter()


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class CallRateIn(BaseModel):
    rate_cents_per_minute: int = Field(..., ge=100, le=10000)
    enabled: bool = True
    min_balance_minutes: int = Field(default=5, ge=1, le=60)
    max_duration_minutes: int = Field(default=120, ge=1, le=480)


class CallRateOut(BaseModel):
    rate_cents_per_minute: int
    enabled: bool
    currency: str = "USD"
    min_balance_minutes: int
    max_duration_minutes: int


class HeartbeatIn(BaseModel):
    client_ts: Optional[int] = None


class HeartbeatOut(BaseModel):
    call_id: str
    elapsed_seconds: int = 0
    total_cost_cents: int = 0
    balance_remaining_cents: int = 0
    rate_cents_per_minute: int = 0
    next_bill_in_seconds: int = 0
    warn_low_balance: bool = False
    minutes_remaining: float = 0
    max_duration_warning: bool = False
    action: str = "ok"


class CallBillingStatusOut(BaseModel):
    call_id: str
    paid: bool
    rate_cents_per_minute: int = 0
    total_cost_cents: int = 0
    total_billed_seconds: int = 0
    billing_cycle_count: int = 0
    caller_balance_remaining_cents: int = 0
    platform_fee_bps: int = 0
    max_duration_seconds: int = 0
    elapsed_seconds: int = 0
    billing_status: str = ""


# ---------------------------------------------------------------------------
# Rate endpoints
# ---------------------------------------------------------------------------

@router.get("/ui/calls/rates/{creator_id}", response_model=CallRateOut)
async def get_creator_rate(
    creator_id: str,
    session=Depends(require_ui_session),
):
    """Get a creator's per-minute call rate."""
    from app.services.call_billing_timer import get_call_rate

    rate = get_call_rate(creator_id)
    if not rate:
        raise HTTPException(404, detail={"code": "rate_not_found", "message": "Creator has not set a call rate"})
    return CallRateOut(
        rate_cents_per_minute=rate.rate_cents_per_minute,
        enabled=rate.enabled,
        currency=rate.currency,
        min_balance_minutes=rate.min_balance_minutes,
        max_duration_minutes=rate.max_duration_minutes,
    )


@router.post("/ui/calls/rates", response_model=CallRateOut)
async def set_own_rate(
    body: CallRateIn,
    session=Depends(require_ui_session),
):
    """Set or create own call rate (creator)."""
    from app.services.call_billing_timer import set_call_rate

    user_id = session["user_sub"]
    rate = set_call_rate(
        user_id=user_id,
        rate_cents_per_minute=body.rate_cents_per_minute,
        enabled=body.enabled,
        min_balance_minutes=body.min_balance_minutes,
        max_duration_minutes=body.max_duration_minutes,
    )
    return CallRateOut(
        rate_cents_per_minute=rate.rate_cents_per_minute,
        enabled=rate.enabled,
        currency=rate.currency,
        min_balance_minutes=rate.min_balance_minutes,
        max_duration_minutes=rate.max_duration_minutes,
    )


@router.put("/ui/calls/rates", response_model=CallRateOut)
async def update_own_rate(
    body: CallRateIn,
    session=Depends(require_ui_session),
):
    """Update own call rate (same as set)."""
    return await set_own_rate(body, session)


@router.delete("/ui/calls/rates")
async def delete_own_rate(
    session=Depends(require_ui_session),
):
    """Disable paid calls by deleting rate."""
    from app.services.call_billing_timer import delete_call_rate

    user_id = session["user_sub"]
    delete_call_rate(user_id)
    return {"ok": True}


# ---------------------------------------------------------------------------
# Heartbeat endpoint
# ---------------------------------------------------------------------------

@router.patch("/messaging/messages/calls/{call_id}/heartbeat", response_model=HeartbeatOut)
async def call_heartbeat(
    call_id: str,
    body: HeartbeatIn = HeartbeatIn(),
    session=Depends(require_ui_session),
):
    """Process a billing heartbeat for a paid call."""
    if not S.call_billing_enabled:
        raise HTTPException(400, detail={"code": "feature_disabled", "message": "Paid calls are not enabled"})

    from app.services.messaging_call_sessions import get_call_session
    from app.services.call_billing_timer import process_heartbeat
    from app.core.time import now_ts

    user_id = session["user_sub"]
    call = get_call_session(call_id)
    if not call:
        raise HTTPException(404, detail={"code": "call_not_found", "message": "Call not found"})
    if user_id not in {call.caller_user_id, call.callee_user_id}:
        raise HTTPException(403, detail={"code": "forbidden", "message": "Not a call participant"})
    if call.state != "connected":
        raise HTTPException(409, detail={"code": "invalid_state", "message": "Call is not connected"})
    if not call.paid:
        raise HTTPException(400, detail={"code": "not_paid_call", "message": "This is not a paid call"})

    result = process_heartbeat(call_id, user_id)

    # If billing says to end the call, do it
    if result.action == "end_call":
        try:
            from app.services.messaging_call_lifecycle import end_call
            end_call(
                call_id=call_id,
                actor_user_id="system",
                reason=result.reason or "balance_depleted",
            )
        except Exception:
            pass
        raise HTTPException(402, detail={
            "code": "balance_depleted",
            "message": "Insufficient balance",
            "reason": result.reason or "balance_depleted",
        })

    billing_start = call.billing_start_ts or call.connect_ts or call.start_ts
    elapsed = now_ts() - billing_start if billing_start else 0
    max_dur = call.max_duration_seconds or 7200
    max_dur_warning = (max_dur - elapsed) < 300 if elapsed > 0 else False

    return HeartbeatOut(
        call_id=call_id,
        elapsed_seconds=elapsed,
        total_cost_cents=result.total_cost_cents,
        balance_remaining_cents=result.balance_remaining,
        rate_cents_per_minute=call.rate_cents_per_min,
        next_bill_in_seconds=result.next_bill_in,
        warn_low_balance=result.warn_low_balance,
        minutes_remaining=result.minutes_remaining,
        max_duration_warning=max_dur_warning,
        action=result.action,
    )


# ---------------------------------------------------------------------------
# Billing summary endpoint
# ---------------------------------------------------------------------------

@router.get("/messaging/messages/calls/{call_id}/billing", response_model=CallBillingStatusOut)
async def get_call_billing(
    call_id: str,
    session=Depends(require_ui_session),
):
    """Get billing summary for a call."""
    from app.services.messaging_call_sessions import get_call_session
    from app.services.call_billing_timer import get_call_billing_summary

    user_id = session["user_sub"]
    call = get_call_session(call_id)
    if not call:
        raise HTTPException(404, detail={"code": "call_not_found", "message": "Call not found"})
    if user_id not in {call.caller_user_id, call.callee_user_id}:
        raise HTTPException(403, detail={"code": "forbidden", "message": "Not a call participant"})

    summary = get_call_billing_summary(call_id)
    if not summary:
        raise HTTPException(404, detail={"code": "call_not_found", "message": "Call not found"})

    return CallBillingStatusOut(
        call_id=summary["call_id"],
        paid=summary["paid"],
        rate_cents_per_minute=summary["rate_cents_per_minute"],
        total_cost_cents=summary["total_cost_cents"],
        total_billed_seconds=summary["total_billed_seconds"],
        billing_cycle_count=summary["billing_cycle_count"],
        caller_balance_remaining_cents=summary["caller_balance_remaining_cents"],
        platform_fee_bps=summary["platform_fee_bps"],
        max_duration_seconds=summary["max_duration_seconds"],
        elapsed_seconds=summary["elapsed_seconds"],
        billing_status=summary.get("billing_status", ""),
    )
