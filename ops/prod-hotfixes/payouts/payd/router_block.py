

# ===========================================================================
# PAY-D (PAY-30..34): scheduled runner trigger + lifecycle fail/return +
# manual hold place/release + provider webhook seam. All admin/root gated
# except the provider webhook (which is guarded by a shared secret when set).
# ===========================================================================

import os as _payd_os

from fastapi import APIRouter as _APIRouter, Request as _Request

from app.services.creator_payouts import (
    fail_payout as _fail_payout,
    place_payout_hold as _place_payout_hold,
    release_payout_hold as _release_payout_hold,
    run_payout_sweep as _run_payout_sweep,
    handle_payout_provider_webhook as _handle_payout_provider_webhook,
)

# Admin runner trigger lives under /ui/admin/payouts (mirrors the subscriptions
# run-renewals admin trigger); the fail/return/hold endpoints extend the existing
# /v1/admin/payouts admin router below.
payd_admin_router = _APIRouter(prefix="/ui/admin/payouts", tags=["admin-payouts"])
# Provider webhook is NOT admin-gated (it is called by Stripe/PayPal); a shared
# secret gate is enforced when PAYOUT_WEBHOOK_SECRET is configured.
payd_webhook_router = _APIRouter(prefix="/v1/payouts", tags=["payouts-webhook"])


@payd_admin_router.post("/run")
def admin_run_payout_sweep(
    limit: int = Query(default=1000, ge=1, le=5000),
    now_override: Optional[int] = Query(default=None),
    payout_id: Optional[str] = Query(default=None),
    admin: AuthenticatedUser = Depends(require_admin_or_root),
):
    """PAY-30: drive one payout runner sweep now. ``now_override`` (unix ts) lets a
    verifier fast-forward past a retry backoff; ``payout_id`` restricts to one
    payout. Returns the sweep action summary."""
    return _run_payout_sweep(now=now_override, limit=limit, payout_id=payout_id)


@router.post("/{payout_id}/fail", response_model=PayoutActionOut)
def fail_payout_request(
    payout_id: str,
    reason: str = "",
    admin: AuthenticatedUser = Depends(require_admin_or_root),
):
    """PAY-31: fail a payout and REVERSE its debit if it was already paid (funds
    return to the creator balance). Idempotent."""
    try:
        result = _fail_payout(payout_id, reason=reason, returned=False)
    except LookupError:
        raise HTTPException(status_code=404, detail="Payout not found")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return PayoutActionOut(ok=True, payout_id=result["payout_id"], status=result["status"])


@router.post("/{payout_id}/return", response_model=PayoutActionOut)
def return_payout_request(
    payout_id: str,
    reason: str = "",
    admin: AuthenticatedUser = Depends(require_admin_or_root),
):
    """PAY-31: mark a paid payout RETURNED (provider bounce) and reverse its debit
    so the funds return to the creator balance. Idempotent."""
    try:
        result = _fail_payout(payout_id, reason=reason, returned=True)
    except LookupError:
        raise HTTPException(status_code=404, detail="Payout not found")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return PayoutActionOut(ok=True, payout_id=result["payout_id"], status=result["status"])


@router.post("/{payout_id}/hold", response_model=PayoutActionOut)
def hold_payout_request(
    payout_id: str,
    reason: str = "",
    admin: AuthenticatedUser = Depends(require_admin_or_root),
):
    """PAY-32: place a manual hold; the runner SKIPS a held payout until released."""
    try:
        result = _place_payout_hold(payout_id, admin.sub, reason=reason)
    except LookupError:
        raise HTTPException(status_code=404, detail="Payout not found")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return PayoutActionOut(ok=True, payout_id=result["payout_id"], status=result["status"])


@router.post("/{payout_id}/release-hold", response_model=PayoutActionOut)
def release_payout_hold_request(
    payout_id: str,
    admin: AuthenticatedUser = Depends(require_admin_or_root),
):
    """PAY-32: release a manual hold so the runner may process the payout again."""
    try:
        result = _release_payout_hold(payout_id, admin.sub)
    except LookupError:
        raise HTTPException(status_code=404, detail="Payout not found")
    return PayoutActionOut(ok=True, payout_id=result["payout_id"], status=result["status"])


@payd_webhook_router.post("/webhook")
async def payout_provider_webhook(request: _Request):
    """PAY-31 seam: consume a provider payout webhook (returned/failed) -> reverse
    the debit / fail the payout. Guarded by PAYOUT_WEBHOOK_SECRET when configured."""
    secret = _payd_os.environ.get("PAYOUT_WEBHOOK_SECRET", "")
    if secret:
        supplied = request.headers.get("X-Payout-Webhook-Secret", "")
        if supplied != secret:
            raise HTTPException(status_code=401, detail="invalid_webhook_secret")
    try:
        body = await request.json()
    except Exception:
        body = {}
    event = str(body.get("event") or body.get("type") or "")
    payout_id = str(body.get("payout_id") or body.get("id") or "")
    reason = str(body.get("reason") or "")
    try:
        result = _handle_payout_provider_webhook(event, payout_id, reason=reason)
    except LookupError:
        raise HTTPException(status_code=404, detail="Payout not found")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"ok": True, "payout_id": result["payout_id"], "status": result["status"]}
