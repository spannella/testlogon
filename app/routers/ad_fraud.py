"""Ad fraud prevention — admin review dashboard endpoints (ADS-014).

All endpoints are admin/root gated. They expose flagged ad-fraud events,
per-account risk scores, platform summary stats, manual confirm/dismiss of
flagged events, and manual account suspension/unsuspension.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root
from app.models import AdFraudReviewIn, AdFraudSuspendIn
from app.services import ad_fraud_prevention as fraud

ad_fraud_router = APIRouter(prefix="/ui/ads/fraud", tags=["ad-fraud"])


@ad_fraud_router.get("/events")
async def list_fraud_events_endpoint(
    date: str = Query(default=""),
    limit: int = Query(default=100, ge=1, le=1000),
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    return fraud.list_fraud_events(date=date, limit=limit)


@ad_fraud_router.get("/events/{event_id}")
async def get_fraud_event_endpoint(
    event_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    ev = fraud.get_fraud_event(event_id)
    if not ev:
        raise HTTPException(status_code=404, detail="Fraud event not found")
    return ev


@ad_fraud_router.post("/events/{event_id}/review")
async def review_fraud_event_endpoint(
    event_id: str,
    body: AdFraudReviewIn,
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    result = fraud.review_fraud_event(
        event_id=event_id, decision=body.decision, actor=user.sub
    )
    if not result:
        raise HTTPException(status_code=404, detail="Fraud event not found")
    return result


@ad_fraud_router.get("/summary")
async def fraud_summary_endpoint(
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    return fraud.get_fraud_summary()


@ad_fraud_router.get("/accounts")
async def list_account_risk_endpoint(
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    return fraud.get_account_risk_scores()


@ad_fraud_router.get("/accounts/{account_id}")
async def get_account_risk_endpoint(
    account_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    risk = fraud.get_account_risk(account_id)
    events = fraud.list_fraud_events_for_account(account_id, limit=50)
    return {**risk, "recent_events": events}


@ad_fraud_router.post("/accounts/{account_id}/suspend")
async def suspend_account_endpoint(
    account_id: str,
    body: AdFraudSuspendIn,
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    return fraud.suspend_account(
        account_id=account_id, actor=user.sub, reason=body.reason
    )


@ad_fraud_router.post("/accounts/{account_id}/unsuspend")
async def unsuspend_account_endpoint(
    account_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    return fraud.unsuspend_account(account_id=account_id, actor=user.sub)
