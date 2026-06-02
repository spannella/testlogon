"""KYC Ongoing Monitoring & Periodic Review — router endpoints (KYC-016)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root
from app.models import (
    KycCompleteReviewRequest,
    KycMonitoringDashboardEnvelope,
    KycRescreeningResult,
    KycReviewCheckResult,
    KycReviewScheduleEnvelope,
    KycTriggerEventListEnvelope,
    KycTriggerEventRequest,
)
from app.services.kyc_monitoring import (
    complete_review,
    create_trigger_event,
    get_monitoring_dashboard,
    get_review_schedule,
    list_trigger_events,
    run_rescreening,
    run_review_checker,
)
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/v1/kyc/monitoring", tags=["kyc-monitoring"])


# ── User endpoints ──────────────────────────────────────────────────────────


@router.get("/schedule", response_model=KycReviewScheduleEnvelope)
async def get_my_schedule(ctx: dict = Depends(require_ui_session)):
    schedule = get_review_schedule(ctx["user_sub"])
    return KycReviewScheduleEnvelope(schedule=schedule)


@router.get("/triggers", response_model=KycTriggerEventListEnvelope)
async def list_my_triggers(ctx: dict = Depends(require_ui_session)):
    events = list_trigger_events(ctx["user_sub"])
    return KycTriggerEventListEnvelope(events=events)


# ── Admin endpoints ─────────────────────────────────────────────────────────


@router.get("/admin/dashboard", response_model=KycMonitoringDashboardEnvelope)
async def admin_dashboard(user: AuthenticatedUser = Depends(require_admin_or_root)):
    return KycMonitoringDashboardEnvelope(**get_monitoring_dashboard())


@router.post("/admin/review-check", response_model=KycReviewCheckResult)
async def admin_run_review_check(
    dry_run: bool = Query(False),
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    return KycReviewCheckResult(**run_review_checker(dry_run=dry_run))


@router.post("/admin/rescreening", response_model=KycRescreeningResult)
async def admin_run_rescreening(
    dry_run: bool = Query(False),
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    return KycRescreeningResult(**run_rescreening(dry_run=dry_run))


@router.get("/admin/{user_sub}/schedule", response_model=KycReviewScheduleEnvelope)
async def admin_get_user_schedule(
    user_sub: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    return KycReviewScheduleEnvelope(schedule=get_review_schedule(user_sub))


@router.post("/admin/{user_sub}/trigger")
async def admin_trigger_review(
    user_sub: str,
    body: KycTriggerEventRequest,
    request: Request,
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    return create_trigger_event(
        user_sub=user_sub,
        trigger_type="manual",
        details={"reason": body.reason},
        actor_sub=user.sub,
        request=request,
    )


@router.post("/admin/{user_sub}/complete-review", response_model=KycReviewScheduleEnvelope)
async def admin_complete_review(
    user_sub: str,
    body: KycCompleteReviewRequest,
    request: Request,
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    try:
        item = complete_review(
            user_sub=user_sub,
            new_risk_tier=body.new_risk_tier,
            case_id=body.case_id,
            admin_sub=user.sub,
            request=request,
        )
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
    return KycReviewScheduleEnvelope(schedule=item)
