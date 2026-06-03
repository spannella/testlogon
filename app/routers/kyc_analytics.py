"""KYC Analytics & Funnel Dashboard router (KYC-024).

Admin-gated, read-only analytics endpoints over the ``kyc_cases`` table.
Auth pattern mirrors ``app/routers/kyc_cases.py``: ``require_ui_session`` plus a
manual ``ADMIN``/``ROOT`` role check.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.auth.roles import Role, normalize_role
from app.core.settings import S
from app.models import (
    AnalyticsSnapshotOut,
    CompareResponse,
    CountryStatsOut,
    DeltasOut,
    DropOffResponse,
    DropOffStepOut,
    FunnelResponse,
    FunnelStepOut,
    GeographicResponse,
    HistogramBucketOut,
    PercentilesOut,
    ProcessingTimesResponse,
    RejectionReasonsResponse,
    ScreeningHitPointOut,
    ScreeningHitsResponse,
    SnapshotResponse,
    TrendPointOut,
    TrendsResponse,
)
from app.services.alerts import audit_event
from app.services.kyc_analytics import ANALYTICS_SERVICE, AnalyticsSnapshot
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/v1/kyc/analytics", tags=["kyc-analytics"])


def _require_admin(user: AuthenticatedUser, request: Request) -> None:
    if normalize_role(user.role) not in {Role.ADMIN, Role.ROOT}:
        audit_event(
            "kyc_analytics_denied",
            user.sub,
            request,
            outcome="failure",
            reason="admin_role_required",
        )
        raise HTTPException(status_code=403, detail={"code": "admin_required", "message": "Admin access required to view KYC analytics."})


def _validate_range(frm: int, to: int) -> None:
    if frm > to:
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_date_range", "message": "Start date must be before end date."},
        )


def _validate_periods(periods: int) -> None:
    if periods > int(S.kyc_analytics_trend_max_periods):
        raise HTTPException(
            status_code=400,
            detail={
                "code": "max_periods_exceeded",
                "message": f"Maximum {S.kyc_analytics_trend_max_periods} periods allowed.",
            },
        )


def _snapshot_to_out(snap: AnalyticsSnapshot) -> AnalyticsSnapshotOut:
    return AnalyticsSnapshotOut(
        period_start=snap.period_start,
        period_end=snap.period_end,
        total_applications=snap.total_applications,
        approved_count=snap.approved_count,
        rejected_count=snap.rejected_count,
        pending_count=snap.pending_count,
        conversion_rate=snap.conversion_rate,
        avg_processing_hours=snap.avg_processing_hours,
        processing_time_distribution=PercentilesOut(**snap.processing_time_distribution),
        funnel=[FunnelStepOut(**vars(s)) for s in snap.funnel],
        rejection_reasons=snap.rejection_reasons,
        geographic_distribution=[CountryStatsOut(**c) for c in snap.geographic_distribution],
        tier_breakdown=snap.tier_breakdown,
    )


@router.get("/funnel", response_model=FunnelResponse)
def get_funnel(
    request: Request,
    frm: int = Query(default=0, alias="from", ge=0),
    to: int = Query(default=9999999999, ge=0),
    country: str | None = Query(default=None),
    tier: str | None = Query(default=None),
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
) -> FunnelResponse:
    _require_admin(user, request)
    _validate_range(frm, to)
    funnel = ANALYTICS_SERVICE.compute_funnel(
        period_start=frm, period_end=to, country=country, tier=tier
    )
    return FunnelResponse(
        funnel=[FunnelStepOut(**vars(s)) for s in funnel],
        conversion_rate=ANALYTICS_SERVICE.conversion_rate(funnel),
    )


@router.get("/snapshot", response_model=SnapshotResponse)
def get_snapshot(
    request: Request,
    frm: int = Query(default=0, alias="from", ge=0),
    to: int = Query(default=9999999999, ge=0),
    country: str | None = Query(default=None),
    tier: str | None = Query(default=None),
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
) -> SnapshotResponse:
    _require_admin(user, request)
    _validate_range(frm, to)
    snap = ANALYTICS_SERVICE.compute_snapshot(
        period_start=frm, period_end=to, country=country, tier=tier
    )
    return SnapshotResponse(snapshot=_snapshot_to_out(snap))


@router.get("/trends", response_model=TrendsResponse)
def get_trends(
    request: Request,
    granularity: str = Query(default="daily", pattern=r"^(daily|weekly|monthly)$"),
    periods: int = Query(default=7, ge=1),
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
) -> TrendsResponse:
    _require_admin(user, request)
    _validate_periods(periods)
    trends = ANALYTICS_SERVICE.get_volume_trends(granularity=granularity, periods=periods)
    return TrendsResponse(trends=[TrendPointOut(**t) for t in trends])


@router.get("/processing-times", response_model=ProcessingTimesResponse)
def get_processing_times(
    request: Request,
    frm: int = Query(default=0, alias="from", ge=0),
    to: int = Query(default=9999999999, ge=0),
    bucket_hours: int = Query(default=4, ge=1, le=24),
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
) -> ProcessingTimesResponse:
    _require_admin(user, request)
    _validate_range(frm, to)
    result = ANALYTICS_SERVICE.get_processing_time_histogram(
        period_start=frm, period_end=to, bucket_hours=bucket_hours
    )
    return ProcessingTimesResponse(
        histogram=[HistogramBucketOut(**b) for b in result["histogram"]],
        percentiles=PercentilesOut(**result["percentiles"]),
    )


@router.get("/rejection-reasons", response_model=RejectionReasonsResponse)
def get_rejection_reasons(
    request: Request,
    frm: int = Query(default=0, alias="from", ge=0),
    to: int = Query(default=9999999999, ge=0),
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
) -> RejectionReasonsResponse:
    _require_admin(user, request)
    _validate_range(frm, to)
    reasons = ANALYTICS_SERVICE.get_rejection_reasons(period_start=frm, period_end=to)
    return RejectionReasonsResponse(reasons=reasons)


@router.get("/screening-hits", response_model=ScreeningHitsResponse)
def get_screening_hits(
    request: Request,
    granularity: str = Query(default="daily", pattern=r"^(daily|weekly|monthly)$"),
    periods: int = Query(default=7, ge=1),
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
) -> ScreeningHitsResponse:
    _require_admin(user, request)
    _validate_periods(periods)
    trends = ANALYTICS_SERVICE.get_screening_hit_trends(granularity=granularity, periods=periods)
    return ScreeningHitsResponse(trends=[ScreeningHitPointOut(**t) for t in trends])


@router.get("/geographic", response_model=GeographicResponse)
def get_geographic(
    request: Request,
    frm: int = Query(default=0, alias="from", ge=0),
    to: int = Query(default=9999999999, ge=0),
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
) -> GeographicResponse:
    _require_admin(user, request)
    _validate_range(frm, to)
    countries = ANALYTICS_SERVICE.get_geographic_distribution(period_start=frm, period_end=to)
    return GeographicResponse(countries=[CountryStatsOut(**c) for c in countries])


@router.get("/drop-off", response_model=DropOffResponse)
def get_drop_off(
    request: Request,
    frm: int = Query(default=0, alias="from", ge=0),
    to: int = Query(default=9999999999, ge=0),
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
) -> DropOffResponse:
    _require_admin(user, request)
    _validate_range(frm, to)
    steps = ANALYTICS_SERVICE.get_drop_off_analysis(period_start=frm, period_end=to)
    return DropOffResponse(steps=[DropOffStepOut(**s) for s in steps])


@router.get("/compare", response_model=CompareResponse)
def compare_periods(
    request: Request,
    current_from: int = Query(..., ge=0),
    current_to: int = Query(..., ge=0),
    previous_from: int = Query(..., ge=0),
    previous_to: int = Query(..., ge=0),
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
) -> CompareResponse:
    _require_admin(user, request)
    _validate_range(current_from, current_to)
    _validate_range(previous_from, previous_to)
    result = ANALYTICS_SERVICE.compare_periods(
        current_start=current_from,
        current_end=current_to,
        previous_start=previous_from,
        previous_end=previous_to,
    )
    return CompareResponse(
        current=_snapshot_to_out(result["current"]),
        previous=_snapshot_to_out(result["previous"]),
        deltas=DeltasOut(**result["deltas"]),
    )
