"""KYC-019 — Case Assignment & Workload Management router.

All endpoints are admin-or-root gated via ``require_admin_or_root``; SLA config
mutation additionally requires root. New logic lives entirely in
``app/services/kyc_case_assignment.py`` — this router is a thin HTTP layer.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root
from app.auth.roles import Role, normalize_role
from app.models import (
    KycAdminAvailabilityIn,
    KycAdminAvailabilityOut,
    KycAssignmentHistoryOut,
    KycAutoAssignBatchIn,
    KycAutoAssignBatchOut,
    KycAutoAssignIn,
    KycAutoAssignOut,
    KycClaimOut,
    KycEscalateOut,
    KycMyAssignedOut,
    KycReassignIn,
    KycReassignOut,
    KycSlaBreachListOut,
    KycSlaConfigEnvelope,
    KycSlaConfigOut,
    KycSlaConfigUpdateIn,
    KycWorkloadDashboardOut,
)
from app.services.kyc_case_assignment import (
    ASSIGNMENT_SERVICE,
    KycCaseAssignmentError,
)

router = APIRouter(prefix="/v1/kyc/assignment", tags=["kyc-assignment"])


def _raise(exc: KycCaseAssignmentError) -> None:
    raise HTTPException(
        status_code=exc.status_code,
        detail={"code": exc.code, "message": exc.message},
    )


def _require_root(user: AuthenticatedUser) -> None:
    if normalize_role(user.role) is not Role.ROOT:
        raise HTTPException(
            status_code=403,
            detail={"code": "forbidden", "message": "Root session required"},
        )


# ── Auto-assignment ─────────────────────────────────────────────────


@router.post("/cases/{case_id}/auto-assign", response_model=KycAutoAssignOut)
def auto_assign_case(
    case_id: str,
    body: KycAutoAssignIn | None = None,
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    language = (body.applicant_language if body else "en") or "en"
    try:
        result = ASSIGNMENT_SERVICE.auto_assign(
            case_id=case_id, applicant_language=language, actor_sub=user.sub
        )
    except KycCaseAssignmentError as exc:
        _raise(exc)
    return KycAutoAssignOut.model_validate(result)


@router.post("/auto-assign-batch", response_model=KycAutoAssignBatchOut)
def auto_assign_batch(
    body: KycAutoAssignBatchIn,
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    results = ASSIGNMENT_SERVICE.auto_assign_batch(
        case_ids=body.case_ids, applicant_language=body.applicant_language, actor_sub=user.sub
    )
    return KycAutoAssignBatchOut(results=results)


# ── Manual (re)assign / claim ───────────────────────────────────────


@router.post("/cases/{case_id}/reassign", response_model=KycReassignOut)
def reassign_case(
    case_id: str,
    body: KycReassignIn,
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    try:
        result = ASSIGNMENT_SERVICE.manual_reassign(
            case_id=case_id,
            new_admin_sub=body.new_admin_sub,
            reason=body.reason,
            actor_sub=user.sub,
        )
    except KycCaseAssignmentError as exc:
        _raise(exc)
    return KycReassignOut.model_validate(result)


@router.post("/cases/{case_id}/claim", response_model=KycClaimOut)
def claim_case(
    case_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    try:
        result = ASSIGNMENT_SERVICE.claim(case_id=case_id, admin_sub=user.sub)
    except KycCaseAssignmentError as exc:
        _raise(exc)
    return KycClaimOut.model_validate(result)


@router.post("/cases/{case_id}/unclaim", response_model=KycClaimOut)
def unclaim_case(
    case_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    try:
        result = ASSIGNMENT_SERVICE.unclaim(case_id=case_id, admin_sub=user.sub)
    except KycCaseAssignmentError as exc:
        _raise(exc)
    return KycClaimOut.model_validate(result)


@router.get("/my-queue", response_model=KycMyAssignedOut)
def list_my_queue(user: AuthenticatedUser = Depends(require_admin_or_root)):
    cases = ASSIGNMENT_SERVICE.list_my_assigned(admin_sub=user.sub)
    return KycMyAssignedOut(cases=cases)


@router.get("/cases/{case_id}/history", response_model=KycAssignmentHistoryOut)
def assignment_history(
    case_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    events = ASSIGNMENT_SERVICE.get_assignment_history(case_id=case_id)
    return KycAssignmentHistoryOut(events=events)


# ── Admin availability ──────────────────────────────────────────────


@router.get("/availability", response_model=KycAdminAvailabilityOut)
def get_my_availability(user: AuthenticatedUser = Depends(require_admin_or_root)):
    avail = ASSIGNMENT_SERVICE.get_admin_availability(user.sub)
    return KycAdminAvailabilityOut.model_validate(avail.to_dict())


@router.patch("/availability", response_model=KycAdminAvailabilityOut)
def set_my_availability(
    body: KycAdminAvailabilityIn,
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    avail = ASSIGNMENT_SERVICE.set_admin_availability(
        admin_sub=user.sub,
        on_duty=body.on_duty,
        expertise_tiers=body.expertise_tiers,
        languages=body.languages,
        max_cases=body.max_cases,
        seniority_level=body.seniority_level,
    )
    return KycAdminAvailabilityOut.model_validate(avail.to_dict())


# ── Workload dashboard ──────────────────────────────────────────────


@router.get("/workloads", response_model=KycWorkloadDashboardOut)
def workload_dashboard(user: AuthenticatedUser = Depends(require_admin_or_root)):
    return KycWorkloadDashboardOut.model_validate(ASSIGNMENT_SERVICE.workload_dashboard())


# ── SLA compliance + escalation ─────────────────────────────────────


@router.get("/sla/breaches", response_model=KycSlaBreachListOut)
def sla_breaches(user: AuthenticatedUser = Depends(require_admin_or_root)):
    breaches = ASSIGNMENT_SERVICE.check_sla_compliance()
    return KycSlaBreachListOut(breaches=breaches)


@router.post("/cases/{case_id}/escalate", response_model=KycEscalateOut)
def escalate_case(
    case_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    case = ASSIGNMENT_SERVICE._get_case(case_id)
    current_level = int((case.get("review") or {}).get("escalation_level") or 0) if case else 0
    try:
        result = ASSIGNMENT_SERVICE.escalate_case(
            case_id=case_id,
            current_level=current_level,
            reason="Manual escalation by admin",
        )
    except KycCaseAssignmentError as exc:
        _raise(exc)
    return KycEscalateOut.model_validate(result)


# ── SLA configuration (root only) ───────────────────────────────────


@router.get("/sla-config", response_model=KycSlaConfigEnvelope)
def get_sla_config(user: AuthenticatedUser = Depends(require_admin_or_root)):
    return KycSlaConfigEnvelope(sla_config=ASSIGNMENT_SERVICE.get_sla_config())


@router.patch("/sla-config/{tier}", response_model=KycSlaConfigOut)
def update_sla_config(
    tier: str,
    body: KycSlaConfigUpdateIn,
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    _require_root(user)
    try:
        result = ASSIGNMENT_SERVICE.update_sla_config(
            tier=tier,
            target_hours=body.target_hours,
            warning_pct=body.warning_pct,
            actor_sub=user.sub,
        )
    except KycCaseAssignmentError as exc:
        _raise(exc)
    return KycSlaConfigOut.model_validate(result)
