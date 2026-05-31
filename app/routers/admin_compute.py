"""Admin Compute Dashboard router (INFRA-012).

Cross-user compute visibility, platform spending, force-terminate, and quotas.

Auth:
  - Listing / spending / stats / force-terminate / quota view: require_admin_or_root
  - Quota set/delete: require_root (prevents admins escalating their own quotas)
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root, require_root
from app.core.settings import S
from app.models import (
    AdminInstanceListOut,
    AdminPodListOut,
    ForceTerminateIn,
    InstanceTypeStatsOut,
    PerUserSpendingOut,
    PlatformSpendingOut,
    QuotaOut,
    SetQuotaIn,
)
from app.services import admin_compute
from app.services.ec2_launcher import InstanceNotFound, InvalidInstanceState
from app.services.k8s_launcher import PodAlreadyTerminated, PodNotFound

router = APIRouter(prefix="/v1/admin/compute", tags=["admin-compute"])


def _check_enabled() -> None:
    if not S.admin_compute_dashboard_enabled:
        raise HTTPException(status_code=404, detail="Admin compute dashboard disabled")


# ---------------------------------------------------------------------------
# Cross-user listing
# ---------------------------------------------------------------------------

@router.get("/instances", response_model=AdminInstanceListOut)
async def list_instances(
    status: Optional[str] = Query(default=None),
    user_sub: Optional[str] = Query(default=None),
    instance_type: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    cursor: Optional[str] = Query(default=None),
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    _check_enabled()
    return admin_compute.list_all_instances(
        status=status,
        user_sub=user_sub,
        instance_type=instance_type,
        limit=limit,
        cursor=cursor,
    )


@router.get("/pods", response_model=AdminPodListOut)
async def list_pods(
    status: Optional[str] = Query(default=None),
    user_sub: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    cursor: Optional[str] = Query(default=None),
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    _check_enabled()
    return admin_compute.list_all_pods(
        status=status,
        user_sub=user_sub,
        limit=limit,
        cursor=cursor,
    )


# ---------------------------------------------------------------------------
# Force-terminate
# ---------------------------------------------------------------------------

@router.post("/instances/{user_sub}/{instance_id}/terminate")
async def force_terminate_instance(
    user_sub: str,
    instance_id: str,
    body: ForceTerminateIn,
    request: Request,
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    _check_enabled()
    try:
        return admin_compute.force_terminate_instance(
            user.sub, user_sub, instance_id, reason=body.reason, request=request
        )
    except InstanceNotFound:
        raise HTTPException(status_code=404, detail="Instance not found")
    except InvalidInstanceState:
        raise HTTPException(status_code=409, detail="Instance already terminated")


@router.post("/pods/{user_sub}/{pod_id}/terminate")
async def force_terminate_pod(
    user_sub: str,
    pod_id: str,
    body: ForceTerminateIn,
    request: Request,
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    _check_enabled()
    try:
        return admin_compute.force_terminate_pod(
            user.sub, user_sub, pod_id, reason=body.reason, request=request
        )
    except PodNotFound:
        raise HTTPException(status_code=404, detail="Pod not found")
    except PodAlreadyTerminated:
        raise HTTPException(status_code=409, detail="Pod already terminated")


# ---------------------------------------------------------------------------
# Spending & stats
# ---------------------------------------------------------------------------

@router.get("/spending", response_model=PlatformSpendingOut)
async def platform_spending(
    month: Optional[str] = Query(default=None),
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    _check_enabled()
    return admin_compute.get_platform_spending(month=month)


@router.get("/spending/users", response_model=PerUserSpendingOut)
async def per_user_spending(
    month: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    _check_enabled()
    return admin_compute.get_per_user_spending(month=month, limit=limit)


@router.get("/stats/instance-types", response_model=InstanceTypeStatsOut)
async def instance_type_stats(
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    _check_enabled()
    return admin_compute.get_instance_type_stats()


# ---------------------------------------------------------------------------
# Quotas
# ---------------------------------------------------------------------------

@router.get("/quotas/{user_sub}", response_model=QuotaOut)
async def get_quota(
    user_sub: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    _check_enabled()
    return admin_compute.get_quota(user_sub)


@router.put("/quotas/{user_sub}", response_model=QuotaOut)
async def set_quota(
    user_sub: str,
    body: SetQuotaIn,
    request: Request,
    user: AuthenticatedUser = Depends(require_root),
):
    _check_enabled()
    try:
        return admin_compute.set_quota(
            user.sub,
            user_sub,
            max_ec2_instances=body.max_ec2_instances,
            max_k8s_pods=body.max_k8s_pods,
            max_monthly_spend_cents=body.max_monthly_spend_cents,
            allowed_instance_types=body.allowed_instance_types,
            allowed_k8s_presets=body.allowed_k8s_presets,
            notes=body.notes,
            request=request,
        )
    except admin_compute.InvalidInstanceType as e:
        raise HTTPException(status_code=422, detail=str(e))


@router.delete("/quotas/{user_sub}")
async def delete_quota(
    user_sub: str,
    request: Request,
    user: AuthenticatedUser = Depends(require_root),
):
    _check_enabled()
    admin_compute.delete_quota(user.sub, user_sub, request=request)
    return {"ok": True}
