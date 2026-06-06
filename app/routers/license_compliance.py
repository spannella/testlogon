"""License compliance & verification router (LICENSE-006).

Creator-scoped endpoints under ``/ui/licenses/compliance`` let a creator verify
and review the licensing health of their own content. Admin-scoped endpoints
under ``/ui/admin/licenses/compliance`` give platform oversight: issue queue,
flag queue, flag resolution, status overrides, and a platform-wide scan.

This router only READS + VERIFIES against the LICENSE-001 agreement and
LICENSE-002 issuance services; it does not recreate them.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root
from app.auth.roles import Role, normalize_role
from app.models import (
    AdminComplianceIssueListOut,
    ComplianceCheckResultOut,
    ComplianceFlagIn,
    ComplianceFlagListOut,
    ComplianceFlagOut,
    ComplianceFlagResolveIn,
    ComplianceScanResultOut,
    ComplianceStatusOut,
    ComplianceStatusUpdateIn,
    CreatorComplianceListOut,
    LicenseRefListOut,
)
from app.services import license_compliance as svc
from app.services.sessions import require_ui_session

logger = logging.getLogger(__name__)

license_compliance_router = APIRouter(
    prefix="/ui/licenses/compliance", tags=["license-compliance"]
)
license_compliance_admin_router = APIRouter(
    prefix="/ui/admin/licenses/compliance", tags=["license-compliance-admin"]
)


# ─── Creator-scoped ─────────────────────────────────────────────────────────

@license_compliance_router.get("/my-content", response_model=CreatorComplianceListOut)
async def my_content_compliance(
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=100),
    cursor: Optional[str] = Query(default=None),
    session: dict = Depends(require_ui_session),
):
    result = svc.list_creator_compliance(
        creator_sub=session["user_sub"],
        status_filter=status,
        limit=limit,
        cursor=cursor,
    )
    return CreatorComplianceListOut(**result)


@license_compliance_router.get(
    "/content/{content_id}", response_model=ComplianceStatusOut
)
async def content_compliance_detail(
    content_id: str,
    session: dict = Depends(require_ui_session),
):
    record = svc.get_compliance_status(content_id=content_id)
    if not record:
        raise HTTPException(404, "No compliance record for this content")
    # Content owner OR admin/root may view the compliance status (LICENSE-006).
    caller_role = normalize_role(session.get("role"))
    is_owner = record.get("creator_id") == session["user_sub"]
    is_privileged = caller_role in {Role.ADMIN, Role.ROOT}
    if record.get("creator_id") and not is_owner and not is_privileged:
        raise HTTPException(403, "Not authorized to view this content's compliance")
    return ComplianceStatusOut(**record)


@license_compliance_router.get(
    "/content/{content_id}/refs", response_model=LicenseRefListOut
)
async def content_license_refs(
    content_id: str,
    session: dict = Depends(require_ui_session),
):
    return LicenseRefListOut(items=svc.list_license_refs(content_id=content_id))


@license_compliance_router.get(
    "/content/{content_id}/flags", response_model=ComplianceFlagListOut
)
async def content_flags(
    content_id: str,
    status: Optional[str] = Query(default=None),
    session: dict = Depends(require_ui_session),
):
    flags = svc.list_content_flags(content_id=content_id, status_filter=status)
    return ComplianceFlagListOut(items=flags)


@license_compliance_router.post(
    "/content/{content_id}/check", response_model=ComplianceCheckResultOut
)
async def check_content(
    content_id: str,
    content_type: str = Query(default=""),
    session: dict = Depends(require_ui_session),
):
    result = svc.check_content_compliance(
        content_id=content_id,
        content_type=content_type,
        creator_id=session["user_sub"],
    )
    return ComplianceCheckResultOut(**result)


@license_compliance_router.post("/flag", response_model=ComplianceFlagOut)
async def flag_content(
    body: ComplianceFlagIn,
    session: dict = Depends(require_ui_session),
):
    try:
        flag = svc.flag_content(
            reporter_id=session["user_sub"],
            content_id=body.content_id,
            reason=body.reason,
            evidence=body.evidence,
            reporter_type=body.reporter_type,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return ComplianceFlagOut(**flag)


# ─── Admin-scoped ───────────────────────────────────────────────────────────

@license_compliance_admin_router.get(
    "/issues", response_model=AdminComplianceIssueListOut
)
async def admin_issues(
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=100),
    cursor: Optional[str] = Query(default=None),
    _admin: AuthenticatedUser = Depends(require_admin_or_root),
):
    result = svc.admin_list_issues(status_filter=status, limit=limit, cursor=cursor)
    return AdminComplianceIssueListOut(**result)


@license_compliance_admin_router.get(
    "/flags", response_model=ComplianceFlagListOut
)
async def admin_flags(
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=100),
    cursor: Optional[str] = Query(default=None),
    _admin: AuthenticatedUser = Depends(require_admin_or_root),
):
    result = svc.admin_list_flags(status_filter=status, limit=limit, cursor=cursor)
    return ComplianceFlagListOut(**result)


@license_compliance_admin_router.post("/flags/{flag_id}/resolve")
async def admin_resolve_flag(
    flag_id: str,
    body: ComplianceFlagResolveIn,
    admin: AuthenticatedUser = Depends(require_admin_or_root),
):
    try:
        return svc.admin_resolve_flag(
            admin_sub=admin.sub,
            flag_id=flag_id,
            resolution=body.resolution,
            notes=body.notes,
            content_id=body.content_id,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc


@license_compliance_admin_router.post("/content/{content_id}/status")
async def admin_update_status(
    content_id: str,
    body: ComplianceStatusUpdateIn,
    admin: AuthenticatedUser = Depends(require_admin_or_root),
):
    try:
        return svc.admin_update_compliance(
            admin_sub=admin.sub,
            content_id=content_id,
            new_status=body.new_status,
            notes=body.notes,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc


@license_compliance_admin_router.post("/scan", response_model=ComplianceScanResultOut)
async def admin_scan(
    _admin: AuthenticatedUser = Depends(require_admin_or_root),
):
    return ComplianceScanResultOut(**svc.run_compliance_scan())
