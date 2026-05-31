"""Account deletion + privacy export endpoints (PLATFORM-018).

Distinct from the existing privacy/GDPR router (``app/routers/privacy.py``);
this adds the grace-period scheduled-deletion lifecycle backed by the
``account_deletion_requests`` table.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse

from app.core.settings import S
from app.core.time import now_ts
from app.models import (
    AccountDeletionAuditTrailOut,
    AccountDeletionCancelOut,
    AccountDeletionListOut,
    AccountDeletionProcessDueOut,
    AccountDeletionRequestIn,
    AccountDeletionRetentionHoldIn,
    AccountDeletionRetentionHoldOut,
    AccountDeletionStatusOut,
    PrivacyExportRequestIn,
    PrivacyExportStatusOut,
)
from app.services import account_deletion as svc
from app.services.cognito_auth import verify_user_password
from app.services.sessions import require_ui_session

logger = logging.getLogger(__name__)

account_deletion_router = APIRouter(
    prefix="/ui/privacy/account-deletion", tags=["account-deletion"]
)
account_deletion_admin_router = APIRouter(
    prefix="/ui/admin/privacy/account-deletion", tags=["admin-account-deletion"]
)


def _require_admin(ctx: Dict[str, Any]) -> str:
    role = ctx.get("role", "")
    role_str = (
        str(role).upper()
        if hasattr(role, "upper")
        else str(getattr(role, "value", role)).upper()
    )
    if "ADMIN" not in role_str and "ROOT" not in role_str:
        raise HTTPException(status_code=403, detail="Admin access required")
    return ctx["user_sub"]


# ─── User endpoints ─────────────────────────────────────────────

@account_deletion_router.post("/request", status_code=201)
def create_deletion(
    body: AccountDeletionRequestIn,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> AccountDeletionStatusOut:
    if not S.account_deletion_enabled:
        raise HTTPException(status_code=503, detail="Account deletion is temporarily unavailable")
    user_sub = ctx["user_sub"]

    if not verify_user_password(user_sub, body.password):
        logger.warning("privacy.password_verification_failed user=%s", user_sub)
        raise HTTPException(status_code=401, detail="Invalid password")

    if svc.has_pending_deletion(user_sub):
        raise HTTPException(status_code=409, detail="A deletion request is already pending")

    item = svc.create_deletion_request(user_sub, reason=body.reason)
    return AccountDeletionStatusOut(**svc.request_to_out(item))


@account_deletion_router.get("/requests")
def list_deletions(
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> AccountDeletionListOut:
    user_sub = ctx["user_sub"]
    items = [r for r in svc.list_user_requests(user_sub) if r.get("kind") != "export"]
    out = [AccountDeletionStatusOut(**svc.request_to_out(i)) for i in items]
    return AccountDeletionListOut(requests=out, total=len(out))


@account_deletion_router.get("/requests/{request_id}")
def get_deletion(
    request_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> AccountDeletionStatusOut:
    user_sub = ctx["user_sub"]
    item = svc.get_request(user_sub, request_id)
    if not item or item.get("kind") == "export":
        raise HTTPException(status_code=404, detail="Deletion request not found")
    return AccountDeletionStatusOut(**svc.request_to_out(item))


@account_deletion_router.post("/requests/{request_id}/cancel")
def cancel_deletion(
    request_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> AccountDeletionCancelOut:
    user_sub = ctx["user_sub"]
    try:
        item = svc.cancel_deletion(user_sub, request_id)
    except ValueError as e:
        msg = str(e)
        if msg == "not_found":
            raise HTTPException(status_code=404, detail="Deletion request not found")
        if msg == "not_pending":
            raise HTTPException(status_code=409, detail="Request is not in pending status")
        if msg == "grace_expired":
            raise HTTPException(status_code=409, detail="Grace period has expired; deletion is being processed")
        raise HTTPException(status_code=400, detail=msg)
    return AccountDeletionCancelOut(
        request_id=request_id,
        status=item["status"],
        cancelled_at=int(item.get("cancelled_at", now_ts())),
    )


# ─── Data export ────────────────────────────────────────────────

@account_deletion_router.post("/export", status_code=201)
def create_export(
    body: PrivacyExportRequestIn,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> PrivacyExportStatusOut:
    user_sub = ctx["user_sub"]
    if svc.has_recent_export(user_sub):
        raise HTTPException(status_code=429, detail="Export already requested within the last 24 hours")
    item = svc.create_export_request(user_sub, body.categories)
    return PrivacyExportStatusOut(**svc.export_to_out(item))


@account_deletion_router.get("/export/{request_id}")
def get_export(
    request_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> PrivacyExportStatusOut:
    user_sub = ctx["user_sub"]
    item = svc.get_request(user_sub, request_id)
    if not item or item.get("kind") != "export":
        raise HTTPException(status_code=404, detail="Export not found")
    return PrivacyExportStatusOut(**svc.export_to_out(item))


@account_deletion_router.get("/export/{request_id}/download")
def download_export(
    request_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    user_sub = ctx["user_sub"]
    item = svc.get_request(user_sub, request_id)
    if not item or item.get("kind") != "export":
        raise HTTPException(status_code=404, detail="Export not found")
    expires = int(item.get("download_expires_at", 0))
    if expires and now_ts() > expires:
        raise HTTPException(status_code=404, detail="Export download link has expired")
    return JSONResponse(content=item.get("export_data") or {})


# ─── Admin endpoints ────────────────────────────────────────────

@account_deletion_admin_router.get("/requests")
def admin_list(
    status: str = "pending",
    limit: int = 50,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> AccountDeletionListOut:
    _require_admin(ctx)
    items = svc.list_requests_by_status(status, limit=limit)
    out = [AccountDeletionStatusOut(**svc.request_to_out(i, include_user=True)) for i in items]
    return AccountDeletionListOut(requests=out, total=len(out))


@account_deletion_admin_router.get("/requests/{request_id}/audit")
def admin_audit(
    request_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> AccountDeletionAuditTrailOut:
    _require_admin(ctx)
    events = svc.get_audit_trail(request_id)
    return AccountDeletionAuditTrailOut(request_id=request_id, events=events)


@account_deletion_admin_router.post("/requests/{request_id}/hold")
def admin_hold(
    request_id: str,
    body: AccountDeletionRetentionHoldIn,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> AccountDeletionRetentionHoldOut:
    admin_sub = _require_admin(ctx)
    try:
        item = svc.place_retention_hold(request_id, admin_sub, body.reason)
    except ValueError as e:
        msg = str(e)
        if msg == "not_found":
            raise HTTPException(status_code=404, detail="Deletion request not found")
        if msg == "not_pending":
            raise HTTPException(status_code=409, detail="Can only hold pending requests")
        raise HTTPException(status_code=400, detail=msg)
    return AccountDeletionRetentionHoldOut(
        request_id=request_id,
        retention_hold=True,
        retention_hold_reason=item.get("retention_hold_reason"),
        held_by=item.get("held_by"),
        held_at=item.get("held_at"),
    )


@account_deletion_admin_router.post("/requests/{request_id}/release-hold")
def admin_release_hold(
    request_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> AccountDeletionRetentionHoldOut:
    admin_sub = _require_admin(ctx)
    try:
        svc.release_retention_hold(request_id, admin_sub)
    except ValueError as e:
        msg = str(e)
        if msg == "not_found":
            raise HTTPException(status_code=404, detail="Deletion request not found")
        if msg == "no_hold":
            raise HTTPException(status_code=409, detail="No retention hold to release")
        raise HTTPException(status_code=400, detail=msg)
    return AccountDeletionRetentionHoldOut(request_id=request_id, retention_hold=False)


@account_deletion_admin_router.post("/process-due")
def admin_process_due(
    limit: int = 200,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> AccountDeletionProcessDueOut:
    """Manual trigger so E2E can drive finalization deterministically."""
    _require_admin(ctx)
    processed, skipped, ids = svc.process_due_deletions(limit=limit)
    return AccountDeletionProcessDueOut(processed=processed, skipped=skipped, request_ids=ids)
