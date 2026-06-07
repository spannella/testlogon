"""Privacy / GDPR endpoints (PRIVACY-001)."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import RedirectResponse

from app.core.settings import S
from app.models import (
    DataRequestListOut,
    DataRequestOut,
    DeleteAccountRequestIn,
    ExportRequestIn,
)
from app.services.gdpr_service import (
    admin_approve,
    admin_hold,
    admin_reject,
    admin_release_hold,
    cancel_deletion,
    create_deletion_request,
    create_export_request,
    get_audit_trail,
    get_export_download_url,
    get_request,
    has_pending_deletion,
    has_recent_export,
    has_retention_hold,
    list_requests_by_status,
    list_requests_by_type,
    list_user_requests,
    process_deletion,
    process_export,
    _item_to_out,
)
from app.services import cognito_auth
from app.services.sessions import require_ui_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ui/privacy", tags=["privacy"])
admin_router = APIRouter(prefix="/ui/admin/privacy", tags=["admin-privacy"])


# ─── User Endpoints ─────────────────────────────────────────────


@router.post("/export", status_code=201)
def request_export(
    body: ExportRequestIn,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> DataRequestOut:
    if not S.privacy_export_enabled:
        raise HTTPException(status_code=403, detail="Data export is currently disabled")

    user_sub = ctx["user_sub"]

    if has_recent_export(user_sub):
        raise HTTPException(status_code=429, detail="Export already requested within rate limit window")

    categories = {
        "include_messages": body.include_messages,
        "include_files": body.include_files,
        "include_billing": body.include_billing,
        "include_profile": body.include_profile,
    }
    item = create_export_request(user_sub, categories)

    # Run the export in the BACKGROUND (GAP-0338). A large multi-table query +
    # ZipFile build + S3 upload must not block the HTTP request. Schedule the
    # work as a fire-and-forget asyncio task and return the pending request
    # immediately. _run_export_safe flips the request to "failed" on error so
    # it never sticks at "pending".
    _schedule_export(user_sub, item["request_id"], categories)

    return DataRequestOut(**_item_to_out(item))


# Hold strong references to in-flight background tasks so the event loop does
# not garbage-collect them mid-run (standard asyncio fire-and-forget idiom).
_export_tasks: set[asyncio.Task] = set()


def _schedule_export(user_sub: str, request_id: str, categories: Dict[str, bool]) -> None:
    """Schedule the GDPR export to run in the background, returning immediately."""
    task = asyncio.create_task(_run_export_safe(user_sub, request_id, categories))
    _export_tasks.add(task)
    task.add_done_callback(_export_tasks.discard)


async def _run_export_safe(user_sub: str, request_id: str, categories: Dict[str, bool]) -> None:
    """Run process_export off the request path.

    process_export performs blocking I/O (DynamoDB + S3), so it runs in a
    worker thread. Any exception flips the request status to "failed" so the
    record never sticks at "pending" (which has no retry path).
    """
    try:
        await asyncio.to_thread(process_export, user_sub, request_id, categories)
    except Exception as e:  # noqa: BLE001 - background task must never raise
        logger.error(
            "Export background task failed for %s/%s: %s",
            user_sub,
            request_id,
            e,
            exc_info=True,
        )
        try:
            from app.core.tables import T
            from app.core.time import now_ts
            from app.services.gdpr_service import _req_sk, _user_pk

            T.data_requests.update_item(
                Key={"pk": _user_pk(user_sub), "sk": _req_sk(request_id)},
                UpdateExpression="SET #s = :s, updated_at = :t, error_message = :e",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={
                    ":s": "failed",
                    ":t": now_ts(),
                    ":e": str(e)[:500],
                },
            )
        except Exception:  # noqa: BLE001 - best-effort status update
            logger.exception("Failed to mark export request %s as failed", request_id)


@router.get("/requests")
def list_privacy_requests(
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> DataRequestListOut:
    user_sub = ctx["user_sub"]
    items = list_user_requests(user_sub)
    return DataRequestListOut(
        requests=[DataRequestOut(**_item_to_out(i)) for i in items],
    )


@router.get("/requests/{request_id}")
def get_request_status(
    request_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> DataRequestOut:
    user_sub = ctx["user_sub"]
    item = get_request(user_sub, request_id)
    if not item:
        raise HTTPException(status_code=404, detail="Request not found")

    out = _item_to_out(item)

    # If export is completed, include download URL
    if item.get("status") == "completed" and item.get("request_type") == "export":
        url = get_export_download_url(user_sub, request_id)
        if url:
            out["export_download_url"] = url

    return DataRequestOut(**out)


@router.get("/export/{request_id}/download")
def download_export(
    request_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    user_sub = ctx["user_sub"]
    url = get_export_download_url(user_sub, request_id)
    if not url:
        raise HTTPException(status_code=404, detail="Export not found or expired")
    return RedirectResponse(url=url, status_code=302)


@router.post("/delete-account", status_code=201)
def request_deletion(
    body: DeleteAccountRequestIn,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> DataRequestOut:
    if not S.privacy_deletion_enabled:
        raise HTTPException(status_code=403, detail="Account deletion is currently disabled")

    user_sub = ctx["user_sub"]

    # Check retention hold
    if has_retention_hold(user_sub):
        raise HTTPException(status_code=403, detail="Account has a retention hold")

    # Check for existing pending deletion
    if has_pending_deletion(user_sub):
        raise HTTPException(status_code=409, detail="Pending deletion request already exists")

    # Password re-verification (GAP-0029). verify_user_password handles the
    # dev/prod split internally: empty password is always rejected; in dev mode
    # (or when Cognito is unconfigured) any non-empty password is accepted; in
    # production it re-authenticates against Cognito (AdminInitiateAuth).
    if not body.password:
        raise HTTPException(status_code=401, detail="Password required")

    if not cognito_auth.verify_user_password(user_sub, body.password):
        logger.warning("privacy.password_verification_failed user=%s", user_sub)
        raise HTTPException(status_code=401, detail="Invalid password")

    item = create_deletion_request(user_sub, reason=body.reason)
    return DataRequestOut(**_item_to_out(item))


@router.post("/requests/{request_id}/cancel")
def cancel_deletion_request(
    request_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> DataRequestOut:
    user_sub = ctx["user_sub"]
    try:
        item = cancel_deletion(user_sub, request_id)
    except ValueError as e:
        msg = str(e)
        if msg == "not_found":
            raise HTTPException(status_code=404, detail="Request not found")
        if msg == "not_deletion":
            raise HTTPException(status_code=400, detail="Only deletion requests can be cancelled")
        if msg == "not_pending":
            raise HTTPException(status_code=409, detail="Request is not in pending status")
        if msg == "grace_period_expired":
            raise HTTPException(status_code=409, detail="Grace period has expired")
        raise HTTPException(status_code=400, detail=msg)
    return DataRequestOut(**_item_to_out(item))


# ─── Admin Endpoints ────────────────────────────────────────────


def _require_admin(ctx: Dict[str, Any]) -> str:
    role = ctx.get("role", "")
    role_str = str(role).upper() if hasattr(role, "upper") else str(getattr(role, "value", role)).upper()
    if role_str not in ("ADMIN", "ROOT"):
        raise HTTPException(status_code=403, detail="Admin access required")
    return ctx["user_sub"]


@admin_router.get("/requests")
def admin_list_requests(
    status: str | None = None,
    request_type: str | None = None,
    limit: int = 50,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> DataRequestListOut:
    admin_sub = _require_admin(ctx)

    if status:
        items, _ = list_requests_by_status(status, limit=limit)
    elif request_type:
        items, _ = list_requests_by_type(request_type, limit=limit)
    else:
        # Default: list pending
        items, _ = list_requests_by_status("pending", limit=limit)

    return DataRequestListOut(
        requests=[DataRequestOut(**_item_to_out(i, include_user=True)) for i in items],
    )


@admin_router.get("/requests/{request_id}")
def admin_get_request(
    request_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> Dict[str, Any]:
    admin_sub = _require_admin(ctx)
    from app.services.gdpr_service import get_request_by_id_admin
    item = get_request_by_id_admin(request_id)
    if not item:
        raise HTTPException(status_code=404, detail="Request not found")
    out = _item_to_out(item, include_user=True)
    audit = get_audit_trail(request_id)
    out["audit_trail"] = [
        {"action": a.get("action"), "actor": a.get("actor"), "created_at": int(a.get("created_at", 0)), "details": a.get("details")}
        for a in audit
    ]
    return out


@admin_router.post("/requests/{request_id}/approve")
def admin_approve_request(
    request_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> DataRequestOut:
    admin_sub = _require_admin(ctx)
    try:
        item = admin_approve(request_id, admin_sub)
    except ValueError as e:
        msg = str(e)
        if msg == "not_found":
            raise HTTPException(status_code=404, detail="Request not found")
        raise HTTPException(status_code=400, detail=msg)

    # If it's a deletion request that was approved, and grace period has passed, process it
    if item.get("request_type") == "deletion":
        from app.core.time import now_ts
        grace_ends = int(item.get("grace_period_ends_at", 0))
        if now_ts() >= grace_ends:
            try:
                process_deletion(item["user_sub"], request_id)
                item = get_request(item["user_sub"], request_id) or item
            except Exception as e:
                logger.error("Deletion processing failed after approval: %s", e)

    return DataRequestOut(**_item_to_out(item, include_user=True))


@admin_router.post("/requests/{request_id}/reject")
def admin_reject_request(
    request_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> DataRequestOut:
    admin_sub = _require_admin(ctx)
    try:
        item = admin_reject(request_id, admin_sub)
    except ValueError as e:
        msg = str(e)
        if msg == "not_found":
            raise HTTPException(status_code=404, detail="Request not found")
        raise HTTPException(status_code=400, detail=msg)
    return DataRequestOut(**_item_to_out(item, include_user=True))


@admin_router.post("/requests/{request_id}/hold")
def admin_hold_request(
    request_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> DataRequestOut:
    admin_sub = _require_admin(ctx)
    from app.models import AdminHoldIn
    # Accept reason from query or body -- for simplicity, use a default
    # The actual body will be parsed by FastAPI if provided
    try:
        item = admin_hold(request_id, admin_sub, reason="Admin hold")
    except ValueError as e:
        msg = str(e)
        if msg == "not_found":
            raise HTTPException(status_code=404, detail="Request not found")
        raise HTTPException(status_code=400, detail=msg)
    return DataRequestOut(**_item_to_out(item, include_user=True))


@admin_router.post("/requests/{request_id}/release-hold")
def admin_release_hold_request(
    request_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> DataRequestOut:
    admin_sub = _require_admin(ctx)
    try:
        item = admin_release_hold(request_id, admin_sub)
    except ValueError as e:
        msg = str(e)
        if msg == "not_found":
            raise HTTPException(status_code=404, detail="Request not found")
        if msg == "no_hold":
            raise HTTPException(status_code=400, detail="No retention hold to release")
        raise HTTPException(status_code=400, detail=msg)
    return DataRequestOut(**_item_to_out(item, include_user=True))
