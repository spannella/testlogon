from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_general_admin_or_root
from app.models import (
    AdminAppleCalendarRelinkIn,
    AdminAppleCalendarRelinkOut,
    AdminAppleCalendarRepairSyncIn,
    AdminAppleCalendarTroubleshootOut,
    AppleCalendarSyncNowOut,
)
from app.services.calendar_integrations.credentials import (
    admin_get_apple_caldav_troubleshooting_bundle,
    admin_safe_relink_apple_event,
    trigger_apple_caldav_sync_now,
)


router = APIRouter(prefix="/admin/calendar/integrations/apple", tags=["admin_calendar_integrations"])


@router.get("/troubleshoot", response_model=AdminAppleCalendarTroubleshootOut)
def get_apple_troubleshooting(
    user_sub: str = Query(..., min_length=1, max_length=128),
    limit: int = Query(25, ge=1, le=200),
    _admin: AuthenticatedUser = Depends(require_general_admin_or_root),
):
    try:
        out = admin_get_apple_caldav_troubleshooting_bundle(user_sub=user_sub, limit=limit)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return AdminAppleCalendarTroubleshootOut(**out)


@router.post("/repair/relink", response_model=AdminAppleCalendarRelinkOut)
def repair_relink_apple_event(
    body: AdminAppleCalendarRelinkIn,
    _admin: AuthenticatedUser = Depends(require_general_admin_or_root),
):
    try:
        out = admin_safe_relink_apple_event(
            user_sub=body.user_sub,
            external_calendar_id=body.external_calendar_id,
            remote_uid=body.remote_uid,
            internal_event_id=body.internal_event_id,
            resource_url=body.resource_url,
            etag=body.etag,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Apple CalDAV connection not found for user") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return AdminAppleCalendarRelinkOut(**out)


@router.post("/repair/sync-now", response_model=AppleCalendarSyncNowOut)
def repair_sync_now(
    body: AdminAppleCalendarRepairSyncIn,
    _admin: AuthenticatedUser = Depends(require_general_admin_or_root),
):
    try:
        out: dict[str, Any] = trigger_apple_caldav_sync_now(user_sub=body.user_sub)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Apple CalDAV connection not found for user") from exc
    return AppleCalendarSyncNowOut(**out)
