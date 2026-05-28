"""Admin SMS delivery monitoring endpoints (PLATFORM-007)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.auth.policy import require_admin_or_root
from app.core.settings import S
from app.services.sms_delivery import (
    get_dev_sms_log,
    get_sms_delivery_stats,
    get_suppression_list,
    is_sms_suppressed,
    list_sms_deliveries,
    list_sms_failures,
    remove_sms_suppression,
    suppress_sms,
)

router = APIRouter(prefix="/ui/admin/sms", tags=["admin-sms"])


@router.get("/stats")
async def sms_stats(
    days: int = Query(default=7, ge=1, le=90),
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    """Get SMS delivery statistics for the last N days."""
    return get_sms_delivery_stats(days=days)


@router.get("/deliveries")
async def sms_deliveries(
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str = Query(default=None),
    status: str = Query(default="sent"),
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    """List recent SMS deliveries (newest first, paginated)."""
    items, next_cursor = list_sms_deliveries(limit=limit, cursor=cursor, status_filter=status)
    return {"items": items, "next_cursor": next_cursor}


@router.get("/failures")
async def sms_failures(
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str = Query(default=None),
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    """List recent SMS delivery failures (newest first, paginated)."""
    items, next_cursor = list_sms_failures(limit=limit, cursor=cursor)
    return {"items": items, "next_cursor": next_cursor}


@router.get("/suppressed")
async def suppressed_list(
    limit: int = Query(default=50, ge=1, le=200),
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    """List suppressed (opted-out) phone numbers."""
    return get_suppression_list(limit=limit)


@router.get("/suppressed/{phone:path}")
async def check_suppression(
    phone: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    """Check if a phone number is suppressed."""
    return {"phone": phone, "suppressed": is_sms_suppressed(phone)}


@router.post("/suppressed/{phone:path}")
async def suppress_phone(
    phone: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    """Manually suppress a phone number (admin action)."""
    suppress_sms(phone, reason="admin")
    return {"ok": True, "phone": phone, "suppressed": True}


@router.delete("/suppressed/{phone:path}")
async def unsuppress_phone(
    phone: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    """Remove phone from suppression list (admin re-consent)."""
    remove_sms_suppression(phone)
    return {"ok": True, "phone": phone, "suppressed": False}


@router.get("/dev-log")
async def dev_log(
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    """Read dev SMS log (dev mode only)."""
    if not S.dev_mode:
        raise HTTPException(status_code=404, detail="Not available in production")
    entries = get_dev_sms_log()
    return {"entries": entries, "count": len(entries)}
