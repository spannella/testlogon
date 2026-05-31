"""Admin email delivery monitoring endpoints (PLATFORM-006)."""
from __future__ import annotations

import os

from fastapi import APIRouter, Body, Depends, HTTPException, Query

from app.auth.deps import get_authenticated_user, AuthenticatedUser
from app.auth.policy import require_admin_or_root
from app.core.settings import S
from app.core.time import now_ts
from app.models import (
    DashboardBreakdownOut,
    DashboardSuppressionAdd,
    DashboardTimeseriesOut,
    EmailDashboardStatsOut,
)
from app.services.email_delivery import (
    get_delivery_stats,
    get_delivery_timeseries,
    get_recipient_domain_breakdown,
    get_suppression_list,
    list_bounces,
    list_complaints,
    list_deliveries,
    read_dev_email_log,
    remove_suppression,
    suppress_email,
)
from app.services.alert_email_templates import render_alert_email_template

router = APIRouter(prefix="/ui/admin/email", tags=["admin-email"])


@router.get("/stats")
async def email_stats(
    days: int = Query(default=7, ge=1, le=90),
    _actor: AuthenticatedUser = Depends(require_admin_or_root),
):
    """Get email delivery statistics for the last N days."""
    return get_delivery_stats(days=days)


@router.get("/deliveries")
async def email_deliveries(
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str = Query(default=None),
    status: str = Query(default=None),
    _actor: AuthenticatedUser = Depends(require_admin_or_root),
):
    """List recent email deliveries (newest first, paginated)."""
    items, next_cursor = list_deliveries(limit=limit, cursor=cursor, status_filter=status)
    return {"items": items, "next_cursor": next_cursor}


@router.get("/bounces")
async def email_bounces(
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str = Query(default=None),
    _actor: AuthenticatedUser = Depends(require_admin_or_root),
):
    """List recent email bounces (newest first, paginated)."""
    items, next_cursor = list_bounces(limit=limit, cursor=cursor)
    return {"items": items, "next_cursor": next_cursor}


@router.get("/complaints")
async def email_complaints(
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str = Query(default=None),
    _actor: AuthenticatedUser = Depends(require_admin_or_root),
):
    """List recent email complaints (newest first, paginated)."""
    items, next_cursor = list_complaints(limit=limit, cursor=cursor)
    return {"items": items, "next_cursor": next_cursor}


@router.get("/suppressed")
async def suppressed_emails(
    limit: int = Query(default=50, ge=1, le=200),
    _actor: AuthenticatedUser = Depends(require_admin_or_root),
):
    """List suppressed email addresses."""
    return get_suppression_list(limit=limit)


@router.delete("/suppressed/{email:path}")
async def unsuppress_email(
    email: str,
    _actor: AuthenticatedUser = Depends(require_admin_or_root),
):
    """Remove email from suppression list (admin override)."""
    remove_suppression(email)
    return {"ok": True, "email": email}


@router.get("/preview")
async def email_preview(
    event_type: str = Query(default="login.success"),
    _actor: AuthenticatedUser = Depends(require_admin_or_root),
):
    """Render an email template with sample data for preview."""
    sample_details = {
        "ip": "203.0.113.42",
        "user_agent": "Chrome/125.0 (Windows NT 10.0)",
        "location": "San Francisco, US",
        "amount_cents": 999,
        "currency": "usd",
        "sender_name": "Demo User",
        "subscriber_name": "New Subscriber",
        "plan_name": "Premium Monthly",
        "refund_amount_cents": 499,
        "reason": "Customer requested",
    }
    result = render_alert_email_template(event_type, sample_details)
    if result is None:
        return {"html": None, "subject": None, "event_type": event_type, "available": False}
    subject, html_body = result
    return {"html": html_body, "subject": subject, "event_type": event_type, "available": True}


@router.get("/dev-log")
async def dev_email_log(
    limit: int = Query(default=100, ge=1, le=500),
    _actor: AuthenticatedUser = Depends(require_admin_or_root),
):
    """Read the dev email log file and return parsed entries. Dev mode only."""
    if not S.dev_mode:
        raise HTTPException(status_code=404, detail="Dev mode only endpoint")
    entries = read_dev_email_log(max_entries=limit)
    return {"entries": entries, "count": len(entries)}


# ──────────────────────────────────────────────────────────────────────
# ADMIN-002: Dashboard endpoints
# ──────────────────────────────────────────────────────────────────────


@router.get("/dashboard/stats", response_model=EmailDashboardStatsOut)
async def email_dashboard_stats(
    days: int = Query(default=7, ge=1, le=365),
    _actor: AuthenticatedUser = Depends(require_admin_or_root),
) -> EmailDashboardStatsOut:
    """Normalized email delivery stats for the dashboard KPI cards."""
    raw = get_delivery_stats(days=days)
    sent = int(raw.get("sent", 0) or 0) + int(raw.get("dev_logged", 0) or 0)
    bounced = max(int(raw.get("bounced", 0) or 0), 0)
    complained = max(int(raw.get("complained", 0) or 0), 0)
    failed = max(int(raw.get("failed", 0) or 0), 0)
    suppressed = max(int(raw.get("suppressed", 0) or 0), 0)
    delivered = max(sent - bounced - complained, 0)
    denom = max(sent, 1)
    return EmailDashboardStatsOut(
        sent=sent,
        delivered=delivered,
        bounced=bounced,
        complained=complained,
        failed=failed,
        suppressed=suppressed,
        total=sent + failed,
        delivery_rate=delivered / denom * 100.0,
        bounce_rate=bounced / denom * 100.0,
        complaint_rate=complained / denom * 100.0,
        period_days=days,
    )


@router.get("/dashboard/timeseries", response_model=DashboardTimeseriesOut)
async def email_dashboard_timeseries(
    days: int = Query(default=7, ge=1, le=365),
    _actor: AuthenticatedUser = Depends(require_admin_or_root),
) -> DashboardTimeseriesOut:
    """Daily email delivery counts for charting."""
    points = get_delivery_timeseries(days=days)
    return DashboardTimeseriesOut(channel="email", period_days=days, points=points)


@router.get("/dashboard/bounce-domains", response_model=DashboardBreakdownOut)
async def email_dashboard_bounce_domains(
    days: int = Query(default=7, ge=1, le=365),
    limit: int = Query(default=10, ge=1, le=50),
    _actor: AuthenticatedUser = Depends(require_admin_or_root),
) -> DashboardBreakdownOut:
    """Top recipient domains by bounce count."""
    items = get_recipient_domain_breakdown(days=days, limit=limit)
    return DashboardBreakdownOut(channel="email", dimension="bounce_domain", items=items)


@router.post("/suppressed")
async def add_email_suppression(
    payload: DashboardSuppressionAdd = Body(...),
    actor: AuthenticatedUser = Depends(require_admin_or_root),
):
    """Add an email address to the suppression list (admin action, idempotent)."""
    suppress_email(payload.address, reason=payload.reason)
    return {
        "ok": True,
        "address": payload.address,
        "reason": payload.reason,
        "suppressed_at": now_ts(),
        "suppressed_by": actor.sub,
    }
