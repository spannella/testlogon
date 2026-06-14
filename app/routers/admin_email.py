"""Admin email delivery monitoring endpoints (PLATFORM-006)."""
from __future__ import annotations

import os

from fastapi import APIRouter, Body, Depends, HTTPException, Query

from app.auth.deps import get_authenticated_user, AuthenticatedUser
from app.auth.policy import require_admin_or_root, require_admin_or_root_csrf, require_root
from app.core.settings import S
from app.core.time import now_ts
from app.models import (
    CampaignEmailTemplateCreate,
    CampaignEmailTemplateOut,
    CampaignEmailTemplatePreviewOut,
    CampaignEmailTemplateUpdate,
    DashboardBreakdownOut,
    DashboardSuppressionAdd,
    DashboardTimeseriesOut,
    EmailDashboardStatsOut,
    EmailSettingsOut,
    EmailSettingsUpdate,
    NotificationTemplatePreviewRequest,
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


# ---------------------------------------------------------------------------
# EML-002: Admin runtime email settings
# ---------------------------------------------------------------------------


def _require_email_settings_enabled():
    if not S.admin_email_settings_enabled:
        raise HTTPException(status_code=503, detail="Email settings management not enabled")


@router.get("/settings", response_model=EmailSettingsOut)
async def get_email_settings_endpoint(
    _actor: AuthenticatedUser = Depends(require_admin_or_root),
):
    """Return the effective outbound email settings (env fallback or DDB override)."""
    _require_email_settings_enabled()
    from app.services.email_settings import get_email_settings
    return get_email_settings()


@router.patch("/settings", response_model=EmailSettingsOut)
async def update_email_settings_endpoint(
    payload: EmailSettingsUpdate = Body(...),
    actor: AuthenticatedUser = Depends(require_root),
):
    """Update outbound email settings (ROOT only)."""
    _require_email_settings_enabled()
    from fastapi import Request
    from app.auth.policy import enforce_cookie_csrf
    from app.services.email_settings import update_email_settings
    result = update_email_settings(
        actor.sub,
        **payload.model_dump(exclude_none=True),
    )
    return result


@router.get("/settings/audit")
async def get_email_settings_audit(
    limit: int = Query(default=50, ge=1, le=200),
    _actor: AuthenticatedUser = Depends(require_admin_or_root),
):
    """Return the audit history for email settings changes."""
    _require_email_settings_enabled()
    from boto3.dynamodb.conditions import Key
    from app.core.tables import T
    try:
        resp = T.alerts.query(
            KeyConditionExpression=Key("user_sub").eq("system_email_settings"),
            ScanIndexForward=False,
            Limit=limit,
        )
        items = resp.get("Items", [])
    except Exception:
        items = []
    return {"items": items, "count": len(items)}


# ---------------------------------------------------------------------------
# EML-009: Campaign email template admin endpoints
# ---------------------------------------------------------------------------


def _require_campaign_templates_enabled():
    if not S.campaign_email_templates_enabled:
        raise HTTPException(status_code=503, detail="campaign_email_templates disabled")


@router.get("/campaign-templates")
async def list_campaign_email_templates(
    _actor: AuthenticatedUser = Depends(require_admin_or_root),
):
    """List all campaign-channel email templates."""
    _require_campaign_templates_enabled()
    from app.services.notification_templates import list_campaign_templates
    templates = list_campaign_templates()
    return templates


@router.post("/campaign-templates", status_code=201)
async def create_campaign_email_template(
    payload: CampaignEmailTemplateCreate = Body(...),
    actor: AuthenticatedUser = Depends(require_admin_or_root_csrf),
):
    """Create a new campaign email template."""
    _require_campaign_templates_enabled()
    from app.services.notification_templates import create_campaign_template
    return create_campaign_template(actor.sub, payload.model_dump())


@router.patch("/campaign-templates/{template_id}")
async def update_campaign_email_template(
    template_id: str,
    payload: CampaignEmailTemplateUpdate = Body(...),
    actor: AuthenticatedUser = Depends(require_admin_or_root_csrf),
):
    """Update a campaign email template (campaign-channel only)."""
    _require_campaign_templates_enabled()
    from app.services.notification_templates import get_template, update_template
    from app.core.tables import T
    from app.core.time import now_ts as _now_ts

    tpl = get_template(template_id)
    if not tpl or tpl.get("channel") != "campaign":
        raise HTTPException(status_code=404, detail="Template not found or not a campaign template")

    update_kwargs = {}
    if payload.subject is not None:
        update_kwargs["subject"] = payload.subject
    if payload.body is not None:
        update_kwargs["body"] = payload.body
    if payload.active is not None:
        update_kwargs["active"] = payload.active

    if update_kwargs:
        update_template(template_id, admin_sub=actor.sub, **update_kwargs)

    # Handle campaign-specific extra fields (name, campaign_id, merge_fields)
    extra_set_parts = []
    extra_values = {}
    extra_names = {}
    if payload.name is not None:
        extra_set_parts.append("#nm = :nm")
        extra_names["#nm"] = "name"
        extra_values[":nm"] = payload.name
    if payload.campaign_id is not None:
        extra_set_parts.append("campaign_id = :cid")
        extra_values[":cid"] = payload.campaign_id
    if payload.merge_fields is not None:
        extra_set_parts.append("merge_fields = :mf")
        extra_values[":mf"] = payload.merge_fields

    if extra_set_parts:
        extra_values[":ua"] = _now_ts()
        extra_set_parts.append("updated_at = :ua")
        kwargs = {
            "Key": {"pk": f"TEMPLATE#{template_id}", "sk": "META"},
            "UpdateExpression": "SET " + ", ".join(extra_set_parts),
            "ExpressionAttributeValues": extra_values,
        }
        if extra_names:
            kwargs["ExpressionAttributeNames"] = extra_names
        try:
            T.admin_messaging_templates.update_item(**kwargs)
        except Exception:
            pass

    try:
        from app.services.alerts import audit_event
        audit_event("campaign_template_updated", actor.sub, template_id=template_id)
    except Exception:
        pass

    from app.services.notification_templates import _campaign_to_out
    resp = T.admin_messaging_templates.get_item(Key={"pk": f"TEMPLATE#{template_id}", "sk": "META"})
    item = resp.get("Item") or {}
    return _campaign_to_out(item)


@router.delete("/campaign-templates/{template_id}", status_code=204)
async def delete_campaign_email_template(
    template_id: str,
    actor: AuthenticatedUser = Depends(require_admin_or_root_csrf),
):
    """Soft-delete (deactivate) a campaign email template."""
    _require_campaign_templates_enabled()
    from app.services.notification_templates import get_template, update_template
    tpl = get_template(template_id)
    if not tpl or tpl.get("channel") != "campaign":
        raise HTTPException(status_code=404, detail="Template not found or not a campaign template")
    update_template(template_id, admin_sub=actor.sub, active=False)
    try:
        from app.services.alerts import audit_event
        audit_event("campaign_template_deleted", actor.sub, template_id=template_id)
    except Exception:
        pass
    return None


@router.post("/campaign-templates/{template_id}/preview")
async def preview_campaign_email_template(
    template_id: str,
    payload: NotificationTemplatePreviewRequest = Body(default_factory=lambda: NotificationTemplatePreviewRequest()),
    _actor: AuthenticatedUser = Depends(require_admin_or_root),
):
    """Render a campaign template with sample variables."""
    _require_campaign_templates_enabled()
    from app.services.notification_templates import get_template, preview_template, _campaign_to_out
    from app.core.tables import T

    tpl = get_template(template_id)
    if not tpl or tpl.get("channel") != "campaign":
        raise HTTPException(status_code=404, detail="Template not found or not a campaign template")

    preview = preview_template(template_id, sample_vars=payload.sample_vars)
    if not preview:
        raise HTTPException(status_code=404, detail="Template not found")

    # Fetch merge_fields from raw item
    resp = T.admin_messaging_templates.get_item(Key={"pk": f"TEMPLATE#{template_id}", "sk": "META"})
    raw = resp.get("Item") or {}
    merge_fields = list(raw.get("merge_fields") or [])

    return {**preview, "merge_fields": merge_fields}
