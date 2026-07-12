"""CMP-001..CMP-008 — SuiteCRM Campaigns-Extra router.

Registers:
  /ui/crm-marketing/campaigns         — campaign CRUD + send + attribution
  /ui/crm-marketing/email-templates   — HTML email template CRUD + preview
  /ui/crm-marketing/t/{slug}/open.gif — open-tracking pixel (CMP-003, public, no auth)
  /ui/crm-marketing/optout/{token}    — unsubscribe endpoint (CMP-004, public, no auth)
  /ui/crm-marketing/leads/capture     — web-to-lead (CMP-006, public, no auth)
  /ui/admin/crm-marketing/leads       — admin lead list (CMP-006)
"""
from __future__ import annotations

import logging
from typing import Optional

import anyio
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse

from app.auth.roles import Role
from app.services.sessions import require_ui_session
from app.core.normalize import client_ip_from_request
from app.core.settings import S
from app.models import (
    CrmCampaignCreateIn,
    MarketingCampaignListOut,
    CrmCampaignOut,
    MarketingCampaignSendIn,
    MarketingCampaignSendOut,
    CrmCampaignUpdateIn,
    MarketingEmailPreviewIn,
    MarketingEmailPreviewOut,
    MarketingEmailTemplateCreateIn,
    MarketingEmailTemplateListOut,
    MarketingEmailTemplateOut,
    MarketingEmailTemplatePreviewIn,
    MarketingEmailTemplatePreviewOut,
    MarketingEmailTemplateUpdateIn,
    MarketingUnsubscribeOut,
    WebLeadCaptureIn,
    WebLeadCaptureOut,
    WebLeadListOut,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["marketing-campaigns"])

# ─── Tiny helpers ─────────────────────────────────────────────────────────────

# 43-byte minimal 1x1 transparent GIF89a
_TRANSPARENT_GIF = (
    b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00"
    b"\x21\xf9\x04\x00\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00"
    b"\x01\x00\x00\x02\x02\x44\x01\x00\x3b"
)

_UNSUBSCRIBE_HTML = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Unsubscribed</title></head>
<body style="font-family:sans-serif;max-width:560px;margin:60px auto;text-align:center">
<h1>&#x2713; Unsubscribed</h1>
<p>{message}</p>
</body></html>"""


def _require_enabled() -> None:
    if not getattr(S, "crm_campaigns_enabled", False):
        raise HTTPException(status_code=404, detail="Marketing campaigns are not enabled")


def _require_web_to_lead_enabled() -> None:
    if not getattr(S, "web_to_lead_enabled", False):
        raise HTTPException(status_code=404, detail="Web-to-lead capture is not enabled")


# ─── CMP-003: open-tracking pixel (public, no auth) — MUST be before /{id} ───

@router.get(
    "/ui/crm-marketing/t/{code_slug}/open.gif",
    include_in_schema=False,
    response_class=Response,
)
async def campaign_open_pixel(code_slug: str, request: Request) -> Response:
    """Return 1x1 transparent GIF and (optionally) record an open event."""
    if (
        getattr(S, "crm_campaigns_enabled", False)
        and getattr(S, "marketing_open_tracking_enabled", False)
    ):
        ua = request.headers.get("user-agent", "")[:256]
        try:
            from app.services.marketing_tracking_codes import _is_bot_ua, record_visit
            if not _is_bot_ua(ua):
                ip = client_ip_from_request(request)

                def _record() -> None:
                    try:
                        record_visit(
                            code_slug,
                            party_id="anon",
                            event_type="open",
                            ip_address=ip,
                            user_agent=ua,
                        )
                    except Exception:
                        logger.debug("open-pixel record_visit failed for code=%s", code_slug)

                await anyio.to_thread.run_sync(_record)
        except Exception:
            pass

    return Response(
        content=_TRANSPARENT_GIF,
        media_type="image/gif",
        headers={
            "Cache-Control": "no-store, no-cache",
            "Pragma": "no-cache",
            "X-Content-Type-Options": "nosniff",
        },
    )


# ─── CMP-004: opt-out endpoint (public, no auth) ──────────────────────────────

@router.get(
    "/ui/crm-marketing/optout/{token}",
    response_class=HTMLResponse,
    include_in_schema=False,
)
async def marketing_unsubscribe(token: str) -> HTMLResponse:
    """Process unsubscribe token and show confirmation page."""
    try:
        from app.services.marketing_unsubscribe import process_unsubscribe
        result = process_unsubscribe(token)
    except Exception:
        result = {"ok": False, "message": "An error occurred. Please try again."}

    msg = result.get("message", "You have been unsubscribed.")
    return HTMLResponse(content=_UNSUBSCRIBE_HTML.format(message=msg), status_code=200)


# ─── CMP-006: web-to-lead capture (public, no auth) ───────────────────────────

@router.post(
    "/ui/crm-marketing/leads/capture",
    response_model=WebLeadCaptureOut,
    status_code=200,
)
async def web_lead_capture(
    body: WebLeadCaptureIn,
    request: Request,
) -> WebLeadCaptureOut:
    """Accept a web-to-lead form submission."""
    _require_web_to_lead_enabled()

    source_ip = client_ip_from_request(request)

    # IP rate limiting
    try:
        from app.services.rate_limit import _bucket_limit
        max_per_hour = getattr(S, "web_to_lead_max_per_ip_per_hour", 10)
        _bucket_limit(
            f"ip#{source_ip}",
            "web_to_lead_capture",
            max_n=max_per_hour,
            win=3600,
        )
    except HTTPException:
        raise
    except Exception:
        pass

    from app.services.marketing_web_leads import create_lead_capture
    result = create_lead_capture(body, source_ip=source_ip)
    return WebLeadCaptureOut(**result)


# ─── CMP-002: email templates ─────────────────────────────────────────────────
# Must be declared BEFORE /{campaign_id} catch-all routes.

@router.post(
    "/ui/crm-marketing/email-templates",
    response_model=MarketingEmailTemplateOut,
    status_code=201,
)
async def create_email_template(
    body: MarketingEmailTemplateCreateIn,
    ctx: dict = Depends(require_ui_session),
) -> MarketingEmailTemplateOut:
    _require_enabled()
    from app.services.marketing_email_templates import create_template
    result = create_template(ctx["user_sub"], body)
    return MarketingEmailTemplateOut(**result)


@router.get("/ui/crm-marketing/email-templates", response_model=MarketingEmailTemplateListOut)
async def list_email_templates(
    limit: int = Query(default=20, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    ctx: dict = Depends(require_ui_session),
) -> MarketingEmailTemplateListOut:
    _require_enabled()
    from app.services.marketing_email_templates import list_templates
    result = list_templates(ctx["user_sub"], limit=limit, cursor=cursor)
    return MarketingEmailTemplateListOut(**result)


@router.get(
    "/ui/crm-marketing/email-templates/{template_id}",
    response_model=MarketingEmailTemplateOut,
)
async def get_email_template(
    template_id: str,
    ctx: dict = Depends(require_ui_session),
) -> MarketingEmailTemplateOut:
    _require_enabled()
    from app.services.marketing_email_templates import get_template
    tmpl = get_template(ctx["user_sub"], template_id)
    if not tmpl:
        raise HTTPException(404, detail="Template not found")
    return MarketingEmailTemplateOut(**tmpl)


@router.patch(
    "/ui/crm-marketing/email-templates/{template_id}",
    response_model=MarketingEmailTemplateOut,
)
async def update_email_template(
    template_id: str,
    body: MarketingEmailTemplateUpdateIn,
    ctx: dict = Depends(require_ui_session),
) -> MarketingEmailTemplateOut:
    _require_enabled()
    from app.services.marketing_email_templates import update_template
    result = update_template(ctx["user_sub"], template_id, body)
    return MarketingEmailTemplateOut(**result)


@router.delete("/ui/crm-marketing/email-templates/{template_id}")
async def delete_email_template(
    template_id: str,
    ctx: dict = Depends(require_ui_session),
) -> dict:
    _require_enabled()
    from app.services.marketing_email_templates import delete_template
    delete_template(ctx["user_sub"], template_id)
    return {"ok": True}


@router.post(
    "/ui/crm-marketing/email-templates/{template_id}/preview",
    response_model=MarketingEmailTemplatePreviewOut,
)
async def preview_email_template(
    template_id: str,
    body: MarketingEmailTemplatePreviewIn,
    ctx: dict = Depends(require_ui_session),
) -> MarketingEmailTemplatePreviewOut:
    _require_enabled()
    from app.services.marketing_email_templates import preview_template
    result = preview_template(ctx["user_sub"], template_id, body.sample_vars)
    return MarketingEmailTemplatePreviewOut(**result)


# ─── Campaign CRUD ────────────────────────────────────────────────────────────

@router.post(
    "/ui/crm-marketing/campaigns",
    response_model=CrmCampaignOut,
    status_code=201,
)
async def create_campaign(
    body: CrmCampaignCreateIn,
    ctx: dict = Depends(require_ui_session),
) -> CrmCampaignOut:
    _require_enabled()
    from app.services.crm_campaigns import create_campaign as svc_create
    result = svc_create(ctx["user_sub"], body)
    return CrmCampaignOut(**result)


@router.get("/ui/crm-marketing/campaigns", response_model=MarketingCampaignListOut)
async def list_campaigns(
    campaign_type: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    ctx: dict = Depends(require_ui_session),
) -> MarketingCampaignListOut:
    _require_enabled()
    if campaign_type and campaign_type not in {"email", "phone", "mail", "fax", "sms"}:
        raise HTTPException(422, detail=f"Invalid campaign_type: {campaign_type}")
    from app.services.crm_campaigns import list_campaigns as svc_list
    result = svc_list(
        ctx["user_sub"],
        campaign_type=campaign_type,
        status=status,
        limit=limit,
        cursor=cursor,
    )
    return MarketingCampaignListOut(**result)


@router.get(
    "/ui/crm-marketing/campaigns/{campaign_id}",
    response_model=CrmCampaignOut,
)
async def get_campaign(
    campaign_id: str,
    ctx: dict = Depends(require_ui_session),
) -> CrmCampaignOut:
    _require_enabled()
    from app.services.crm_campaigns import get_campaign as svc_get
    result = svc_get(campaign_id, ctx["user_sub"])
    if not result:
        raise HTTPException(404, detail="Campaign not found")
    return CrmCampaignOut(**result)


@router.patch(
    "/ui/crm-marketing/campaigns/{campaign_id}",
    response_model=CrmCampaignOut,
)
async def update_campaign(
    campaign_id: str,
    body: CrmCampaignUpdateIn,
    ctx: dict = Depends(require_ui_session),
) -> CrmCampaignOut:
    _require_enabled()
    from app.services.crm_campaigns import update_campaign as svc_update
    result = svc_update(campaign_id, ctx["user_sub"], body)
    return CrmCampaignOut(**result)


@router.delete("/ui/crm-marketing/campaigns/{campaign_id}")
async def delete_campaign(
    campaign_id: str,
    ctx: dict = Depends(require_ui_session),
) -> dict:
    _require_enabled()
    from app.services.crm_campaigns import delete_campaign as svc_delete
    svc_delete(campaign_id, ctx["user_sub"])
    return {"ok": True}


# ─── Send + attribution (CMP-001..CMP-008) ────────────────────────────────────

@router.post(
    "/ui/crm-marketing/campaigns/{campaign_id}/send",
    response_model=MarketingCampaignSendOut,
)
async def send_campaign(
    campaign_id: str,
    body: MarketingCampaignSendIn,
    ctx: dict = Depends(require_ui_session),
) -> MarketingCampaignSendOut:
    _require_enabled()
    from app.services.crm_campaigns import send_campaign as svc_send
    result = svc_send(
        campaign_id,
        ctx["user_sub"],
        dry_run=body.dry_run,
        snapshot_ts=body.snapshot_ts,
    )
    return MarketingCampaignSendOut(**result)


@router.get("/ui/crm-marketing/campaigns/{campaign_id}/attribution")
async def get_attribution(
    campaign_id: str,
    ctx: dict = Depends(require_ui_session),
) -> dict:
    _require_enabled()
    from app.services.crm_campaigns import get_campaign_attribution
    return get_campaign_attribution(campaign_id, ctx["user_sub"])


@router.get("/ui/crm-marketing/campaigns/{campaign_id}/ab-results")
async def get_ab_results(
    campaign_id: str,
    ctx: dict = Depends(require_ui_session),
) -> dict:
    _require_enabled()
    from app.services.crm_campaigns import get_ab_results as svc_ab
    return svc_ab(campaign_id, ctx["user_sub"])


# ─── CMP-008: email preview endpoint ─────────────────────────────────────────

@router.post(
    "/ui/crm-marketing/campaigns/{campaign_id}/preview-email",
    response_model=MarketingEmailPreviewOut,
)
async def preview_campaign_email(
    campaign_id: str,
    body: MarketingEmailPreviewIn,
    ctx: dict = Depends(require_ui_session),
) -> MarketingEmailPreviewOut:
    _require_enabled()
    from app.services.crm_campaigns import (
        _build_merge_vars,
        _build_message_body,
        get_campaign as svc_get,
    )

    campaign_dict = svc_get(campaign_id, ctx["user_sub"])
    if not campaign_dict:
        raise HTTPException(404, detail="Campaign not found")

    sample_party_id = body.sample_party_id or ctx["user_sub"]
    merge_vars = _build_merge_vars(sample_party_id, campaign_id, extra=body.sample_vars)

    # Convert output model dict back to raw for _build_message_body
    raw_campaign = {
        "campaign_id": campaign_dict["campaign_id"],
        "owner_id": campaign_dict["owner_id"],
        "name": campaign_dict["name"],
        "campaign_type": campaign_dict.get("campaign_type", "email"),
        "email_template_id": campaign_dict.get("email_template_id"),
        "questionnaire_url": campaign_dict.get("questionnaire_url"),
        "tracking_code": campaign_dict.get("tracking_code"),
    }

    body_text, body_html = _build_message_body(raw_campaign, merge_vars, owner_id=ctx["user_sub"])

    # Determine missing merge vars
    from app.services.notification_templates import _VAR_RE
    all_placeholders = set(_VAR_RE.findall(body_text + (body_html or "")))
    missing = [p for p in all_placeholders if p not in merge_vars or not merge_vars[p]]

    return MarketingEmailPreviewOut(
        subject=campaign_dict["name"],
        body_text=body_text,
        body_html=body_html,
        merge_vars_used={k: v for k, v in merge_vars.items() if v},
        merge_vars_missing=missing,
    )


# ─── CMP-006: admin lead list ─────────────────────────────────────────────────

@router.get("/ui/admin/crm-marketing/leads", response_model=WebLeadListOut)
async def admin_list_leads(
    campaign_id: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    ctx: dict = Depends(require_ui_session),
) -> WebLeadListOut:
    if ctx.get("role") not in (Role.ADMIN, Role.ROOT):
        raise HTTPException(403, detail="Admin access required")
    if not getattr(S, "web_to_lead_enabled", False) and not getattr(S, "crm_campaigns_enabled", False):
        raise HTTPException(404, detail="Feature not enabled")

    from app.services.marketing_web_leads import list_lead_captures
    result = list_lead_captures(campaign_id=campaign_id, limit=limit, cursor=cursor)
    return WebLeadListOut(**result)
