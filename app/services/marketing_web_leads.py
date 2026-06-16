"""CMP-006 — Web-to-lead capture form service.

Owns T.marketing_web_lead_captures.
Falls back to T.marketing_web_lead_captures when T.leads (LED-001) is absent/disabled.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from fastapi import HTTPException

from app.core.cursor import decode_cursor, encode_cursor
from app.core.normalize import normalize_email
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)


def _capture_id() -> str:
    return uuid.uuid4().hex[:20]


def create_lead_capture(
    data: Any,
    *,
    source_ip: Optional[str] = None,
) -> Dict[str, Any]:
    """Write a web-lead capture row. Returns {capture_id, ok}."""
    # Honeypot check
    if getattr(data, "honeypot", None):
        # Silent bot rejection
        return {"capture_id": "bot", "ok": True}

    email_raw = getattr(data, "email", "") or ""
    try:
        email = normalize_email(email_raw)
    except Exception:
        email = email_raw.lower().strip()

    capture_id = _capture_id()
    ts = now_ts()
    campaign_id = getattr(data, "campaign_id", None)

    item: Dict[str, Any] = {
        "pk": f"CAPTURE#{capture_id}",
        "sk": "META",
        "capture_id": capture_id,
        "first_name": getattr(data, "first_name", ""),
        "last_name": getattr(data, "last_name", ""),
        "email": email,
        "created_at": ts,
        "updated_at": ts,
    }
    if campaign_id:
        item["campaign_id"] = campaign_id
    for opt in ("phone", "company", "message"):
        val = getattr(data, opt, None)
        if val:
            item[opt] = val
    if source_ip:
        item["source_ip"] = source_ip[:45]

    # Prefer LED-001 leads table when available
    wrote_leads = False
    leads_enabled = getattr(S, "leads_enabled", False)
    if leads_enabled:
        try:
            leads_item = {
                "pk": f"LEAD#{capture_id}",
                "sk": "META",
                "lead_id": capture_id,
                "first_name": item["first_name"],
                "last_name": item["last_name"],
                "email": email,
                "phone": item.get("phone"),
                "company": item.get("company"),
                "notes": item.get("message"),
                "campaign_id": campaign_id,
                "source": "web_to_lead",
                "status": "new",
                "created_at": ts,
                "updated_at": ts,
            }
            leads_item = {k: v for k, v in leads_item.items() if v is not None}
            T.leads.put_item(Item=leads_item)  # type: ignore[attr-defined]
            wrote_leads = True
        except Exception:
            pass  # fall through to web_lead_captures

    if not wrote_leads:
        T.marketing_web_lead_captures.put_item(Item=item)

    # Optionally add to contact list
    contact_list_id = getattr(data, "contact_list_id", None)
    if contact_list_id and getattr(S, "crm_campaigns_enabled", False):
        try:
            from app.services.marketing_lists import add_member  # type: ignore[import]
            add_member("system", contact_list_id, capture_id)
        except Exception:
            pass

    # Auto-responder email
    if getattr(S, "web_to_lead_autoresponder_enabled", False) and email:
        try:
            from app.services.alerts import send_alert_email
            from app.services.branding import get_branding
            branding = get_branding()
            platform_name = branding.get("platform_name", "testlogon")
            send_alert_email(
                [email],
                f"Thank you for contacting {platform_name}",
                (
                    f"Hi {item['first_name']},\n\n"
                    f"Thank you for reaching out to {platform_name}. "
                    f"We'll get back to you shortly.\n\n"
                    f"Best regards,\nThe {platform_name} Team"
                ),
            )
        except Exception:
            pass

    try:
        from app.services.alerts import audit_event
        audit_event(
            "marketing.web_lead.captured",
            "system",
            capture_id=capture_id,
            email=email,
            campaign_id=campaign_id,
        )
    except Exception:
        pass

    return {"capture_id": capture_id, "ok": True}


def list_lead_captures(
    *,
    campaign_id: Optional[str] = None,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List captured leads (admin-only). Optionally filter by campaign_id."""
    from boto3.dynamodb.conditions import Key, Attr

    if campaign_id:
        kwargs: Dict[str, Any] = {
            "IndexName": "ByCampaignCreatedAt",
            "KeyConditionExpression": Key("campaign_id").eq(campaign_id),
            "Limit": limit,
            "ScanIndexForward": False,
        }
    else:
        kwargs = {
            "Limit": limit,
        }

    if cursor:
        try:
            kwargs["ExclusiveStartKey"] = decode_cursor(cursor)
        except Exception:
            pass

    if campaign_id:
        resp = T.marketing_web_lead_captures.query(**kwargs)
    else:
        resp = T.marketing_web_lead_captures.scan(**kwargs)

    items = resp.get("Items", [])
    last_key = resp.get("LastEvaluatedKey")
    next_cursor = encode_cursor(last_key) if last_key else None
    return {"leads": items, "cursor": next_cursor, "count": len(items)}
