"""CMP-001..CMP-008 — SuiteCRM Campaigns-Extra: core campaign service.

Owns:
- Campaign CRUD (CMP-001)
- Send/track path with channel dispatch (CMP-001), HTML template (CMP-002),
  open-pixel injection (CMP-003), unsubscribe URL (CMP-004),
  survey URL (CMP-005), merge-vars (CMP-008), A/B variant split (CMP-007)
- ROI attribution rollup (CMP-007)

Lazy-imports sibling modules (MKT-003..MKT-011 live in integrated tree but are
ABSENT in this isolated worktree) following RULE-1 and RULE-2.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import secrets
from typing import Any, Dict, List, Optional, Tuple

from fastapi import HTTPException

from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# ─── Constants ────────────────────────────────────────────────────────────────

CAMPAIGN_TYPES = {"email", "phone", "mail", "fax", "sms"}


def _require_enabled() -> None:
    if not getattr(S, "crm_campaigns_enabled", False):
        raise HTTPException(status_code=404, detail="Marketing campaigns are not enabled")


# ─── Campaign CRUD ────────────────────────────────────────────────────────────


def _campaign_id(owner_id: str, name: str) -> str:
    return hashlib.sha256(f"{owner_id}|{name}".encode()).hexdigest()[:24]


def _item_to_out(item: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise a DDB campaign item to the CrmCampaignOut shape."""
    return {
        "campaign_id": item.get("campaign_id", ""),
        "owner_id": item.get("owner_id", ""),
        "name": item.get("name", ""),
        "status": item.get("status", "draft"),
        "objective": item.get("objective"),
        "budget_cents": int(item.get("budget_cents", 0)),
        "contact_list_ids": item.get("contact_list_ids") or [],
        "segment_ids": item.get("segment_ids") or [],
        "tracking_code": item.get("tracking_code"),
        "email_template_id": item.get("email_template_id"),
        "questionnaire_id": item.get("questionnaire_id"),
        "questionnaire_url": item.get("questionnaire_url"),
        "campaign_type": item.get("campaign_type", "email"),
        "variants": _parse_variants(item.get("variants")),
        "created_at": int(item.get("created_at", 0)),
        "updated_at": int(item.get("updated_at", 0)),
    }


def _parse_variants(raw: Any) -> Optional[List[Dict[str, Any]]]:
    if raw is None:
        return None
    if isinstance(raw, list):
        return raw
    try:
        return json.loads(raw)
    except Exception:
        return None


def create_campaign(owner_id: str, data: Any) -> Dict[str, Any]:
    """Create a new marketing campaign. Raises 409 on duplicate name."""
    campaign_id = _campaign_id(owner_id, data.name)
    ts = now_ts()

    # Optional: validate email_template_id exists
    if getattr(data, "email_template_id", None):
        try:
            from app.services.marketing_email_templates import get_template
            tmpl = get_template(owner_id, data.email_template_id)
            if tmpl is None:
                raise HTTPException(422, detail="email_template_id does not exist or does not belong to this owner")
        except HTTPException:
            raise
        except Exception:
            pass  # sibling absent — skip validation

    # Optional: validate questionnaire
    questionnaire_url: Optional[str] = None
    if getattr(data, "questionnaire_id", None):
        try:
            from app.services.questionnaires_repository import DynamoQuestionnaireRepository
            repo = DynamoQuestionnaireRepository()
            qnr = repo.get_questionnaire(data.questionnaire_id)
            if qnr is None or qnr.get("status") != "published":
                raise HTTPException(422, detail="questionnaire_id must reference a published questionnaire")
            slug = qnr.get("published_slug", "")
            if slug:
                questionnaire_url = f"{S.public_base_url}/questionnaires/published/{slug}"
        except HTTPException:
            raise
        except Exception:
            pass  # sibling absent — skip

    item: Dict[str, Any] = {
        "pk": f"OWNER#{owner_id}",
        "sk": f"MKTCAMP#{campaign_id}",
        "campaign_id": campaign_id,
        "owner_id": owner_id,
        "name": data.name,
        "status": "draft",
        "objective": getattr(data, "objective", None),
        "budget_cents": int(getattr(data, "budget_cents", 0) or 0),
        "contact_list_ids": list(getattr(data, "contact_list_ids", None) or []),
        "segment_ids": list(getattr(data, "segment_ids", None) or []),
        "tracking_code": getattr(data, "tracking_code", None),
        "email_template_id": getattr(data, "email_template_id", None),
        "questionnaire_id": getattr(data, "questionnaire_id", None),
        "questionnaire_url": questionnaire_url,
        "campaign_type": getattr(data, "campaign_type", "email") or "email",
        "created_at": ts,
        "updated_at": ts,
    }
    variants = getattr(data, "variants", None)
    if variants is not None:
        item["variants"] = json.dumps(variants)

    # Remove None values for sparse DDB items
    item = {k: v for k, v in item.items() if v is not None}

    try:
        T.crm_campaigns.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(pk) OR attribute_not_exists(sk)",
        )
    except Exception as exc:
        if "ConditionalCheckFailedException" in type(exc).__name__:
            raise HTTPException(409, detail="Campaign with this name already exists for this owner")
        raise

    try:
        from app.services.alerts import audit_event
        audit_event("marketing.campaign.created", owner_id, campaign_id=campaign_id)
    except Exception:
        pass

    return _item_to_out(item)


def get_campaign(campaign_id: str, owner_id: str) -> Optional[Dict[str, Any]]:
    """Fetch a campaign by id. Returns None when not found. Raises 403 on ownership mismatch."""
    resp = T.crm_campaigns.get_item(
        Key={"pk": f"OWNER#{owner_id}", "sk": f"MKTCAMP#{campaign_id}"}
    )
    item = resp.get("Item")
    if not item:
        return None
    if item.get("owner_id") != owner_id:
        raise HTTPException(403, detail="Access denied")
    return _item_to_out(item)


def list_campaigns(
    owner_id: str,
    *,
    campaign_type: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List campaigns for an owner with optional filtering."""
    from boto3.dynamodb.conditions import Key, Attr

    kwargs: Dict[str, Any] = {
        "IndexName": "ByOwnerCreatedAt",
        "KeyConditionExpression": Key("owner_id").eq(owner_id),
        "Limit": limit,
        "ScanIndexForward": False,
    }

    filter_parts = []
    if campaign_type:
        filter_parts.append(Attr("campaign_type").eq(campaign_type))
    if status:
        filter_parts.append(Attr("status").eq(status))
    if filter_parts:
        fe = filter_parts[0]
        for part in filter_parts[1:]:
            fe = fe & part
        kwargs["FilterExpression"] = fe

    if cursor:
        try:
            kwargs["ExclusiveStartKey"] = decode_cursor(cursor)
        except Exception:
            pass

    results: List[Dict[str, Any]] = []
    pages = 0
    last_key = None
    while pages < 20:
        resp = T.crm_campaigns.query(**kwargs)
        for item in resp.get("Items", []):
            results.append(_item_to_out(item))
            if len(results) >= limit:
                break
        last_key = resp.get("LastEvaluatedKey")
        if not last_key or len(results) >= limit:
            break
        kwargs["ExclusiveStartKey"] = last_key
        pages += 1

    next_cursor = encode_cursor(last_key) if last_key and len(results) >= limit else None
    return {"campaigns": results, "cursor": next_cursor, "count": len(results)}


def update_campaign(campaign_id: str, owner_id: str, data: Any) -> Dict[str, Any]:
    """Update a campaign. Blocks campaign_type changes on active campaigns."""
    resp = T.crm_campaigns.get_item(
        Key={"pk": f"OWNER#{owner_id}", "sk": f"MKTCAMP#{campaign_id}"}
    )
    item = resp.get("Item")
    if not item:
        raise HTTPException(404, detail="Campaign not found")
    if item.get("owner_id") != owner_id:
        raise HTTPException(403, detail="Access denied")

    new_type = getattr(data, "campaign_type", None)
    if new_type and new_type != item.get("campaign_type", "email"):
        if item.get("status", "draft") not in ("draft",):
            raise HTTPException(409, detail="campaign_type cannot be changed after activation")

    ts = now_ts()
    updates: List[str] = ["#upd = :upd"]
    names = {"#upd": "updated_at"}
    vals: Dict[str, Any] = {":upd": ts}

    simple_fields = [
        ("name", "name"), ("objective", "objective"), ("budget_cents", "budget_cents"),
        ("tracking_code", "tracking_code"), ("start_date", "start_date"),
        ("end_date", "end_date"), ("campaign_type", "campaign_type"),
        ("email_template_id", "email_template_id"), ("questionnaire_id", "questionnaire_id"),
    ]
    for attr, field in simple_fields:
        val = getattr(data, field, None)
        if val is not None:
            updates.append(f"#{attr} = :{attr}")
            names[f"#{attr}"] = attr
            vals[f":{attr}"] = val

    for list_field in ("contact_list_ids", "segment_ids", "promo_code_ids"):
        val = getattr(data, list_field, None)
        if val is not None:
            updates.append(f"#{list_field} = :{list_field}")
            names[f"#{list_field}"] = list_field
            vals[f":{list_field}"] = list(val)

    variants = getattr(data, "variants", None)
    if variants is not None:
        updates.append("#variants = :variants")
        names["#variants"] = "variants"
        vals[":variants"] = json.dumps(variants)

    T.crm_campaigns.update_item(
        Key={"pk": f"OWNER#{owner_id}", "sk": f"MKTCAMP#{campaign_id}"},
        UpdateExpression="SET " + ", ".join(updates),
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=vals,
    )

    try:
        from app.services.alerts import audit_event
        audit_event("marketing.campaign.updated", owner_id, campaign_id=campaign_id)
    except Exception:
        pass

    return get_campaign(campaign_id, owner_id) or {}


def delete_campaign(campaign_id: str, owner_id: str) -> None:
    resp = T.crm_campaigns.get_item(
        Key={"pk": f"OWNER#{owner_id}", "sk": f"MKTCAMP#{campaign_id}"}
    )
    item = resp.get("Item")
    if not item:
        raise HTTPException(404, detail="Campaign not found")
    if item.get("owner_id") != owner_id:
        raise HTTPException(403, detail="Access denied")

    T.crm_campaigns.delete_item(
        Key={"pk": f"OWNER#{owner_id}", "sk": f"MKTCAMP#{campaign_id}"}
    )
    try:
        from app.services.alerts import audit_event
        audit_event("marketing.campaign.deleted", owner_id, campaign_id=campaign_id)
    except Exception:
        pass


# ─── Send path ────────────────────────────────────────────────────────────────


def _redact_phone(phone: Optional[str]) -> str:
    if phone and len(phone) >= 4:
        return f"***{phone[-4:]}"
    return "***"


def _build_merge_vars(
    party_id: str,
    campaign_id: str,
    *,
    extra: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    """Build the merge-vars dict for a recipient (CMP-008)."""
    merge_vars: Dict[str, str] = {}

    # CMP-008: D6 — platform_name from get_branding()
    try:
        from app.services.branding import get_branding
        branding = get_branding()
        merge_vars["platform_name"] = branding.get("platform_name") or "testlogon"
    except Exception:
        merge_vars["platform_name"] = "testlogon"

    # Recipient profile fields
    try:
        from app.services.profile import get_profile
        profile = get_profile(party_id)
        merge_vars["first_name"] = profile.get("first_name") or ""
        merge_vars["last_name"] = profile.get("last_name") or ""
        merge_vars["email"] = profile.get("displayed_email") or profile.get("email") or ""
        merge_vars["phone"] = profile.get("displayed_telephone_number") or ""
        # company absent from platform profile (CMP-008 §5.4)
    except Exception:
        pass

    if extra:
        merge_vars.update(extra)

    return merge_vars


def _build_message_body(
    campaign: Dict[str, Any],
    merge_vars: Dict[str, str],
    *,
    owner_id: str,
) -> Tuple[str, Optional[str]]:
    """Build (body_text, body_html|None) for a campaign send.

    CMP-002: optionally renders HTML template.
    CMP-003: injects open-tracking pixel into HTML body.
    CMP-004: merge_vars["unsubscribe_url"] already set by caller.
    CMP-005: merge_vars["survey_url"] already set by caller.
    """
    campaign_id = campaign.get("campaign_id", "")
    campaign_name = campaign.get("name", "Campaign")

    subject_tpl = merge_vars.get("subject") or campaign_name
    body_text = (
        f"Subject: {subject_tpl}\n\n"
        f"This is a campaign email from {merge_vars.get('platform_name', 'testlogon')}.\n"
    )
    if merge_vars.get("unsubscribe_url"):
        body_text += f"\nTo unsubscribe: {merge_vars['unsubscribe_url']}\n"
    if merge_vars.get("survey_url"):
        body_text += f"\nShare your feedback: {merge_vars['survey_url']}\n"

    # Apply merge field substitution to body_text
    try:
        from app.services.notification_templates import _render
        rendered_text, _ = _render(body_text, merge_vars)
        body_text = rendered_text or body_text
    except Exception:
        pass

    # CMP-002: render HTML template if linked
    body_html: Optional[str] = None
    if (campaign.get("email_template_id") and
            campaign.get("campaign_type", "email") == "email"):
        try:
            from app.services.marketing_email_templates import get_template, render_template
            tmpl = get_template(owner_id, campaign["email_template_id"])
            if tmpl:
                _, body_html = render_template(tmpl, merge_vars)
        except Exception:
            body_html = None  # best-effort; fall back to plain text

    # CMP-003: inject open-tracking pixel
    if body_html is not None and getattr(S, "marketing_open_tracking_enabled", False):
        code_slug = campaign.get("tracking_code")
        if code_slug:
            pixel_url = f"{S.public_base_url}/ui/crm-marketing/t/{code_slug}/open.gif"
            pixel_tag = (
                f'<img src="{pixel_url}" width="1" height="1" '
                f'alt="" style="display:none" />'
            )
            if "</div></div>\n</body>" in body_html:
                body_html = body_html.replace(
                    "</div></div>\n</body>",
                    f"{pixel_tag}\n</div></div>\n</body>",
                    1,
                )
            else:
                body_html = body_html + pixel_tag

    return body_text, body_html


def _assign_variant(party_id: str, campaign_id: str, variants: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Deterministically assign a recipient to an A/B variant (CMP-007)."""
    total = sum(int(v.get("weight", 1)) for v in variants)
    if total <= 0:
        total = len(variants)
    h = int(hashlib.sha256(f"{campaign_id}\x00{party_id}".encode()).hexdigest(), 16)
    bucket = h % total
    cumulative = 0
    for v in variants:
        cumulative += int(v.get("weight", 1))
        if bucket < cumulative:
            return v
    return variants[-1]


def _try_send_one(
    *,
    campaign_id: str,
    campaign_type: str,
    party_id: str,
    subject: str,
    body_text: str,
    body_html: Optional[str],
    dry_run: bool,
    now: int,
    snapshot_ts: int,
    send_id_prefix: str,
    variant_id: Optional[str] = None,
) -> bool:
    """Attempt to send to a single recipient. Returns True on success."""
    if dry_run:
        return True

    # Dedup: write send-log row with conditional put
    send_id = f"{snapshot_ts}#{party_id}"
    log_pk = f"CAMP#{campaign_id}"
    log_sk = f"SEND#{send_id}"

    try:
        T.crm_campaign_send_log.put_item(
            Item={
                "pk": log_pk,
                "sk": log_sk,
                "campaign_id": campaign_id,
                "party_id": party_id,
                "sent_at": now,
                "channel": campaign_type,
                **({"variant_id": variant_id} if variant_id else {}),
            },
            ConditionExpression="attribute_not_exists(pk) AND attribute_not_exists(sk)",
        )
    except Exception as exc:
        if "ConditionalCheckFailedException" in type(exc).__name__:
            return False  # already sent
        # DDB error — log and skip
        logger.warning("send_log put_item failed for %s/%s: %s", campaign_id, party_id, exc)
        return False

    # Get recipient profile for delivery
    email: Optional[str] = None
    phone: Optional[str] = None
    try:
        from app.services.profile import get_profile
        profile = get_profile(party_id)
        email = profile.get("displayed_email") or profile.get("email")
        phone = profile.get("displayed_telephone_number")
    except Exception:
        pass

    # In-app alert for all channels
    try:
        from app.services.alerts import write_alert
        write_alert(
            party_id,
            event=f"marketing.campaign.{campaign_type}",
            outcome="delivered",
            title=subject,
            details={
                "campaign_id": campaign_id,
                "channel": campaign_type,
                **({"note": "Delivery via physical channel; complete outreach out-of-band."} if campaign_type in ("phone", "mail", "fax") else {}),
            },
            action_url=None,
        )
    except Exception:
        pass

    sms_ok = False

    if campaign_type == "email":
        # CMP-001/002: email path
        if email:
            try:
                from app.services.alerts import send_alert_email
                send_alert_email([email], subject, body_text, body_html=body_html)
                # Update send-log with email_sent=True
                T.crm_campaign_send_log.update_item(
                    Key={"pk": log_pk, "sk": log_sk},
                    UpdateExpression="SET email_sent = :t",
                    ExpressionAttributeValues={":t": True},
                )
            except Exception as exc:
                logger.warning("send_alert_email failed for %s: %s", party_id, exc)
    elif campaign_type == "sms":
        if phone:
            try:
                from app.services.alerts import send_alert_sms
                results = send_alert_sms([phone], body_text)
                sms_ok = any(r.get("status") not in ("failed", "error") for r in (results or []))
            except Exception:
                sms_ok = False

            # Update send-log with sms info
            try:
                T.crm_campaign_send_log.update_item(
                    Key={"pk": log_pk, "sk": log_sk},
                    UpdateExpression="SET sms_sent = :s, sms_number = :n",
                    ExpressionAttributeValues={":s": sms_ok, ":n": _redact_phone(phone)},
                )
            except Exception:
                pass
    # phone/mail/fax: in-app only (already done above)

    return True


def send_campaign(
    campaign_id: str,
    owner_id: str,
    *,
    dry_run: bool = False,
    snapshot_ts: Optional[int] = None,
) -> Dict[str, Any]:
    """Send a campaign to its audience (CMP-001..CMP-008 full path)."""
    _require_enabled()

    resp = T.crm_campaigns.get_item(
        Key={"pk": f"OWNER#{owner_id}", "sk": f"MKTCAMP#{campaign_id}"}
    )
    campaign = resp.get("Item")
    if not campaign:
        raise HTTPException(404, detail="Campaign not found")
    if campaign.get("owner_id") != owner_id:
        raise HTTPException(403, detail="Access denied")
    if campaign.get("status") not in ("draft", "scheduled", "active"):
        raise HTTPException(409, detail=f"Campaign is in status '{campaign.get('status')}' and cannot be sent")

    now = now_ts()
    snap_ts = snapshot_ts or now
    campaign_type = campaign.get("campaign_type", "email")

    # Resolve audience (lazy import MKT-007 contact lists)
    party_ids: List[str] = []
    contact_list_ids = campaign.get("contact_list_ids") or []
    for list_id in contact_list_ids:
        try:
            from app.services.marketing_lists import list_members_for_send  # type: ignore[import]
            members = list_members_for_send(owner_id, list_id)
            party_ids.extend(members)
        except ImportError:
            pass
        except Exception as exc:
            logger.warning("list_members_for_send failed for list %s: %s", list_id, exc)

    # Deduplicate
    seen: set = set()
    unique_parties: List[str] = []
    for p in party_ids:
        if p not in seen:
            seen.add(p)
            unique_parties.append(p)

    # Parse variants for A/B split (CMP-007)
    variants = _parse_variants(campaign.get("variants"))

    # Resolve questionnaire URL / survey merge var
    survey_url: Optional[str] = campaign.get("questionnaire_url")

    total_resolved = len(unique_parties)
    total_sent = 0
    total_skipped = 0

    for party_id in unique_parties:
        # Opt-out check (CMP-004, MKT-007)
        try:
            from app.services.cart_reminders import is_user_opted_out
            if is_user_opted_out(party_id):
                total_skipped += 1
                continue
        except Exception:
            pass

        # Build merge vars (CMP-008)
        extra_vars: Dict[str, str] = {}

        # CMP-004: unsubscribe URL
        unsubscribe_url: Optional[str] = None
        if campaign_type == "email":
            try:
                from app.services.marketing_unsubscribe import generate_unsubscribe_url
                unsubscribe_url = generate_unsubscribe_url(party_id, campaign_id)
                extra_vars["unsubscribe_url"] = unsubscribe_url
            except Exception:
                pass

        # CMP-005: survey URL
        if survey_url:
            extra_vars["survey_url"] = survey_url

        # CMP-007: A/B variant assignment
        variant: Optional[Dict[str, Any]] = None
        variant_id: Optional[str] = None
        if variants:
            variant = _assign_variant(party_id, campaign_id, variants)
            variant_id = variant.get("variant_id") or variant.get("id")

        merge_vars = _build_merge_vars(party_id, campaign_id, extra=extra_vars)

        # CMP-007: variant subject override
        subject = campaign.get("name", "Campaign")
        if variant and variant.get("subject_override"):
            try:
                from app.services.notification_templates import _render
                rendered, _ = _render(variant["subject_override"], merge_vars)
                subject = rendered or subject
            except Exception:
                pass

        # Per-variant template override (CMP-007)
        email_tpl_id = campaign.get("email_template_id")
        if variant and variant.get("email_template_id"):
            email_tpl_id = variant["email_template_id"]

        # Build message body (CMP-002/003/004/005/008)
        campaign_for_send = dict(campaign)
        campaign_for_send["email_template_id"] = email_tpl_id
        campaign_for_send["campaign_type"] = campaign_type

        merge_vars["subject"] = subject
        body_text, body_html = _build_message_body(campaign_for_send, merge_vars, owner_id=owner_id)

        ok = _try_send_one(
            campaign_id=campaign_id,
            campaign_type=campaign_type,
            party_id=party_id,
            subject=subject,
            body_text=body_text,
            body_html=body_html,
            dry_run=dry_run,
            now=now,
            snapshot_ts=snap_ts,
            send_id_prefix=f"{snap_ts}#{party_id}",
            variant_id=variant_id,
        )
        if ok:
            total_sent += 1
        else:
            total_skipped += 1

    if not dry_run and total_sent > 0:
        try:
            T.crm_campaigns.update_item(
                Key={"pk": f"OWNER#{owner_id}", "sk": f"MKTCAMP#{campaign_id}"},
                UpdateExpression="SET #st = :st, last_sent_at = :ts",
                ExpressionAttributeNames={"#st": "status"},
                ExpressionAttributeValues={":st": "active", ":ts": now},
            )
        except Exception:
            pass

    try:
        from app.services.alerts import audit_event
        audit_event(
            "marketing.campaign.sent",
            owner_id,
            campaign_id=campaign_id,
            total_sent=total_sent,
            total_skipped=total_skipped,
            dry_run=dry_run,
        )
    except Exception:
        pass

    return {
        "campaign_id": campaign_id,
        "total_resolved": total_resolved,
        "total_sent": total_sent,
        "total_skipped": total_skipped,
        "dry_run": dry_run,
    }


# ─── Attribution rollup (CMP-007) ────────────────────────────────────────────


def get_campaign_attribution(campaign_id: str, owner_id: str) -> Dict[str, Any]:
    """Return attribution stats for a campaign (opens, clicks, email_sent)."""
    from boto3.dynamodb.conditions import Key

    # Verify access
    resp = T.crm_campaigns.get_item(
        Key={"pk": f"OWNER#{owner_id}", "sk": f"MKTCAMP#{campaign_id}"}
    )
    if not resp.get("Item"):
        raise HTTPException(404, detail="Campaign not found")
    if resp["Item"].get("owner_id") != owner_id:
        raise HTTPException(403, detail="Access denied")

    # Count send-log rows
    total_sent = 0
    email_sent = 0
    kw = {
        "IndexName": "ByCampaignSentAt",
        "KeyConditionExpression": Key("campaign_id").eq(campaign_id),
    }
    last_key = None
    while True:
        if last_key:
            kw["ExclusiveStartKey"] = last_key
        r = T.crm_campaign_send_log.query(**kw)
        for row in r.get("Items", []):
            total_sent += 1
            if row.get("email_sent"):
                email_sent += 1
        last_key = r.get("LastEvaluatedKey")
        if not last_key:
            break

    # Open/click counts from tracking codes table
    open_count = 0
    click_count = 0
    code_slug = resp["Item"].get("tracking_code")
    if code_slug:
        try:
            meta_resp = T.marketing_tracking_codes.get_item(
                Key={"pk": f"TRACK#{code_slug}", "sk": "META"}
            )
            meta = meta_resp.get("Item") or {}
            open_count = int(meta.get("open_count", 0))
            click_count = int(meta.get("visit_count", 0)) - open_count
        except Exception:
            pass

    open_rate = open_count / total_sent if total_sent > 0 else 0.0
    click_rate = click_count / total_sent if total_sent > 0 else 0.0

    return {
        "campaign_id": campaign_id,
        "total_sent": total_sent,
        "email_sent": email_sent,
        "open_count": open_count,
        "open_rate": open_rate,
        "click_count": click_count,
        "click_rate": click_rate,
    }


def get_ab_results(campaign_id: str, owner_id: str) -> Dict[str, Any]:
    """Return A/B test results with statistical significance (CMP-007)."""
    from boto3.dynamodb.conditions import Key

    resp = T.crm_campaigns.get_item(
        Key={"pk": f"OWNER#{owner_id}", "sk": f"MKTCAMP#{campaign_id}"}
    )
    campaign = resp.get("Item")
    if not campaign:
        raise HTTPException(404, detail="Campaign not found")
    if campaign.get("owner_id") != owner_id:
        raise HTTPException(403, detail="Access denied")

    variants = _parse_variants(campaign.get("variants")) or []
    if not variants:
        raise HTTPException(400, detail="Campaign has no A/B variants")

    # Count sends per variant
    variant_sent: Dict[str, int] = {}
    last_key = None
    kw: Dict[str, Any] = {
        "IndexName": "ByCampaignSentAt",
        "KeyConditionExpression": Key("campaign_id").eq(campaign_id),
    }
    while True:
        if last_key:
            kw["ExclusiveStartKey"] = last_key
        r = T.crm_campaign_send_log.query(**kw)
        for row in r.get("Items", []):
            vid = row.get("variant_id", "control")
            variant_sent[vid] = variant_sent.get(vid, 0) + 1
        last_key = r.get("LastEvaluatedKey")
        if not last_key:
            break

    variant_stats = []
    for v in variants:
        vid = v.get("variant_id") or v.get("id", "")
        sent = variant_sent.get(vid, 0)
        variant_stats.append({
            "variant_id": vid,
            "label": v.get("label") or v.get("name", vid),
            "sent": sent,
            "opens": 0,
            "clicks": 0,
            "open_rate": 0.0,
            "click_rate": 0.0,
        })

    # Compute significance between first two variants (CMP-007)
    significance = None
    if len(variant_stats) >= 2:
        try:
            from app.services.ad_optimization import ab_test_significance
            a = variant_stats[0]
            b = variant_stats[1]
            significance = ab_test_significance(
                variant_a={"impressions": a["sent"], "clicks": a["opens"]},
                variant_b={"impressions": b["sent"], "clicks": b["opens"]},
            )
        except Exception:
            pass

    try:
        from app.services.alerts import audit_event
        audit_event("marketing.ab_test.results_queried", owner_id, campaign_id=campaign_id)
    except Exception:
        pass

    return {
        "campaign_id": campaign_id,
        "variant_stats": variant_stats,
        "significance": significance,
    }
