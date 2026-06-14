"""CMP-002 — HTML email templates for marketing campaigns with merge-field substitution.

New service module. Owns T.marketing_email_templates.
"""
from __future__ import annotations

import hashlib
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from fastapi import HTTPException

from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# Reuse the same regex the notification_templates module uses
_VAR_RE = re.compile(r"\{\{\s*([a-zA-Z0-9_]+)\s*\}\}")


def _template_id(owner_id: str, name: str) -> str:
    return hashlib.sha256(f"{owner_id}|{name}".encode()).hexdigest()[:16]


def _extract_variables(subject: str, body: str) -> List[str]:
    return sorted(set(_VAR_RE.findall(subject + body)))


def _item_to_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "template_id": item.get("template_id", ""),
        "owner_id": item.get("owner_id", ""),
        "name": item.get("name", ""),
        "subject_template": item.get("subject_template", ""),
        "body_html_template": item.get("body_html_template", ""),
        "variables": list(item.get("variables") or []),
        "status": item.get("status", "draft"),
        "created_at": int(item.get("created_at", 0)),
        "updated_at": int(item.get("updated_at", 0)),
    }


def create_template(owner_id: str, data: Any) -> Dict[str, Any]:
    """Create an email template. Raises 409 on duplicate name for this owner."""
    template_id = _template_id(owner_id, data.name)
    ts = now_ts()
    variables = _extract_variables(data.subject_template, data.body_html_template)

    item: Dict[str, Any] = {
        "pk": f"TMPL#{template_id}",
        "sk": "META",
        "template_id": template_id,
        "owner_id": owner_id,
        "name": data.name,
        "subject_template": data.subject_template,
        "body_html_template": data.body_html_template,
        "variables": variables,
        "status": "draft",
        "created_at": ts,
        "updated_at": ts,
    }

    try:
        T.marketing_email_templates.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(pk)",
        )
    except Exception as exc:
        if "ConditionalCheckFailedException" in type(exc).__name__:
            raise HTTPException(409, detail="Template name already exists for this owner")
        raise

    try:
        from app.services.alerts import audit_event
        audit_event("marketing.template.created", owner_id, template_id=template_id)
    except Exception:
        pass

    return _item_to_out(item)


def get_template(owner_id: str, template_id: str) -> Optional[Dict[str, Any]]:
    """Fetch a template by id. Returns None when not found. Raises 403 on ownership mismatch."""
    resp = T.marketing_email_templates.get_item(
        Key={"pk": f"TMPL#{template_id}", "sk": "META"}
    )
    item = resp.get("Item")
    if not item:
        return None
    if item.get("owner_id") != owner_id:
        raise HTTPException(403, detail="Access denied")
    return _item_to_out(item)


def list_templates(
    owner_id: str,
    *,
    limit: int = 20,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    from boto3.dynamodb.conditions import Key

    kwargs: Dict[str, Any] = {
        "IndexName": "ByOwnerCreatedAt",
        "KeyConditionExpression": Key("owner_id").eq(owner_id),
        "Limit": limit,
        "ScanIndexForward": False,
    }
    if cursor:
        try:
            kwargs["ExclusiveStartKey"] = decode_cursor(cursor)
        except Exception:
            pass

    resp = T.marketing_email_templates.query(**kwargs)
    items = [_item_to_out(i) for i in resp.get("Items", [])]
    last_key = resp.get("LastEvaluatedKey")
    next_cursor = encode_cursor(last_key) if last_key else None
    return {"templates": items, "cursor": next_cursor, "count": len(items)}


def update_template(owner_id: str, template_id: str, data: Any) -> Dict[str, Any]:
    resp = T.marketing_email_templates.get_item(
        Key={"pk": f"TMPL#{template_id}", "sk": "META"}
    )
    item = resp.get("Item")
    if not item:
        raise HTTPException(404, detail="Template not found")
    if item.get("owner_id") != owner_id:
        raise HTTPException(403, detail="Access denied")

    ts = now_ts()
    updates = ["#upd = :upd"]
    names: Dict[str, str] = {"#upd": "updated_at"}
    vals: Dict[str, Any] = {":upd": ts}

    new_subject = getattr(data, "subject_template", None)
    new_body = getattr(data, "body_html_template", None)
    new_name = getattr(data, "name", None)
    new_status = getattr(data, "status", None)

    if new_name is not None:
        updates.append("#name = :name")
        names["#name"] = "name"
        vals[":name"] = new_name

    if new_status is not None:
        updates.append("#status = :status")
        names["#status"] = "status"
        vals[":status"] = new_status

    subject_for_vars = new_subject if new_subject is not None else item.get("subject_template", "")
    body_for_vars = new_body if new_body is not None else item.get("body_html_template", "")

    if new_subject is not None:
        updates.append("#subj = :subj")
        names["#subj"] = "subject_template"
        vals[":subj"] = new_subject

    if new_body is not None:
        updates.append("#body = :body")
        names["#body"] = "body_html_template"
        vals[":body"] = new_body

    if new_subject is not None or new_body is not None:
        variables = _extract_variables(subject_for_vars, body_for_vars)
        updates.append("#vars = :vars")
        names["#vars"] = "variables"
        vals[":vars"] = variables

    T.marketing_email_templates.update_item(
        Key={"pk": f"TMPL#{template_id}", "sk": "META"},
        UpdateExpression="SET " + ", ".join(updates),
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=vals,
    )

    try:
        from app.services.alerts import audit_event
        audit_event("marketing.template.updated", owner_id, template_id=template_id)
    except Exception:
        pass

    return get_template(owner_id, template_id) or {}


def delete_template(owner_id: str, template_id: str) -> None:
    resp = T.marketing_email_templates.get_item(
        Key={"pk": f"TMPL#{template_id}", "sk": "META"}
    )
    item = resp.get("Item")
    if not item:
        raise HTTPException(404, detail="Template not found")
    if item.get("owner_id") != owner_id:
        raise HTTPException(403, detail="Access denied")

    T.marketing_email_templates.delete_item(
        Key={"pk": f"TMPL#{template_id}", "sk": "META"}
    )
    try:
        from app.services.alerts import audit_event
        audit_event("marketing.template.deleted", owner_id, template_id=template_id)
    except Exception:
        pass


def render_template(
    template_item: Dict[str, Any],
    merge_vars: Dict[str, str],
) -> Tuple[str, str]:
    """Render template with merge vars. Returns (rendered_subject, wrapped_html_body)."""
    try:
        from app.services.notification_templates import _render
        rendered_subject, _ = _render(template_item["subject_template"], merge_vars)
        rendered_body, missing = _render(template_item["body_html_template"], merge_vars)
    except Exception:
        rendered_subject = template_item.get("subject_template", "")
        rendered_body = template_item.get("body_html_template", "")
        missing = []

    try:
        from app.services.alert_email_templates import _wrap_html
        wrapped = _wrap_html(rendered_subject or "", rendered_body or "")
    except Exception:
        wrapped = rendered_body or ""

    return rendered_subject or "", wrapped


def preview_template(
    owner_id: str,
    template_id: str,
    sample_vars: Dict[str, str],
) -> Dict[str, Any]:
    """Preview template rendering without any side effects."""
    tmpl = get_template(owner_id, template_id)
    if not tmpl:
        raise HTTPException(404, detail="Template not found")

    try:
        from app.services.notification_templates import _render
        rendered_subject, missing_s = _render(tmpl["subject_template"], sample_vars)
        rendered_body, missing_b = _render(tmpl["body_html_template"], sample_vars)
    except Exception:
        rendered_subject = tmpl["subject_template"]
        rendered_body = tmpl["body_html_template"]
        missing_s = []
        missing_b = []

    try:
        from app.services.alert_email_templates import _wrap_html
        wrapped = _wrap_html(rendered_subject or "", rendered_body or "")
    except Exception:
        wrapped = rendered_body or ""

    missing = sorted(set(list(missing_s) + list(missing_b)))
    return {
        "subject": rendered_subject or "",
        "body_html": wrapped,
        "variables": tmpl["variables"],
        "missing_vars": missing,
    }
