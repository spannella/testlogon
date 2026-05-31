"""Notification template management (ADMIN-002).

CRUD for email and SMS notification templates, plus preview and test send.

Table: admin_messaging_templates
  PK: TEMPLATE#{template_id}
  SK: META
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Attr

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

_VAR_RE = re.compile(r"\{\{\s*([a-zA-Z0-9_]+)\s*\}\}")

# In-memory rate limiter for test sends: admin_sub -> list[ts]
_test_send_log: Dict[str, List[int]] = {}


# ──────────────────────────────────────────────────────────────────────
# Default templates (seeded into DDB at startup)
# ──────────────────────────────────────────────────────────────────────

_DEFAULT_TEMPLATES: List[Dict[str, Any]] = [
    {
        "template_id": "email_welcome",
        "channel": "email",
        "name": "Welcome Email",
        "subject": "Welcome to {{platform_name}}!",
        "body": (
            "<h1>Welcome, {{user_name}}!</h1>"
            "<p>Thanks for joining {{platform_name}}. "
            "Sign in any time at <a href=\"{{login_url}}\">{{login_url}}</a>.</p>"
        ),
        "variables": ["user_name", "platform_name", "login_url"],
    },
    {
        "template_id": "email_password_reset",
        "channel": "email",
        "name": "Password Reset",
        "subject": "Reset your {{platform_name}} password",
        "body": (
            "<h1>Password reset</h1>"
            "<p>Hi {{user_name}}, use the link below to reset your password:</p>"
            "<p><a href=\"{{reset_url}}\">{{reset_url}}</a></p>"
            "<p>This link expires in {{expires_minutes}} minutes.</p>"
        ),
        "variables": ["user_name", "platform_name", "reset_url", "expires_minutes"],
    },
    {
        "template_id": "sms_verification",
        "channel": "sms",
        "name": "SMS Verification Code",
        "subject": None,
        "body": "Your verification code is {{code}}. Expires in {{expires_minutes}} minutes.",
        "variables": ["code", "expires_minutes"],
    },
    {
        "template_id": "sms_alert",
        "channel": "sms",
        "name": "SMS Security Alert",
        "subject": None,
        "body": "{{platform_name}} alert: {{message}}",
        "variables": ["platform_name", "message"],
    },
]


def _pk(template_id: str) -> str:
    return f"TEMPLATE#{template_id}"


def _to_out(item: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a DDB item into the public template shape."""
    return {
        "template_id": item.get("template_id", ""),
        "channel": item.get("channel", "email"),
        "name": item.get("name", item.get("template_id", "")),
        "subject": item.get("subject"),
        "body": item.get("body", "") or "",
        "variables": list(item.get("variables", []) or []),
        "active": bool(item.get("active", True)),
        "updated_at": int(item["updated_at"]) if item.get("updated_at") is not None else None,
        "updated_by": item.get("updated_by"),
    }


# ──────────────────────────────────────────────────────────────────────
# Seeding
# ──────────────────────────────────────────────────────────────────────


def seed_default_templates() -> int:
    """Seed default templates into DDB if not already present.

    Returns the number of templates created. Idempotent: existing
    templates (by template_id) are left untouched.
    """
    created = 0
    ts = now_ts()
    for tpl in _DEFAULT_TEMPLATES:
        tid = tpl["template_id"]
        try:
            existing = T.admin_messaging_templates.get_item(
                Key={"pk": _pk(tid), "sk": "META"},
                ProjectionExpression="pk",
            )
            if "Item" in existing:
                continue
            T.admin_messaging_templates.put_item(Item={
                "pk": _pk(tid),
                "sk": "META",
                "template_id": tid,
                "channel": tpl["channel"],
                "name": tpl["name"],
                "subject": tpl.get("subject"),
                "body": tpl.get("body", ""),
                "variables": list(tpl.get("variables", [])),
                "active": True,
                "updated_at": ts,
                "updated_by": None,
            })
            created += 1
        except Exception:
            logger.exception("Failed to seed template %s", tid)
    if created:
        logger.info("Seeded %d default notification templates", created)
    return created


# ──────────────────────────────────────────────────────────────────────
# CRUD
# ──────────────────────────────────────────────────────────────────────


def list_templates(*, channel: Optional[str] = None) -> List[Dict[str, Any]]:
    """List all notification templates, optionally filtered by channel."""
    try:
        resp = T.admin_messaging_templates.scan(
            FilterExpression=Attr("sk").eq("META"),
            Limit=1000,
        )
        items = resp.get("Items", [])
        while resp.get("LastEvaluatedKey"):
            resp = T.admin_messaging_templates.scan(
                FilterExpression=Attr("sk").eq("META"),
                Limit=1000,
                ExclusiveStartKey=resp["LastEvaluatedKey"],
            )
            items.extend(resp.get("Items", []))
    except Exception:
        logger.exception("Failed to list templates")
        items = []

    out = [_to_out(it) for it in items if it.get("template_id")]
    if channel:
        out = [t for t in out if t["channel"] == channel]
    out.sort(key=lambda t: t["template_id"])
    return out


def get_template(template_id: str) -> Optional[Dict[str, Any]]:
    """Get a template by ID, or None if not found."""
    try:
        resp = T.admin_messaging_templates.get_item(
            Key={"pk": _pk(template_id), "sk": "META"}
        )
    except Exception:
        logger.exception("Failed to get template %s", template_id)
        return None
    item = resp.get("Item")
    if not item:
        return None
    return _to_out(item)


def update_template(
    template_id: str,
    *,
    admin_sub: str,
    subject: Any = ...,
    body: Optional[str] = None,
    active: Optional[bool] = None,
) -> Optional[Dict[str, Any]]:
    """Update editable template fields. Returns updated template or None if not found.

    ``template_id`` and ``channel`` are immutable. ``subject`` uses a sentinel
    default (``...``) so that an explicit ``None``/`""` can clear it while an
    omitted value leaves it unchanged.
    """
    current = get_template(template_id)
    if current is None:
        return None

    set_parts: List[str] = ["updated_at = :ua", "updated_by = :ub"]
    names: Dict[str, str] = {}
    values: Dict[str, Any] = {":ua": now_ts(), ":ub": admin_sub}

    if subject is not ...:
        set_parts.append("#subject = :subject")
        names["#subject"] = "subject"
        values[":subject"] = subject
    if body is not None:
        set_parts.append("#body = :body")
        names["#body"] = "body"
        values[":body"] = body
    if active is not None:
        set_parts.append("active = :active")
        values[":active"] = bool(active)

    kwargs: Dict[str, Any] = {
        "Key": {"pk": _pk(template_id), "sk": "META"},
        "UpdateExpression": "SET " + ", ".join(set_parts),
        "ExpressionAttributeValues": values,
        "ReturnValues": "ALL_NEW",
    }
    if names:
        kwargs["ExpressionAttributeNames"] = names

    try:
        resp = T.admin_messaging_templates.update_item(**kwargs)
        logger.info(
            "admin_template_updated template_id=%s admin_sub=%s", template_id, admin_sub
        )
        return _to_out(resp.get("Attributes", {}))
    except Exception:
        logger.exception("Failed to update template %s", template_id)
        return get_template(template_id)


# ──────────────────────────────────────────────────────────────────────
# Render / preview / test send
# ──────────────────────────────────────────────────────────────────────


def _render(text: Optional[str], sample_vars: Dict[str, str]) -> Tuple[Optional[str], List[str]]:
    """Render a single template string. Returns (rendered, missing_vars)."""
    if text is None:
        return None, []
    missing: List[str] = []

    def repl(match: "re.Match[str]") -> str:
        var = match.group(1)
        if var in sample_vars and sample_vars[var] != "":
            return str(sample_vars[var])
        if var not in missing:
            missing.append(var)
        return match.group(0)

    rendered = _VAR_RE.sub(repl, text)
    return rendered, missing


def preview_template(
    template_id: str, *, sample_vars: Optional[Dict[str, str]] = None
) -> Optional[Dict[str, Any]]:
    """Render a template with sample variables for preview."""
    tpl = get_template(template_id)
    if tpl is None:
        return None
    sample_vars = sample_vars or {}

    rendered_subject, missing_subj = _render(tpl.get("subject"), sample_vars)
    rendered_body, missing_body = _render(tpl.get("body", ""), sample_vars)

    missing: List[str] = []
    for v in missing_subj + missing_body:
        if v not in missing:
            missing.append(v)

    return {
        "template_id": template_id,
        "channel": tpl["channel"],
        "rendered_subject": rendered_subject,
        "rendered_body": rendered_body or "",
        "missing_vars": missing,
    }


def test_send_allowed(admin_sub: str) -> bool:
    """Return True if the admin is under the per-hour test-send rate limit."""
    limit = S.admin_messaging_dashboard_test_send_limit_per_hour
    cutoff = now_ts() - 3600
    recent = [t for t in _test_send_log.get(admin_sub, []) if t >= cutoff]
    _test_send_log[admin_sub] = recent
    return len(recent) < limit


def _record_test_send(admin_sub: str) -> None:
    _test_send_log.setdefault(admin_sub, []).append(now_ts())


def test_send(
    template_id: str,
    *,
    recipient: str,
    admin_sub: str,
    sample_vars: Optional[Dict[str, str]] = None,
) -> Optional[Dict[str, Any]]:
    """Send a test notification using the template's channel.

    In dev mode this records to the channel dev-log instead of dispatching
    a real notification. Returns the result dict, or None if the template
    does not exist. Raises ``PermissionError`` if rate limited.
    """
    tpl = get_template(template_id)
    if tpl is None:
        return None

    if not test_send_allowed(admin_sub):
        logger.warning(
            "admin_template_test_rate_limited admin_sub=%s template_id=%s",
            admin_sub, template_id,
        )
        raise PermissionError("rate_limited")

    rendered = preview_template(template_id, sample_vars=sample_vars) or {}
    body = rendered.get("rendered_body", "") or ""
    subject = rendered.get("rendered_subject") or "(test)"
    channel = tpl["channel"]
    ts = now_ts()

    try:
        if channel == "email":
            from app.services import email_delivery
            email_delivery.record_dev_email([recipient], subject)
        else:
            from app.services import sms_delivery
            sms_delivery.record_sms_dev_logged(recipient, body)
    except Exception:
        logger.exception("Failed to record test send for %s", template_id)

    _record_test_send(admin_sub)
    logger.info(
        "admin_template_test_sent template_id=%s channel=%s recipient=%s admin_sub=%s",
        template_id, channel, recipient, admin_sub,
    )
    return {
        "ok": True,
        "template_id": template_id,
        "channel": channel,
        "recipient": recipient,
        "sent_at": ts,
    }
