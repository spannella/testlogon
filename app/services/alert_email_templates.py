"""HTML email templates for common notification events.

Each template function returns a (subject, html_body) tuple.
Uses simple Python f-strings — no Jinja2 or external dependency.

When ``send_alert_email()`` is called in the dispatch pipeline,
``render_alert_email_template()`` is tried first.  If it returns
``None``, the caller falls back to the existing plain-text body.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple


def _wrap_html(title: str, body_html: str) -> str:
    """Wrap body content in a minimal responsive email template."""
    return f"""\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
body {{ margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f4f4f5; }}
.container {{ max-width: 560px; margin: 0 auto; padding: 32px 16px; }}
.card {{ background: #fff; border-radius: 8px; padding: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
.header {{ color: #18181b; font-size: 18px; font-weight: 600; margin: 0 0 16px; }}
.body {{ color: #3f3f46; font-size: 14px; line-height: 1.6; }}
.footer {{ margin-top: 24px; padding-top: 16px; border-top: 1px solid #e4e4e7; color: #a1a1aa; font-size: 12px; }}
.highlight {{ color: #18181b; font-weight: 600; }}
</style>
</head>
<body>
<div class="container"><div class="card">
{body_html}
<div class="footer">You received this email because of your notification preferences. You can update your settings at any time.</div>
</div></div>
</body>
</html>"""


def _template_new_message(details: Dict[str, Any]) -> Tuple[str, str]:
    sender = str(details.get("actor_display_name") or details.get("from") or "Someone")
    preview = str(details.get("text_preview") or details.get("text") or "")[:100]
    subject = f"New message from {sender}"
    body = f"""\
<p class="header">New Message</p>
<div class="body">
<p>You have a new message from <span class="highlight">{sender}</span>.</p>
{f'<p style="background:#f4f4f5;padding:12px;border-radius:6px;font-style:italic;">{preview}</p>' if preview else ''}
</div>"""
    return subject, _wrap_html(subject, body)


def _template_payment_received(details: Dict[str, Any]) -> Tuple[str, str]:
    sender = str(details.get("actor_display_name") or details.get("from") or "Someone")
    amount_cents = details.get("amount_cents") or details.get("amount") or 0
    try:
        amount = f"${int(amount_cents) / 100:.2f}"
    except (ValueError, TypeError):
        amount = str(amount_cents)
    subject = f"You received {amount} from {sender}"
    body = f"""\
<p class="header">Payment Received</p>
<div class="body">
<p>You received <span class="highlight">{amount}</span> from <span class="highlight">{sender}</span>.</p>
</div>"""
    return subject, _wrap_html(subject, body)


def _template_subscription_started(details: Dict[str, Any]) -> Tuple[str, str]:
    username = str(details.get("actor_display_name") or details.get("subscriber") or details.get("username") or "Someone")
    subject = f"New subscriber: {username}"
    body = f"""\
<p class="header">New Subscriber</p>
<div class="body">
<p><span class="highlight">{username}</span> has subscribed to your content.</p>
</div>"""
    return subject, _wrap_html(subject, body)


def _template_refund_processed(details: Dict[str, Any]) -> Tuple[str, str]:
    amount_cents = details.get("amount_cents") or details.get("amount") or 0
    try:
        amount = f"${int(amount_cents) / 100:.2f}"
    except (ValueError, TypeError):
        amount = str(amount_cents)
    reason = str(details.get("reason") or "")
    subject = f"Your refund of {amount} has been processed"
    body = f"""\
<p class="header">Refund Processed</p>
<div class="body">
<p>Your refund of <span class="highlight">{amount}</span> has been processed.</p>
{f'<p>Reason: {reason}</p>' if reason else ''}
<p>The funds will be returned to your original payment method within 5-10 business days.</p>
</div>"""
    return subject, _wrap_html(subject, body)


def _template_security_alert(details: Dict[str, Any]) -> Tuple[str, str]:
    description = str(details.get("title") or details.get("event") or "A security event occurred")
    ip = str(details.get("ip") or "")
    user_agent = str(details.get("user_agent") or "")[:120]
    subject = f"Security alert: {description[:60]}"
    extra_lines = ""
    if ip:
        extra_lines += f"<p><strong>IP Address:</strong> {ip}</p>"
    if user_agent:
        extra_lines += f"<p><strong>Device:</strong> {user_agent}</p>"
    body = f"""\
<p class="header">Security Alert</p>
<div class="body">
<p style="color:#dc2626;font-weight:600;">{description}</p>
{extra_lines}
<p>If this was not you, please secure your account immediately by changing your password and reviewing your active sessions.</p>
</div>"""
    return subject, _wrap_html(subject, body)


# ─── Dispatch map ────────────────────────────────────────────────

_TEMPLATE_MAP = {
    # Messaging
    "new_message": _template_new_message,
    "messaging.new_message": _template_new_message,

    # Billing / tips
    "post_tip": _template_payment_received,
    "message_tip": _template_payment_received,
    "billing.tip_received": _template_payment_received,
    "payment_received": _template_payment_received,

    # Subscriptions
    "subscription_started": _template_subscription_started,

    # Refunds
    "refund_processed": _template_refund_processed,

    # Security
    "security_event": _template_security_alert,
    "login_failure": _template_security_alert,
    "mfa_failure": _template_security_alert,
    "access_denied": _template_security_alert,
    "device_new": _template_security_alert,
    "device_location_mismatch": _template_security_alert,
    "rate_limited": _template_security_alert,
}


def render_alert_email_template(
    event_type: str,
    details: Dict[str, Any],
) -> Optional[Tuple[str, str]]:
    """Render an HTML email template for the given event type.

    Returns ``(subject, html_body)`` if a template exists, else ``None``.
    The caller should fall back to plain text when this returns ``None``.
    """
    fn = _TEMPLATE_MAP.get(event_type)
    if fn is None:
        return None
    try:
        return fn(details)
    except Exception:
        return None
