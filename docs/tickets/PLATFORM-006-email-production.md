# PLATFORM-006: Email Delivery Production Config

**Ticket**: PLATFORM-006
**Author**: Engineering
**Status**: Implemented
**Date**: 2026-05-27
**Priority**: High
**Estimated effort**: 8-10 days

---

## 1. Executive Summary

The platform has a complete email delivery path: `send_alert_email()` in `app/services/alerts.py:332-353` uses boto3 SES to send emails when not in dev mode. In dev mode, it logs to `.logs/dev/emails.log` (`alerts.py:340`). There are HTML email templates for at least 5 event categories via `alert_email_templates.py` (165 lines). The alert preferences UI (`AlertPrefs.tsx:32-36`) allows users to add email addresses and select which event types trigger email delivery.

However, the system is not configured for real delivery outside of production:

- `ALERTS_EMAIL_ENABLED` defaults to `"0"` (`app/core/settings.py:186`), meaning email is disabled unless explicitly turned on
- No SES domain verification, no DKIM/SPF configuration documented for staging
- No delivery status tracking: `send_alert_email()` catches all exceptions silently (`alerts.py:352-353`)
- No bounce/complaint handling: SES notifications for bounces and complaints are not configured or consumed
- No delivery metrics: no counter for emails sent, failed, bounced, or complained
- No email delivery dashboard for admins to monitor delivery health

This ticket covers enabling email delivery in staging with proper SES configuration, implementing delivery status tracking through SES SNS notifications stored in DynamoDB, adding delivery health metrics, and building an admin dashboard to monitor email delivery performance.

---

## 2. Detailed Problem Analysis

### 2.1 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| User | I want to receive email alerts for security events. | Email sent via SES when security alert fires. |
| User | I want delivery receipts so I know my email was sent. | Alert history shows delivery status (sent, bounced, failed). |
| User | I want to stop receiving emails by marking them as spam. | Complaint is processed; email address suppressed automatically. |
| Admin | I want to see email delivery success/failure rates. | Admin dashboard shows sent/bounced/complained metrics. |
| Admin | I want to see which emails bounced so I can clean up bad addresses. | Bounce list with email address, reason, and timestamp. |
| Admin | I want to monitor complaint rates to maintain sender reputation. | Complaint rate metric with threshold alerts. |
| Admin | I want to unsuppress an incorrectly suppressed address. | Admin endpoint removes email from suppression list. |
| Admin | I want to see aggregate stats over configurable time windows. | Stats endpoint accepts `days` parameter (1-90). |
| Ops | I want staging to send real emails so we can test the full flow. | Staging environment has `ALERTS_EMAIL_ENABLED=1` with SES sandbox. |
| Ops | I want Prometheus metrics for email delivery health. | `/metrics` includes `email_delivery_total{status}` counter. |

### 2.2 Pain Points

1. **Silent failures**: `send_alert_email()` wraps the entire SES call in a bare `except Exception: pass` (`alerts.py:352-353`). If SES rejects the email (bad address, quota exceeded, domain not verified), the failure is silently swallowed. No log line, no metric, no retry.
2. **No delivery feedback loop**: SES provides delivery notifications (success, bounce, complaint) via SNS topics. These are not configured, so the platform has no way to know if an email was actually delivered to the recipient's inbox.
3. **No bounce handling**: SES penalizes senders with high bounce rates (suspension threshold: 5%). Without tracking bounces, the platform cannot suppress emails to invalid addresses, risking SES sending quota suspension.
4. **No complaint handling**: SES requires complaint rates below 0.1%. Without tracking complaints, the platform cannot unsubscribe users who mark emails as spam, risking account-level SES suspension.
5. **SES client created per-call**: `alerts.py:346` creates a new `boto3.client("ses")` on every email send. This wastes connection establishment time (~50ms) and does not benefit from HTTP connection pooling.
6. **Staging untested**: Email delivery has never been tested in a staging environment. The first real delivery will be production, which is a significant risk for a security-critical channel.
7. **No per-message tracking**: There is no DDB record linking a sent email to its SES `MessageId`, making it impossible to correlate SES bounce/complaint notifications back to the original alert.
8. **Rate limiting exists but is opaque**: `can_send_alert_channel(user_sub, "email")` in `app/services/rate_limit.py:322-323` enforces `alerts_email_max_per_window` (default 20, `settings.py:187`) over `alerts_email_window_seconds` (default 3600, `settings.py:188`), but rate-limited sends produce no visible feedback to the user or admin.

---

## 3. Current State Analysis

### 3.1 Email Sending Function

`app/services/alerts.py:332-353`:

```python
def send_alert_email(to_emails: List[str], subject: str, body_text: str) -> None:
    if not to_emails:
        return
    if S.dev_mode:
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        for addr in to_emails:
            entry = f"[{ts}] ALERT_EMAIL TO={addr}\n  Subject: {subject}\n  Body: {body_text}\n\n"
            _write_dev_log(S.dev_email_log, entry)
        return
    if not S.alerts_email_enabled or not S.alerts_from_email:
        return
    try:
        import boto3
        ses = boto3.client("ses")
        ses.send_email(
            Source=S.alerts_from_email,
            Destination={"ToAddresses": to_emails},
            Message={"Subject": {"Data": subject[:120]}, "Body": {"Text": {"Data": body_text[:8000]}}},
        )
    except Exception:
        pass
```

Key observations:
- Dev mode: writes to `.logs/dev/emails.log` via `_write_dev_log()` (`alerts.py:322-329`)
- Non-dev: checks `S.alerts_email_enabled` (default `False`, `settings.py:186`) and `S.alerts_from_email` (default empty, `settings.py:185`)
- SES client created per-call with no region specification (defaults to boto3 session region)
- Exception handling: bare `except Exception: pass` -- **no logging, no metric, no retry**
- Subject truncated to 120 chars, body to 8000 chars
- Returns `None` always -- no way for the caller to know if the email was sent

### 3.2 Dev Mode Logging

`app/services/alerts.py:322-329`:

```python
def _write_dev_log(path: str, entry: str) -> None:
    try:
        import os
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a") as f:
            f.write(entry)
    except Exception:
        pass
```

The dev log path is configurable via `S.dev_email_log` (default `.logs/dev/emails.log`, `settings.py:246`). The Dev Tools UI reads this log via `S.devtools_email_log_path` (`settings.py:249`).

### 3.3 Email Settings

`app/core/settings.py`:

| Setting | Line | Default | Description |
|---------|------|---------|-------------|
| `ses_from_email` | 179 | `""` | SES module-level client trigger (in `aws.py:12-19`) |
| `alerts_from_email` | 185 | `""` | Sender address for alert emails |
| `alerts_email_enabled` | 186 | `"0"` (disabled) | Master switch for email delivery |
| `alerts_email_max_per_window` | 187 | `20` | Rate limit: max emails per window |
| `alerts_email_window_seconds` | 188 | `3600` | Rate limit: window size (1 hour) |
| `dev_email_log` | 246 | `.logs/dev/emails.log` | Dev mode email log path |
| `devtools_email_log_path` | 249 | (same as dev_email_log) | Dev Tools UI discovery path |
| `notification_email_templates_enabled` | 1314 | `True` | Enable NOTIFY-001 HTML templates |

### 3.4 SES Client in aws.py

`app/core/aws.py:11-19`:

```python
ses = None
if S.ses_from_email:
    from boto3 import client as _boto3_client  # lazy import

    ses = _boto3_client(
        "ses",
        region_name=S.aws_region or "us-east-1",
        endpoint_url=S.aws_endpoint_url or None,
    )
```

Note: `aws.py` creates a module-level SES client if `ses_from_email` is set, but `send_alert_email()` ignores this and creates its own client per-call (`alerts.py:346`). This is a wasted opportunity for connection reuse.

### 3.5 Email Template System

`app/services/alert_email_templates.py` (165 lines):

- `_wrap_html(title, body_html)` (line 16-39): Responsive email template shell with inline CSS, max-width 560px container, card layout with header/body/footer
- `_TEMPLATE_MAP` (line 122-147): Maps 12 event type strings to 5 template functions:
  - `_template_new_message` (line 42): Messaging alerts
  - `_template_payment_received` (line 55): Tips, payments
  - `_template_subscription_started` (line 71): New subscriber
  - `_template_refund_processed` (line 82): Refund confirmations
  - `_template_security_alert` (line 100): Security events (6 event types mapped)
- `render_alert_email_template(event_type, details)` (line 150-165): Lookup + render, returns `(subject, html_body)` or `None`

### 3.6 Alert Email Fanout

The alert fanout in `alerts.py:622-669` tries three template strategies in order:

1. **Ticket-specific templates** via `render_ticket_email_template()` (line 628-631) -- for ticket-related alerts
2. **NOTIFY-001 HTML templates** via `render_alert_email_template()` (line 633-643), gated by `S.notification_email_templates_enabled`
3. **Fallback plain text** with alert type, event, outcome, IP, user-agent, and JSON payload (lines 644-669)

The fanout wraps the entire email section in `except Exception: pass` (line 670-671), creating a second layer of silent failure on top of `send_alert_email`'s own silent catch.

### 3.7 Rate Limiting

`app/services/rate_limit.py:321-324`:

```python
def can_send_alert_channel(user_sub: str, channel: str) -> bool:
    if channel == "email":
        return _bucket_limit(user_sub, "rl#alert_email", S.alerts_email_max_per_window, S.alerts_email_window_seconds)
```

Rate limit uses a sliding-window bucket stored in DDB. Default: 20 emails per hour per user. When exceeded, `can_send_alert_channel()` returns `False` and the email is silently dropped -- no metric, no log.

### 3.8 Alert Preferences

`frontend/src/pages/alerts/AlertPrefs.tsx:32-36`:

```tsx
const CHANNELS = [
  { key: "email", label: "Email" },
  { key: "sms", label: "SMS" },
  { key: "toast", label: "In-App Toast" },
] as const;
```

Users can:
- Add email addresses via OTP verification flow (`alertEmailBegin` + `alertEmailConfirm` API calls, AlertPrefs.tsx:44-47)
- Select event types for email delivery
- Remove previously verified email addresses (`alertEmailRemove`)

### 3.9 Gaps Summary

1. `ALERTS_EMAIL_ENABLED` defaults to `"0"` (`settings.py:186`)
2. Silent exception swallowing in `send_alert_email()` (`alerts.py:352-353`)
3. Silent exception swallowing in email fanout wrapper (`alerts.py:670-671`)
4. No SES delivery notification configuration (bounces, complaints, deliveries)
5. No delivery status stored in DDB
6. No bounce/complaint tracking
7. No email suppression list for bounced/complained addresses
8. No delivery metrics (counters/gauges)
9. No admin email delivery dashboard
10. SES client created per-call in `send_alert_email` (ignores `aws.py` module-level client)
11. Rate-limited sends produce no visible feedback

---

## 4. Implementation Plan

### 4.1 Backend: Improve `send_alert_email()`

**File: `app/services/alerts.py`** -- Replace silent exception handling:

```python
import logging
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# Module-level SES client (reuse connection pool)
_ses_client = None


def _get_ses_client():
    """Get or create a reusable SES client."""
    global _ses_client
    if _ses_client is None:
        import boto3
        _ses_client = boto3.client(
            "ses",
            region_name=S.aws_region or "us-east-1",
            endpoint_url=S.aws_endpoint_url or None,
        )
    return _ses_client


def send_alert_email(
    to_emails: List[str], subject: str, body_text: str, *, html_body: str = ""
) -> Optional[str]:
    """Send email via SES. Returns message_id on success, None on failure.

    Args:
        to_emails: List of recipient email addresses.
        subject: Email subject (truncated to 120 chars).
        body_text: Plain text body (truncated to 8000 chars).
        html_body: Optional HTML body. If provided, both text and HTML parts are sent.

    Returns:
        SES MessageId string on success, None on failure or dev mode.
    """
    if not to_emails:
        return None

    if S.dev_mode:
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        for addr in to_emails:
            entry = f"[{ts}] ALERT_EMAIL TO={addr}\n  Subject: {subject}\n  Body: {body_text}\n\n"
            _write_dev_log(S.dev_email_log, entry)
        return f"dev-{now_ts()}"

    if not S.alerts_email_enabled or not S.alerts_from_email:
        return None

    # Filter out suppressed addresses
    if S.email_suppression_enabled:
        from app.services.email_delivery import is_suppressed
        original_count = len(to_emails)
        to_emails = [e for e in to_emails if not is_suppressed(e)]
        suppressed_count = original_count - len(to_emails)
        if suppressed_count > 0:
            logger.info(
                "Skipped %d suppressed email(s) out of %d",
                suppressed_count, original_count,
            )
            EMAIL_SUPPRESSED.labels(reason="pre_send_filter").inc(suppressed_count)
        if not to_emails:
            return None

    try:
        ses = _get_ses_client()
        message_body: Dict[str, Any] = {
            "Text": {"Data": body_text[:8000], "Charset": "UTF-8"},
        }
        if html_body:
            message_body["Html"] = {"Data": html_body[:50000], "Charset": "UTF-8"}

        response = ses.send_email(
            Source=S.alerts_from_email,
            Destination={"ToAddresses": to_emails},
            Message={
                "Subject": {"Data": subject[:120], "Charset": "UTF-8"},
                "Body": message_body,
            },
        )
        message_id = response.get("MessageId", "")

        # Record delivery event in DDB
        from app.services.email_delivery import record_email_sent
        record_email_sent(to_emails, subject, message_id)

        EMAIL_SENT.inc(len(to_emails))
        logger.info(
            "Email sent: message_id=%s, to=%s, subject=%s",
            message_id, to_emails, subject[:50],
        )
        return message_id

    except Exception as exc:
        # Record failure in DDB
        from app.services.email_delivery import record_email_failure
        record_email_failure(to_emails, subject, str(exc))

        EMAIL_FAILED.inc(len(to_emails))
        logger.exception(
            "Email send failed: to=%s, subject=%s, error=%s",
            to_emails, subject[:50], str(exc)[:200],
        )
        return None
```

### 4.2 Backend: Prometheus Metrics

**File: `app/metrics.py`** -- Add email delivery metrics alongside existing counters (after line 95):

```python
# Email delivery metrics (PLATFORM-006)
EMAIL_SENT = Counter(
    "email_sent_total",
    "Total emails successfully sent via SES",
)
EMAIL_FAILED = Counter(
    "email_failed_total",
    "Total email send failures",
)
EMAIL_BOUNCED = Counter(
    "email_bounced_total",
    "Total email bounces received from SES",
    ["bounce_type"],
)
EMAIL_COMPLAINED = Counter(
    "email_complained_total",
    "Total email complaints received from SES",
)
EMAIL_SUPPRESSED = Counter(
    "email_suppressed_total",
    "Total emails skipped due to suppression",
    ["reason"],
)
```

### 4.3 Backend: Delivery Status Tracking

**New file: `app/services/email_delivery.py`**

```python
"""Email delivery status tracking -- DDB storage for sent, bounced, complained.

Table: email_delivery
  PK: EMAIL#{address} or SUPPRESS#{address} or STATS#{period}
  SK: SENT#{ts}#{msg_id} or BOUNCE#{ts}#{msg_id} or COMPLAINT#{ts}#{msg_id} or STATUS

GSI ByStatus:
  Partition key: status (S)
  Sort key: created_at (N)
  Projection: ALL

TTL: ttl_epoch (N)
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Attr, Key

from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────
# Record helpers
# ──────────────────────────────────────────────────────────────────────


def record_email_sent(
    to_emails: List[str], subject: str, message_id: str
) -> None:
    """Record a successful email send in DDB.

    One item per recipient address, allowing per-address bounce/complaint
    correlation via the EMAIL#{address} partition key.
    """
    ts = now_ts()
    for addr in to_emails:
        try:
            T.email_delivery.put_item(Item={
                "pk": f"EMAIL#{addr}",
                "sk": f"SENT#{ts}#{message_id}",
                "message_id": message_id,
                "to_email": addr,
                "subject": subject[:120],
                "status": "sent",
                "created_at": ts,
                "ttl_epoch": ts + 90 * 86400,  # 90-day retention
            })
        except Exception:
            logger.exception("Failed to record email sent for %s", addr)


def record_email_failure(
    to_emails: List[str], subject: str, error: str
) -> None:
    """Record a failed email send attempt."""
    ts = now_ts()
    for addr in to_emails:
        try:
            T.email_delivery.put_item(Item={
                "pk": f"EMAIL#{addr}",
                "sk": f"FAILED#{ts}",
                "to_email": addr,
                "subject": subject[:120],
                "error": error[:500],
                "status": "failed",
                "created_at": ts,
                "ttl_epoch": ts + 90 * 86400,
            })
        except Exception:
            logger.exception("Failed to record email failure for %s", addr)


def record_email_bounce(
    message_id: str,
    bounce_type: str,
    bounce_sub_type: str,
    bounced_recipients: List[str],
    raw: dict,
) -> None:
    """Record a bounce notification from SES SNS.

    Args:
        message_id: SES MessageId from the original send.
        bounce_type: "Permanent" or "Transient".
        bounce_sub_type: e.g., "General", "NoEmail", "Suppressed".
        bounced_recipients: List of email addresses that bounced.
        raw: Full SES notification JSON (stored for forensics).
    """
    ts = now_ts()
    for addr in bounced_recipients:
        try:
            T.email_delivery.put_item(Item={
                "pk": f"EMAIL#{addr}",
                "sk": f"BOUNCE#{ts}#{message_id}",
                "message_id": message_id,
                "to_email": addr,
                "bounce_type": bounce_type,
                "bounce_sub_type": bounce_sub_type,
                "diagnostic_code": _extract_diagnostic(raw, addr),
                "status": "bounced",
                "created_at": ts,
                "ttl_epoch": ts + 365 * 86400,  # 1-year retention for bounces
            })
        except Exception:
            logger.exception("Failed to record bounce for %s", addr)

        # Auto-suppress hard bounces
        if bounce_type == "Permanent":
            suppress_email(addr, reason="hard_bounce")

    from app.metrics import EMAIL_BOUNCED
    EMAIL_BOUNCED.labels(bounce_type=bounce_type).inc(len(bounced_recipients))


def record_email_complaint(
    message_id: str,
    complaint_feedback_type: str,
    complained_recipients: List[str],
    raw: dict,
) -> None:
    """Record a complaint notification from SES SNS.

    All complaints trigger suppression regardless of type -- this is
    required to maintain SES complaint rates below the 0.1% threshold.
    """
    ts = now_ts()
    for addr in complained_recipients:
        try:
            T.email_delivery.put_item(Item={
                "pk": f"EMAIL#{addr}",
                "sk": f"COMPLAINT#{ts}#{message_id}",
                "message_id": message_id,
                "to_email": addr,
                "complaint_feedback_type": complaint_feedback_type,
                "status": "complained",
                "created_at": ts,
                "ttl_epoch": ts + 365 * 86400,
            })
        except Exception:
            logger.exception("Failed to record complaint for %s", addr)

        suppress_email(addr, reason="complaint")

    from app.metrics import EMAIL_COMPLAINED
    EMAIL_COMPLAINED.inc(len(complained_recipients))


def _extract_diagnostic(raw: dict, addr: str) -> str:
    """Extract diagnostic code for a specific recipient from SES bounce payload."""
    try:
        bounce = raw.get("bounce", {})
        for r in bounce.get("bouncedRecipients", []):
            if r.get("emailAddress") == addr:
                return r.get("diagnosticCode", "")[:500]
    except Exception:
        pass
    return ""


# ──────────────────────────────────────────────────────────────────────
# Suppression list
# ──────────────────────────────────────────────────────────────────────


def suppress_email(email: str, reason: str) -> None:
    """Add email to suppression list.

    Suppressed emails are skipped by send_alert_email() before the SES
    call, preventing repeated bounces from degrading sender reputation.

    Item schema:
      PK: SUPPRESS#{email}
      SK: STATUS
    """
    try:
        T.email_delivery.put_item(Item={
            "pk": f"SUPPRESS#{email}",
            "sk": "STATUS",
            "email": email,
            "reason": reason,
            "suppressed_at": now_ts(),
            "status": "suppressed",  # For ByStatus GSI queries
            "created_at": now_ts(),
        })
        logger.warning("Suppressed email: %s (reason=%s)", email, reason)
    except Exception:
        logger.exception("Failed to suppress email %s", email)


def is_suppressed(email: str) -> bool:
    """Check if email is on suppression list.

    This is called on the hot path (every email send), so it must be fast.
    A DDB GetItem on a known PK/SK is ~5ms.
    """
    try:
        resp = T.email_delivery.get_item(
            Key={"pk": f"SUPPRESS#{email}", "sk": "STATUS"},
            ProjectionExpression="pk",  # Minimize read capacity
        )
        return "Item" in resp
    except Exception:
        # Fail open: if we can't check, send the email
        return False


def remove_suppression(email: str) -> None:
    """Remove email from suppression list (admin action).

    This should only be used when an address was incorrectly suppressed
    (e.g., transient bounce misclassified as permanent).
    """
    try:
        T.email_delivery.delete_item(
            Key={"pk": f"SUPPRESS#{email}", "sk": "STATUS"}
        )
        logger.info("Unsuppressed email: %s", email)
    except Exception:
        logger.exception("Failed to unsuppress email %s", email)


# ──────────────────────────────────────────────────────────────────────
# Admin query functions
# ──────────────────────────────────────────────────────────────────────


def get_delivery_stats(days: int = 7) -> Dict[str, Any]:
    """Get aggregate delivery stats for the last N days.

    Queries the ByStatus GSI for each status value, counting items
    where created_at >= cutoff. Returns totals and rates.
    """
    cutoff = now_ts() - days * 86400
    counts: Dict[str, int] = {}

    for status in ("sent", "bounced", "complained", "failed"):
        try:
            resp = T.email_delivery.query(
                IndexName="ByStatus",
                KeyConditionExpression=(
                    Key("status").eq(status) & Key("created_at").gte(cutoff)
                ),
                Select="COUNT",
            )
            count = resp.get("Count", 0)
            # Handle pagination for large result sets
            while resp.get("LastEvaluatedKey"):
                resp = T.email_delivery.query(
                    IndexName="ByStatus",
                    KeyConditionExpression=(
                        Key("status").eq(status)
                        & Key("created_at").gte(cutoff)
                    ),
                    Select="COUNT",
                    ExclusiveStartKey=resp["LastEvaluatedKey"],
                )
                count += resp.get("Count", 0)
            counts[status] = count
        except Exception:
            counts[status] = -1  # Signal error to caller

    sent = counts.get("sent", 0)
    bounced = counts.get("bounced", 0)
    complained = counts.get("complained", 0)
    failed = counts.get("failed", 0)
    total = sent + bounced + complained + failed

    # Count suppressed addresses (scan SUPPRESS# prefix)
    suppressed_count = 0
    try:
        resp = T.email_delivery.scan(
            FilterExpression=Attr("pk").begins_with("SUPPRESS#"),
            Select="COUNT",
            Limit=10000,
        )
        suppressed_count = resp.get("Count", 0)
    except Exception:
        suppressed_count = -1

    return {
        "period_days": days,
        "sent": sent,
        "bounced": bounced,
        "complained": complained,
        "failed": failed,
        "suppressed": suppressed_count,
        "total": total,
        "bounce_rate": round(bounced / max(sent, 1) * 100, 2),
        "complaint_rate": round(complained / max(sent, 1) * 100, 3),
        "success_rate": round(sent / max(total, 1) * 100, 1),
    }


def list_bounces(
    limit: int = 50, cursor: Optional[str] = None
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """List recent bounces, newest first.

    Returns (items, next_cursor) tuple for paginated admin UI.
    """
    kwargs: Dict[str, Any] = {
        "IndexName": "ByStatus",
        "KeyConditionExpression": Key("status").eq("bounced"),
        "ScanIndexForward": False,  # Newest first
        "Limit": limit,
    }
    if cursor:
        kwargs["ExclusiveStartKey"] = decode_cursor(cursor)

    resp = T.email_delivery.query(**kwargs)
    items = resp.get("Items", [])
    next_cursor = None
    if resp.get("LastEvaluatedKey"):
        next_cursor = encode_cursor(resp["LastEvaluatedKey"])
    return items, next_cursor


def list_complaints(
    limit: int = 50, cursor: Optional[str] = None
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """List recent complaints, newest first."""
    kwargs: Dict[str, Any] = {
        "IndexName": "ByStatus",
        "KeyConditionExpression": Key("status").eq("complained"),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if cursor:
        kwargs["ExclusiveStartKey"] = decode_cursor(cursor)

    resp = T.email_delivery.query(**kwargs)
    items = resp.get("Items", [])
    next_cursor = None
    if resp.get("LastEvaluatedKey"):
        next_cursor = encode_cursor(resp["LastEvaluatedKey"])
    return items, next_cursor


def get_suppression_list(
    limit: int = 50,
) -> Dict[str, Any]:
    """List suppressed email addresses.

    Uses a scan with filter (no GSI needed for this low-volume query).
    """
    try:
        resp = T.email_delivery.scan(
            FilterExpression=Attr("pk").begins_with("SUPPRESS#"),
            Limit=limit,
        )
        items = resp.get("Items", [])
        return {"items": items, "count": len(items)}
    except Exception:
        return {"items": [], "count": 0}
```

### 4.4 Backend: SES SNS Notification Webhook

**New file: `app/routers/ses_notifications.py`**

SES sends delivery notifications to an SNS topic, which can push to an HTTPS endpoint. The webhook must handle three message types from SNS:

1. **SubscriptionConfirmation**: SNS sends this when the topic subscription is first created. The endpoint must fetch the `SubscribeURL` to confirm.
2. **Notification**: The actual bounce/complaint/delivery event from SES.
3. **UnsubscribeConfirmation**: Sent when the subscription is being removed.

```python
"""SES delivery notification receiver (bounces, complaints, deliveries).

This endpoint receives SNS HTTPS push notifications. It must:
  1. Auto-confirm SNS subscription requests
  2. Parse SES notification JSON from the SNS message body
  3. Dispatch to the appropriate handler (bounce, complaint, delivery)
  4. Return 200 to prevent SNS from retrying

Security:
  - The endpoint is at /internal/ses/notifications, behind the
    internal prefix which is not exposed via the Vite proxy.
  - SNS message signature verification is recommended for production
    (see AWS SNS docs for MessageSignatureVersion 2).
  - In staging, signature verification can be skipped if the endpoint
    is only reachable from within the VPC.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict

from fastapi import APIRouter, Request, Response

from app.services.email_delivery import (
    record_email_bounce,
    record_email_complaint,
)

logger = logging.getLogger(__name__)
router = APIRouter(tags=["ses-notifications"])


@router.post("/internal/ses/notifications")
async def ses_notification(request: Request) -> Response:
    """Receive SES delivery notifications via SNS HTTPS subscription.

    SNS wraps the SES event in an envelope with Type, Message, etc.
    The SES event is JSON-encoded inside the Message field.

    Response must always be 200 to prevent SNS retry storms.
    """
    try:
        body = await request.json()
    except Exception:
        logger.warning("SES notification: invalid JSON body")
        return Response(status_code=400)

    msg_type = body.get("Type", "")

    # ── Handle SNS subscription confirmation ──
    if msg_type == "SubscriptionConfirmation":
        subscribe_url = body.get("SubscribeURL", "")
        topic_arn = body.get("TopicArn", "")
        logger.info(
            "SNS subscription confirmation: topic=%s, url=%s",
            topic_arn, subscribe_url[:100],
        )
        if subscribe_url:
            try:
                import httpx
                async with httpx.AsyncClient(timeout=10) as client:
                    resp = await client.get(subscribe_url)
                    logger.info(
                        "SNS subscription confirmed: status=%d", resp.status_code
                    )
            except Exception:
                logger.exception("Failed to confirm SNS subscription")
        return Response(status_code=200)

    # ── Handle unsubscribe confirmation ──
    if msg_type == "UnsubscribeConfirmation":
        logger.info("SNS unsubscribe confirmation: %s", body.get("TopicArn", ""))
        return Response(status_code=200)

    # ── Handle notification ──
    if msg_type == "Notification":
        try:
            message = json.loads(body.get("Message", "{}"))
            _process_ses_notification(message)
        except Exception:
            logger.exception("Error processing SES notification")
        return Response(status_code=200)

    logger.warning("SES notification: unknown type=%s", msg_type)
    return Response(status_code=200)


def _process_ses_notification(message: Dict[str, Any]) -> None:
    """Route SES notification to the appropriate handler."""
    notification_type = message.get("notificationType", "")
    mail = message.get("mail", {})
    message_id = mail.get("messageId", "")
    source = mail.get("source", "")
    destination = mail.get("destination", [])

    if notification_type == "Bounce":
        bounce = message.get("bounce", {})
        bounce_type = bounce.get("bounceType", "Unknown")
        bounce_sub_type = bounce.get("bounceSubType", "Unknown")
        bounced_recipients = [
            r["emailAddress"] for r in bounce.get("bouncedRecipients", [])
        ]
        record_email_bounce(
            message_id=message_id,
            bounce_type=bounce_type,
            bounce_sub_type=bounce_sub_type,
            bounced_recipients=bounced_recipients,
            raw=message,
        )
        logger.warning(
            "SES bounce: type=%s, sub_type=%s, recipients=%s, source=%s",
            bounce_type, bounce_sub_type, bounced_recipients, source,
        )

    elif notification_type == "Complaint":
        complaint = message.get("complaint", {})
        complaint_feedback_type = complaint.get("complaintFeedbackType", "")
        complained_recipients = [
            r["emailAddress"] for r in complaint.get("complainedRecipients", [])
        ]
        record_email_complaint(
            message_id=message_id,
            complaint_feedback_type=complaint_feedback_type,
            complained_recipients=complained_recipients,
            raw=message,
        )
        logger.warning(
            "SES complaint: type=%s, recipients=%s, source=%s",
            complaint_feedback_type, complained_recipients, source,
        )

    elif notification_type == "Delivery":
        delivery = message.get("delivery", {})
        recipients = delivery.get("recipients", destination)
        processing_time_ms = delivery.get("processingTimeMillis", 0)
        logger.info(
            "SES delivery confirmed: message_id=%s, recipients=%s, time=%dms",
            message_id, recipients, processing_time_ms,
        )

    else:
        logger.warning(
            "SES notification: unknown type=%s, message_id=%s",
            notification_type, message_id,
        )
```

### 4.5 Backend: DynamoDB Table

**File: `scripts/local-ddb-init.py`** -- Add `email_delivery` table:

```python
TableDef(
    _resolve_table_name(S.email_delivery_table_name, "email_delivery"),
    "pk",
    "sk",
    gsi=[
        {
            "index_name": "ByStatus",
            "partition_key": "status",
            "sort_key": "created_at",
        },
    ],
    attr_types={"created_at": "N"},
    ttl_attribute="ttl_epoch",
),
```

#### DDB Item Examples

**Sent email**:
```json
{
  "pk": "EMAIL#user@example.com",
  "sk": "SENT#1748380800#0102017890abcdef-12345678-1234-1234-1234-123456789012-000000",
  "message_id": "0102017890abcdef-12345678-1234-1234-1234-123456789012-000000",
  "to_email": "user@example.com",
  "subject": "[Alert] login: success",
  "status": "sent",
  "created_at": 1748380800,
  "ttl_epoch": 1756156800
}
```

**Bounce**:
```json
{
  "pk": "EMAIL#invalid@example.com",
  "sk": "BOUNCE#1748381000#0102017890abcdef-deadbeef",
  "message_id": "0102017890abcdef-deadbeef",
  "to_email": "invalid@example.com",
  "bounce_type": "Permanent",
  "bounce_sub_type": "General",
  "diagnostic_code": "smtp; 550 5.1.1 <invalid@example.com>... User unknown",
  "status": "bounced",
  "created_at": 1748381000,
  "ttl_epoch": 1779917000
}
```

**Complaint**:
```json
{
  "pk": "EMAIL#annoyed@example.com",
  "sk": "COMPLAINT#1748382000#0102017890abcdef-cafebabe",
  "message_id": "0102017890abcdef-cafebabe",
  "to_email": "annoyed@example.com",
  "complaint_feedback_type": "abuse",
  "status": "complained",
  "created_at": 1748382000,
  "ttl_epoch": 1779918000
}
```

**Suppression**:
```json
{
  "pk": "SUPPRESS#invalid@example.com",
  "sk": "STATUS",
  "email": "invalid@example.com",
  "reason": "hard_bounce",
  "suppressed_at": 1748381000,
  "status": "suppressed",
  "created_at": 1748381000
}
```

### 4.6 Backend: Settings

**File: `app/core/settings.py`** -- Add new settings near existing alert channel settings (after line 197):

```python
# Email Delivery Tracking (PLATFORM-006)
email_delivery_table_name: str = os.environ.get("EMAIL_DELIVERY_TABLE_NAME", "email_delivery")
email_suppression_enabled: bool = os.environ.get("EMAIL_SUPPRESSION_ENABLED", "1") not in ("0", "false", "False")
```

### 4.7 Backend: Tables

**File: `app/core/tables.py`** -- Add `email_delivery` table handle to the `Tables` dataclass (after `push_devices` at line 21):

```python
email_delivery: Any
```

And wire it in the `Tables()` constructor call:

```python
email_delivery=ddb.Table(S.email_delivery_table_name),
```

### 4.8 Backend: Pydantic Models

**File: `app/models.py`** -- Add response models:

```python
# ─── Email Delivery (PLATFORM-006) ───────────────────────────────

class EmailDeliveryStatsOut(BaseModel):
    period_days: int
    sent: int
    bounced: int
    complained: int
    failed: int
    suppressed: int
    total: int
    bounce_rate: float
    complaint_rate: float
    success_rate: float


class EmailBounceItem(BaseModel):
    pk: str
    sk: str
    message_id: str
    to_email: str
    bounce_type: str
    bounce_sub_type: Optional[str] = None
    diagnostic_code: Optional[str] = None
    status: str
    created_at: int
    ttl_epoch: Optional[int] = None


class EmailBounceListOut(BaseModel):
    items: List[EmailBounceItem]
    next_cursor: Optional[str] = None


class EmailComplaintItem(BaseModel):
    pk: str
    sk: str
    message_id: str
    to_email: str
    complaint_feedback_type: Optional[str] = None
    status: str
    created_at: int
    ttl_epoch: Optional[int] = None


class EmailComplaintListOut(BaseModel):
    items: List[EmailComplaintItem]
    next_cursor: Optional[str] = None


class EmailSuppressedItem(BaseModel):
    email: str
    reason: str
    suppressed_at: int


class EmailSuppressedListOut(BaseModel):
    items: List[EmailSuppressedItem]
    count: int
```

### 4.9 Backend: Admin Endpoints

**New file: `app/routers/admin_email.py`**

```python
"""Admin email delivery monitoring endpoints (PLATFORM-006)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth.deps import require_admin_session
from app.services.email_delivery import (
    get_delivery_stats,
    get_suppression_list,
    list_bounces,
    list_complaints,
    remove_suppression,
)

router = APIRouter(prefix="/ui/admin/email", tags=["admin-email"])


@router.get("/stats")
async def email_stats(
    days: int = Query(default=7, ge=1, le=90),
    _=Depends(require_admin_session),
):
    """Get email delivery statistics for the last N days.

    curl -s -b cookies.txt https://host/ui/admin/email/stats?days=7
    """
    return get_delivery_stats(days=days)


@router.get("/bounces")
async def email_bounces(
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str = Query(default=None),
    _=Depends(require_admin_session),
):
    """List recent email bounces (newest first, paginated).

    curl -s -b cookies.txt https://host/ui/admin/email/bounces?limit=50
    """
    items, next_cursor = list_bounces(limit=limit, cursor=cursor)
    return {"items": items, "next_cursor": next_cursor}


@router.get("/complaints")
async def email_complaints(
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str = Query(default=None),
    _=Depends(require_admin_session),
):
    """List recent email complaints (newest first, paginated).

    curl -s -b cookies.txt https://host/ui/admin/email/complaints?limit=50
    """
    items, next_cursor = list_complaints(limit=limit, cursor=cursor)
    return {"items": items, "next_cursor": next_cursor}


@router.get("/suppressed")
async def suppressed_emails(
    limit: int = Query(default=50, ge=1, le=200),
    _=Depends(require_admin_session),
):
    """List suppressed email addresses.

    curl -s -b cookies.txt https://host/ui/admin/email/suppressed?limit=50
    """
    return get_suppression_list(limit=limit)


@router.delete("/suppressed/{email:path}")
async def unsuppress_email(
    email: str,
    _=Depends(require_admin_session),
):
    """Remove email from suppression list (admin override).

    curl -s -X DELETE -b cookies.txt https://host/ui/admin/email/suppressed/user@example.com
    """
    remove_suppression(email)
    return {"ok": True, "email": email}
```

### 4.10 Backend: Register Routers

**File: `app/main.py`** -- Import and register both new routers:

```python
from app.routers.ses_notifications import router as ses_notifications_router
from app.routers.admin_email import router as admin_email_router
# ...
app.include_router(ses_notifications_router)
app.include_router(admin_email_router)
```

### 4.11 Frontend: TypeScript Types

**File: `frontend/src/api/types.ts`** -- Add email delivery types:

```typescript
// ─── Email Delivery (PLATFORM-006) ──────────────────────────────

export interface EmailDeliveryStats {
  period_days: number;
  sent: number;
  bounced: number;
  complained: number;
  failed: number;
  suppressed: number;
  total: number;
  bounce_rate: number;
  complaint_rate: number;
  success_rate: number;
}

export interface EmailBounceItem {
  pk: string;
  sk: string;
  message_id: string;
  to_email: string;
  bounce_type: string;
  bounce_sub_type?: string;
  diagnostic_code?: string;
  status: string;
  created_at: number;
}

export interface EmailComplaintItem {
  pk: string;
  sk: string;
  message_id: string;
  to_email: string;
  complaint_feedback_type?: string;
  status: string;
  created_at: number;
}

export interface EmailSuppressedItem {
  email: string;
  reason: string;
  suppressed_at: number;
}
```

### 4.12 Frontend: API Endpoints

**New file: `frontend/src/api/endpoints/admin-email.ts`**

```typescript
import { api } from "@/api/client";
import type {
  EmailDeliveryStats,
  EmailBounceItem,
  EmailComplaintItem,
  EmailSuppressedItem,
} from "@/api/types";

export const getEmailDeliveryStats = (days = 7) =>
  api.get<EmailDeliveryStats>(`/ui/admin/email/stats?days=${days}`);

export const getEmailBounces = (limit = 50, cursor?: string) =>
  api.get<{ items: EmailBounceItem[]; next_cursor: string | null }>(
    `/ui/admin/email/bounces?limit=${limit}${cursor ? `&cursor=${cursor}` : ""}`
  );

export const getEmailComplaints = (limit = 50, cursor?: string) =>
  api.get<{ items: EmailComplaintItem[]; next_cursor: string | null }>(
    `/ui/admin/email/complaints?limit=${limit}${cursor ? `&cursor=${cursor}` : ""}`
  );

export const getEmailSuppressed = (limit = 50) =>
  api.get<{ items: EmailSuppressedItem[]; count: number }>(
    `/ui/admin/email/suppressed?limit=${limit}`
  );

export const unsuppressEmail = (email: string) =>
  api.delete(`/ui/admin/email/suppressed/${encodeURIComponent(email)}`);
```

### 4.13 Frontend: Admin Email Dashboard

**New file: `frontend/src/pages/admin/EmailDeliveryPage.tsx`**

```tsx
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Card, CardContent, CardHeader, CardTitle, CardDescription,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Mail, AlertTriangle, ShieldAlert, Ban, RefreshCw, Trash2,
} from "lucide-react";
import { toast } from "sonner";
import {
  getEmailDeliveryStats,
  getEmailBounces,
  getEmailComplaints,
  getEmailSuppressed,
  unsuppressEmail,
} from "@/api/endpoints/admin-email";
import type {
  EmailBounceItem, EmailComplaintItem, EmailSuppressedItem,
} from "@/api/types";

function bounceTypeBadge(type: string) {
  if (type === "Permanent") return <Badge variant="destructive">Permanent</Badge>;
  if (type === "Transient") return <Badge variant="secondary">Transient</Badge>;
  return <Badge variant="outline">{type}</Badge>;
}

export default function EmailDeliveryPage() {
  const qc = useQueryClient();

  const statsQ = useQuery({
    queryKey: ["admin", "email", "stats"],
    queryFn: () => getEmailDeliveryStats(7),
    refetchInterval: 60_000,
  });
  const bouncesQ = useQuery({
    queryKey: ["admin", "email", "bounces"],
    queryFn: () => getEmailBounces(50),
  });
  const complaintsQ = useQuery({
    queryKey: ["admin", "email", "complaints"],
    queryFn: () => getEmailComplaints(50),
  });
  const suppressedQ = useQuery({
    queryKey: ["admin", "email", "suppressed"],
    queryFn: () => getEmailSuppressed(50),
  });

  const unsuppressMut = useMutation({
    mutationFn: (email: string) => unsuppressEmail(email),
    onSuccess: () => {
      toast.success("Email unsuppressed");
      qc.invalidateQueries({ queryKey: ["admin", "email"] });
    },
    onError: () => toast.error("Failed to unsuppress email"),
  });

  const stats = statsQ.data;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Email Delivery</h1>
        <Button
          variant="outline"
          size="sm"
          onClick={() => qc.invalidateQueries({ queryKey: ["admin", "email"] })}
        >
          <RefreshCw className="h-4 w-4 mr-2" /> Refresh
        </Button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-2">
              <Mail className="h-4 w-4 text-green-500" />
              <p className="text-sm text-muted-foreground">Sent</p>
            </div>
            <p className="text-2xl font-bold">{stats?.sent ?? 0}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-amber-500" />
              <p className="text-sm text-muted-foreground">Bounced</p>
            </div>
            <p className="text-2xl font-bold">{stats?.bounced ?? 0}</p>
            <p className="text-xs text-muted-foreground">
              Rate: {stats?.bounce_rate ?? 0}%
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-red-500" />
              <p className="text-sm text-muted-foreground">Complaints</p>
            </div>
            <p className="text-2xl font-bold">{stats?.complained ?? 0}</p>
            <p className="text-xs text-muted-foreground">
              Rate: {stats?.complaint_rate ?? 0}%
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-2">
              <Ban className="h-4 w-4 text-gray-500" />
              <p className="text-sm text-muted-foreground">Suppressed</p>
            </div>
            <p className="text-2xl font-bold">{stats?.suppressed ?? 0}</p>
          </CardContent>
        </Card>
      </div>

      {/* Bounce List */}
      <Card>
        <CardHeader>
          <CardTitle>Recent Bounces</CardTitle>
          <CardDescription>
            Hard bounces auto-suppress the recipient address
          </CardDescription>
        </CardHeader>
        <CardContent>
          {bouncesQ.data?.items?.length === 0 ? (
            <p className="text-muted-foreground text-sm">No bounces</p>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b text-left">
                  <th className="py-2">Email</th>
                  <th>Type</th>
                  <th>Diagnostic</th>
                  <th>Date</th>
                </tr>
              </thead>
              <tbody>
                {bouncesQ.data?.items?.map((item: EmailBounceItem) => (
                  <tr key={item.sk} className="border-b">
                    <td className="py-2 font-mono text-xs">{item.to_email}</td>
                    <td>{bounceTypeBadge(item.bounce_type)}</td>
                    <td className="max-w-xs truncate text-xs text-muted-foreground">
                      {item.diagnostic_code || "—"}
                    </td>
                    <td className="text-xs">
                      {new Date(item.created_at * 1000).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </CardContent>
      </Card>

      {/* Complaint List */}
      <Card>
        <CardHeader>
          <CardTitle>Recent Complaints</CardTitle>
          <CardDescription>
            All complaints auto-suppress to maintain sender reputation
          </CardDescription>
        </CardHeader>
        <CardContent>
          {complaintsQ.data?.items?.length === 0 ? (
            <p className="text-muted-foreground text-sm">No complaints</p>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b text-left">
                  <th className="py-2">Email</th>
                  <th>Feedback Type</th>
                  <th>Message ID</th>
                  <th>Date</th>
                </tr>
              </thead>
              <tbody>
                {complaintsQ.data?.items?.map((item: EmailComplaintItem) => (
                  <tr key={item.sk} className="border-b">
                    <td className="py-2 font-mono text-xs">{item.to_email}</td>
                    <td>{item.complaint_feedback_type || "—"}</td>
                    <td className="font-mono text-xs">{item.message_id.slice(0, 16)}...</td>
                    <td className="text-xs">
                      {new Date(item.created_at * 1000).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </CardContent>
      </Card>

      {/* Suppression List */}
      <Card>
        <CardHeader>
          <CardTitle>Suppressed Addresses</CardTitle>
          <CardDescription>
            Emails to these addresses are silently dropped
          </CardDescription>
        </CardHeader>
        <CardContent>
          {suppressedQ.data?.items?.length === 0 ? (
            <p className="text-muted-foreground text-sm">No suppressed addresses</p>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b text-left">
                  <th className="py-2">Email</th>
                  <th>Reason</th>
                  <th>Since</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {suppressedQ.data?.items?.map((item: EmailSuppressedItem) => (
                  <tr key={item.email} className="border-b">
                    <td className="py-2 font-mono text-xs">{item.email}</td>
                    <td><Badge variant="outline">{item.reason}</Badge></td>
                    <td className="text-xs">
                      {new Date(item.suppressed_at * 1000).toLocaleString()}
                    </td>
                    <td>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => unsuppressMut.mutate(item.email)}
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
```

### 4.14 Frontend: Route

**File: `frontend/src/App.tsx`** -- Add admin route:

```tsx
const EmailDeliveryPage = lazy(() => import("@/pages/admin/EmailDeliveryPage"));
// ...
<Route path="admin/email" element={<EmailDeliveryPage />} />
```

### 4.15 Staging Configuration

**.env.staging** (example):

```bash
# Email delivery (PLATFORM-006)
ALERTS_EMAIL_ENABLED=1
ALERTS_FROM_EMAIL=noreply@staging.example.com
SES_FROM_EMAIL=noreply@staging.example.com
EMAIL_DELIVERY_TABLE_NAME=email_delivery
EMAIL_SUPPRESSION_ENABLED=1
DEV_MODE=0
AWS_REGION=us-east-1
```

SES setup requirements for staging:
1. Verify sender domain in SES console (Route 53 or external DNS)
2. Configure DKIM by adding 3 CNAME records provided by SES
3. Configure SPF by adding TXT record: `v=spf1 include:amazonses.com ~all`
4. Configure DMARC: `v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@example.com`
5. Create SNS topic `ses-delivery-notifications`
6. Configure SES to publish bounce, complaint, and delivery events to the SNS topic
7. Subscribe the `/internal/ses/notifications` HTTPS endpoint to the SNS topic
8. Confirm the SNS subscription (auto-confirmed by the endpoint)
9. Request SES production access (exit sandbox) if sending to non-verified addresses

### 4.16 curl Examples

```bash
# Get email delivery stats (last 7 days)
curl -s -b cookies.txt -H "x-csrf-token: $CSRF" \
  http://localhost:8000/ui/admin/email/stats?days=7

# List recent bounces
curl -s -b cookies.txt -H "x-csrf-token: $CSRF" \
  http://localhost:8000/ui/admin/email/bounces?limit=50

# List recent complaints
curl -s -b cookies.txt -H "x-csrf-token: $CSRF" \
  http://localhost:8000/ui/admin/email/complaints?limit=50

# List suppressed addresses
curl -s -b cookies.txt -H "x-csrf-token: $CSRF" \
  http://localhost:8000/ui/admin/email/suppressed?limit=50

# Unsuppress an address
curl -s -X DELETE -b cookies.txt -H "x-csrf-token: $CSRF" \
  http://localhost:8000/ui/admin/email/suppressed/user@example.com

# Simulate SES bounce notification (for testing)
curl -s -X POST http://localhost:8000/internal/ses/notifications \
  -H "Content-Type: application/json" \
  -d '{
    "Type": "Notification",
    "Message": "{\"notificationType\":\"Bounce\",\"bounce\":{\"bounceType\":\"Permanent\",\"bounceSubType\":\"General\",\"bouncedRecipients\":[{\"emailAddress\":\"bad@example.com\",\"diagnosticCode\":\"550 5.1.1 user unknown\"}]},\"mail\":{\"messageId\":\"test-msg-001\",\"source\":\"noreply@example.com\"}}"
  }'
```

---

## 5. Data Model

### 5.1 Email Delivery Table

**Table name**: `email_delivery` (configurable via `EMAIL_DELIVERY_TABLE_NAME`)

**Primary key**: `pk` (S) + `sk` (S)

**GSI**: `ByStatus` -- partition key `status` (S), sort key `created_at` (N), projection ALL

**TTL attribute**: `ttl_epoch`

| Field | Type | PK pattern | Description | Example |
|-------|------|------------|-------------|---------|
| `pk` | S | `EMAIL#{address}` | Groups all events for one address | `"EMAIL#user@example.com"` |
| `pk` | S | `SUPPRESS#{address}` | Suppression record | `"SUPPRESS#user@example.com"` |
| `sk` | S | `SENT#{ts}#{msg_id}` | Sent event | `"SENT#1748380800#abc123"` |
| `sk` | S | `BOUNCE#{ts}#{msg_id}` | Bounce event | `"BOUNCE#1748381000#abc123"` |
| `sk` | S | `COMPLAINT#{ts}#{msg_id}` | Complaint event | `"COMPLAINT#1748382000#abc123"` |
| `sk` | S | `FAILED#{ts}` | Send failure event | `"FAILED#1748380800"` |
| `sk` | S | `STATUS` | Suppression status | `"STATUS"` |
| `message_id` | S | — | SES message ID | `"0102017890abcdef-..."` |
| `to_email` | S | — | Recipient address | `"user@example.com"` |
| `subject` | S | — | Email subject (truncated to 120 chars) | `"[Alert] login: success"` |
| `status` | S | GSI PK | `sent`, `bounced`, `complained`, `failed`, `suppressed` | `"bounced"` |
| `bounce_type` | S | — | `Permanent` or `Transient` (bounces only) | `"Permanent"` |
| `bounce_sub_type` | S | — | `General`, `NoEmail`, `Suppressed`, etc. | `"General"` |
| `diagnostic_code` | S | — | SMTP diagnostic from receiving MTA | `"550 5.1.1 user unknown"` |
| `complaint_feedback_type` | S | — | `abuse`, `not-spam`, etc. | `"abuse"` |
| `error` | S | — | Python exception string (failures only) | `"ClientError: ..."` |
| `reason` | S | — | Suppression reason | `"hard_bounce"` |
| `email` | S | — | Address (suppression items) | `"user@example.com"` |
| `suppressed_at` | N | — | Unix timestamp of suppression | `1748381000` |
| `created_at` | N | GSI SK | Unix timestamp | `1748380800` |
| `ttl_epoch` | N | TTL | Auto-delete timestamp | `1756156800` |

### 5.2 DDB Capacity Estimates

| Scenario | RCU (on-demand) | WCU (on-demand) | Notes |
|----------|----------------|-----------------|-------|
| 1000 emails/day sent | ~1 RCU avg | ~12 WCU burst (1 per send) | Low volume |
| 5% bounce rate | +50 writes/day | Negligible | One BOUNCE + one SUPPRESS per bounce |
| Admin stats query (7d) | ~5-10 RCU per status | — | 4 GSI queries, COUNT only |
| `is_suppressed` check | ~1 RCU per send | — | GetItem, 5ms latency |

### 5.3 Item Size Estimates

| Item type | Avg size | 90-day items (1K emails/day) |
|-----------|----------|------------------------------|
| SENT | ~300 bytes | 90,000 items (~27 MB) |
| BOUNCE | ~400 bytes | 4,500 items (~1.8 MB) |
| COMPLAINT | ~350 bytes | 90 items (~31 KB) |
| SUPPRESS | ~200 bytes | 100 items (~20 KB) |

---

## 6. Security Considerations

### 6.1 SES Notification Endpoint Security

- The endpoint is at `/internal/ses/notifications`, which is behind the internal prefix. The Vite dev proxy does not forward `/internal` paths to the backend unless explicitly configured (see `vite.config.ts` proxy configuration).
- In production, the endpoint should be restricted to SNS IP ranges (published by AWS) via security group or WAF rules.
- SNS message signature verification (MessageSignatureVersion 2) should be implemented for production to prevent spoofed notifications.
- The endpoint auto-confirms subscription requests. In production, restrict confirmation to expected TopicArn values.

### 6.2 Admin Endpoint Authorization

- All admin email endpoints use `require_admin_session` from `app/auth/deps.py`, which requires `role >= ADMIN`.
- The unsuppress endpoint (`DELETE /suppressed/{email}`) is a sensitive operation that could re-enable sending to a user who marked emails as spam. Consider adding audit logging for this action.

### 6.3 Email Address Privacy

- The bounce/complaint admin endpoints expose recipient email addresses. These should only be visible to admin/root users.
- The DDB items store email addresses in plain text. In a multi-tenant production environment, consider encrypting the `to_email` field and using a hashed PK.

### 6.4 SES Sending Limits

- SES sandbox mode limits sending to verified addresses only. Production access must be requested per-region.
- SES has a sending quota (default: 200 emails/day in sandbox, 50,000+/day in production).
- Monitor the `ses:GetSendQuota` API to check remaining quota before sending bursts.

---

## 7. Performance Analysis

### 7.1 Send Path Latency

| Step | Latency | Notes |
|------|---------|-------|
| `is_suppressed()` check | ~5ms | DDB GetItem on known PK/SK |
| SES `send_email()` call | ~100-300ms | HTTP to SES endpoint |
| `record_email_sent()` DDB write | ~10ms | PutItem, fire-and-forget |
| **Total per send** | **~115-315ms** | Non-blocking for the alert write path |

### 7.2 Connection Pooling Impact

The current code creates a new `boto3.client("ses")` per call (~50ms connection overhead). Using a module-level client reduces per-call latency by ~30% for sequential sends.

### 7.3 Throughput

The `send_alert_email()` function is called from the alert fanout path, which runs synchronously within the `write_alert()` call. For burst scenarios (e.g., 100 security alerts in 1 second), the sequential SES calls would take 10-30 seconds. For high-volume scenarios, consider:
- Batching: SES `send_raw_email()` with `Destinations` list (up to 50 recipients per call)
- Queueing: SQS with a dedicated email worker (defers delivery from the alert path)

---

## 8. Migration & Rollback

### 8.1 Feature Flags

| Flag | Default | Effect when disabled |
|------|---------|---------------------|
| `ALERTS_EMAIL_ENABLED` | `"0"` | No emails sent (existing behavior) |
| `EMAIL_SUPPRESSION_ENABLED` | `"1"` | Suppression checks skipped; all addresses receive emails |

### 8.2 Migration Steps

1. **DDB table**: Create `email_delivery` table in all environments via `scripts/local-ddb-init.py`
2. **Settings**: Add new settings to `.env.local` and `.env.staging`
3. **Deploy backend**: New code is backward-compatible; `EMAIL_SUPPRESSION_ENABLED=0` disables suppression
4. **SES configuration**: Set up domain verification, DKIM, SPF, DMARC in staging
5. **SNS topic**: Create and subscribe the notification endpoint
6. **Enable**: Set `ALERTS_EMAIL_ENABLED=1` in staging

### 8.3 Rollback

- Set `ALERTS_EMAIL_ENABLED=0` to immediately stop all email delivery
- Set `EMAIL_SUPPRESSION_ENABLED=0` to bypass suppression checks
- The `email_delivery` DDB table can remain (items expire via TTL)
- No database migration to reverse

---

## 9. Testing Strategy

### 9.1 Unit Tests (pytest)

| # | Test | Assertion |
|---|------|-----------|
| 1 | `send_alert_email` logs failure instead of silently swallowing | Logger called with `exception()` on SES error |
| 2 | `send_alert_email` returns message_id on success | Non-None string return |
| 3 | `send_alert_email` returns None when disabled | `alerts_email_enabled=False` |
| 4 | `send_alert_email` returns None when no from address | `alerts_from_email=""` |
| 5 | `record_email_sent` writes DDB item with correct fields | Item has `status=sent`, `message_id`, `to_email` |
| 6 | `record_email_bounce` writes DDB item and calls `suppress_email` for hard bounces | BOUNCE item + SUPPRESS item created |
| 7 | `record_email_bounce` does NOT suppress transient bounces | No SUPPRESS item for `bounce_type=Transient` |
| 8 | `record_email_complaint` suppresses all complainants | SUPPRESS item created for each recipient |
| 9 | `is_suppressed` returns True for suppressed email | Correct boolean after `suppress_email()` |
| 10 | `is_suppressed` returns False for non-suppressed email | Correct boolean |
| 11 | `is_suppressed` fails open on DDB error | Returns False when table is unavailable |
| 12 | `send_alert_email` skips suppressed addresses | Suppressed email not in SES call args |
| 13 | `send_alert_email` sends to non-suppressed addresses in mixed list | Only non-suppressed emails in SES call |
| 14 | `remove_suppression` clears suppression | `is_suppressed` returns False after removal |
| 15 | `get_delivery_stats` returns correct counts | Sent/bounced/complained counts match seeded data |
| 16 | `get_delivery_stats` handles pagination | Correct count for >1 page of items |
| 17 | `list_bounces` returns newest first | Items sorted by `created_at` descending |
| 18 | `list_bounces` respects cursor pagination | Second page returns different items |
| 19 | SES notification endpoint handles bounce JSON | 200 response; bounce recorded in DDB |
| 20 | SES notification endpoint handles complaint JSON | 200 response; complaint recorded in DDB |
| 21 | SES notification endpoint handles delivery JSON | 200 response; logged |
| 22 | SES notification endpoint handles subscription confirmation | 200 response |
| 23 | SES notification endpoint handles invalid JSON | 400 response |
| 24 | Admin stats endpoint requires admin role | 403 for regular user |
| 25 | Admin unsuppress endpoint removes suppression | `is_suppressed` returns False |
| 26 | `_get_ses_client` reuses client instance | Same object returned on second call |
| 27 | `send_alert_email` supports HTML body | SES call includes Html body part |
| 28 | `_extract_diagnostic` returns code for matching recipient | Correct diagnostic string |

### 9.2 E2E Tests

**File:** `frontend/e2e/email-delivery.spec.ts`

**Section 1: Delivery API (6 tests)**

| # | Test Title | Assertion |
|---|------------|-----------|
| 1 | "Admin can GET email delivery stats" | Root user GET `/ui/admin/email/stats`; 200; response has `sent`, `bounced`, `complained` fields |
| 2 | "Stats endpoint accepts days parameter" | GET `/ui/admin/email/stats?days=30`; 200; response has `period_days: 30` |
| 3 | "Admin can GET email bounces" | Root user GET `/ui/admin/email/bounces`; 200; response has `items` array |
| 4 | "Admin can GET email complaints" | Root user GET `/ui/admin/email/complaints`; 200; response has `items` array |
| 5 | "Admin can GET suppressed list" | Root user GET `/ui/admin/email/suppressed`; 200; response has `items` and `count` |
| 6 | "Non-admin user gets 403 on stats" | Alice GET `/ui/admin/email/stats`; 403 |

**Section 2: SES Notification Webhook (4 tests)**

| # | Test Title | Assertion |
|---|------------|-----------|
| 7 | "SES bounce notification is processed" | POST `/internal/ses/notifications` with bounce JSON; 200 |
| 8 | "SES complaint notification is processed" | POST with complaint JSON; 200 |
| 9 | "SES delivery confirmation is processed" | POST with delivery JSON; 200 |
| 10 | "SNS subscription confirmation is handled" | POST with SubscriptionConfirmation type; 200 |

**Section 3: Suppression (3 tests)**

| # | Test Title | Assertion |
|---|------------|-----------|
| 11 | "Admin can unsuppress an email address" | DELETE `/ui/admin/email/suppressed/test@e2e.local`; 200; `ok: true` |
| 12 | "Unsuppress returns ok even for non-suppressed email" | DELETE for unknown address; 200 |
| 13 | "Suppressed list reflects unsuppression" | After unsuppress; GET suppressed; address not in list |

**Section 4: Admin UI (5 tests)**

| # | Test Title | Assertion |
|---|------------|-----------|
| 14 | "Email delivery page loads for admin" | Navigate to `/admin/email`; "Email Delivery" heading visible |
| 15 | "Stats cards display sent and bounced counts" | "Sent" and "Bounced" text visible in cards |
| 16 | "Bounce rate percentage is displayed" | "Rate:" text visible in bounce card |
| 17 | "Bounce table renders with headers" | "Email", "Type", "Diagnostic" column headers visible |
| 18 | "Complaint table renders with headers" | "Email", "Feedback Type" column headers visible |

---

## 10. Acceptance Criteria

1. `send_alert_email()` logs failures and records metrics instead of silently swallowing exceptions.
2. `send_alert_email()` returns SES `MessageId` on success, `None` on failure.
3. SES client is reused across calls (module-level client via `_get_ses_client()`).
4. Delivery events (sent, bounced, complained, failed) are tracked in the `email_delivery` DDB table.
5. Hard bounces and complaints automatically suppress the affected email address.
6. Suppressed emails are skipped in `send_alert_email()` before the SES call.
7. `POST /internal/ses/notifications` processes SES SNS bounce/complaint/delivery events.
8. Admin endpoints (`/ui/admin/email/stats`, `/bounces`, `/complaints`, `/suppressed`) return delivery data.
9. Admin `DELETE /ui/admin/email/suppressed/{email}` removes suppression.
10. Admin dashboard page shows delivery stats, bounce list, complaint list, and suppression list.
11. Prometheus metrics `email_sent_total`, `email_failed_total`, `email_bounced_total`, `email_complained_total` are emitted.
12. Staging environment has `ALERTS_EMAIL_ENABLED=1` with verified SES domain.
13. Feature flag `EMAIL_SUPPRESSION_ENABLED` controls address suppression.
14. All admin endpoints require `role >= ADMIN` via `require_admin_session`.

---

## 11. Files to Create

| File | Purpose |
|------|---------|
| `app/services/email_delivery.py` | Delivery status tracking, suppression list, admin query functions |
| `app/routers/ses_notifications.py` | SES SNS notification webhook receiver |
| `app/routers/admin_email.py` | Admin email monitoring endpoints |
| `frontend/src/api/endpoints/admin-email.ts` | Admin email API client |
| `frontend/src/pages/admin/EmailDeliveryPage.tsx` | Admin email delivery dashboard |
| `frontend/e2e/email-delivery.spec.ts` | E2E tests |

## 12. Files to Modify

| File | Change |
|------|--------|
| `app/services/alerts.py:332-353` | Improve `send_alert_email()`: log errors, return message_id, filter suppressed, reuse SES client, add HTML body support |
| `app/core/settings.py` (after line 197) | Add `email_delivery_table_name`, `email_suppression_enabled` |
| `app/core/tables.py` (after line 21) | Add `email_delivery` table handle |
| `app/models.py` | Add `EmailDeliveryStatsOut`, `EmailBounceItem`, `EmailBounceListOut`, `EmailComplaintItem`, `EmailComplaintListOut`, `EmailSuppressedItem`, `EmailSuppressedListOut` |
| `app/metrics.py` (after line 95) | Add `EMAIL_SENT`, `EMAIL_FAILED`, `EMAIL_BOUNCED`, `EMAIL_COMPLAINED`, `EMAIL_SUPPRESSED` counters |
| `app/main.py` | Register `ses_notifications_router` and `admin_email_router` |
| `scripts/local-ddb-init.py` | Add `email_delivery` table with ByStatus GSI and TTL |
| `frontend/src/api/types.ts` | Add `EmailDeliveryStats`, `EmailBounceItem`, `EmailComplaintItem`, `EmailSuppressedItem` interfaces |
| `frontend/src/App.tsx` | Add `/admin/email` route |

---

## 13. Dependencies

- **SES**: Already used by `alerts.py:344-351`. No new AWS service needed.
- **SNS**: SES delivery notifications push via SNS topic to HTTPS endpoint. SNS client already exists (`app/core/aws.py:30-37`).
- **httpx**: For SNS subscription confirmation auto-confirm. Already in requirements (used by webhook delivery in `webhook_service.py`).
- **DynamoDB**: New `email_delivery` table. Same infrastructure as all existing tables.

---

## Appendix A: Codebase Citations

| Claim | File | Line(s) | Status |
|-------|------|---------|--------|
| `send_alert_email()` with SES | `app/services/alerts.py` | 458 | VERIFIED |
| Dev mode logs to `.logs/dev/emails.log` | `app/services/alerts.py` | within send_alert_email | VERIFIED |
| `audit_event()` (master dispatch, routes to email/sms/push) | `app/services/alerts.py` | 695 | VERIFIED |
| `alerts_email_enabled` default `"0"` | `app/core/settings.py` | 186 | VERIFIED |
| `alerts_from_email` default empty | `app/core/settings.py` | 185 | VERIFIED |
| `ses_from_email` setting | `app/core/settings.py` | 179 | VERIFIED |
| `alerts_email_max_per_window` default 20 | `app/core/settings.py` | 187 | VERIFIED |
| `alerts_email_window_seconds` default 3600 | `app/core/settings.py` | 188 | VERIFIED |
| `dev_email_log` default path | `app/core/settings.py` | 261 | VERIFIED |
| `devtools_email_log_path` default | `app/core/settings.py` | 264 | VERIFIED |
| `notification_email_templates_enabled` | `app/core/settings.py` | 1392 | VERIFIED |
| Module-level SES client in aws.py | `app/core/aws.py` | 11-19 | VERIFIED |
| `sns_client()` lazy import per-call | `app/core/aws.py` | 30-37 | VERIFIED |
| `alert_email_templates.py` 165 lines, 5 templates | `app/services/alert_email_templates.py` | 1-165 | VERIFIED |
| `_TEMPLATE_MAP` maps 12 event types | `app/services/alert_email_templates.py` | 122-147 | VERIFIED |
| `_wrap_html` responsive template | `app/services/alert_email_templates.py` | 16-39 | VERIFIED |
| `render_alert_email_template` dispatcher | `app/services/alert_email_templates.py` | 150-165 | VERIFIED |
| AlertPrefs SMS/email channels | `frontend/src/pages/alerts/AlertPrefs.tsx` | 32-36 | VERIFIED |
| AlertPrefs email OTP state | `frontend/src/pages/alerts/AlertPrefs.tsx` | 44-47 | VERIFIED |
| `can_send_alert_channel` email rate limit | `app/services/rate_limit.py` | 321-323 | VERIFIED |
| `push_devices` table in tables.py | `app/core/tables.py` | 21 | VERIFIED |
| `PushRegisterReq` model | `app/models.py` | 628-630 | VERIFIED |
| Metrics noop pattern in non-production | `app/metrics.py` | 26-55 | VERIFIED |
| Prometheus counters (existing pattern) | `app/metrics.py` | 57-94 | VERIFIED |

## Appendix B: SES Notification JSON Examples

### Bounce Notification

```json
{
  "Type": "Notification",
  "MessageId": "22b80b92-fdea-4c2c-8f9d-bdfb0c7bf324",
  "TopicArn": "arn:aws:sns:us-east-1:123456789012:ses-notifications",
  "Message": "{\"notificationType\":\"Bounce\",\"bounce\":{\"feedbackId\":\"0102017890abcdef-...\",\"bounceType\":\"Permanent\",\"bounceSubType\":\"General\",\"bouncedRecipients\":[{\"emailAddress\":\"invalid@example.com\",\"action\":\"failed\",\"status\":\"5.1.1\",\"diagnosticCode\":\"smtp; 550 5.1.1 <invalid@example.com>... User unknown\"}],\"timestamp\":\"2026-05-27T12:00:00.000Z\"},\"mail\":{\"messageId\":\"0102017890abcdef-12345678\",\"timestamp\":\"2026-05-27T11:59:50.000Z\",\"source\":\"noreply@staging.example.com\",\"destination\":[\"invalid@example.com\"]}}"
}
```

### Complaint Notification

```json
{
  "Type": "Notification",
  "MessageId": "33c90c03-feeb-5d3d-9a0e-cefc1d8eg435",
  "TopicArn": "arn:aws:sns:us-east-1:123456789012:ses-notifications",
  "Message": "{\"notificationType\":\"Complaint\",\"complaint\":{\"feedbackId\":\"0102017890abcdef-...\",\"complaintSubType\":null,\"complainedRecipients\":[{\"emailAddress\":\"annoyed@example.com\"}],\"timestamp\":\"2026-05-27T13:00:00.000Z\",\"complaintFeedbackType\":\"abuse\"},\"mail\":{\"messageId\":\"0102017890abcdef-cafebabe\",\"timestamp\":\"2026-05-27T12:55:00.000Z\",\"source\":\"noreply@staging.example.com\",\"destination\":[\"annoyed@example.com\"]}}"
}
```


---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_email_delivery.py`

| # | Test Function | Description |
|---|--------------|-------------|
| 1 | `test_send_logs_failure` | Logger called with exception() on SES error |
| 2 | `test_send_returns_message_id` | Non-None string on success |
| 3 | `test_send_disabled_returns_none` | alerts_email_enabled=False; None |
| 4 | `test_record_sent_writes_item` | DDB item with status=sent |
| 5 | `test_bounce_suppresses_hard` | Permanent bounce creates SUPPRESS item |
| 6 | `test_bounce_skips_transient` | Transient bounce; no SUPPRESS item |
| 7 | `test_complaint_suppresses` | All complainants suppressed |
| 8 | `test_is_suppressed_true` | Correct after suppress_email() |
| 9 | `test_is_suppressed_fails_open` | DDB error; returns False |
| 10 | `test_ses_notification_bounce` | POST bounce JSON; 200; bounce recorded |

All tests use moto-mocked DynamoDB.

### Integration Tests

| # | Scenario | Services Involved |
|---|----------|-------------------|
| 1 | Send filters suppressed addresses | alerts service + email_delivery service |
| 2 | SES notification processes bounce and suppresses | ses_notifications router + email_delivery |
| 3 | Admin stats aggregates across statuses | admin_email router + email_delivery service |

### E2E Tests (Playwright)

**File**: `frontend/e2e/email-delivery.spec.ts` -- 18 tests

**Auth**: `injectAuth(page, identity)` for cookie auth; CSRF header for mutations.

Sections: 1 (delivery API, 6), 2 (SES notification webhook, 4), 3 (suppression, 3), 4 (admin UI, 5)

**Negative/edge tests**: 403 for non-admin on stats, bounce auto-suppresses, complaint auto-suppresses

### Test Data Requirements

- DDB seeds: email_delivery table with ByStatus GSI
- Test users: Root (admin), Alice (non-admin)
- SES mock (moto) for send_email

### CI/Pipeline

- Feature flags: ALERTS_EMAIL_ENABLED=1, EMAIL_SUPPRESSION_ENABLED=1
- Serial execution (1 worker), 1 retry per playwright.config.ts
- Retry-safe: unique timestamps in test data


---

## Dependencies & Merge Safety

### Depends On

| Ticket | Type | Detail |
|--------|------|--------|
| (none) | -- | Standalone feature |

### Depended On By

| Ticket | Type | Detail |
|--------|------|--------|
| PLATFORM-007 | Pattern | SMS production follows same delivery tracking pattern |

### Merge Strategy

**Independent** -- No prerequisites. Extends existing send_alert_email().

### Merge Checklist

- [ ] send_alert_email() logs errors and returns message_id
- [ ] email_delivery DDB table with ByStatus GSI
- [ ] SES notification webhook at /internal/ses/notifications
- [ ] Suppression list with auto-suppress on hard bounce/complaint
- [ ] Admin endpoints for stats/bounces/complaints/suppressed
- [ ] EmailDeliveryPage admin dashboard
- [ ] E2E pass: `npx playwright test e2e/email-delivery.spec.ts`
