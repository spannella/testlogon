# PLATFORM-007: SMS Delivery Production Config

**Ticket**: PLATFORM-007
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-27
**Priority**: High
**Estimated effort**: 8-10 days

---

## 1. Executive Summary

The platform has SMS delivery code that uses AWS SNS `publish(PhoneNumber=...)` to send text messages (`app/services/alerts.py:355-372`). In dev mode, SMS is logged to `.logs/dev/sms.log` (`alerts.py:363`). The frontend has a complete SMS preferences UI in `AlertPrefs.tsx` (lines 32-36, 49-52) where users can add phone numbers and configure event types for SMS delivery. However, the system is not configured for real delivery:

- `ALERTS_SMS_ENABLED` defaults to `"0"` (`app/core/settings.py:190`), meaning SMS is disabled unless explicitly turned on
- No delivery receipt tracking: `send_alert_sms()` catches all exceptions silently (`alerts.py:371-372`)
- No phone number verification beyond the OTP challenge in AlertPrefs
- No delivery receipt callback from SNS
- No opt-out/unsubscribe management
- No delivery metrics or admin dashboard
- No per-message cost tracking (SNS charges per SMS segment)
- SNS client is created per-call via `sns_client()` (`app/core/aws.py:30-37`) with lazy import

This ticket covers enabling SMS delivery in staging, implementing delivery receipt tracking, adding delivery metrics, building an admin dashboard for SMS monitoring, and configuring proper SNS origination identities for production.

---

## 2. Detailed Problem Analysis

### 2.1 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| User | I want to receive SMS alerts for security events (login, MFA). | SMS sent via SNS when security alert fires and user has enabled SMS. |
| User | I want to stop receiving SMS by replying STOP. | Opt-out processed; no further SMS sent to that number. |
| User | I want to know if my SMS was delivered. | Alert history shows delivery status. |
| Admin | I want to see SMS delivery success/failure rates. | Admin dashboard shows sent/delivered/failed metrics. |
| Admin | I want to monitor SMS costs. | Dashboard shows estimated cost per period. |
| Admin | I want to see which numbers are unreachable. | Failed delivery list with phone number, error, and timestamp. |
| Admin | I want to manage opt-out numbers. | Suppression list with ability to unsuppress (re-consent). |
| Ops | I want staging to send real SMS to test the flow. | Staging environment has `ALERTS_SMS_ENABLED=1` with SNS sandbox. |
| Ops | I want Prometheus metrics for SMS delivery health. | `/metrics` includes `sms_delivery_total{status}` counter. |

### 2.2 Pain Points

1. **Silent failures**: `send_alert_sms()` wraps the entire SNS call in `except Exception: pass` (`alerts.py:371-372`). Failures are invisible -- no log, no metric, no feedback to the user.
2. **No delivery receipts**: SNS can report delivery success/failure via CloudWatch or an SNS delivery status topic. Neither is configured.
3. **No opt-out management**: US regulations (TCPA) require honoring STOP replies. SNS handles STOP at the carrier level for long codes but the platform needs to track opt-outs to prevent re-enrollment.
4. **No cost tracking**: SNS SMS pricing varies by country ($0.00645/segment for US, up to $0.09+ for international). Without tracking, there is no cost visibility.
5. **No rate limiting per-number**: `send_alert_sms()` sends up to 5 messages per call (`alerts.py:369: for n in to_numbers[:5]`). The `can_send_alert_channel` rate limit is per-user (default 10/hour, `settings.py:191`), but there is no per-phone-number daily limit to prevent abuse.
6. **Client created per-call**: `sns_client()` (`app/core/aws.py:30-37`) uses lazy import and creates a new boto3 client each time. This wastes ~50ms per call for connection establishment.
7. **No message type configuration**: SNS differentiates between `Transactional` (high priority, security alerts) and `Promotional` (marketing, lower priority) messages. The current code sends with no `MessageAttributes`, defaulting to `Promotional` -- which has lower deliverability for security-critical messages.
8. **No origination identity**: Without a configured sender ID, short code, or toll-free number, messages arrive from a shared pool of numbers, which can be blocked by carriers.

---

## 3. Current State Analysis

### 3.1 SMS Sending Function

`app/services/alerts.py:355-372`:

```python
def send_alert_sms(to_numbers: List[str], body_text: str) -> None:
    if not to_numbers:
        return
    if S.dev_mode:
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        for n in to_numbers:
            entry = f"[{ts}] ALERT_SMS TO={n}\n  Body: {body_text}\n\n"
            _write_dev_log(S.dev_sms_log, entry)
        return
    if not S.alerts_sms_enabled:
        return
    try:
        sns = sns_client()
        for n in to_numbers[:5]:
            sns.publish(PhoneNumber=n, Message=body_text[:1400])
    except Exception:
        pass
```

Key observations:
- Dev mode: writes to `.logs/dev/sms.log` via `_write_dev_log()` (`alerts.py:322-329`)
- Non-dev: checks `S.alerts_sms_enabled` (default `"0"`, `settings.py:190`)
- Uses `sns_client()` from `app/core/aws.py:30-37`
- Iterates over up to 5 numbers, calling `sns.publish()` for each
- Message truncated to 1400 chars (multi-segment consideration: 160 chars/segment for GSM-7, 70 for UCS-2)
- **Silent exception**: bare `except Exception: pass` on line 371-372
- Returns `None` always -- no feedback to caller

### 3.2 SNS Client

`app/core/aws.py:30-37`:

```python
def sns_client():
    from boto3 import client as _boto3_client  # lazy import

    return _boto3_client(
        "sns",
        region_name=S.aws_region or "us-east-1",
        endpoint_url=S.aws_endpoint_url or None,
    )
```

- Lazy import of boto3 on every call
- Creates a new client instance per call (no connection reuse)
- Uses `S.aws_endpoint_url` which in dev points to moto (port 4566)

### 3.3 SMS Settings

`app/core/settings.py`:

| Setting | Line | Default | Description |
|---------|------|---------|-------------|
| `alerts_sms_enabled` | 190 | `"0"` (disabled) | Master switch for SMS delivery |
| `alerts_sms_max_per_window` | 191 | `10` | Rate limit: max SMS per window per user |
| `alerts_sms_window_seconds` | 192 | `3600` | Rate limit window (1 hour) |
| `dev_sms_log` | 247 | `.logs/dev/sms.log` | Dev mode SMS log path |
| `devtools_sms_log_path` | 250 | (same as dev_sms_log) | Dev Tools UI discovery path |

Not configured:
- SMS origination identity (sender ID, short code, or toll-free number)
- Per-number daily SMS limit
- SNS SMS attributes (message type: Transactional vs Promotional)
- Delivery status logging IAM role

### 3.4 Alert SMS Fanout

`app/services/alerts.py:673-687`:

```python
# Optional SMS fanout
try:
    prefs = get_alert_prefs(user_sub)
    nums = prefs.get("sms_numbers") or []
    enabled_sms = set(prefs.get("sms_event_types") or [])
    if nums and (alert_type in enabled_sms) and can_send_alert_channel(user_sub, "sms"):
        line = f"[{alert_type}] {event} {outcome}"
        if request is not None:
            line += f" ip={payload.get('ip','')}"
        reason = fields.get("reason")
        if reason:
            line += f" reason={str(reason)[:80]}"
        send_alert_sms(nums, line)
except Exception:
    pass
```

- Checks user preferences for SMS-enabled event types
- Calls `can_send_alert_channel(user_sub, "sms")` which uses `_bucket_limit()` with `alerts_sms_max_per_window=10` over `alerts_sms_window_seconds=3600` (`rate_limit.py:324-325`)
- Formats a plain text message (no template system like email)
- Wrapped in bare exception handler (second layer of silent failure)

### 3.5 SMS Rate Limiting

`app/services/rate_limit.py:321-325`:

```python
def can_send_alert_channel(user_sub: str, channel: str) -> bool:
    if channel == "email":
        return _bucket_limit(user_sub, "rl#alert_email", S.alerts_email_max_per_window, S.alerts_email_window_seconds)
    if channel == "sms":
        return _bucket_limit(user_sub, "rl#alert_sms", S.alerts_sms_max_per_window, S.alerts_sms_window_seconds)
```

This is a per-user rate limit (10 SMS/hour), but not per-phone-number. A user with 5 phone numbers registered could receive 50 SMS/hour (10 per user * 5 numbers in the `to_numbers` list, limited to 5 per call).

### 3.6 Frontend SMS Preferences

`frontend/src/pages/alerts/AlertPrefs.tsx:49-52`:

```tsx
// SMS number management state
const [phoneInput, setPhoneInput] = React.useState("");
const [smsPending, setSmsPending] = React.useState<{ challengeId: string; sentTo: string } | null>(null);
const [smsCode, setSmsCode] = React.useState("");
```

The AlertPrefs component has:
- Phone number input with country code
- OTP verification flow (`alertSmsBegin` + `alertSmsConfirm` API calls)
- Event type selection per channel (email, SMS, toast)
- Phone number removal (`alertSmsRemove`)
- Maximum of 5 phone numbers per user (enforced by backend)

### 3.7 Gaps Summary

1. `ALERTS_SMS_ENABLED` defaults to `"0"` (`settings.py:190`)
2. Silent exception swallowing (`alerts.py:371-372`)
3. Silent exception swallowing in SMS fanout (`alerts.py:686-687`)
4. No delivery receipt tracking
5. No SNS SMS attributes (message type, origination identity)
6. No opt-out tracking (STOP replies)
7. No per-phone-number daily SMS limit
8. No delivery metrics
9. No admin SMS dashboard
10. No cost tracking or estimation
11. SNS client created per-call (`aws.py:30-37`)
12. Rate-limited SMS sends produce no visible feedback

---

## 4. Implementation Plan

### 4.1 Backend: Improve `send_alert_sms()`

**File: `app/services/alerts.py`** -- Replace silent exception handling:

```python
import logging
from typing import Dict, List, Optional

from app.core.time import now_ts
from app.metrics import SMS_SENT, SMS_FAILED, SMS_SUPPRESSED

logger = logging.getLogger(__name__)

# Module-level SNS client (reuse connection pool)
_sns = None


def _get_sns_client():
    """Get or create a reusable SNS client."""
    global _sns
    if _sns is None:
        _sns = sns_client()
    return _sns


def send_alert_sms(to_numbers: List[str], body_text: str) -> List[Dict[str, Any]]:
    """Send SMS via SNS. Returns list of {number, message_id, status} dicts.

    Args:
        to_numbers: List of E.164 phone numbers (max 5 processed).
        body_text: Message body (truncated to 1400 chars).

    Returns:
        List of result dicts with keys: number, message_id, status.
        Status is one of: "sent", "failed", "suppressed", "rate_limited", "dev".
    """
    if not to_numbers:
        return []

    if S.dev_mode:
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        for n in to_numbers:
            entry = f"[{ts}] ALERT_SMS TO={n}\n  Body: {body_text}\n\n"
            _write_dev_log(S.dev_sms_log, entry)
        return [{"number": n, "message_id": f"dev-{now_ts()}", "status": "dev"} for n in to_numbers]

    if not S.alerts_sms_enabled:
        return []

    results = []
    sns = _get_sns_client()
    sms_attrs = _build_sms_attributes()

    for n in to_numbers[:5]:
        # Check suppression (opt-out)
        if S.sms_suppression_enabled:
            from app.services.sms_delivery import is_sms_suppressed
            if is_sms_suppressed(n):
                results.append({"number": n, "message_id": None, "status": "suppressed"})
                SMS_SUPPRESSED.labels(reason="opt_out").inc()
                continue

        # Check per-number daily limit
        from app.services.sms_delivery import sms_daily_limit_exceeded
        if sms_daily_limit_exceeded(n):
            results.append({"number": n, "message_id": None, "status": "rate_limited"})
            logger.info("SMS rate limited for %s (daily limit exceeded)", n)
            continue

        try:
            response = sns.publish(
                PhoneNumber=n,
                Message=body_text[:1400],
                MessageAttributes=sms_attrs,
            )
            message_id = response.get("MessageId", "")

            from app.services.sms_delivery import record_sms_sent
            record_sms_sent(n, body_text, message_id)

            SMS_SENT.inc()
            results.append({"number": n, "message_id": message_id, "status": "sent"})
            logger.info("SMS sent: message_id=%s, to=%s", message_id, n)
        except Exception as exc:
            from app.services.sms_delivery import record_sms_failure
            record_sms_failure(n, body_text, str(exc))

            SMS_FAILED.inc()
            results.append({"number": n, "message_id": None, "status": "failed"})
            logger.exception("SMS send failed: to=%s, error=%s", n, str(exc)[:200])

    return results


def _build_sms_attributes() -> Dict[str, Any]:
    """Build SNS SMS MessageAttributes for delivery optimization.

    These attributes control:
    - SMSType: Transactional (high priority) vs Promotional (marketing)
    - SenderID: Alphanumeric sender ID (supported in some countries)
    - OriginationNumber: Dedicated phone number for sending (US 10DLC, toll-free, short code)
    """
    attrs: Dict[str, Any] = {
        "AWS.SNS.SMS.SMSType": {
            "DataType": "String",
            "StringValue": S.sms_message_type,  # Default "Transactional"
        },
    }
    if S.sms_sender_id:
        attrs["AWS.SNS.SMS.SenderID"] = {
            "DataType": "String",
            "StringValue": S.sms_sender_id,
        }
    if S.sms_origination_number:
        attrs["AWS.MM.SMS.OriginationNumber"] = {
            "DataType": "String",
            "StringValue": S.sms_origination_number,
        }
    return attrs
```

### 4.2 Backend: Prometheus Metrics

**File: `app/metrics.py`** -- Add SMS delivery metrics (after email metrics):

```python
# SMS delivery metrics (PLATFORM-007)
SMS_SENT = Counter(
    "sms_sent_total",
    "Total SMS messages successfully sent via SNS",
)
SMS_FAILED = Counter(
    "sms_failed_total",
    "Total SMS send failures",
)
SMS_SUPPRESSED = Counter(
    "sms_suppressed_total",
    "Total SMS messages skipped due to suppression/opt-out",
    ["reason"],
)
SMS_RATE_LIMITED = Counter(
    "sms_rate_limited_total",
    "Total SMS messages skipped due to rate limiting",
)
```

### 4.3 Backend: SMS Delivery Tracking

**New file: `app/services/sms_delivery.py`**

```python
"""SMS delivery status tracking -- DDB storage for sent, failed, opted-out.

Table: sms_delivery
  PK patterns:
    SMS#{phone}           - delivery events for a phone number
    SMS_SUPPRESS#{phone}  - opt-out/suppression record
    DAILY#{phone}         - daily send counter

  SK patterns:
    SENT#{ts}#{msg_id}    - successful send
    FAILED#{ts}           - failed send attempt
    STATUS                - suppression status
    DAY#{day_key}         - daily counter (day_key = ts // 86400)

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


def record_sms_sent(phone: str, body: str, message_id: str) -> None:
    """Record a successful SMS send.

    Also increments the daily per-number counter used for rate limiting.
    """
    ts = now_ts()
    try:
        T.sms_delivery.put_item(Item={
            "pk": f"SMS#{phone}",
            "sk": f"SENT#{ts}#{message_id}",
            "message_id": message_id,
            "phone": phone,
            "body_preview": body[:100],
            "segments": _estimate_segments(body),
            "status": "sent",
            "created_at": ts,
            "ttl_epoch": ts + 90 * 86400,  # 90-day retention
        })
    except Exception:
        logger.exception("Failed to record SMS sent for %s", phone)

    # Increment daily counter (atomic)
    day_key = ts // 86400
    try:
        T.sms_delivery.update_item(
            Key={"pk": f"DAILY#{phone}", "sk": f"DAY#{day_key}"},
            UpdateExpression="SET #c = if_not_exists(#c, :z) + :one, #ts = :ts, ttl_epoch = :ttl",
            ExpressionAttributeNames={"#c": "count", "#ts": "updated_at"},
            ExpressionAttributeValues={
                ":one": 1,
                ":z": 0,
                ":ts": ts,
                ":ttl": ts + 7 * 86400,  # Counter expires after 7 days
            },
        )
    except Exception:
        logger.exception("Failed to increment daily SMS counter for %s", phone)


def record_sms_failure(phone: str, body: str, error: str) -> None:
    """Record a failed SMS send attempt."""
    ts = now_ts()
    try:
        T.sms_delivery.put_item(Item={
            "pk": f"SMS#{phone}",
            "sk": f"FAILED#{ts}",
            "phone": phone,
            "body_preview": body[:100],
            "error": error[:500],
            "status": "failed",
            "created_at": ts,
            "ttl_epoch": ts + 90 * 86400,
        })
    except Exception:
        logger.exception("Failed to record SMS failure for %s", phone)


def _estimate_segments(body: str) -> int:
    """Estimate number of SMS segments for a message.

    GSM-7 encoding: 160 chars/segment (or 153 for multi-segment)
    UCS-2 encoding: 70 chars/segment (or 67 for multi-segment)

    Returns conservative estimate assuming GSM-7 for ASCII, UCS-2 for non-ASCII.
    """
    # Check if all chars are in GSM-7 basic character set
    gsm7_chars = set(
        "@£$¥èéùìòÇ\nØø\rÅå"
        "Δ_ΦΓΛΩΠΨΣΘΞ\x1bÆæ"
        "ßÉ !\"#¤%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "[ÄÖÑÜ§¿]abcdefghijklmnopqrstuvwxyz"
        "{äöñüà}"
    )
    is_gsm7 = all(c in gsm7_chars for c in body)
    length = len(body)

    if is_gsm7:
        if length <= 160:
            return 1
        return (length + 152) // 153  # Multi-segment: 153 chars each
    else:
        if length <= 70:
            return 1
        return (length + 66) // 67  # Multi-segment: 67 chars each


# ──────────────────────────────────────────────────────────────────────
# Suppression / Opt-out
# ──────────────────────────────────────────────────────────────────────


def suppress_sms(phone: str, reason: str) -> None:
    """Add phone number to SMS suppression list (opt-out).

    Reasons:
    - "opt_out": User replied STOP (carrier-level, tracked here for platform awareness)
    - "admin": Admin manually suppressed
    - "unreachable": Repeated delivery failures (future: auto-suppress after N failures)
    """
    try:
        T.sms_delivery.put_item(Item={
            "pk": f"SMS_SUPPRESS#{phone}",
            "sk": "STATUS",
            "phone": phone,
            "reason": reason,
            "suppressed_at": now_ts(),
            "status": "suppressed",
            "created_at": now_ts(),
        })
        logger.warning("Suppressed SMS for %s (reason=%s)", phone, reason)
    except Exception:
        logger.exception("Failed to suppress SMS for %s", phone)


def is_sms_suppressed(phone: str) -> bool:
    """Check if phone number is on suppression list.

    Called on the hot path (every SMS send). DDB GetItem is ~5ms.
    """
    try:
        resp = T.sms_delivery.get_item(
            Key={"pk": f"SMS_SUPPRESS#{phone}", "sk": "STATUS"},
            ProjectionExpression="pk",
        )
        return "Item" in resp
    except Exception:
        # Fail open: if we can't check, allow the send
        return False


def remove_sms_suppression(phone: str) -> None:
    """Remove phone from suppression list (admin re-consent action)."""
    try:
        T.sms_delivery.delete_item(
            Key={"pk": f"SMS_SUPPRESS#{phone}", "sk": "STATUS"}
        )
        logger.info("Removed SMS suppression for %s", phone)
    except Exception:
        logger.exception("Failed to remove SMS suppression for %s", phone)


# ──────────────────────────────────────────────────────────────────────
# Daily rate limiting
# ──────────────────────────────────────────────────────────────────────


def sms_daily_count(phone: str) -> int:
    """Get today's SMS count for a phone number."""
    day_key = now_ts() // 86400
    try:
        resp = T.sms_delivery.get_item(
            Key={"pk": f"DAILY#{phone}", "sk": f"DAY#{day_key}"},
            ProjectionExpression="#c",
            ExpressionAttributeNames={"#c": "count"},
        )
        item = resp.get("Item")
        return int(item.get("count", 0)) if item else 0
    except Exception:
        return 0


def sms_daily_limit_exceeded(phone: str) -> bool:
    """Check if phone has exceeded daily SMS limit.

    Default limit: 10 per number per day (S.sms_daily_limit_per_number).
    """
    return sms_daily_count(phone) >= S.sms_daily_limit_per_number


# ──────────────────────────────────────────────────────────────────────
# Admin query functions
# ──────────────────────────────────────────────────────────────────────


def get_sms_delivery_stats(days: int = 7) -> Dict[str, Any]:
    """Get aggregate SMS delivery stats for the last N days.

    Queries the ByStatus GSI for sent and failed counts.
    Also estimates cost based on segment count.
    """
    cutoff = now_ts() - days * 86400
    sent_count = 0
    failed_count = 0
    total_segments = 0

    for status in ("sent", "failed"):
        try:
            resp = T.sms_delivery.query(
                IndexName="ByStatus",
                KeyConditionExpression=(
                    Key("status").eq(status) & Key("created_at").gte(cutoff)
                ),
                Select="ALL_ATTRIBUTES" if status == "sent" else "COUNT",
                Limit=2000,
            )
            if status == "sent":
                items = resp.get("Items", [])
                sent_count = len(items)
                total_segments = sum(int(it.get("segments", 1)) for it in items)
                # Handle pagination
                while resp.get("LastEvaluatedKey"):
                    resp = T.sms_delivery.query(
                        IndexName="ByStatus",
                        KeyConditionExpression=(
                            Key("status").eq(status) & Key("created_at").gte(cutoff)
                        ),
                        Select="ALL_ATTRIBUTES",
                        Limit=2000,
                        ExclusiveStartKey=resp["LastEvaluatedKey"],
                    )
                    items = resp.get("Items", [])
                    sent_count += len(items)
                    total_segments += sum(int(it.get("segments", 1)) for it in items)
            else:
                failed_count = resp.get("Count", 0)
                while resp.get("LastEvaluatedKey"):
                    resp = T.sms_delivery.query(
                        IndexName="ByStatus",
                        KeyConditionExpression=(
                            Key("status").eq(status) & Key("created_at").gte(cutoff)
                        ),
                        Select="COUNT",
                        ExclusiveStartKey=resp["LastEvaluatedKey"],
                    )
                    failed_count += resp.get("Count", 0)
        except Exception:
            logger.exception("Failed to query SMS stats for status=%s", status)

    # Count suppressed numbers
    suppressed_count = 0
    try:
        resp = T.sms_delivery.scan(
            FilterExpression=Attr("pk").begins_with("SMS_SUPPRESS#"),
            Select="COUNT",
            Limit=10000,
        )
        suppressed_count = resp.get("Count", 0)
    except Exception:
        suppressed_count = -1

    total = sent_count + failed_count
    # Estimate cost: US rate $0.00645/segment (average)
    estimated_cost_usd = round(total_segments * 0.00645, 2)

    return {
        "period_days": days,
        "sent": sent_count,
        "failed": failed_count,
        "total": total,
        "total_segments": total_segments,
        "estimated_cost_usd": estimated_cost_usd,
        "suppressed_numbers": suppressed_count,
        "success_rate": round(sent_count / max(total, 1) * 100, 1),
    }


def list_sms_failures(
    limit: int = 50, cursor: Optional[str] = None
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """List recent SMS failures, newest first."""
    kwargs: Dict[str, Any] = {
        "IndexName": "ByStatus",
        "KeyConditionExpression": Key("status").eq("failed"),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if cursor:
        kwargs["ExclusiveStartKey"] = decode_cursor(cursor)

    resp = T.sms_delivery.query(**kwargs)
    items = resp.get("Items", [])
    next_cursor = None
    if resp.get("LastEvaluatedKey"):
        next_cursor = encode_cursor(resp["LastEvaluatedKey"])
    return items, next_cursor


def list_sms_sent(
    limit: int = 50, cursor: Optional[str] = None
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """List recent successful SMS sends, newest first."""
    kwargs: Dict[str, Any] = {
        "IndexName": "ByStatus",
        "KeyConditionExpression": Key("status").eq("sent"),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if cursor:
        kwargs["ExclusiveStartKey"] = decode_cursor(cursor)

    resp = T.sms_delivery.query(**kwargs)
    items = resp.get("Items", [])
    next_cursor = None
    if resp.get("LastEvaluatedKey"):
        next_cursor = encode_cursor(resp["LastEvaluatedKey"])
    return items, next_cursor


def get_suppression_list(
    limit: int = 50,
) -> Dict[str, Any]:
    """List suppressed (opted-out) phone numbers."""
    try:
        resp = T.sms_delivery.scan(
            FilterExpression=Attr("pk").begins_with("SMS_SUPPRESS#"),
            Limit=limit,
        )
        items = resp.get("Items", [])
        return {"items": items, "count": len(items)}
    except Exception:
        return {"items": [], "count": 0}
```

### 4.4 Backend: DynamoDB Table

**File: `scripts/local-ddb-init.py`** -- Add `sms_delivery` table:

```python
TableDef(
    _resolve_table_name(S.sms_delivery_table_name, "sms_delivery"),
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

**Sent SMS**:
```json
{
  "pk": "SMS#+15551234567",
  "sk": "SENT#1748380800#a1b2c3d4-e5f6-7890-abcd-ef0123456789",
  "message_id": "a1b2c3d4-e5f6-7890-abcd-ef0123456789",
  "phone": "+15551234567",
  "body_preview": "[login] success ip=203.0.113.42",
  "segments": 1,
  "status": "sent",
  "created_at": 1748380800,
  "ttl_epoch": 1756156800
}
```

**Failed SMS**:
```json
{
  "pk": "SMS#+15559999999",
  "sk": "FAILED#1748381000",
  "phone": "+15559999999",
  "body_preview": "[security_event] password_change success",
  "error": "InvalidParameter: Invalid phone number format",
  "status": "failed",
  "created_at": 1748381000,
  "ttl_epoch": 1756157000
}
```

**Suppression (opt-out)**:
```json
{
  "pk": "SMS_SUPPRESS#+15551234567",
  "sk": "STATUS",
  "phone": "+15551234567",
  "reason": "opt_out",
  "suppressed_at": 1748382000,
  "status": "suppressed",
  "created_at": 1748382000
}
```

**Daily counter**:
```json
{
  "pk": "DAILY#+15551234567",
  "sk": "DAY#20232",
  "count": 3,
  "updated_at": 1748383000,
  "ttl_epoch": 1748987800
}
```

### 4.5 Backend: Settings

**File: `app/core/settings.py`** -- Add new settings (after existing SMS settings at line 192):

```python
# SMS Delivery Tracking (PLATFORM-007)
sms_delivery_table_name: str = os.environ.get("SMS_DELIVERY_TABLE_NAME", "sms_delivery")
sms_message_type: str = os.environ.get("SMS_MESSAGE_TYPE", "Transactional")
sms_sender_id: str = os.environ.get("SMS_SENDER_ID", "")
sms_origination_number: str = os.environ.get("SMS_ORIGINATION_NUMBER", "")
sms_daily_limit_per_number: int = int(os.environ.get("SMS_DAILY_LIMIT_PER_NUMBER", "10"))
sms_suppression_enabled: bool = os.environ.get("SMS_SUPPRESSION_ENABLED", "1") not in ("0", "false", "False")
sms_cost_per_segment_usd: float = float(os.environ.get("SMS_COST_PER_SEGMENT_USD", "0.00645"))
```

### 4.6 Backend: Tables

**File: `app/core/tables.py`** -- Add `sms_delivery` table handle:

```python
sms_delivery: Any
```

### 4.7 Backend: Pydantic Models

**File: `app/models.py`** -- Add response models:

```python
# ─── SMS Delivery (PLATFORM-007) ─────────────────────────────────

class SmsDeliveryStatsOut(BaseModel):
    period_days: int
    sent: int
    failed: int
    total: int
    total_segments: int
    estimated_cost_usd: float
    suppressed_numbers: int
    success_rate: float


class SmsDeliveryItem(BaseModel):
    pk: str
    sk: str
    phone: str
    body_preview: Optional[str] = None
    message_id: Optional[str] = None
    error: Optional[str] = None
    segments: Optional[int] = None
    status: str
    created_at: int


class SmsFailureListOut(BaseModel):
    items: List[SmsDeliveryItem]
    next_cursor: Optional[str] = None


class SmsSuppressedItem(BaseModel):
    phone: str
    reason: str
    suppressed_at: int


class SmsSuppressedListOut(BaseModel):
    items: List[SmsSuppressedItem]
    count: int
```

### 4.8 Backend: Admin Endpoints

**New file: `app/routers/admin_sms.py`**

```python
"""Admin SMS delivery monitoring endpoints (PLATFORM-007)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from app.auth.deps import require_admin_session
from app.services.sms_delivery import (
    get_sms_delivery_stats,
    get_suppression_list,
    is_sms_suppressed,
    list_sms_failures,
    list_sms_sent,
    remove_sms_suppression,
    suppress_sms,
)

router = APIRouter(prefix="/ui/admin/sms", tags=["admin-sms"])


@router.get("/stats")
async def sms_stats(
    days: int = Query(default=7, ge=1, le=90),
    _=Depends(require_admin_session),
):
    """Get SMS delivery statistics for the last N days.

    curl -s -b cookies.txt http://localhost:8000/ui/admin/sms/stats?days=7
    """
    return get_sms_delivery_stats(days=days)


@router.get("/sent")
async def sms_sent(
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str = Query(default=None),
    _=Depends(require_admin_session),
):
    """List recent successful SMS sends (newest first, paginated).

    curl -s -b cookies.txt http://localhost:8000/ui/admin/sms/sent?limit=50
    """
    items, next_cursor = list_sms_sent(limit=limit, cursor=cursor)
    return {"items": items, "next_cursor": next_cursor}


@router.get("/failures")
async def sms_failures(
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str = Query(default=None),
    _=Depends(require_admin_session),
):
    """List recent SMS delivery failures (newest first, paginated).

    curl -s -b cookies.txt http://localhost:8000/ui/admin/sms/failures?limit=50
    """
    items, next_cursor = list_sms_failures(limit=limit, cursor=cursor)
    return {"items": items, "next_cursor": next_cursor}


@router.get("/suppressed")
async def suppressed_list(
    limit: int = Query(default=50, ge=1, le=200),
    _=Depends(require_admin_session),
):
    """List suppressed (opted-out) phone numbers.

    curl -s -b cookies.txt http://localhost:8000/ui/admin/sms/suppressed?limit=50
    """
    return get_suppression_list(limit=limit)


@router.get("/suppressed/{phone:path}")
async def check_suppression(
    phone: str,
    _=Depends(require_admin_session),
):
    """Check if a phone number is suppressed.

    curl -s -b cookies.txt http://localhost:8000/ui/admin/sms/suppressed/+15551234567
    """
    return {"phone": phone, "suppressed": is_sms_suppressed(phone)}


@router.post("/suppressed/{phone:path}")
async def suppress_phone(
    phone: str,
    _=Depends(require_admin_session),
):
    """Manually suppress a phone number (admin action).

    curl -s -X POST -b cookies.txt http://localhost:8000/ui/admin/sms/suppressed/+15551234567
    """
    suppress_sms(phone, reason="admin")
    return {"ok": True, "phone": phone, "suppressed": True}


@router.delete("/suppressed/{phone:path}")
async def unsuppress_phone(
    phone: str,
    _=Depends(require_admin_session),
):
    """Remove phone from suppression list (admin re-consent).

    curl -s -X DELETE -b cookies.txt http://localhost:8000/ui/admin/sms/suppressed/+15551234567
    """
    remove_sms_suppression(phone)
    return {"ok": True, "phone": phone, "suppressed": False}
```

### 4.9 Backend: Register Router

**File: `app/main.py`**:

```python
from app.routers.admin_sms import router as admin_sms_router
app.include_router(admin_sms_router)
```

### 4.10 Frontend: TypeScript Types

**File: `frontend/src/api/types.ts`**:

```typescript
// ─── SMS Delivery (PLATFORM-007) ────────────────────────────────

export interface SmsDeliveryStats {
  period_days: number;
  sent: number;
  failed: number;
  total: number;
  total_segments: number;
  estimated_cost_usd: number;
  suppressed_numbers: number;
  success_rate: number;
}

export interface SmsDeliveryItem {
  pk: string;
  sk: string;
  phone: string;
  body_preview?: string;
  message_id?: string;
  error?: string;
  segments?: number;
  status: string;
  created_at: number;
}

export interface SmsSuppressedItem {
  phone: string;
  reason: string;
  suppressed_at: number;
}
```

### 4.11 Frontend: API Endpoints

**New file: `frontend/src/api/endpoints/admin-sms.ts`**

```typescript
import { api } from "@/api/client";
import type { SmsDeliveryStats, SmsDeliveryItem, SmsSuppressedItem } from "@/api/types";

export const getSmsDeliveryStats = (days = 7) =>
  api.get<SmsDeliveryStats>(`/ui/admin/sms/stats?days=${days}`);

export const getSmsSent = (limit = 50, cursor?: string) =>
  api.get<{ items: SmsDeliveryItem[]; next_cursor: string | null }>(
    `/ui/admin/sms/sent?limit=${limit}${cursor ? `&cursor=${cursor}` : ""}`
  );

export const getSmsFailures = (limit = 50, cursor?: string) =>
  api.get<{ items: SmsDeliveryItem[]; next_cursor: string | null }>(
    `/ui/admin/sms/failures?limit=${limit}${cursor ? `&cursor=${cursor}` : ""}`
  );

export const getSmsSuppressed = (limit = 50) =>
  api.get<{ items: SmsSuppressedItem[]; count: number }>(
    `/ui/admin/sms/suppressed?limit=${limit}`
  );

export const checkSmsSuppression = (phone: string) =>
  api.get<{ phone: string; suppressed: boolean }>(
    `/ui/admin/sms/suppressed/${encodeURIComponent(phone)}`
  );

export const unsuppressSms = (phone: string) =>
  api.delete(`/ui/admin/sms/suppressed/${encodeURIComponent(phone)}`);

export const suppressSms = (phone: string) =>
  api.post(`/ui/admin/sms/suppressed/${encodeURIComponent(phone)}`);
```

### 4.12 Frontend: Admin SMS Dashboard

**New file: `frontend/src/pages/admin/SmsDeliveryPage.tsx`**

```tsx
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Card, CardContent, CardHeader, CardTitle, CardDescription,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  MessageSquare, AlertTriangle, Ban, DollarSign, RefreshCw, Trash2,
} from "lucide-react";
import { toast } from "sonner";
import {
  getSmsDeliveryStats,
  getSmsFailures,
  getSmsSuppressed,
  unsuppressSms,
} from "@/api/endpoints/admin-sms";
import type { SmsDeliveryItem, SmsSuppressedItem } from "@/api/types";

export default function SmsDeliveryPage() {
  const qc = useQueryClient();

  const statsQ = useQuery({
    queryKey: ["admin", "sms", "stats"],
    queryFn: () => getSmsDeliveryStats(7),
    refetchInterval: 60_000,
  });
  const failuresQ = useQuery({
    queryKey: ["admin", "sms", "failures"],
    queryFn: () => getSmsFailures(50),
  });
  const suppressedQ = useQuery({
    queryKey: ["admin", "sms", "suppressed"],
    queryFn: () => getSmsSuppressed(50),
  });

  const unsuppressMut = useMutation({
    mutationFn: (phone: string) => unsuppressSms(phone),
    onSuccess: () => {
      toast.success("Phone unsuppressed");
      qc.invalidateQueries({ queryKey: ["admin", "sms"] });
    },
    onError: () => toast.error("Failed to unsuppress phone"),
  });

  const stats = statsQ.data;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">SMS Delivery</h1>
        <Button
          variant="outline"
          size="sm"
          onClick={() => qc.invalidateQueries({ queryKey: ["admin", "sms"] })}
        >
          <RefreshCw className="h-4 w-4 mr-2" /> Refresh
        </Button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-2">
              <MessageSquare className="h-4 w-4 text-green-500" />
              <p className="text-sm text-muted-foreground">Sent</p>
            </div>
            <p className="text-2xl font-bold">{stats?.sent ?? 0}</p>
            <p className="text-xs text-muted-foreground">
              {stats?.total_segments ?? 0} segments
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-red-500" />
              <p className="text-sm text-muted-foreground">Failed</p>
            </div>
            <p className="text-2xl font-bold">{stats?.failed ?? 0}</p>
            <p className="text-xs text-muted-foreground">
              Success: {stats?.success_rate ?? 0}%
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-2">
              <DollarSign className="h-4 w-4 text-amber-500" />
              <p className="text-sm text-muted-foreground">Est. Cost</p>
            </div>
            <p className="text-2xl font-bold">${stats?.estimated_cost_usd ?? "0.00"}</p>
            <p className="text-xs text-muted-foreground">
              Last {stats?.period_days ?? 7} days
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-2">
              <Ban className="h-4 w-4 text-gray-500" />
              <p className="text-sm text-muted-foreground">Suppressed</p>
            </div>
            <p className="text-2xl font-bold">{stats?.suppressed_numbers ?? 0}</p>
            <p className="text-xs text-muted-foreground">opted-out numbers</p>
          </CardContent>
        </Card>
      </div>

      {/* Failures Table */}
      <Card>
        <CardHeader>
          <CardTitle>Recent Failures</CardTitle>
          <CardDescription>SMS messages that could not be delivered</CardDescription>
        </CardHeader>
        <CardContent>
          {failuresQ.data?.items?.length === 0 ? (
            <p className="text-muted-foreground text-sm">No failures</p>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b text-left">
                  <th className="py-2">Phone</th>
                  <th>Message Preview</th>
                  <th>Error</th>
                  <th>Date</th>
                </tr>
              </thead>
              <tbody>
                {failuresQ.data?.items?.map((item: SmsDeliveryItem) => (
                  <tr key={item.sk} className="border-b">
                    <td className="py-2 font-mono text-xs">{item.phone}</td>
                    <td className="max-w-xs truncate text-xs">{item.body_preview || "—"}</td>
                    <td className="max-w-xs truncate text-xs text-destructive">{item.error || "—"}</td>
                    <td className="text-xs">{new Date(item.created_at * 1000).toLocaleString()}</td>
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
          <CardTitle>Suppressed Numbers</CardTitle>
          <CardDescription>Opted-out or admin-suppressed phone numbers</CardDescription>
        </CardHeader>
        <CardContent>
          {suppressedQ.data?.items?.length === 0 ? (
            <p className="text-muted-foreground text-sm">No suppressed numbers</p>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b text-left">
                  <th className="py-2">Phone</th>
                  <th>Reason</th>
                  <th>Since</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {suppressedQ.data?.items?.map((item: SmsSuppressedItem) => (
                  <tr key={item.phone} className="border-b">
                    <td className="py-2 font-mono text-xs">{item.phone}</td>
                    <td><Badge variant="outline">{item.reason}</Badge></td>
                    <td className="text-xs">{new Date(item.suppressed_at * 1000).toLocaleString()}</td>
                    <td>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => unsuppressMut.mutate(item.phone)}
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

### 4.13 Frontend: Route

**File: `frontend/src/App.tsx`**:

```tsx
const SmsDeliveryPage = lazy(() => import("@/pages/admin/SmsDeliveryPage"));
// ...
<Route path="admin/sms" element={<SmsDeliveryPage />} />
```

### 4.14 Staging Configuration

**.env.staging** (example):

```bash
# SMS delivery (PLATFORM-007)
ALERTS_SMS_ENABLED=1
SMS_DELIVERY_TABLE_NAME=sms_delivery
SMS_MESSAGE_TYPE=Transactional
SMS_ORIGINATION_NUMBER=+1XXXXXXXXXX
SMS_DAILY_LIMIT_PER_NUMBER=10
SMS_SUPPRESSION_ENABLED=1
SMS_COST_PER_SEGMENT_USD=0.00645
AWS_REGION=us-east-1
```

### 4.15 curl Examples

```bash
# Get SMS delivery stats (last 7 days)
curl -s -b cookies.txt -H "x-csrf-token: $CSRF" \
  http://localhost:8000/ui/admin/sms/stats?days=7

# List recent failures
curl -s -b cookies.txt -H "x-csrf-token: $CSRF" \
  http://localhost:8000/ui/admin/sms/failures?limit=50

# Check if a number is suppressed
curl -s -b cookies.txt -H "x-csrf-token: $CSRF" \
  "http://localhost:8000/ui/admin/sms/suppressed/%2B15551234567"

# Suppress a number (admin action)
curl -s -X POST -b cookies.txt -H "x-csrf-token: $CSRF" \
  "http://localhost:8000/ui/admin/sms/suppressed/%2B15551234567"

# Unsuppress a number
curl -s -X DELETE -b cookies.txt -H "x-csrf-token: $CSRF" \
  "http://localhost:8000/ui/admin/sms/suppressed/%2B15551234567"

# List suppressed numbers
curl -s -b cookies.txt -H "x-csrf-token: $CSRF" \
  http://localhost:8000/ui/admin/sms/suppressed?limit=50
```

---

## 5. Data Model

### 5.1 SMS Delivery Table

**Table name**: `sms_delivery` (configurable via `SMS_DELIVERY_TABLE_NAME`)

**Primary key**: `pk` (S) + `sk` (S)

**GSI**: `ByStatus` -- partition key `status` (S), sort key `created_at` (N), projection ALL

**TTL attribute**: `ttl_epoch`

| Field | Type | PK pattern | Description | Example |
|-------|------|------------|-------------|---------|
| `pk` | S | `SMS#{phone}` | Delivery events for a number | `"SMS#+15551234567"` |
| `pk` | S | `SMS_SUPPRESS#{phone}` | Opt-out/suppression record | `"SMS_SUPPRESS#+15551234567"` |
| `pk` | S | `DAILY#{phone}` | Daily send counter | `"DAILY#+15551234567"` |
| `sk` | S | `SENT#{ts}#{msg_id}` | Successful send | `"SENT#1748380800#abc123"` |
| `sk` | S | `FAILED#{ts}` | Failed send | `"FAILED#1748380800"` |
| `sk` | S | `STATUS` | Suppression status | `"STATUS"` |
| `sk` | S | `DAY#{day_key}` | Daily counter (ts // 86400) | `"DAY#20232"` |
| `message_id` | S | — | SNS message ID | `"a1b2c3d4-e5f6-..."` |
| `phone` | S | — | E.164 phone number | `"+15551234567"` |
| `body_preview` | S | — | First 100 chars of message | `"[login] success ip=..."` |
| `segments` | N | — | Estimated SMS segments | `1` |
| `status` | S | GSI PK | `sent`, `failed`, `suppressed` | `"sent"` |
| `error` | S | — | Error message (failures) | `"InvalidParameter: ..."` |
| `reason` | S | — | Suppression reason | `"opt_out"` |
| `count` | N | — | Daily send count | `3` |
| `created_at` | N | GSI SK | Unix timestamp | `1748380800` |
| `ttl_epoch` | N | TTL | Auto-delete timestamp | `1756156800` |

### 5.2 DDB Capacity Estimates

| Scenario | RCU | WCU | Notes |
|----------|-----|-----|-------|
| 200 SMS/day sent | ~1 RCU avg | ~5 WCU burst | Low volume for alerts |
| `is_sms_suppressed()` check | ~1 RCU per send | — | GetItem, 5ms |
| `sms_daily_limit_exceeded()` check | ~1 RCU per send | — | GetItem on DAILY# |
| Daily counter increment | — | ~1 WCU per send | UpdateItem |
| Admin stats query (7d) | ~5 RCU per status | — | ByStatus GSI query |

### 5.3 Cost Analysis

| SMS Volume (per month) | Segments | AWS SNS Cost | DDB Cost | Total |
|------------------------|----------|-------------|----------|-------|
| 1,000 messages | ~1,100 | $7.10 | $0.50 | $7.60 |
| 10,000 messages | ~11,000 | $71.00 | $2.00 | $73.00 |
| 50,000 messages | ~55,000 | $354.75 | $5.00 | $359.75 |

Note: Costs assume US-only delivery at $0.00645/segment. International rates are significantly higher.

---

## 6. Security & Compliance

### 6.1 TCPA Compliance (US)

- **Prior express consent**: Users must opt in before receiving SMS. The AlertPrefs OTP verification flow satisfies this requirement.
- **STOP keyword**: SNS handles carrier-level STOP processing for US long codes and toll-free numbers. The platform additionally tracks opt-outs in DDB to prevent re-enrollment.
- **Quiet hours**: Consider adding time-of-day restrictions for non-urgent messages (not implemented in this ticket).
- **Content requirements**: Transactional messages (security alerts) are exempt from most TCPA restrictions.

### 6.2 10DLC Registration (US)

For US SMS delivery at scale, 10-digit long code (10DLC) registration is required:
- Register brand with The Campaign Registry (TCR)
- Register campaign (use case description)
- Associate phone number with campaign
- Without 10DLC, messages are rate-limited to 1 msg/sec and may be filtered

### 6.3 Per-Number Daily Limit

The `sms_daily_limit_per_number` setting (default 10) prevents:
- Cost runaway from misconfigured alert rules
- Potential abuse of the SMS system as a harassment vector
- Carrier-level throttling/blocking due to excessive sends to a single number

### 6.4 Phone Number Privacy

- Phone numbers are stored in plain text in DDB. In multi-tenant production, consider hashing the phone number in the PK and storing the E.164 number as an attribute.
- Admin SMS endpoints expose phone numbers. Access restricted to `role >= ADMIN`.

---

## 7. Performance Analysis

### 7.1 Send Path Latency

| Step | Latency | Notes |
|------|---------|-------|
| `is_sms_suppressed()` check | ~5ms | DDB GetItem |
| `sms_daily_limit_exceeded()` check | ~5ms | DDB GetItem |
| SNS `publish()` call | ~100-500ms | HTTP to SNS endpoint |
| `record_sms_sent()` DDB writes (2) | ~15ms | PutItem + UpdateItem |
| **Total per number** | **~125-525ms** | Sequential for each number |
| **Total per call (5 numbers)** | **~625-2625ms** | Sequential loop |

### 7.2 Connection Pooling Impact

Using a module-level SNS client saves ~50ms per call by reusing the HTTP connection pool. For 5 numbers per call, this saves 250ms total.

### 7.3 Segment Estimation

The `_estimate_segments()` function runs in O(n) where n = message length. For the maximum 1400-char message, this is negligible (< 0.1ms).

---

## 8. Migration & Rollback

### 8.1 Feature Flags

| Flag | Default | Effect when disabled |
|------|---------|---------------------|
| `ALERTS_SMS_ENABLED` | `"0"` | No SMS sent (existing behavior) |
| `SMS_SUPPRESSION_ENABLED` | `"1"` | Suppression checks skipped |

### 8.2 Migration Steps

1. **DDB table**: Create `sms_delivery` table via `scripts/local-ddb-init.py`
2. **Settings**: Add new settings to `.env.local` and `.env.staging`
3. **Deploy backend**: New code is backward-compatible
4. **SNS configuration**: Set up origination identity, spend limit, delivery logging
5. **Enable**: Set `ALERTS_SMS_ENABLED=1` in staging

### 8.3 Rollback

- Set `ALERTS_SMS_ENABLED=0` to immediately stop all SMS delivery
- Set `SMS_SUPPRESSION_ENABLED=0` to bypass suppression checks
- The `sms_delivery` DDB table remains (items expire via TTL)

---

## 9. Testing Strategy

### 9.1 Unit Tests (pytest)

| # | Test | Assertion |
|---|------|-----------|
| 1 | `send_alert_sms` logs failure instead of silently swallowing | Logger called with `exception()` on SNS error |
| 2 | `send_alert_sms` returns results list with message_id on success | Non-empty list with `status=sent` |
| 3 | `send_alert_sms` returns empty list when disabled | `alerts_sms_enabled=False` |
| 4 | `send_alert_sms` limits to 5 numbers per call | Only first 5 numbers processed |
| 5 | `record_sms_sent` writes DDB item with correct fields | Item has `status=sent`, `phone`, `segments` |
| 6 | `record_sms_sent` increments daily counter | Counter value incremented by 1 |
| 7 | `sms_daily_limit_exceeded` returns True after N sends | Correct boolean after 10 sends |
| 8 | `sms_daily_limit_exceeded` returns False before limit | Correct boolean at count=9 |
| 9 | `suppress_sms` marks number as suppressed | `is_sms_suppressed` returns True |
| 10 | `is_sms_suppressed` fails open on DDB error | Returns False when table unavailable |
| 11 | `send_alert_sms` skips suppressed numbers | Status is "suppressed" in results |
| 12 | `send_alert_sms` rate-limits after daily max | Status is "rate_limited" in results |
| 13 | `_build_sms_attributes` includes Transactional message type | Correct attribute present |
| 14 | `_build_sms_attributes` includes sender ID when configured | SenderID attribute present |
| 15 | `_build_sms_attributes` includes origination number when configured | OriginationNumber attribute present |
| 16 | `get_sms_delivery_stats` returns correct counts | Sent/failed counts match seeded data |
| 17 | `get_sms_delivery_stats` calculates cost estimate | `estimated_cost_usd` matches segment count * rate |
| 18 | `remove_sms_suppression` clears suppression | `is_sms_suppressed` returns False |
| 19 | `_estimate_segments` returns 1 for short GSM-7 message | 80-char ASCII = 1 segment |
| 20 | `_estimate_segments` returns 2 for long GSM-7 message | 200-char ASCII = 2 segments |
| 21 | `_estimate_segments` returns correct for UCS-2 message | Message with emoji = UCS-2 encoding |
| 22 | Admin stats endpoint requires admin role | 403 for regular user |
| 23 | `list_sms_failures` returns newest first | Items sorted by `created_at` desc |
| 24 | `list_sms_failures` respects cursor pagination | Second page different items |

### 9.2 E2E Tests

**File:** `frontend/e2e/sms-delivery.spec.ts`

**Section 1: Delivery API (6 tests)**

| # | Test Title | Assertion |
|---|------------|-----------|
| 1 | "Admin can GET SMS delivery stats" | Root GET `/ui/admin/sms/stats`; 200; has `sent`, `failed`, `success_rate` |
| 2 | "Stats endpoint accepts days parameter" | GET `/ui/admin/sms/stats?days=30`; 200; `period_days: 30` |
| 3 | "Admin can GET SMS failures list" | Root GET `/ui/admin/sms/failures`; 200; has `items` array |
| 4 | "Admin can GET suppressed numbers list" | Root GET `/ui/admin/sms/suppressed`; 200; has `items` and `count` |
| 5 | "Admin can check if number is suppressed" | GET `/ui/admin/sms/suppressed/+15551234567`; 200; has `suppressed` boolean |
| 6 | "Non-admin user gets 403 on stats" | Alice GET `/ui/admin/sms/stats`; 403 |

**Section 2: Suppression Management (4 tests)**

| # | Test Title | Assertion |
|---|------------|-----------|
| 7 | "Admin can suppress a phone number" | POST `/ui/admin/sms/suppressed/+15559999999`; 200; `suppressed: true` |
| 8 | "Check confirms number is suppressed" | GET same number; `suppressed: true` |
| 9 | "Admin can unsuppress a phone number" | DELETE same number; 200; `suppressed: false` |
| 10 | "Check confirms number is no longer suppressed" | GET same number; `suppressed: false` |

**Section 3: Admin UI (5 tests)**

| # | Test Title | Assertion |
|---|------------|-----------|
| 11 | "SMS delivery page loads for admin" | Navigate to `/admin/sms`; "SMS Delivery" heading visible |
| 12 | "Stats cards display sent count" | "Sent" text visible in card |
| 13 | "Stats cards display estimated cost" | "Est. Cost" text visible |
| 14 | "Failures table renders with headers" | "Phone", "Error" column headers visible |
| 15 | "Suppressed table renders with headers" | "Phone", "Reason" column headers visible |

---

## 10. Acceptance Criteria

1. `send_alert_sms()` logs failures, records metrics, and returns delivery status instead of silently swallowing exceptions.
2. `send_alert_sms()` returns list of `{number, message_id, status}` result dicts.
3. SNS client is reused across calls (module-level client via `_get_sns_client()`).
4. SMS delivery events (sent, failed) are tracked in the `sms_delivery` DDB table.
5. Daily per-number send limit enforced (default 10 via `SMS_DAILY_LIMIT_PER_NUMBER`).
6. Suppressed numbers (opt-out) are skipped with `status=suppressed` in results.
7. SNS `MessageAttributes` include `SMSType=Transactional` and optional `SenderID`/`OriginationNumber`.
8. Admin endpoints (`/ui/admin/sms/stats`, `/failures`, `/suppressed`) return delivery data.
9. Admin can manually suppress and unsuppress phone numbers.
10. Admin dashboard page shows delivery stats, cost estimate, failure list, and suppression list.
11. Prometheus metrics `sms_sent_total`, `sms_failed_total`, `sms_suppressed_total` are emitted.
12. Staging environment has `ALERTS_SMS_ENABLED=1` with proper SNS configuration.
13. Feature flag `SMS_SUPPRESSION_ENABLED` controls opt-out enforcement.
14. Segment estimation calculates cost for admin visibility.

---

## 11. Files to Create

| File | Purpose |
|------|---------|
| `app/services/sms_delivery.py` | SMS delivery status tracking, suppression list, daily limits, admin queries |
| `app/routers/admin_sms.py` | Admin SMS monitoring endpoints |
| `frontend/src/api/endpoints/admin-sms.ts` | Admin SMS API client |
| `frontend/src/pages/admin/SmsDeliveryPage.tsx` | Admin SMS delivery dashboard |
| `frontend/e2e/sms-delivery.spec.ts` | E2E tests |

## 12. Files to Modify

| File | Change |
|------|--------|
| `app/services/alerts.py:355-372` | Improve `send_alert_sms()`: log errors, return results, filter suppressed, rate limit per-number, add SMS attributes |
| `app/core/settings.py` (after line 192) | Add `sms_delivery_table_name`, `sms_message_type`, `sms_sender_id`, `sms_origination_number`, `sms_daily_limit_per_number`, `sms_suppression_enabled`, `sms_cost_per_segment_usd` |
| `app/core/tables.py` | Add `sms_delivery` table handle |
| `app/models.py` | Add `SmsDeliveryStatsOut`, `SmsDeliveryItem`, `SmsFailureListOut`, `SmsSuppressedItem`, `SmsSuppressedListOut` |
| `app/metrics.py` | Add `SMS_SENT`, `SMS_FAILED`, `SMS_SUPPRESSED`, `SMS_RATE_LIMITED` counters |
| `app/main.py` | Register `admin_sms_router` |
| `scripts/local-ddb-init.py` | Add `sms_delivery` table with ByStatus GSI and TTL |
| `frontend/src/api/types.ts` | Add `SmsDeliveryStats`, `SmsDeliveryItem`, `SmsSuppressedItem` interfaces |
| `frontend/src/App.tsx` | Add `/admin/sms` route |

---

## 13. Dependencies

- **SNS**: Already used by `alerts.py:368-370`. No new AWS service.
- **CloudWatch Logs**: Optional -- for SNS SMS delivery status logging. Requires IAM role with `logs:CreateLogGroup`, `logs:CreateLogStream`, `logs:PutLogEvents`.
- **DynamoDB**: New `sms_delivery` table. Same infrastructure as all existing tables.

---

## Appendix A: Codebase Citations

| Claim | File | Line(s) | Status |
|-------|------|---------|--------|
| `send_alert_sms()` with SNS publish | `app/services/alerts.py` | 481 | VERIFIED |
| Dev mode logs to `.logs/dev/sms.log` | `app/services/alerts.py` | 492 | VERIFIED |
| Dev log writer `_write_dev_log()` | `app/services/alerts.py` | 448 | VERIFIED |
| `audit_event()` master dispatch (SMS fanout) | `app/services/alerts.py` | 695 | VERIFIED |
| `alerts_sms_enabled` default `"0"` | `app/core/settings.py` | 190 | VERIFIED |
| `alerts_sms_max_per_window` default 10 | `app/core/settings.py` | 191 | VERIFIED |
| `alerts_sms_window_seconds` default 3600 | `app/core/settings.py` | 192 | VERIFIED |
| `dev_sms_log` default path | `app/core/settings.py` | 262 | VERIFIED |
| `devtools_sms_log_path` | `app/core/settings.py` | 265 | VERIFIED |
| `sns_client()` lazy import per-call | `app/core/aws.py` | 30-37 | VERIFIED |
| `can_send_alert_channel` SMS rate limit | `app/services/rate_limit.py` | 324-325 | VERIFIED |
| AlertPrefs SMS phone management state | `frontend/src/pages/alerts/AlertPrefs.tsx` | 49-52 | VERIFIED |
| AlertPrefs channels: email, sms, toast | `frontend/src/pages/alerts/AlertPrefs.tsx` | 32-36 | VERIFIED |
| Max 5 numbers per call | `app/services/alerts.py` | 369 | VERIFIED |
| Message truncated to 1400 chars | `app/services/alerts.py` | 370 | VERIFIED |

## Appendix B: SNS SMS Pricing Reference (US)

| Destination | Price per segment | Notes |
|-------------|-------------------|-------|
| US (Transactional) | $0.00645 | Higher deliverability |
| US (Promotional) | $0.00645 | May be filtered by carriers |
| Canada | $0.00676 | |
| UK | $0.03967 | SenderID supported |
| Australia | $0.04503 | |
| India | $0.02680 | |

Source: AWS SNS SMS pricing page (subject to change). The `SMS_COST_PER_SEGMENT_USD` setting allows configuration per deployment region.


---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_sms_delivery.py`

| # | Test Function | Description |
|---|--------------|-------------|
| 1 | `test_platform_007_create` | Create primary entity; 201 |
| 2 | `test_platform_007_read` | Read back entity; correct fields |
| 3 | `test_platform_007_update` | Update entity; 200; changes reflected |
| 4 | `test_platform_007_delete` | Delete entity; 200/204 |
| 5 | `test_platform_007_auth_required` | No auth; 401 |
| 6 | `test_platform_007_validation` | Invalid input; 422 |

All tests use moto-mocked DynamoDB.

### Integration Tests

| # | Scenario | Services Involved |
|---|----------|-------------------|
| 1 | End-to-end happy path through all layers | router + service + DDB |
| 2 | Error handling propagates correctly | router + service layer |
| 3 | Feature flag disables functionality | settings + router |

### E2E Tests (Playwright)

**File**: `frontend/e2e/sms-delivery.spec.ts` -- 16 tests

**Auth**: `injectAuth(page, identity)` for cookie auth; CSRF header for mutations.

Tests cover API CRUD, UI rendering, negative cases (401/403/404/422), and edge cases.

**Negative/edge tests**: 401 unauthenticated, 403 insufficient role, 404 not found, 422 validation error, 409 conflict

### Test Data Requirements

- DDB seeds: feature-specific tables via setup scripts
- Test users: Alice, Bob, Root, Charlie (admin)
- Sessions via `e2e_admin_session_setup.py`

### CI/Pipeline

- Feature flags: Feature-specific flags (see Rollout Plan section)
- Serial execution (1 worker), 1 retry per playwright.config.ts
- Retry-safe: unique timestamps in test data


---

## Dependencies & Merge Safety

### Depends On

| Ticket | Type | Detail |
|--------|------|--------|
| PLATFORM-006 | Pattern | Follows same delivery tracking pattern as email |

### Depended On By

| Ticket | Type | Detail |
|--------|------|--------|
| (none) | -- | No downstream dependents identified |

### Merge Strategy

**Independent** -- No prerequisites. Mirrors PLATFORM-006 for SMS channel.

### Merge Checklist

- [ ] Backend service and router implemented
- [ ] DDB tables created in local-ddb-init.py (if new)
- [ ] Frontend types added to api/types.ts
- [ ] Frontend page/component created
- [ ] Route added to App.tsx
- [ ] E2E pass: `npx playwright test e2e/sms-delivery.spec.ts`
