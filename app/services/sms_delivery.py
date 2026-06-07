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

# DynamoDB partition key for the platform-wide daily segment counter
# (SEC-014 / GAP-0326). Lives in the same `sms_delivery` table as the
# per-number DAILY#{phone} counters; SK = DAY#{day_key}.
_GLOBAL_DAILY_PK = "DAILY#GLOBAL"

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

    # Increment the platform-wide daily segment counter (SEC-014 / GAP-0326).
    _increment_global_daily_segments(_estimate_segments(body), ts)


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


def record_sms_dev_logged(phone: str, body: str) -> None:
    """Record a dev-mode SMS log entry."""
    ts = now_ts()
    try:
        T.sms_delivery.put_item(Item={
            "pk": f"SMS#{phone}",
            "sk": f"SENT#{ts}#dev-{ts}",
            "message_id": f"dev-{ts}",
            "phone": phone,
            "body_preview": body[:100],
            "segments": _estimate_segments(body),
            "status": "dev_logged",
            "created_at": ts,
            "ttl_epoch": ts + 90 * 86400,
        })
    except Exception:
        logger.exception("Failed to record dev SMS for %s", phone)

    # Increment the platform-wide daily segment counter (SEC-014 / GAP-0326) so
    # dev mode faithfully exercises the global cost-cap logic.
    _increment_global_daily_segments(_estimate_segments(body), ts)


def _increment_global_daily_segments(segments: int, ts: int) -> None:
    """Atomically add ``segments`` to today's platform-wide segment counter."""
    if segments <= 0:
        return
    day_key = ts // 86400
    try:
        T.sms_delivery.update_item(
            Key={"pk": _GLOBAL_DAILY_PK, "sk": f"DAY#{day_key}"},
            UpdateExpression="SET #c = if_not_exists(#c, :z) + :segs, #ts = :ts, ttl_epoch = :ttl",
            ExpressionAttributeNames={"#c": "count", "#ts": "updated_at"},
            ExpressionAttributeValues={
                ":segs": segments,
                ":z": 0,
                ":ts": ts,
                ":ttl": ts + 7 * 86400,  # Counter expires after 7 days
            },
        )
    except Exception:
        logger.exception("Failed to increment global SMS segment counter")


def _estimate_segments(body: str) -> int:
    """Estimate number of SMS segments for a message.

    GSM-7 encoding: 160 chars/segment (or 153 for multi-segment)
    UCS-2 encoding: 70 chars/segment (or 67 for multi-segment)
    """
    length = len(body)
    if length == 0:
        return 0
    # Simple heuristic: if all ASCII printable, assume GSM-7
    try:
        body.encode("ascii")
        is_gsm7 = True
    except UnicodeEncodeError:
        is_gsm7 = False

    if is_gsm7:
        if length <= 160:
            return 1
        return (length + 152) // 153
    else:
        if length <= 70:
            return 1
        return (length + 66) // 67


# ──────────────────────────────────────────────────────────────────────
# Production send path (PLATFORM-007)
# ──────────────────────────────────────────────────────────────────────


def _build_sms_attributes() -> Dict[str, Any]:
    """Build SNS SMS MessageAttributes for delivery optimization.

    Controls SMSType (Transactional vs Promotional), optional alphanumeric
    SenderID, and optional dedicated OriginationNumber (10DLC / toll-free /
    short code). Driven by the PLATFORM-007 settings.
    """
    attrs: Dict[str, Any] = {
        "AWS.SNS.SMS.SMSType": {
            "DataType": "String",
            "StringValue": S.sms_message_type or "Transactional",
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


def send_sms(phone: str, body: str, *, check_suppression: bool = True,
             enforce_daily_limit: bool = True) -> Dict[str, Any]:
    """Production single-number SMS sender.

    This is the consolidated production pipeline used by the alert fanout and
    the admin send-test endpoint. Behaviour:

    - In dev mode (``S.dev_mode``): never touches real AWS — writes to the dev
      SMS log and records a ``dev_logged`` delivery row. Fully deterministic
      for E2E.
    - In production (``not S.dev_mode``): gated on ``S.alerts_sms_enabled``;
      honours the suppression list and the per-number daily limit; sends via
      SNS with proper ``MessageAttributes``; records a ``sent`` / ``failed``
      delivery row either way.

    Returns a result dict ``{number, message_id, status}`` where status is one
    of: ``dev_logged``, ``disabled``, ``suppressed``, ``rate_limited``,
    ``sent``, ``failed``.
    """
    from app.metrics import SMS_FAILED, SMS_RATE_LIMITED, SMS_SENT, SMS_SUPPRESSED

    if not phone:
        return {"number": phone, "message_id": None, "status": "failed"}

    # Suppression check (hot path) — applies in dev and prod so opt-out is
    # always honoured and deterministically testable.
    if check_suppression and S.sms_suppression_enabled:
        try:
            if is_sms_suppressed(phone):
                SMS_SUPPRESSED.labels(reason="opt_out").inc()
                return {"number": phone, "message_id": None, "status": "suppressed"}
        except Exception:
            logger.exception("Suppression check failed for %s", phone)

    # Per-number daily rate limit (applies in dev and prod).
    if enforce_daily_limit:
        try:
            if sms_daily_limit_exceeded(phone):
                SMS_RATE_LIMITED.inc()
                logger.info("SMS rate limited for %s (daily limit exceeded)", phone)
                return {"number": phone, "message_id": None, "status": "rate_limited"}
        except Exception:
            logger.exception("Daily-limit check failed for %s", phone)

    # Global platform-wide daily cost cap (SEC-014 / GAP-0326). Disabled by
    # default (cap=0). Runs in dev and prod for parity; uses the same DDB
    # counter path. Checked before the dev-mode short-circuit AND the real send
    # so it halts all outbound SMS once the estimated daily spend hits the cap.
    if S.sms_daily_cost_cap_usd and S.sms_daily_cost_cap_usd > 0:
        try:
            if sms_global_cost_cap_exceeded(_estimate_segments(body)):
                SMS_RATE_LIMITED.inc()
                logger.warning(
                    "SMS blocked: global daily cost cap exceeded (cap=%.4f USD)",
                    S.sms_daily_cost_cap_usd,
                )
                return {"number": phone, "message_id": None, "status": "rate_limited"}
        except Exception:
            logger.exception("Global cost cap check failed; proceeding")

    # Dev mode: log + record, never hit AWS.
    if S.dev_mode:
        try:
            from datetime import datetime, timezone

            from app.services.alerts import _write_dev_log

            ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            _write_dev_log(S.dev_sms_log, f"[{ts}] ALERT_SMS TO={phone}\n  Body: {body}\n\n")
        except Exception:
            pass
        record_sms_dev_logged(phone, body)
        SMS_SENT.inc()
        return {"number": phone, "message_id": f"dev-{now_ts()}", "status": "dev_logged"}

    # Production gate: SMS disabled → no-op.
    if not S.alerts_sms_enabled:
        return {"number": phone, "message_id": None, "status": "disabled"}

    # Real SNS send.
    try:
        from app.core.aws import sns_client

        sns = sns_client()
        response = sns.publish(
            PhoneNumber=phone,
            Message=(body or "")[:1400],
            MessageAttributes=_build_sms_attributes(),
        )
        message_id = response.get("MessageId", "")
        record_sms_sent(phone, body, message_id)
        SMS_SENT.inc()
        logger.info("SMS sent: message_id=%s, to=%s", message_id, phone)
        return {"number": phone, "message_id": message_id, "status": "sent"}
    except Exception as exc:
        record_sms_failure(phone, body, str(exc))
        SMS_FAILED.inc()
        logger.exception("SMS send failed: to=%s, error=%s", phone, str(exc)[:200])
        return {"number": phone, "message_id": None, "status": "failed"}


def send_sms_bulk(numbers: List[str], body: str, *, limit: int = 5) -> List[Dict[str, Any]]:
    """Send to up to ``limit`` numbers via :func:`send_sms`. Returns result dicts."""
    return [send_sms(n, body) for n in (numbers or [])[:limit]]


# ──────────────────────────────────────────────────────────────────────
# Suppression / Opt-out
# ──────────────────────────────────────────────────────────────────────


def suppress_sms(phone: str, reason: str) -> None:
    """Add phone number to SMS suppression list (opt-out)."""
    ts = now_ts()
    try:
        T.sms_delivery.put_item(Item={
            "pk": f"SMS_SUPPRESS#{phone}",
            "sk": "STATUS",
            "phone": phone,
            "reason": reason,
            "suppressed_at": ts,
            "status": "suppressed",
            "created_at": ts,
        })
        logger.warning("Suppressed SMS for %s (reason=%s)", phone, reason)
    except Exception:
        logger.exception("Failed to suppress SMS for %s", phone)


def is_sms_suppressed(phone: str) -> bool:
    """Check if phone number is on suppression list."""
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
    """Check if phone has exceeded daily SMS limit."""
    return sms_daily_count(phone) >= S.sms_daily_limit_per_number


def _global_daily_segments() -> int:
    """Return today's total platform-wide SMS segment count (SEC-014 / GAP-0326)."""
    day_key = now_ts() // 86400
    try:
        resp = T.sms_delivery.get_item(
            Key={"pk": _GLOBAL_DAILY_PK, "sk": f"DAY#{day_key}"},
            ProjectionExpression="#c",
            ExpressionAttributeNames={"#c": "count"},
        )
        item = resp.get("Item")
        return int(item.get("count", 0)) if item else 0
    except Exception:
        # Fail open: don't block sends on a counter read failure.
        return 0


def sms_global_cost_cap_exceeded(extra_segments: int = 0) -> bool:
    """Return True if the platform-wide daily SMS cost estimate has hit the cap.

    SEC-014 / GAP-0326. A cap of ``0`` (the default) means disabled. The
    estimate includes ``extra_segments`` (this message's segments) so the cap
    is enforced inclusively before the message is published.
    """
    cap = S.sms_daily_cost_cap_usd
    if not cap or cap <= 0:
        return False
    segments = _global_daily_segments() + max(extra_segments, 0)
    estimated = segments * S.sms_cost_per_segment_usd
    return estimated >= cap


def check_sms_rate_limit(user_id: str) -> bool:
    """Check if user is under the SMS rate limit. Returns True if under limit."""
    from app.services.rate_limit import can_send_alert_channel
    return can_send_alert_channel(user_id, "sms")


# ──────────────────────────────────────────────────────────────────────
# Admin query functions
# ──────────────────────────────────────────────────────────────────────


def get_sms_delivery_stats(days: int = 7) -> Dict[str, Any]:
    """Get aggregate SMS delivery stats for the last N days."""
    cutoff = now_ts() - days * 86400
    sent_count = 0
    failed_count = 0
    total_segments = 0

    for status in ("sent", "failed", "dev_logged"):
        try:
            resp = T.sms_delivery.query(
                IndexName="ByStatus",
                KeyConditionExpression=(
                    Key("status").eq(status) & Key("created_at").gte(cutoff)
                ),
                Select="ALL_ATTRIBUTES",
                Limit=2000,
            )
            items = resp.get("Items", [])
            if status in ("sent", "dev_logged"):
                sent_count += len(items)
                total_segments += sum(int(it.get("segments", 1)) for it in items)
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
                failed_count = len(items)
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
    estimated_cost_usd = round(total_segments * S.sms_cost_per_segment_usd, 2)

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


def list_sms_deliveries(
    limit: int = 50, cursor: Optional[str] = None, status_filter: Optional[str] = None
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """List recent SMS deliveries, newest first."""
    filter_status = status_filter or "sent"
    kwargs: Dict[str, Any] = {
        "IndexName": "ByStatus",
        "KeyConditionExpression": Key("status").eq(filter_status),
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


def list_sms_failures(
    limit: int = 50, cursor: Optional[str] = None
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """List recent SMS failures, newest first."""
    return list_sms_deliveries(limit=limit, cursor=cursor, status_filter="failed")


def get_suppression_list(limit: int = 50) -> Dict[str, Any]:
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


def get_sms_delivery_timeseries(days: int = 7) -> List[Dict[str, Any]]:
    """Daily counts of sent/failed plus segments for the last N days (oldest first)."""
    import datetime as _dt

    cutoff = now_ts() - days * 86400
    buckets: Dict[str, Dict[str, int]] = {}

    def _bucket(day_ts: int) -> Dict[str, int]:
        key = _dt.datetime.utcfromtimestamp(day_ts).strftime("%Y-%m-%d")
        return buckets.setdefault(
            key,
            {"sent": 0, "delivered": 0, "bounced": 0, "complained": 0, "failed": 0, "segments": 0},
        )

    for status in ("sent", "dev_logged", "failed"):
        field_name = "failed" if status == "failed" else "sent"
        try:
            kwargs: Dict[str, Any] = {
                "IndexName": "ByStatus",
                "KeyConditionExpression": (
                    Key("status").eq(status) & Key("created_at").gte(cutoff)
                ),
                "Select": "ALL_ATTRIBUTES",
                "Limit": 2000,
            }
            resp = T.sms_delivery.query(**kwargs)
            while True:
                for it in resp.get("Items", []):
                    created = int(it.get("created_at", 0))
                    b = _bucket(created)
                    b[field_name] += 1
                    if field_name == "sent":
                        b["delivered"] += 1
                        b["segments"] += int(it.get("segments", 1) or 1)
                if not resp.get("LastEvaluatedKey"):
                    break
                kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
                resp = T.sms_delivery.query(**kwargs)
        except Exception:
            logger.exception("Failed SMS timeseries query for status=%s", status)

    points: List[Dict[str, Any]] = []
    today = now_ts()
    for offset in range(days - 1, -1, -1):
        day_ts = today - offset * 86400
        key = _dt.datetime.utcfromtimestamp(day_ts).strftime("%Y-%m-%d")
        c = buckets.get(
            key,
            {"sent": 0, "delivered": 0, "bounced": 0, "complained": 0, "failed": 0, "segments": 0},
        )
        points.append({
            "date": key,
            "sent": c["sent"],
            "delivered": c["delivered"],
            "bounced": 0,
            "complained": 0,
            "failed": c["failed"],
            "segments": c["segments"],
        })
    return points


def get_sms_failure_breakdown(days: int = 7, limit: int = 10) -> List[Dict[str, Any]]:
    """Top SMS failure error types for the last N days."""
    cutoff = now_ts() - days * 86400
    error_counts: Dict[str, int] = {}
    try:
        kwargs: Dict[str, Any] = {
            "IndexName": "ByStatus",
            "KeyConditionExpression": (
                Key("status").eq("failed") & Key("created_at").gte(cutoff)
            ),
            "Select": "ALL_ATTRIBUTES",
            "Limit": 2000,
        }
        resp = T.sms_delivery.query(**kwargs)
        while True:
            for it in resp.get("Items", []):
                err = str(it.get("error", "") or "unknown")
                # Use first 60 chars as a coarse error-type label
                label = err[:60] if err else "unknown"
                error_counts[label] = error_counts.get(label, 0) + 1
            if not resp.get("LastEvaluatedKey"):
                break
            kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
            resp = T.sms_delivery.query(**kwargs)
    except Exception:
        logger.exception("Failed SMS failure breakdown query")

    ranked = sorted(error_counts.items(), key=lambda kv: kv[1], reverse=True)[:limit]
    return [
        {"key": label, "label": label, "count": count}
        for label, count in ranked
    ]


def get_dev_sms_log() -> List[Dict[str, str]]:
    """Read dev SMS log file and return parsed entries."""
    import os
    log_path = S.dev_sms_log
    entries: List[Dict[str, str]] = []
    if not os.path.exists(log_path):
        return entries
    try:
        with open(log_path, "r") as f:
            content = f.read()
        # Parse entries: [timestamp] ALERT_SMS TO=number\n  Body: text\n\n
        blocks = content.strip().split("\n\n")
        for block in blocks:
            if not block.strip():
                continue
            lines = block.strip().split("\n")
            if len(lines) >= 2:
                header = lines[0]
                body_line = lines[1] if len(lines) > 1 else ""
                # Parse: [2026-05-28T10:00:00Z] ALERT_SMS TO=+15551234567
                ts = ""
                phone = ""
                body = ""
                if header.startswith("[") and "]" in header:
                    ts = header[1:header.index("]")]
                    rest = header[header.index("]") + 1:].strip()
                    if "TO=" in rest:
                        phone = rest.split("TO=")[1].strip()
                if body_line.strip().startswith("Body:"):
                    body = body_line.strip()[5:].strip()
                entries.append({
                    "timestamp": ts,
                    "phone": phone,
                    "body": body,
                })
    except Exception:
        logger.exception("Failed to read dev SMS log")
    return entries
