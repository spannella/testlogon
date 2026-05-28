"""Email delivery status tracking -- DDB storage for sent, bounced, complained.

Table: email_delivery
  PK: EMAIL#{address} or SUPPRESS#{address}
  SK: SENT#{ts}#{msg_id} or BOUNCE#{ts}#{msg_id} or COMPLAINT#{ts}#{msg_id} or FAILED#{ts} or STATUS

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
    """Record a successful email send in DDB."""
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
                "ttl_epoch": ts + 90 * 86400,
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


def record_dev_email(
    to_emails: List[str], subject: str
) -> None:
    """Record a dev-logged email."""
    ts = now_ts()
    for addr in to_emails:
        try:
            T.email_delivery.put_item(Item={
                "pk": f"EMAIL#{addr}",
                "sk": f"SENT#{ts}#dev-{ts}",
                "message_id": f"dev-{ts}",
                "to_email": addr,
                "subject": subject[:120],
                "status": "dev_logged",
                "created_at": ts,
                "ttl_epoch": ts + 90 * 86400,
            })
        except Exception:
            logger.exception("Failed to record dev email for %s", addr)


def record_email_bounce(
    message_id: str,
    bounce_type: str,
    bounce_sub_type: str,
    bounced_recipients: List[str],
    raw: dict,
) -> None:
    """Record a bounce notification from SES SNS."""
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
                "ttl_epoch": ts + 365 * 86400,
            })
        except Exception:
            logger.exception("Failed to record bounce for %s", addr)

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
    """Record a complaint notification from SES SNS."""
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
    """Add email to suppression list."""
    try:
        ts = now_ts()
        T.email_delivery.put_item(Item={
            "pk": f"SUPPRESS#{email}",
            "sk": "STATUS",
            "email": email,
            "reason": reason,
            "suppressed_at": ts,
            "status": "suppressed",
            "created_at": ts,
        })
        logger.warning("Suppressed email: %s (reason=%s)", email, reason)
    except Exception:
        logger.exception("Failed to suppress email %s", email)


def is_suppressed(email: str) -> bool:
    """Check if email is on suppression list."""
    try:
        resp = T.email_delivery.get_item(
            Key={"pk": f"SUPPRESS#{email}", "sk": "STATUS"},
            ProjectionExpression="pk",
        )
        return "Item" in resp
    except Exception:
        return False


def remove_suppression(email: str) -> None:
    """Remove email from suppression list (admin action)."""
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
    """Get aggregate delivery stats for the last N days."""
    cutoff = now_ts() - days * 86400
    counts: Dict[str, int] = {}

    for status in ("sent", "dev_logged", "bounced", "complained", "failed"):
        try:
            resp = T.email_delivery.query(
                IndexName="ByStatus",
                KeyConditionExpression=(
                    Key("status").eq(status) & Key("created_at").gte(cutoff)
                ),
                Select="COUNT",
            )
            count = resp.get("Count", 0)
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
            counts[status] = -1

    sent = counts.get("sent", 0)
    dev_logged = counts.get("dev_logged", 0)
    bounced = counts.get("bounced", 0)
    complained = counts.get("complained", 0)
    failed = counts.get("failed", 0)
    total = sent + dev_logged + bounced + complained + failed

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
        "dev_logged": dev_logged,
        "bounced": bounced,
        "complained": complained,
        "failed": failed,
        "suppressed": suppressed_count,
        "total": total,
        "bounce_rate": round(bounced / max(sent + dev_logged, 1) * 100, 2),
        "complaint_rate": round(complained / max(sent + dev_logged, 1) * 100, 3),
        "success_rate": round((sent + dev_logged) / max(total, 1) * 100, 1),
    }


def list_deliveries(
    limit: int = 50, cursor: Optional[str] = None, status_filter: Optional[str] = None
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """List recent deliveries, newest first."""
    if status_filter:
        kwargs: Dict[str, Any] = {
            "IndexName": "ByStatus",
            "KeyConditionExpression": Key("status").eq(status_filter),
            "ScanIndexForward": False,
            "Limit": limit,
        }
        if cursor:
            kwargs["ExclusiveStartKey"] = decode_cursor(cursor)
        resp = T.email_delivery.query(**kwargs)
    else:
        kwargs = {
            "IndexName": "ByStatus",
            "KeyConditionExpression": Key("status").eq("sent"),
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


def list_bounces(
    limit: int = 50, cursor: Optional[str] = None
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """List recent bounces, newest first."""
    kwargs: Dict[str, Any] = {
        "IndexName": "ByStatus",
        "KeyConditionExpression": Key("status").eq("bounced"),
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
    """List suppressed email addresses."""
    try:
        resp = T.email_delivery.scan(
            FilterExpression=Attr("pk").begins_with("SUPPRESS#"),
            Limit=limit,
        )
        items = resp.get("Items", [])
        return {"items": items, "count": len(items)}
    except Exception:
        return {"items": [], "count": 0}


def read_dev_email_log(max_entries: int = 100) -> List[Dict[str, str]]:
    """Read the dev email log file and return parsed entries."""
    import os
    import re

    path = S.dev_email_log
    if not path or not os.path.exists(path):
        return []

    entries: List[Dict[str, str]] = []
    try:
        with open(path, "r") as f:
            content = f.read()

        # Parse log entries: [timestamp] ALERT_EMAIL TO=addr\n  Subject: ...\n  Body: ...\n
        pattern = re.compile(
            r"\[([^\]]+)\]\s+ALERT_EMAIL\s+TO=(\S+)\s*\n\s*Subject:\s*(.*?)\n\s*Body:\s*(.*?)(?=\n\n|\Z)",
            re.DOTALL,
        )
        for match in pattern.finditer(content):
            entries.append({
                "timestamp": match.group(1).strip(),
                "to": match.group(2).strip(),
                "subject": match.group(3).strip(),
                "body": match.group(4).strip(),
            })

        # Return newest first, limited
        entries.reverse()
        return entries[:max_entries]
    except Exception:
        logger.exception("Failed to read dev email log at %s", path)
        return []
