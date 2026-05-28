"""Broadcast reminder system -- subscriber management and reminder dispatch."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Set

from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# Allowed reminder intervals (seconds before scheduled_at)
ALLOWED_INTERVALS: Set[int] = {900, 3600, 86400}  # 15min, 1hr, 24hr

_INTERVAL_LABELS: Dict[int, str] = {
    900: "15 minutes",
    3600: "1 hour",
    86400: "24 hours",
}


def register_reminder(
    *,
    session_id: str,
    user_id: str,
    remind_at_ts: int,
    session_name: str = "Broadcast",
    interval: int = 1800,
) -> Dict[str, Any]:
    """Write a single reminder item for the given user.

    PK: SESSION#{session_id}   SK: USER#{user_id}
    GSI ByRemindAt: remind_status=pending, remind_at=remind_at_ts
    """
    ts = now_ts()
    item: Dict[str, Any] = {
        "pk": f"SESSION#{session_id}",
        "sk": f"USER#{user_id}",
        "user_id": user_id,
        "session_id": session_id,
        "interval": interval,
        "remind_at": remind_at_ts,
        "session_name": session_name,
        "remind_status": "pending",
        "sent": False,
        "created_at": ts,
    }
    T.broadcast_reminders.put_item(Item=item)
    return {"ok": True, "remind_at": remind_at_ts}


def cancel_reminder(session_id: str, user_id: str) -> Dict[str, Any]:
    """Delete the reminder for a specific user on a session."""
    T.broadcast_reminders.delete_item(
        Key={"pk": f"SESSION#{session_id}", "sk": f"USER#{user_id}"},
    )
    return {"ok": True}


def cancel_reminders_for_session(session_id: str) -> int:
    """Delete all reminder items for a cancelled/rescheduled session."""
    deleted = 0
    last_key: Optional[Dict[str, Any]] = None
    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("pk").eq(f"SESSION#{session_id}"),
            "Limit": 500,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.broadcast_reminders.query(**kwargs)
        items = resp.get("Items", [])
        if items:
            with T.broadcast_reminders.batch_writer() as bw:
                for item in items:
                    bw.delete_item(Key={"pk": item["pk"], "sk": item["sk"]})
                    deleted += 1
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    return deleted


def dispatch_due_reminders(*, now: int, limit: int = 50) -> int:
    """Find and send all due reminders.

    Queries ByRemindAt GSI: remind_status="pending", remind_at <= now.
    For each due reminder, creates an in-app alert and marks it as sent.
    """
    resp = T.broadcast_reminders.query(
        IndexName="ByRemindAt",
        KeyConditionExpression=(
            Key("remind_status").eq("pending") & Key("remind_at").lte(now)
        ),
        Limit=limit,
    )
    items = resp.get("Items", [])
    dispatched = 0

    for item in items:
        if item.get("sent"):
            continue
        try:
            interval = int(item.get("interval", 1800))
            label = _INTERVAL_LABELS.get(interval, f"{interval // 60} minutes")
            session_name = item.get("session_name", "Broadcast")

            from app.services.alerts import write_alert
            write_alert(
                item["user_id"],
                event="broadcast_reminder",
                outcome="pending",
                title=f"Broadcast starting in {label}",
                details={
                    "body": f'"{session_name}" is starting in {label}. Don\'t miss it!',
                    "session_id": item["session_id"],
                    "remind_at": int(item.get("remind_at", 0)),
                    "interval": interval,
                },
            )

            # Mark as sent -- remove from GSI
            T.broadcast_reminders.update_item(
                Key={"pk": item["pk"], "sk": item["sk"]},
                UpdateExpression="SET sent = :t, remind_status = :done",
                ExpressionAttributeValues={":t": True, ":done": "sent"},
            )
            dispatched += 1
        except Exception:
            logger.exception("Failed to dispatch reminder pk=%s sk=%s", item["pk"], item["sk"])

    return dispatched


def list_reminders_for_session(session_id: str) -> List[Dict[str, Any]]:
    """List all reminder subscriptions for a session."""
    items: List[Dict[str, Any]] = []
    last_key: Optional[Dict[str, Any]] = None
    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("pk").eq(f"SESSION#{session_id}"),
            "Limit": 500,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.broadcast_reminders.query(**kwargs)
        items.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    return items


def generate_ical(
    *,
    session_id: str,
    name: str,
    description: str,
    scheduled_at: int,
    frontend_base_url: str,
) -> str:
    """Generate RFC 5545 iCalendar content for a scheduled broadcast."""
    from datetime import datetime, timezone

    dt = datetime.fromtimestamp(scheduled_at, tz=timezone.utc)
    dtstart = dt.strftime("%Y%m%dT%H%M%SZ")
    end_dt = datetime.fromtimestamp(scheduled_at + 3600, tz=timezone.utc)
    dtend = end_dt.strftime("%Y%m%dT%H%M%SZ")
    dtstamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    url = f"{frontend_base_url}/broadcast/{session_id}"

    name_escaped = name.replace("\\", "\\\\").replace(",", "\\,").replace(";", "\\;").replace("\n", "\\n")
    desc_escaped = description.replace("\\", "\\\\").replace(",", "\\,").replace(";", "\\;").replace("\n", "\\n")

    return (
        "BEGIN:VCALENDAR\r\n"
        "VERSION:2.0\r\n"
        "PRODID:-//Platform//Broadcast//EN\r\n"
        "BEGIN:VEVENT\r\n"
        f"UID:broadcast-{session_id}@platform\r\n"
        f"DTSTAMP:{dtstamp}\r\n"
        f"DTSTART:{dtstart}\r\n"
        f"DTEND:{dtend}\r\n"
        f"SUMMARY:{name_escaped}\r\n"
        f"DESCRIPTION:{desc_escaped}\r\n"
        f"URL:{url}\r\n"
        "BEGIN:VALARM\r\n"
        "TRIGGER:-PT15M\r\n"
        "ACTION:DISPLAY\r\n"
        "DESCRIPTION:Broadcast starting in 15 minutes\r\n"
        "END:VALARM\r\n"
        "END:VEVENT\r\n"
        "END:VCALENDAR\r\n"
    )
