"""
ACT-004 — CRM Event Reminder background poller service.

Polls the DueReminders GSI on crm_event_reminders and fires in-app or email
reminders.  A conditional update (fired=False → fired=True) prevents double-fire
even in multi-worker deployments.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from typing import List, Optional

from boto3.dynamodb.conditions import Attr, Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

_LOOKAHEAD = 0  # fire_at strictly <= now (no look-ahead; accurate)


def list_due_reminders(now: int, lookahead: int = 0) -> List[dict]:
    """Query DueReminders GSI for items with fire_at in [now-1, now+lookahead]."""
    items: List[dict] = []
    kw: dict = dict(
        IndexName="DueReminders",
        KeyConditionExpression=(
            Key("GSI1PK").eq("DUE") & Key("GSI1SK").between(0, now + lookahead)
        ),
        FilterExpression=Attr("fired").eq(False),
        ScanIndexForward=True,
        Limit=200,
    )
    safety = 0
    while safety < 5:
        resp = T.crm_event_reminders.query(**kw)
        items.extend(resp.get("Items", []))
        lek = resp.get("LastEvaluatedKey")
        if not lek or len(items) >= 200:
            break
        kw["ExclusiveStartKey"] = lek
        safety += 1
    return items


def mark_reminder_fired(reminder_key: str, reminder_id: str) -> None:
    """Atomic conditional update: fired=False → fired=True, remove from GSI."""
    try:
        from botocore.exceptions import ClientError
        T.crm_event_reminders.update_item(
            Key={"reminder_key": reminder_key, "reminder_id": reminder_id},
            UpdateExpression="SET fired = :t REMOVE GSI1PK, GSI1SK",
            ConditionExpression=Attr("fired").eq(False),
            ExpressionAttributeValues={":t": True},
        )
        try:
            from app.services.alerts import audit_event
            audit_event("crm_reminder_fired", "system", None, reminder_id=reminder_id)
        except Exception:
            pass
    except Exception as exc:
        # ConditionalCheckFailedException means already fired — idempotent
        if "ConditionalCheckFailedException" not in type(exc).__name__:
            logger.warning("mark_reminder_fired failed: %s", exc)


def _dispatch_reminder(item: dict) -> None:
    """Dispatch a single reminder via the appropriate channel."""
    user_sub = item.get("user_sub", "")
    event_name = item.get("event_name", "")
    event_start_utc = item.get("event_start_utc", "")
    minutes = int(item.get("minutes_before", 0))
    method = item.get("method", "in_app")
    title = f"Reminder: {event_name}"
    body = (
        f"Your event '{event_name}' starts in {minutes} minute(s)"
        + (f" at {event_start_utc} UTC" if event_start_utc else "")
        + "."
    )
    if method == "in_app":
        from app.services.alerts import write_alert
        write_alert(
            user_sub,
            event="calendar_event_reminder",
            outcome="reminder",
            title=title,
            details={
                "calendar_id": item.get("calendar_id", ""),
                "event_id": item.get("event_id", ""),
                "minutes_before": minutes,
            },
            action_url="/calendar",
            source_type="calendar_event",
            source_id=item.get("event_id"),
        )
    else:
        from app.services.alerts import send_alert_email
        from app.services.profile import get_profile_identity
        identity = get_profile_identity(user_sub)
        email_addr = identity.get("email")
        if email_addr:
            send_alert_email([email_addr], subject=title, body_text=body)


async def _fire_due_reminders() -> None:
    now = now_ts()
    due = list_due_reminders(now=now, lookahead=_LOOKAHEAD)
    for item in due:
        try:
            _dispatch_reminder(item)
            mark_reminder_fired(item["reminder_key"], item["reminder_id"])
        except Exception:
            logger.exception("Failed to dispatch reminder %s", item.get("reminder_id"))


async def run_event_reminder_loop() -> None:
    """Background loop; runs forever, polls every poll_interval seconds."""
    poll_interval = S.crm_event_reminders_poll_interval_seconds
    while True:
        try:
            await _fire_due_reminders()
        except Exception:
            logger.exception("crm_event_reminder loop error")
        await asyncio.sleep(poll_interval)


async def start_event_reminder_task() -> None:
    """Registered as a startup hook in app/main.py (ACT-004)."""
    if S.crm_activities_enabled and S.crm_event_reminders_enabled:
        asyncio.create_task(run_event_reminder_loop())
