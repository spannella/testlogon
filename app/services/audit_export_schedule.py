"""Scheduled (recurring) audit export reports (FIN-016 / GAP-0210).

The on-demand audit export pipeline (``audit_export_pipeline``) only supports
manually triggered, one-off exports. FIN-016 requires recurring daily / weekly /
monthly exports that are auto-generated and dispatched to compliance recipients.

This module adds the missing capability:

* Schedule records are stored in the existing ``audit_exports`` DynamoDB table
  (single-table design) using ``pk = SCHEDULE#{schedule_id}`` / ``sk = META``.
  Active schedules carry ``GSI1PK = "SCHEDULES#ACTIVE"`` and ``GSI1SK =
  next_run_at`` (numeric) so the runner can query due schedules time-ordered via
  the ``schedules-due-index`` GSI.
* ``run_due_schedules`` is invoked by a background loop (see
  ``start_audit_export_scheduler_task``). For each due, enabled schedule it
  spawns a one-off export job (reusing ``create_export_job``), advances
  ``next_run_at`` by one cadence, and notifies recipients.
* Notification reuses ``alerts.send_alert_email`` — dev logs, prod sends via SES
  (SECOPS-007 dev/prod parity, no in-line ``if dev_mode`` branch in business
  logic).
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

SCHEDULE_INDEX_NAME = "schedules-due-index"
SCHEDULES_ACTIVE_PK = "SCHEDULES#ACTIVE"

CADENCE_OFFSETS = {
    "daily": 86400,
    "weekly": 7 * 86400,
    "monthly": 30 * 86400,
}

VALID_FORMATS = ("csv", "ndjson", "pdf")


def _schedule_pk(schedule_id: str) -> str:
    return f"SCHEDULE#{schedule_id}"


def create_schedule(
    *,
    created_by: str,
    categories: List[str],
    format: str,
    cadence: str,
    recipients: Optional[List[str]] = None,
    lookback_seconds: Optional[int] = None,
) -> Dict[str, Any]:
    """Create a recurring audit export schedule record.

    The first run is set one cadence interval from now (``next_run_at``).
    """
    if cadence not in CADENCE_OFFSETS:
        raise ValueError(f"Invalid cadence: {cadence}")
    if format not in VALID_FORMATS:
        raise ValueError(f"Invalid format: {format}")
    schedule_id = f"sched_{uuid.uuid4().hex[:12]}"
    now = now_ts()
    offset = CADENCE_OFFSETS[cadence]
    lookback = int(lookback_seconds) if lookback_seconds else offset
    item: Dict[str, Any] = {
        "export_id": _schedule_pk(schedule_id),
        "sk": "META",
        "GSI1PK": SCHEDULES_ACTIVE_PK,
        "GSI1SK": now + offset,  # first run = now + one cadence
        "schedule_id": schedule_id,
        "created_by": created_by,
        "categories": list(categories),
        "format": format,
        "cadence": cadence,
        "lookback_seconds": lookback,
        "recipients": list(recipients or []),
        "enabled": True,
        "created_at": now,
        "next_run_at": now + offset,
        "last_run_at": None,
        "last_export_id": None,
    }
    T.audit_exports.put_item(Item=item)
    return item


def get_schedule(schedule_id: str) -> Optional[Dict[str, Any]]:
    resp = T.audit_exports.get_item(Key={"export_id": _schedule_pk(schedule_id), "sk": "META"})
    return resp.get("Item")


def list_schedules(created_by: Optional[str] = None) -> List[Dict[str, Any]]:
    """List active schedules, optionally filtered to a single owner."""
    kwargs: Dict[str, Any] = {
        "IndexName": SCHEDULE_INDEX_NAME,
        "KeyConditionExpression": Key("GSI1PK").eq(SCHEDULES_ACTIVE_PK),
        "ScanIndexForward": True,
    }
    if created_by:
        kwargs["FilterExpression"] = Key("created_by").eq(created_by)
    resp = T.audit_exports.query(**kwargs)
    return resp.get("Items", [])


def update_schedule(
    schedule_id: str,
    *,
    cadence: Optional[str] = None,
    recipients: Optional[List[str]] = None,
    categories: Optional[List[str]] = None,
    format: Optional[str] = None,
    enabled: Optional[bool] = None,
    lookback_seconds: Optional[int] = None,
) -> Dict[str, Any]:
    """Patch a schedule. Changing cadence recomputes next_run_at and lookback."""
    existing = get_schedule(schedule_id)
    if not existing:
        raise KeyError(schedule_id)

    set_parts: List[str] = []
    names: Dict[str, str] = {}
    values: Dict[str, Any] = {}

    if cadence is not None:
        if cadence not in CADENCE_OFFSETS:
            raise ValueError(f"Invalid cadence: {cadence}")
        offset = CADENCE_OFFSETS[cadence]
        now = now_ts()
        set_parts += ["cadence = :cad", "GSI1SK = :nra", "next_run_at = :nra"]
        values[":cad"] = cadence
        values[":nra"] = now + offset
        # If the caller did not also override lookback, keep it in sync with the
        # new cadence so a daily->weekly change covers a week.
        if lookback_seconds is None and not int(existing.get("lookback_seconds", 0)) == offset:
            set_parts.append("lookback_seconds = :lbc")
            values[":lbc"] = offset
    if lookback_seconds is not None:
        set_parts.append("lookback_seconds = :lb")
        values[":lb"] = int(lookback_seconds)
    if recipients is not None:
        set_parts.append("recipients = :rcp")
        values[":rcp"] = list(recipients)
    if categories is not None:
        set_parts.append("categories = :cats")
        values[":cats"] = list(categories)
    if format is not None:
        if format not in VALID_FORMATS:
            raise ValueError(f"Invalid format: {format}")
        set_parts.append("#fmt = :fmt")
        names["#fmt"] = "format"
        values[":fmt"] = format
    if enabled is not None:
        set_parts.append("enabled = :en")
        values[":en"] = bool(enabled)
        # Disabled schedules are removed from the active index so the runner
        # never selects them; re-enabling restores it.
        if enabled:
            set_parts.append("GSI1PK = :gpk")
            values[":gpk"] = SCHEDULES_ACTIVE_PK
        else:
            set_parts.append("GSI1PK = :gpk")
            values[":gpk"] = "SCHEDULES#DISABLED"

    if not set_parts:
        return existing

    kwargs: Dict[str, Any] = {
        "Key": {"export_id": _schedule_pk(schedule_id), "sk": "META"},
        "UpdateExpression": "SET " + ", ".join(set_parts),
        "ExpressionAttributeValues": values,
        "ReturnValues": "ALL_NEW",
    }
    if names:
        kwargs["ExpressionAttributeNames"] = names
    resp = T.audit_exports.update_item(**kwargs)
    return resp.get("Attributes", existing)


def delete_schedule(schedule_id: str) -> None:
    T.audit_exports.delete_item(Key={"export_id": _schedule_pk(schedule_id), "sk": "META"})


def get_due_schedules(now: Optional[int] = None) -> List[Dict[str, Any]]:
    """Return all active schedules whose next_run_at <= now."""
    ts = now if now is not None else now_ts()
    resp = T.audit_exports.query(
        IndexName=SCHEDULE_INDEX_NAME,
        KeyConditionExpression=(
            Key("GSI1PK").eq(SCHEDULES_ACTIVE_PK) & Key("GSI1SK").lte(ts)
        ),
        ScanIndexForward=True,
    )
    return resp.get("Items", [])


def _advance_schedule(schedule_id: str, cadence: str, export_id: str) -> None:
    offset = CADENCE_OFFSETS.get(cadence, 86400)
    now = now_ts()
    T.audit_exports.update_item(
        Key={"export_id": _schedule_pk(schedule_id), "sk": "META"},
        UpdateExpression=(
            "SET GSI1SK = :next, next_run_at = :next, "
            "last_run_at = :now, last_export_id = :eid"
        ),
        ExpressionAttributeValues={
            ":next": now + offset,
            ":now": now,
            ":eid": export_id,
        },
    )


def _notify_recipients(sched: Dict[str, Any], job: Dict[str, Any]) -> None:
    """Notify recipients of a completed scheduled export.

    Reuses ``alerts.send_alert_email`` so the dev/prod backends match the rest of
    the platform: dev writes to the dev email log, prod dispatches via SES
    (SECOPS-007 parity). Best-effort — failures are logged, never raised.
    """
    recipients = [r for r in sched.get("recipients", []) if r]
    export_id = job.get("export_id", "")
    schedule_id = sched.get("schedule_id", "")
    logger.info(
        "scheduled_export_dispatched schedule_id=%s export_id=%s recipients=%s",
        schedule_id, export_id, recipients,
    )
    if not recipients:
        return
    try:
        from app.services.alerts import send_alert_email

        subject = f"Scheduled audit export {export_id}"
        body = (
            f"A scheduled audit export has been generated.\n\n"
            f"Schedule: {schedule_id}\n"
            f"Export ID: {export_id}\n"
            f"Cadence: {sched.get('cadence', '')}\n"
            f"Format: {sched.get('format', '')}\n"
            f"Categories: {', '.join(sched.get('categories', []))}\n"
            f"Status: {job.get('status', '')}\n"
        )
        send_alert_email(recipients, subject, body)
    except Exception:
        logger.exception("scheduled_export_notify_failed schedule_id=%s", schedule_id)


def run_due_schedules() -> int:
    """Process all due, enabled schedules. Returns the number of jobs spawned."""
    from app.services.audit_export_pipeline import create_export_job

    due = get_due_schedules()
    spawned = 0
    for sched in due:
        if not sched.get("enabled", True):
            continue
        schedule_id = sched.get("schedule_id")
        if not schedule_id:
            continue
        try:
            now = now_ts()
            lookback = int(sched.get("lookback_seconds", 86400))
            job = create_export_job(
                categories=list(sched.get("categories", [])),
                format=str(sched.get("format", "ndjson")),
                from_ts=now - lookback,
                to_ts=now,
                created_by=str(sched.get("created_by", "")),
                column_format=(sched.get("column_format") or None),
            )
            _advance_schedule(
                schedule_id=str(schedule_id),
                cadence=str(sched.get("cadence", "daily")),
                export_id=str(job.get("export_id", "")),
            )
            _notify_recipients(sched, job)
            spawned += 1
        except Exception:
            logger.exception(
                "scheduled_export_run_failed schedule_id=%s", schedule_id
            )
    if spawned:
        logger.info("scheduled_exports_ran count=%s", spawned)
    return spawned


async def run_audit_export_scheduler_loop() -> None:
    """Background loop: run due audit export schedules on a fixed interval."""
    poll_interval = S.audit_export_scheduler_poll_interval_seconds or 3600
    while True:
        try:
            run_due_schedules()
        except Exception:
            logger.exception("audit_export_scheduler_loop_error")
        await asyncio.sleep(poll_interval)


async def start_audit_export_scheduler_task() -> None:
    """Start the scheduled-export background loop if enabled (FastAPI startup)."""
    if S.audit_export_scheduler_enabled:
        asyncio.create_task(run_audit_export_scheduler_loop())
