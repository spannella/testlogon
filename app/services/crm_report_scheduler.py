"""RPT-004 — Scheduled report email delivery.

Schedule records live in the same ``crm_reports`` DynamoDB table as report
META and RUN rows (single-table design), with PK ``SCHEDULE#{schedule_id}``
/ SK ``META``.  Active schedules carry ``GSI2PK = "RPT_SCHEDULES#ACTIVE"``
and ``GSI2SK = next_run_at`` (numeric) on the ``rpt-schedules-due-index``
GSI (declared with ``attr_types={"GSI2SK": "N"}`` in RPT-001's TableDef).

Pattern is identical to ``app/services/audit_export_schedule.py``.
"""
from __future__ import annotations

import asyncio
import csv
import io
import json
import logging
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.core.cursor import encode_cursor, decode_cursor
from app.services.alerts import audit_event, send_alert_email

logger = logging.getLogger(__name__)

SCHEDULE_INDEX = "rpt-schedules-due-index"
SCHEDULES_ACTIVE = "RPT_SCHEDULES#ACTIVE"
SCHEDULES_DISABLED = "RPT_SCHEDULES#DISABLED"

CADENCE_OFFSETS: Dict[str, int] = {
    "daily": 86400,
    "weekly": 7 * 86400,
    "monthly": 30 * 86400,
}
VALID_FORMATS = ("csv", "json")
MAX_SCHEDULES_PER_REPORT = 10


def _schedule_pk(schedule_id: str) -> str:
    return f"SCHEDULE#{schedule_id}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _item_to_out(item: Dict[str, Any]) -> Dict[str, Any]:
    recipients_raw = item.get("recipients", "[]")
    if isinstance(recipients_raw, str):
        recipients = json.loads(recipients_raw)
    else:
        recipients = list(recipients_raw)
    return {
        "schedule_id": item["schedule_id"],
        "report_id": item["report_id"],
        "owner_sub": item["owner_sub"],
        "cadence": item["cadence"],
        "recipients": recipients,
        "format": item.get("format", "csv"),
        "enabled": bool(item.get("enabled", True)),
        "created_at": int(item["created_at"]),
        "next_run_at": int(item["next_run_at"]),
        "last_run_at": int(item["last_run_at"]) if item.get("last_run_at") else None,
        "last_run_id": item.get("last_run_id"),
    }


def _get_schedule_item(schedule_id: str) -> Optional[Dict[str, Any]]:
    resp = T.crm_reports.get_item(Key={"report_id": _schedule_pk(schedule_id), "sk": "META"})
    return resp.get("Item")


# ---------------------------------------------------------------------------
# Public CRUD
# ---------------------------------------------------------------------------

def create_report_schedule(
    *,
    owner_sub: str,
    report_id: str,
    cadence: str,
    recipients: List[str],
    fmt: str = "csv",
) -> Dict[str, Any]:
    from app.services import crm_reports

    if cadence not in CADENCE_OFFSETS:
        raise HTTPException(status_code=422, detail=f"Invalid cadence: {cadence}")
    if fmt not in VALID_FORMATS:
        raise HTTPException(status_code=422, detail=f"Invalid format: {fmt}")

    # Ownership check on the report
    crm_reports.get_report(report_id, owner_sub)

    # Check existing schedule count for this report
    existing_scheds = T.crm_reports.query(
        KeyConditionExpression=Key("report_id").eq(report_id) & Key("sk").begins_with("SCHEDULE#"),
    )
    if len(existing_scheds.get("Items", [])) >= MAX_SCHEDULES_PER_REPORT:
        raise HTTPException(status_code=422, detail="Maximum 10 schedules per report")

    schedule_id = f"rptsched_{uuid4().hex[:12]}"
    now = now_ts()
    next_run_at = now + CADENCE_OFFSETS[cadence]

    # Deduplicate recipients
    deduped = list(dict.fromkeys(recipients))

    item: Dict[str, Any] = {
        "report_id": _schedule_pk(schedule_id),
        "sk": "META",
        "GSI2PK": SCHEDULES_ACTIVE,
        "GSI2SK": next_run_at,
        "schedule_id": schedule_id,
        "linked_report_id": report_id,
        "owner_sub": owner_sub,
        "cadence": cadence,
        "recipients": json.dumps(deduped),
        "format": fmt,
        "enabled": True,
        "created_at": now,
        "next_run_at": next_run_at,
    }
    T.crm_reports.put_item(Item=item)

    try:
        audit_event("crm_report_schedule.created", owner_sub, None, schedule_id=schedule_id, report_id=report_id)
    except Exception:
        pass

    return _item_to_out(item)


def get_report_schedule(schedule_id: str, owner_sub: str) -> Optional[Dict[str, Any]]:
    item = _get_schedule_item(schedule_id)
    if not item:
        return None
    if item.get("owner_sub") != owner_sub:
        raise HTTPException(status_code=403, detail="Forbidden")
    return _item_to_out(item)


def list_report_schedules(
    owner_sub: str,
    report_id: Optional[str] = None,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List schedules for a user, optionally filtered by report_id."""
    if report_id:
        resp = T.crm_reports.query(
            KeyConditionExpression=Key("report_id").eq(report_id) & Key("sk").begins_with("SCHEDULE#"),
        )
        items = [i for i in resp.get("Items", []) if i.get("owner_sub") == owner_sub]
        return {"schedules": [_item_to_out(i) for i in items], "cursor": None}
    else:
        # Scan by owner_sub (no owner GSI; small numbers expected)
        resp = T.crm_reports.scan(
            FilterExpression="owner_sub = :sub AND begins_with(sk, :pfx)",
            ExpressionAttributeValues={":sub": owner_sub, ":pfx": "META"},
        )
        # Filter only schedule rows
        items = [i for i in resp.get("Items", []) if str(i.get("report_id", "")).startswith("SCHEDULE#")]
        return {"schedules": [_item_to_out(i) for i in items], "cursor": None}


def update_report_schedule(
    schedule_id: str,
    owner_sub: str,
    *,
    cadence: Optional[str] = None,
    recipients: Optional[List[str]] = None,
    fmt: Optional[str] = None,
    enabled: Optional[bool] = None,
) -> Dict[str, Any]:

    item = _get_schedule_item(schedule_id)
    if not item:
        raise HTTPException(status_code=404, detail="Schedule not found")
    if item.get("owner_sub") != owner_sub:
        raise HTTPException(status_code=403, detail="Forbidden")

    update_parts = ["#upd = :upd"]
    expr_names = {"#upd": "updated_at"}
    expr_vals: Dict[str, Any] = {":upd": now_ts()}

    if cadence is not None:
        if cadence not in CADENCE_OFFSETS:
            raise HTTPException(status_code=422, detail=f"Invalid cadence: {cadence}")
        new_next = now_ts() + CADENCE_OFFSETS[cadence]
        update_parts += ["cadence = :cad", "next_run_at = :nra", "GSI2SK = :gsi2sk"]
        expr_vals[":cad"] = cadence
        expr_vals[":nra"] = new_next
        expr_vals[":gsi2sk"] = new_next

    if recipients is not None:
        update_parts.append("recipients = :rec")
        expr_vals[":rec"] = json.dumps(list(dict.fromkeys(recipients)))

    if fmt is not None:
        if fmt not in VALID_FORMATS:
            raise HTTPException(status_code=422, detail=f"Invalid format: {fmt}")
        update_parts.append("#fmt = :fmt")
        expr_names["#fmt"] = "format"
        expr_vals[":fmt"] = fmt

    if enabled is not None:
        new_gsi2pk = SCHEDULES_ACTIVE if enabled else SCHEDULES_DISABLED
        update_parts += ["#en = :en", "GSI2PK = :gsi2pk"]
        expr_names["#en"] = "enabled"
        expr_vals[":en"] = enabled
        expr_vals[":gsi2pk"] = new_gsi2pk
        if enabled:
            # Recompute next_run_at to avoid immediate fire
            new_next = now_ts() + CADENCE_OFFSETS[item.get("cadence", "daily")]
            update_parts += ["next_run_at = :nra2", "GSI2SK = :gsi2sk2"]
            expr_vals[":nra2"] = new_next
            expr_vals[":gsi2sk2"] = new_next

    T.crm_reports.update_item(
        Key={"report_id": _schedule_pk(schedule_id), "sk": "META"},
        UpdateExpression="SET " + ", ".join(update_parts),
        ExpressionAttributeNames=expr_names,
        ExpressionAttributeValues=expr_vals,
    )

    try:
        audit_event("crm_report_schedule.updated", owner_sub, None, schedule_id=schedule_id)
    except Exception:
        pass

    updated = _get_schedule_item(schedule_id)
    return _item_to_out(updated)


def delete_report_schedule(schedule_id: str, owner_sub: str) -> None:

    item = _get_schedule_item(schedule_id)
    if not item:
        raise HTTPException(status_code=404, detail="Schedule not found")
    if item.get("owner_sub") != owner_sub:
        raise HTTPException(status_code=403, detail="Forbidden")

    T.crm_reports.delete_item(Key={"report_id": _schedule_pk(schedule_id), "sk": "META"})
    try:
        audit_event("crm_report_schedule.deleted", owner_sub, None, schedule_id=schedule_id)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Scheduler loop
# ---------------------------------------------------------------------------

def get_due_report_schedules(now: Optional[int] = None) -> List[Dict[str, Any]]:
    ts = now if now is not None else now_ts()
    resp = T.crm_reports.query(
        IndexName=SCHEDULE_INDEX,
        KeyConditionExpression=Key("GSI2PK").eq(SCHEDULES_ACTIVE) & Key("GSI2SK").lte(ts),
        ScanIndexForward=True,
    )
    return resp.get("Items", [])


def _serialize_result_csv(columns: List[str], rows: List[List[Any]], row_limit: int = 100) -> str:
    from app.services.csv_export import _sanitize_csv_field
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([_sanitize_csv_field(str(c)) for c in columns])
    for row in rows[:row_limit]:
        writer.writerow([_sanitize_csv_field(str(v) if v is not None else "") for v in row])
    return buf.getvalue()


def run_due_report_schedules() -> int:
    from app.services import crm_reports

    due = get_due_report_schedules()
    dispatched = 0

    for sched in due:
        schedule_id = sched.get("schedule_id", "")
        report_id = sched.get("linked_report_id", "")
        owner_sub = sched.get("owner_sub", "")
        cadence = sched.get("cadence", "daily")
        fmt = sched.get("format", "csv")
        recipients_raw = sched.get("recipients", "[]")
        if isinstance(recipients_raw, str):
            recipients = json.loads(recipients_raw)
        else:
            recipients = list(recipients_raw)

        try:
            run_result = crm_reports.run_report(report_id, owner_sub)

            report_name = report_id
            try:
                meta_resp = T.crm_reports.get_item(Key={"report_id": report_id, "sk": "META"})
                report_name = meta_resp.get("Item", {}).get("name", report_id)
            except Exception:
                pass

            subject = f"Scheduled report: {report_name} ({cadence})"
            columns = run_result.get("columns", [])
            rows = run_result.get("rows", [])
            row_count = run_result.get("row_count", 0)
            run_id = run_result.get("run_id", "")

            if row_count == 0:
                body_text = (
                    f"Scheduled report: {report_name}\n"
                    f"Schedule ID: {schedule_id}\nRun ID: {run_id}\nCadence: {cadence}\n\n"
                    "No rows matched the report criteria for this period."
                )
            elif fmt == "csv":
                csv_content = _serialize_result_csv(columns, rows, row_limit=100)
                if row_count > 100:
                    csv_content += f"\n(showing 100 of {row_count} rows — run report interactively for full results)"
                body_text = (
                    f"Scheduled report: {report_name}\n"
                    f"Schedule ID: {schedule_id}\nRun ID: {run_id}\nCadence: {cadence}\n"
                    f"Row count: {row_count}\n\n{csv_content}"
                )
            else:
                payload = {"columns": columns, "rows": rows[:100], "row_count": row_count}
                body_text = (
                    f"Scheduled report: {report_name}\n"
                    f"Schedule ID: {schedule_id}\nRun ID: {run_id}\nCadence: {cadence}\n"
                    f"Row count: {row_count}\n\n{json.dumps(payload)}"
                )

            try:
                send_alert_email(recipients, subject, body_text)
            except Exception as email_exc:
                logger.warning("rpt_schedule_email_failed schedule_id=%s err=%s", schedule_id, email_exc)

            # Advance next_run_at regardless of email success
            new_next = now_ts() + CADENCE_OFFSETS.get(cadence, 86400)
            T.crm_reports.update_item(
                Key={"report_id": _schedule_pk(schedule_id), "sk": "META"},
                UpdateExpression="SET next_run_at = :n, GSI2SK = :n, last_run_at = :now, last_run_id = :rid",
                ExpressionAttributeValues={":n": new_next, ":now": now_ts(), ":rid": run_id},
            )

            try:
                audit_event(
                    "crm_report_schedule.dispatched", owner_sub, None,
                    schedule_id=schedule_id, run_id=run_id,
                    row_count=row_count, recipient_count=len(recipients),
                )
            except Exception:
                pass

            dispatched += 1

        except Exception as exc:
            logger.error("rpt_schedule_dispatch_error schedule_id=%s err=%s", schedule_id, exc)
            continue

    return dispatched


async def run_report_scheduler_loop() -> None:
    poll_interval = S.crm_reports_scheduler_poll_interval or 300
    while True:
        try:
            await asyncio.to_thread(run_due_report_schedules)
        except Exception:
            logger.exception("crm_report_scheduler_loop_error")
        await asyncio.sleep(poll_interval)


async def start_report_scheduler_task() -> None:
    if S.crm_reports_enabled and S.crm_reports_scheduler_enabled:
        asyncio.create_task(run_report_scheduler_loop())
