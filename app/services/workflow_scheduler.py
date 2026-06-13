"""CRM Workflow Background Scheduler — WFL-005.

Drives on_schedule and on_time_elapsed trigger modes by polling the
workflow rules table and enqueuing crm_workflow action items in
T.scheduled_actions for dispatch by the unified scheduler executor.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import uuid
from time import perf_counter
from typing import Any

from app.core.settings import S
from app.core.time import now_ts
from app.services.job_registry import register_task, report_error, report_poll

logger = logging.getLogger(__name__)

_TASK_NAME = "crm_workflow_scheduler"


# ---------------------------------------------------------------------------
# Startup hook
# ---------------------------------------------------------------------------

async def start_workflow_scheduler_task() -> None:
    """FastAPI startup hook. No-op when S.crm_workflow_enabled is False."""
    if not S.crm_workflow_enabled:
        register_task(
            _TASK_NAME,
            S.crm_workflow_poll_interval_seconds,
            enabled=False,
            description="CRM workflow rule scheduler (disabled)",
        )
        logger.info("crm_workflow scheduler disabled")
        return
    asyncio.create_task(run_workflow_scheduler_loop())


async def run_workflow_scheduler_loop() -> None:
    """Infinite background loop: runs both tick functions on each interval."""
    poll_interval = S.crm_workflow_poll_interval_seconds
    register_task(
        _TASK_NAME,
        poll_interval,
        enabled=True,
        description="CRM workflow rule scheduler",
    )
    logger.info("crm_workflow scheduler started (interval=%ds)", poll_interval)

    while True:
        t0 = perf_counter()
        enqueued_sched = 0
        enqueued_elapsed = 0
        try:
            _now = now_ts()
            enqueued_sched = _tick_scheduled_rules(_now)
            enqueued_elapsed = _tick_time_elapsed_rules(_now)
            report_poll(
                _TASK_NAME,
                items_processed=enqueued_sched + enqueued_elapsed,
                duration_ms=(perf_counter() - t0) * 1000,
            )
        except Exception as exc:
            report_error(_TASK_NAME, str(exc))
            logger.exception("crm_workflow_scheduler_loop_error")
        await asyncio.sleep(poll_interval)


# ---------------------------------------------------------------------------
# Tick functions
# ---------------------------------------------------------------------------

def _tick_scheduled_rules(now: int) -> int:
    """Fire all on_schedule rules that are due. Returns count enqueued."""
    if not S.crm_workflow_enabled:
        return 0

    from app.services.workflow_rules import list_all_enabled_rules, update_rule_next_run_at
    from app.services.workflow_condition_evaluator import evaluate_conditions
    from app.services.workflow_record_fetcher import fetch_module_records
    from app.services.bot_scheduler import _parse_cron, _next_run_from_cron

    rules = list_all_enabled_rules(trigger_type="on_schedule")
    enqueued = 0

    for rule in rules:
        try:
            rule_id = rule["rule_id"]
            tc = rule.get("trigger_config") or {}
            cron_expr = tc.get("cron_expression", "")
            timezone = tc.get("timezone", "UTC")

            if not cron_expr or _parse_cron(cron_expr) is None:
                logger.warning(
                    "crm_workflow scheduler: invalid cron expression rule_id=%s expr=%r",
                    rule_id,
                    cron_expr,
                )
                continue

            next_run_at = rule.get("next_run_at")
            if next_run_at is None:
                # Initialise next_run_at and skip this tick
                try:
                    nra = _next_run_from_cron(cron_expr, timezone)
                    update_rule_next_run_at(rule_id, nra)
                except Exception as exc:
                    logger.warning(
                        "crm_workflow scheduler: failed to init next_run_at rule=%s: %s",
                        rule_id,
                        exc,
                    )
                continue

            if int(next_run_at) > now:
                continue  # Not due yet

            # Fetch records and evaluate conditions
            records = fetch_module_records(rule["target_module"])
            for record in records:
                matched, _ = evaluate_conditions(rule.get("conditions", []), record)
                if matched:
                    record_id = _get_record_id(rule["target_module"], record)
                    _enqueue_workflow_action(
                        rule_id=rule_id,
                        module=rule["target_module"],
                        record_id=record_id,
                        trigger_type="on_schedule",
                    )
                    enqueued += 1

            # Advance next_run_at
            try:
                nra = _next_run_from_cron(cron_expr, timezone)
                update_rule_next_run_at(rule_id, nra)
            except Exception as exc:
                logger.warning(
                    "crm_workflow scheduler: failed advance next_run_at rule=%s: %s",
                    rule_id,
                    exc,
                )

        except Exception as exc:
            logger.warning(
                "crm_workflow scheduler: on_schedule tick error rule=%s: %s",
                rule.get("rule_id"),
                exc,
                exc_info=True,
            )

    return enqueued


def _tick_time_elapsed_rules(now: int) -> int:
    """Fire on_time_elapsed rules for records in the elapsed window.

    Returns count enqueued.
    """
    if not S.crm_workflow_enabled:
        return 0

    from app.services.workflow_rules import list_all_enabled_rules
    from app.services.workflow_condition_evaluator import evaluate_conditions
    from app.services.workflow_record_fetcher import fetch_module_records

    poll_window = S.crm_workflow_poll_interval_seconds
    rules = list_all_enabled_rules(trigger_type="on_time_elapsed")
    enqueued = 0

    for rule in rules:
        try:
            rule_id = rule["rule_id"]
            tc = rule.get("trigger_config") or {}
            field = tc.get("field", "")
            offset_hours = int(tc.get("offset_hours", 0))
            offset_seconds = offset_hours * 3600

            window_start = now - offset_seconds - poll_window
            window_end = now - offset_seconds

            records = fetch_module_records(rule["target_module"])
            for record in records:
                field_val = record.get(field)
                if field_val is None:
                    continue
                try:
                    field_ts = _coerce_to_ts(field_val)
                except Exception:
                    continue

                if not (window_start <= field_ts <= window_end):
                    continue

                matched, _ = evaluate_conditions(rule.get("conditions", []), record)
                if not matched:
                    continue

                record_id = _get_record_id(rule["target_module"], record)
                # Write dedup sentinel before enqueue
                written = _write_enqueue_sentinel(
                    rule_id=rule_id,
                    module=rule["target_module"],
                    record_id=record_id,
                    now=now,
                    window_start=window_start,
                    window_end=window_end,
                )
                if not written:
                    continue

                _enqueue_workflow_action(
                    rule_id=rule_id,
                    module=rule["target_module"],
                    record_id=record_id,
                    trigger_type="on_time_elapsed",
                )
                enqueued += 1

        except Exception as exc:
            logger.warning(
                "crm_workflow scheduler: on_time_elapsed tick error rule=%s: %s",
                rule.get("rule_id"),
                exc,
                exc_info=True,
            )

    return enqueued


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_record_id(module: str, record: dict) -> str:
    if module == "ticket":
        return record.get("ticket_id", "")
    if module == "contact":
        return record.get("contact_id", "")
    return record.get("id", record.get("record_id", ""))


def _coerce_to_ts(value: Any) -> int:
    """Coerce a field value (int epoch or ISO string) to int Unix timestamp."""
    from decimal import Decimal
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, Decimal):
        return int(value)
    if isinstance(value, str):
        stripped = value.strip()
        try:
            return int(float(stripped))
        except ValueError:
            pass
        from datetime import datetime
        dt = datetime.fromisoformat(stripped.replace("Z", "+00:00"))
        return int(dt.timestamp())
    raise ValueError(f"Cannot coerce {type(value).__name__} to timestamp")


def _enqueue_workflow_action(
    rule_id: str, module: str, record_id: str, trigger_type: str
) -> str:
    """Write one crm_workflow pending item to T.scheduled_actions.

    Bypasses create_action min-lead-time guard via direct put_item.
    Returns action_id.
    """
    from app.core.tables import T

    action_id = "sa_" + uuid.uuid4().hex
    scheduled_at = now_ts() + S.scheduled_actions_min_lead_time_seconds + 1
    _now = now_ts()
    item: dict[str, Any] = {
        "pk": "USER#system",
        "sk": f"ACTION#{scheduled_at}#{action_id}",
        "action_id": action_id,
        "user_sub": "system",
        "action_type": "crm_workflow",
        "status": "pending",
        "scheduled_at": scheduled_at,
        "created_at": _now,
        "updated_at": _now,
        "title": f"WFL {trigger_type}: rule={rule_id}",
        "payload": {
            "rule_id": rule_id,
            "module": module,
            "record_id": record_id,
            "trigger_type": trigger_type,
        },
        "GSI_DUE_PK": "DUE",
        "GSI_DUE_SK": scheduled_at,
        "GSI_TYPE_PK": "USER#system#TYPE#crm_workflow",
        "GSI_TYPE_SK": scheduled_at,
        "ttl_epoch": scheduled_at + S.scheduled_actions_ttl_days * 86400,
        "retry_count": 0,
        "max_retries": S.scheduled_actions_max_retries,
        "reminder_sent": False,
        "notify_before_seconds": 0,
    }
    T.scheduled_actions.put_item(Item=item)
    return action_id


def _is_already_enqueued(rule_id: str, record_id: str, window_start: int) -> bool:
    """Check T.crm_workflow_runs ByRecord GSI for a sentinel in this window."""
    from app.core.tables import T
    from boto3.dynamodb.conditions import Key, Attr

    run_id = _sentinel_run_id(rule_id, record_id, window_start)
    pk = f"RULE#{rule_id}"
    try:
        resp = T.crm_workflow_runs.query(
            IndexName="ByRecord",
            KeyConditionExpression=Key("GSI_RECORD_PK").eq(f"{record_id}"),
            FilterExpression=Attr("run_id").eq(run_id),
            Limit=1,
        )
        return len(resp.get("Items", [])) > 0
    except Exception:
        return False


def _sentinel_run_id(rule_id: str, record_id: str, window_start: int) -> str:
    h = hashlib.sha256(f"{rule_id}{record_id}{window_start}".encode()).hexdigest()
    return h[:16]


def _write_enqueue_sentinel(
    rule_id: str,
    module: str,
    record_id: str,
    now: int,
    window_start: int,
    window_end: int,
) -> bool:
    """Conditional-put sentinel for dedup. Returns True if written."""
    from app.core.tables import T
    from botocore.exceptions import ClientError

    run_id = _sentinel_run_id(rule_id, record_id, window_start)
    pk = f"RULE#{rule_id}"
    sk = f"RUN#{now:010d}#{run_id}"

    item: dict[str, Any] = {
        "pk": pk,
        "sk": sk,
        "run_id": run_id,
        "rule_id": rule_id,
        "target_module": module,
        "record_id": record_id,
        "trigger_type": "on_time_elapsed",
        "outcome": "enqueued",
        "started_at": now,
        "dedup_window_start": window_start,
        "dedup_window_end": window_end,
        "GSI_RECORD_PK": f"{module}#{record_id}",
        "GSI_RECORD_SK": now,
    }

    try:
        T.crm_workflow_runs.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(pk)",
        )
        return True
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "ConditionalCheckFailedException":
            return False
        raise
