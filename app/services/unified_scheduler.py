"""
Unified Content Scheduler -- background task that polls for due actions and dispatches them.
"""
from __future__ import annotations

import asyncio
import logging
import time as _time

from app.core.settings import S
from app.core.time import now_ts
from app.services import schedule_executors
from app.services.job_registry import register_task, report_error, report_poll
from app.services.scheduled_actions import (
    claim_action,
    mark_action_completed,
    mark_action_failed,
    mark_reminder_sent,
    query_due_actions,
    query_upcoming_reminders,
    schedule_retry,
)

logger = logging.getLogger(__name__)

MAX_BATCH_SIZE = 25

_EXECUTORS = {
    "post": schedule_executors.execute_scheduled_post,
    "file_share": schedule_executors.execute_scheduled_file_share,
    "catalog_sale": schedule_executors.execute_scheduled_catalog_sale,
}


async def run_unified_scheduler_loop() -> None:
    if not S.unified_scheduler_enabled:
        register_task("unified_scheduler", S.unified_scheduler_poll_interval_seconds,
                       enabled=False, description="Processes scheduled posts, file shares, and catalog sales")
        logger.info("Unified scheduler disabled")
        return

    poll_interval = S.unified_scheduler_poll_interval_seconds
    register_task("unified_scheduler", poll_interval, enabled=True,
                   description="Processes scheduled posts, file shares, and catalog sales")
    logger.info("Unified scheduler started (poll_interval=%ds)", poll_interval)

    while True:
        _poll_start = _time.perf_counter()
        _processed = 0
        _failed = 0
        try:
            now = now_ts()

            # 1. Process due actions
            due_actions = query_due_actions(now=now, limit=MAX_BATCH_SIZE)
            for action in due_actions:
                try:
                    await _process_action(action, now)
                    _processed += 1
                except Exception:
                    _failed += 1
                    logger.exception("Action processing failed: %s", action.get("action_id", "?"))

            # 2. Send pre-execution reminders
            try:
                upcoming = query_upcoming_reminders(now=now, lookahead=300)
                for action in upcoming:
                    nbs = int(action.get("notify_before_seconds", 0) or 0)
                    if nbs > 0 and not action.get("reminder_sent"):
                        remind_at = int(action.get("scheduled_at", 0)) - nbs
                        if remind_at <= now:
                            _send_reminder(action)
            except Exception:
                logger.exception("Error processing reminders")

            _duration_ms = (_time.perf_counter() - _poll_start) * 1000
            report_poll("unified_scheduler", items_processed=_processed,
                        items_failed=_failed, duration_ms=_duration_ms)
            _record_run("success" if _failed == 0 else "partial",
                        _poll_start, _processed, _failed)

        except Exception as exc:
            report_error("unified_scheduler", str(exc))
            _record_run("failed", _poll_start, _processed, _failed, error=str(exc))
            logger.exception("Unified scheduler loop error")

        await asyncio.sleep(poll_interval)


def _record_run(status: str, poll_start: float, processed: int, failed: int,
                error: str | None = None) -> None:
    """Persist this poll cycle to the job_runs history (PLATFORM-008)."""
    try:
        from app.services.job_dashboard import record_job_run

        record_job_run(
            "unified_scheduler", status,
            duration_ms=(_time.perf_counter() - poll_start) * 1000,
            items_processed=processed, items_failed=failed, error=error,
        )
    except Exception:
        logger.debug("unified_scheduler: record_job_run failed", exc_info=True)


async def run_unified_scheduler_once() -> dict:
    """Run a single scheduler iteration (manual "run now").

    Processes currently-due actions once and returns counters. Used by the
    job dashboard's manual trigger; awaited from an async context.
    """
    now = now_ts()
    processed = 0
    failed = 0
    due_actions = query_due_actions(now=now, limit=MAX_BATCH_SIZE)
    for action in due_actions:
        try:
            await _process_action(action, now)
            processed += 1
        except Exception:
            failed += 1
            logger.exception("run-now action processing failed: %s", action.get("action_id", "?"))
    return {"items_processed": processed, "items_failed": failed, "due": len(due_actions)}


async def _process_action(action: dict, now: int) -> None:
    action_id = action.get("action_id", "?")
    action_type = action.get("action_type", "")
    user_sub = action.get("user_sub", "")
    sk = action.get("sk", "")

    claimed = claim_action(action_id, user_sub, sk)
    if not claimed:
        return  # Another scheduler instance claimed it

    executor = _EXECUTORS.get(action_type)
    if not executor:
        mark_action_failed(action, error=f"Unknown action_type: {action_type}")
        return

    try:
        await executor(user_sub, action.get("payload") or {})
        mark_action_completed(action)
        logger.info("Executed scheduled action %s (type=%s)", action_id, action_type)
    except Exception as exc:
        retry_count = int(action.get("retry_count", 0) or 0) + 1
        max_retries = int(action.get("max_retries", S.scheduled_actions_max_retries) or S.scheduled_actions_max_retries)
        if retry_count < max_retries:
            schedule_retry(action, retry_count, delay_seconds=60 * retry_count)
            logger.warning(
                "Scheduled action %s failed (attempt %d/%d), retrying: %s",
                action_id, retry_count, max_retries, exc,
            )
        else:
            mark_action_failed(action, error=str(exc))
            logger.error("Scheduled action %s permanently failed: %s", action_id, exc)


def _send_reminder(action: dict) -> None:
    """Send a pre-execution reminder alert."""
    try:
        from app.services.alerts import write_alert

        user_sub = action.get("user_sub", "")
        action_type = action.get("action_type", "")
        title = action.get("title", "") or f"Scheduled {action_type}"
        scheduled_at = int(action.get("scheduled_at", 0))

        write_alert(
            user_sub,
            event="scheduled_action_reminder",
            outcome="info",
            title=f"Upcoming: {title}",
            details={
                "action_id": action.get("action_id", ""),
                "action_type": action_type,
                "scheduled_at": scheduled_at,
            },
        )
        mark_reminder_sent(action)
        logger.info("Sent reminder for action %s", action.get("action_id", ""))
    except Exception:
        logger.exception("Failed to send reminder for action %s", action.get("action_id", ""))


async def start_unified_scheduler_task() -> None:
    """FastAPI startup event handler."""
    if S.unified_scheduler_enabled:
        asyncio.create_task(run_unified_scheduler_loop())
