"""Background scheduler that auto-starts broadcast sessions at their scheduled_at time."""

from __future__ import annotations

import asyncio
import logging
import time as _time

from app.core.settings import S
from app.core.time import now_ts
from app.services.job_registry import register_task, report_error, report_poll

logger = logging.getLogger(__name__)


def promote_due_sessions(*, now: int | None = None, limit: int = 10) -> dict:
    """Promote all scheduled broadcasts whose scheduled_at has passed.

    Shared by the background loop and the manual ``POST /broadcast/scheduler/run-due``
    trigger so promotion is deterministically testable. For each due session it
    re-reads with a consistent read (race guard), verifies it is still
    ``schedule_status='scheduled'``, then calls ``start_session_with_provider()``.
    Returns ``{"processed": int, "failed": int, "session_ids": [...]}``.
    """
    from app.services.broadcast_store import (
        list_due_scheduled_sessions,
        get_session,
        update_session_fields,
    )
    from app.services.broadcast_orchestrator import start_session_with_provider

    if now is None:
        now = now_ts()

    processed = 0
    failed = 0
    started: list[str] = []
    for session in list_due_scheduled_sessions(now=now, limit=limit):
        try:
            fresh = get_session(session.id)
            if fresh.schedule_status != "scheduled":
                logger.info(
                    "Session %s schedule_status=%s (not 'scheduled'), skipping",
                    session.id, fresh.schedule_status,
                )
                continue
            logger.info(
                "Auto-starting scheduled broadcast %s (scheduled_at=%s, now=%d)",
                session.id, session.scheduled_at, now,
            )
            start_session_with_provider(
                session_id=session.id,
                actor="system:broadcast-scheduler",
                reason="scheduled-auto-start",
                correlation_id=f"sched-{session.id}-{now}",
            )
            # Mark the schedule as launched so the session is no longer reported
            # as 'scheduled' (and drops out of the ByScheduledAt due-query GSI,
            # preventing re-promotion). schedule_status values: scheduled /
            # launched / cancelled.
            update_session_fields(session.id, {"schedule_status": "launched"})
            logger.info("Auto-start succeeded for session %s", session.id)
            processed += 1
            started.append(session.id)
        except Exception:
            failed += 1
            logger.exception("Auto-start failed for session %s", session.id)

    return {"processed": processed, "failed": failed, "session_ids": started}


async def run_broadcast_scheduler_loop() -> None:
    """Poll ByScheduledAt GSI for due scheduled broadcasts and auto-start them.

    Runs every ``S.broadcast_scheduler_poll_interval_seconds`` seconds.
    For each due session the loop:
    1. Re-fetches the session with a consistent read (guards against races).
    2. Verifies the session is still in ``schedule_status="scheduled"``.
    3. Calls ``start_session_with_provider()`` to provision and go live.
    """
    if not S.broadcast_scheduler_enabled:
        register_task("broadcast_scheduler", S.broadcast_scheduler_poll_interval_seconds,
                       enabled=False, description="Auto-starts scheduled broadcast sessions")
        logger.info("Broadcast scheduler disabled")
        return

    poll_interval = S.broadcast_scheduler_poll_interval_seconds
    register_task("broadcast_scheduler", poll_interval, enabled=True,
                   description="Auto-starts scheduled broadcast sessions")
    logger.info("Broadcast scheduler started (poll_interval=%ds)", poll_interval)

    while True:
        _start = _time.perf_counter()
        try:
            summary = promote_due_sessions(now=now_ts(), limit=10)
            _dur = (_time.perf_counter() - _start) * 1000
            report_poll("broadcast_scheduler", items_processed=summary["processed"],
                        items_failed=summary["failed"], duration_ms=_dur)

        except Exception as exc:
            report_error("broadcast_scheduler", str(exc))
            logger.exception("Broadcast scheduler loop error")

        await asyncio.sleep(poll_interval)


def start_broadcast_scheduler_task() -> None:
    """Register the broadcast scheduler as an asyncio background task."""
    asyncio.create_task(run_broadcast_scheduler_loop())


async def run_broadcast_reminder_loop() -> None:
    """Poll BroadcastReminders for due reminders and dispatch alerts."""
    if not S.broadcast_scheduler_enabled:
        register_task("broadcast_reminder", S.broadcast_scheduler_poll_interval_seconds,
                       enabled=False, description="Dispatches broadcast pre-start reminders")
        logger.info("Broadcast reminder loop disabled (scheduler disabled)")
        return

    poll_interval = S.broadcast_scheduler_poll_interval_seconds
    register_task("broadcast_reminder", poll_interval, enabled=True,
                   description="Dispatches broadcast pre-start reminders")
    logger.info("Broadcast reminder loop started (poll_interval=%ds)", poll_interval)

    while True:
        _start = _time.perf_counter()
        try:
            now = now_ts()
            from app.services.broadcast_reminders import dispatch_due_reminders
            dispatched = dispatch_due_reminders(now=now, limit=50)
            if dispatched:
                logger.info("Dispatched %d broadcast reminders", dispatched)
            _dur = (_time.perf_counter() - _start) * 1000
            report_poll("broadcast_reminder", items_processed=dispatched or 0, duration_ms=_dur)
        except Exception as exc:
            report_error("broadcast_reminder", str(exc))
            logger.exception("Broadcast reminder loop error")

        await asyncio.sleep(poll_interval)


def start_broadcast_reminder_task() -> None:
    """Register the broadcast reminder loop as an asyncio background task."""
    asyncio.create_task(run_broadcast_reminder_loop())
