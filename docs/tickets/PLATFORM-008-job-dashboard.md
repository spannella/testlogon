# PLATFORM-008: Background Job Dashboard

**Ticket**: PLATFORM-008
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-27
**Priority**: Medium
**Estimated effort**: 10-14 days

---

## 1. Executive Summary

The platform runs 11 background tasks registered as FastAPI startup event handlers in `app/main.py:348-421`. These include the unified content scheduler (`unified_scheduler.py`), webhook dispatcher (`webhook_dispatcher.py`), billing dunning, billing reconciliation, file manager purge, scheduled messages, broadcast scheduler/reminder/reconciler, transcode worker, project reconciliation, and file mount reconciliation. Each runs as an asyncio coroutine in a polling loop with its own interval.

There is no admin visibility into any of these background jobs. No endpoint reports queue depths, failure counts, last execution times, or currently running jobs. The user-facing scheduler router (`app/routers/scheduler.py:45-148`) only shows a user's own scheduled actions. The webhook admin endpoints (`app/routers/webhooks.py:182-215`) show webhook-specific delivery health but not the dispatcher's own operational status.

When a background job fails silently or stops polling, the only indication is missing side effects (e.g., scheduled posts not publishing, webhooks not delivering). There is no monitoring dashboard, no health check for background tasks, and no admin API to inspect failed jobs.

This ticket adds a unified background job status API (`GET /ui/admin/jobs/status`), a failed job list (`GET /ui/admin/jobs/failed`), a job retry endpoint, an in-memory job health registry that each background task reports to, and an admin dashboard page showing real-time job health metrics.

---

## 2. Detailed Problem Analysis

### 2.1 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Admin | I want to see which background jobs are running. | Dashboard shows all 11+ tasks with running/stopped status. |
| Admin | I want to see how many items are pending in each queue. | Dashboard shows queue depths for scheduled actions and webhook deliveries. |
| Admin | I want to see failed jobs and their error messages. | Failed jobs table with action_id, type, error, timestamp. |
| Admin | I want to retry a failed job manually. | "Retry" button reschedules a failed action back to pending. |
| Admin | I want to see the last time each background loop executed. | Dashboard shows last_poll_at and poll_interval per task. |
| Admin | I want to detect stale tasks that have stopped polling. | Task marked "stale" when no poll in 3x its interval. |
| Admin | I want to detect unhealthy tasks with repeated errors. | Task marked "unhealthy" after 5+ consecutive poll errors. |
| Admin | I want to see aggregate stats by action type. | Stats endpoint breaks down completed/failed/pending by type. |
| Ops | I want an alerting endpoint for Prometheus/Grafana. | `/metrics` includes background job health counters and gauges. |
| Ops | I want the dashboard to auto-refresh. | Dashboard polls every 15 seconds for status updates. |

### 2.2 Pain Points

1. **Invisible failures**: `unified_scheduler.py:62` catches all exceptions in the main loop and logs them, but there is no way to see these errors without SSH access to the server logs. The same pattern exists in all 11 tasks.
2. **No queue depth visibility**: `query_due_actions()` (`scheduled_actions.py:355-363`) returns pending items but this count is never exposed to admins.
3. **No task health signal**: If a background task crashes or stops polling, nothing detects it. The uvicorn process stays alive (health checks pass) but the asyncio coroutine is dead.
4. **Webhook dashboard exists but is incomplete**: `admin_get_health_summary()` in `webhook_service.py:717-761` provides webhook delivery stats, but it requires scanning the entire deliveries table (expensive at scale) and doesn't cover the dispatcher task itself.
5. **11 background tasks, zero observability**: Each task runs independently with its own error handling. There is no unified view across all tasks.
6. **No admin retry for failed jobs**: `mark_action_failed()` (`scheduled_actions.py:413-425`) removes the action from the due GSI and sets `status=failed`. There is no way for an admin to reschedule it.
7. **No cross-user visibility**: The scheduler router (`app/routers/scheduler.py:45-148`) only shows a user's own actions. Admins cannot see all users' failed actions.

---

## 3. Current State Analysis

### 3.1 Background Tasks Registered in main.py

From `app/main.py:348-421`, all startup event handlers:

| # | Task | Source File | Start Function | Poll Interval |
|---|------|------------|----------------|---------------|
| 1 | billing_dunning | `app/services/billing_dunning.py` | `start_billing_dunning_task` (main.py:348) | Configurable |
| 2 | filemgr_purge | `app/services/filemanager.py` | `start_filemgr_purge_task` (main.py:349) | Configurable |
| 3 | scheduled_messages | `app/routers/messaging.py` | `start_scheduled_messages_task` (main.py:350) | 30s |
| 4 | broadcast_scheduler | `app/services/broadcast_scheduler.py` | `start_broadcast_scheduler_task` (main.py:351) | Configurable |
| 5 | broadcast_reminder | `app/services/broadcast_scheduler.py` | `start_broadcast_reminder_task` (main.py:352) | Configurable |
| 6 | unified_scheduler | `app/services/unified_scheduler.py:128-131` | `start_unified_scheduler_task` (main.py:415) | 15s (settings.py:1256) |
| 7 | billing_reconcile | `app/services/billing_reconcile.py` | `start_billing_reconcile_task` (main.py:416) | Configurable |
| 8 | projects_reconcile | `app/services/projects_reconcile.py` | `start_projects_reconcile_task` (main.py:417) | Configurable |
| 9 | filemgr_mount_reconcile | `app/services/filemanager_mount_reconcile.py` | `start_filemgr_mount_reconcile_task` (main.py:418) | Configurable |
| 10 | broadcast_reconciler | `app/services/broadcast_reconciler.py` | `start_broadcast_reconciler_task` (main.py:419) | Configurable |
| 11 | transcode_worker | `app/services/transcode_worker.py` | `start_transcode_worker_task` (main.py:420) | Configurable |
| 12 | webhook_dispatcher | `app/services/webhook_dispatcher.py:67-70` | `start_webhook_dispatcher_task` (main.py:421) | 10s (settings.py:1250) |

### 3.2 Unified Scheduler (Primary Job Processor)

`app/services/unified_scheduler.py:33-65`:

```python
async def run_unified_scheduler_loop() -> None:
    if not S.unified_scheduler_enabled:
        logger.info("Unified scheduler disabled")
        return

    poll_interval = S.unified_scheduler_poll_interval_seconds
    logger.info("Unified scheduler started (poll_interval=%ds)", poll_interval)

    while True:
        try:
            now = now_ts()
            # 1. Process due actions
            due_actions = query_due_actions(now=now, limit=MAX_BATCH_SIZE)
            for action in due_actions:
                await _process_action(action, now)

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

        except Exception:
            logger.exception("Unified scheduler loop error")

        await asyncio.sleep(poll_interval)
```

Key details:
- Polls every 15 seconds (`S.unified_scheduler_poll_interval_seconds`, `settings.py:1256`)
- Processes up to 25 actions per poll (`MAX_BATCH_SIZE = 25`, line 24)
- Three action types registered: `post`, `file_share`, `catalog_sale` (`_EXECUTORS` dict, lines 26-30)
- Each action is claimed atomically via `claim_action()` (`scheduled_actions.py:377-396`) using DDB conditional update
- Failed actions retry up to `S.scheduled_actions_max_retries` (default 3, `settings.py:1259`) with exponential backoff via `schedule_retry()` (`scheduled_actions.py:428-442`)
- Permanently failed actions marked `status=failed` and removed from due GSI via `mark_action_failed()` (`scheduled_actions.py:413-425`)

Startup handler (`unified_scheduler.py:128-131`):
```python
async def start_unified_scheduler_task() -> None:
    """FastAPI startup event handler."""
    if S.unified_scheduler_enabled:
        asyncio.create_task(run_unified_scheduler_loop())
```

### 3.3 Scheduled Actions DDB Schema

From `app/services/scheduled_actions.py:1-9`:

```
Table: scheduled_actions
  PK: USER#{user_sub}
  SK: ACTION#{scheduled_at}#{action_id}
  GSI ByDue: GSI_DUE_PK="DUE"  GSI_DUE_SK=scheduled_at (N)
  GSI ByType: GSI_TYPE_PK="USER#{user_sub}#TYPE#{action_type}"  GSI_TYPE_SK=scheduled_at (N)
```

DDB init (`scripts/local-ddb-init.py:884-893`):
```python
TableDef(
    _resolve_table_name(S.scheduled_actions_table_name, "scheduled_actions"),
    "pk",
    "sk",
    gsi=[
        {"index_name": "ByDue", "partition_key": "GSI_DUE_PK", "sort_key": "GSI_DUE_SK"},
        {"index_name": "ByType", "partition_key": "GSI_TYPE_PK", "sort_key": "GSI_TYPE_SK"},
    ],
    attr_types={"GSI_DUE_SK": "N", "GSI_TYPE_SK": "N"},
),
```

Status values: `pending`, `executing`, `completed`, `failed`, `cancelled`

Key functions:
- `query_due_actions(now, limit)` (`scheduled_actions.py:355-363`): Queries ByDue GSI where `GSI_DUE_PK="DUE"` and `GSI_DUE_SK <= now`, filtered by `status=pending`
- `claim_action(action_id, user_sub, sk)` (`scheduled_actions.py:377-396`): Atomic conditional update `pending -> executing`
- `mark_action_completed(action)` (`scheduled_actions.py:399-410`): Sets `status=completed`, REMOVEs `GSI_DUE_PK` and `GSI_DUE_SK`
- `mark_action_failed(action, error)` (`scheduled_actions.py:413-425`): Sets `status=failed`, stores error string, REMOVEs GSI keys
- `schedule_retry(action, retry_count, delay_seconds)` (`scheduled_actions.py:428-442`): Sets back to `pending` with new `GSI_DUE_SK = now + delay_seconds`
- `mark_reminder_sent(action)` (`scheduled_actions.py:445-452`): Sets `reminder_sent=True`

### 3.4 Webhook Dispatcher (Secondary Job Processor)

`app/services/webhook_dispatcher.py:26-64`:

```python
async def run_webhook_dispatcher_loop() -> None:
    """Background coroutine that processes pending webhook deliveries."""
    while True:
        try:
            now = now_ts()
            due_pending = query_due_deliveries(status="pending", now=now, limit=MAX_BATCH_SIZE)
            due_retry = query_due_deliveries(status="failed", now=now, limit=MAX_BATCH_SIZE)
            due = due_pending + due_retry

            for delivery in due:
                try:
                    endpoint_id = delivery.get("endpoint_id", "")
                    user_sub = delivery.get("user_sub", "")
                    endpoint = _get_endpoint_raw(user_sub, endpoint_id)
                    if not endpoint or not endpoint.get("enabled", True):
                        mark_delivery_dead_letter(delivery, reason="endpoint_disabled")
                        continue

                    secret = _decrypt_secret(endpoint["secret"])
                    result = await deliver_webhook(...)

                    if result["success"]:
                        mark_delivery_success(delivery, result)
                        reset_endpoint_failure_count(endpoint_id, user_sub)
                    else:
                        handle_delivery_failure(delivery, endpoint, result)
                except Exception:
                    logger.exception("Webhook delivery error for %s", delivery.get("delivery_id", ""))

        except Exception:
            logger.exception("Webhook dispatcher loop error")

        await asyncio.sleep(S.webhooks_dispatcher_poll_interval or POLL_INTERVAL_SECONDS)
```

- Polls every 10 seconds (`POLL_INTERVAL_SECONDS = 10`, line 22; or `S.webhooks_dispatcher_poll_interval`, `settings.py:1250`)
- Processes up to 50 deliveries per poll (`MAX_BATCH_SIZE = 50`, line 23)
- Queries both `pending` and `failed` deliveries via `query_due_deliveries()` (`webhook_service.py:815-822`)
- Failed deliveries retry with exponential backoff or become `dead_letter` after `S.webhooks_max_retries` (default 5, `settings.py:1248`)

Startup handler (`webhook_dispatcher.py:67-70`):
```python
async def start_webhook_dispatcher_task() -> None:
    """Start the webhook dispatcher if enabled."""
    if S.webhooks_enabled:
        asyncio.create_task(run_webhook_dispatcher_loop())
```

### 3.5 Existing Webhook Admin Endpoints

`app/routers/webhooks.py:182-215`:

```python
@router.get("/ui/admin/webhooks/endpoints")     # line 182: list all endpoints
@router.get("/ui/admin/webhooks/health")         # line 193: delivery health summary
@router.get("/ui/admin/webhooks/dead-letter")    # line 204: dead letter list
@router.post("/ui/admin/webhooks/endpoints/{endpoint_id}/disable")  # line 215: force-disable
```

`admin_get_health_summary()` (`webhook_service.py:717-761`) scans the deliveries table with a 24-hour filter and counts by status:
```python
def admin_get_health_summary() -> Dict[str, Any]:
    # Scan with FilterExpression "created_at >= :cutoff" (last 24h)
    # Returns: total_endpoints, enabled/disabled, total_deliveries_24h,
    #          success_count_24h, failed_count_24h, dead_letter_count_24h
```

These cover webhook delivery visibility but NOT:
- The dispatcher task's own health (is it running? when did it last poll?)
- The unified scheduler's health
- Any of the other 9 background tasks
- A unified view across all job types

### 3.6 User-Facing Scheduler Router

`app/routers/scheduler.py:45-148`:

- `POST /ui/scheduler/actions` -- create scheduled action
- `GET /ui/scheduler/actions` -- list user's own actions
- `GET /ui/scheduler/actions/{action_id}` -- get action detail
- `PATCH /ui/scheduler/actions/{action_id}` -- update/reschedule
- `DELETE /ui/scheduler/actions/{action_id}` -- cancel
- `GET /ui/scheduler/calendar` -- calendar view

All user-scoped. No admin cross-user visibility.

### 3.7 Scheduled Actions Helper Functions

`app/services/scheduled_actions.py:30-48`:

```python
def _new_action_id() -> str:
    return "sa_" + uuid.uuid4().hex

def _pk(user_sub: str) -> str:
    return f"USER#{user_sub}"

def _sk(scheduled_at: int, action_id: str) -> str:
    return f"ACTION#{scheduled_at}#{action_id}"

def _gsi_type_pk(user_sub: str, action_type: str) -> str:
    return f"USER#{user_sub}#TYPE#{action_type}"

def _ttl_epoch(ts: int) -> int:
    return ts + S.scheduled_actions_ttl_days * 86400
```

### 3.8 Settings for Background Tasks

`app/core/settings.py`:

| Setting | Line | Default | Description |
|---------|------|---------|-------------|
| `unified_scheduler_enabled` | 1255 | `"1"` (enabled) | Master switch for unified scheduler |
| `unified_scheduler_poll_interval_seconds` | 1256 | `15` | Poll interval |
| `scheduled_actions_max_retries` | 1259 | `3` | Max retries before permanent failure |
| `scheduled_actions_ttl_days` | 1260 | `90` | DDB TTL for completed/failed actions |
| `webhooks_enabled` | 1245 | `"1"` (enabled) | Master switch for webhooks |
| `webhooks_dispatcher_poll_interval` | 1250 | `10` | Webhook poll interval |
| `webhooks_max_retries` | 1248 | `5` | Max webhook delivery retries |

### 3.9 Gaps Summary

1. No unified background job health API
2. No admin endpoint for queue depths
3. No admin endpoint for cross-user failed jobs
4. No task heartbeat/health registry
5. No admin dashboard for job monitoring
6. No retry mechanism for permanently failed actions (admin-initiated)
7. No alerting metrics for job health
8. Existing webhook admin endpoints don't cover the dispatcher task itself
9. No stale task detection
10. No unhealthy task detection (repeated errors)
11. No per-task polling duration tracking

---

## 4. Implementation Plan

### 4.1 Backend: Job Health Registry (In-Memory)

**New file: `app/services/job_registry.py`**

An in-memory registry that background tasks report to on each poll cycle. Thread-safe via `threading.Lock` (asyncio tasks share the same process but may run on different OS threads in some configurations).

```python
"""In-memory background job health registry (PLATFORM-008).

Each background task registers itself and reports health on every poll cycle.
The admin API reads from this registry to provide real-time task status.

This is intentionally in-memory (not DDB) because:
1. Task health is per-process -- each uvicorn worker has its own tasks
2. No persistence needed -- the registry rebuilds on process restart
3. Zero additional DDB cost
4. Sub-microsecond read latency
"""
from __future__ import annotations

import threading
from typing import Any, Dict, Optional

from app.core.time import now_ts

_lock = threading.Lock()
_tasks: Dict[str, Dict[str, Any]] = {}


def register_task(
    name: str,
    poll_interval_seconds: int,
    enabled: bool = True,
    description: str = "",
) -> None:
    """Register a background task with initial state.

    Called once at task startup (or when the task is disabled).

    Args:
        name: Unique task identifier (e.g., "unified_scheduler").
        poll_interval_seconds: Expected interval between poll cycles.
        enabled: Whether the task is actually running.
        description: Human-readable description of the task.
    """
    with _lock:
        _tasks[name] = {
            "name": name,
            "description": description,
            "poll_interval_seconds": poll_interval_seconds,
            "enabled": enabled,
            "started_at": now_ts() if enabled else None,
            "last_poll_at": None,
            "last_poll_duration_ms": None,
            "items_processed": 0,
            "items_failed": 0,
            "total_polls": 0,
            "consecutive_errors": 0,
            "last_error": None,
            "last_error_at": None,
            "status": "running" if enabled else "disabled",
        }


def report_poll(
    name: str,
    items_processed: int = 0,
    items_failed: int = 0,
    duration_ms: float = 0,
) -> None:
    """Report a successful poll cycle completion.

    Called at the end of each successful poll iteration. Resets
    consecutive_errors to 0 and updates status to "running".

    Args:
        name: Task identifier (must match register_task call).
        items_processed: Number of items successfully processed this cycle.
        items_failed: Number of items that failed processing this cycle.
        duration_ms: Wall-clock time of this poll cycle in milliseconds.
    """
    with _lock:
        task = _tasks.get(name)
        if not task:
            return
        task["last_poll_at"] = now_ts()
        task["last_poll_duration_ms"] = round(duration_ms, 1)
        task["items_processed"] += items_processed
        task["items_failed"] += items_failed
        task["total_polls"] += 1
        task["consecutive_errors"] = 0
        task["status"] = "running"


def report_error(name: str, error: str) -> None:
    """Report a poll cycle error (exception in the main loop).

    Increments consecutive_errors. After 5+ consecutive errors, the
    task status is set to "unhealthy".

    Args:
        name: Task identifier.
        error: Error message string (truncated to 500 chars).
    """
    with _lock:
        task = _tasks.get(name)
        if not task:
            return
        task["consecutive_errors"] += 1
        task["last_error"] = error[:500]
        task["last_error_at"] = now_ts()
        task["total_polls"] += 1
        if task["consecutive_errors"] >= 5:
            task["status"] = "unhealthy"


def get_all_tasks() -> Dict[str, Dict[str, Any]]:
    """Get snapshot of all registered tasks with staleness detection.

    A task is marked "stale" if:
    - It has polled at least once (last_poll_at is set)
    - No poll in 3x the expected interval
    - It was previously "running"

    Returns a deep copy to prevent mutation.
    """
    with _lock:
        now = now_ts()
        result = {}
        for name, task in _tasks.items():
            t = dict(task)
            # Staleness detection
            if (
                t["enabled"]
                and t["last_poll_at"]
                and t["poll_interval_seconds"]
                and t["status"] == "running"
            ):
                stale_threshold = t["poll_interval_seconds"] * 3
                if now - t["last_poll_at"] > stale_threshold:
                    t["status"] = "stale"
                    t["stale_seconds"] = now - t["last_poll_at"]
            result[name] = t
        return result


def get_task(name: str) -> Optional[Dict[str, Any]]:
    """Get a single task's status."""
    with _lock:
        task = _tasks.get(name)
        if not task:
            return None
        t = dict(task)
        # Apply staleness check
        if (
            t["enabled"]
            and t["last_poll_at"]
            and t["poll_interval_seconds"]
            and t["status"] == "running"
        ):
            stale_threshold = t["poll_interval_seconds"] * 3
            if now_ts() - t["last_poll_at"] > stale_threshold:
                t["status"] = "stale"
                t["stale_seconds"] = now_ts() - t["last_poll_at"]
        return t


def reset_registry() -> None:
    """Clear all registered tasks. For testing only."""
    with _lock:
        _tasks.clear()
```

### 4.2 Backend: Instrument Background Tasks

Each of the 11+ background tasks needs three lines added:

1. `register_task()` call before the loop starts
2. `report_poll()` call at the end of each successful iteration
3. `report_error()` call in the exception handler

**`app/services/unified_scheduler.py`** -- instrumented version:

```python
import time
from app.services.job_registry import register_task, report_poll, report_error

async def run_unified_scheduler_loop() -> None:
    if not S.unified_scheduler_enabled:
        register_task("unified_scheduler", S.unified_scheduler_poll_interval_seconds,
                      enabled=False, description="Processes scheduled posts, file shares, and catalog sales")
        return

    poll_interval = S.unified_scheduler_poll_interval_seconds
    register_task("unified_scheduler", poll_interval, enabled=True,
                  description="Processes scheduled posts, file shares, and catalog sales")

    while True:
        start = time.perf_counter()
        processed = 0
        failed = 0
        try:
            now = now_ts()
            due_actions = query_due_actions(now=now, limit=MAX_BATCH_SIZE)
            for action in due_actions:
                try:
                    await _process_action(action, now)
                    processed += 1
                except Exception:
                    failed += 1
                    logger.exception("Action processing failed: %s", action.get("action_id", "?"))

            # Reminders (existing code)
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

            duration_ms = (time.perf_counter() - start) * 1000
            report_poll("unified_scheduler", items_processed=processed,
                       items_failed=failed, duration_ms=duration_ms)

        except Exception as exc:
            report_error("unified_scheduler", str(exc))
            logger.exception("Unified scheduler loop error")

        await asyncio.sleep(poll_interval)
```

**`app/services/webhook_dispatcher.py`** -- instrumented version:

```python
import time
from app.services.job_registry import register_task, report_poll, report_error

async def run_webhook_dispatcher_loop() -> None:
    poll_interval = S.webhooks_dispatcher_poll_interval or POLL_INTERVAL_SECONDS
    register_task("webhook_dispatcher", poll_interval, enabled=True,
                  description="Delivers pending webhook notifications to user endpoints")

    while True:
        start = time.perf_counter()
        processed = 0
        failed = 0
        try:
            now = now_ts()
            due_pending = query_due_deliveries(status="pending", now=now, limit=MAX_BATCH_SIZE)
            due_retry = query_due_deliveries(status="failed", now=now, limit=MAX_BATCH_SIZE)
            due = due_pending + due_retry

            for delivery in due:
                try:
                    # ... existing delivery logic ...
                    if result["success"]:
                        mark_delivery_success(delivery, result)
                        reset_endpoint_failure_count(endpoint_id, user_sub)
                        processed += 1
                    else:
                        handle_delivery_failure(delivery, endpoint, result)
                        failed += 1
                except Exception:
                    failed += 1
                    logger.exception("Webhook delivery error for %s", delivery.get("delivery_id", ""))

            duration_ms = (time.perf_counter() - start) * 1000
            report_poll("webhook_dispatcher", items_processed=processed,
                       items_failed=failed, duration_ms=duration_ms)

        except Exception as exc:
            report_error("webhook_dispatcher", str(exc))
            logger.exception("Webhook dispatcher loop error")

        await asyncio.sleep(poll_interval)

async def start_webhook_dispatcher_task() -> None:
    if S.webhooks_enabled:
        asyncio.create_task(run_webhook_dispatcher_loop())
    else:
        register_task("webhook_dispatcher", POLL_INTERVAL_SECONDS, enabled=False,
                      description="Delivers pending webhook notifications")
```

Apply the same pattern to all remaining background tasks. Each needs:

```python
# At task start:
register_task("<name>", poll_interval, enabled=<flag>, description="...")

# End of successful poll:
report_poll("<name>", items_processed=N, items_failed=M, duration_ms=D)

# In exception handler:
report_error("<name>", str(exc))
```

**Task registration map (all 12 tasks)**:

| Task Name | Source File | Enabled Flag |
|-----------|------------|-------------|
| `unified_scheduler` | `unified_scheduler.py` | `S.unified_scheduler_enabled` |
| `webhook_dispatcher` | `webhook_dispatcher.py` | `S.webhooks_enabled` |
| `billing_dunning` | `billing_dunning.py` | Configurable |
| `billing_reconcile` | `billing_reconcile.py` | Configurable |
| `filemgr_purge` | `filemanager.py` | Configurable |
| `filemgr_mount_reconcile` | `filemanager_mount_reconcile.py` | Configurable |
| `scheduled_messages` | `messaging.py` (routers) | Configurable |
| `broadcast_scheduler` | `broadcast_scheduler.py` | Configurable |
| `broadcast_reminder` | `broadcast_scheduler.py` | Configurable |
| `broadcast_reconciler` | `broadcast_reconciler.py` | Configurable |
| `transcode_worker` | `transcode_worker.py` | Configurable |
| `projects_reconcile` | `projects_reconcile.py` | Configurable |

### 4.3 Backend: Admin Job Status API

**New file: `app/routers/admin_jobs.py`**

```python
"""Admin background job monitoring endpoints (PLATFORM-008)."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth.deps import require_admin_session
from app.core.time import now_ts
from app.services.job_registry import get_all_tasks, get_task

router = APIRouter(prefix="/ui/admin/jobs", tags=["admin-jobs"])


@router.get("/status")
async def job_status(_=Depends(require_admin_session)):
    """Get health status of all background tasks + queue depths.

    curl -s -b cookies.txt -H "x-csrf-token: $CSRF" \\
      http://localhost:8000/ui/admin/jobs/status
    """
    tasks = get_all_tasks()

    # Enrich with queue depths from DDB
    now = now_ts()

    # Scheduled actions queue
    try:
        from app.services.scheduled_actions import count_pending_actions, count_failed_actions
        pending_actions = count_pending_actions()
        failed_actions = count_failed_actions()
    except Exception:
        pending_actions = -1
        failed_actions = -1

    # Webhook delivery queue
    try:
        from app.services.webhook_service import admin_get_health_summary
        webhook_health = admin_get_health_summary()
    except Exception:
        webhook_health = {}

    return {
        "tasks": tasks,
        "queues": {
            "scheduled_actions": {
                "pending": pending_actions,
                "failed": failed_actions,
            },
            "webhook_deliveries": {
                "pending": webhook_health.get("failed_count_24h", 0),
                "dead_letter": webhook_health.get("dead_letter_count_24h", 0),
                "success_24h": webhook_health.get("success_count_24h", 0),
                "total_endpoints": webhook_health.get("total_endpoints", 0),
                "enabled_endpoints": webhook_health.get("enabled_endpoints", 0),
            },
        },
        "timestamp": now,
    }


@router.get("/task/{task_name}")
async def job_task_detail(task_name: str, _=Depends(require_admin_session)):
    """Get detailed status of a specific background task.

    curl -s -b cookies.txt -H "x-csrf-token: $CSRF" \\
      http://localhost:8000/ui/admin/jobs/task/unified_scheduler
    """
    task = get_task(task_name)
    if not task:
        raise HTTPException(status_code=404, detail=f"Task '{task_name}' not found")
    return task


@router.get("/failed")
async def failed_jobs(
    limit: int = Query(default=50, ge=1, le=200),
    action_type: Optional[str] = Query(default=None),
    _=Depends(require_admin_session),
):
    """List failed scheduled actions across all users.

    curl -s -b cookies.txt -H "x-csrf-token: $CSRF" \\
      http://localhost:8000/ui/admin/jobs/failed?limit=50

    curl -s -b cookies.txt -H "x-csrf-token: $CSRF" \\
      http://localhost:8000/ui/admin/jobs/failed?action_type=post
    """
    from app.services.scheduled_actions import query_failed_actions
    items = query_failed_actions(limit=limit, action_type=action_type)
    return {"items": items, "count": len(items)}


@router.post("/retry/{action_id}")
async def retry_failed_job(
    action_id: str,
    user_sub: str = Query(...),
    _=Depends(require_admin_session),
):
    """Retry a permanently failed action (admin override).

    Reschedules the action back to pending state with retry_count=0
    and a new due time (now + 5 seconds).

    curl -s -X POST -b cookies.txt -H "x-csrf-token: $CSRF" \\
      "http://localhost:8000/ui/admin/jobs/retry/sa_abc123?user_sub=alice@test.local"
    """
    from app.services.scheduled_actions import reschedule_failed_action
    result = reschedule_failed_action(user_sub, action_id)
    if not result:
        raise HTTPException(status_code=404, detail="Action not found or not in failed state")
    return {"ok": True, "action_id": action_id, "status": "rescheduled"}


@router.get("/stats")
async def job_stats(
    days: int = Query(default=7, ge=1, le=90),
    _=Depends(require_admin_session),
):
    """Get aggregate job execution stats for the last N days.

    curl -s -b cookies.txt -H "x-csrf-token: $CSRF" \\
      http://localhost:8000/ui/admin/jobs/stats?days=7
    """
    from app.services.scheduled_actions import query_action_stats
    return query_action_stats(days=days)
```

### 4.4 Backend: Add Query Functions for Admin

**File: `app/services/scheduled_actions.py`** -- Add admin query functions (after the existing scheduler query functions at line 442+):

```python
# ─── Admin query functions (PLATFORM-008) ────────────────────────


def query_failed_actions(
    limit: int = 50, action_type: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Query failed actions across all users (admin endpoint).

    Uses a table scan with FilterExpression. This is acceptable because:
    - Failed actions are rare (< 1% of total)
    - The scan is admin-only and infrequent
    - Items expire via TTL after scheduled_actions_ttl_days
    """
    filter_expr = Attr("status").eq("failed")
    if action_type:
        filter_expr = filter_expr & Attr("action_type").eq(action_type)

    try:
        resp = T.scheduled_actions.scan(
            FilterExpression=filter_expr,
            Limit=limit,
        )
        items = resp.get("Items", [])
        return [_action_out(item) for item in items]
    except Exception:
        logger.exception("Failed to query failed actions")
        return []


def count_pending_actions() -> int:
    """Count pending actions in the due queue.

    Queries the ByDue GSI with a far-future cutoff to get all pending items.
    Uses SELECT COUNT to minimize read capacity.
    """
    try:
        from app.core.time import now_ts
        far_future = now_ts() + 365 * 86400  # 1 year ahead
        resp = T.scheduled_actions.query(
            IndexName="ByDue",
            KeyConditionExpression=Key("GSI_DUE_PK").eq("DUE") & Key("GSI_DUE_SK").lte(far_future),
            FilterExpression=Attr("status").eq("pending"),
            Select="COUNT",
        )
        count = resp.get("Count", 0)
        # Handle pagination
        while resp.get("LastEvaluatedKey"):
            resp = T.scheduled_actions.query(
                IndexName="ByDue",
                KeyConditionExpression=Key("GSI_DUE_PK").eq("DUE") & Key("GSI_DUE_SK").lte(far_future),
                FilterExpression=Attr("status").eq("pending"),
                Select="COUNT",
                ExclusiveStartKey=resp["LastEvaluatedKey"],
            )
            count += resp.get("Count", 0)
        return count
    except Exception:
        return -1


def count_failed_actions() -> int:
    """Count permanently failed actions."""
    try:
        resp = T.scheduled_actions.scan(
            FilterExpression=Attr("status").eq("failed"),
            Select="COUNT",
        )
        count = resp.get("Count", 0)
        while resp.get("LastEvaluatedKey"):
            resp = T.scheduled_actions.scan(
                FilterExpression=Attr("status").eq("failed"),
                Select="COUNT",
                ExclusiveStartKey=resp["LastEvaluatedKey"],
            )
            count += resp.get("Count", 0)
        return count
    except Exception:
        return -1


def reschedule_failed_action(user_sub: str, action_id: str) -> bool:
    """Reschedule a permanently failed action (admin retry).

    Finds the action by scanning the user's items (since we don't
    know the SK without the scheduled_at). Resets status to pending,
    retry_count to 0, and sets a new due time (now + 5s).
    """
    from app.core.time import now_ts
    try:
        resp = T.scheduled_actions.query(
            KeyConditionExpression=Key("pk").eq(_pk(user_sub)),
            FilterExpression=Attr("action_id").eq(action_id) & Attr("status").eq("failed"),
            Limit=1,
        )
        items = resp.get("Items", [])
        if not items:
            return False

        action = items[0]
        now = now_ts()

        T.scheduled_actions.update_item(
            Key={"pk": action["pk"], "sk": action["sk"]},
            UpdateExpression=(
                "SET #status = :pending, retry_count = :z, "
                "GSI_DUE_PK = :duekey, GSI_DUE_SK = :dueat, "
                "updated_at = :now "
                "REMOVE #error, completed_at"
            ),
            ExpressionAttributeNames={"#status": "status", "#error": "error"},
            ExpressionAttributeValues={
                ":pending": "pending",
                ":z": 0,
                ":duekey": "DUE",
                ":dueat": now + 5,  # Due in 5 seconds
                ":now": now,
            },
        )
        logger.info("Admin rescheduled failed action: user=%s, action=%s", user_sub, action_id)
        return True
    except Exception:
        logger.exception("Failed to reschedule action: user=%s, action=%s", user_sub, action_id)
        return False


def query_action_stats(days: int = 7) -> Dict[str, Any]:
    """Get aggregate action execution stats for the last N days.

    Scans the scheduled_actions table (filtered by updated_at).
    Returns totals and per-type breakdowns.
    """
    from app.core.time import now_ts
    cutoff = now_ts() - days * 86400

    completed = 0
    failed = 0
    pending = 0
    cancelled = 0
    by_type: Dict[str, Dict[str, int]] = {}

    try:
        last_key = None
        while True:
            kwargs: Dict[str, Any] = {
                "FilterExpression": Attr("updated_at").gte(cutoff),
                "Limit": 2000,
            }
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key

            resp = T.scheduled_actions.scan(**kwargs)
            for item in resp.get("Items", []):
                status = item.get("status", "")
                action_type = item.get("action_type", "unknown")

                if action_type not in by_type:
                    by_type[action_type] = {"completed": 0, "failed": 0, "pending": 0, "cancelled": 0}

                if status == "completed":
                    completed += 1
                    by_type[action_type]["completed"] += 1
                elif status == "failed":
                    failed += 1
                    by_type[action_type]["failed"] += 1
                elif status == "pending":
                    pending += 1
                    by_type[action_type]["pending"] += 1
                elif status == "cancelled":
                    cancelled += 1
                    by_type[action_type]["cancelled"] += 1

            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
    except Exception:
        logger.exception("Failed to query action stats")

    total = completed + failed + pending + cancelled
    return {
        "period_days": days,
        "total": total,
        "total_completed": completed,
        "total_failed": failed,
        "total_pending": pending,
        "total_cancelled": cancelled,
        "success_rate": round(completed / max(completed + failed, 1) * 100, 1),
        "by_type": by_type,
    }
```

### 4.5 Backend: Pydantic Models

**File: `app/models.py`** -- Add response models:

```python
# ─── Job Dashboard (PLATFORM-008) ────────────────────────────────

class JobTaskStatus(BaseModel):
    name: str
    description: Optional[str] = None
    poll_interval_seconds: int
    enabled: bool
    started_at: Optional[int] = None
    last_poll_at: Optional[int] = None
    last_poll_duration_ms: Optional[float] = None
    items_processed: int = 0
    items_failed: int = 0
    total_polls: int = 0
    consecutive_errors: int = 0
    last_error: Optional[str] = None
    last_error_at: Optional[int] = None
    status: str  # "running", "disabled", "stale", "unhealthy"


class JobQueueDepths(BaseModel):
    scheduled_actions: dict
    webhook_deliveries: dict


class JobStatusResponse(BaseModel):
    tasks: Dict[str, JobTaskStatus]
    queues: JobQueueDepths
    timestamp: int


class FailedActionItem(BaseModel):
    action_id: str
    action_type: str
    user_sub: str
    title: Optional[str] = None
    error: Optional[str] = None
    scheduled_at: Optional[int] = None
    completed_at: Optional[int] = None
    retry_count: Optional[int] = None


class FailedActionsResponse(BaseModel):
    items: List[FailedActionItem]
    count: int


class JobActionStats(BaseModel):
    period_days: int
    total: int
    total_completed: int
    total_failed: int
    total_pending: int
    total_cancelled: int
    success_rate: float
    by_type: Dict[str, Dict[str, int]]
```

### 4.6 Backend: Prometheus Metrics

**File: `app/metrics.py`** -- Add job-related metrics:

```python
# Background job metrics (PLATFORM-008)
JOB_POLL_DURATION = Histogram(
    "job_poll_duration_seconds",
    "Background task poll duration in seconds",
    ["task_name"],
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30),
)
JOB_ITEMS_PROCESSED = Counter(
    "job_items_processed_total",
    "Total items processed by background tasks",
    ["task_name"],
)
JOB_ITEMS_FAILED = Counter(
    "job_items_failed_total",
    "Total items that failed processing in background tasks",
    ["task_name"],
)
JOB_POLL_ERRORS = Counter(
    "job_poll_errors_total",
    "Total poll cycle errors in background tasks",
    ["task_name"],
)
```

### 4.7 Backend: Register Router

**File: `app/main.py`**:

```python
from app.routers.admin_jobs import router as admin_jobs_router
app.include_router(admin_jobs_router)
```

### 4.8 Frontend: TypeScript Types

**File: `frontend/src/api/types.ts`**:

```typescript
// ─── Job Dashboard (PLATFORM-008) ───────────────────────────────

export interface JobTaskStatus {
  name: string;
  description?: string;
  poll_interval_seconds: number;
  enabled: boolean;
  started_at: number | null;
  last_poll_at: number | null;
  last_poll_duration_ms: number | null;
  items_processed: number;
  items_failed: number;
  total_polls: number;
  consecutive_errors: number;
  last_error: string | null;
  last_error_at: number | null;
  status: "running" | "disabled" | "stale" | "unhealthy";
}

export interface JobQueueDepths {
  scheduled_actions: {
    pending: number;
    failed: number;
  };
  webhook_deliveries: {
    pending: number;
    dead_letter: number;
    success_24h: number;
    total_endpoints: number;
    enabled_endpoints: number;
  };
}

export interface JobStatusResponse {
  tasks: Record<string, JobTaskStatus>;
  queues: JobQueueDepths;
  timestamp: number;
}

export interface FailedActionItem {
  action_id: string;
  action_type: string;
  user_sub: string;
  title?: string;
  error?: string;
  scheduled_at?: number;
  completed_at?: number;
  retry_count?: number;
}

export interface JobActionStats {
  period_days: number;
  total: number;
  total_completed: number;
  total_failed: number;
  total_pending: number;
  total_cancelled: number;
  success_rate: number;
  by_type: Record<string, Record<string, number>>;
}
```

### 4.9 Frontend: API Endpoints

**New file: `frontend/src/api/endpoints/admin-jobs.ts`**

```typescript
import { api } from "@/api/client";
import type {
  JobStatusResponse,
  FailedActionItem,
  JobActionStats,
  JobTaskStatus,
} from "@/api/types";

export const getJobStatus = () =>
  api.get<JobStatusResponse>("/ui/admin/jobs/status");

export const getJobTaskDetail = (taskName: string) =>
  api.get<JobTaskStatus>(`/ui/admin/jobs/task/${taskName}`);

export const getFailedJobs = (limit = 50, actionType?: string) =>
  api.get<{ items: FailedActionItem[]; count: number }>(
    `/ui/admin/jobs/failed?limit=${limit}${actionType ? `&action_type=${actionType}` : ""}`
  );

export const retryFailedJob = (actionId: string, userSub: string) =>
  api.post(`/ui/admin/jobs/retry/${actionId}?user_sub=${encodeURIComponent(userSub)}`);

export const getJobStats = (days = 7) =>
  api.get<JobActionStats>(`/ui/admin/jobs/stats?days=${days}`);
```

### 4.10 Frontend: Admin Job Dashboard Page

**New file: `frontend/src/pages/admin/JobDashboardPage.tsx`**

```tsx
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Card, CardContent, CardHeader, CardTitle, CardDescription,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  RefreshCw, AlertTriangle, CheckCircle, Clock, XCircle, Activity,
} from "lucide-react";
import { toast } from "sonner";
import {
  getJobStatus,
  getFailedJobs,
  retryFailedJob,
  getJobStats,
} from "@/api/endpoints/admin-jobs";
import type { JobTaskStatus, FailedActionItem } from "@/api/types";

function statusBadge(status: string) {
  switch (status) {
    case "running":
      return <Badge className="bg-green-500 text-white">Running</Badge>;
    case "disabled":
      return <Badge variant="secondary">Disabled</Badge>;
    case "stale":
      return <Badge variant="destructive">Stale</Badge>;
    case "unhealthy":
      return <Badge variant="destructive">Unhealthy</Badge>;
    default:
      return <Badge variant="outline">{status}</Badge>;
  }
}

function formatDuration(ms: number | null): string {
  if (ms === null) return "—";
  if (ms < 1) return "<1ms";
  if (ms < 1000) return `${Math.round(ms)}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function formatTimestamp(ts: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleTimeString();
}

export default function JobDashboardPage() {
  const qc = useQueryClient();

  const statusQ = useQuery({
    queryKey: ["admin", "jobs", "status"],
    queryFn: getJobStatus,
    refetchInterval: 15_000, // Auto-refresh every 15s
  });

  const failedQ = useQuery({
    queryKey: ["admin", "jobs", "failed"],
    queryFn: () => getFailedJobs(50),
  });

  const statsQ = useQuery({
    queryKey: ["admin", "jobs", "stats"],
    queryFn: () => getJobStats(7),
  });

  const retryMut = useMutation({
    mutationFn: (params: { actionId: string; userSub: string }) =>
      retryFailedJob(params.actionId, params.userSub),
    onSuccess: () => {
      toast.success("Job rescheduled for retry");
      qc.invalidateQueries({ queryKey: ["admin", "jobs"] });
    },
    onError: () => toast.error("Failed to retry job"),
  });

  const tasks = statusQ.data?.tasks ?? {};
  const queues = statusQ.data?.queues ?? { scheduled_actions: {}, webhook_deliveries: {} };
  const stats = statsQ.data;

  const runningCount = Object.values(tasks).filter((t: any) => t.status === "running").length;
  const unhealthyCount = Object.values(tasks).filter(
    (t: any) => t.status === "stale" || t.status === "unhealthy"
  ).length;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Background Jobs</h1>
          <p className="text-sm text-muted-foreground">
            {runningCount} running, {unhealthyCount} need attention
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => qc.invalidateQueries({ queryKey: ["admin", "jobs"] })}
        >
          <RefreshCw className="h-4 w-4 mr-2" /> Refresh
        </Button>
      </div>

      {/* Queue Depth Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-2">
              <Clock className="h-4 w-4 text-blue-500" />
              <p className="text-sm text-muted-foreground">Pending Actions</p>
            </div>
            <p className="text-2xl font-bold">
              {queues.scheduled_actions?.pending ?? "?"}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-2">
              <XCircle className="h-4 w-4 text-red-500" />
              <p className="text-sm text-muted-foreground">Failed Actions</p>
            </div>
            <p className="text-2xl font-bold text-destructive">
              {queues.scheduled_actions?.failed ?? "?"}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-2">
              <CheckCircle className="h-4 w-4 text-green-500" />
              <p className="text-sm text-muted-foreground">Webhook Success (24h)</p>
            </div>
            <p className="text-2xl font-bold">
              {queues.webhook_deliveries?.success_24h ?? "?"}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-amber-500" />
              <p className="text-sm text-muted-foreground">Webhook Dead Letters</p>
            </div>
            <p className="text-2xl font-bold text-destructive">
              {queues.webhook_deliveries?.dead_letter ?? "?"}
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Execution Stats (7-day) */}
      {stats && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Activity className="h-5 w-5" /> Execution Stats (Last {stats.period_days} Days)
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-4 gap-4 text-center">
              <div>
                <p className="text-2xl font-bold">{stats.total_completed}</p>
                <p className="text-sm text-muted-foreground">Completed</p>
              </div>
              <div>
                <p className="text-2xl font-bold text-destructive">{stats.total_failed}</p>
                <p className="text-sm text-muted-foreground">Failed</p>
              </div>
              <div>
                <p className="text-2xl font-bold">{stats.total_pending}</p>
                <p className="text-sm text-muted-foreground">Pending</p>
              </div>
              <div>
                <p className="text-2xl font-bold">{stats.success_rate}%</p>
                <p className="text-sm text-muted-foreground">Success Rate</p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Task List Table */}
      <Card>
        <CardHeader>
          <CardTitle>Background Tasks</CardTitle>
          <CardDescription>
            Real-time health status of all background polling tasks
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b text-left">
                  <th className="py-2 pr-4">Task</th>
                  <th className="pr-4">Status</th>
                  <th className="pr-4">Interval</th>
                  <th className="pr-4">Last Poll</th>
                  <th className="pr-4">Duration</th>
                  <th className="pr-4">Processed</th>
                  <th className="pr-4">Failed</th>
                  <th className="pr-4">Polls</th>
                  <th>Last Error</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(tasks)
                  .sort(([, a]: any, [, b]: any) => {
                    // Sort: unhealthy/stale first, then running, then disabled
                    const order: Record<string, number> = { unhealthy: 0, stale: 1, running: 2, disabled: 3 };
                    return (order[a.status] ?? 4) - (order[b.status] ?? 4);
                  })
                  .map(([name, task]: [string, any]) => (
                    <tr key={name} className="border-b hover:bg-muted/50">
                      <td className="py-2 pr-4">
                        <span className="font-mono text-xs">{name}</span>
                        {task.description && (
                          <p className="text-xs text-muted-foreground mt-0.5 max-w-xs truncate">
                            {task.description}
                          </p>
                        )}
                      </td>
                      <td className="pr-4">{statusBadge(task.status)}</td>
                      <td className="pr-4 text-xs">{task.poll_interval_seconds}s</td>
                      <td className="pr-4 text-xs">{formatTimestamp(task.last_poll_at)}</td>
                      <td className="pr-4 text-xs">{formatDuration(task.last_poll_duration_ms)}</td>
                      <td className="pr-4">{task.items_processed.toLocaleString()}</td>
                      <td className={`pr-4 ${task.items_failed > 0 ? "text-destructive font-medium" : ""}`}>
                        {task.items_failed}
                      </td>
                      <td className="pr-4 text-xs text-muted-foreground">{task.total_polls.toLocaleString()}</td>
                      <td className="max-w-xs truncate text-xs text-muted-foreground">
                        {task.last_error || "—"}
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>

      {/* Failed Jobs Table */}
      <Card>
        <CardHeader>
          <CardTitle>Failed Jobs</CardTitle>
          <CardDescription>
            Permanently failed scheduled actions across all users
          </CardDescription>
        </CardHeader>
        <CardContent>
          {failedQ.data?.items?.length === 0 ? (
            <div className="flex items-center gap-2 text-muted-foreground text-sm py-4">
              <CheckCircle className="h-4 w-4 text-green-500" />
              No failed jobs
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left">
                    <th className="py-2 pr-4">Action ID</th>
                    <th className="pr-4">Type</th>
                    <th className="pr-4">User</th>
                    <th className="pr-4">Error</th>
                    <th className="pr-4">Retries</th>
                    <th className="pr-4">Failed At</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {failedQ.data?.items?.map((item: FailedActionItem) => (
                    <tr key={item.action_id} className="border-b">
                      <td className="py-2 pr-4 font-mono text-xs">{item.action_id}</td>
                      <td className="pr-4">
                        <Badge variant="outline">{item.action_type}</Badge>
                      </td>
                      <td className="pr-4 text-xs max-w-[120px] truncate">{item.user_sub}</td>
                      <td className="pr-4 max-w-xs truncate text-xs text-destructive">
                        {item.error || "—"}
                      </td>
                      <td className="pr-4 text-xs">{item.retry_count ?? "—"}</td>
                      <td className="pr-4 text-xs">
                        {item.completed_at
                          ? new Date(item.completed_at * 1000).toLocaleString()
                          : "—"}
                      </td>
                      <td>
                        <Button
                          size="sm"
                          variant="outline"
                          disabled={retryMut.isPending}
                          onClick={() =>
                            retryMut.mutate({
                              actionId: item.action_id,
                              userSub: item.user_sub,
                            })
                          }
                        >
                          Retry
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
```

### 4.11 Frontend: Route

**File: `frontend/src/App.tsx`**:

```tsx
const JobDashboardPage = lazy(() => import("@/pages/admin/JobDashboardPage"));
// ...
<Route path="admin/jobs" element={<JobDashboardPage />} />
```

### 4.12 Frontend: Sidebar Link

Add "Background Jobs" link to the admin section of the sidebar, using the `Activity` lucide icon, alongside existing admin links (Moderation, Video Review, DMCA, Refunds, Rate Limits).

---

## 5. API Contract

### 5.1 Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/ui/admin/jobs/status` | `require_admin_session` | All task health + queue depths |
| GET | `/ui/admin/jobs/task/{name}` | `require_admin_session` | Single task detail |
| GET | `/ui/admin/jobs/failed` | `require_admin_session` | Failed scheduled actions (cross-user) |
| POST | `/ui/admin/jobs/retry/{action_id}` | `require_admin_session` | Retry failed action |
| GET | `/ui/admin/jobs/stats` | `require_admin_session` | Aggregate job stats |

### 5.2 GET `/ui/admin/jobs/status` Response

```json
{
  "tasks": {
    "unified_scheduler": {
      "name": "unified_scheduler",
      "description": "Processes scheduled posts, file shares, and catalog sales",
      "status": "running",
      "poll_interval_seconds": 15,
      "enabled": true,
      "started_at": 1748380800,
      "last_poll_at": 1748381400,
      "last_poll_duration_ms": 45.2,
      "items_processed": 142,
      "items_failed": 3,
      "total_polls": 9400,
      "consecutive_errors": 0,
      "last_error": null,
      "last_error_at": null
    },
    "webhook_dispatcher": {
      "name": "webhook_dispatcher",
      "description": "Delivers pending webhook notifications to user endpoints",
      "status": "running",
      "poll_interval_seconds": 10,
      "enabled": true,
      "started_at": 1748380800,
      "last_poll_at": 1748381398,
      "last_poll_duration_ms": 120.5,
      "items_processed": 891,
      "items_failed": 12,
      "total_polls": 14000,
      "consecutive_errors": 0,
      "last_error": null,
      "last_error_at": null
    },
    "billing_dunning": {
      "name": "billing_dunning",
      "status": "disabled",
      "poll_interval_seconds": 300,
      "enabled": false,
      "started_at": null,
      "last_poll_at": null,
      "items_processed": 0,
      "items_failed": 0,
      "total_polls": 0,
      "consecutive_errors": 0
    }
  },
  "queues": {
    "scheduled_actions": {
      "pending": 5,
      "failed": 2
    },
    "webhook_deliveries": {
      "pending": 0,
      "dead_letter": 3,
      "success_24h": 47,
      "total_endpoints": 12,
      "enabled_endpoints": 10
    }
  },
  "timestamp": 1748381400
}
```

### 5.3 GET `/ui/admin/jobs/failed` Response

```json
{
  "items": [
    {
      "action_id": "sa_abc123def456",
      "action_type": "post",
      "user_sub": "alice@test.local",
      "title": "Scheduled post: Weekend sale",
      "error": "ValueError: invalid post body — missing required field 'content'",
      "scheduled_at": 1748380000,
      "completed_at": 1748380015,
      "retry_count": 3
    }
  ],
  "count": 1
}
```

### 5.4 GET `/ui/admin/jobs/stats` Response

```json
{
  "period_days": 7,
  "total": 156,
  "total_completed": 148,
  "total_failed": 5,
  "total_pending": 3,
  "total_cancelled": 0,
  "success_rate": 96.7,
  "by_type": {
    "post": { "completed": 120, "failed": 3, "pending": 2, "cancelled": 0 },
    "file_share": { "completed": 25, "failed": 1, "pending": 1, "cancelled": 0 },
    "catalog_sale": { "completed": 3, "failed": 1, "pending": 0, "cancelled": 0 }
  }
}
```

### 5.5 curl Examples

```bash
# Get all task statuses and queue depths
curl -s -b cookies.txt -H "x-csrf-token: $CSRF" \
  http://localhost:8000/ui/admin/jobs/status | python3 -m json.tool

# Get single task detail
curl -s -b cookies.txt -H "x-csrf-token: $CSRF" \
  http://localhost:8000/ui/admin/jobs/task/unified_scheduler

# List failed jobs
curl -s -b cookies.txt -H "x-csrf-token: $CSRF" \
  http://localhost:8000/ui/admin/jobs/failed?limit=10

# List failed jobs filtered by type
curl -s -b cookies.txt -H "x-csrf-token: $CSRF" \
  "http://localhost:8000/ui/admin/jobs/failed?action_type=post"

# Retry a failed job
curl -s -X POST -b cookies.txt -H "x-csrf-token: $CSRF" \
  "http://localhost:8000/ui/admin/jobs/retry/sa_abc123?user_sub=alice@test.local"

# Get execution stats (last 30 days)
curl -s -b cookies.txt -H "x-csrf-token: $CSRF" \
  http://localhost:8000/ui/admin/jobs/stats?days=30
```

---

## 6. Health Detection Logic

### 6.1 Task Status States

| Status | Condition | Meaning | Dashboard Color |
|--------|-----------|---------|----------------|
| `running` | Last poll within 3x interval, < 5 consecutive errors | Task operating normally | Green |
| `stale` | No poll in 3x the poll interval | Task may have crashed or is blocked | Red |
| `unhealthy` | 5+ consecutive poll errors | Task running but failing repeatedly | Red |
| `disabled` | Feature flag is off | Task intentionally not started | Gray |

### 6.2 Staleness Detection

Staleness is checked in `get_all_tasks()` and `get_task()`:

```
stale_threshold = poll_interval_seconds * 3

if (now - last_poll_at) > stale_threshold:
    status = "stale"
```

Example: `unified_scheduler` has `poll_interval_seconds=15`. If `last_poll_at` is 50+ seconds ago (3 * 15 + buffer), the task is marked `stale`. This indicates the asyncio coroutine may have:
- Crashed with an unhandled exception that escaped the main try/except
- Been cancelled by uvicorn during a reload
- Become blocked on a long-running DDB scan

### 6.3 Unhealthy Detection

If any task reports 5+ consecutive errors via `report_error()`, it is marked `unhealthy`. The task is still running (it caught the exception and continued the loop) but every poll iteration is failing. Common causes:
- DDB table deleted or permissions changed
- Network partition to DDB endpoint
- Bug in processing logic that fails for all items

### 6.4 Recovery

When a task reports a successful poll via `report_poll()`, `consecutive_errors` is reset to 0 and status returns to `running`. Recovery from `stale` requires the task to actually poll again (which means the coroutine must be alive).

---

## 7. Performance Analysis

### 7.1 Admin Status Endpoint Cost

| Operation | Latency | Notes |
|-----------|---------|-------|
| `get_all_tasks()` (in-memory) | < 0.1ms | Dict copy, no IO |
| `count_pending_actions()` (DDB) | ~10-50ms | ByDue GSI query with COUNT |
| `count_failed_actions()` (DDB) | ~50-200ms | Table scan with filter (infrequent, low volume) |
| `admin_get_health_summary()` (DDB) | ~50-200ms | Table scan with 24h filter |
| **Total** | **~110-450ms** | Acceptable for admin endpoint |

### 7.2 Job Registry Memory

Each task entry is ~500 bytes. With 12 tasks, total registry memory is ~6KB. Negligible.

### 7.3 Instrumentation Overhead

The `register_task`, `report_poll`, and `report_error` calls are protected by a `threading.Lock`. Each call acquires the lock, updates a dict, and releases. Total overhead: < 1 microsecond per poll cycle per task. With 12 tasks polling every 10-30 seconds, this adds < 0.1ms/second of lock contention.

---

## 8. Migration & Rollback

### 8.1 Feature Flags

No new feature flags needed. The admin endpoints are behind `require_admin_session` and the job registry is always active (zero cost when not queried).

### 8.2 Migration Steps

1. **Add job_registry.py**: New file, no dependencies
2. **Instrument tasks**: Add 3 lines to each of the 12 background task files
3. **Add admin_jobs.py router**: Register in main.py
4. **Add scheduled_actions.py functions**: New functions only, no changes to existing
5. **Add frontend page**: New lazy-loaded page + route
6. **Deploy**: Rolling deployment safe -- registry starts empty and fills as tasks poll

### 8.3 Rollback

- Remove the admin router from main.py -- dashboard becomes 404
- Remove instrumentation from tasks -- registry stays empty
- No DDB changes to reverse
- No user-facing impact

---

## 9. Testing Strategy

### 9.1 Unit Tests (pytest)

| # | Test | Assertion |
|---|------|-----------|
| 1 | `register_task` adds task to registry | `get_all_tasks()` includes task with correct fields |
| 2 | `register_task` with enabled=False sets status=disabled | `status == "disabled"` |
| 3 | `report_poll` updates last_poll_at and items_processed | Fields match expected values |
| 4 | `report_poll` increments total_polls | Counter incremented by 1 |
| 5 | `report_error` increments consecutive_errors | Error count incremented |
| 6 | `report_error` stores error message (truncated to 500) | `last_error` set correctly |
| 7 | 5 consecutive errors marks task unhealthy | `status == "unhealthy"` |
| 8 | `report_poll` after errors resets consecutive_errors to 0 | Error count back to 0, status back to running |
| 9 | Stale detection when last_poll exceeds 3x interval | `status == "stale"` |
| 10 | Non-stale task within 2x interval stays running | `status == "running"` |
| 11 | `get_task` returns None for unknown task | Returns None |
| 12 | `reset_registry` clears all tasks | `get_all_tasks()` returns empty dict |
| 13 | `query_failed_actions` returns failed items only | Items all have `status=failed` |
| 14 | `query_failed_actions` filters by action_type | Only matching type returned |
| 15 | `count_pending_actions` returns correct count | Count matches seeded pending items |
| 16 | `count_failed_actions` returns correct count | Count matches seeded failed items |
| 17 | `reschedule_failed_action` resets to pending | Status changed to `pending`, retry_count=0 |
| 18 | `reschedule_failed_action` sets new due time | `GSI_DUE_SK` is now+5 |
| 19 | `reschedule_failed_action` returns False for non-failed action | Cannot reschedule completed action |
| 20 | `reschedule_failed_action` returns False for unknown action | Returns False |
| 21 | `query_action_stats` returns correct aggregates | Completed/failed/pending counts match seed |
| 22 | `query_action_stats` breaks down by type | `by_type` has correct per-type counts |
| 23 | Admin status endpoint requires admin role | 403 for regular user |
| 24 | Admin status endpoint returns tasks and queues | Both keys present in response |
| 25 | Admin retry endpoint reschedules action | Action status changes to pending |
| 26 | Thread safety: concurrent register_task calls | No data corruption |

### 9.2 E2E Tests

**File:** `frontend/e2e/job-dashboard.spec.ts`

**Section 1: Admin Jobs API (7 tests)**

| # | Test Title | Assertion |
|---|------------|-----------|
| 1 | "Job status endpoint returns tasks and queues" | Root GET `/ui/admin/jobs/status`; 200; response has `tasks` object and `queues` object |
| 2 | "Status response includes unified_scheduler task" | `tasks.unified_scheduler` exists with `status` field |
| 3 | "Task detail endpoint returns single task" | GET `/ui/admin/jobs/task/unified_scheduler`; 200; has `name`, `status` |
| 4 | "Task detail returns 404 for unknown task" | GET `/ui/admin/jobs/task/nonexistent`; 404 |
| 5 | "Failed jobs endpoint returns items array" | GET `/ui/admin/jobs/failed`; 200; has `items` and `count` |
| 6 | "Stats endpoint returns period and counts" | GET `/ui/admin/jobs/stats?days=7`; 200; has `period_days`, `total_completed`, `by_type` |
| 7 | "Non-admin user gets 403 on status" | Alice GET `/ui/admin/jobs/status`; 403 |

**Section 2: Retry API (3 tests)**

| # | Test Title | Assertion |
|---|------------|-----------|
| 8 | "Retry endpoint returns 404 for non-existent action" | POST `/ui/admin/jobs/retry/sa_nonexistent?user_sub=alice`; 404 |
| 9 | "Retry endpoint requires user_sub parameter" | POST without user_sub; 422 (validation error) |
| 10 | "Retry endpoint requires admin role" | Alice POST retry; 403 |

**Section 3: Admin UI (7 tests)**

| # | Test Title | Assertion |
|---|------------|-----------|
| 11 | "Job dashboard page loads for admin" | Navigate to `/admin/jobs`; "Background Jobs" heading visible |
| 12 | "Task table shows at least one task" | Table has at least one row |
| 13 | "Task table shows status badges" | At least one "Running" or "Disabled" badge visible |
| 14 | "Queue depth cards display" | "Pending Actions" text visible in card |
| 15 | "Failed actions card shows count" | "Failed Actions" card visible |
| 16 | "Refresh button triggers data reload" | Click Refresh; `waitForResponse` on status endpoint |
| 17 | "Failed jobs section renders" | "Failed Jobs" heading visible |

---

## 10. Acceptance Criteria

1. All 12 background tasks report health to the in-memory job registry via `register_task`, `report_poll`, and `report_error`.
2. `GET /ui/admin/jobs/status` returns all task health statuses and queue depths.
3. `GET /ui/admin/jobs/task/{name}` returns detailed status of a specific task.
4. `GET /ui/admin/jobs/failed` returns a list of permanently failed scheduled actions across all users.
5. `GET /ui/admin/jobs/stats` returns aggregate execution stats with per-type breakdown.
6. `POST /ui/admin/jobs/retry/{action_id}` reschedules a failed action back to pending state.
7. Admin dashboard shows task table with status badges (running/stale/unhealthy/disabled).
8. Dashboard shows queue depth cards for scheduled actions and webhook deliveries.
9. Dashboard shows execution stats (completed/failed/pending/success rate).
10. Dashboard shows failed jobs table with retry button per job.
11. Tasks marked `stale` when no poll in 3x their interval.
12. Tasks marked `unhealthy` after 5+ consecutive errors.
13. Dashboard auto-refreshes every 15 seconds.
14. Prometheus metrics emitted for poll duration, items processed, items failed, poll errors.
15. All admin endpoints require `role >= ADMIN` via `require_admin_session`.

---

## 11. Files to Create

| File | Purpose |
|------|---------|
| `app/services/job_registry.py` | In-memory background job health registry |
| `app/routers/admin_jobs.py` | Admin job monitoring endpoints |
| `frontend/src/api/endpoints/admin-jobs.ts` | Admin jobs API client |
| `frontend/src/pages/admin/JobDashboardPage.tsx` | Admin job dashboard page |
| `frontend/e2e/job-dashboard.spec.ts` | E2E tests |

## 12. Files to Modify

| File | Change |
|------|--------|
| `app/services/unified_scheduler.py:33-65` | Add `register_task`, `report_poll`, `report_error` calls |
| `app/services/webhook_dispatcher.py:26-70` | Add `register_task`, `report_poll`, `report_error` calls |
| `app/services/billing_dunning.py` | Add job registry reporting (3 lines) |
| `app/services/billing_reconcile.py` | Add job registry reporting (3 lines) |
| `app/services/filemanager.py` | Add job registry reporting to purge task (3 lines) |
| `app/services/filemanager_mount_reconcile.py` | Add job registry reporting (3 lines) |
| `app/services/broadcast_scheduler.py` | Add job registry reporting (3 lines each for scheduler + reminder) |
| `app/services/broadcast_reconciler.py` | Add job registry reporting (3 lines) |
| `app/services/transcode_worker.py` | Add job registry reporting (3 lines) |
| `app/services/projects_reconcile.py` | Add job registry reporting (3 lines) |
| `app/routers/messaging.py` | Add job registry reporting to scheduled_messages task (3 lines) |
| `app/services/scheduled_actions.py` (after line 442) | Add `query_failed_actions`, `count_pending_actions`, `count_failed_actions`, `reschedule_failed_action`, `query_action_stats` |
| `app/models.py` | Add `JobTaskStatus`, `JobQueueDepths`, `JobStatusResponse`, `FailedActionItem`, `FailedActionsResponse`, `JobActionStats` |
| `app/metrics.py` | Add `JOB_POLL_DURATION`, `JOB_ITEMS_PROCESSED`, `JOB_ITEMS_FAILED`, `JOB_POLL_ERRORS` |
| `app/main.py` | Register `admin_jobs_router` |
| `frontend/src/api/types.ts` | Add `JobTaskStatus`, `JobQueueDepths`, `JobStatusResponse`, `FailedActionItem`, `JobActionStats` interfaces |
| `frontend/src/App.tsx` | Add `/admin/jobs` route |

---

## 13. Dependencies

- **None new**. Uses in-memory state (no new DDB tables) and existing `scheduled_actions` + `webhook_deliveries` tables for admin queries.
- The `admin_get_health_summary()` function in `webhook_service.py:717-761` is already available and is reused for webhook queue depth information.

---

## Appendix A: Codebase Citations

| Claim | File | Line(s) | Status |
|-------|------|---------|--------|
| 12 background tasks in main.py | `app/main.py` | 348-421 | VERIFIED |
| Unified scheduler loop | `app/services/unified_scheduler.py` | 33-65 | VERIFIED |
| Unified scheduler startup handler | `app/services/unified_scheduler.py` | 128-131 | VERIFIED |
| `_EXECUTORS` map (3 types: post, file_share, catalog_sale) | `app/services/unified_scheduler.py` | 26-30 | VERIFIED |
| `MAX_BATCH_SIZE = 25` (scheduler) | `app/services/unified_scheduler.py` | 24 | VERIFIED |
| `_process_action` with claim/execute/complete/fail/retry | `app/services/unified_scheduler.py` | 68-98 | VERIFIED |
| `_send_reminder` with write_alert | `app/services/unified_scheduler.py` | 101-125 | VERIFIED |
| Webhook dispatcher loop | `app/services/webhook_dispatcher.py` | 26-64 | VERIFIED |
| Webhook dispatcher startup | `app/services/webhook_dispatcher.py` | 67-70 | VERIFIED |
| Webhook `MAX_BATCH_SIZE = 50` | `app/services/webhook_dispatcher.py` | 23 | VERIFIED |
| Webhook `POLL_INTERVAL_SECONDS = 10` | `app/services/webhook_dispatcher.py` | 22 | VERIFIED |
| Scheduled actions DDB schema (PK/SK/GSI) | `app/services/scheduled_actions.py` | 1-9 | VERIFIED |
| Scheduled actions DDB init (ByDue, ByType GSIs) | `scripts/local-ddb-init.py` | 884-893 | VERIFIED |
| `_new_action_id()` format | `app/services/scheduled_actions.py` | 30-31 | VERIFIED |
| `_pk(user_sub)` format | `app/services/scheduled_actions.py` | 34-35 | VERIFIED |
| `_sk(scheduled_at, action_id)` format | `app/services/scheduled_actions.py` | 38-39 | VERIFIED |
| `query_due_actions` ByDue GSI query | `app/services/scheduled_actions.py` | 355-363 | VERIFIED |
| `query_upcoming_reminders` | `app/services/scheduled_actions.py` | 366-374 | VERIFIED |
| `claim_action` conditional update | `app/services/scheduled_actions.py` | 377-396 | VERIFIED |
| `mark_action_completed` REMOVE GSI keys | `app/services/scheduled_actions.py` | 399-410 | VERIFIED |
| `mark_action_failed` stores error, REMOVEs GSI keys | `app/services/scheduled_actions.py` | 413-425 | VERIFIED |
| `schedule_retry` sets new GSI_DUE_SK | `app/services/scheduled_actions.py` | 428-442 | VERIFIED |
| `mark_reminder_sent` conditional update | `app/services/scheduled_actions.py` | 445-452 | VERIFIED |
| User-facing scheduler router (CRUD + calendar) | `app/routers/scheduler.py` | 45-148 | VERIFIED |
| Webhook admin health summary (table scan) | `app/services/webhook_service.py` | 717-761 | VERIFIED |
| Webhook admin dead letters | `app/services/webhook_service.py` | 791-812 | VERIFIED |
| Webhook admin endpoints (4 routes) | `app/routers/webhooks.py` | 182-215 | VERIFIED |
| `query_due_deliveries` (ByStatus GSI) | `app/services/webhook_service.py` | 815-822 | VERIFIED |
| Webhook deliveries DDB init (ByStatus, ByUser GSIs) | `scripts/local-ddb-init.py` | 862-871 | VERIFIED |
| Scheduler poll interval setting (15s) | `app/core/settings.py` | 1327 | VERIFIED |
| `scheduled_actions_max_retries` (3) | `app/core/settings.py` | 1330 | VERIFIED |
| `scheduled_actions_ttl_days` (90) | `app/core/settings.py` | 1331 | VERIFIED |
| `webhooks_max_retries` (5) | `app/core/settings.py` | 1307 | VERIFIED |
| Prometheus counter/gauge/histogram pattern | `app/metrics.py` | 57-105 | VERIFIED |
| Noop metric pattern in non-production | `app/metrics.py` | 26-55 | VERIFIED |
