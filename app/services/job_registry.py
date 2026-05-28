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
