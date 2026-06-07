"""Regression test for GAP-0137.

`start_bot_scheduler_task` calls `asyncio.create_task()`, which requires a
running event loop. As a synchronous `def`, calling it from a sync context
(unit test, CLI tool, or an ASGI server that invokes sync startup handlers
outside a loop) raises ``RuntimeError: no running event loop``.

The fix makes `start_bot_scheduler_task` an `async def` so Starlette awaits it
(guaranteeing a running loop) and so it can be safely awaited from any sync
context via ``asyncio.run``.

Fails-before / passes-after:
  - Before fix: the function is a plain ``def``; ``iscoroutinefunction`` is
    False and calling it from a sync context with the feature enabled raises
    RuntimeError.
  - After fix: the function is ``async def``; awaiting it under
    ``asyncio.run`` creates the background task without raising.

Offline: no real AWS — the background loop coroutine is patched out.
"""
import asyncio
import inspect
from unittest.mock import patch

from app.services import bot_scheduler


def test_start_bot_scheduler_task_is_async():
    """GAP-0137: starter must be a coroutine function so Starlette awaits it."""
    assert inspect.iscoroutinefunction(bot_scheduler.start_bot_scheduler_task), (
        "start_bot_scheduler_task must be an async def so asyncio.create_task() "
        "runs inside a running event loop (GAP-0137)."
    )


def test_start_bot_scheduler_task_from_sync_context_does_not_raise():
    """GAP-0137: invoking the starter from a sync context must not raise.

    Driving the async starter via asyncio.run() establishes a running loop, so
    asyncio.create_task() succeeds. Before the fix the function was sync and
    asyncio.create_task() raised RuntimeError: no running event loop.
    """
    created = {}

    async def _fake_loop():  # pragma: no cover - never actually awaited
        return None

    async def _runner():
        # Capture the task so we can cancel it instead of leaking it.
        real_create_task = asyncio.create_task

        def _capture(coro, *a, **kw):
            task = real_create_task(coro, *a, **kw)
            created["task"] = task
            return task

        with patch.object(bot_scheduler, "S") as mock_s, \
                patch.object(bot_scheduler, "run_bot_scheduler_loop", _fake_loop), \
                patch.object(bot_scheduler.asyncio, "create_task", _capture):
            mock_s.bot_scheduled_messages_enabled = True
            await bot_scheduler.start_bot_scheduler_task()

        task = created.get("task")
        assert task is not None, "expected a background task to be scheduled"
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass

    # The key assertion: this call from a sync test body must not raise.
    asyncio.run(_runner())


def test_start_bot_scheduler_task_returns_early_when_disabled():
    """GAP-0137: no task is created when the feature flag is disabled."""

    async def _runner():
        with patch.object(bot_scheduler, "S") as mock_s, \
                patch.object(bot_scheduler.asyncio, "create_task") as mock_create:
            mock_s.bot_scheduled_messages_enabled = False
            await bot_scheduler.start_bot_scheduler_task()
            mock_create.assert_not_called()

    asyncio.run(_runner())
