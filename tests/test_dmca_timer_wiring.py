"""Regression tests for GAP-0027: DMCA waiting-period timer startup wiring.

The service function ``process_expired_dmca_waiting_periods`` was complete but
never invoked by any running server (no async loop, no startup hook). These
tests verify the added loop wrapper drives the service function and that
``app.main`` registers the startup handler. Fully offline (no real AWS).
"""
from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest

from app.services import dmca_claims as svc


class _StopLoop(Exception):
    """Sentinel raised from the patched sleep to break the infinite loop."""


@pytest.fixture
def set_timer_enabled():
    """Set ``S.dmca_timer_enabled`` (frozen dataclass) and restore afterwards."""
    original = svc.S.dmca_timer_enabled

    def _set(value: bool) -> None:
        object.__setattr__(svc.S, "dmca_timer_enabled", value)

    yield _set
    object.__setattr__(svc.S, "dmca_timer_enabled", original)


def test_dmca_timer_loop_calls_service_each_tick(monkeypatch, set_timer_enabled) -> None:
    """One deterministic iteration: the loop calls
    ``process_expired_dmca_waiting_periods`` then sleeps. Patching sleep to
    raise lets us run exactly one tick.

    FAILS BEFORE FIX: ``_dmca_timer_loop`` does not exist.
    PASSES AFTER FIX: the service function is invoked once per tick.
    """
    set_timer_enabled(True)

    process_mock = MagicMock(return_value=2)
    monkeypatch.setattr(svc, "process_expired_dmca_waiting_periods", process_mock)

    async def _fake_sleep(_seconds):
        raise _StopLoop

    monkeypatch.setattr(asyncio, "sleep", _fake_sleep)

    with pytest.raises(_StopLoop):
        asyncio.run(svc._dmca_timer_loop())

    process_mock.assert_called_once_with()


def test_dmca_timer_loop_disabled_returns_without_calling(monkeypatch, set_timer_enabled) -> None:
    """When the feature flag is off, the loop returns immediately without
    invoking the service function (keeps test runs deterministic)."""
    set_timer_enabled(False)

    process_mock = MagicMock(return_value=0)
    monkeypatch.setattr(svc, "process_expired_dmca_waiting_periods", process_mock)

    asyncio.run(svc._dmca_timer_loop())

    process_mock.assert_not_called()


def test_dmca_timer_loop_swallows_service_exceptions(monkeypatch, set_timer_enabled) -> None:
    """A failure in one sweep must not break the loop; it logs and sleeps."""
    set_timer_enabled(True)

    process_mock = MagicMock(side_effect=RuntimeError("boom"))
    monkeypatch.setattr(svc, "process_expired_dmca_waiting_periods", process_mock)

    async def _fake_sleep(_seconds):
        raise _StopLoop

    monkeypatch.setattr(asyncio, "sleep", _fake_sleep)

    # Should reach the sleep (StopLoop) rather than propagating RuntimeError.
    with pytest.raises(_StopLoop):
        asyncio.run(svc._dmca_timer_loop())

    process_mock.assert_called_once()


def test_start_dmca_timer_task_schedules_loop_when_enabled(monkeypatch, set_timer_enabled) -> None:
    """The startup hook creates a background task when enabled."""
    set_timer_enabled(True)

    fake_loop = MagicMock()
    monkeypatch.setattr(asyncio, "get_event_loop", lambda: fake_loop)
    # Avoid scheduling a real coroutine onto an event loop.
    monkeypatch.setattr(asyncio, "ensure_future", MagicMock())

    svc.start_dmca_timer_task()

    fake_loop.create_task.assert_called_once()
    # Close the coroutine passed in to avoid "never awaited" warnings.
    coro = fake_loop.create_task.call_args[0][0]
    coro.close()


def test_start_dmca_timer_task_noop_when_disabled(monkeypatch, set_timer_enabled) -> None:
    """The startup hook does nothing when the flag is off."""
    set_timer_enabled(False)

    fake_loop = MagicMock()
    monkeypatch.setattr(asyncio, "get_event_loop", lambda: fake_loop)

    svc.start_dmca_timer_task()

    fake_loop.create_task.assert_not_called()


def test_main_registers_dmca_timer_startup_handler() -> None:
    """``app.main`` must wire ``start_dmca_timer_task`` as a startup handler.

    FAILS BEFORE FIX: no DMCA timer is registered in main.py.
    """
    import app.main as main_module

    assert hasattr(main_module, "start_dmca_timer_task")

    app = main_module.create_app()
    handlers = app.router.on_startup
    assert svc.start_dmca_timer_task in handlers, (
        "start_dmca_timer_task is not registered as a FastAPI startup handler"
    )
