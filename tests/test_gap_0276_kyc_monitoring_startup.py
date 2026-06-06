"""GAP-0276 regression: KYC monitoring background loops must be started.

The review-checker and re-screening enforcement functions in
``app.services.kyc_monitoring`` were never launched as background tasks, so
overdue reviews were never auto-detected and tier downgrades never fired without
a manual admin API call. These offline, hermetic tests verify that:

1. A single tick of ``_kyc_review_checker_loop`` invokes ``run_review_checker``.
2. A single tick of ``_kyc_rescreening_loop`` invokes ``run_rescreening`` (and
   skips it when the feature flag is off).
3. ``kyc_monitoring_startup`` schedules both loops (only one when re-screening is
   disabled).
4. ``kyc_monitoring_startup`` is registered as a FastAPI startup handler.

Isolation rules (no global moto interception that could leak to real AWS):
- Settings ``S`` is frozen -> mutate via ``object.__setattr__`` and restore.
- The underlying service functions are patched, so no DynamoDB / AWS calls
  happen at all.
- Async loop ticks use ``asyncio.run`` with a fresh event loop (never
  ``asyncio.get_event_loop``); a sentinel injected via the patched
  ``asyncio.sleep`` breaks out after exactly one iteration.
"""

import asyncio

import pytest

import app.services.kyc_monitoring_scheduler as sched


class _StopLoop(Exception):
    """Sentinel raised from the patched sleep to break a loop after one tick."""


def _run_one_tick(coro_factory, monkeypatch):
    """Run a single iteration of an infinite loop coroutine.

    Patches the scheduler module's ``asyncio.sleep`` so the first sleep raises
    ``_StopLoop``, which the loop body lets propagate (it only swallows the work
    function's exceptions, not the sleep). Uses a fresh event loop via
    ``asyncio.run``.
    """

    async def _fake_sleep(_interval):
        raise _StopLoop

    monkeypatch.setattr(sched.asyncio, "sleep", _fake_sleep)

    async def _driver():
        with pytest.raises(_StopLoop):
            await coro_factory()

    asyncio.run(_driver())


def test_review_checker_loop_invokes_run_review_checker(monkeypatch):
    """One tick of the review-checker loop calls run_review_checker."""
    calls = {"n": 0}

    def _fake_checker():
        calls["n"] += 1
        return {"entered_grace_period": 1, "auto_downgraded": 2}

    monkeypatch.setattr(sched, "run_review_checker", _fake_checker)
    _run_one_tick(sched._kyc_review_checker_loop, monkeypatch)
    assert calls["n"] == 1


def test_rescreening_loop_invokes_run_rescreening_when_enabled(monkeypatch):
    """One tick of the re-screening loop calls run_rescreening when enabled."""
    calls = {"n": 0}

    def _fake_rescreen():
        calls["n"] += 1
        return {"total_screened": 3, "matches_found": 0, "triggers_created": 0}

    monkeypatch.setattr(sched, "run_rescreening", _fake_rescreen)

    orig = sched.S.kyc_rescreening_enabled
    object.__setattr__(sched.S, "kyc_rescreening_enabled", True)
    try:
        _run_one_tick(sched._kyc_rescreening_loop, monkeypatch)
    finally:
        object.__setattr__(sched.S, "kyc_rescreening_enabled", orig)

    assert calls["n"] == 1


def test_rescreening_loop_skips_run_rescreening_when_disabled(monkeypatch):
    """The re-screening loop must NOT call run_rescreening when the flag is off."""
    calls = {"n": 0}

    def _fake_rescreen():  # pragma: no cover - must not be called
        calls["n"] += 1
        return {}

    monkeypatch.setattr(sched, "run_rescreening", _fake_rescreen)

    orig = sched.S.kyc_rescreening_enabled
    object.__setattr__(sched.S, "kyc_rescreening_enabled", False)
    try:
        _run_one_tick(sched._kyc_rescreening_loop, monkeypatch)
    finally:
        object.__setattr__(sched.S, "kyc_rescreening_enabled", orig)

    assert calls["n"] == 0


def test_startup_schedules_both_loops_when_enabled(monkeypatch):
    """kyc_monitoring_startup schedules review-checker + re-screening loops."""
    scheduled = []
    monkeypatch.setattr(
        sched.asyncio, "ensure_future", lambda coro: scheduled.append(coro)
    )

    orig_tbl = sched.S.kyc_review_schedule_table_name
    orig_flag = sched.S.kyc_rescreening_enabled
    object.__setattr__(sched.S, "kyc_review_schedule_table_name", "kyc_review_schedule")
    object.__setattr__(sched.S, "kyc_rescreening_enabled", True)
    try:
        sched.kyc_monitoring_startup()
    finally:
        # Close the un-awaited coroutines to avoid 'never awaited' warnings.
        for coro in scheduled:
            coro.close()
        object.__setattr__(sched.S, "kyc_review_schedule_table_name", orig_tbl)
        object.__setattr__(sched.S, "kyc_rescreening_enabled", orig_flag)

    assert len(scheduled) == 2


def test_startup_schedules_only_review_checker_when_rescreening_disabled(monkeypatch):
    """Only the review-checker loop runs when re-screening is disabled."""
    scheduled = []
    monkeypatch.setattr(
        sched.asyncio, "ensure_future", lambda coro: scheduled.append(coro)
    )

    orig_tbl = sched.S.kyc_review_schedule_table_name
    orig_flag = sched.S.kyc_rescreening_enabled
    object.__setattr__(sched.S, "kyc_review_schedule_table_name", "kyc_review_schedule")
    object.__setattr__(sched.S, "kyc_rescreening_enabled", False)
    try:
        sched.kyc_monitoring_startup()
    finally:
        for coro in scheduled:
            coro.close()
        object.__setattr__(sched.S, "kyc_review_schedule_table_name", orig_tbl)
        object.__setattr__(sched.S, "kyc_rescreening_enabled", orig_flag)

    assert len(scheduled) == 1


def test_main_registers_kyc_monitoring_startup_handler():
    """app/main.py must register kyc_monitoring_startup as a startup handler."""
    from app.main import create_app

    app = create_app()
    handler_names = [
        getattr(h, "__name__", repr(h)) for h in app.router.on_startup
    ]
    assert "kyc_monitoring_startup" in handler_names, (
        "kyc_monitoring_startup not found in app.on_startup (GAP-0276)"
    )
