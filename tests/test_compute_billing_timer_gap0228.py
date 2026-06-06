"""GAP-0228: background compute-billing timer registration + per-tick deduction.

Offline, hermetic regression tests (in-memory, no real AWS). These verify:

1. ``_tick_all_running_resources`` enumerates every running EC2 instance and
   K8s pod and calls ``record_billing_tick`` for each (the same per-tick
   deduction performed by the manual POST /ui/remote/billing/tick endpoint),
   and updates ``last_billed_at`` after each tick.
2. A resource whose wallet is exhausted (``InsufficientBalanceError``) is
   auto-terminated rather than aborting the batch.
3. ``start_compute_billing_timer_task`` schedules the loop when enabled and is
   a no-op when ``compute_billing_enabled`` is False.
4. The startup handler is wired into the FastAPI app.

Settings ``S`` is frozen, so we mutate it via ``object.__setattr__``.
DynamoDB table handles ``T.<table>`` are never touched by real AWS: every
table-backed helper is monkeypatched, and the scan helpers are stubbed so the
``T.ec2_instances`` / ``T.k8s_pods`` scans are never executed.
"""

from unittest.mock import patch

import app.services.compute_billing as cb


def test_tick_all_running_resources_calls_record_billing_tick():
    """GAP-0228: each running EC2 instance and K8s pod is billed once."""
    fake_instances = [
        {"user_sub": "alice", "instance_id": "i_001", "label": "My EC2",
         "instance_type": "t3.micro", "started_at": 1000000, "last_billed_at": 0},
    ]
    fake_pods = [
        {"user_sub": "alice", "pod_id": "p_001", "label": "My Pod",
         "preset": "small", "started_at": 1000000, "last_billed_at": 0},
    ]
    ticks = []
    updates = []

    def fake_record(user_sub, **kw):
        ticks.append((user_sub, kw))
        return {
            "entry_id": "e_x", "amount_cents": 1, "wallet_balance_after": 999,
            "rate_cents_per_min": 0.2, "created_at": 9999999,
        }

    with (
        patch.object(cb, "_scan_all_running_instances", return_value=fake_instances),
        patch.object(cb, "_scan_all_running_pods", return_value=fake_pods),
        patch.object(cb, "record_billing_tick", side_effect=fake_record),
        patch.object(cb, "_update_last_billed_at",
                     side_effect=lambda *a, **kw: updates.append(a)),
        # now far in the future so elapsed_minutes >> _MIN_TICK_MINUTES
        patch.object(cb, "now_ts", return_value=2000000),
    ):
        count = cb._tick_all_running_resources()

    assert count == 2
    resource_types = {kw["resource_type"] for _, kw in ticks}
    assert resource_types == {"ec2", "k8s"}
    # last_billed_at must be advanced for both resources
    assert len(updates) == 2
    for _, kw in ticks:
        assert kw["event"] == "periodic_tick"
        assert kw["duration_minutes"] > cb._MIN_TICK_MINUTES


def test_tick_skips_resources_billed_too_recently():
    """A resource billed less than _MIN_TICK_MINUTES ago is not re-billed."""
    fresh = [
        {"user_sub": "alice", "instance_id": "i_fresh", "label": "",
         "instance_type": "t3.micro", "started_at": 1000000, "last_billed_at": 1000000},
    ]
    ticks = []

    with (
        patch.object(cb, "_scan_all_running_instances", return_value=fresh),
        patch.object(cb, "_scan_all_running_pods", return_value=[]),
        patch.object(cb, "record_billing_tick",
                     side_effect=lambda u, **kw: ticks.append(u)),
        patch.object(cb, "_update_last_billed_at", side_effect=lambda *a, **kw: None),
        # only 6 seconds elapsed -> 0.1 min < 0.5 min
        patch.object(cb, "now_ts", return_value=1000006),
    ):
        count = cb._tick_all_running_resources()

    assert count == 0
    assert ticks == []


def test_tick_auto_terminates_on_insufficient_balance():
    """Zero-balance resources are auto-terminated, not left running."""
    insolvent = [
        {"user_sub": "bob", "pod_id": "p_broke", "label": "",
         "preset": "small", "started_at": 1000000, "last_billed_at": 0},
    ]
    terminated = []

    with (
        patch.object(cb, "_scan_all_running_instances", return_value=[]),
        patch.object(cb, "_scan_all_running_pods", return_value=insolvent),
        patch.object(cb, "record_billing_tick",
                     side_effect=cb.InsufficientBalanceError("broke")),
        patch.object(cb, "_update_last_billed_at", side_effect=lambda *a, **kw: None),
        patch.object(cb, "_auto_terminate_resource",
                     side_effect=lambda rt, u, rid: terminated.append((rt, u, rid))),
        patch.object(cb, "now_ts", return_value=2000000),
    ):
        count = cb._tick_all_running_resources()

    assert count == 0  # no successful tick
    assert terminated == [("k8s", "bob", "p_broke")]


def test_start_compute_billing_timer_task_schedules_loop_when_enabled():
    """start_compute_billing_timer_task schedules the loop when enabled."""
    orig = cb.S.compute_billing_enabled
    object.__setattr__(cb.S, "compute_billing_enabled", True)
    try:
        with patch.object(cb.asyncio, "ensure_future") as mock_ensure:
            cb.start_compute_billing_timer_task()
        assert mock_ensure.call_count == 1
    finally:
        object.__setattr__(cb.S, "compute_billing_enabled", orig)


def test_start_compute_billing_timer_task_noop_when_disabled():
    """start_compute_billing_timer_task is a no-op when billing is disabled."""
    orig = cb.S.compute_billing_enabled
    object.__setattr__(cb.S, "compute_billing_enabled", False)
    try:
        with patch.object(cb.asyncio, "ensure_future") as mock_ensure:
            cb.start_compute_billing_timer_task()
        mock_ensure.assert_not_called()
    finally:
        object.__setattr__(cb.S, "compute_billing_enabled", orig)


def test_compute_billing_timer_startup_handler_registered():
    """The compute billing timer startup handler must be registered on the app."""
    from app.main import create_app

    app = create_app()
    handler_names = [
        getattr(h, "__name__", repr(h)) for h in app.router.on_startup
    ]
    assert "start_compute_billing_timer_task" in handler_names, (
        "Compute billing timer startup handler not found in app.on_startup"
    )
