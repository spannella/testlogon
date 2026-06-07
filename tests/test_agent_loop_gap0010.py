"""Regression tests for GAP-0010: agent loop never actually starts.

Before the fix, ``start_agent_loop()`` set ``_running_loops[worker_id] = True``
but never scheduled any background task, and no ``run_agent_loop`` coroutine
existed. These tests verify:

  1. ``run_agent_loop`` exists and is a coroutine function.
  2. Starting the loop on a running event loop schedules a task that actually
     ticks (polls for a ticket and claims it).
  3. The loop exits cleanly when ``_running_loops`` is cleared
     (``stop_agent_loop``).

All DynamoDB access is mocked -- no real AWS / moto / dev stack required.
The tests drive the asyncio event loop manually so they need no
``pytest-asyncio`` plugin.
"""

from __future__ import annotations

import asyncio
import inspect

import pytest
from unittest.mock import patch

from app.services import agent_orchestrator as svc


# The DDB table wrapper uses __slots__, so update_item must be patched at the
# class level (instance-level patching fails). This avoids any real AWS call
# from the loop's best-effort heartbeat update.
_TABLE_CLS = type(svc.T.agent_workers)


WORKER_ID = "w_gap0010"
USER_ID = "u_gap0010"
ELIGIBLE_TICKET = {"ticket_id": "t_gap0010", "title": "Demo", "priority": "high"}


@pytest.fixture(autouse=True)
def clear_running_loops():
    svc._running_loops.clear()
    yield
    svc._running_loops.clear()


@pytest.fixture
def fast_poll(monkeypatch):
    # Make the loop tick fast so tests stay quick and deterministic.
    monkeypatch.setattr(svc, "AGENT_LOOP_POLL_INTERVAL_SECONDS", 0)


def test_run_agent_loop_coroutine_exists():
    """The coroutine that the stub never had must now exist."""
    assert hasattr(svc, "run_agent_loop"), "run_agent_loop is missing"
    assert inspect.iscoroutinefunction(svc.run_agent_loop)


def test_start_agent_loop_schedules_task_and_claims_ticket(fast_poll):
    """FAILS before fix (no loop ticks) -- PASSES after.

    On a running event loop, ``start_agent_loop`` must schedule
    ``run_agent_loop``, which then finds and claims one eligible ticket.
    """

    async def scenario():
        # One ticket, then the queue is empty.
        find_calls = {"n": 0}

        def find_side_effect(user_id, worker_id):
            find_calls["n"] += 1
            return ELIGIBLE_TICKET if find_calls["n"] == 1 else None

        worker_item = {"agent_state": "idle"}

        with patch.object(svc, "_get_worker_item", return_value=worker_item), \
             patch.object(svc, "find_next_ticket", side_effect=find_side_effect), \
             patch.object(svc, "transition_agent_state") as mock_transition, \
             patch.object(svc, "claim_ticket") as mock_claim, \
             patch.object(svc, "inject_ticket_context", return_value="## ctx"), \
             patch.object(_TABLE_CLS, "update_item"):

            result = svc.start_agent_loop(USER_ID, WORKER_ID)
            assert result["ok"] is True
            assert WORKER_ID in svc._running_loops

            # Let the scheduled task run a few iterations.
            for _ in range(20):
                if mock_claim.call_count >= 1:
                    break
                await asyncio.sleep(0)

            svc.stop_agent_loop(USER_ID, WORKER_ID)

            # Let the loop observe the cleared flag and exit.
            for _ in range(20):
                if WORKER_ID not in svc._running_loops:
                    break
                await asyncio.sleep(0)

        mock_claim.assert_called_once_with(USER_ID, WORKER_ID, ELIGIBLE_TICKET["ticket_id"])
        mock_transition.assert_any_call(USER_ID, WORKER_ID, "claiming")
        assert WORKER_ID not in svc._running_loops

    asyncio.run(scenario())


def test_stop_agent_loop_exits_coroutine(fast_poll):
    """``stop_agent_loop`` must cause a running coroutine to exit."""

    async def scenario():
        worker_item = {"agent_state": "idle"}
        with patch.object(svc, "_get_worker_item", return_value=worker_item), \
             patch.object(svc, "find_next_ticket", return_value=None), \
             patch.object(_TABLE_CLS, "update_item"):

            svc.start_agent_loop(USER_ID, WORKER_ID)
            assert WORKER_ID in svc._running_loops

            # Let it tick at least once.
            await asyncio.sleep(0)
            await asyncio.sleep(0)

            svc.stop_agent_loop(USER_ID, WORKER_ID)

            for _ in range(20):
                if WORKER_ID not in svc._running_loops:
                    break
                await asyncio.sleep(0)

        assert WORKER_ID not in svc._running_loops

    asyncio.run(scenario())


def test_run_agent_loop_single_poll_then_stops(fast_poll):
    """Run one poll iteration (empty queue) then stop -- deterministic.

    Directly exercises the coroutine: flag is set, one tick observes an
    empty queue, then the flag is cleared and the coroutine exits via its
    ``finally`` block.
    """

    async def scenario():
        poll_count = {"n": 0}

        def find_side_effect(user_id, worker_id):
            poll_count["n"] += 1
            # After the first poll, signal the loop to stop.
            svc._running_loops.pop(WORKER_ID, None)
            return None

        worker_item = {"agent_state": "idle"}
        svc._running_loops[WORKER_ID] = True

        with patch.object(svc, "_get_worker_item", return_value=worker_item), \
             patch.object(svc, "find_next_ticket", side_effect=find_side_effect), \
             patch.object(_TABLE_CLS, "update_item"):
            await asyncio.wait_for(svc.run_agent_loop(USER_ID, WORKER_ID), timeout=5)

        assert poll_count["n"] == 1
        assert WORKER_ID not in svc._running_loops

    asyncio.run(scenario())
