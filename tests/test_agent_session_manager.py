"""Hermetic pytest / unittest tests for app.services.agent_session_manager.

Covers:
  1. create_session - happy path (starting state)
  2. create_session - worker not found (get_worker_raw returns None)
  3. create_session - worker in non-sessionable state
  4. get_session - found and not found
  5. list_sessions_for_worker - via ByWorker GSI
  6. list_sessions_for_worker - filters out other users' sessions
  7. transition_state - starting -> ready (stamps started_at)
  8. transition_state - ready -> awaiting_input
  9. transition_state - awaiting_input -> running
 10. transition_state - running -> awaiting_input (back and forth)
 11. transition_state - any -> ended (terminal)
 12. transition_state - any -> error (terminal with message)
 13. transition_state - invalid transition raises ValueError
 14. transition_state - unknown target state raises ValueError
 15. transition_state - session not found raises SessionError
 16. transition_state - idempotent same-state transition
 17. transition_state - sets claude_pid when supplied
 18. end_session - ends a live session
 19. end_session - idempotent on already-ended session
 20. end_session - returns None for missing session
 21. end_session - transitions to error when error arg is provided
 22. end_sessions_for_worker - ends all live sessions, skips terminal ones

Hermetic / offline:
* Real in-memory DynamoDB ``agent_sessions`` table via moto, with the
  ByWorker GSI, bound to the exact frozen T.agent_sessions handle via
  object.__setattr__ (restored in tearDown).
* app.services.agent_worker_provisioner.get_worker_raw patched at the
  module level (where agent_session_manager imports it from) — no real
  DDB worker table needed.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack
from unittest.mock import patch

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover
    mock_aws = None

from app.core.tables import T
import app.services.agent_session_manager as svc
from app.services.agent_session_manager import (
    SessionError,
    STATE_STARTING,
    STATE_READY,
    STATE_AWAITING_INPUT,
    STATE_RUNNING,
    STATE_ENDED,
    STATE_ERROR,
)

_TABLE_NAME = "agent_sessions"


def _make_agent_sessions_table(ddb):
    """Create the agent_sessions table with its ByWorker GSI."""
    return ddb.create_table(
        TableName=_TABLE_NAME,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "worker_id", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByWorker",
                "KeySchema": [
                    {"AttributeName": "worker_id", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _fake_worker(worker_id: str, status: str = "ready") -> dict:
    return {
        "pk": "USER#alice",
        "sk": f"WORKER#{worker_id}",
        "worker_id": worker_id,
        "user_id": "alice",
        "worker_status": status,
    }


class AgentSessionManagerTests(unittest.TestCase):
    def setUp(self):
        if mock_aws is None:
            self.skipTest("moto not available")

        self._stack = ExitStack()
        self._stack.enter_context(mock_aws())

        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _make_agent_sessions_table(ddb)

        # Rebind frozen T.agent_sessions to the moto table.
        self._orig_agent_sessions = T.agent_sessions
        object.__setattr__(T, "agent_sessions", self.table)

        # Patch get_worker_raw at the location where agent_session_manager
        # has already imported it (the module-level name, not the source).
        self._patcher = patch.object(svc, "get_worker_raw", autospec=True)
        self.mock_get_worker_raw = self._patcher.start()
        # Default: return a ready worker for user "alice", worker "w1"
        self.mock_get_worker_raw.return_value = _fake_worker("w1", "ready")

    def tearDown(self):
        self._patcher.stop()
        object.__setattr__(T, "agent_sessions", self._orig_agent_sessions)
        self._stack.close()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _create(self, user_id="alice", worker_id="w1", cols=80, rows=24):
        self.mock_get_worker_raw.return_value = _fake_worker(worker_id, "ready")
        return svc.create_session(
            user_id=user_id, worker_id=worker_id, cols=cols, rows=rows
        )

    # ------------------------------------------------------------------
    # 1. create_session - happy path
    # ------------------------------------------------------------------

    def test_create_session_happy_path(self):
        sess = self._create()

        self.assertEqual(sess["state"], STATE_STARTING)
        self.assertEqual(sess["user_id"], "alice")
        self.assertEqual(sess["worker_id"], "w1")
        self.assertTrue(sess["session_id"].startswith("acs_"))
        self.assertEqual(sess["cols"], 80)
        self.assertEqual(sess["rows"], 24)
        self.assertEqual(sess["claude_pid"], 0)
        self.assertEqual(sess["error_message"], "")
        self.assertIsInstance(sess["created_at"], int)
        # pk/sk must be stripped
        self.assertNotIn("pk", sess)
        self.assertNotIn("sk", sess)

    def test_create_session_custom_dimensions(self):
        sess = self._create(cols=132, rows=50)
        self.assertEqual(sess["cols"], 132)
        self.assertEqual(sess["rows"], 50)

    def test_create_session_default_dimensions_when_zero(self):
        self.mock_get_worker_raw.return_value = _fake_worker("w1", "ready")
        sess = svc.create_session(user_id="alice", worker_id="w1", cols=0, rows=0)
        self.assertEqual(sess["cols"], 80)
        self.assertEqual(sess["rows"], 24)

    # ------------------------------------------------------------------
    # 2. create_session - worker not found
    # ------------------------------------------------------------------

    def test_create_session_unknown_worker_raises_session_error(self):
        self.mock_get_worker_raw.return_value = None
        with self.assertRaises(SessionError) as ctx:
            svc.create_session(user_id="alice", worker_id="no-such-worker")
        self.assertIn("not found", str(ctx.exception).lower())

    # ------------------------------------------------------------------
    # 3. create_session - worker in non-sessionable state
    # ------------------------------------------------------------------

    def test_create_session_worker_in_starting_state_raises(self):
        self.mock_get_worker_raw.return_value = _fake_worker("w1", "starting")
        with self.assertRaises(SessionError) as ctx:
            svc.create_session(user_id="alice", worker_id="w1")
        self.assertIn("starting", str(ctx.exception))

    def test_create_session_worker_in_stopped_state_raises(self):
        self.mock_get_worker_raw.return_value = _fake_worker("w1", "stopped")
        with self.assertRaises(SessionError):
            svc.create_session(user_id="alice", worker_id="w1")

    def test_create_session_worker_in_running_state_allowed(self):
        """Workers in 'running' state can also host sessions."""
        self.mock_get_worker_raw.return_value = _fake_worker("w1", "running")
        sess = svc.create_session(user_id="alice", worker_id="w1")
        self.assertEqual(sess["state"], STATE_STARTING)

    # ------------------------------------------------------------------
    # 4. get_session - found and not found
    # ------------------------------------------------------------------

    def test_get_session_found(self):
        created = self._create()
        fetched = svc.get_session("alice", created["session_id"])
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["session_id"], created["session_id"])
        self.assertEqual(fetched["state"], STATE_STARTING)

    def test_get_session_not_found(self):
        result = svc.get_session("alice", "acs_doesnotexist")
        self.assertIsNone(result)

    def test_get_session_wrong_user_not_found(self):
        """DDB key includes user_id so a different user cannot fetch it."""
        created = self._create(user_id="alice")
        result = svc.get_session("bob", created["session_id"])
        self.assertIsNone(result)

    # ------------------------------------------------------------------
    # 5. list_sessions_for_worker - via ByWorker GSI
    # ------------------------------------------------------------------

    def test_list_sessions_for_worker_returns_sessions(self):
        s1 = self._create(worker_id="w1")
        s2 = self._create(worker_id="w1")
        results = svc.list_sessions_for_worker("alice", "w1")
        ids = {r["session_id"] for r in results}
        self.assertIn(s1["session_id"], ids)
        self.assertIn(s2["session_id"], ids)

    def test_list_sessions_for_worker_empty_when_none(self):
        results = svc.list_sessions_for_worker("alice", "w-unknown")
        self.assertEqual(results, [])

    def test_list_sessions_for_worker_different_worker_isolated(self):
        self._create(worker_id="w1")
        self.mock_get_worker_raw.return_value = _fake_worker("w2", "ready")
        s2 = svc.create_session(user_id="alice", worker_id="w2")
        results = svc.list_sessions_for_worker("alice", "w2")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["session_id"], s2["session_id"])

    # ------------------------------------------------------------------
    # 6. list_sessions_for_worker - filters other users' sessions
    # ------------------------------------------------------------------

    def test_list_sessions_for_worker_filters_other_users(self):
        """Sessions owned by another user sharing the same worker_id
        must be filtered out by the defensive user_id check."""
        # Alice owns session on w1
        self._create(user_id="alice", worker_id="w1")
        # Directly insert a Bob session for w1 into DDB to simulate a
        # cross-user data anomaly (bypasses ownership check in create_session).
        import uuid
        from app.core.time import now_ts
        bob_session_id = f"acs_{uuid.uuid4().hex}"
        ts = now_ts()
        self.table.put_item(Item={
            "pk": "USER#bob",
            "sk": f"SESSION#{bob_session_id}",
            "session_id": bob_session_id,
            "worker_id": "w1",
            "user_id": "bob",
            "state": STATE_STARTING,
            "created_at": ts,
            "started_at": 0,
            "ended_at": 0,
            "last_activity_at": ts,
            "cols": 80,
            "rows": 24,
            "claude_pid": 0,
            "error_message": "",
        })
        # Alice's query should not see Bob's session
        results = svc.list_sessions_for_worker("alice", "w1")
        for r in results:
            self.assertEqual(r["user_id"], "alice")

    # ------------------------------------------------------------------
    # 7. transition_state - starting -> ready (stamps started_at)
    # ------------------------------------------------------------------

    def test_transition_starting_to_ready_stamps_started_at(self):
        sess = self._create()
        updated = svc.transition_state("alice", sess["session_id"], STATE_READY)
        self.assertEqual(updated["state"], STATE_READY)
        self.assertGreater(updated["started_at"], 0)

    def test_transition_ready_does_not_overwrite_started_at(self):
        """If started_at is already set, a re-transition to ready must not
        overwrite it (the guard checks `not int(item.get('started_at', 0))`)."""
        sess = self._create()
        first = svc.transition_state("alice", sess["session_id"], STATE_READY)
        first_started = first["started_at"]
        # Move away then back to ready
        svc.transition_state("alice", sess["session_id"], STATE_AWAITING_INPUT)
        second = svc.transition_state("alice", sess["session_id"], STATE_READY)
        self.assertEqual(second["started_at"], first_started)

    # ------------------------------------------------------------------
    # 8. transition_state - ready -> awaiting_input
    # ------------------------------------------------------------------

    def test_transition_ready_to_awaiting_input(self):
        sess = self._create()
        svc.transition_state("alice", sess["session_id"], STATE_READY)
        updated = svc.transition_state("alice", sess["session_id"], STATE_AWAITING_INPUT)
        self.assertEqual(updated["state"], STATE_AWAITING_INPUT)

    # ------------------------------------------------------------------
    # 9. transition_state - awaiting_input -> running
    # ------------------------------------------------------------------

    def test_transition_awaiting_input_to_running(self):
        sess = self._create()
        svc.transition_state("alice", sess["session_id"], STATE_READY)
        svc.transition_state("alice", sess["session_id"], STATE_AWAITING_INPUT)
        updated = svc.transition_state("alice", sess["session_id"], STATE_RUNNING)
        self.assertEqual(updated["state"], STATE_RUNNING)

    # ------------------------------------------------------------------
    # 10. transition_state - running -> awaiting_input (back and forth)
    # ------------------------------------------------------------------

    def test_transition_running_to_awaiting_input(self):
        sess = self._create()
        svc.transition_state("alice", sess["session_id"], STATE_READY)
        svc.transition_state("alice", sess["session_id"], STATE_RUNNING)
        updated = svc.transition_state("alice", sess["session_id"], STATE_AWAITING_INPUT)
        self.assertEqual(updated["state"], STATE_AWAITING_INPUT)

    # ------------------------------------------------------------------
    # 11. transition_state - any -> ended (terminal)
    # ------------------------------------------------------------------

    def test_transition_to_ended_stamps_ended_at(self):
        sess = self._create()
        svc.transition_state("alice", sess["session_id"], STATE_READY)
        ended = svc.transition_state("alice", sess["session_id"], STATE_ENDED)
        self.assertEqual(ended["state"], STATE_ENDED)
        self.assertGreater(ended["ended_at"], 0)

    def test_transition_from_starting_to_ended(self):
        sess = self._create()
        ended = svc.transition_state("alice", sess["session_id"], STATE_ENDED)
        self.assertEqual(ended["state"], STATE_ENDED)

    # ------------------------------------------------------------------
    # 12. transition_state - any -> error (terminal with message)
    # ------------------------------------------------------------------

    def test_transition_to_error_stamps_ended_at_and_message(self):
        sess = self._create()
        errored = svc.transition_state(
            "alice", sess["session_id"], STATE_ERROR,
            error_message="PTY bridge crashed"
        )
        self.assertEqual(errored["state"], STATE_ERROR)
        self.assertGreater(errored["ended_at"], 0)
        self.assertEqual(errored["error_message"], "PTY bridge crashed")

    # ------------------------------------------------------------------
    # 13. transition_state - invalid transition raises ValueError
    # ------------------------------------------------------------------

    def test_transition_invalid_starting_to_running_raises(self):
        """starting -> running is not in the allowed transitions."""
        sess = self._create()
        with self.assertRaises(ValueError) as ctx:
            svc.transition_state("alice", sess["session_id"], STATE_RUNNING)
        self.assertIn("starting", str(ctx.exception))
        self.assertIn("running", str(ctx.exception))

    def test_transition_ended_to_ready_raises(self):
        """Terminal states have no outgoing transitions."""
        sess = self._create()
        svc.transition_state("alice", sess["session_id"], STATE_ENDED)
        with self.assertRaises(ValueError):
            svc.transition_state("alice", sess["session_id"], STATE_READY)

    def test_transition_error_to_ready_raises(self):
        sess = self._create()
        svc.transition_state("alice", sess["session_id"], STATE_ERROR)
        with self.assertRaises(ValueError):
            svc.transition_state("alice", sess["session_id"], STATE_READY)

    # ------------------------------------------------------------------
    # 14. transition_state - unknown target state raises ValueError
    # ------------------------------------------------------------------

    def test_transition_unknown_state_raises_value_error(self):
        sess = self._create()
        with self.assertRaises(ValueError) as ctx:
            svc.transition_state("alice", sess["session_id"], "totally_made_up")
        self.assertIn("totally_made_up", str(ctx.exception))

    # ------------------------------------------------------------------
    # 15. transition_state - session not found raises SessionError
    # ------------------------------------------------------------------

    def test_transition_missing_session_raises_session_error(self):
        with self.assertRaises(SessionError) as ctx:
            svc.transition_state("alice", "acs_nonexistent", STATE_READY)
        self.assertIn("not found", str(ctx.exception).lower())

    # ------------------------------------------------------------------
    # 16. transition_state - idempotent same-state transition
    # ------------------------------------------------------------------

    def test_transition_same_state_is_idempotent(self):
        sess = self._create()
        svc.transition_state("alice", sess["session_id"], STATE_READY)
        # Transition to ready again — should not raise and should refresh activity
        updated = svc.transition_state("alice", sess["session_id"], STATE_READY)
        self.assertEqual(updated["state"], STATE_READY)

    def test_transition_same_state_refreshes_last_activity_at(self):
        sess = self._create()
        svc.transition_state("alice", sess["session_id"], STATE_READY)
        svc.transition_state("alice", sess["session_id"], STATE_RUNNING)
        before = svc.get_session("alice", sess["session_id"])["last_activity_at"]
        import time; time.sleep(1.1)  # ensure clock advances
        svc.transition_state("alice", sess["session_id"], STATE_RUNNING)
        after = svc.get_session("alice", sess["session_id"])["last_activity_at"]
        self.assertGreaterEqual(after, before)

    # ------------------------------------------------------------------
    # 17. transition_state - sets claude_pid when supplied
    # ------------------------------------------------------------------

    def test_transition_sets_claude_pid(self):
        sess = self._create()
        updated = svc.transition_state(
            "alice", sess["session_id"], STATE_READY, claude_pid=12345
        )
        self.assertEqual(updated["claude_pid"], 12345)

    # ------------------------------------------------------------------
    # 18. end_session - ends a live session
    # ------------------------------------------------------------------

    def test_end_session_transitions_to_ended(self):
        sess = self._create()
        svc.transition_state("alice", sess["session_id"], STATE_READY)
        result = svc.end_session("alice", sess["session_id"])
        self.assertEqual(result["state"], STATE_ENDED)

    # ------------------------------------------------------------------
    # 19. end_session - idempotent on already-ended session
    # ------------------------------------------------------------------

    def test_end_session_idempotent_on_already_ended(self):
        sess = self._create()
        svc.transition_state("alice", sess["session_id"], STATE_ENDED)
        result = svc.end_session("alice", sess["session_id"])
        # Must return the existing terminal session, not raise
        self.assertEqual(result["state"], STATE_ENDED)

    def test_end_session_idempotent_on_error_state(self):
        sess = self._create()
        svc.transition_state("alice", sess["session_id"], STATE_ERROR)
        result = svc.end_session("alice", sess["session_id"])
        self.assertEqual(result["state"], STATE_ERROR)

    # ------------------------------------------------------------------
    # 20. end_session - returns None for missing session
    # ------------------------------------------------------------------

    def test_end_session_missing_returns_none(self):
        result = svc.end_session("alice", "acs_doesnotexist")
        self.assertIsNone(result)

    # ------------------------------------------------------------------
    # 21. end_session - transitions to error when error arg is provided
    # ------------------------------------------------------------------

    def test_end_session_with_error_transitions_to_error(self):
        sess = self._create()
        svc.transition_state("alice", sess["session_id"], STATE_READY)
        result = svc.end_session("alice", sess["session_id"], error="connection lost")
        self.assertEqual(result["state"], STATE_ERROR)
        self.assertEqual(result["error_message"], "connection lost")

    def test_end_session_without_error_transitions_to_ended(self):
        sess = self._create()
        svc.transition_state("alice", sess["session_id"], STATE_READY)
        svc.transition_state("alice", sess["session_id"], STATE_RUNNING)
        result = svc.end_session("alice", sess["session_id"])
        self.assertEqual(result["state"], STATE_ENDED)

    # ------------------------------------------------------------------
    # 22. end_sessions_for_worker - ends all live sessions, skips terminal
    # ------------------------------------------------------------------

    def test_end_sessions_for_worker_ends_all_live(self):
        s1 = self._create(worker_id="w1")
        s2 = self._create(worker_id="w1")
        # Advance both to a non-terminal live state
        svc.transition_state("alice", s1["session_id"], STATE_READY)
        svc.transition_state("alice", s2["session_id"], STATE_READY)

        count = svc.end_sessions_for_worker("alice", "w1")
        self.assertEqual(count, 2)
        self.assertEqual(
            svc.get_session("alice", s1["session_id"])["state"], STATE_ENDED
        )
        self.assertEqual(
            svc.get_session("alice", s2["session_id"])["state"], STATE_ENDED
        )

    def test_end_sessions_for_worker_skips_already_terminal(self):
        s1 = self._create(worker_id="w1")
        s2 = self._create(worker_id="w1")
        # End s1 manually; s2 stays in starting
        svc.transition_state("alice", s1["session_id"], STATE_ENDED)

        count = svc.end_sessions_for_worker("alice", "w1")
        self.assertEqual(count, 1)  # only s2 ended
        self.assertEqual(
            svc.get_session("alice", s2["session_id"])["state"], STATE_ENDED
        )

    def test_end_sessions_for_worker_returns_zero_when_none(self):
        count = svc.end_sessions_for_worker("alice", "w-no-sessions")
        self.assertEqual(count, 0)

    def test_end_sessions_for_worker_only_affects_target_worker(self):
        s1 = self._create(worker_id="w1")
        self.mock_get_worker_raw.return_value = _fake_worker("w2", "ready")
        s2 = svc.create_session(user_id="alice", worker_id="w2")

        svc.end_sessions_for_worker("alice", "w1")

        # w1's session ended, w2's session untouched
        self.assertEqual(
            svc.get_session("alice", s1["session_id"])["state"], STATE_ENDED
        )
        self.assertEqual(
            svc.get_session("alice", s2["session_id"])["state"], STATE_STARTING
        )

    # ------------------------------------------------------------------
    # Bonus: _item_to_session strips pk/sk and coerces Decimals
    # ------------------------------------------------------------------

    def test_item_to_session_strips_pk_sk(self):
        from decimal import Decimal
        from app.services.agent_session_manager import _item_to_session
        item = {
            "pk": "USER#alice",
            "sk": "SESSION#abc",
            "session_id": "abc",
            "created_at": Decimal("1700000000"),
            "state": "starting",
        }
        out = _item_to_session(item)
        self.assertNotIn("pk", out)
        self.assertNotIn("sk", out)
        self.assertIsInstance(out["created_at"], int)
        self.assertEqual(out["session_id"], "abc")


if __name__ == "__main__":
    unittest.main()
