"""Offline hermetic tests for the interactive Claude Code session subsystem
(ACS-001..ACS-009 / ADR-002).

Coverage:
- ACS-002 session state machine (legal/illegal transitions, terminal states,
  newest-first listing, worker validation).
- ACS-003 mock PTY bridge: input -> echoed output, scripted feedback banner.
- ACS-004/005 the one-way -> two-way WS wiring: a `connect -> output -> input
  -> output` exchange against the mock bridge, output BOTH reaches the browser
  AND feeds terminal_monitor; a `[AGENT_FEEDBACK_NEEDED]` line yields a
  `feedback_request` message.
- ACS-006 detach-without-kill + reattach replay.
- ACS-007 ownership: a foreign/unknown worker is rejected before any bridge.
- ACS-008 feedback signal -> awaiting_input; input -> running.

Isolation rules (per repo TEST ISOLATION guidance):
- moto in-memory tables bound to the EXACT frozen ``T.agent_sessions`` /
  ``T.agent_workers`` handles via ``object.__setattr__`` (restored on cleanup),
  inside a scoped ExitStack.
- The PTY bridge factory is patched so no real SSH/PTY/network is used.
- The auth + rate-limit + session-slot helpers are patched to admit the user.
- ``terminal_monitor.create_feedback_request`` is patched so the feedback DDB
  table + orchestrator side effects are not exercised by handler tests.
- The WS handler runs on a FRESH ``asyncio.new_event_loop()``.
- Frozen ``S`` flags toggled via ``object.__setattr__``.
"""
from __future__ import annotations

import asyncio
import json
import unittest
from contextlib import ExitStack
from unittest.mock import patch

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover
    mock_aws = None


def _make_sessions_table(ddb):
    return ddb.create_table(
        TableName="agent_sessions_test_acs",
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


def _make_workers_table(ddb):
    return ddb.create_table(
        TableName="agent_workers_test_acs",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


@unittest.skipIf(mock_aws is None, "moto is not installed")
class _Base(unittest.TestCase):
    USER = "acs-user-1"
    WORKER = "w_test_acs"

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.sessions_table = _make_sessions_table(ddb)
        self.workers_table = _make_workers_table(ddb)

        self.feedback_table = ddb.create_table(
            TableName="agent_feedback_test_acs",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        from app.core.tables import T

        prev_sessions = T.agent_sessions
        prev_workers = T.agent_workers
        prev_feedback = T.agent_feedback
        object.__setattr__(T, "agent_sessions", self.sessions_table)
        object.__setattr__(T, "agent_workers", self.workers_table)
        object.__setattr__(T, "agent_feedback", self.feedback_table)
        self.addCleanup(lambda: object.__setattr__(T, "agent_sessions", prev_sessions))
        self.addCleanup(lambda: object.__setattr__(T, "agent_workers", prev_workers))
        self.addCleanup(lambda: object.__setattr__(T, "agent_feedback", prev_feedback))

        import app.services.agent_session_manager as sm

        self.sm = sm

    def _seed_worker(self, status="ready"):
        self.workers_table.put_item(
            Item={
                "pk": f"USER#{self.USER}",
                "sk": f"WORKER#{self.WORKER}",
                "worker_id": self.WORKER,
                "user_id": self.USER,
                "worker_status": status,
                "compute_type": "ec2",
                "public_ip": "10.0.0.9",
            }
        )


# ---------------------------------------------------------------------------
# ACS-002: state machine + CRUD
# ---------------------------------------------------------------------------


class TestStateMachine(_Base):
    def test_create_requires_existing_worker(self):
        with self.assertRaises(self.sm.SessionError):
            self.sm.create_session(user_id=self.USER, worker_id="missing")

    def test_create_rejects_non_sessionable_worker(self):
        self._seed_worker(status="terminated")
        with self.assertRaises(self.sm.SessionError):
            self.sm.create_session(user_id=self.USER, worker_id=self.WORKER)

    def test_create_starts_in_starting(self):
        self._seed_worker()
        s = self.sm.create_session(user_id=self.USER, worker_id=self.WORKER)
        self.assertEqual(s["state"], self.sm.STATE_STARTING)
        self.assertEqual(s["worker_id"], self.WORKER)
        self.assertEqual(s["user_id"], self.USER)

    def test_legal_transitions(self):
        self._seed_worker()
        s = self.sm.create_session(user_id=self.USER, worker_id=self.WORKER)
        sid = s["session_id"]
        self.sm.transition_state(self.USER, sid, self.sm.STATE_READY)
        self.sm.transition_state(self.USER, sid, self.sm.STATE_RUNNING)
        self.sm.transition_state(self.USER, sid, self.sm.STATE_AWAITING_INPUT)
        back = self.sm.transition_state(self.USER, sid, self.sm.STATE_RUNNING)
        self.assertEqual(back["state"], self.sm.STATE_RUNNING)
        ended = self.sm.transition_state(self.USER, sid, self.sm.STATE_ENDED)
        self.assertEqual(ended["state"], self.sm.STATE_ENDED)
        self.assertGreater(ended["ended_at"], 0)

    def test_illegal_transition_from_terminal_raises(self):
        self._seed_worker()
        s = self.sm.create_session(user_id=self.USER, worker_id=self.WORKER)
        sid = s["session_id"]
        self.sm.transition_state(self.USER, sid, self.sm.STATE_READY)
        self.sm.transition_state(self.USER, sid, self.sm.STATE_ENDED)
        with self.assertRaises(ValueError):
            self.sm.transition_state(self.USER, sid, self.sm.STATE_RUNNING)

    def test_starting_cannot_jump_to_awaiting_input(self):
        self._seed_worker()
        s = self.sm.create_session(user_id=self.USER, worker_id=self.WORKER)
        with self.assertRaises(ValueError):
            self.sm.transition_state(self.USER, s["session_id"], self.sm.STATE_AWAITING_INPUT)

    def test_ready_sets_started_at(self):
        self._seed_worker()
        s = self.sm.create_session(user_id=self.USER, worker_id=self.WORKER)
        out = self.sm.transition_state(self.USER, s["session_id"], self.sm.STATE_READY)
        self.assertGreater(out["started_at"], 0)

    def test_end_session_idempotent(self):
        self._seed_worker()
        s = self.sm.create_session(user_id=self.USER, worker_id=self.WORKER)
        sid = s["session_id"]
        self.sm.transition_state(self.USER, sid, self.sm.STATE_READY)
        e1 = self.sm.end_session(self.USER, sid)
        e2 = self.sm.end_session(self.USER, sid)
        self.assertEqual(e1["state"], self.sm.STATE_ENDED)
        self.assertEqual(e2["state"], self.sm.STATE_ENDED)

    def test_list_newest_first(self):
        self._seed_worker()
        with patch.object(self.sm, "now_ts", return_value=100):
            a = self.sm.create_session(user_id=self.USER, worker_id=self.WORKER)
        with patch.object(self.sm, "now_ts", return_value=200):
            b = self.sm.create_session(user_id=self.USER, worker_id=self.WORKER)
        listed = self.sm.list_sessions_for_worker(self.USER, self.WORKER)
        self.assertEqual(listed[0]["session_id"], b["session_id"])
        self.assertEqual(listed[1]["session_id"], a["session_id"])


# ---------------------------------------------------------------------------
# ACS-003: mock PTY bridge
# ---------------------------------------------------------------------------


class TestMockBridge(unittest.TestCase):
    def test_mock_bridge_echo_and_feedback_banner(self):
        from app.services.claude_code_pty_bridge import MockClaudePtyBridge

        b = MockClaudePtyBridge(cols=80, rows=24)
        b.connect()
        banner = b.poll_output()
        self.assertIn("[AGENT_FEEDBACK_NEEDED]", banner)
        b.send_input("hello\n")
        echoed = b.poll_output()
        self.assertIn("hello", echoed)
        b.close()
        with self.assertRaises(Exception):
            b.send_input("after close")

    def test_factory_dev_returns_mock(self):
        from app.core.settings import S
        from app.services import claude_code_pty_bridge as cb

        prev = S.dev_mode
        object.__setattr__(S, "dev_mode", True)
        try:
            bridge = cb.build_claude_code_bridge(
                user_id="u", worker={"public_ip": "1.2.3.4"}, cols=80, rows=24
            )
            self.assertIsInstance(bridge, cb.MockClaudePtyBridge)
        finally:
            object.__setattr__(S, "dev_mode", prev)


# ---------------------------------------------------------------------------
# WebSocket handler exchange (ACS-004/005/006/007/008)
# ---------------------------------------------------------------------------


class _FakeWebSocket:
    def __init__(self, messages):
        self._messages = list(messages)
        self.sent = []
        self.closed_code = None
        self.headers = {}
        self.cookies = {}
        self.client = None

    async def accept(self):
        return None

    async def receive_text(self):
        from fastapi import WebSocketDisconnect

        if not self._messages:
            raise WebSocketDisconnect(code=1000)
        return self._messages.pop(0)

    async def send_json(self, data):
        self.sent.append(data)

    async def close(self, code=1000):
        self.closed_code = code


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestWsHandler(_Base):
    def setUp(self):
        super().setUp()
        import app.routers.agent_session_terminal as ast

        self.ast = ast

        # Admit the user through the shared auth + limit helpers.
        async def _authorize(ws):
            return {"user_sub": self.USER, "role": "admin"}, None

        self.stack.enter_context(patch.object(ast, "_authorize_terminal_access", _authorize))
        self.stack.enter_context(patch.object(ast, "_consume_connect_rate_limit", lambda *a, **k: True))
        self.stack.enter_context(patch.object(ast, "_try_acquire_user_session_slot", lambda *a, **k: True))
        self.stack.enter_context(patch.object(ast, "_release_user_session_slot", lambda *a, **k: None))
        self.stack.enter_context(patch.object(ast, "audit_event", lambda *a, **k: None))

        # Capture monitor taps + stub feedback creation (no DDB / orchestrator).
        import app.services.terminal_monitor as tm

        self.tm = tm
        self.monitor_calls = []
        real_process = tm.process_terminal_output

        def _tracked(worker_id, output):
            self.monitor_calls.append((worker_id, output))
            return real_process(worker_id, output)

        self.stack.enter_context(patch.object(ast.terminal_monitor, "process_terminal_output", _tracked))
        self.stack.enter_context(
            patch.object(
                ast.terminal_monitor,
                "create_feedback_request",
                lambda **kw: {"request_id": "fb_test"},
            )
        )

        # Enable the feature flag.
        from app.core.settings import S

        self.S = S
        prev = S.agent_claude_code_session_enabled
        object.__setattr__(S, "agent_claude_code_session_enabled", True)
        self.addCleanup(lambda: object.__setattr__(S, "agent_claude_code_session_enabled", prev))
        prev_dev = S.dev_mode
        object.__setattr__(S, "dev_mode", True)
        self.addCleanup(lambda: object.__setattr__(S, "dev_mode", prev_dev))

        # Clear the process-local bridge registry between tests.
        ast._LIVE_BRIDGES.clear()
        self.addCleanup(ast._LIVE_BRIDGES.clear)

    def _run(self, messages):
        ws = _FakeWebSocket([json.dumps(m) for m in messages])
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self.ast.agent_session_ws(ws))
        finally:
            loop.close()
            asyncio.set_event_loop(None)
        return ws

    def test_feature_disabled_rejects(self):
        object.__setattr__(self.S, "agent_claude_code_session_enabled", False)
        ws = self._run([{"type": "connect", "payload": {"worker_id": self.WORKER}}])
        errs = [m for m in ws.sent if m.get("type") == "error"]
        self.assertTrue(any(e["payload"]["code"] == "feature_disabled" for e in errs))

    def test_unknown_worker_rejected_before_bridge(self):
        ws = self._run([{"type": "connect", "payload": {"worker_id": "nope"}}])
        errs = [m for m in ws.sent if m.get("type") == "error"]
        self.assertTrue(any(e["payload"]["code"] == "worker_not_found" for e in errs))
        # No session was created (ownership enforced before bridge).
        self.assertEqual(self.sm.list_sessions_for_worker(self.USER, "nope"), [])

    def test_raw_ssh_payload_rejected(self):
        self._seed_worker()
        ws = self._run(
            [{"type": "connect", "payload": {"worker_id": self.WORKER, "host": "evil", "port": 22, "authType": "password"}}]
        )
        errs = [m for m in ws.sent if m.get("type") == "error"]
        self.assertTrue(any("worker_id only" in e["payload"]["message"] for e in errs))

    def test_two_way_exchange_output_reaches_browser_and_monitor(self):
        """The one-way -> two-way assertion: a connect yields scripted output
        that BOTH reaches the browser AND feeds terminal_monitor; browser input
        reaches the CLI and produces a visible response."""
        self._seed_worker()
        ws = self._run(
            [
                {"type": "connect", "payload": {"worker_id": self.WORKER, "cols": 100, "rows": 30}},
                {"type": "input", "payload": {"data": "list files\n"}},
            ]
        )
        outputs = [m for m in ws.sent if m.get("type") == "output"]
        all_output = "".join(m["payload"]["data"] for m in outputs)
        # Output reached the browser.
        self.assertIn("[AGENT_FEEDBACK_NEEDED]", all_output)
        # Input drove the CLI -> visible response.
        self.assertIn("list files", all_output)
        # The SAME output fed terminal_monitor (the preserved tap).
        self.assertTrue(self.monitor_calls)
        monitor_text = "".join(o for (_w, o) in self.monitor_calls)
        self.assertIn("[AGENT_FEEDBACK_NEEDED]", monitor_text)

    def test_feedback_signal_emits_request_and_awaiting_input_state(self):
        self._seed_worker()
        ws = self._run([{"type": "connect", "payload": {"worker_id": self.WORKER}}])
        fb = [m for m in ws.sent if m.get("type") == "feedback_request"]
        self.assertTrue(fb, "feedback_request must be emitted on the scripted banner")
        # Session moved to awaiting_input (ACS-008).
        sessions = self.sm.list_sessions_for_worker(self.USER, self.WORKER)
        self.assertEqual(sessions[0]["state"], self.sm.STATE_AWAITING_INPUT)

    def test_input_returns_state_to_running(self):
        self._seed_worker()
        ws = self._run(
            [
                {"type": "connect", "payload": {"worker_id": self.WORKER}},
                {"type": "input", "payload": {"data": "answer\n"}},
            ]
        )
        sessions = self.sm.list_sessions_for_worker(self.USER, self.WORKER)
        self.assertEqual(sessions[0]["state"], self.sm.STATE_RUNNING)

    def test_detach_keeps_bridge_then_reattach_replays(self):
        self._seed_worker()
        # First connect (detach by exhausting messages -> WebSocketDisconnect).
        ws1 = self._run([{"type": "connect", "payload": {"worker_id": self.WORKER}}])
        status = [m for m in ws1.sent if m.get("type") == "status" and m["payload"].get("session_id")]
        self.assertTrue(status)
        sid = status[0]["payload"]["session_id"]
        # Bridge survived detach (ACS-006).
        self.assertIn(sid, self.ast._LIVE_BRIDGES)
        # Reattach: replay recent scrollback from the monitor ring buffer.
        ws2 = self._run([{"type": "connect", "payload": {"worker_id": self.WORKER, "session_id": sid}}])
        outputs = [m for m in ws2.sent if m.get("type") == "output"]
        replay = "".join(m["payload"]["data"] for m in outputs)
        self.assertIn("[AGENT_FEEDBACK_NEEDED]", replay)
        reattach_status = [m for m in ws2.sent if m.get("type") == "status" and "Reattached" in m["payload"].get("message", "")]
        self.assertTrue(reattach_status)

    def test_stop_ends_session_and_drops_bridge(self):
        self._seed_worker()
        ws = self._run(
            [
                {"type": "connect", "payload": {"worker_id": self.WORKER}},
                {"type": "stop", "payload": {}},
            ]
        )
        sessions = self.sm.list_sessions_for_worker(self.USER, self.WORKER)
        self.assertEqual(sessions[0]["state"], self.sm.STATE_ENDED)
        self.assertEqual(self.ast._LIVE_BRIDGES, {})


if __name__ == "__main__":
    unittest.main()
