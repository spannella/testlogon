"""Offline hermetic regression tests for GAP-0233 and GAP-0234 (INFRA-010).

Both gaps live in the Browser SSH terminal -> session recording wiring.

GAP-0234 — host records lacked a ``record_sessions`` boolean, ``create_host`` /
``update_host`` had no way to set it, and no ``_should_record()`` gate existed.
The fix adds the field to the schema (``_item_to_host`` / ``create_host`` /
``update_host``), the Pydantic models, and a ``_should_record(user_sub, host_id)``
helper that reads the flag (never raises, gated by the global
``ssh_session_recording_enabled`` setting).

GAP-0233 — the Browser SSH WebSocket handler streamed SSH output to the browser
but never called the recording service. The fix adds ``start_recording`` on a
successful connect (when ``_should_record`` is True or the always-record
override is set), ``append_events`` per output chunk in the poll loop, and
``stop_recording`` in the ``finally`` block. All three calls are best-effort.

Isolation rules (per repo TEST ISOLATION guidance):
- NO unscoped global botocore interception. ``mock_aws()`` is entered inside an
  ExitStack with a clearly scoped lifetime and the EXACT frozen table handle
  (``T.host_inventory``) is patched via ``object.__setattr__``.
- The recording service is exercised both for real (host_inventory schema tests)
  and via patched ``start_recording`` / ``append_events`` / ``stop_recording``
  symbols for the WebSocket handler tests, so no recording DDB table or real AWS
  is needed by the handler tests.
- ``ParamikoSshBridge`` is stubbed so no network connection is attempted.
- The websocket connect handler runs on a FRESH event loop
  (``asyncio.new_event_loop()``), never ``get_event_loop()``.
- Settings ``S`` is frozen; any mutation uses ``object.__setattr__``.
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
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


def _make_host_inventory_table(ddb):
    return ddb.create_table(
        TableName="host_inventory_test_0234",
        KeySchema=[
            {"AttributeName": "user_sub", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "user_sub", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


# ---------------------------------------------------------------------------
# GAP-0234: record_sessions schema + _should_record gate
# ---------------------------------------------------------------------------

@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestRecordSessionsSchemaGap0234(unittest.TestCase):
    USER = "rec-flag-user-0234"

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.host_table = _make_host_inventory_table(ddb)

        from app.core.tables import T

        prev_host = T.host_inventory
        object.__setattr__(T, "host_inventory", self.host_table)
        self.addCleanup(lambda: object.__setattr__(T, "host_inventory", prev_host))

        # Silence audit_event (host_inventory._audit uses a local import).
        self.stack.enter_context(
            patch("app.services.alerts.audit_event", lambda *a, **k: None)
        )

        import app.services.host_inventory as hi

        self.hi = hi

    def test_create_stores_record_sessions_true(self):
        """FAILS BEFORE FIX: record_sessions absent from create_host return dict."""
        h = self.hi.create_host(
            self.USER, label="db", hostname="10.0.0.5", record_sessions=True
        )
        self.assertIn("record_sessions", h)
        self.assertIs(h["record_sessions"], True)

    def test_create_defaults_record_sessions_false(self):
        h = self.hi.create_host(self.USER, label="web", hostname="10.0.0.6")
        self.assertIs(h["record_sessions"], False)

    def test_update_toggles_record_sessions(self):
        h = self.hi.create_host(
            self.USER, label="db", hostname="10.0.0.7", record_sessions=True
        )
        updated = self.hi.update_host(self.USER, h["host_id"], record_sessions=False)
        self.assertIs(updated["record_sessions"], False)
        again = self.hi.update_host(self.USER, h["host_id"], record_sessions=True)
        self.assertIs(again["record_sessions"], True)

    def test_get_host_round_trips_flag(self):
        h = self.hi.create_host(
            self.USER, label="prod", hostname="10.0.0.8", record_sessions=True
        )
        fetched = self.hi.get_host(self.USER, h["host_id"])
        self.assertIs(fetched["record_sessions"], True)

    def test_should_record_true_when_flag_set(self):
        h = self.hi.create_host(
            self.USER, label="prod", hostname="10.0.0.9", record_sessions=True
        )
        self.assertTrue(self.hi._should_record(self.USER, h["host_id"]))

    def test_should_record_false_when_flag_unset(self):
        h = self.hi.create_host(
            self.USER, label="dev", hostname="10.0.0.10", record_sessions=False
        )
        self.assertFalse(self.hi._should_record(self.USER, h["host_id"]))

    def test_should_record_false_for_unknown_host(self):
        # Must never raise, returns False.
        self.assertFalse(self.hi._should_record(self.USER, "nonexistent"))
        self.assertFalse(self.hi._should_record(self.USER, ""))
        self.assertFalse(self.hi._should_record(self.USER, None))

    def test_should_record_false_when_global_flag_off(self):
        from app.core.settings import S

        h = self.hi.create_host(
            self.USER, label="prod", hostname="10.0.0.11", record_sessions=True
        )
        prev = S.ssh_session_recording_enabled
        object.__setattr__(S, "ssh_session_recording_enabled", False)
        try:
            self.assertFalse(self.hi._should_record(self.USER, h["host_id"]))
        finally:
            object.__setattr__(S, "ssh_session_recording_enabled", prev)


# ---------------------------------------------------------------------------
# Fake WebSocket: scripts client messages then disconnects.
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


# ---------------------------------------------------------------------------
# GAP-0233 + GAP-0234: WebSocket handler auto-records when host flag is set.
# ---------------------------------------------------------------------------

@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestRecordingHandlerGap0233(unittest.TestCase):
    USER = "rec-handler-user-0233"

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.host_table = _make_host_inventory_table(ddb)

        from app.core.tables import T
        import app.routers.browser_ssh_terminal as bst
        import app.services.host_inventory as hi

        self.bst = bst
        self.hi = hi

        prev_host = T.host_inventory
        object.__setattr__(T, "host_inventory", self.host_table)
        self.addCleanup(lambda: object.__setattr__(T, "host_inventory", prev_host))

        self.stack.enter_context(
            patch("app.services.alerts.audit_event", lambda *a, **k: None)
        )

        # Allow this user through the authorization gate.
        async def _authorize(ws):
            return {"user_sub": self.USER, "role": "admin"}, None

        self.stack.enter_context(patch.object(bst, "_authorize_terminal_access", _authorize))
        self.stack.enter_context(patch.object(bst, "browser_ssh_terminal_enabled", lambda: True))
        self.stack.enter_context(patch.object(bst, "_consume_connect_rate_limit", lambda *a, **k: True))
        self.stack.enter_context(patch.object(bst, "_try_acquire_user_session_slot", lambda *a, **k: True))
        self.stack.enter_context(patch.object(bst, "_release_user_session_slot", lambda *a, **k: None))
        self.stack.enter_context(patch.object(bst, "_enforce_destination_policy", lambda *a, **k: None))

        # Patch the recording service symbols so no recording DDB table / real
        # AWS is needed. These are imported lazily inside the handler, so we
        # patch them at the SOURCE module.
        import app.services.ssh_session_recording as rec

        self.rec = rec
        self.start_calls = []
        self.append_calls = []
        self.stop_calls = []

        def _start(user_sub, **kwargs):
            self.start_calls.append((user_sub, kwargs))
            return {"recording_id": "rec_test_0233"}

        def _append(user_sub, recording_id, events):
            self.append_calls.append((user_sub, recording_id, events))
            return {}

        def _stop(user_sub, recording_id):
            self.stop_calls.append((user_sub, recording_id))
            return {}

        self.stack.enter_context(patch.object(rec, "start_recording", _start))
        self.stack.enter_context(patch.object(rec, "append_events", _append))
        self.stack.enter_context(patch.object(rec, "stop_recording", _stop))

        # Ensure the global feature flag is ON for these tests.
        from app.core.settings import S

        self.S = S
        prev_enabled = S.ssh_session_recording_enabled
        object.__setattr__(S, "ssh_session_recording_enabled", True)
        self.addCleanup(lambda: object.__setattr__(S, "ssh_session_recording_enabled", prev_enabled))
        prev_always = S.ssh_session_recording_always_record
        object.__setattr__(S, "ssh_session_recording_always_record", False)
        self.addCleanup(lambda: object.__setattr__(S, "ssh_session_recording_always_record", prev_always))

    def _make_bridge(self, outputs):
        """Bridge stub that yields the given output chunks one per poll."""
        chunks = list(outputs)

        class _StubBridge:
            def __init__(self, **kwargs):
                pass

            def connect(self):
                return None

            def poll_output(self):
                return chunks.pop(0) if chunks else ""

            def send_input(self, data):
                return None

            def resize(self, cols, rows):
                return None

            def close(self):
                return None

        return _StubBridge

    def _run(self, payload, bridge_cls, extra_msgs=None):
        msgs = [json.dumps({"type": "connect", "payload": payload})]
        for m in (extra_msgs or []):
            msgs.append(json.dumps(m))
        ws = _FakeWebSocket(msgs)
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            with patch.object(self.bst, "ParamikoSshBridge", bridge_cls):
                loop.run_until_complete(self.bst.browser_ssh_terminal_ws(ws))
        finally:
            loop.close()
            asyncio.set_event_loop(None)
        return ws

    def _seed_host(self, host_id, record_sessions):
        self.host_table.put_item(Item={
            "user_sub": self.USER,
            "sk": f"HOST#{host_id}",
            "host_id": host_id,
            "label": "h",
            "protocol": "ssh",
            "status": "offline",
            "record_sessions": record_sessions,
        })

    def test_recording_started_when_host_flag_true(self):
        """FAILS BEFORE FIX: handler never calls start_recording (count 0).
        PASSES AFTER FIX: start + append + stop are all invoked."""
        self._seed_host("h_rec_on", record_sessions=True)
        bridge = self._make_bridge(["$ echo hello\r\nhello\r\n"])
        self._run({
            "host": "10.0.0.1", "port": 22, "username": "alice",
            "authType": "password", "password": "pw",
            "host_id": "h_rec_on",
        }, bridge)

        self.assertEqual(len(self.start_calls), 1, "start_recording must be called once")
        start_kwargs = self.start_calls[0][1]
        self.assertEqual(start_kwargs.get("hostname"), "10.0.0.1")
        self.assertEqual(start_kwargs.get("host_id"), "h_rec_on")

        self.assertGreaterEqual(len(self.append_calls), 1, "append_events must capture output")
        _user, rec_id, events = self.append_calls[0]
        self.assertEqual(rec_id, "rec_test_0233")
        self.assertEqual(events[0][1], "o")
        self.assertIn("hello", events[0][2])

        self.assertEqual(len(self.stop_calls), 1, "stop_recording must finalize the session")

    def test_recording_not_started_when_host_flag_false(self):
        self._seed_host("h_rec_off", record_sessions=False)
        bridge = self._make_bridge(["some output\r\n"])
        self._run({
            "host": "10.0.0.2", "port": 22, "username": "alice",
            "authType": "password", "password": "pw",
            "host_id": "h_rec_off",
        }, bridge)

        self.assertEqual(len(self.start_calls), 0, "no recording when host flag is false")
        self.assertEqual(len(self.append_calls), 0)
        self.assertEqual(len(self.stop_calls), 0)

    def test_recording_not_started_without_host_id(self):
        bridge = self._make_bridge(["some output\r\n"])
        self._run({
            "host": "10.0.0.3", "port": 22, "username": "alice",
            "authType": "password", "password": "pw",
        }, bridge)
        self.assertEqual(len(self.start_calls), 0)

    def test_always_record_override_records_without_host_flag(self):
        object.__setattr__(self.S, "ssh_session_recording_always_record", True)
        bridge = self._make_bridge(["out\r\n"])
        self._run({
            "host": "10.0.0.4", "port": 22, "username": "alice",
            "authType": "password", "password": "pw",
        }, bridge)
        self.assertEqual(len(self.start_calls), 1,
                         "always-record override must start recording even without host flag")

    def test_recording_skipped_when_global_flag_off(self):
        object.__setattr__(self.S, "ssh_session_recording_enabled", False)
        self._seed_host("h_global_off", record_sessions=True)
        bridge = self._make_bridge(["out\r\n"])
        self._run({
            "host": "10.0.0.5", "port": 22, "username": "alice",
            "authType": "password", "password": "pw",
            "host_id": "h_global_off",
        }, bridge)
        self.assertEqual(len(self.start_calls), 0,
                         "global recording flag off must suppress recording")

    def test_recording_append_failure_does_not_break_session(self):
        """A recording append error must never interrupt the terminal stream."""
        self._seed_host("h_fail", record_sessions=True)

        def _boom(*a, **k):
            raise RuntimeError("ddb down")

        bridge = self._make_bridge(["hello\r\n"])
        with patch.object(self.rec, "append_events", _boom):
            ws = self._run({
                "host": "10.0.0.6", "port": 22, "username": "alice",
                "authType": "password", "password": "pw",
                "host_id": "h_fail",
            }, bridge)
        # Output was still forwarded to the browser despite the append failure.
        outputs = [m for m in ws.sent if m.get("type") == "output"]
        self.assertTrue(any("hello" in m["payload"].get("data", "") for m in outputs))
        # The session still finalized cleanly.
        self.assertEqual(len(self.stop_calls), 1)


if __name__ == "__main__":
    unittest.main()
