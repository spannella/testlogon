"""Unit tests for CALL-007: call ringing timeout and missed-call handling."""
from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from app.services import messaging_call_lifecycle as lifecycle
from app.services import messaging_call_sessions as sessions


@dataclass
class _FakeCallSessionTable:
    items: dict[str, dict] = field(default_factory=dict)

    def put_item(self, *, Item):
        self.items[str(Item["call_id"])] = dict(Item)

    def get_item(self, *, Key):
        item = self.items.get(str(Key["call_id"]))
        return {"Item": dict(item)} if item else {}

    def query(self, **kwargs):
        conv_id = (kwargs.get("ExpressionAttributeValues") or {}).get(":conversation_id")
        items = [item for item in self.items.values() if item.get("conversation_id") == conv_id]
        items.sort(key=lambda i: int(i.get("start_ts_sort") or 0), reverse=not kwargs.get("ScanIndexForward", False))
        limit = int(kwargs.get("Limit") or len(items))
        return {"Items": items[:limit]}

    def scan(self, **kwargs):
        """Simple scan that applies FilterExpression as a lambda."""
        items = list(self.items.values())
        # For our tests, we don't need to evaluate FilterExpression — return all items
        return {"Items": items}


_clock = 1700000000


def _patch_store(monkeypatch, *, clock_offset=0):
    table = _FakeCallSessionTable()
    emitted: list[dict] = []
    ts = _clock + clock_offset
    monkeypatch.setattr(sessions, "_table", lambda: table)
    monkeypatch.setattr(sessions, "now_ts", lambda: ts)
    monkeypatch.setattr(lifecycle, "now_ts", lambda: ts + 1)

    def timeline_emitter(**kwargs):
        emitted.append(dict(kwargs))
        return kwargs

    return table, emitted, timeline_emitter


def _create_invited_call(monkeypatch, call_id="c1", clock_offset=0):
    """Helper: create an invited call and return (table, emitted, timeline_emitter)."""
    table, emitted, timeline_emitter = _patch_store(monkeypatch, clock_offset=clock_offset)
    participants = {"caller", "callee"}
    lifecycle.create_invite(
        call_id=call_id,
        conversation_id="conv1",
        actor_user_id="caller",
        caller_user_id="caller",
        callee_user_id="callee",
        initial_mode="audio",
        participant_resolver=lambda _cid: participants,
        timeline_emitter=timeline_emitter,
    )
    return table, emitted, timeline_emitter


class TestTimeoutCallTransition:
    """timeout_call transitions invited -> missed."""

    def test_transitions_invited_to_missed(self, monkeypatch):
        _table, emitted, timeline_emitter = _create_invited_call(monkeypatch)
        record, event = lifecycle.timeout_call(
            call_id="c1",
            actor_user_id="caller",
            reason="no_answer",
            timeline_emitter=timeline_emitter,
        )
        assert record.state == "missed"
        assert event.event_type == "call.missed"
        assert event.from_state == "invited"
        assert event.to_state == "missed"

    def test_sets_end_reason_no_answer(self, monkeypatch):
        _table, emitted, timeline_emitter = _create_invited_call(monkeypatch)
        record, event = lifecycle.timeout_call(
            call_id="c1",
            actor_user_id="caller",
            reason="no_answer",
            timeline_emitter=timeline_emitter,
        )
        assert record.end_reason == "no_answer"
        assert record.end_ts is not None

    def test_emits_timeline_event_missed_call(self, monkeypatch):
        _table, emitted, timeline_emitter = _create_invited_call(monkeypatch)
        lifecycle.timeout_call(
            call_id="c1",
            actor_user_id="caller",
            reason="no_answer",
            timeline_emitter=timeline_emitter,
        )
        missed_events = [e for e in emitted if e.get("event_type") == "call.missed"]
        assert len(missed_events) == 1
        assert missed_events[0]["call_state"] == "missed"

    def test_returns_409_if_already_declined(self, monkeypatch):
        _table, emitted, timeline_emitter = _create_invited_call(monkeypatch)
        # First decline the call
        lifecycle.decline_invite(
            call_id="c1",
            actor_user_id="callee",
            reason="declined",
            timeline_emitter=timeline_emitter,
        )
        # Now try to timeout — should raise
        with pytest.raises(lifecycle.CallLifecycleError) as exc_info:
            lifecycle.timeout_call(
                call_id="c1",
                actor_user_id="caller",
                reason="no_answer",
                timeline_emitter=timeline_emitter,
            )
        assert exc_info.value.code == "invalid_state_transition"

    def test_returns_409_if_already_ended(self, monkeypatch):
        _table, emitted, timeline_emitter = _create_invited_call(monkeypatch)
        # Accept then end
        lifecycle.accept_invite(call_id="c1", actor_user_id="callee", timeline_emitter=timeline_emitter)
        lifecycle.end_call(call_id="c1", actor_user_id="caller", timeline_emitter=timeline_emitter)
        with pytest.raises(lifecycle.CallLifecycleError) as exc_info:
            lifecycle.timeout_call(
                call_id="c1",
                actor_user_id="caller",
                reason="no_answer",
                timeline_emitter=timeline_emitter,
            )
        assert exc_info.value.code == "invalid_state_transition"

    def test_only_caller_or_system_can_timeout(self, monkeypatch):
        _table, emitted, timeline_emitter = _create_invited_call(monkeypatch)
        with pytest.raises(lifecycle.CallLifecycleError) as exc_info:
            lifecycle.timeout_call(
                call_id="c1",
                actor_user_id="callee",
                reason="no_answer",
                timeline_emitter=timeline_emitter,
            )
        assert exc_info.value.code == "forbidden"

    def test_system_actor_can_timeout(self, monkeypatch):
        _table, emitted, timeline_emitter = _create_invited_call(monkeypatch)
        record, event = lifecycle.timeout_call(
            call_id="c1",
            actor_user_id="system",
            reason="server_timeout",
            timeline_emitter=timeline_emitter,
        )
        assert record.state == "missed"
        assert record.end_reason == "server_timeout"

    def test_idempotency_key_prevents_duplicate_transitions(self, monkeypatch):
        _table, emitted, timeline_emitter = _create_invited_call(monkeypatch)
        record1, event1 = lifecycle.timeout_call(
            call_id="c1",
            actor_user_id="caller",
            reason="no_answer",
            idempotency_key="idem1",
            timeline_emitter=timeline_emitter,
        )
        # Second call with same idempotency key should return same result (no error)
        record2, event2 = lifecycle.timeout_call(
            call_id="c1",
            actor_user_id="caller",
            reason="no_answer",
            idempotency_key="idem1",
            timeline_emitter=timeline_emitter,
        )
        assert record2.call_id == record1.call_id
        assert record2.state == "missed"

    def test_call_not_found_raises_404(self, monkeypatch):
        _patch_store(monkeypatch)
        with pytest.raises(lifecycle.CallLifecycleError) as exc_info:
            lifecycle.timeout_call(
                call_id="nonexistent",
                actor_user_id="caller",
                reason="no_answer",
            )
        assert exc_info.value.code == "call_not_found"


class TestTimeoutCallEndpoint:
    """Test the /messages/calls/{call_id}/timeout HTTP endpoint."""

    def test_endpoint_returns_200_on_success(self, monkeypatch):
        table, emitted, timeline_emitter = _create_invited_call(monkeypatch)

        from app.routers import messaging as msg_module
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        # fanout_event_to_conversation queries tbl_parts (DDB) — patch to no-op
        # (added after test was written; GAP-0142 wired fanout into timeout endpoint)
        monkeypatch.setattr(msg_module, "fanout_event_to_conversation", lambda *a, **kw: None)

        app = FastAPI()
        app.include_router(msg_module.router)

        # Override dependency
        async def override_user_id():
            return "caller"

        app.dependency_overrides[msg_module.get_messaging_user_id] = override_user_id

        client = TestClient(app)
        resp = client.post("/messaging/messages/calls/c1/timeout", json={"reason": "no_answer"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["state"] == "missed"
        assert data["call_id"] == "c1"
        assert data["reason"] == "no_answer"

    def test_endpoint_returns_404_for_nonexistent(self, monkeypatch):
        _patch_store(monkeypatch)

        from app.routers import messaging as msg_module
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        app = FastAPI()
        app.include_router(msg_module.router)

        async def override_user_id():
            return "caller"

        app.dependency_overrides[msg_module.get_messaging_user_id] = override_user_id

        client = TestClient(app)
        resp = client.post("/messaging/messages/calls/nonexistent/timeout", json={"reason": "no_answer"})
        assert resp.status_code == 404

    def test_endpoint_returns_409_for_terminal_state(self, monkeypatch):
        _table, emitted, timeline_emitter = _create_invited_call(monkeypatch)
        # Decline first
        lifecycle.decline_invite(call_id="c1", actor_user_id="callee", timeline_emitter=timeline_emitter)

        from app.routers import messaging as msg_module
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        app = FastAPI()
        app.include_router(msg_module.router)

        async def override_user_id():
            return "caller"

        app.dependency_overrides[msg_module.get_messaging_user_id] = override_user_id

        client = TestClient(app)
        resp = client.post("/messaging/messages/calls/c1/timeout", json={"reason": "no_answer"})
        assert resp.status_code == 409


class TestExpireStaleInvites:
    """Test the server-side background timeout for stale invites."""

    def test_server_timeout_finds_stale_invites(self, monkeypatch):
        import asyncio
        table, emitted, timeline_emitter = _patch_store(monkeypatch)
        # Create a call session directly in "invited" with old start_ts
        old_ts = _clock - 60  # 60 seconds ago (past the 30s timeout)
        table.items["stale_call"] = {
            "call_id": "stale_call",
            "conversation_id": "conv_stale",
            "caller_user_id": "caller",
            "callee_user_id": "callee",
            "initial_mode": "audio",
            "state": "invited",
            "start_ts": old_ts,
            "start_ts_sort": old_ts,
            "updated_at": old_ts,
            "lifecycle_events": [],
            "idempotency_records": {},
        }

        from app.routers.messaging import _expire_stale_invites
        asyncio.run(_expire_stale_invites())

        # Check the call session was transitioned to missed
        updated = sessions.get_call_session("stale_call")
        assert updated is not None
        assert updated.state == "missed"

    def test_server_timeout_is_idempotent(self, monkeypatch):
        import asyncio
        table, emitted, timeline_emitter = _patch_store(monkeypatch)
        old_ts = _clock - 60
        table.items["stale_call2"] = {
            "call_id": "stale_call2",
            "conversation_id": "conv_stale2",
            "caller_user_id": "caller",
            "callee_user_id": "callee",
            "initial_mode": "audio",
            "state": "invited",
            "start_ts": old_ts,
            "start_ts_sort": old_ts,
            "updated_at": old_ts,
            "lifecycle_events": [],
            "idempotency_records": {},
        }

        from app.routers.messaging import _expire_stale_invites
        # Run twice — should not raise
        asyncio.run(_expire_stale_invites())
        asyncio.run(_expire_stale_invites())

        updated = sessions.get_call_session("stale_call2")
        assert updated is not None
        assert updated.state == "missed"


class TestTimeoutSetting:
    """Setting controls timeout threshold."""

    def test_setting_default_is_30(self):
        from app.core.settings import S
        assert S.messaging_webrtc_call_ringing_timeout_seconds == 30


class TestTimelinePreviewForMissed:
    """Timeline preview shows 'Missed call' for call.missed events."""

    def test_preview_for_missed_event(self):
        from app.services.messaging_call_timeline import _preview_for_event
        preview = _preview_for_event(event_type="call.missed", call_state="missed", reason="no_answer")
        assert preview == "Missed call"
