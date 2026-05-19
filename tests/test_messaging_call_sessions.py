from __future__ import annotations

from dataclasses import dataclass, field

from app.services import messaging_call_sessions as svc


@dataclass
class _FakeCallSessionTable:
    items: dict[str, dict] = field(default_factory=dict)

    def put_item(self, *, Item):
        self.items[str(Item["call_id"])] = dict(Item)

    def get_item(self, *, Key):
        item = self.items.get(str(Key["call_id"]))
        return {"Item": dict(item)} if item else {}

    def query(self, *, IndexName, KeyConditionExpression, ExpressionAttributeValues, ScanIndexForward, Limit):
        assert IndexName == "ByConversationStartedAt"
        conversation_id = ExpressionAttributeValues[":conversation_id"]
        rows = [v for v in self.items.values() if v.get("conversation_id") == conversation_id]
        rows.sort(key=lambda r: int(r.get("start_ts_sort") or 0), reverse=not ScanIndexForward)
        return {"Items": rows[:Limit]}


def _patch_table(monkeypatch):
    table = _FakeCallSessionTable()

    monkeypatch.setattr(svc, "_table", lambda: table)
    monkeypatch.setattr(svc, "now_ts", lambda: 1700000000)
    return table


def test_create_and_get_call_session(monkeypatch):
    _patch_table(monkeypatch)
    created = svc.create_call_session(
        call_id="call-1",
        conversation_id="conv-1",
        caller_user_id="u-a",
        callee_user_id="u-b",
        initial_mode="video",
    )
    fetched = svc.get_call_session("call-1")

    assert created.call_id == "call-1"
    assert created.start_ts == 1700000000
    assert fetched is not None
    assert fetched.conversation_id == "conv-1"
    assert fetched.state == "invited"


def test_update_call_session_state_persists_timestamps(monkeypatch):
    _patch_table(monkeypatch)
    svc.create_call_session(
        call_id="call-2",
        conversation_id="conv-1",
        caller_user_id="u-a",
        callee_user_id="u-b",
        initial_mode="audio",
    )

    updated = svc.update_call_session_state(
        call_id="call-2",
        state="connected",
        connect_ts=1700000005,
        network_path="turn",
    )
    assert updated is not None
    assert updated.state == "connected"
    assert updated.connect_ts == 1700000005
    assert updated.network_path == "turn"
    assert updated.updated_at == 1700000000


def test_list_call_sessions_for_conversation_descending(monkeypatch):
    _patch_table(monkeypatch)
    svc.create_call_session(
        call_id="call-3",
        conversation_id="conv-1",
        caller_user_id="u-a",
        callee_user_id="u-b",
        initial_mode="audio",
        start_ts=100,
    )
    svc.create_call_session(
        call_id="call-4",
        conversation_id="conv-1",
        caller_user_id="u-a",
        callee_user_id="u-b",
        initial_mode="audio",
        start_ts=200,
    )
    svc.create_call_session(
        call_id="call-5",
        conversation_id="conv-2",
        caller_user_id="u-a",
        callee_user_id="u-b",
        initial_mode="audio",
        start_ts=300,
    )

    rows = svc.list_call_sessions_for_conversation("conv-1", limit=10)
    assert [r.call_id for r in rows] == ["call-4", "call-3"]


def test_update_missing_call_returns_none(monkeypatch):
    _patch_table(monkeypatch)
    assert svc.update_call_session_state(call_id="missing", state="ended") is None
