from __future__ import annotations

from dataclasses import dataclass, field

from app.services import messaging_call_timeline as timeline


@dataclass
class _FakeTable:
    items: list[dict] = field(default_factory=list)
    updates: list[dict] = field(default_factory=list)

    def put_item(self, *, Item, ConditionExpression=None):
        self.items.append(dict(Item))

    def update_item(self, **kwargs):
        self.updates.append(dict(kwargs))


def test_emit_call_timeline_event_persists_message_and_archive_payload(monkeypatch):
    msgs = _FakeTable()
    convs = _FakeTable()
    archive_calls: list[dict] = []

    monkeypatch.setattr(timeline, "_messages_table", lambda: msgs)
    monkeypatch.setattr(timeline, "_conversations_table", lambda: convs)
    item = timeline.emit_call_timeline_event(
        call_id="call-1",
        conversation_id="conv-1",
        actor_user_id="u-1",
        event_type="call.end",
        call_state="ended",
        reason="ended",
        event_ts=1700000100,
        extra_payload={"network_path": "turn"},
        archive_emitter=lambda **kwargs: archive_calls.append(dict(kwargs)) or "ok",
    )

    assert item["conversation_id"] == "conv-1"
    assert item["subtype"] == "call_lifecycle"
    assert item["call_id"] == "call-1"
    assert item["call_event_type"] == "call.end"
    assert item["timeline_state"]["network_path"] == "turn"

    assert len(msgs.items) == 1
    assert len(convs.updates) == 1
    assert len(archive_calls) == 1
    assert archive_calls[0]["event_type"] == "call.lifecycle"
    assert archive_calls[0]["payload"]["call_id"] == "call-1"
    assert archive_calls[0]["payload"]["call_event_type"] == "call.end"
