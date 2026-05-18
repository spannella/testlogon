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


def _patch_store(monkeypatch):
    table = _FakeCallSessionTable()
    emitted: list[dict] = []
    monkeypatch.setattr(sessions, "_table", lambda: table)
    monkeypatch.setattr(sessions, "now_ts", lambda: 1700000000)
    monkeypatch.setattr(lifecycle, "now_ts", lambda: 1700000001)

    def timeline_emitter(**kwargs):
        emitted.append(dict(kwargs))
        return kwargs

    return table, emitted, timeline_emitter


def test_create_accept_end_happy_path(monkeypatch):
    _table, emitted, timeline_emitter = _patch_store(monkeypatch)
    participants = {"caller", "callee"}

    created, ev1 = lifecycle.create_invite(
        call_id="c1",
        conversation_id="conv1",
        actor_user_id="caller",
        caller_user_id="caller",
        callee_user_id="callee",
        initial_mode="audio",
        participant_resolver=lambda _cid: participants,
        timeline_emitter=timeline_emitter,
    )
    assert created.state == "invited"
    assert ev1.event_type == "call.invite"

    accepted, ev2 = lifecycle.accept_invite(call_id="c1", actor_user_id="callee", timeline_emitter=timeline_emitter)
    assert accepted.state == "accepted"
    assert ev2.from_state == "invited"

    ended, ev3 = lifecycle.end_call(call_id="c1", actor_user_id="caller", timeline_emitter=timeline_emitter)
    assert ended.state == "ended"
    assert ev3.to_state == "ended"
    assert len(ended.lifecycle_events or []) == 3
    assert [e["event_type"] for e in emitted] == ["call.invite", "call.accept", "call.end"]


def test_decline_requires_callee(monkeypatch):
    _table, _emitted, timeline_emitter = _patch_store(monkeypatch)
    lifecycle.create_invite(
        call_id="c2",
        conversation_id="conv1",
        actor_user_id="caller",
        caller_user_id="caller",
        callee_user_id="callee",
        initial_mode="video",
        participant_resolver=lambda _cid: {"caller", "callee"},
        timeline_emitter=timeline_emitter,
    )

    with pytest.raises(lifecycle.CallLifecycleError) as exc:
        lifecycle.decline_invite(call_id="c2", actor_user_id="caller", timeline_emitter=timeline_emitter)
    assert exc.value.code == "forbidden"


def test_invalid_transition_rejected(monkeypatch):
    _table, _emitted, timeline_emitter = _patch_store(monkeypatch)
    lifecycle.create_invite(
        call_id="c3",
        conversation_id="conv1",
        actor_user_id="caller",
        caller_user_id="caller",
        callee_user_id="callee",
        initial_mode="audio",
        participant_resolver=lambda _cid: {"caller", "callee"},
        timeline_emitter=timeline_emitter,
    )
    lifecycle.decline_invite(call_id="c3", actor_user_id="callee", reason="declined", timeline_emitter=timeline_emitter)

    with pytest.raises(lifecycle.CallLifecycleError) as exc:
        lifecycle.accept_invite(call_id="c3", actor_user_id="callee", timeline_emitter=timeline_emitter)
    assert exc.value.code == "invalid_state_transition"


def test_participant_authorization_enforced_on_invite(monkeypatch):
    _table, _emitted, timeline_emitter = _patch_store(monkeypatch)

    with pytest.raises(lifecycle.CallLifecycleError) as exc:
        lifecycle.create_invite(
            call_id="c4",
            conversation_id="conv1",
            actor_user_id="caller",
            caller_user_id="caller",
            callee_user_id="outside-user",
            initial_mode="audio",
            participant_resolver=lambda _cid: {"caller", "callee"},
            timeline_emitter=timeline_emitter,
        )
    assert exc.value.code == "forbidden"


def test_invite_idempotency_retries_are_deterministic(monkeypatch):
    _table, emitted, timeline_emitter = _patch_store(monkeypatch)
    kwargs = dict(
        call_id="c5",
        conversation_id="conv1",
        actor_user_id="caller",
        caller_user_id="caller",
        callee_user_id="callee",
        initial_mode="audio",
        participant_resolver=lambda _cid: {"caller", "callee"},
        idempotency_key="idem-invite-1",
        timeline_emitter=timeline_emitter,
    )

    first_record, _ = lifecycle.create_invite(**kwargs)
    second_record, _ = lifecycle.create_invite(**kwargs)

    assert first_record.call_id == second_record.call_id
    assert first_record.state == second_record.state == "invited"
    assert len(second_record.lifecycle_events or []) == 1
    assert len(emitted) == 1


def test_accept_and_end_idempotency_do_not_duplicate_events(monkeypatch):
    _table, emitted, timeline_emitter = _patch_store(monkeypatch)
    lifecycle.create_invite(
        call_id="c6",
        conversation_id="conv1",
        actor_user_id="caller",
        caller_user_id="caller",
        callee_user_id="callee",
        initial_mode="audio",
        participant_resolver=lambda _cid: {"caller", "callee"},
        timeline_emitter=timeline_emitter,
    )

    rec1, _ = lifecycle.accept_invite(
        call_id="c6", actor_user_id="callee", idempotency_key="idem-accept-1", timeline_emitter=timeline_emitter
    )
    rec2, _ = lifecycle.accept_invite(
        call_id="c6", actor_user_id="callee", idempotency_key="idem-accept-1", timeline_emitter=timeline_emitter
    )
    assert rec1.state == rec2.state == "accepted"
    assert len(rec2.lifecycle_events or []) == 2

    rec3, _ = lifecycle.end_call(
        call_id="c6", actor_user_id="caller", idempotency_key="idem-end-1", timeline_emitter=timeline_emitter
    )
    rec4, _ = lifecycle.end_call(
        call_id="c6", actor_user_id="caller", idempotency_key="idem-end-1", timeline_emitter=timeline_emitter
    )
    assert rec3.state == rec4.state == "ended"
    assert len(rec4.lifecycle_events or []) == 3
    assert [e["event_type"] for e in emitted] == ["call.invite", "call.accept", "call.end"]


def test_idempotency_conflict_reused_for_different_action(monkeypatch):
    _table, _emitted, timeline_emitter = _patch_store(monkeypatch)
    lifecycle.create_invite(
        call_id="c7",
        conversation_id="conv1",
        actor_user_id="caller",
        caller_user_id="caller",
        callee_user_id="callee",
        initial_mode="audio",
        participant_resolver=lambda _cid: {"caller", "callee"},
        idempotency_key="idem-shared",
        timeline_emitter=timeline_emitter,
    )

    with pytest.raises(lifecycle.CallLifecycleError) as exc:
        lifecycle.accept_invite(call_id="c7", actor_user_id="callee", idempotency_key="idem-shared", timeline_emitter=timeline_emitter)
    assert exc.value.code == "idempotency_conflict"


def test_competing_invites_reject_when_callee_already_busy(monkeypatch):
    _table, _emitted, timeline_emitter = _patch_store(monkeypatch)
    lifecycle.create_invite(
        call_id="c8",
        conversation_id="conv1",
        actor_user_id="caller-a",
        caller_user_id="caller-a",
        callee_user_id="callee",
        initial_mode="audio",
        participant_resolver=lambda _cid: {"caller-a", "caller-b", "callee"},
        timeline_emitter=timeline_emitter,
    )

    with pytest.raises(lifecycle.CallLifecycleError) as exc:
        lifecycle.create_invite(
            call_id="c9",
            conversation_id="conv1",
            actor_user_id="caller-b",
            caller_user_id="caller-b",
            callee_user_id="callee",
            initial_mode="video",
            participant_resolver=lambda _cid: {"caller-a", "caller-b", "callee"},
            timeline_emitter=timeline_emitter,
        )

    assert exc.value.code == "callee_busy"
