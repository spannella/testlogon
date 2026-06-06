"""Regression test for GAP-0142.

When a WebRTC call invite times out — either via the HTTP timeout endpoint or
the server-side ``_expire_stale_invites`` backstop — a ``call.missed`` SSE event
must be fanned out to the conversation participants so the callee dismisses the
ringing overlay in real time (instead of waiting for the next SSE poll).

Fails-before: neither the endpoint nor the backstop called
``fanout_event_to_conversation`` after ``timeout_call``.
Passes-after: both call sites fan out a ``call.missed`` event.

Fully offline: the call-session store is replaced with an in-memory fake and
``fanout_event_to_conversation`` is monkeypatched to record its kwargs, so no
real AWS / DynamoDB access occurs.
"""
from __future__ import annotations

from dataclasses import dataclass, field

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
        items = [i for i in self.items.values() if i.get("conversation_id") == conv_id]
        items.sort(
            key=lambda i: int(i.get("start_ts_sort") or 0),
            reverse=not kwargs.get("ScanIndexForward", False),
        )
        limit = int(kwargs.get("Limit") or len(items))
        return {"Items": items[:limit]}

    def scan(self, **kwargs):
        # Tests rely on a single stale item; return everything.
        return {"Items": list(self.items.values())}


_CLOCK = 1700000000


def _patch_store(monkeypatch):
    table = _FakeCallSessionTable()
    emitted: list[dict] = []
    monkeypatch.setattr(sessions, "_table", lambda: table)
    monkeypatch.setattr(sessions, "now_ts", lambda: _CLOCK)
    monkeypatch.setattr(lifecycle, "now_ts", lambda: _CLOCK + 1)

    def timeline_emitter(**kwargs):
        emitted.append(dict(kwargs))
        return kwargs

    return table, emitted, timeline_emitter


def _seed_invited_call(table, *, call_id, conversation_id, start_ts):
    table.items[call_id] = {
        "call_id": call_id,
        "conversation_id": conversation_id,
        "caller_user_id": "caller",
        "callee_user_id": "callee",
        "initial_mode": "audio",
        "state": "invited",
        "start_ts": start_ts,
        "start_ts_sort": start_ts,
        "updated_at": start_ts,
        "lifecycle_events": [],
        "idempotency_records": {},
    }


def _record_fanout(monkeypatch):
    """Replace fanout_event_to_conversation with a recorder; return the list."""
    from app.routers import messaging as msg_module

    fanout_calls: list[dict] = []

    def mock_fanout(**kwargs):
        fanout_calls.append(kwargs)

    monkeypatch.setattr(msg_module, "fanout_event_to_conversation", mock_fanout)
    return fanout_calls


def test_timeout_endpoint_fans_out_call_missed(monkeypatch):
    import asyncio

    table, _emitted, _emitter = _patch_store(monkeypatch)
    _seed_invited_call(table, call_id="c1", conversation_id="conv1", start_ts=_CLOCK)

    from app.routers import messaging as msg_module

    fanout_calls = _record_fanout(monkeypatch)

    # Invoke the endpoint coroutine directly (offline; avoids TestClient/httpx
    # version coupling). This still exercises the exact fanout code path.
    result = asyncio.get_event_loop().run_until_complete(
        msg_module.timeout_call_endpoint(
            call_id="c1",
            body=msg_module.CallTimeoutIn(reason="no_answer"),
            user_id="caller",
        )
    )
    assert result.state == "missed"
    assert result.call_id == "c1"

    # FAILS-BEFORE: no fanout call recorded.
    missed = [c for c in fanout_calls if c.get("event_type") == "call.missed"]
    assert len(missed) == 1, "timeout endpoint must fan out exactly one call.missed event"
    payload = missed[0]["payload"]
    assert missed[0]["conversation_id"] == "conv1"
    assert payload["call_id"] == "c1"
    assert payload["caller_user_id"] == "caller"
    assert payload["callee_user_id"] == "callee"
    assert missed[0]["respect_mute"] is False


def test_expire_stale_invites_fans_out_call_missed(monkeypatch):
    import asyncio

    table, _emitted, _emitter = _patch_store(monkeypatch)
    # start_ts well past the 30s ringing timeout.
    _seed_invited_call(table, call_id="stale", conversation_id="conv_stale", start_ts=_CLOCK - 60)

    from app.routers import messaging as msg_module

    fanout_calls = _record_fanout(monkeypatch)

    asyncio.get_event_loop().run_until_complete(msg_module._expire_stale_invites())

    # Transition still happened.
    updated = sessions.get_call_session("stale")
    assert updated is not None and updated.state == "missed"

    # FAILS-BEFORE: backstop never fanned out.
    missed = [c for c in fanout_calls if c.get("event_type") == "call.missed"]
    assert len(missed) == 1, "backstop must fan out call.missed for each expired invite"
    assert missed[0]["conversation_id"] == "conv_stale"
    assert missed[0]["sender_id"] == "system"
    assert missed[0]["payload"]["call_id"] == "stale"
