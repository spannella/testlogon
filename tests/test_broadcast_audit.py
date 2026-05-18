from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

from app.services import broadcast_audit


class _FakeAuditTable:
    def __init__(self):
        self.items = []

    def put_item(self, *, Item):
        self.items.append(Item)

    def query(self, **kwargs):
        items = self.items
        if kwargs.get("IndexName") == "ByActorCreatedAt":
            actor = kwargs["KeyConditionExpression"]._values[1]
            items = [i for i in items if i.get("actor") == actor]
        return {"Items": items}


def test_record_audit_persists_correlation_and_actor() -> None:
    table = _FakeAuditTable()
    with patch.object(broadcast_audit, "T", SimpleNamespace(broadcast_action_audit=table)):
        out = broadcast_audit.record_broadcast_action(
            action="create_session",
            actor="user-1",
            correlation_id="cid-1",
            resource_type="session",
            resource_id="s1",
            metadata={"stream_key_ref": "secret://x"},
        )
    assert out.actor == "user-1"
    assert out.correlation_id == "cid-1"
    assert table.items[0]["metadata"]["stream_key_ref"] == "secret://x"


def test_query_audit_by_actor_filter() -> None:
    table = _FakeAuditTable()
    table.put_item(Item={
        "audit_id": "a1",
        "action": "start_session",
        "actor": "admin-1",
        "correlation_id": "cid-1",
        "resource_type": "session",
        "resource_id": "s1",
        "created_at": "2026-03-26T00:00:00+00:00",
        "metadata": {},
        "scope": "ALL",
    })
    table.put_item(Item={
        "audit_id": "a2",
        "action": "stop_session",
        "actor": "admin-2",
        "correlation_id": "cid-2",
        "resource_type": "session",
        "resource_id": "s2",
        "created_at": "2026-03-26T00:01:00+00:00",
        "metadata": {},
        "scope": "ALL",
    })
    with patch.object(broadcast_audit, "T", SimpleNamespace(broadcast_action_audit=table)):
        out = broadcast_audit.query_broadcast_actions(actor="admin-1", limit=10)
    assert len(out) == 1
    assert out[0].actor == "admin-1"
