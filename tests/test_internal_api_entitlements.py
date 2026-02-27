from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.services import internal_api_entitlements as svc


class _EntitlementsTable:
    name = "entitlements"

    def __init__(self, items):
        self.items = items

    def query(self, **kwargs):
        expr = kwargs["KeyConditionExpression"]
        user_id = expr._values[-1]
        return {"Items": [i for i in self.items if i.get("user_id") == user_id]}


class _UsageEventsTable:
    name = "entitlement_usage_events"

    def __init__(self):
        self.by_entitlement = {}

    def query(self, **kwargs):
        expr = kwargs["KeyConditionExpression"]
        entitlement_id = expr._values[-1]
        return {"Items": list(self.by_entitlement.get(entitlement_id, []))}


class _Client:
    def __init__(self, usage_events: _UsageEventsTable):
        self.usage_events = usage_events
        self.raise_exhausted = False

    def transact_write_items(self, **kwargs):
        if self.raise_exhausted:
            from botocore.exceptions import ClientError

            raise ClientError({"Error": {"Code": "TransactionCanceledException", "Message": "ConditionalCheckFailed"}}, "TransactWriteItems")
        put = kwargs["TransactItems"][0]["Put"]["Item"]
        entitlement_id = put["entitlement_id"]["S"]
        event = {
            "entitlement_id": entitlement_id,
            "event_id": put["event_id"]["S"],
            "idempotency_key": put["idempotency_key"]["S"],
            "meter": put["meter"]["S"],
            "amount": int(put["amount"]["N"]),
            "timestamp": put["timestamp"]["S"],
        }
        self.usage_events.by_entitlement.setdefault(entitlement_id, []).append(event)


def _active_entitlement(*, entitlement_id: str = "e1", usage_limit: int = 10, scope=None):
    now = datetime.now(timezone.utc)
    return {
        "entitlement_id": entitlement_id,
        "user_id": "u1",
        "product_type": "internal_api_package",
        "status": "active",
        "starts_at": (now - timedelta(minutes=1)).isoformat(),
        "ends_at": (now + timedelta(minutes=10)).isoformat(),
        "usage_limit": usage_limit,
        "scope": scope or {"internal_namespaces": ["messaging.*"], "allowed_actions": ["send_message"]},
    }


def test_internal_entitlement_allowed_and_usage_event_queryable(monkeypatch: pytest.MonkeyPatch) -> None:
    usage_events = _UsageEventsTable()
    entitlements = _EntitlementsTable([_active_entitlement()])
    client = _Client(usage_events)

    monkeypatch.setattr(svc, "T", SimpleNamespace(entitlements=entitlements, entitlement_usage_events=usage_events))
    monkeypatch.setattr(svc, "ddb", SimpleNamespace(meta=SimpleNamespace(client=client)))
    monkeypatch.setattr(svc, "S", SimpleNamespace(catalog_commercialization_enabled=True))

    out = svc.enforce_internal_api_entitlement(
        user_id="u1",
        namespace="messaging",
        action="send_message",
        request_id="req-1",
    )
    assert out["allowed"] is True
    assert out["entitlement_id"] == "e1"
    assert out["meter"] == "messaging.message.send.count"

    events = svc.list_usage_events_for_entitlement("e1")
    assert len(events) == 1
    assert events[0]["meter"] == "messaging.message.send.count"


def test_internal_entitlement_denied_when_missing_namespace(monkeypatch: pytest.MonkeyPatch) -> None:
    usage_events = _UsageEventsTable()
    entitlements = _EntitlementsTable([_active_entitlement(scope={"internal_namespaces": ["filemanager.*"]})])
    client = _Client(usage_events)

    monkeypatch.setattr(svc, "T", SimpleNamespace(entitlements=entitlements, entitlement_usage_events=usage_events))
    monkeypatch.setattr(svc, "ddb", SimpleNamespace(meta=SimpleNamespace(client=client)))
    monkeypatch.setattr(svc, "S", SimpleNamespace(catalog_commercialization_enabled=True))

    with pytest.raises(HTTPException) as exc:
        svc.enforce_internal_api_entitlement(
            user_id="u1",
            namespace="messaging",
            action="send_message",
            request_id="req-2",
        )
    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == "internal_api_entitlement_denied"
    assert exc.value.detail["reason"] == "no_entitlement"


def test_internal_entitlement_exhausted(monkeypatch: pytest.MonkeyPatch) -> None:
    usage_events = _UsageEventsTable()
    entitlements = _EntitlementsTable([_active_entitlement(usage_limit=1)])
    client = _Client(usage_events)
    client.raise_exhausted = True

    monkeypatch.setattr(svc, "T", SimpleNamespace(entitlements=entitlements, entitlement_usage_events=usage_events))
    monkeypatch.setattr(svc, "ddb", SimpleNamespace(meta=SimpleNamespace(client=client)))
    monkeypatch.setattr(svc, "S", SimpleNamespace(catalog_commercialization_enabled=True))

    with pytest.raises(HTTPException) as exc:
        svc.enforce_internal_api_entitlement(
            user_id="u1",
            namespace="messaging",
            action="send_message",
            request_id="req-3",
        )
    assert exc.value.detail["reason"] == "exhausted"


def test_filemanager_action_records_meter_and_entitlement_id(monkeypatch: pytest.MonkeyPatch) -> None:
    usage_events = _UsageEventsTable()
    entitlements = _EntitlementsTable(
        [
            _active_entitlement(
                entitlement_id="fm-ent-1",
                scope={"internal_namespaces": ["filemanager.*"], "allowed_actions": ["download_file"]},
            )
        ]
    )
    client = _Client(usage_events)

    monkeypatch.setattr(svc, "T", SimpleNamespace(entitlements=entitlements, entitlement_usage_events=usage_events))
    monkeypatch.setattr(svc, "ddb", SimpleNamespace(meta=SimpleNamespace(client=client)))
    monkeypatch.setattr(svc, "S", SimpleNamespace(catalog_commercialization_enabled=True))

    out = svc.enforce_internal_api_entitlement(
        user_id="u1",
        namespace="filemanager",
        action="download_file",
        request_id="req-fm-1",
    )
    assert out["entitlement_id"] == "fm-ent-1"
    assert out["meter"] == "filemanager.file.download.bytes"

    events = svc.list_usage_events_for_entitlement("fm-ent-1")
    assert len(events) == 1
    assert events[0]["meter"] == "filemanager.file.download.bytes"


def test_internal_entitlement_bypassed_when_family_flag_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    usage_events = _UsageEventsTable()
    entitlements = _EntitlementsTable([_active_entitlement()])
    client = _Client(usage_events)

    monkeypatch.setattr(svc, "T", SimpleNamespace(entitlements=entitlements, entitlement_usage_events=usage_events))
    monkeypatch.setattr(svc, "ddb", SimpleNamespace(meta=SimpleNamespace(client=client)))
    monkeypatch.setattr(svc, "S", SimpleNamespace(catalog_commercialization_enabled=True, catalog_internal_api_package_enabled=False))

    out = svc.enforce_internal_api_entitlement(user_id="u1", namespace="messaging", action="send_message", request_id="req-off")
    assert out["enforced"] is False
