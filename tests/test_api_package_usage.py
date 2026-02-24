from __future__ import annotations

from types import SimpleNamespace

from botocore.exceptions import ClientError

from app.services import api_package_usage as svc


class _EntitlementsTable:
    def __init__(self, items):
        self.items = items
        self.update_calls = []
        self.seen_markers = set()

    def query(self, **_kwargs):
        return {"Items": list(self.items)}

    def update_item(self, **kwargs):
        marker = kwargs["ExpressionAttributeValues"][":marker_val"]
        if marker in self.seen_markers:
            raise ClientError({"Error": {"Code": "ConditionalCheckFailedException"}}, "UpdateItem")
        self.seen_markers.add(marker)
        self.update_calls.append(kwargs)


class _UsageEventsTable:
    def __init__(self, by_entitlement):
        self.by_entitlement = by_entitlement

    def query(self, **kwargs):
        expr = kwargs["KeyConditionExpression"]
        entitlement_id = expr._values[-1]
        return {"Items": list(self.by_entitlement.get(entitlement_id, []))}


def test_list_api_package_usage_reconciles_ledger(monkeypatch) -> None:
    ent = _EntitlementsTable(
        [
            {
                "entitlement_id": "e1",
                "user_id": "u1",
                "sku": "api.basic",
                "product_type": "api_package",
                "status": "active",
                "usage_limit": 100,
                "usage_consumed": 2,
            }
        ]
    )
    events = _UsageEventsTable({"e1": [{"event_id": "a", "amount": 1}, {"event_id": "b", "amount": 1}]})
    monkeypatch.setattr(svc, "T", SimpleNamespace(entitlements=ent, entitlement_usage_events=events))

    out = svc.list_api_package_usage("u1")
    assert out["count"] == 1
    row = out["items"][0]
    assert row["remaining"] == 98
    assert row["ledger_consumed"] == 2
    assert row["ledger_matches"] is True


def test_emit_usage_threshold_alerts_emits_once_per_marker(monkeypatch) -> None:
    ent = _EntitlementsTable([])
    monkeypatch.setattr(svc, "T", SimpleNamespace(entitlements=ent))
    alerts = []
    monkeypatch.setattr(svc, "write_alert", lambda *args, **kwargs: alerts.append((args, kwargs)))

    svc.emit_usage_threshold_alerts(
        user_id="u1",
        entitlement_id="e1",
        sku="api.pro",
        usage_limit=100,
        usage_consumed=80,
    )
    svc.emit_usage_threshold_alerts(
        user_id="u1",
        entitlement_id="e1",
        sku="api.pro",
        usage_limit=100,
        usage_consumed=85,
    )

    assert len(alerts) == 2
    markers = {a[1]["details"]["marker"] for a in alerts}
    assert markers == {"near_cap:0.8", "low_balance:0.2"}
