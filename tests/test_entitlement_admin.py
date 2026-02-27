from __future__ import annotations

from types import SimpleNamespace

from app.services import entitlement_admin as svc


class _EntitlementsTable:
    def __init__(self, item):
        self.item = dict(item)
        self.updated = []

    def scan(self, **kwargs):
        return {"Items": [dict(self.item)]}

    def update_item(self, **kwargs):
        self.updated.append(kwargs)


class _EventsTable:
    def __init__(self):
        self.items = []

    def put_item(self, Item):
        self.items.append(dict(Item))


def test_revoke_entitlement_admin_writes_update_and_event(monkeypatch):
    ent = _EntitlementsTable({"user_id": "u1", "entitlement_id": "e1", "status": "active"})
    events = _EventsTable()
    monkeypatch.setattr(svc, "T", SimpleNamespace(entitlements=ent, entitlement_usage_events=events))

    out = svc.revoke_entitlement_admin(
        entitlement_id="e1",
        reason_code="customer_support",
        audit_comment="customer requested immediate revoke",
        actor_sub="admin-1",
    )

    assert out["ok"] is True
    assert out["status"] == "revoked"
    assert ent.updated
    assert events.items and events.items[0]["action"] == "revoke"


def test_extend_and_credit_adjust_admin(monkeypatch):
    ent = _EntitlementsTable(
        {
            "user_id": "u1",
            "entitlement_id": "e1",
            "status": "active",
            "starts_at": "2026-01-01T00:00:00+00:00",
            "ends_at": "2026-01-02T00:00:00+00:00",
            "usage_limit": 10,
        }
    )
    events = _EventsTable()
    monkeypatch.setattr(svc, "T", SimpleNamespace(entitlements=ent, entitlement_usage_events=events))

    ext = svc.extend_entitlement_admin(
        entitlement_id="e1",
        extend_hours=24,
        reason_code="incident_remediation",
        audit_comment="service outage compensation",
        actor_sub="admin-1",
    )
    cred = svc.credit_adjust_entitlement_admin(
        entitlement_id="e1",
        credit_units=5,
        reason_code="billing_correction",
        audit_comment="invoice correction credits",
        actor_sub="admin-1",
    )

    assert ext["extended_hours"] == 24
    assert cred["usage_limit"] == 15
    assert len(events.items) == 2
    assert {events.items[0]["action"], events.items[1]["action"]} == {"extend", "credit"}
