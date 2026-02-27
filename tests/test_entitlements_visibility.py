from __future__ import annotations

from types import SimpleNamespace

from app.services import entitlements_visibility as svc


class _EntitlementsTable:
    def __init__(self, items):
        self.items = items

    def query(self, **_kwargs):
        return {"Items": list(self.items)}


def test_list_entitlements_surfaces_file_bundle_scope_and_statuses(monkeypatch) -> None:
    items = [
        {
            "entitlement_id": "e-active",
            "user_id": "u1",
            "sku": "bundle-a",
            "product_type": "file_bundle",
            "status": "active",
            "starts_at": "2026-01-01T00:00:00Z",
            "ends_at": None,
            "scope": {
                "selection_type": "date_range",
                "date_start": "2026-01-01T00:00:00Z",
                "date_end": "2026-01-31T00:00:00Z",
                "access_mode": "purchase",
            },
        },
        {
            "entitlement_id": "e-upcoming",
            "user_id": "u1",
            "sku": "bundle-b",
            "product_type": "file_bundle",
            "status": "pending_payment",
            "starts_at": "2999-01-01T00:00:00Z",
            "ends_at": None,
            "scope": {"selection_type": "date_range", "date_start": "2999-01-01T00:00:00Z", "date_end": "2999-01-31T00:00:00Z", "access_mode": "rental"},
        },
        {
            "entitlement_id": "e-expired",
            "user_id": "u1",
            "sku": "bundle-c",
            "product_type": "file_bundle",
            "status": "active",
            "starts_at": "2020-01-01T00:00:00Z",
            "ends_at": "2020-01-02T00:00:00Z",
            "scope": {"selection_type": "date_range", "date_start": "2020-01-01T00:00:00Z", "date_end": "2020-01-02T00:00:00Z", "access_mode": "rental"},
        },
    ]
    monkeypatch.setattr(svc, "T", SimpleNamespace(entitlements=_EntitlementsTable(items)))

    out = svc.list_user_entitlements("u1", product_type="file_bundle")
    assert out["count"] == 3
    by_id = {row["entitlement_id"]: row for row in out["items"]}
    assert by_id["e-active"]["status"] == "active"
    assert by_id["e-upcoming"]["status"] == "upcoming"
    assert by_id["e-expired"]["status"] == "expired"
    assert by_id["e-expired"]["denial_reason_hint"] == "expired_entitlement"
    assert by_id["e-active"]["scope"]["selection_type"] == "date_range"


def test_list_entitlements_filters_by_status_and_product_type(monkeypatch) -> None:
    items = [
        {"entitlement_id": "e1", "user_id": "u1", "sku": "s1", "product_type": "file_bundle", "status": "active", "starts_at": "2020-01-01T00:00:00Z", "ends_at": None, "scope": {}},
        {"entitlement_id": "e2", "user_id": "u1", "sku": "s2", "product_type": "api_package", "status": "active", "starts_at": "2020-01-01T00:00:00Z", "ends_at": None, "scope": {}},
    ]
    monkeypatch.setattr(svc, "T", SimpleNamespace(entitlements=_EntitlementsTable(items)))

    out = svc.list_user_entitlements("u1", product_type="file_bundle", status="active")
    assert out["count"] == 1
    assert out["items"][0]["entitlement_id"] == "e1"


def test_list_entitlements_includes_source_attribution_and_source_filter(monkeypatch) -> None:
    items = [
        {
            "entitlement_id": "e-sub",
            "user_id": "u1",
            "sku": "subscription_plan:pro",
            "product_type": "api_package",
            "status": "active",
            "starts_at": "2026-01-01T00:00:00Z",
            "ends_at": "2099-02-01T00:00:00Z",
            "source_system": "subscription_cycle",
            "order_id": "ord-sub-1",
            "scope": {
                "subscription": {
                    "subscription_id": "sub-1",
                    "invoice_id": "inv-1",
                    "provider_invoice_id": "p-inv-1",
                }
            },
        },
        {
            "entitlement_id": "e-cart",
            "user_id": "u1",
            "sku": "bundle",
            "product_type": "file_bundle",
            "status": "active",
            "starts_at": "2026-01-01T00:00:00Z",
            "ends_at": None,
            "source_system": "shopping_cart",
            "order_id": "ord-cart-1",
            "scope": {},
        },
    ]
    monkeypatch.setattr(svc, "T", SimpleNamespace(entitlements=_EntitlementsTable(items)))

    out = svc.list_user_entitlements("u1", source_system="subscription_cycle", lifecycle_status="active")
    assert out["count"] == 1
    row = out["items"][0]
    assert row["source_system"] == "subscription_cycle"
    assert row["order_id"] == "ord-sub-1"
    assert row["subscription_id"] == "sub-1"
    assert row["billing_metadata"]["invoice_id"] == "inv-1"
