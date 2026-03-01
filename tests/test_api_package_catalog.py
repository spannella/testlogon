from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.services import api_package_catalog as svc


class _FakeTable:
    def __init__(self):
        self.items = {}

    def put_item(self, Item, ConditionExpression=None):
        key = (Item.get("sku") or Item.get("PK"), Item.get("effective_at") or Item.get("SK"))
        if ConditionExpression and key in self.items:
            raise RuntimeError("conditional put failed")
        self.items[key] = dict(Item)


def _stub_tables(monkeypatch: pytest.MonkeyPatch):
    products = _FakeTable()
    versions = _FakeTable()
    monkeypatch.setattr(svc, "T", SimpleNamespace(catalog_products=products, catalog_product_versions=versions))
    return products, versions


def test_create_api_package_sku_version_with_credit_limit_access_templates(monkeypatch: pytest.MonkeyPatch) -> None:
    products, versions = _stub_tables(monkeypatch)
    body = SimpleNamespace(
        sku="api-pro-v1",
        display_name="API Pro",
        amount_cents=4900,
        currency="usd",
        billing_model="credit_pack",
        effective_at="2026-01-01T00:00:00Z",
        credit_grant={"credits": 50000, "bucket": "api_calls"},
        limit_overrides={"period": "monthly", "monthly_call_limit": 100000, "rps_limit": 200},
        access_template={"route_allowlist": ["POST:/v1/messages/send"], "feature_unlocks": ["analytics"]},
    )

    out = svc.create_api_package_sku_version("author", body)
    assert out["sku"] == "api-pro-v1"
    assert out["product_type"] == "api_package"
    assert ("api-pro-v1", "2026-01-01T00:00:00+00:00") in versions.items
    assert ("api-pro-v1", "LATEST") in products.items


def test_rejects_conflicting_limit_definitions(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_tables(monkeypatch)
    body = SimpleNamespace(
        sku="api-conflict",
        display_name="Conflict",
        amount_cents=1000,
        currency="USD",
        billing_model="subscription",
        effective_at="2026-01-01T00:00:00Z",
        credit_grant=None,
        limit_overrides={"period": "monthly", "unlimited_calls": True, "monthly_call_limit": 1000},
        access_template=None,
    )
    with pytest.raises(HTTPException, match="Conflicting limit definitions"):
        svc.create_api_package_sku_version("author", body)


def test_rejects_missing_templates(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_tables(monkeypatch)
    body = SimpleNamespace(
        sku="api-empty",
        display_name="Empty",
        amount_cents=1000,
        currency="USD",
        billing_model="subscription",
        effective_at="2026-01-01T00:00:00Z",
        credit_grant=None,
        limit_overrides=None,
        access_template=None,
    )
    with pytest.raises(HTTPException, match="At least one entitlement template"):
        svc.create_api_package_sku_version("author", body)


def test_rejects_conflicting_access_templates(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_tables(monkeypatch)
    body = SimpleNamespace(
        sku="api-access-conflict",
        display_name="Access Conflict",
        amount_cents=1000,
        currency="USD",
        billing_model="subscription",
        effective_at="2026-01-01T00:00:00Z",
        credit_grant=None,
        limit_overrides=None,
        access_template={"route_allowlist": ["feature_x"], "feature_unlocks": ["feature_x"]},
    )
    with pytest.raises(HTTPException, match="Conflicting access definitions"):
        svc.create_api_package_sku_version("author", body)
