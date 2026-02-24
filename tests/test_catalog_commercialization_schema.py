from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.services import api_pricing_catalog
from app.services import catalog_commercialization as commercialization


def _valid_catalog_json() -> str:
    return """{
      "versions": [
        {
          "sku": "files-daily-2026-01",
          "product_type": "file_bundle",
          "display_name": "Daily files Jan",
          "billing_model": "rental",
          "effective_at": "2026-01-01T00:00:00Z",
          "amount": 1999,
          "currency": "usd",
          "config": {
            "selection_type": "date_range",
            "date_start": "2026-01-01T00:00:00Z",
            "date_end": "2026-01-31T23:59:59Z",
            "access_mode": "rental",
            "rental_duration_hours": 72
          }
        },
        {
          "sku": "api-pro-credits",
          "product_type": "api_package",
          "display_name": "API Pro Credits",
          "billing_model": "credit_pack",
          "effective_at": "2026-01-01T00:00:00Z",
          "amount": 4900,
          "currency": "USD",
          "config": {
            "credit_amount": 50000,
            "route_allowlist": ["POST:/v1/messages/send"]
          }
        },
        {
          "sku": "internal-msg-plus",
          "product_type": "internal_api_package",
          "display_name": "Internal Messaging Plus",
          "billing_model": "subscription",
          "effective_at": "2026-01-01T00:00:00Z",
          "amount": 9900,
          "currency": "USD",
          "config": {
            "internal_namespaces": ["messaging.*", "filemanager.*"]
          }
        }
      ]
    }"""


def test_load_product_catalog_accepts_valid_typed_versions(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        commercialization,
        "S",
        SimpleNamespace(catalog_commercialization_enabled=True, catalog_pricing_catalog=_valid_catalog_json()),
    )
    out = commercialization.load_product_catalog()
    assert len(out.versions) == 3
    assert {v.product_type for v in out.versions} == {"file_bundle", "api_package", "internal_api_package"}


def test_load_product_catalog_rejects_missing_required_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        commercialization,
        "S",
        SimpleNamespace(
            catalog_commercialization_enabled=True,
            catalog_pricing_catalog='{"versions":[{"product_type":"file_bundle"}]}',
        ),
    )
    with pytest.raises(ValueError, match="sku is required"):
        commercialization.load_product_catalog()


def test_load_product_catalog_rejects_invalid_product_specific_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        commercialization,
        "S",
        SimpleNamespace(
            catalog_commercialization_enabled=True,
            catalog_pricing_catalog=(
                '{"versions":[{"sku":"a","product_type":"internal_api_package","display_name":"x",'
                '"billing_model":"subscription","effective_at":"2026-01-01T00:00:00Z","amount":1,'
                '"currency":"USD","config":{"internal_namespaces":[]}}]}'
            ),
        ),
    )
    with pytest.raises(ValueError, match="internal_api_package.internal_namespaces"):
        commercialization.load_product_catalog()


def test_existing_api_catalog_reader_works_with_commercialization_flag_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        commercialization,
        "S",
        SimpleNamespace(catalog_commercialization_enabled=False, catalog_pricing_catalog=""),
    )
    commercial_out = commercialization.load_product_catalog()
    assert commercial_out.versions == []

    monkeypatch.setattr(
        api_pricing_catalog,
        "S",
        SimpleNamespace(
            api_usage_pricing_catalog='{"versions":[{"pricing_catalog_version":"v1","effective_at":"2026-01-01T00:00:00Z","routes":{},"default_route":{"price_per_call_micros":1}}]}',
            api_usage_default_pricing_catalog_version="v1",
            api_usage_pricing_missing_route_behavior="default_route",
        ),
    )
    api_out = api_pricing_catalog.load_api_pricing_catalog()
    assert api_out[0].pricing_catalog_version == "v1"
