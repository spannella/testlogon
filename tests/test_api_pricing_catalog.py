from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.services import api_pricing_catalog as pricing


def _catalog_json() -> str:
    return """{
      "versions": [
        {
          "pricing_catalog_version": "v1",
          "effective_at": "2026-01-01T00:00:00Z",
          "routes": {
            "POST:/v1/messages/send": {"price_per_call_micros": 1500}
          },
          "default_route": {"price_per_call_micros": 100}
        },
        {
          "pricing_catalog_version": "v2",
          "effective_at": "2026-01-15T00:00:00Z",
          "routes": {
            "POST:/v1/messages/send": {
              "price_per_call_micros": 1200,
              "tiers": [
                {"up_to_calls": 1000, "price_per_call_micros": 1300},
                {"up_to_calls": 10000, "price_per_call_micros": 1250}
              ]
            }
          },
          "default_route": {"price_per_call_micros": 90}
        }
      ]
    }"""


def test_resolve_catalog_version_is_timestamp_deterministic(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        pricing,
        "S",
        SimpleNamespace(
            api_usage_pricing_catalog=_catalog_json(),
            api_usage_default_pricing_catalog_version="v1",
            api_usage_pricing_missing_route_behavior="default_route",
        ),
    )
    catalog = pricing.load_api_pricing_catalog()
    v1 = pricing.resolve_catalog_version(event_ts=1736467200, catalog=catalog)  # 2025-01-10
    v2 = pricing.resolve_catalog_version(event_ts=1768435200, catalog=catalog)  # 2026-01-15
    assert v1.pricing_catalog_version == "v1"
    assert v2.pricing_catalog_version == "v2"


def test_resolve_route_pricing_uses_route_tiers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        pricing,
        "S",
        SimpleNamespace(
            api_usage_pricing_catalog=_catalog_json(),
            api_usage_default_pricing_catalog_version="v1",
            api_usage_pricing_missing_route_behavior="default_route",
        ),
    )
    out_500 = pricing.resolve_route_pricing(
        route_id="POST:/v1/messages/send",
        event_ts=1768435200,
        call_number_in_period=500,
    )
    out_5000 = pricing.resolve_route_pricing(
        route_id="POST:/v1/messages/send",
        event_ts=1768435200,
        call_number_in_period=5000,
    )
    out_50000 = pricing.resolve_route_pricing(
        route_id="POST:/v1/messages/send",
        event_ts=1768435200,
        call_number_in_period=50000,
    )
    assert out_500.unit_price_micros == 1300
    assert out_5000.unit_price_micros == 1250
    assert out_50000.unit_price_micros == 1200


def test_missing_route_fallback_default_route(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        pricing,
        "S",
        SimpleNamespace(
            api_usage_pricing_catalog=_catalog_json(),
            api_usage_default_pricing_catalog_version="v1",
            api_usage_pricing_missing_route_behavior="default_route",
        ),
    )
    out = pricing.resolve_route_pricing(route_id="GET:/v1/unknown", event_ts=1768435200)
    assert out.matched_route_id == "<default_route>"
    assert out.unit_price_micros == 90


def test_missing_route_fallback_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        pricing,
        "S",
        SimpleNamespace(
            api_usage_pricing_catalog=_catalog_json(),
            api_usage_default_pricing_catalog_version="v1",
            api_usage_pricing_missing_route_behavior="error",
        ),
    )
    with pytest.raises(HTTPException) as exc:
        pricing.resolve_route_pricing(route_id="GET:/v1/unknown", event_ts=1768435200)
    assert exc.value.status_code == 400


def test_missing_route_fallback_zero_price(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        pricing,
        "S",
        SimpleNamespace(
            api_usage_pricing_catalog=_catalog_json(),
            api_usage_default_pricing_catalog_version="v1",
            api_usage_pricing_missing_route_behavior="zero_price",
        ),
    )
    out = pricing.resolve_route_pricing(route_id="GET:/v1/unknown", event_ts=1768435200)
    assert out.matched_route_id == "<zero_price_fallback>"
    assert out.unit_price_micros == 0


def test_unknown_version_override_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        pricing,
        "S",
        SimpleNamespace(
            api_usage_pricing_catalog=_catalog_json(),
            api_usage_default_pricing_catalog_version="v1",
            api_usage_pricing_missing_route_behavior="default_route",
        ),
    )
    with pytest.raises(HTTPException):
        pricing.resolve_catalog_version(event_ts=1768435200, pricing_catalog_version="nope")
