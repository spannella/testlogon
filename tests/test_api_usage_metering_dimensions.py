from __future__ import annotations

import json
from types import SimpleNamespace

from fastapi import Request

from app.services import api_usage_metering


def _request(headers: dict[str, str] | None = None) -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/v1/files",
        "headers": [(k.lower().encode("utf-8"), v.encode("utf-8")) for k, v in (headers or {}).items()],
        "query_string": b"",
        "client": ("127.0.0.1", 1234),
        "server": ("test", 80),
        "scheme": "http",
        "route": type("R", (), {"path": "/v1/files"})(),
    }
    return Request(scope)


def test_product_from_route_id_mapping() -> None:
    assert api_usage_metering._product_from_route_id("GET:/v1/files") == "filemanager"
    assert api_usage_metering._product_from_route_id("POST:/v1/newsfeed/posts") == "newsfeed"
    assert api_usage_metering._product_from_route_id("GET:/v1/tickets") == "tickets"
    assert api_usage_metering._product_from_route_id("POST:/v1/cart/checkout") == "shopping"
    assert api_usage_metering._product_from_route_id("POST:/v1/messages/send") == "messager"
    assert api_usage_metering._product_from_route_id("POST:/messaging/conversations/c1/messages/image") == "messager_media"
    assert api_usage_metering._product_from_route_id("GET:/messaging/conversations/c1/gallery") == "messager_media"


def test_build_api_usage_event_includes_product_and_never_includes_secret(monkeypatch) -> None:
    monkeypatch.setattr(api_usage_metering, "route_id_from_request", lambda request: "GET:/v1/files")
    monkeypatch.setattr(api_usage_metering, "classify_api_call", lambda *_args, **_kwargs: SimpleNamespace(billable=True, counts_toward_quota=True))
    monkeypatch.setattr(
        api_usage_metering,
        "resolve_route_pricing",
        lambda **_kwargs: SimpleNamespace(unit_price_micros=7, pricing_catalog_version="v1"),
    )

    event = api_usage_metering.build_api_usage_event(
        _request({"x-user-sub": "u1", "x-request-id": "r1", "x-api-key": "ak_k1.supersecret"}),
        200,
    )
    assert event is not None
    assert event["product"] == "filemanager"
    assert event["api_key_id"] == "k1"
    blob = json.dumps(event)
    assert "supersecret" not in blob
