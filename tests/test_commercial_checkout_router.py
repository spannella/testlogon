from __future__ import annotations

import asyncio

from app.routers import commercial_checkout as router


def test_ui_create_api_package_sku_calls_service(monkeypatch) -> None:
    captured = {}

    def _fake_create(author_id, body):
        captured["author_id"] = author_id
        captured["sku"] = body.sku
        return {
            "sku": body.sku,
            "product_type": "api_package",
            "display_name": "API Pro",
            "amount_cents": 4900,
            "currency": "USD",
            "billing_model": "credit_pack",
            "effective_at": "2026-01-01T00:00:00+00:00",
            "credit_grant": {"credits": 1, "bucket": "b"},
            "limit_overrides": {},
            "access_template": {},
        }

    monkeypatch.setattr(router, "create_api_package_sku_version", _fake_create)
    monkeypatch.setattr(router, "audit_event", lambda *args, **kwargs: None)

    body = type("Body", (), {"sku": "api-pro"})()
    out = asyncio.run(router.ui_create_api_package_sku(body=body, ctx={"user_sub": "u1"}))
    assert out["sku"] == "api-pro"
    assert captured["author_id"] == "u1"


def test_unified_checkout_session_route_calls_service(monkeypatch) -> None:
    captured = {}

    def _fake_checkout(user_sub, body):
        captured["user_sub"] = user_sub
        captured["source"] = body.source
        return {
            "order_id": "ord-1",
            "checkout_session_id": "chk-1",
            "line_items": [{"sku": "sku-1"}],
            "source": body.source,
            "status": "pending_payment",
        }

    monkeypatch.setattr(router, "create_unified_checkout_session", _fake_checkout)
    monkeypatch.setattr(router, "audit_event", lambda *args, **kwargs: None)

    body = type("Body", (), {"source": "cart"})()
    out = asyncio.run(router.ui_create_checkout_session(body=body, ctx={"user_sub": "u1"}))
    assert out["order_id"] == "ord-1"
    assert captured["user_sub"] == "u1"
    assert captured["source"] == "cart"


def test_file_bundle_wrapper_routes_to_unified_checkout(monkeypatch) -> None:
    captured = {}

    def _fake_wrapper(user_sub, body):
        captured["user_sub"] = user_sub
        captured["sku"] = body.sku
        return {
            "checkout_session_id": "chk-2",
            "order_id": "ord-2",
            "status": "pending_payment",
            "sku": body.sku,
            "amount_cents": 100,
            "currency": "USD",
            "access_mode": "purchase",
        }

    monkeypatch.setattr(router, "create_file_bundle_checkout_via_unified", _fake_wrapper)
    monkeypatch.setattr(router, "audit_event", lambda *args, **kwargs: None)

    body = type("Body", (), {"sku": "fb-1"})()
    out = asyncio.run(router.ui_create_file_bundle_checkout_session(body=body, ctx={"user_sub": "u1"}))
    assert out["order_id"] == "ord-2"
    assert captured["user_sub"] == "u1"
    assert captured["sku"] == "fb-1"
