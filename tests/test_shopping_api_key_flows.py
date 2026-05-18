from __future__ import annotations

from fastapi.testclient import TestClient

import app.main as main_app
from app.main import create_app
from app.services import api_key_auth_dependency


def _build_api_key_client(monkeypatch, *, capabilities: list[str]) -> TestClient:
    app = create_app()

    monkeypatch.setattr(
        api_key_auth_dependency.api_keys,
        "parse_api_key",
        lambda raw: {"key_id": "k_shop", "secret": "secret"},
    )
    monkeypatch.setattr(
        api_key_auth_dependency.api_keys,
        "check_api_key_allowed",
        lambda _key_id, _secret, _client_ip: {
            "key_id": "k_shop",
            "user_sub": "shopper-1",
            "capabilities": capabilities,
        },
    )
    monkeypatch.setattr(main_app, "enforce_api_package_entitlement_pre_request", lambda _request: {})
    return TestClient(app)


def test_api_key_checkout_requires_idempotency_key(monkeypatch):
    from app.routers import shoppingcart

    monkeypatch.setattr(shoppingcart, "purchase_cart", lambda *_args, **_kwargs: {"cart_id": "c1", "order_id": "o1", "purchased_total_cents": 100, "currency": "USD"})

    client = _build_api_key_client(
        monkeypatch,
        capabilities=["shopping:cart:write", "shopping:checkout:write", "shopping:orders:read", "shopping:catalog:read"],
    )

    missing = client.post("/ui/shoppingcart/carts/c1/purchase")
    assert missing.status_code == 400
    assert missing.json()["detail"]["code"] == "idempotency_key_required"



def test_api_key_cart_to_order_lifecycle_replay_is_stable(monkeypatch):
    from app.routers import shoppingcart, purchase_history

    monkeypatch.setattr(shoppingcart, "start_cart", lambda _user: {"cart_id": "c1", "status": "OPEN", "created_at": "now", "currency": "USD"})
    monkeypatch.setattr(
        shoppingcart,
        "add_item",
        lambda _user, _cart_id, _payload: {"sku": "sku-1", "name": "Item", "quantity": 1, "unit_price_cents": 100, "line_total_cents": 100, "updated_at": "now"},
    )
    monkeypatch.setattr(
        shoppingcart,
        "purchase_cart",
        lambda _user, _cart_id, **_kwargs: {
            "cart_id": "c1",
            "order_id": "ord_1",
            "purchased_at": "now",
            "purchased_total_cents": 100,
            "currency": "USD",
            "purchase_txn_id": "txn_1",
        },
    )
    monkeypatch.setattr(
        purchase_history,
        "list_transactions",
        lambda _user, _limit, _status=None: [
            {
                "txn_id": "txn_1",
                "created_at": 1,
                "updated_at": 1,
                "status": "COMPLETED",
                "amount": 1.0,
                "currency": "USD",
            }
        ],
    )

    client = _build_api_key_client(
        monkeypatch,
        capabilities=["shopping:cart:write", "shopping:checkout:write", "shopping:orders:read", "shopping:catalog:read"],
    )

    cart = client.post("/ui/shoppingcart/carts")
    assert cart.status_code == 200

    added = client.post(
        "/ui/shoppingcart/carts/c1/items",
        json={"sku": "sku-1", "name": "Item", "quantity": 1, "unit_price_cents": 100},
    )
    assert added.status_code == 200

    first = client.post("/ui/shoppingcart/carts/c1/purchase", headers={"X-Idempotency-Key": "idem-1"})
    second = client.post("/ui/shoppingcart/carts/c1/purchase", headers={"X-Idempotency-Key": "idem-1"})
    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["order_id"] == second.json()["order_id"]

    txns = client.get("/ui/purchase-history/transactions")
    assert txns.status_code == 200
    assert txns.json()[0]["txn_id"] == "txn_1"
