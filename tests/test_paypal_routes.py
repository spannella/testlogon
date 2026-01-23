from __future__ import annotations

import asyncio
import types
from typing import Any, Dict, List

import pytest
from fastapi import HTTPException

from app.routers import paypal


class FakeTable:
    def __init__(self) -> None:
        self.items: Dict[tuple[str, str], Dict[str, Any]] = {}

    def get_item(self, Key: Dict[str, str]) -> Dict[str, Any]:
        item = self.items.get((Key["pk"], Key["sk"]))
        return {"Item": item} if item else {}

    def put_item(self, Item: Dict[str, Any], **kwargs) -> None:
        self.items[(Item["pk"], Item["sk"])] = dict(Item)

    def delete_item(self, Key: Dict[str, str]) -> None:
        self.items.pop((Key["pk"], Key["sk"]), None)

    def query(self, KeyConditionExpression: str, ExpressionAttributeValues: Dict[str, Any]) -> Dict[str, Any]:
        pk = ExpressionAttributeValues[":pk"]
        return {"Items": [item for (item_pk, _), item in self.items.items() if item_pk == pk]}

    def update_item(
        self,
        Key: Dict[str, str],
        UpdateExpression: str,
        ExpressionAttributeValues: Dict[str, Any],
        ExpressionAttributeNames: Dict[str, str] | None = None,
    ) -> None:
        item = self.items.setdefault((Key["pk"], Key["sk"]), {"pk": Key["pk"], "sk": Key["sk"]})
        names = ExpressionAttributeNames or {}
        expr = UpdateExpression.replace("SET ", "")
        parts = []
        buff = []
        depth = 0
        for ch in expr:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth = max(depth - 1, 0)
            if ch == "," and depth == 0:
                part = "".join(buff).strip()
                if part:
                    parts.append(part)
                buff = []
            else:
                buff.append(ch)
        if buff:
            part = "".join(buff).strip()
            if part:
                parts.append(part)
        for part in parts:
            lhs, rhs = [chunk.strip() for chunk in part.split("=", 1)]
            target = names.get(lhs, lhs.lstrip("#"))
            if "if_not_exists" in rhs:
                if "+" in rhs:
                    fn_part, add_part = [chunk.strip() for chunk in rhs.split("+", 1)]
                    inner = fn_part[fn_part.find("(") + 1 : fn_part.rfind(")")]
                    name_ref, default_ref = [chunk.strip() for chunk in inner.split(",", 1)]
                    base_key = names.get(name_ref, name_ref.lstrip("#"))
                    base_val = item.get(base_key, ExpressionAttributeValues[default_ref])
                    value = base_val + ExpressionAttributeValues[add_part]
                else:
                    inner = rhs[rhs.find("(") + 1 : rhs.rfind(")")]
                    name_ref, default_ref = [chunk.strip() for chunk in inner.split(",", 1)]
                    base_key = names.get(name_ref, name_ref.lstrip("#"))
                    value = item.get(base_key, ExpressionAttributeValues[default_ref])
            else:
                value = ExpressionAttributeValues[rhs]
            item[target] = value
        self.items[(Key["pk"], Key["sk"])] = item


def test_billing_config():
    resp = paypal.billing_config()

    assert resp["paypal_env"] == paypal.PAYPAL_ENV
    assert "default_currency" in resp


def test_billing_settings_and_autopay(monkeypatch):
    monkeypatch.setattr(
        paypal,
        "ddb_get",
        lambda pk, sk: {"autopay_enabled": True, "currency": "usd", "default_payment_token_id": "pm"},
    )

    resp = paypal.get_settings(x_user_id="user")

    assert resp["autopay_enabled"] is True

    calls = {}

    def fake_put(item, **kwargs):
        calls["put"] = item

    def fake_update(pk, sk, expr, values, names=None):
        calls["update"] = {"pk": pk, "sk": sk, "expr": expr, "values": values, "names": names}

    monkeypatch.setattr(paypal, "ddb_get", lambda pk, sk: None)
    monkeypatch.setattr(paypal, "ddb_put", fake_put)
    monkeypatch.setattr(paypal, "ddb_update", fake_update)

    resp = paypal.set_autopay(paypal.SetAutopayIn(enabled=True), x_user_id="user")

    assert resp["ok"] is True
    assert calls["put"]["sk"] == "BILLING"
    assert calls["update"]["values"][":e"] is True


def test_billing_balance(monkeypatch):
    monkeypatch.setattr(paypal, "ensure_balance_row", lambda pk: None)
    monkeypatch.setattr(
        paypal,
        "ddb_get",
        lambda pk, sk: {
            "currency": "usd",
            "owed_pending_cents": 50,
            "owed_settled_cents": 200,
            "payments_pending_cents": 25,
            "payments_settled_cents": 75,
            "updated_at": 123,
        },
    )

    resp = paypal.get_balance(x_user_id="user")

    assert resp["due_settled_cents"] == 125
    assert resp["due_if_all_settles_cents"] == 150


def test_payment_method_list_and_setup(monkeypatch):
    monkeypatch.setattr(
        paypal,
        "list_payment_methods_ddb",
        lambda user_id: [{"payment_token_id": "pm1", "label": "Card", "priority": 0, "pm_type": "card"}],
    )

    resp = paypal.list_payment_methods(x_user_id="user")

    assert resp[0].payment_token_id == "pm1"

    def fake_setup_token(**kwargs):
        return {"id": "setup", "links": [{"rel": "approve", "href": "https://approve"}]}

    monkeypatch.setattr(paypal, "paypal_create_setup_token", fake_setup_token)

    resp = paypal.create_setup_token(
        paypal.SetupTokenIn(pm_kind="paypal", label="Main", make_default=True),
        x_user_id="user",
    )

    assert resp["setup_token"] == "setup"


def test_exchange_set_default_and_priority(monkeypatch):
    recorded = {}

    monkeypatch.setattr(paypal, "list_payment_methods_ddb", lambda user_id: [])
    monkeypatch.setattr(
        paypal,
        "paypal_exchange_setup_for_payment_token",
        lambda setup_token_id, idempotency_key: {"id": "pm_123", "payment_source": {"paypal": {}}},
    )

    monkeypatch.setattr(paypal, "ddb_put", lambda item, **kwargs: recorded.setdefault("put", item))
    monkeypatch.setattr(paypal, "set_default_pm", lambda user_id, token_id: recorded.setdefault("default", token_id))

    resp = paypal.exchange_setup_token(
        paypal.ExchangeTokenIn(setup_token_id="setup", label="PayPal", make_default=True),
        x_user_id="user",
    )

    assert resp["ok"] is True
    assert recorded["put"]["payment_token_id"] == "pm_123"
    assert recorded["default"] == "pm_123"

    monkeypatch.setattr(paypal, "ddb_get", lambda pk, sk: {"pk": pk, "sk": sk})
    monkeypatch.setattr(paypal, "ddb_update", lambda *args, **kwargs: recorded.setdefault("update", True))

    resp = paypal.set_priority(paypal.SetPriorityIn(payment_token_id="pm_123", priority=3), x_user_id="user")
    assert resp["ok"] is True

    resp = paypal.set_default(paypal.SetDefaultIn(payment_token_id="pm_123"), x_user_id="user")
    assert resp["ok"] is True


def test_remove_payment_method(monkeypatch):
    recorded = {}

    monkeypatch.setattr(paypal, "ddb_get", lambda pk, sk: {"pk": pk, "sk": sk})
    monkeypatch.setattr(paypal, "ddb_del", lambda pk, sk: recorded.setdefault("del", sk))
    monkeypatch.setattr(paypal, "current_default_pm", lambda user_id: "pm_123")
    monkeypatch.setattr(paypal, "list_payment_methods_ddb", lambda user_id: [])
    monkeypatch.setattr(paypal, "set_default_pm", lambda user_id, token_id: recorded.setdefault("default", token_id))

    resp = paypal.remove_payment_method("pm_123", x_user_id="user")

    assert resp["ok"] is True
    assert recorded["del"] == "PM#pm_123"
    assert recorded["default"] is None


def test_charge_once_and_capture(monkeypatch):
    recorded = {}

    monkeypatch.setattr(paypal, "_get_default_token_or_400", lambda user_id: "pm_default")
    monkeypatch.setattr(paypal, "new_ledger_entry", lambda **kwargs: ("LEDGER#1", {"pk": "USER#user", "sk": "LEDGER#1"}))
    monkeypatch.setattr(paypal, "ddb_put", lambda item, **kwargs: recorded.setdefault("put", item))
    monkeypatch.setattr(paypal, "apply_balance_delta", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        paypal,
        "paypal_create_order",
        lambda **kwargs: {"id": "ORDER-1", "links": [{"rel": "approve", "href": "https://approve"}]},
    )

    resp = asyncio.run(paypal.charge_once(paypal.OneTimeChargeIn(amount_cents=500), request=None, x_user_id="user"))

    assert resp["order_id"] == "ORDER-1"

    monkeypatch.setattr(paypal, "ddb_get", lambda pk, sk: {"ledger_sk": "LEDGER#1", "amount_cents": 500})
    monkeypatch.setattr(paypal, "paypal_capture_order", lambda **kwargs: {"status": "COMPLETED"})
    monkeypatch.setattr(paypal, "settle_or_reverse_ledger", lambda *args, **kwargs: recorded.setdefault("settled", True))
    monkeypatch.setattr(paypal, "update_payment_status", lambda *args, **kwargs: recorded.setdefault("updated", True))

    resp = asyncio.run(paypal.capture_order(paypal.CaptureOrderIn(order_id="ORDER-1"), x_user_id="user"))

    assert resp["ok"] is True


def test_pay_balance(monkeypatch):
    async def fake_charge_once(body, request, x_user_id=None):
        return {"order_id": "ORDER-2"}

    monkeypatch.setattr(paypal, "ensure_balance_row", lambda pk: None)
    monkeypatch.setattr(paypal, "ddb_get", lambda pk, sk: {"owed_settled_cents": 400, "payments_settled_cents": 0})
    monkeypatch.setattr(paypal, "_get_default_token_or_400", lambda user_id: "pm_default")
    monkeypatch.setattr(paypal, "charge_once", fake_charge_once)

    resp = asyncio.run(paypal.pay_balance(paypal.PayBalanceIn(), request=None, x_user_id="user"))

    assert resp["order_id"] == "ORDER-2"


def test_subscriptions_and_lists(monkeypatch):
    monkeypatch.setattr(paypal, "PAYPAL_PLAN_MAP", {"monthly": "P-123"})
    monkeypatch.setattr(
        paypal,
        "paypal_create_subscription",
        lambda **kwargs: {"id": "SUB-1", "status": "APPROVAL_PENDING", "links": [{"rel": "approve", "href": "https://approve"}]},
    )
    monkeypatch.setattr(paypal, "upsert_subscription", lambda *args, **kwargs: None)

    resp = asyncio.run(paypal.subscribe_monthly(paypal.SubscribeMonthlyIn(plan_id="monthly"), x_user_id="user"))

    assert resp["subscription_id"] == "SUB-1"

    monkeypatch.setattr(paypal, "paypal_cancel_subscription", lambda *args, **kwargs: None)

    resp = paypal.cancel_subscription(
        paypal.CancelSubscriptionIn(subscription_id="SUB-1", reason="user"),
        x_user_id="user",
    )

    assert resp["ok"] is True

    items = [
        {"sk": "LEDGER#1", "ts": 1},
        {"sk": "PAY#1", "created_at": 2},
        {"sk": "SUB#1", "created_at": 3},
    ]
    monkeypatch.setattr(paypal, "ddb_query_pk", lambda pk: items)

    resp = paypal.list_ledger(x_user_id="user")
    assert "items" in resp

    resp = paypal.list_payments(x_user_id="user")
    assert "items" in resp

    resp = paypal.list_subscriptions(x_user_id="user")
    assert "items" in resp


def test_paypal_webhook(monkeypatch):
    monkeypatch.setattr(paypal, "mark_webhook_processed", lambda dedupe_key: True)
    monkeypatch.setattr(paypal, "paypal_verify_webhook_signature", lambda **kwargs: True)
    monkeypatch.setattr(paypal, "ensure_balance_row", lambda pk: None)
    monkeypatch.setattr(paypal, "ddb_put", lambda *args, **kwargs: None)
    monkeypatch.setattr(paypal, "S", types.SimpleNamespace(paypal_webhook_id="wh"))

    async def fake_body():
        return b"{}"

    req = types.SimpleNamespace(
        body=fake_body,
        headers={
            "paypal-transmission-id": "id",
            "paypal-transmission-time": "time",
            "paypal-transmission-sig": "sig",
            "paypal-cert-url": "cert",
            "paypal-auth-algo": "algo",
        },
    )

    resp = asyncio.run(paypal.paypal_webhook(req))

    assert resp["received"] is True


def test_charge_once_capture_updates_balance(monkeypatch):
    table = FakeTable()

    monkeypatch.setattr(paypal, "_billing_table", lambda: table)
    monkeypatch.setattr(
        paypal,
        "paypal_create_order",
        lambda **kwargs: {"id": "ORDER-1", "links": []},
    )
    monkeypatch.setattr(
        paypal,
        "paypal_capture_order",
        lambda **kwargs: {"status": "COMPLETED"},
    )

    table.put_item(
        Item={
            "pk": "USER#user",
            "sk": "BILLING",
            "autopay_enabled": False,
            "currency": "usd",
            "default_payment_token_id": "pm_default",
        }
    )

    resp = asyncio.run(paypal.charge_once(paypal.OneTimeChargeIn(amount_cents=500), request=None, x_user_id="user"))

    bal = paypal.ddb_get("USER#user", "BALANCE")
    assert bal["payments_pending_cents"] == 500
    assert bal["payments_settled_cents"] == 0

    capture_resp = asyncio.run(paypal.capture_order(paypal.CaptureOrderIn(order_id="ORDER-1"), x_user_id="user"))
    assert capture_resp["ok"] is True

    bal = paypal.ddb_get("USER#user", "BALANCE")
    assert bal["payments_pending_cents"] == 0
    assert bal["payments_settled_cents"] == 500

    ledger = paypal.ddb_get("USER#user", resp["ledger_sk"])
    assert ledger["state"] == "settled"


def test_missing_user_header_raises_401():
    with pytest.raises(HTTPException) as excinfo:
        paypal.get_settings(x_user_id=None)

    assert excinfo.value.status_code == 401


def test_charge_once_requires_default_payment_method(monkeypatch):
    monkeypatch.setattr(paypal, "ddb_get", lambda pk, sk: {"autopay_enabled": False})

    with pytest.raises(HTTPException) as excinfo:
        asyncio.run(paypal.charge_once(paypal.OneTimeChargeIn(amount_cents=100), request=None, x_user_id="user"))

    assert excinfo.value.status_code == 400


def test_subscribe_monthly_requires_plan(monkeypatch):
    monkeypatch.setattr(paypal, "PAYPAL_PLAN_MAP", {})

    with pytest.raises(HTTPException) as excinfo:
        asyncio.run(paypal.subscribe_monthly(paypal.SubscribeMonthlyIn(plan_id="monthly"), x_user_id="user"))

    assert excinfo.value.status_code == 400


def test_capture_order_unknown_payment(monkeypatch):
    monkeypatch.setattr(paypal, "ddb_get", lambda pk, sk: None)

    with pytest.raises(HTTPException) as excinfo:
        asyncio.run(paypal.capture_order(paypal.CaptureOrderIn(order_id="ORDER-404"), x_user_id="user"))

    assert excinfo.value.status_code == 404


def test_webhook_requires_headers(monkeypatch):
    monkeypatch.setattr(paypal, "mark_webhook_processed", lambda dedupe_key: True)
    monkeypatch.setattr(paypal, "S", types.SimpleNamespace(paypal_webhook_id="wh"))

    async def fake_body():
        return b"{}"

    req = types.SimpleNamespace(body=fake_body, headers={})

    with pytest.raises(HTTPException) as excinfo:
        asyncio.run(paypal.paypal_webhook(req))

    assert excinfo.value.status_code == 400
