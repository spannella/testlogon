from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple
from unittest.mock import MagicMock

from starlette.requests import Request
from fastapi import HTTPException

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))

sys.modules.setdefault("stripe", MagicMock())

from app.core.settings import S
from app.core.tables import T
from app.routers import billing as billing_router
from app.models import (
    AddChargeReq,
    BillingCheckoutReq,
    PayBalanceReq,
    SetAutopayReq,
    SetDefaultReq,
    SetPriorityReq,
    VerifyMicrodepositsReq,
)


class FakeTable:
    def __init__(self) -> None:
        self.items: Dict[Tuple[str, str], Dict[str, Any]] = {}

    def get_item(self, *, Key: Dict[str, str]) -> Dict[str, Any]:
        item = self.items.get((Key["pk"], Key["sk"]))
        return {"Item": item} if item else {}

    def put_item(self, *, Item: Dict[str, Any], **_: Any) -> None:
        self.items[(Item["pk"], Item["sk"])] = Item

    def delete_item(self, *, Key: Dict[str, str]) -> None:
        self.items.pop((Key["pk"], Key["sk"]), None)

    def query(self, *, ExpressionAttributeValues: Dict[str, str], **_: Any) -> Dict[str, List[Dict[str, Any]]]:
        pk = ExpressionAttributeValues[":pk"]
        return {"Items": [item for (item_pk, _), item in self.items.items() if item_pk == pk]}

    def update_item(
        self,
        *,
        Key: Dict[str, str],
        UpdateExpression: str,
        ExpressionAttributeValues: Dict[str, Any],
        ExpressionAttributeNames: Dict[str, str] | None = None,
        **_: Any,
    ) -> None:
        item = self.items.setdefault((Key["pk"], Key["sk"]), {"pk": Key["pk"], "sk": Key["sk"]})
        expr = UpdateExpression.strip()
        if expr.startswith("SET"):
            assignments: List[str] = []
            current = []
            depth = 0
            for char in expr[3:]:
                if char == "(":
                    depth += 1
                elif char == ")":
                    depth -= 1
                if char == "," and depth == 0:
                    assignments.append("".join(current))
                    current = []
                else:
                    current.append(char)
            if current:
                assignments.append("".join(current))
            for assignment in assignments:
                left, right = assignment.strip().split("=", 1)
                left = left.strip()
                right = right.strip()
                attr = ExpressionAttributeNames.get(left, left) if ExpressionAttributeNames else left
                if right.startswith("if_not_exists"):
                    fallback = ExpressionAttributeValues.get(":z", 0)
                    delta_key = right.split("+")[-1].strip()
                    delta = int(ExpressionAttributeValues[delta_key])
                    base = int(item.get(attr, fallback))
                    item[attr] = base + delta
                else:
                    item[attr] = ExpressionAttributeValues[right]


def build_request(
    *,
    method: str = "POST",
    body: bytes = b"",
    headers: Dict[str, str] | None = None,
) -> Request:
    scope = {
        "type": "http",
        "method": method,
        "path": "/",
        "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
        "scheme": "http",
        "server": ("testserver", 80),
    }

    async def receive() -> Dict[str, Any]:
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(scope, receive)


def setup_table(fake_table: FakeTable) -> None:
    object.__setattr__(T, "billing", fake_table)


def run_async(coro):
    return asyncio.run(coro)


def setup_stripe_mocks(monkeypatch, *, payment_intent_status: str = "processing") -> None:
    object.__setattr__(S, "stripe_secret_key", "sk_test")
    object.__setattr__(S, "stripe_publishable_key", "pk_test")
    object.__setattr__(S, "stripe_webhook_secret", "whsec_test")

    stripe_mock = MagicMock()
    stripe_mock.Customer.create.return_value = {"id": "cus_123"}
    stripe_mock.Customer.retrieve.return_value = {"metadata": {"app_user_id": "user-123"}}
    stripe_mock.Customer.modify.return_value = {}

    stripe_mock.SetupIntent.create.return_value = {"client_secret": "seti_secret"}
    stripe_mock.SetupIntent.verify_microdeposits.return_value = {"status": "succeeded"}

    stripe_mock.PaymentMethod.attach.return_value = {}
    stripe_mock.PaymentMethod.retrieve.return_value = {"type": "card", "card": {"brand": "visa", "last4": "4242", "exp_month": 1, "exp_year": 2030}}
    stripe_mock.PaymentMethod.detach.return_value = {}

    stripe_mock.PaymentIntent.create.return_value = {"id": "pi_123", "status": payment_intent_status, "amount": 500, "currency": "usd", "payment_method": "pm_123", "customer": "cus_123"}
    stripe_mock.PaymentIntent.retrieve.return_value = {"metadata": {"app_user_id": "user-123"}}

    stripe_mock.Charge.retrieve.return_value = {"payment_intent": "pi_123", "customer": "cus_123"}
    stripe_mock.checkout.Session.create.return_value = MagicMock(id="cs_123", url="https://stripe.example/checkout")

    monkeypatch.setattr("app.routers.billing.stripe", stripe_mock)


def build_webhook_payload(event_type: str, data_object: Dict[str, Any]) -> Dict[str, Any]:
    return {"id": "evt_123", "type": event_type, "data": {"object": data_object}}


def test_billing_balance_initializes(monkeypatch) -> None:
    fake_table = FakeTable()
    setup_table(fake_table)
    setup_stripe_mocks(monkeypatch)

    payload = billing_router.get_balance(ctx={"user_sub": "user-123"})

    assert payload["currency"] == "usd"
    assert payload["owed_pending_cents"] == 0
    assert payload["owed_settled_cents"] == 0
    assert payload["payments_pending_cents"] == 0
    assert payload["payments_settled_cents"] == 0
    assert payload["due_settled_cents"] == 0
    assert payload["due_if_all_settles_cents"] == 0

    assert ("USER#user-123", "BALANCE") in fake_table.items


def test_billing_ledger_limit(monkeypatch) -> None:
    fake_table = FakeTable()
    setup_stripe_mocks(monkeypatch)
    fake_table.put_item(Item={"pk": "USER#user-123", "sk": "LEDGER#1#A", "ts": 1})
    fake_table.put_item(Item={"pk": "USER#user-123", "sk": "LEDGER#2#B", "ts": 2})
    fake_table.put_item(Item={"pk": "USER#user-123", "sk": "LEDGER#3#C", "ts": 3})
    setup_table(fake_table)

    payload = billing_router.list_ledger(ctx={"user_sub": "user-123"}, limit=1)

    assert len(payload["items"]) == 1
    assert payload["items"][0]["sk"] == "LEDGER#3#C"


def test_billing_settings_and_autopay(monkeypatch) -> None:
    fake_table = FakeTable()
    setup_table(fake_table)
    setup_stripe_mocks(monkeypatch)

    settings = billing_router.get_settings(ctx={"user_sub": "user-123"})
    assert settings["autopay_enabled"] is False

    resp = billing_router.set_autopay(body=SetAutopayReq(enabled=True), ctx={"user_sub": "user-123"})
    assert resp["ok"] is True

    settings = billing_router.get_settings(ctx={"user_sub": "user-123"})
    assert settings["autopay_enabled"] is True


def test_billing_setup_intents(monkeypatch) -> None:
    fake_table = FakeTable()
    setup_table(fake_table)
    setup_stripe_mocks(monkeypatch)

    resp = billing_router.create_card_setup_intent(ctx={"user_sub": "user-123"})
    assert resp["client_secret"] == "seti_secret"

    resp = billing_router.create_us_bank_setup_intent(ctx={"user_sub": "user-123"})
    assert resp["client_secret"] == "seti_secret"


def test_billing_verify_microdeposits(monkeypatch) -> None:
    fake_table = FakeTable()
    setup_table(fake_table)
    setup_stripe_mocks(monkeypatch)

    resp = billing_router.verify_microdeposits(body=VerifyMicrodepositsReq(setup_intent_id="seti_123", amounts=[1, 2]), ctx={"user_sub": "user-123"})
    assert resp["status"] == "succeeded"


def test_billing_payment_methods_flow(monkeypatch) -> None:
    fake_table = FakeTable()
    setup_table(fake_table)
    setup_stripe_mocks(monkeypatch)

    fake_table.put_item(Item={"pk": "USER#user-123", "sk": "PM#pm_123", "payment_method_id": "pm_123", "priority": 0})

    resp = billing_router.list_payment_methods(ctx={"user_sub": "user-123"})
    assert resp[0].payment_method_id == "pm_123"

    resp = billing_router.set_priority(body=SetPriorityReq(payment_method_id="pm_123", priority=5), ctx={"user_sub": "user-123"})
    assert resp["ok"] is True

    resp = billing_router.set_default(body=SetDefaultReq(payment_method_id="pm_123"), ctx={"user_sub": "user-123"})
    assert resp["ok"] is True

    resp = billing_router.remove_payment_method(payment_method_id="pm_123", ctx={"user_sub": "user-123"})
    assert resp["ok"] is True


def test_billing_checkout_session(monkeypatch) -> None:
    fake_table = FakeTable()
    setup_table(fake_table)
    setup_stripe_mocks(monkeypatch)

    req = build_request()
    data = billing_router.create_checkout_session(body=BillingCheckoutReq(amount_cents=1200), req=req, ctx={"user_sub": "user-123"})
    assert data["session_id"] == "cs_123"
    assert data["url"] == "https://stripe.example/checkout"


def test_billing_config(monkeypatch) -> None:
    fake_table = FakeTable()
    setup_table(fake_table)
    setup_stripe_mocks(monkeypatch)

    resp = billing_router.billing_config()
    assert resp["publishable_key"] == "pk_test"


def test_billing_pay_balance(monkeypatch) -> None:
    fake_table = FakeTable()
    setup_table(fake_table)
    setup_stripe_mocks(monkeypatch, payment_intent_status="processing")
    fake_table.put_item(Item={"pk": "USER#user-123", "sk": "BILLING", "currency": "usd", "default_payment_method_id": "pm_123"})
    fake_table.put_item(Item={"pk": "USER#user-123", "sk": "BALANCE", "owed_settled_cents": 500, "payments_settled_cents": 0})

    resp = billing_router.pay_balance(body=PayBalanceReq(), ctx={"user_sub": "user-123"})
    assert resp["status"] == "processing"


def test_billing_dev_add_charge(monkeypatch) -> None:
    fake_table = FakeTable()
    setup_table(fake_table)
    setup_stripe_mocks(monkeypatch)

    resp = billing_router.dev_add_charge(body=AddChargeReq(amount_cents=500, state="pending", reason="usage"), ctx={"user_sub": "user-123"})
    assert resp["ok"] is True


def test_billing_webhook_handlers(monkeypatch) -> None:
    fake_table = FakeTable()
    setup_table(fake_table)
    setup_stripe_mocks(monkeypatch)

    import app.routers.billing as billing_module

    def fake_construct_event(*_, **__):
        return build_webhook_payload("setup_intent.succeeded", {"customer": "cus_123", "payment_method": "pm_123"})

    monkeypatch.setattr(billing_module.stripe.Webhook, "construct_event", fake_construct_event)

    req = build_request(body=b"{}", headers={"stripe-signature": "sig"})
    resp = run_async(billing_router.stripe_webhook(req))
    assert resp["received"] is True

    fake_table.put_item(Item={"pk": "USER#user-123", "sk": "PAY#pi_123", "payment_intent_id": "pi_123", "amount_cents": 500, "status": "processing"})

    def fake_construct_pi_event(*_, **__):
        return build_webhook_payload("payment_intent.succeeded", {"id": "pi_123", "status": "succeeded"})

    monkeypatch.setattr(billing_module.stripe.Webhook, "construct_event", fake_construct_pi_event)
    req = build_request(body=b"{}", headers={"stripe-signature": "sig2"})
    resp = run_async(billing_router.stripe_webhook(req))
    assert resp["received"] is True


def test_billing_dispute_webhook(monkeypatch) -> None:
    fake_table = FakeTable()
    setup_table(fake_table)
    setup_stripe_mocks(monkeypatch)

    import app.routers.billing as billing_module

    def fake_dispute_event(*_, **__):
        return build_webhook_payload("charge.dispute.funds_withdrawn", {"charge": "ch_123", "amount": 300, "currency": "usd", "id": "dp_1"})

    monkeypatch.setattr(billing_module.stripe.Webhook, "construct_event", fake_dispute_event)
    req = build_request(body=b"{}", headers={"stripe-signature": "sig3"})
    resp = run_async(billing_router.stripe_webhook(req))
    assert resp["received"] is True


def test_billing_ui_routes_registered() -> None:
    paths = {route.path for route in billing_router.router.routes}
    expected = {
        "/ui/billing/config",
        "/ui/billing/settings",
        "/ui/billing/autopay",
        "/ui/billing/balance",
        "/ui/billing/setup-intent/card",
        "/ui/billing/setup-intent/us-bank",
        "/ui/billing/us-bank/verify-microdeposits",
        "/ui/billing/payment-methods",
        "/ui/billing/payment-methods/priority",
        "/ui/billing/payment-methods/default",
        "/ui/billing/payment-methods/{payment_method_id}",
        "/ui/billing/checkout_session",
        "/ui/billing/pay-balance",
        "/ui/billing/_dev/add-charge",
        "/ui/billing/ledger",
    }
    assert expected.issubset(paths)


def test_billing_card_flow_to_charge(monkeypatch) -> None:
    fake_table = FakeTable()
    setup_table(fake_table)
    setup_stripe_mocks(monkeypatch, payment_intent_status="processing")

    import app.routers.billing as billing_module

    def fake_card_event(*_, **__):
        return build_webhook_payload("setup_intent.succeeded", {"customer": "cus_123", "payment_method": "pm_card"})

    monkeypatch.setattr(billing_module.stripe.Webhook, "construct_event", fake_card_event)
    req = build_request(body=b"{}", headers={"stripe-signature": "sig-card"})
    resp = run_async(billing_router.stripe_webhook(req))
    assert resp["received"] is True

    fake_table.put_item(Item={"pk": "USER#user-123", "sk": "BILLING", "currency": "usd", "default_payment_method_id": "pm_card"})
    fake_table.put_item(Item={"pk": "USER#user-123", "sk": "BALANCE", "owed_settled_cents": 500, "payments_settled_cents": 0})

    pay = billing_router.pay_balance(body=PayBalanceReq(), ctx={"user_sub": "user-123"})
    assert pay["status"] == "processing"


def test_billing_bank_verify_and_charge(monkeypatch) -> None:
    fake_table = FakeTable()
    setup_table(fake_table)
    setup_stripe_mocks(monkeypatch, payment_intent_status="processing")

    verify = billing_router.verify_microdeposits(
        body=VerifyMicrodepositsReq(setup_intent_id="seti_bank", amounts=[11, 22]),
        ctx={"user_sub": "user-123"},
    )
    assert verify["status"] == "succeeded"

    import app.routers.billing as billing_module

    def fake_bank_event(*_, **__):
        return build_webhook_payload("setup_intent.succeeded", {"customer": "cus_123", "payment_method": "pm_bank"})

    monkeypatch.setattr(billing_module.stripe.Webhook, "construct_event", fake_bank_event)
    req = build_request(body=b"{}", headers={"stripe-signature": "sig-bank"})
    resp = run_async(billing_router.stripe_webhook(req))
    assert resp["received"] is True

    fake_table.put_item(Item={"pk": "USER#user-123", "sk": "BILLING", "currency": "usd", "default_payment_method_id": "pm_bank"})
    fake_table.put_item(Item={"pk": "USER#user-123", "sk": "BALANCE", "owed_settled_cents": 700, "payments_settled_cents": 0})

    pay = billing_router.pay_balance(body=PayBalanceReq(), ctx={"user_sub": "user-123"})
    assert pay["status"] == "processing"


def test_billing_rejects_invalid_checkout_amount(monkeypatch) -> None:
    fake_table = FakeTable()
    setup_table(fake_table)
    setup_stripe_mocks(monkeypatch)

    req = build_request()
    try:
        billing_router.create_checkout_session(body=BillingCheckoutReq(amount_cents=0), req=req, ctx={"user_sub": "user-123"})
    except HTTPException as exc:
        assert exc.status_code == 400
    else:
        raise AssertionError("Expected HTTPException for invalid amount")


def test_billing_microdeposits_require_payload(monkeypatch) -> None:
    fake_table = FakeTable()
    setup_table(fake_table)
    setup_stripe_mocks(monkeypatch)

    try:
        billing_router.verify_microdeposits(
            body=VerifyMicrodepositsReq(setup_intent_id="seti_missing"),
            ctx={"user_sub": "user-123"},
        )
    except HTTPException as exc:
        assert exc.status_code == 400
    else:
        raise AssertionError("Expected HTTPException for missing verification data")


def test_billing_pay_balance_requires_default_pm(monkeypatch) -> None:
    fake_table = FakeTable()
    setup_table(fake_table)
    setup_stripe_mocks(monkeypatch)
    fake_table.put_item(Item={"pk": "USER#user-123", "sk": "BALANCE", "owed_settled_cents": 500, "payments_settled_cents": 0})

    try:
        billing_router.pay_balance(body=PayBalanceReq(), ctx={"user_sub": "user-123"})
    except HTTPException as exc:
        assert exc.status_code == 400
    else:
        raise AssertionError("Expected HTTPException when default payment method missing")


def test_billing_default_pm_requires_existing_method(monkeypatch) -> None:
    fake_table = FakeTable()
    setup_table(fake_table)
    setup_stripe_mocks(monkeypatch)

    try:
        billing_router.set_default(body=SetDefaultReq(payment_method_id="pm_missing"), ctx={"user_sub": "user-123"})
    except HTTPException as exc:
        assert exc.status_code == 404
    else:
        raise AssertionError("Expected HTTPException when payment method not found")


def test_billing_webhook_allows_missing_signature(monkeypatch) -> None:
    fake_table = FakeTable()
    setup_table(fake_table)
    setup_stripe_mocks(monkeypatch)

    req = build_request(body=b"{}")
    resp = run_async(billing_router.stripe_webhook(req))
    assert resp["received"] is True
