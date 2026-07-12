from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple
from unittest.mock import MagicMock

import pytest

from starlette.requests import Request
from fastapi import HTTPException

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))

sys.modules.setdefault("stripe", MagicMock())

from app.auth.deps import AuthenticatedUser
from app.auth.roles import AdminProfile, AdminProfileType, AdminScope, Role
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
    StripeChargeReq,
    VerifyMicrodepositsReq,
)
from app.services.payment_incident_providers import CanonicalProviderEvent, VerificationResult
from app.services.payment_incident_transitions import TransitionResult


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




def _user_actor(sub: str = "user-123") -> AuthenticatedUser:
    return AuthenticatedUser(sub=sub, role=Role.USER)


def _billing_admin_actor(sub: str = "admin-1") -> AuthenticatedUser:
    return AuthenticatedUser(
        sub=sub,
        role=Role.ADMIN,
        admin_profile=AdminProfile(type=AdminProfileType.SCOPED, scopes=(AdminScope.BILLING_SUPPORT,)),
    )


def _scoped_admin_actor(sub: str, scope: AdminScope) -> AuthenticatedUser:
    return AuthenticatedUser(
        sub=sub,
        role=Role.ADMIN,
        admin_profile=AdminProfile(type=AdminProfileType.SCOPED, scopes=(scope,)),
    )

def setup_table(fake_table: FakeTable) -> None:
    object.__setattr__(T, "billing", fake_table)


def run_async(coro):
    return asyncio.run(coro)


def setup_stripe_mocks(monkeypatch, *, payment_intent_status: str = "processing") -> None:
    object.__setattr__(S, "stripe_secret_key", "sk_test")
    object.__setattr__(S, "stripe_publishable_key", "pk_test")
    object.__setattr__(S, "stripe_webhook_secret", "whsec_test")

    # Patch fraud detection and purchase history so billing route tests never
    # hit real DynamoDB (GAP-0206/0207 fraud gates + purchase_history tracking
    # were both added after these tests were first written).
    # billing.py imports these names at module level, so patch billing's namespace.
    import app.routers.billing as _billing_mod
    monkeypatch.setattr(_billing_mod, "_fraud_gate", lambda *a, **kw: None)
    monkeypatch.setattr(_billing_mod, "_require_provider_enabled", lambda *a, **kw: None)
    monkeypatch.setattr(_billing_mod, "record_billing_transaction", lambda *a, **kw: "txn_fake")
    monkeypatch.setattr(_billing_mod, "mark_completed", lambda *a, **kw: None)
    monkeypatch.setattr(_billing_mod, "mark_reverted", lambda *a, **kw: None)

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
    stripe_mock.Subscription.list.return_value = {"data": [{"id": "sub_123"}]}

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


def test_billing_charge_once(monkeypatch) -> None:
    fake_table = FakeTable()
    setup_table(fake_table)
    setup_stripe_mocks(monkeypatch, payment_intent_status="processing")
    fake_table.put_item(Item={"pk": "USER#user-123", "sk": "BILLING", "currency": "usd", "default_payment_method_id": "pm_123"})
    fake_table.put_item(Item={"pk": "USER#user-123", "sk": "BALANCE", "owed_settled_cents": 0, "payments_settled_cents": 0})

    resp = billing_router.charge_once(body=StripeChargeReq(amount_cents=650), ctx={"user_sub": "user-123"})
    assert resp["status"] == "processing"
    assert resp["payment_intent_id"] == "pi_123"


def test_billing_payments_and_subscriptions(monkeypatch) -> None:
    fake_table = FakeTable()
    setup_table(fake_table)
    setup_stripe_mocks(monkeypatch)
    fake_table.put_item(Item={"pk": "USER#user-123", "sk": "PAY#pi_123", "payment_intent_id": "pi_123", "created_at": 1})

    payments = billing_router.list_payments(ctx={"user_sub": "user-123"})
    assert payments["items"][0]["payment_intent_id"] == "pi_123"

    monkeypatch.setattr(billing_router, "S", type("S", (), {
        "dev_mode": False, "stripe_secret_key": "sk_test", "stripe_api_base": None,
    })())
    subs = billing_router.list_subscriptions(ctx={"user_sub": "user-123"})
    assert subs["items"][0]["id"] == "sub_123"


def test_billing_read_surfaces_allow_admin_target_override(monkeypatch) -> None:
    fake_table = FakeTable()
    setup_table(fake_table)
    setup_stripe_mocks(monkeypatch)
    fake_table.put_item(Item={"pk": "USER#target-1", "sk": "BILLING", "autopay_enabled": True, "currency": "usd", "default_payment_method_id": None})
    fake_table.put_item(Item={"pk": "USER#target-1", "sk": "BALANCE", "owed_settled_cents": 42, "payments_settled_cents": 0})
    fake_table.put_item(Item={"pk": "USER#target-1", "sk": "LEDGER#10#A", "ts": 10})
    fake_table.put_item(Item={"pk": "USER#target-1", "sk": "PAY#pi_target", "payment_intent_id": "pi_target", "created_at": 1})

    admin_ctx = {"user_sub": "admin-1", "role": "admin"}
    settings = billing_router.get_settings(ctx=admin_ctx, actor=_billing_admin_actor(), user_sub="target-1")
    assert settings["autopay_enabled"] is True

    balance = billing_router.get_balance(ctx=admin_ctx, actor=_billing_admin_actor(), user_sub="target-1")
    assert balance["owed_settled_cents"] == 42

    ledger = billing_router.list_ledger(ctx=admin_ctx, actor=_billing_admin_actor(), user_sub="target-1")
    assert ledger["items"][0]["sk"] == "LEDGER#10#A"

    payments = billing_router.list_payments(ctx=admin_ctx, actor=_billing_admin_actor(), user_sub="target-1")
    assert payments["items"][0]["payment_intent_id"] == "pi_target"

    monkeypatch.setattr(billing_router, "S", type("S", (), {
        "dev_mode": False, "stripe_secret_key": "sk_test", "stripe_api_base": None,
    })())
    subs = billing_router.list_subscriptions(ctx=admin_ctx, actor=_billing_admin_actor(), user_sub="target-1")
    assert subs["items"][0]["id"] == "sub_123"


def test_billing_read_surfaces_keep_user_scoped(monkeypatch) -> None:
    fake_table = FakeTable()
    setup_table(fake_table)
    setup_stripe_mocks(monkeypatch)

    user_ctx = {"user_sub": "user-123", "role": "user"}

    try:
        billing_router.get_balance(ctx=user_ctx, actor=_user_actor(), user_sub="target-1")
    except HTTPException as exc:
        assert exc.status_code == 403
        assert exc.detail["code"] == "role_required"
    else:
        raise AssertionError("Expected HTTPException when normal user requests another user's billing")


def test_billing_dev_add_charge(monkeypatch) -> None:
    fake_table = FakeTable()
    setup_table(fake_table)
    setup_stripe_mocks(monkeypatch)

    resp = billing_router.dev_add_charge(body=AddChargeReq(amount_cents=500, state="pending", reason="usage"), ctx={"user_sub": "user-123"}, actor=_billing_admin_actor("user-123"))
    assert resp["ok"] is True


def test_admin_can_write_billing_for_target_with_audit_tags(monkeypatch) -> None:
    fake_table = FakeTable()
    setup_table(fake_table)
    setup_stripe_mocks(monkeypatch)
    fake_table.put_item(Item={"pk": "USER#target-1", "sk": "PM#pm_123", "payment_method_id": "pm_123", "priority": 0})

    audit_calls: list[dict[str, Any]] = []

    def _capture_audit(_event: str, _user_sub: str, _request=None, **fields: Any) -> None:
        audit_calls.append(fields)

    monkeypatch.setattr("app.routers.billing.audit_event", _capture_audit)

    resp = billing_router.set_default(
        body=SetDefaultReq(payment_method_id="pm_123"),
        req=build_request(),
        ctx={"user_sub": "admin-1", "role": "admin"},
        actor=_billing_admin_actor(),
        user_sub="target-1",
    )
    assert resp["ok"] is True
    assert fake_table.items[("USER#target-1", "BILLING")]["default_payment_method_id"] == "pm_123"

    assert audit_calls
    fields = audit_calls[-1]
    assert fields["viewed_as_admin"] is True
    assert fields["viewed-as-admin"] is True
    assert fields["actor_sub"] == "admin-1"
    assert fields["effective_sub"] == "target-1"


def test_non_privileged_user_cannot_write_other_users_billing(monkeypatch) -> None:
    fake_table = FakeTable()
    setup_table(fake_table)
    setup_stripe_mocks(monkeypatch)

    try:
        billing_router.pay_balance(
            body=PayBalanceReq(),
            req=build_request(),
            ctx={"user_sub": "user-123", "role": "user"},
            actor=_user_actor(),
            user_sub="target-1",
        )
    except HTTPException as exc:
        assert exc.status_code == 403
        assert exc.detail["code"] == "role_required"
    else:
        raise AssertionError("Expected HTTPException for unauthorized cross-user billing write")


def test_admin_checkout_session_and_dev_add_charge_targeted(monkeypatch) -> None:
    fake_table = FakeTable()
    setup_table(fake_table)
    setup_stripe_mocks(monkeypatch)

    audit_calls: list[dict[str, Any]] = []

    def _capture_audit(_event: str, _user_sub: str, _request=None, **fields: Any) -> None:
        audit_calls.append(fields)

    monkeypatch.setattr("app.routers.billing.audit_event", _capture_audit)

    req = build_request()
    data = billing_router.create_checkout_session(
        body=BillingCheckoutReq(amount_cents=1200),
        req=req,
        ctx={"user_sub": "admin-1", "role": "admin"},
        actor=_billing_admin_actor(),
        user_sub="target-1",
    )
    assert data["session_id"] == "cs_123"

    resp = billing_router.dev_add_charge(
        body=AddChargeReq(amount_cents=500, state="pending", reason="ops"),
        req=req,
        ctx={"user_sub": "admin-1", "role": "admin"},
        actor=_billing_admin_actor(),
        user_sub="target-1",
    )
    assert resp["ok"] is True

    assert any(fields.get("viewed_as_admin") for fields in audit_calls)
    assert fake_table.items[("USER#target-1", "BALANCE")]["owed_pending_cents"] == 500


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
        "/ui/billing/charge-once",
        "/ui/billing/checkout_session",
        "/ui/billing/pay-balance",
        "/ui/billing/_dev/add-charge",
        "/ui/billing/ledger",
        "/ui/billing/payments",
        "/ui/billing/subscriptions",
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


def test_stripe_payment_incidents_webhook_rejects_invalid_signature(monkeypatch) -> None:
    class _BadAdapter:
        provider_key = "stripe"

        def verify_webhook(self, **kwargs):
            return VerificationResult(valid=False, code="invalid_signature", message="bad sig")

        def parse_webhook_events(self, **kwargs):
            return []

    monkeypatch.setattr(billing_router, "ensure_stripe_configured", lambda: None)
    object.__setattr__(S, "stripe_webhook_secret", "whsec_test")
    monkeypatch.setattr(billing_router, "resolve_provider_adapter", lambda _: _BadAdapter())

    req = build_request(body=b"{}", headers={"stripe-signature": "bad"})
    with pytest.raises(HTTPException) as exc:
        run_async(billing_router.stripe_payment_incidents_webhook(req))

    assert exc.value.status_code == 400
    assert exc.value.detail["code"] == "invalid_signature"


def test_stripe_payment_incidents_webhook_rejects_verification_errors(monkeypatch) -> None:
    class _BadAdapter:
        provider_key = "stripe"

        def verify_webhook(self, **kwargs):
            raise RuntimeError("boom")

        def parse_webhook_events(self, **kwargs):
            return []

    webhook_calls = []
    monkeypatch.setattr(billing_router, "ensure_stripe_configured", lambda: None)
    object.__setattr__(S, "stripe_webhook_secret", "whsec_test")
    monkeypatch.setattr(billing_router, "resolve_provider_adapter", lambda _: _BadAdapter())
    monkeypatch.setattr(billing_router, "record_webhook_outcome", lambda **kwargs: webhook_calls.append(kwargs))

    req = build_request(body=b"{}", headers={"stripe-signature": "bad"})
    with pytest.raises(HTTPException) as exc:
        run_async(billing_router.stripe_payment_incidents_webhook(req))

    assert exc.value.status_code == 400
    assert exc.value.detail["code"] == "verification_error"
    assert webhook_calls == [{"provider": "stripe", "outcome": "rejected", "reason": "verification_error"}]


def test_stripe_payment_incidents_webhook_creates_and_dedupes(monkeypatch) -> None:
    class _Repo:
        def __init__(self):
            self.rows = []

        def list_incidents_by_case(self, *, provider: str, case_id: str, limit: int = 1):
            return [r for r in self.rows if r["provider"] == provider and r["provider_incident_id"] == case_id][:limit]

        def put_incident(self, row):
            self.rows.append(dict(row))
            return self.rows[-1]

        def get_ticket_link(self, incident_id):
            return None

        def put_ticket_link(self, **kwargs):
            return {}

    class _Adapter:
        provider_key = "stripe"

        def verify_webhook(self, **kwargs):
            return VerificationResult(valid=True, code="ok", message="ok")

        def parse_webhook_events(self, **kwargs):
            return [
                CanonicalProviderEvent(
                    provider="stripe",
                    provider_event_id="evt_1",
                    incident_id="dp_1",
                    incident_type="dispute",
                    target_status="opened",
                    payload={"source_event_type": "charge.dispute.created"},
                )
            ]

    class _Service:
        seen = set()

        def __init__(self, repository):
            self.repository = repository

        def apply_provider_transition(self, **kwargs):
            event_id = kwargs["provider_event_id"]
            duplicate = event_id in self.seen
            self.seen.add(event_id)
            return TransitionResult(
                incident={"incident_id": kwargs["incident_id"], "status": kwargs["target_status"]},
                duplicate=duplicate,
                emitted_events=[],
            )

    repo = _Repo()
    billing_router._PAYMENT_INCIDENT_WEBHOOK_REPLAY_CACHE.clear()
    monkeypatch.setattr(billing_router, "ensure_stripe_configured", lambda: None)
    object.__setattr__(S, "stripe_webhook_secret", "whsec_test")
    monkeypatch.setattr(billing_router, "resolve_provider_adapter", lambda _: _Adapter())
    monkeypatch.setattr(billing_router, "DynamoPaymentIncidentRepository", lambda: repo)
    monkeypatch.setattr(billing_router, "PaymentIncidentTransitionService", _Service)

    req = build_request(body=b"{}", headers={"stripe-signature": "ok"})
    first = run_async(billing_router.stripe_payment_incidents_webhook(req))
    billing_router._PAYMENT_INCIDENT_WEBHOOK_REPLAY_CACHE.clear()
    second = run_async(billing_router.stripe_payment_incidents_webhook(req))

    assert first["received"] is True
    assert first["processed"] == 1
    assert first["deduped"] == 0
    assert second["deduped"] == 1
    assert len(repo.rows) == 1


def test_paypal_payment_incidents_webhook_rejects_invalid_signature(monkeypatch) -> None:
    class _BadAdapter:
        provider_key = "paypal"

        def verify_webhook(self, **kwargs):
            return VerificationResult(valid=False, code="invalid_signature", message="bad sig")

        def parse_webhook_events(self, **kwargs):
            return []

    monkeypatch.setattr(billing_router, "resolve_provider_adapter", lambda _: _BadAdapter())

    req = build_request(body=b"{}", headers={"paypal-transmission-sig": "bad"})
    with pytest.raises(HTTPException) as exc:
        run_async(billing_router.paypal_payment_incidents_webhook(req))

    assert exc.value.status_code == 400
    assert exc.value.detail["code"] == "invalid_signature"


def test_paypal_payment_incidents_webhook_creates_and_dedupes(monkeypatch) -> None:
    class _Repo:
        def __init__(self):
            self.rows = []

        def list_incidents_by_case(self, *, provider: str, case_id: str, limit: int = 1):
            return [r for r in self.rows if r["provider"] == provider and r["provider_incident_id"] == case_id][:limit]

        def put_incident(self, row):
            self.rows.append(dict(row))
            return self.rows[-1]

        def get_ticket_link(self, incident_id):
            return None

        def put_ticket_link(self, **kwargs):
            return {}

    class _Adapter:
        provider_key = "paypal"

        def verify_webhook(self, **kwargs):
            return VerificationResult(valid=True, code="ok", message="ok")

        def parse_webhook_events(self, **kwargs):
            return [
                CanonicalProviderEvent(
                    provider="paypal",
                    provider_event_id="evt_p1",
                    incident_id="PP-D-1",
                    incident_type="dispute",
                    target_status="opened",
                    payload={"source_event_type": "CUSTOMER.DISPUTE.CREATED"},
                )
            ]

    class _Service:
        seen = set()

        def __init__(self, repository):
            self.repository = repository

        def apply_provider_transition(self, **kwargs):
            event_id = kwargs["provider_event_id"]
            duplicate = event_id in self.seen
            self.seen.add(event_id)
            return TransitionResult(
                incident={"incident_id": kwargs["incident_id"], "status": kwargs["target_status"]},
                duplicate=duplicate,
                emitted_events=[],
            )

    repo = _Repo()
    billing_router._PAYMENT_INCIDENT_WEBHOOK_REPLAY_CACHE.clear()
    monkeypatch.setattr(billing_router, "resolve_provider_adapter", lambda _: _Adapter())
    monkeypatch.setattr(billing_router, "DynamoPaymentIncidentRepository", lambda: repo)
    monkeypatch.setattr(billing_router, "PaymentIncidentTransitionService", _Service)

    req = build_request(body=b"{}", headers={"paypal-transmission-sig": "ok"})
    first = run_async(billing_router.paypal_payment_incidents_webhook(req))
    billing_router._PAYMENT_INCIDENT_WEBHOOK_REPLAY_CACHE.clear()
    second = run_async(billing_router.paypal_payment_incidents_webhook(req))

    assert first["received"] is True
    assert first["processed"] == 1
    assert first["deduped"] == 0
    assert second["deduped"] == 1
    assert len(repo.rows) == 1


def test_ccbill_payment_incidents_webhook_rejects_invalid_signature(monkeypatch) -> None:
    class _BadAdapter:
        provider_key = "ccbill"

        def verify_webhook(self, **kwargs):
            return VerificationResult(valid=False, code="invalid_signature", message="bad sig")

        def parse_webhook_events(self, **kwargs):
            return []

    monkeypatch.setattr(billing_router, "resolve_provider_adapter", lambda _: _BadAdapter())

    req = build_request(body=b"{}", headers={"x-ccbill-signature": "bad"})
    with pytest.raises(HTTPException) as exc:
        run_async(billing_router.ccbill_payment_incidents_webhook(req))

    assert exc.value.status_code == 400
    assert exc.value.detail["code"] == "invalid_signature"


def test_ccbill_payment_incidents_webhook_creates_and_dedupes(monkeypatch) -> None:
    class _Repo:
        def __init__(self):
            self.rows = []

        def list_incidents_by_case(self, *, provider: str, case_id: str, limit: int = 1):
            return [r for r in self.rows if r["provider"] == provider and r["provider_incident_id"] == case_id][:limit]

        def put_incident(self, row):
            self.rows.append(dict(row))
            return self.rows[-1]

        def get_ticket_link(self, incident_id):
            return None

        def put_ticket_link(self, **kwargs):
            return {}

    class _Adapter:
        provider_key = "ccbill"

        def verify_webhook(self, **kwargs):
            return VerificationResult(valid=True, code="ok", message="ok")

        def parse_webhook_events(self, **kwargs):
            return [
                CanonicalProviderEvent(
                    provider="ccbill",
                    provider_event_id="evt_c1",
                    incident_id="cb_1",
                    incident_type="chargeback",
                    target_status="opened",
                    payload={"source_event_type": "Chargeback"},
                )
            ]

    class _Service:
        seen = set()

        def __init__(self, repository):
            self.repository = repository

        def apply_provider_transition(self, **kwargs):
            event_id = kwargs["provider_event_id"]
            duplicate = event_id in self.seen
            self.seen.add(event_id)
            return TransitionResult(
                incident={"incident_id": kwargs["incident_id"], "status": kwargs["target_status"]},
                duplicate=duplicate,
                emitted_events=[],
            )

    repo = _Repo()
    billing_router._PAYMENT_INCIDENT_WEBHOOK_REPLAY_CACHE.clear()
    monkeypatch.setattr(billing_router, "resolve_provider_adapter", lambda _: _Adapter())
    monkeypatch.setattr(billing_router, "DynamoPaymentIncidentRepository", lambda: repo)
    monkeypatch.setattr(billing_router, "PaymentIncidentTransitionService", _Service)

    req = build_request(body=b"{}", headers={"x-ccbill-signature": "ok"})
    first = run_async(billing_router.ccbill_payment_incidents_webhook(req))
    billing_router._PAYMENT_INCIDENT_WEBHOOK_REPLAY_CACHE.clear()
    second = run_async(billing_router.ccbill_payment_incidents_webhook(req))

    assert first["received"] is True
    assert first["processed"] == 1
    assert first["deduped"] == 0
    assert second["deduped"] == 1
    assert len(repo.rows) == 1


@pytest.mark.parametrize(
    "provider,header,endpoint",
    [
        ("stripe", "stripe-signature", "stripe_payment_incidents_webhook"),
        ("paypal", "paypal-transmission-sig", "paypal_payment_incidents_webhook"),
        ("ccbill", "x-ccbill-signature", "ccbill_payment_incidents_webhook"),
    ],
)
def test_payment_incident_webhook_rejects_parse_errors(monkeypatch, provider: str, header: str, endpoint: str) -> None:
    class _BadAdapter:
        provider_key = provider

        def verify_webhook(self, **kwargs):
            return VerificationResult(valid=True, code="ok", message="ok")

        def parse_webhook_events(self, **kwargs):
            raise ValueError("bad payload")

    webhook_calls = []
    object.__setattr__(S, "stripe_webhook_secret", "whsec_test")
    monkeypatch.setattr(billing_router, "ensure_stripe_configured", lambda: None)
    monkeypatch.setattr(billing_router, "resolve_provider_adapter", lambda _: _BadAdapter())
    monkeypatch.setattr(billing_router, "record_webhook_outcome", lambda **kwargs: webhook_calls.append(kwargs))

    req = build_request(body=b"{}", headers={header: "ok"})
    webhook_handler = getattr(billing_router, endpoint)
    with pytest.raises(HTTPException) as exc:
        run_async(webhook_handler(req))

    assert exc.value.status_code == 400
    assert exc.value.detail["code"] == "invalid_payload"
    assert webhook_calls == [{"provider": provider, "outcome": "rejected", "reason": "invalid_payload"}]


@pytest.mark.parametrize(
    "provider,header,endpoint",
    [
        ("stripe", "stripe-signature", "stripe_payment_incidents_webhook"),
        ("paypal", "paypal-transmission-sig", "paypal_payment_incidents_webhook"),
        ("ccbill", "x-ccbill-signature", "ccbill_payment_incidents_webhook"),
    ],
)
def test_payment_incident_webhook_rejects_unsupported_content_type(monkeypatch, provider: str, header: str, endpoint: str) -> None:
    class _GuardAdapter:
        provider_key = provider

        def verify_webhook(self, **kwargs):
            raise AssertionError("verify_webhook should not be called for unsupported content type")

        def parse_webhook_events(self, **kwargs):
            raise AssertionError("parse_webhook_events should not be called for unsupported content type")

    webhook_calls = []
    object.__setattr__(S, "payment_incidents_webhook_allowed_content_types", "application/json")
    object.__setattr__(S, "stripe_webhook_secret", "whsec_test")
    monkeypatch.setattr(billing_router, "ensure_stripe_configured", lambda: None)
    monkeypatch.setattr(billing_router, "resolve_provider_adapter", lambda _: _GuardAdapter())
    monkeypatch.setattr(billing_router, "record_webhook_outcome", lambda **kwargs: webhook_calls.append(kwargs))

    req = build_request(body=b"{}", headers={header: "ok", "content-type": "text/plain"})
    webhook_handler = getattr(billing_router, endpoint)
    with pytest.raises(HTTPException) as exc:
        run_async(webhook_handler(req))

    assert exc.value.status_code == 415
    assert exc.value.detail["code"] == "unsupported_media_type"
    assert webhook_calls == [{"provider": provider, "outcome": "rejected", "reason": "unsupported_media_type"}]


@pytest.mark.parametrize(
    "provider,header,endpoint",
    [
        ("stripe", "stripe-signature", "stripe_payment_incidents_webhook"),
        ("paypal", "paypal-transmission-sig", "paypal_payment_incidents_webhook"),
        ("ccbill", "x-ccbill-signature", "ccbill_payment_incidents_webhook"),
    ],
)
def test_payment_incident_webhook_rejects_oversized_signature(monkeypatch, provider: str, header: str, endpoint: str) -> None:
    class _GuardAdapter:
        provider_key = provider

        def verify_webhook(self, **kwargs):
            raise AssertionError("verify_webhook should not be called for oversized signatures")

        def parse_webhook_events(self, **kwargs):
            raise AssertionError("parse_webhook_events should not be called for oversized signatures")

    webhook_calls = []
    object.__setattr__(S, "payment_incidents_webhook_max_signature_bytes", 64)
    object.__setattr__(S, "stripe_webhook_secret", "whsec_test")
    monkeypatch.setattr(billing_router, "ensure_stripe_configured", lambda: None)
    monkeypatch.setattr(billing_router, "resolve_provider_adapter", lambda _: _GuardAdapter())
    monkeypatch.setattr(billing_router, "record_webhook_outcome", lambda **kwargs: webhook_calls.append(kwargs))

    oversized_sig = "x" * 65
    req = build_request(body=b"{}", headers={header: oversized_sig})
    webhook_handler = getattr(billing_router, endpoint)
    with pytest.raises(HTTPException) as exc:
        run_async(webhook_handler(req))

    assert exc.value.status_code == 400
    assert exc.value.detail["code"] == "signature_too_large"
    assert webhook_calls == [{"provider": provider, "outcome": "rejected", "reason": "signature_too_large"}]


@pytest.mark.parametrize(
    "provider,header,endpoint",
    [
        ("stripe", "stripe-signature", "stripe_payment_incidents_webhook"),
        ("paypal", "paypal-transmission-sig", "paypal_payment_incidents_webhook"),
        ("ccbill", "x-ccbill-signature", "ccbill_payment_incidents_webhook"),
    ],
)
def test_payment_incident_webhook_rejects_too_many_events(monkeypatch, provider: str, header: str, endpoint: str) -> None:
    class _Adapter:
        provider_key = provider

        def verify_webhook(self, **kwargs):
            return VerificationResult(valid=True, code="ok", message="ok")

        def parse_webhook_events(self, **kwargs):
            return [
                CanonicalProviderEvent(
                    provider=provider,
                    provider_event_id="evt_1",
                    incident_id="inc_1",
                    incident_type="dispute",
                    target_status="opened",
                    payload={"source_event_type": "provider.event"},
                ),
                CanonicalProviderEvent(
                    provider=provider,
                    provider_event_id="evt_2",
                    incident_id="inc_2",
                    incident_type="dispute",
                    target_status="opened",
                    payload={"source_event_type": "provider.event"},
                ),
            ]

    webhook_calls = []
    object.__setattr__(S, "payment_incidents_webhook_max_events", 1)
    object.__setattr__(S, "stripe_webhook_secret", "whsec_test")
    monkeypatch.setattr(billing_router, "ensure_stripe_configured", lambda: None)
    monkeypatch.setattr(billing_router, "resolve_provider_adapter", lambda _: _Adapter())
    monkeypatch.setattr(billing_router, "record_webhook_outcome", lambda **kwargs: webhook_calls.append(kwargs))

    req = build_request(body=b"{}", headers={header: "ok"})
    webhook_handler = getattr(billing_router, endpoint)
    with pytest.raises(HTTPException) as exc:
        run_async(webhook_handler(req))

    assert exc.value.status_code == 400
    assert exc.value.detail["code"] == "too_many_events"
    assert webhook_calls == [{"provider": provider, "outcome": "rejected", "reason": "too_many_events"}]


@pytest.mark.parametrize(
    "provider,header,endpoint",
    [
        ("stripe", "stripe-signature", "stripe_payment_incidents_webhook"),
        ("paypal", "paypal-transmission-sig", "paypal_payment_incidents_webhook"),
        ("ccbill", "x-ccbill-signature", "ccbill_payment_incidents_webhook"),
    ],
)
def test_payment_incident_webhook_rejects_oversized_payload(monkeypatch, provider: str, header: str, endpoint: str) -> None:
    class _GuardAdapter:
        provider_key = provider

        def verify_webhook(self, **kwargs):
            raise AssertionError("verify_webhook should not be called for oversized payloads")

        def parse_webhook_events(self, **kwargs):
            raise AssertionError("parse_webhook_events should not be called for oversized payloads")

    webhook_calls = []
    object.__setattr__(S, "payment_incidents_webhook_max_body_bytes", 1024)
    object.__setattr__(S, "stripe_webhook_secret", "whsec_test")
    monkeypatch.setattr(billing_router, "ensure_stripe_configured", lambda: None)
    monkeypatch.setattr(billing_router, "resolve_provider_adapter", lambda _: _GuardAdapter())
    monkeypatch.setattr(
        billing_router,
        "record_webhook_outcome",
        lambda **kwargs: webhook_calls.append(kwargs),
    )

    oversized_body = b"x" * 1025
    req = build_request(body=oversized_body, headers={header: "ok", "content-length": str(len(oversized_body))})
    webhook_handler = getattr(billing_router, endpoint)
    with pytest.raises(HTTPException) as exc:
        run_async(webhook_handler(req))

    assert exc.value.status_code == 413
    assert exc.value.detail["code"] == "payload_too_large"
    assert webhook_calls == [{"provider": provider, "outcome": "rejected", "reason": "payload_too_large"}]


def test_payment_incident_webhook_rejects_replay_delivery(monkeypatch) -> None:
    class _Adapter:
        provider_key = "stripe"

        def verify_webhook(self, **kwargs):
            return VerificationResult(valid=True, code="ok", message="ok")

        def parse_webhook_events(self, **kwargs):
            return [
                CanonicalProviderEvent(
                    provider="stripe",
                    provider_event_id="evt_replay",
                    incident_id="dp_replay_1",
                    incident_type="dispute",
                    target_status="opened",
                    payload={"source_event_type": "charge.dispute.created"},
                )
            ]

    class _Repo:
        def __init__(self):
            self.rows = []

        def list_incidents_by_case(self, *, provider: str, case_id: str, limit: int = 1):
            return [r for r in self.rows if r["provider"] == provider and r["provider_incident_id"] == case_id][:limit]

        def put_incident(self, row):
            self.rows.append(dict(row))
            return self.rows[-1]

        def get_ticket_link(self, incident_id):
            return None

        def put_ticket_link(self, **kwargs):
            return {}

    class _Service:
        def __init__(self, repository):
            self.repository = repository

        def apply_provider_transition(self, **kwargs):
            return TransitionResult(
                incident={"incident_id": kwargs["incident_id"], "status": kwargs["target_status"]},
                duplicate=False,
                emitted_events=[],
            )

    billing_router._PAYMENT_INCIDENT_WEBHOOK_REPLAY_CACHE.clear()
    webhook_calls = []
    object.__setattr__(S, "payment_incidents_webhook_replay_ttl_seconds", 300)
    object.__setattr__(S, "payment_incidents_webhook_replay_cache_size", 1000)
    object.__setattr__(S, "stripe_webhook_secret", "whsec_test")
    monkeypatch.setattr(billing_router, "ensure_stripe_configured", lambda: None)
    monkeypatch.setattr(billing_router, "resolve_provider_adapter", lambda _: _Adapter())
    monkeypatch.setattr(billing_router, "DynamoPaymentIncidentRepository", lambda: _Repo())
    monkeypatch.setattr(billing_router, "PaymentIncidentTransitionService", _Service)
    monkeypatch.setattr(billing_router, "record_webhook_outcome", lambda **kwargs: webhook_calls.append(kwargs))

    req = build_request(body=b"{\"id\":\"evt_replay\"}", headers={"stripe-signature": "sig_1"})
    first = run_async(billing_router.stripe_payment_incidents_webhook(req))
    assert first["received"] is True
    assert first["processed"] == 1

    with pytest.raises(HTTPException) as exc:
        run_async(billing_router.stripe_payment_incidents_webhook(req))

    assert exc.value.status_code == 409
    assert exc.value.detail["code"] == "replay_detected"
    assert webhook_calls[-1] == {"provider": "stripe", "outcome": "rejected", "reason": "replay_detected"}


def test_payment_incident_webhook_parse_error_does_not_poison_replay_cache(monkeypatch) -> None:
    class _FlakyAdapter:
        provider_key = "stripe"

        def __init__(self):
            self.calls = 0

        def verify_webhook(self, **kwargs):
            return VerificationResult(valid=True, code="ok", message="ok")

        def parse_webhook_events(self, **kwargs):
            self.calls += 1
            if self.calls == 1:
                raise ValueError("bad payload")
            return [
                CanonicalProviderEvent(
                    provider="stripe",
                    provider_event_id="evt_parse_retry",
                    incident_id="dp_parse_retry_1",
                    incident_type="dispute",
                    target_status="opened",
                    payload={"source_event_type": "charge.dispute.created"},
                )
            ]

    class _Repo:
        def __init__(self):
            self.rows = []

        def list_incidents_by_case(self, *, provider: str, case_id: str, limit: int = 1):
            return [r for r in self.rows if r["provider"] == provider and r["provider_incident_id"] == case_id][:limit]

        def put_incident(self, row):
            self.rows.append(dict(row))
            return self.rows[-1]

    class _Service:
        def __init__(self, repository):
            self.repository = repository

        def apply_provider_transition(self, **kwargs):
            return TransitionResult(
                incident={"incident_id": kwargs["incident_id"], "status": kwargs["target_status"]},
                duplicate=False,
                emitted_events=[],
            )

    adapter = _FlakyAdapter()
    billing_router._PAYMENT_INCIDENT_WEBHOOK_REPLAY_CACHE.clear()
    object.__setattr__(S, "payment_incidents_webhook_replay_ttl_seconds", 300)
    object.__setattr__(S, "payment_incidents_webhook_replay_cache_size", 1000)
    object.__setattr__(S, "stripe_webhook_secret", "whsec_test")
    monkeypatch.setattr(billing_router, "ensure_stripe_configured", lambda: None)
    monkeypatch.setattr(billing_router, "resolve_provider_adapter", lambda _: adapter)

    class _RepoWithTicketLink(_Repo):
        def get_ticket_link(self, incident_id):
            return None

        def put_ticket_link(self, **kwargs):
            return {}

    monkeypatch.setattr(billing_router, "DynamoPaymentIncidentRepository", lambda: _RepoWithTicketLink())
    monkeypatch.setattr(billing_router, "PaymentIncidentTransitionService", _Service)

    req = build_request(body=b"{\"id\":\"evt_parse_retry\"}", headers={"stripe-signature": "sig_parse_retry"})
    with pytest.raises(HTTPException) as first_exc:
        run_async(billing_router.stripe_payment_incidents_webhook(req))
    assert first_exc.value.detail["code"] == "invalid_payload"

    second = run_async(billing_router.stripe_payment_incidents_webhook(req))
    assert second["processed"] == 1


def test_payment_incident_webhook_transition_error_does_not_poison_replay_cache(monkeypatch) -> None:
    class _Adapter:
        provider_key = "stripe"

        def verify_webhook(self, **kwargs):
            return VerificationResult(valid=True, code="ok", message="ok")

        def parse_webhook_events(self, **kwargs):
            return [
                CanonicalProviderEvent(
                    provider="stripe",
                    provider_event_id="evt_transition_retry",
                    incident_id="dp_transition_retry_1",
                    incident_type="dispute",
                    target_status="opened",
                    payload={"source_event_type": "charge.dispute.created"},
                )
            ]

    class _Repo:
        def __init__(self):
            self.rows = []

        def list_incidents_by_case(self, *, provider: str, case_id: str, limit: int = 1):
            return [r for r in self.rows if r["provider"] == provider and r["provider_incident_id"] == case_id][:limit]

        def put_incident(self, row):
            self.rows.append(dict(row))
            return self.rows[-1]

        def get_ticket_link(self, incident_id):
            return None

        def put_ticket_link(self, **kwargs):
            return {}

    class _FlakyService:
        calls = 0

        def __init__(self, repository):
            self.repository = repository

        def apply_provider_transition(self, **kwargs):
            self.__class__.calls += 1
            if self.__class__.calls == 1:
                raise billing_router.PaymentIncidentTransitionError(code="missing_incident", message="not found")
            return TransitionResult(
                incident={"incident_id": kwargs["incident_id"], "status": kwargs["target_status"]},
                duplicate=False,
                emitted_events=[],
            )

    billing_router._PAYMENT_INCIDENT_WEBHOOK_REPLAY_CACHE.clear()
    object.__setattr__(S, "payment_incidents_webhook_replay_ttl_seconds", 300)
    object.__setattr__(S, "payment_incidents_webhook_replay_cache_size", 1000)
    object.__setattr__(S, "stripe_webhook_secret", "whsec_test")
    monkeypatch.setattr(billing_router, "ensure_stripe_configured", lambda: None)
    monkeypatch.setattr(billing_router, "resolve_provider_adapter", lambda _: _Adapter())
    monkeypatch.setattr(billing_router, "DynamoPaymentIncidentRepository", lambda: _Repo())
    monkeypatch.setattr(billing_router, "PaymentIncidentTransitionService", _FlakyService)

    req = build_request(body=b"{\"id\":\"evt_transition_retry\"}", headers={"stripe-signature": "sig_transition_retry"})
    with pytest.raises(HTTPException) as first_exc:
        run_async(billing_router.stripe_payment_incidents_webhook(req))
    assert first_exc.value.status_code == 404
    assert first_exc.value.detail["code"] == "missing_incident"

    second = run_async(billing_router.stripe_payment_incidents_webhook(req))
    assert second["processed"] == 1


def test_payment_incident_webhook_skipped_events_do_not_mark_replay(monkeypatch) -> None:
    class _Adapter:
        provider_key = "stripe"

        def verify_webhook(self, **kwargs):
            return VerificationResult(valid=True, code="ok", message="ok")

        def parse_webhook_events(self, **kwargs):
            return [
                CanonicalProviderEvent(
                    provider="stripe",
                    provider_event_id="evt_skip_1",
                    incident_id=None,
                    incident_type="dispute",
                    target_status="opened",
                    payload={"source_event_type": "charge.dispute.created"},
                )
            ]

    billing_router._PAYMENT_INCIDENT_WEBHOOK_REPLAY_CACHE.clear()
    object.__setattr__(S, "payment_incidents_webhook_replay_ttl_seconds", 300)
    object.__setattr__(S, "payment_incidents_webhook_replay_cache_size", 1000)
    object.__setattr__(S, "stripe_webhook_secret", "whsec_test")
    monkeypatch.setattr(billing_router, "ensure_stripe_configured", lambda: None)
    monkeypatch.setattr(billing_router, "resolve_provider_adapter", lambda _: _Adapter())

    req = build_request(body=b"{\"id\":\"evt_skip_1\"}", headers={"stripe-signature": "sig_skip_1"})
    first = run_async(billing_router.stripe_payment_incidents_webhook(req))
    second = run_async(billing_router.stripe_payment_incidents_webhook(req))

    assert first["processed"] == 0
    assert first["deduped"] == 0
    assert second["processed"] == 0
    assert second["deduped"] == 0


def test_payment_incident_webhook_rollout_disabled_returns_ignored(monkeypatch) -> None:
    class _Adapter:
        provider_key = "stripe"

        def verify_webhook(self, **kwargs):
            return VerificationResult(valid=True, code="ok", message="ok")

        def parse_webhook_events(self, **kwargs):
            return [
                CanonicalProviderEvent(
                    provider="stripe",
                    provider_event_id="evt_r1",
                    incident_id="dp_1",
                    incident_type="dispute",
                    target_status="opened",
                    payload={"source_event_type": "charge.dispute.created"},
                )
            ]

    monkeypatch.setattr(billing_router, "ensure_stripe_configured", lambda: None)
    monkeypatch.setattr(billing_router, "resolve_provider_adapter", lambda _: _Adapter())
    orig_secret = S.stripe_webhook_secret
    orig_rollout = S.payment_incidents_rollout_enabled
    object.__setattr__(S, "stripe_webhook_secret", "whsec_test")
    object.__setattr__(S, "payment_incidents_rollout_enabled", False)
    try:
        req = build_request(body=b"{}", headers={"stripe-signature": "ok"})
        first = run_async(billing_router.stripe_payment_incidents_webhook(req))
        second = run_async(billing_router.stripe_payment_incidents_webhook(req))
        assert first["ignored"] is True
        assert first["reason"] == "rollout_disabled"
        assert second["ignored"] is True
        assert second["reason"] == "rollout_disabled"
    finally:
        object.__setattr__(S, "stripe_webhook_secret", orig_secret)
        object.__setattr__(S, "payment_incidents_rollout_enabled", orig_rollout)


def test_payment_incident_webhook_shadow_mode_validates_without_writes(monkeypatch) -> None:
    class _Adapter:
        provider_key = "paypal"

        def verify_webhook(self, **kwargs):
            return VerificationResult(valid=True, code="ok", message="ok")

        def parse_webhook_events(self, **kwargs):
            return [
                CanonicalProviderEvent(
                    provider="paypal",
                    provider_event_id="evt_shadow_1",
                    incident_id="pp_dp_1",
                    incident_type="dispute",
                    target_status="opened",
                    payload={"source_event_type": "CUSTOMER.DISPUTE.CREATED"},
                )
            ]

    audit_calls = []
    monkeypatch.setattr(billing_router, "resolve_provider_adapter", lambda _: _Adapter())
    monkeypatch.setattr(billing_router, "audit_event", lambda *a, **k: audit_calls.append((a, k)))
    orig_rollout = S.payment_incidents_rollout_enabled
    orig_shadow = S.payment_incidents_shadow_mode
    object.__setattr__(S, "payment_incidents_rollout_enabled", True)
    object.__setattr__(S, "payment_incidents_shadow_mode", True)
    try:
        req = build_request(body=b"{}", headers={"paypal-transmission-sig": "ok"})
        first = run_async(billing_router.paypal_payment_incidents_webhook(req))
        second = run_async(billing_router.paypal_payment_incidents_webhook(req))
        assert first["ignored"] is True
        assert first["shadow_validated"] == 1
        assert second["ignored"] is True
        assert second["shadow_validated"] == 1
        assert audit_calls
    finally:
        object.__setattr__(S, "payment_incidents_rollout_enabled", orig_rollout)
        object.__setattr__(S, "payment_incidents_shadow_mode", orig_shadow)

def test_billing_scoped_admin_denied_for_cross_user_with_non_billing_scope(monkeypatch) -> None:
    fake_table = FakeTable()
    setup_table(fake_table)
    setup_stripe_mocks(monkeypatch)

    with pytest.raises(HTTPException) as exc:
        billing_router.get_balance(
            ctx={"user_sub": "admin-auth", "role": "admin"},
            actor=_scoped_admin_actor("admin-auth", AdminScope.AUTH_SUPPORT),
            user_sub="target-1",
        )

    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == "role_required_scope"
    assert exc.value.detail["required_scope"] == "billing_support"


def test_admin_payment_incidents_list_applies_filters_and_returns_items(monkeypatch) -> None:
    class _Repo:
        def list_incidents(self, **kwargs):
            assert kwargs["provider"] == "stripe"
            assert kwargs["incident_type"] == "dispute"
            assert kwargs["status"] == "opened"
            assert kwargs["customer_id"] == "cust_1"
            assert kwargs["due_before_ts"] == 1700001000
            assert kwargs["min_amount"] == 10
            assert kwargs["max_amount"] == 100
            return [{"incident_id": "inc_1"}]

    monkeypatch.setattr(billing_router, "DynamoPaymentIncidentRepository", lambda: _Repo())

    out = billing_router.admin_list_payment_incidents(
        provider="stripe",
        incident_type="dispute",
        status="opened",
        customer_id="cust_1",
        due_before_ts=1700001000,
        min_amount=10,
        max_amount=100,
        actor=_billing_admin_actor(),
    )

    assert out["count"] == 1
    assert out["items"][0]["incident_id"] == "inc_1"


def test_admin_payment_incident_detail_not_found(monkeypatch) -> None:
    class _Repo:
        def get_incident(self, incident_id: str):
            return None

    monkeypatch.setattr(billing_router, "DynamoPaymentIncidentRepository", lambda: _Repo())

    with pytest.raises(HTTPException) as exc:
        billing_router.admin_get_payment_incident("missing", actor=_billing_admin_actor())

    assert exc.value.status_code == 404
    assert exc.value.detail["code"] == "payment_incident_not_found"


def test_admin_payment_incidents_forbidden_for_non_admin(monkeypatch) -> None:
    class _Repo:
        def list_incidents(self, **kwargs):
            return []

    monkeypatch.setattr(billing_router, "DynamoPaymentIncidentRepository", lambda: _Repo())

    with pytest.raises(HTTPException) as exc:
        billing_router.admin_list_payment_incidents(actor=_user_actor())

    assert exc.value.status_code == 403


def test_admin_upload_dispute_evidence_versions_increment(monkeypatch) -> None:
    class _Repo:
        def __init__(self):
            self.saved = []

        def get_incident(self, incident_id: str):
            return {"incident_id": incident_id, "incident_type": "dispute"}

        def list_dispute_evidence(self, *, incident_id: str, limit: int = 50):
            return [{"version": "2"}]

        def put_dispute_evidence(self, *, incident_id: str, version: int, evidence: dict[str, Any]):
            self.saved.append((incident_id, version, evidence))
            return {"incident_id": incident_id, "version": str(version), "payload": evidence}

        def append_incident_event(self, *, incident_id: str, event_id: str, event_type: str, payload: dict[str, Any] | None = None):
            return {"incident_id": incident_id, "event_type": event_type, "payload": payload or {}}

    repo = _Repo()
    monkeypatch.setattr(billing_router, "DynamoPaymentIncidentRepository", lambda: repo)
    monkeypatch.setattr(billing_router, "audit_event", lambda *a, **k: None)

    req = build_request()
    out = billing_router.admin_upload_payment_incident_evidence(
        "inc_1",
        billing_router.PaymentIncidentEvidenceUploadReq(summary="docs", file_refs=["s3://f1"], evidence_items=[{"kind": "receipt"}]),
        req,
        actor=_billing_admin_actor(),
    )

    assert out["version"] == 3
    assert repo.saved[0][1] == 3
    assert repo.saved[0][2]["uploaded_by"] == "admin-1"


def test_admin_submit_response_updates_incident_and_stores_event(monkeypatch) -> None:
    class _Repo:
        def get_incident(self, incident_id: str):
            return {
                "incident_id": incident_id,
                "incident_type": "dispute",
                "provider": "stripe",
                "provider_incident_id": "dp_1",
            }

        def list_dispute_evidence(self, *, incident_id: str, limit: int = 50):
            return [{"version": "1", "payload": {"summary": "evidence"}}]

        def append_incident_event(self, *, incident_id: str, event_id: str, event_type: str, payload: dict[str, Any] | None = None):
            return {"event_type": event_type, "payload": payload or {}}

    class _Adapter:
        def submit_dispute_response(self, *, provider_incident_id: str, evidence: dict[str, Any]):
            assert provider_incident_id == "dp_1"
            assert evidence["response_summary"] == "summary"
            class _Result:
                ok = True
                code = "ok"
                message = "submitted"
                payload = {"ok": True}

            return _Result()

    class _Transitions:
        def __init__(self, repository): ...

        def apply_provider_transition(self, **kwargs):
            assert kwargs["target_status"] == "response_submitted"
            return TransitionResult(incident={"incident_id": kwargs["incident_id"], "status": "response_submitted"}, duplicate=False, emitted_events=[])

    monkeypatch.setattr(billing_router, "DynamoPaymentIncidentRepository", lambda: _Repo())
    monkeypatch.setattr(billing_router, "resolve_provider_adapter", lambda _: _Adapter())
    monkeypatch.setattr(billing_router, "PaymentIncidentTransitionService", _Transitions)
    monkeypatch.setattr(billing_router, "audit_event", lambda *a, **k: None)

    req = build_request()
    out = billing_router.admin_submit_payment_incident_response(
        "inc_1",
        billing_router.PaymentIncidentSubmitResponseReq(response_summary="summary", rationale="details"),
        req,
        actor=_billing_admin_actor(),
    )
    assert out["ok"] is True
    assert out["provider_code"] == "ok"
    assert out["incident"]["status"] == "response_submitted"


def test_admin_submit_response_rejects_non_dispute(monkeypatch) -> None:
    class _Repo:
        def get_incident(self, incident_id: str):
            return {"incident_id": incident_id, "incident_type": "payment_failure", "provider": "stripe"}

    monkeypatch.setattr(billing_router, "DynamoPaymentIncidentRepository", lambda: _Repo())
    req = build_request()
    with pytest.raises(HTTPException) as exc:
        billing_router.admin_submit_payment_incident_response(
            "inc_x",
            billing_router.PaymentIncidentSubmitResponseReq(response_summary="summary"),
            req,
            actor=_billing_admin_actor(),
        )
    assert exc.value.status_code == 400
    assert exc.value.detail["code"] == "payment_incident_not_dispute"


def test_list_payment_issues_filters_to_owner_and_includes_retry_attempts(monkeypatch) -> None:
    class _Repo:
        def list_incidents(self, **kwargs):
            assert kwargs["incident_type"] == "payment_failure"
            return [
                {"incident_id": "inc_owned", "incident_type": "payment_failure", "account_id": "user-123", "customer_id": "cust_1"},
                {"incident_id": "inc_other", "incident_type": "payment_failure", "account_id": "other-user", "customer_id": "cust_2"},
            ]

        def list_retry_attempts(self, *, incident_id: str, limit: int = 50):
            return [{"attempt_id": "a1"}] if incident_id == "inc_owned" else []

    monkeypatch.setattr(billing_router, "DynamoPaymentIncidentRepository", lambda: _Repo())
    out = billing_router.list_payment_issues(ctx={"user_sub": "user-123"}, actor=_user_actor())
    assert out["count"] == 1
    assert out["items"][0]["incident_id"] == "inc_owned"
    assert out["items"][0]["retry_attempts"][0]["attempt_id"] == "a1"


def test_confirm_and_retry_persists_attempt(monkeypatch) -> None:
    class _Repo:
        def __init__(self):
            self.saved = []

        def get_incident(self, incident_id: str):
            return {
                "incident_id": incident_id,
                "incident_type": "payment_failure",
                "status": "ready_to_retry",
                "provider": "stripe",
                "account_id": "user-123",
                "payment_reference": "pi_123",
            }

        def put_retry_attempt(self, *, incident_id: str, attempt_id: str, attempt: dict[str, Any]):
            self.saved.append((incident_id, attempt_id, attempt))
            return {"incident_id": incident_id, "attempt_id": attempt_id, "payload": attempt}

        def update_incident_status(self, *, incident_id: str, status: str, status_reason: str | None = None):
            return {"incident_id": incident_id, "status": status, "status_reason": status_reason}

        def get_ticket_link(self, incident_id):
            return None

        def put_ticket_link(self, **kwargs):
            return {}

    class _Adapter:
        def retry_payment(self, *, payment_reference: str, metadata: dict[str, Any] | None = None):
            class _Result:
                ok = True
                code = "ok"
                message = "retried"
                payload = {"payment_reference": payment_reference, "metadata": metadata or {}}

            return _Result()

    class _Transitions:
        def __init__(self, repository): ...

        def apply_provider_transition(self, **kwargs):
            return TransitionResult(incident={"incident_id": kwargs["incident_id"], "status": kwargs["target_status"]}, duplicate=False, emitted_events=[])

    repo = _Repo()
    monkeypatch.setattr(billing_router, "DynamoPaymentIncidentRepository", lambda: repo)
    monkeypatch.setattr(billing_router, "resolve_provider_adapter", lambda _: _Adapter())
    monkeypatch.setattr(billing_router, "PaymentIncidentTransitionService", _Transitions)
    monkeypatch.setattr(billing_router, "audit_event", lambda *a, **k: None)
    dispatch_calls = []
    clear_calls = []
    monkeypatch.setattr(billing_router, "dispatch_auto_payment_failure_alert", lambda repository, incident: dispatch_calls.append(incident.get("incident_id")) or True)
    monkeypatch.setattr(billing_router, "clear_auto_payment_failure_alerts", lambda repository, incident: clear_calls.append(incident.get("incident_id")) or 0)

    out = billing_router.confirm_and_retry_payment_issue("inc_1", ctx={"user_sub": "user-123"}, actor=_user_actor())
    assert out["ok"] is True
    assert repo.saved[0][0] == "inc_1"
    assert repo.saved[0][2]["action"] == "confirm_and_retry"
    assert dispatch_calls == ["inc_1"]
    assert clear_calls == ["inc_1"]


def test_set_default_and_retry_requires_owned_issue(monkeypatch) -> None:
    class _Repo:
        def get_incident(self, incident_id: str):
            return {"incident_id": incident_id, "incident_type": "payment_failure", "provider": "stripe", "account_id": "other-user"}

    monkeypatch.setattr(billing_router, "DynamoPaymentIncidentRepository", lambda: _Repo())
    monkeypatch.setattr(billing_router, "ensure_stripe_configured", lambda: None)
    monkeypatch.setattr(billing_router, "ddb_get", lambda *a, **k: {"payment_method_id": "pm_1"})
    monkeypatch.setattr(billing_router, "set_default_pm", lambda *a, **k: None)
    monkeypatch.setattr(billing_router, "get_or_create_customer", lambda _: "cus_1")
    monkeypatch.setattr(billing_router, "stripe", MagicMock())

    with pytest.raises(HTTPException) as exc:
        billing_router.set_default_and_retry_payment_issue("pm_1", "inc_1", ctx={"user_sub": "user-123"}, actor=_user_actor())
    assert exc.value.status_code == 404
    assert exc.value.detail["code"] == "payment_issue_not_found"
