from __future__ import annotations

import pytest
from botocore.exceptions import ClientError

from app.routers import paypal


def test_compute_due_handles_pending_and_settled():
    balance = {
        "owed_settled_cents": 1200,
        "owed_pending_cents": 300,
        "payments_settled_cents": 200,
        "payments_pending_cents": 100,
    }

    due = paypal.compute_due(balance)

    assert due["due_settled_cents"] == 1000
    assert due["due_if_all_settles_cents"] == 1200


def test_require_user_raises_without_header():
    with pytest.raises(Exception) as excinfo:
        paypal.require_user(None)

    assert "Missing X-User-Id" in str(excinfo.value)


def test_ledger_and_record_keys():
    sk = paypal.ledger_sk(123, "entry")

    assert sk == "LEDGER#123#entry"
    assert paypal.pay_sk("order") == "PAY#order"
    assert paypal.sub_sk("sub") == "SUB#sub"
    assert paypal.pm_sk("token") == "PM#token"


def test_new_ledger_entry_includes_metadata():
    sk, item = paypal.new_ledger_entry(
        user_id="user",
        entry_type="credit",
        amount_cents=1500,
        state="pending",
        reason="test",
        paypal_payment_token_id="token",
        paypal_order_id="order",
        paypal_capture_id="cap",
        paypal_subscription_id="sub",
        meta={"note": "example"},
    )

    assert sk.startswith("LEDGER#")
    assert item["pk"] == "USER#user"
    assert item["type"] == "credit"
    assert item["amount_cents"] == 1500
    assert item["state"] == "pending"
    assert item["reason"] == "test"
    assert item["paypal_payment_token_id"] == "token"
    assert item["paypal_order_id"] == "order"
    assert item["paypal_capture_id"] == "cap"
    assert item["paypal_subscription_id"] == "sub"
    assert item["meta"] == {"note": "example"}


def test_paypal_oauth_caches_access_token(monkeypatch):
    called = {"count": 0}

    class FakeResponse:
        status_code = 200

        def json(self):
            return {"access_token": "token-123", "expires_in": 300}

        text = "ok"

    def fake_post(*args, **kwargs):
        called["count"] += 1
        return FakeResponse()

    monkeypatch.setattr(paypal, "_PAYPAL_OAUTH_CACHE", ("", 0))
    monkeypatch.setattr(paypal, "_require_paypal_config", lambda: None)
    monkeypatch.setattr(paypal.requests, "post", fake_post)

    token_one = paypal.paypal_oauth()
    token_two = paypal.paypal_oauth()

    assert token_one == "token-123"
    assert token_two == "token-123"
    assert called["count"] == 1


def test_paypal_create_order_includes_token(monkeypatch):
    captured = {}

    class FakeResponse:
        status_code = 201
        text = "ok"

        def json(self):
            return {"id": "ORDER-1", "links": []}

    def fake_post(url, headers=None, json=None, timeout=None, auth=None, data=None):
        captured["url"] = url
        captured["json"] = json
        return FakeResponse()

    monkeypatch.setattr(paypal, "_PAYPAL_OAUTH_CACHE", ("access", paypal.now_ts() + 360))
    monkeypatch.setattr(paypal, "_require_paypal_config", lambda: None)
    monkeypatch.setattr(paypal.requests, "post", fake_post)

    resp = paypal.paypal_create_order(
        user_id="user",
        amount_cents=500,
        currency="USD",
        idempotency_key="idem",
        return_url="https://example.com/return",
        cancel_url="https://example.com/cancel",
        payment_token_id="token-xyz",
        custom_id="user|LEDGER#1",
    )

    assert resp["id"] == "ORDER-1"
    assert captured["json"]["payment_source"]["token"]["id"] == "token-xyz"


def test_mark_webhook_processed_dedupes(monkeypatch):
    calls = {"count": 0}

    def fake_put(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] > 1:
            raise ClientError(
                {"Error": {"Code": "ConditionalCheckFailedException", "Message": "dup"}},
                "PutItem",
            )

    monkeypatch.setattr(paypal, "ddb_put", fake_put)

    assert paypal.mark_webhook_processed("dedupe") is True
    assert paypal.mark_webhook_processed("dedupe") is False


def test_paypal_verify_webhook_signature(monkeypatch):
    class FakeResponse:
        status_code = 200

        def json(self):
            return {"verification_status": "SUCCESS"}

        text = "ok"

    def fake_post(*args, **kwargs):
        return FakeResponse()

    monkeypatch.setattr(paypal, "_PAYPAL_OAUTH_CACHE", ("token", paypal.now_ts() + 360))
    monkeypatch.setattr(paypal, "_require_paypal_config", lambda: None)
    monkeypatch.setattr(paypal.requests, "post", fake_post)

    ok = paypal.paypal_verify_webhook_signature(
        transmission_id="id",
        transmission_time="time",
        transmission_sig="sig",
        cert_url="cert",
        auth_algo="algo",
        webhook_id="webhook",
        raw_body=b"{}",
    )

    assert ok is True
