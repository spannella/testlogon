import asyncio
import unittest
from typing import Any, Dict, List
from unittest.mock import patch

from fastapi import HTTPException
from starlette.requests import Request

from app.routers import billing_ccbill as routes


class FakeBillingTable:
    def __init__(self) -> None:
        self._items: Dict[tuple[str, str], Dict[str, Any]] = {}

    def get_item(self, Key: Dict[str, str]) -> Dict[str, Any]:
        return {"Item": self._items.get((Key["user_sub"], Key["sk"]))}

    def put_item(self, Item: Dict[str, Any], **kwargs: Any) -> Dict[str, Any]:
        self._items[(Item["user_sub"], Item["sk"])] = Item
        return {}

    def delete_item(self, Key: Dict[str, str]) -> Dict[str, Any]:
        self._items.pop((Key["user_sub"], Key["sk"]), None)
        return {}

    def update_item(
        self,
        Key: Dict[str, str],
        UpdateExpression: str,
        ExpressionAttributeValues: Dict[str, Any],
        ExpressionAttributeNames: Dict[str, str] | None = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        item = self._items.setdefault((Key["user_sub"], Key["sk"]), {"user_sub": Key["user_sub"], "sk": Key["sk"]})
        expr = UpdateExpression.replace("SET", "").strip()
        parts = []
        depth = 0
        current = []
        for ch in expr:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth = max(0, depth - 1)
            if ch == "," and depth == 0:
                parts.append("".join(current))
                current = []
                continue
            current.append(ch)
        if current:
            parts.append("".join(current))

        for part in parts:
            lhs, rhs = part.strip().split("=", 1)
            lhs = lhs.strip()
            rhs = rhs.strip()
            if ExpressionAttributeNames and lhs in ExpressionAttributeNames:
                lhs = ExpressionAttributeNames[lhs]
            if rhs.startswith(":"):
                item[lhs] = ExpressionAttributeValues[rhs]
        self._items[(Key["user_sub"], Key["sk"])] = item
        return {}

    def query(self, ExpressionAttributeValues: Dict[str, Any], **kwargs: Any) -> Dict[str, List[Dict[str, Any]]]:
        user_sub = ExpressionAttributeValues.get(":u")
        prefix = ExpressionAttributeValues.get(":p", "")
        items = [
            item for (pk, sk), item in self._items.items()
            if pk == user_sub and (sk.startswith(prefix) if prefix else True)
        ]
        return {"Items": items}


def build_request(path: str, *, method: str = "POST", query_string: str = "", json_body: bytes | None = None) -> Request:
    headers = [
        (b"content-type", b"application/json"),
    ]
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "headers": headers,
        "query_string": query_string.encode(),
        "client": ("127.0.0.1", 1234),
    }

    async def receive() -> dict:
        return {"type": "http.request", "body": json_body or b"", "more_body": False}

    return Request(scope, receive)


class BillingRoutesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.table = FakeBillingTable()
        tables_stub = type("TablesStub", (), {"billing": self.table})()
        self.tables_patcher = patch("app.routers.billing_ccbill.T", tables_stub)
        self.services_tables_patcher = patch("app.services.billing_ccbill.T", tables_stub)
        self.tables_patcher.start()
        self.services_tables_patcher.start()
        self.ctx = {"user_sub": "user_123", "session_id": "sess_123"}

    def tearDown(self) -> None:
        self.tables_patcher.stop()
        self.services_tables_patcher.stop()

    def test_config_endpoint(self) -> None:
        body = routes.billing_config()
        self.assertIn("clientAccnum", body)
        self.assertIn("clientSubacc", body)

    def test_billing_page_route(self) -> None:
        response = routes.billing_index()
        self.assertTrue(str(response.path).endswith("index.html"))

    def test_settings_and_autopay(self) -> None:
        body = routes.get_settings(self.ctx)
        self.assertFalse(body["autopay_enabled"])

        resp = routes.set_autopay(routes.SetAutopayIn(enabled=True), self.ctx)
        self.assertTrue(resp["ok"])

        body = routes.get_settings(self.ctx)
        self.assertTrue(body["autopay_enabled"])

    def test_balance_endpoint(self) -> None:
        body = routes.get_balance(self.ctx)
        self.assertIn("due_settled_cents", body)
        self.assertIn("due_if_all_settles_cents", body)

    def test_payment_methods_crud(self) -> None:
        resp = routes.save_payment_token(
            routes.SavePaymentTokenIn(payment_token_id="tok_123", label="Visa ****4242", make_default=True),
            self.ctx,
        )
        self.assertTrue(resp["ok"])

        pms = routes.list_payment_methods_endpoint(self.ctx)
        self.assertEqual(len(pms), 1)

        resp = routes.set_priority(routes.SetPriorityIn(payment_token_id="tok_123", priority=5), self.ctx)
        self.assertTrue(resp["ok"])

        resp = routes.set_default(routes.SetDefaultIn(payment_token_id="tok_123"), self.ctx)
        self.assertTrue(resp["ok"])

        resp = routes.remove_payment_method("tok_123", self.ctx)
        self.assertTrue(resp["ok"])

    def test_charge_once_route(self) -> None:
        with patch("app.routers.billing_ccbill.charge_once", return_value={"approved": True}) as charge_mock:
            resp = asyncio.run(routes.charge_once_endpoint(
                routes.OneTimeChargeIn(amount_cents=500),
                build_request("/api/billing/charge-once"),
                self.ctx,
            ))
        self.assertTrue(resp["approved"])
        charge_mock.assert_called_once()

    def test_pay_balance_route(self) -> None:
        with patch("app.routers.billing_ccbill.pay_balance", return_value={"status": "ok"}) as pay_mock:
            resp = asyncio.run(routes.pay_balance_endpoint(
                routes.PayBalanceIn(),
                build_request("/api/billing/pay-balance"),
                self.ctx,
            ))
        self.assertEqual(resp["status"], "ok")
        pay_mock.assert_called_once()

    def test_subscribe_monthly_route(self) -> None:
        with patch("app.routers.billing_ccbill.subscribe_monthly", return_value={"approved": True}) as sub_mock:
            resp = asyncio.run(routes.subscribe_monthly_endpoint(
                routes.SubscribeMonthlyIn(plan_id="monthly", monthly_price_cents=999),
                build_request("/api/billing/subscribe-monthly"),
                self.ctx,
            ))
        self.assertTrue(resp["approved"])
        sub_mock.assert_called_once()

    def test_dev_add_charge_and_list_ledger(self) -> None:
        resp = routes.dev_add_charge(
            routes.AddChargeIn(amount_cents=250, state="settled", reason="usage"),
            self.ctx,
        )
        self.assertTrue(resp["ok"])
        self.assertIn("ledger_sk", resp)

        resp = routes.list_ledger(self.ctx)
        self.assertGreaterEqual(len(resp["items"]), 1)

    def test_list_payments_and_subscriptions(self) -> None:
        self.table.put_item(Item={
            "user_sub": "user_123",
            "sk": "PAY#txn_1",
            "transaction_id": "txn_1",
            "created_at": 2,
        })
        self.table.put_item(Item={
            "user_sub": "user_123",
            "sk": "SUB#sub_1",
            "subscription_id": "sub_1",
            "created_at": 3,
        })

        resp = routes.list_payments(self.ctx)
        self.assertEqual(len(resp["items"]), 1)

        resp = routes.list_subscriptions(self.ctx)
        self.assertEqual(len(resp["items"]), 1)

    def test_webhook_unmatched_payload(self) -> None:
        with patch("app.services.billing_ccbill.mark_webhook_processed", return_value=True):
            req = build_request("/api/ccbill/webhook", query_string="eventType=NewSaleSuccess", json_body=b"{}")
            resp = asyncio.run(routes.ccbill_webhook(req))
        self.assertTrue(resp["unmatched"])

    def test_payment_methods_default_fallback(self) -> None:
        routes.save_payment_token(
            routes.SavePaymentTokenIn(payment_token_id="tok_a", label="Visa ****1111", make_default=True),
            self.ctx,
        )
        routes.save_payment_token(
            routes.SavePaymentTokenIn(payment_token_id="tok_b", label="Visa ****2222", make_default=False),
            self.ctx,
        )

        routes.set_default(routes.SetDefaultIn(payment_token_id="tok_b"), self.ctx)
        settings = routes.get_settings(self.ctx)
        self.assertEqual(settings["default_payment_token_id"], "tok_b")

        routes.remove_payment_method("tok_b", self.ctx)
        settings = routes.get_settings(self.ctx)
        self.assertEqual(settings["default_payment_token_id"], "tok_a")

    def test_webhook_new_sale_success_updates_records(self) -> None:
        ledger_sk = "LEDGER#1#abc"
        self.table.put_item(Item={
            "user_sub": "user_123",
            "sk": ledger_sk,
            "state": "pending",
            "amount_cents": 999,
        })
        self.table.put_item(Item={
            "user_sub": "user_123",
            "sk": "PAY#txn_1",
            "transaction_id": "txn_1",
            "status": "pending",
            "amount_cents": 999,
            "ledger_sk": ledger_sk,
        })

        payload = b'{"X-app_user_id":"user_123","transactionId":"txn_1","subscriptionId":"sub_1"}'
        with patch("app.services.billing_ccbill.mark_webhook_processed", return_value=True):
            req = build_request("/api/ccbill/webhook", query_string="eventType=NewSaleSuccess", json_body=payload)
            resp = asyncio.run(routes.ccbill_webhook(req))
        self.assertTrue(resp["received"])

        ledger = self.table.get_item(Key={"user_sub": "user_123", "sk": ledger_sk})["Item"]
        self.assertEqual(ledger["state"], "settled")

        payment = self.table.get_item(Key={"user_sub": "user_123", "sk": "PAY#txn_1"})["Item"]
        self.assertEqual(payment["status"], "succeeded")

    def test_set_default_missing_payment_method_rejected(self) -> None:
        with self.assertRaises(HTTPException) as ctx:
            routes.set_default(routes.SetDefaultIn(payment_token_id="missing"), self.ctx)
        self.assertEqual(ctx.exception.status_code, 404)

    def test_set_priority_missing_payment_method_rejected(self) -> None:
        with self.assertRaises(HTTPException) as ctx:
            routes.set_priority(routes.SetPriorityIn(payment_token_id="missing", priority=1), self.ctx)
        self.assertEqual(ctx.exception.status_code, 404)

    def test_remove_missing_payment_method_rejected(self) -> None:
        with self.assertRaises(HTTPException) as ctx:
            routes.remove_payment_method("missing", self.ctx)
        self.assertEqual(ctx.exception.status_code, 404)

    def test_webhook_deduped_returns_flag(self) -> None:
        with patch("app.routers.billing_ccbill.mark_webhook_processed", return_value=False):
            req = build_request("/api/ccbill/webhook", query_string="eventType=NewSaleSuccess", json_body=b"{}")
            resp = asyncio.run(routes.ccbill_webhook(req))
        self.assertTrue(resp["deduped"])

    def test_webhook_rejects_disallowed_ip(self) -> None:
        with patch("app.routers.billing_ccbill.webhook_remote_ip_allowed", return_value=False):
            req = build_request("/api/ccbill/webhook", query_string="eventType=NewSaleSuccess", json_body=b"{}")
            with self.assertRaises(HTTPException) as ctx:
                asyncio.run(routes.ccbill_webhook(req))
        self.assertEqual(ctx.exception.status_code, 403)


if __name__ == "__main__":
    unittest.main()
