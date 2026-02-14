import asyncio
import base64
import json
import unittest
from unittest.mock import patch

from fastapi import HTTPException
from starlette.requests import Request

from app.routers import ccbill_mock


def build_request(path: str, *, method: str = "POST", query_string: str = "", headers: dict[str, str] | None = None, body: bytes = b"") -> Request:
    encoded = []
    for k, v in (headers or {}).items():
        encoded.append((k.lower().encode(), v.encode()))
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "headers": encoded,
        "query_string": query_string.encode(),
        "client": ("127.0.0.1", 9999),
    }

    async def receive() -> dict:
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(scope, receive)


class CcbillMockTests(unittest.TestCase):
    def setUp(self) -> None:
        ccbill_mock._TOKEN_CACHE.clear()
        ccbill_mock._SUBSCRIPTIONS.clear()
        self.settings = type(
            "StubSettings",
            (),
            {
                "ccbill_mock_enabled": True,
                "ccbill_frontend_client_id": "front",
                "ccbill_frontend_client_secret": "front-secret",
                "ccbill_backend_client_id": "back",
                "ccbill_backend_client_secret": "back-secret",
                "ccbill_webhook_signature_secret": "local-ccbill-webhook-secret",
                "ccbill_webhook_signature_header": "x-ccbill-signature",
                "public_base_url": "http://localhost:8000",
            },
        )()

    def _auth(self, username: str, password: str) -> str:
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        return f"Basic {token}"

    def test_oauth_and_charge_subscription_success(self) -> None:
        with patch("app.routers.ccbill_mock.S", new=self.settings):
            oauth_req = build_request(
                "/mock/ccbill/ccbill-auth/oauth/token",
                query_string="grant_type=client_credentials",
                headers={"authorization": self._auth("back", "back-secret")},
            )
            oauth = asyncio.run(ccbill_mock.ccbill_mock_oauth(oauth_req))
            self.assertIn("access_token", oauth)

            charge_payload = json.dumps({"recurringPrice": 9.99, "recurringPeriod": 30, "currencyCode": 840}).encode()
            charge_req = build_request(
                "/mock/ccbill/transactions/payment-tokens/tok_123",
                headers={
                    "authorization": f"Bearer {oauth['access_token']}",
                    "content-type": "application/json",
                },
                body=charge_payload,
            )
            charge = asyncio.run(ccbill_mock.ccbill_mock_charge("tok_123", charge_req))
            self.assertTrue(charge["approved"])
            self.assertTrue(charge["subscriptionId"].startswith("sub_"))

    def test_oauth_rejects_bad_credentials(self) -> None:
        with patch("app.routers.ccbill_mock.S", new=self.settings):
            oauth_req = build_request(
                "/mock/ccbill/ccbill-auth/oauth/token",
                query_string="grant_type=client_credentials",
                headers={"authorization": self._auth("bad", "bad")},
            )
            with self.assertRaises(HTTPException) as ctx:
                asyncio.run(ccbill_mock.ccbill_mock_oauth(oauth_req))
            self.assertEqual(ctx.exception.status_code, 401)

    def test_emit_webhook_signs_and_posts(self) -> None:
        with patch("app.routers.ccbill_mock.S", new=self.settings), patch("app.routers.ccbill_mock.requests.post") as post_mock:
            post_mock.return_value.status_code = 200
            post_mock.return_value.text = '{"received": true}'

            result = ccbill_mock.emit_ccbill_webhook(
                {
                    "event_type": "NewSaleSuccess",
                    "payload": {"X-app_user_id": "dev-user", "transactionId": "txn_1"},
                    "target_url": "http://localhost:8000/api/ccbill/webhook",
                }
            )

            self.assertTrue(result["ok"])
            self.assertEqual(result["status_code"], 200)
            _, kwargs = post_mock.call_args
            self.assertEqual(kwargs["params"]["eventType"], "NewSaleSuccess")
            self.assertIn("x-ccbill-signature", kwargs["headers"])


if __name__ == "__main__":
    unittest.main()
