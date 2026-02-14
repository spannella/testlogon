import asyncio
import base64
import hashlib
import hmac
import json
import unittest
from unittest.mock import patch

from fastapi import HTTPException
from starlette.requests import Request

from app.routers import ups as ups_router
from app.services import ups as ups_service


class FakeBillingTable:
    def __init__(self) -> None:
        self.items = []

    def put_item(self, Item, **kwargs):
        self.items.append(Item)
        return {}


def build_request(path: str, *, headers: dict[str, str] | None = None, body: bytes = b"", query: str = "") -> Request:
    scope = {
        "type": "http",
        "method": "POST",
        "path": path,
        "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
        "query_string": query.encode(),
        "client": ("127.0.0.1", 1234),
    }

    async def receive() -> dict:
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(scope, receive)


class UpsTests(unittest.TestCase):
    def test_verify_tracking_webhook_signature(self) -> None:
        body = b'{"tracking_number":"1Z1"}'
        with patch("app.services.ups.S", new=type("S", (), {"ups_webhook_secret": "abc"})()):
            sig = hmac.new(b"abc", body, hashlib.sha256).hexdigest()
            self.assertTrue(ups_service.verify_tracking_webhook_signature(body, sig))
            self.assertFalse(ups_service.verify_tracking_webhook_signature(body, "bad"))

    def test_mock_oauth_quote_label(self) -> None:
        settings = type(
            "S", (),
            {"dev_mode": True, "ups_client_id": "id", "ups_client_secret": "sec", "ups_webhook_secret": "x", "public_base_url": "http://localhost:8000"},
        )()
        with patch("app.routers.ups.S", new=settings):
            basic = base64.b64encode(b"id:sec").decode()
            oauth_req = build_request("/mock/ups/oauth/token", headers={"authorization": f"Basic {basic}"})
            oauth = ups_router.mock_ups_oauth(oauth_req)
            self.assertIn("access_token", oauth)

            quote_req = build_request("/mock/ups/quote", headers={"content-type": "application/json"}, body=json.dumps({"package": {"weight": 2}}).encode())
            quote = asyncio.run(ups_router.mock_ups_quote(quote_req))
            self.assertIn("amount", quote)

            label_req = build_request("/mock/ups/label", headers={"content-type": "application/json"}, body=json.dumps({"service": "ground"}).encode())
            label = asyncio.run(ups_router.mock_ups_label(label_req))
            self.assertTrue(label["tracking_number"].startswith("1ZMOCK"))

    def test_emit_tracking_webhook(self) -> None:
        settings = type(
            "S", (),
            {"dev_mode": True, "ups_webhook_secret": "local-ups-webhook-secret", "public_base_url": "http://localhost:8000"},
        )()
        with patch("app.routers.ups.S", new=settings), patch("app.routers.ups.requests.post") as post_mock:
            post_mock.return_value.status_code = 200
            post_mock.return_value.text = '{"received": true}'
            out = ups_router.emit_ups_tracking_webhook({"payload": {"tracking_number": "1ZMOCK1", "status": "DELIVERED"}})
            self.assertTrue(out["ok"])
            _, kwargs = post_mock.call_args
            self.assertIn("x-ups-signature", kwargs["headers"])

    def test_tracking_webhook_persists(self) -> None:
        table = FakeBillingTable()
        tables = type("T", (), {"billing": table})()
        settings = type("S", (), {"ups_webhook_secret": "abc"})()
        body = b'{"tracking_number":"1Z111","status":"IN_TRANSIT"}'
        sig = hmac.new(b"abc", body, hashlib.sha256).hexdigest()
        req = build_request("/api/ups/tracking/webhook", headers={"x-ups-signature": sig, "content-type": "application/json"}, body=body)

        with patch("app.routers.ups.T", tables), patch("app.routers.ups.S", settings):
            resp = asyncio.run(ups_router.ups_tracking_webhook(req))
        self.assertTrue(resp["received"])
        self.assertEqual(len(table.items), 1)


if __name__ == "__main__":
    unittest.main()
