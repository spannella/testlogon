"""Offline regression tests for GAP-0317 (NOTIFY-001).

Before the fix, the backend had no dedicated VAPID web-push subscribe/unsubscribe
endpoint: ``POST /ui/push/register`` accepted only a FCM-style ``{token, platform}``
pair, and the frontend shoved the entire subscription JSON into ``token`` as a raw
(non-canonical) string. The delivery path (``web_push_send`` at
``app/services/push.py:166`` / the alert dispatch at ``:285``) expects the stored
``token`` to be ``json.loads``-able into ``{"endpoint":..., "keys":{"p256dh":...,
"auth":...}}``.

The fix adds ``POST /ui/push/subscribe`` and ``DELETE /ui/push/subscribe`` to
``app/routers/push.py``. POST stores the subscription via the existing
``upsert_push_device`` with ``platform="web"`` and a token shaped EXACTLY as the
delivery path expects. DELETE unsubscribes by endpoint.

Fully offline: a real in-memory DynamoDB table is created with moto (no real AWS)
and bound to the EXACT handle ``upsert_push_device`` / ``revoke_push_device`` use
(``app.services.push.T``) via ``object.__setattr__``. The async route handlers are
called directly with a fake ctx + the Pydantic body (the FastAPI TestClient is
unusable in this repo).
"""
from __future__ import annotations

import asyncio
import json
import unittest
from contextlib import ExitStack
from types import SimpleNamespace

import boto3
from boto3.dynamodb.conditions import Key

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


def _make_push_devices_table(ddb):
    """Mirror scripts/local-ddb-init.py: push_devices (user_sub HASH, device_id RANGE)."""
    return ddb.create_table(
        TableName="push_devices",
        KeySchema=[
            {"AttributeName": "user_sub", "KeyType": "HASH"},
            {"AttributeName": "device_id", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "user_sub", "AttributeType": "S"},
            {"AttributeName": "device_id", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


class _FakeReq:
    """Minimal stand-in for fastapi Request (only used by audit_event)."""

    client = SimpleNamespace(host="127.0.0.1")
    headers: dict = {}

    def __init__(self):
        self.headers = {}


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestWebPushSubscribeGap0317(unittest.TestCase):
    USER = "user_sub_alice"

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _make_push_devices_table(ddb)

        from app.core.tables import T
        from app.core.settings import S
        from app.services import push as push_svc

        self.T = T
        self.S = S
        self.push_svc = push_svc

        # Bind the moto table to the EXACT handle the service layer uses.
        self._orig_table = T.push_devices
        object.__setattr__(T, "push_devices", self.table)
        self.addCleanup(lambda: object.__setattr__(T, "push_devices", self._orig_table))

        # Ensure push is enabled for the subscribe endpoint guard.
        self._orig_push_enabled = S.push_enabled
        object.__setattr__(S, "push_enabled", True)
        self.addCleanup(lambda: object.__setattr__(S, "push_enabled", self._orig_push_enabled))

        # Stub audit_event in the router so it doesn't touch the alerts table.
        from app.routers import push as push_router

        self.push_router = push_router
        self._orig_audit = push_router.audit_event
        push_router.audit_event = lambda *a, **k: None
        self.addCleanup(lambda: setattr(push_router, "audit_event", self._orig_audit))

    def _ctx(self):
        return {"user_sub": self.USER, "role": None, "admin_profile": None}

    def test_subscribe_stores_parseable_web_push_subscription(self):
        """FAILS BEFORE FIX: ui_subscribe_push doesn't exist (AttributeError).
        PASSES AFTER FIX: the stored token round-trips via json.loads into the
        exact shape push.py:166 (web_push_send) consumes.
        """
        from app.models import PushSubscribeReq

        body = PushSubscribeReq(
            endpoint="https://fcm.googleapis.com/fcm/send/abc123",
            keys_p256dh="BPp256dhPublicKeyValue",
            keys_auth="authSecretValue",
        )
        result = asyncio.run(
            self.push_router.ui_subscribe_push(_FakeReq(), body, ctx=self._ctx())
        )
        self.assertEqual(result["platform"], "web")
        device_id = result["device_id"]

        # Read the stored item back and confirm the token is a parseable
        # web-push subscription in EXACTLY the shape web_push_send expects.
        item = self.table.get_item(Key={"user_sub": self.USER, "device_id": device_id})["Item"]
        self.assertEqual(item["platform"], "web")
        sub = json.loads(item["token"])  # <- push.py:166 does exactly this
        self.assertEqual(sub["endpoint"], "https://fcm.googleapis.com/fcm/send/abc123")
        self.assertEqual(sub["keys"]["p256dh"], "BPp256dhPublicKeyValue")
        self.assertEqual(sub["keys"]["auth"], "authSecretValue")

        # Mirror what web_push_send (push.py:167-170) extracts.
        endpoint = sub.get("endpoint", "")
        keys = sub.get("keys", {})
        self.assertTrue(endpoint and keys.get("p256dh") and keys.get("auth"))

    def test_unsubscribe_removes_subscription_by_endpoint(self):
        """FAILS BEFORE FIX: ui_unsubscribe_push doesn't exist.
        PASSES AFTER FIX: DELETE by endpoint removes the stored web device.
        """
        from app.models import PushSubscribeReq, PushUnsubscribeReq

        endpoint = "https://updates.push.services.mozilla.com/wpush/v2/xyz"
        sub_body = PushSubscribeReq(
            endpoint=endpoint,
            keys_p256dh="BPmozillaPublicKey",
            keys_auth="mozAuthSecret",
        )
        asyncio.run(self.push_router.ui_subscribe_push(_FakeReq(), sub_body, ctx=self._ctx()))

        # Confirm it exists.
        before = self.table.query(
            KeyConditionExpression=Key("user_sub").eq(self.USER)
        )["Items"]
        self.assertEqual(len(before), 1)

        unsub_body = PushUnsubscribeReq(endpoint=endpoint)
        result = asyncio.run(
            self.push_router.ui_unsubscribe_push(_FakeReq(), unsub_body, ctx=self._ctx())
        )
        self.assertTrue(result["ok"])
        self.assertTrue(result["removed"])

        after = self.table.query(
            KeyConditionExpression=Key("user_sub").eq(self.USER)
        )["Items"]
        self.assertEqual(len(after), 0)

    def test_stored_shape_matches_web_push_send_consumer(self):
        """The stored token, after json.loads, lets us build the same dict that
        web_push_send / send_push_for_alert read (endpoint + keys.p256dh + keys.auth).
        """
        from app.models import PushSubscribeReq

        body = PushSubscribeReq(
            endpoint="https://example.push/endpoint/1",
            keys_p256dh="p256dhAAA",
            keys_auth="authBBB",
        )
        result = asyncio.run(
            self.push_router.ui_subscribe_push(_FakeReq(), body, ctx=self._ctx())
        )
        item = self.table.get_item(
            Key={"user_sub": self.USER, "device_id": result["device_id"]}
        )["Item"]

        # Exactly what web_push_send(subscription_json=...) does internally.
        subscription = json.loads(item["token"])
        consumed = {
            "endpoint": subscription.get("endpoint", ""),
            "keys": {
                "p256dh": subscription.get("keys", {}).get("p256dh", ""),
                "auth": subscription.get("keys", {}).get("auth", ""),
            },
        }
        self.assertEqual(consumed["endpoint"], "https://example.push/endpoint/1")
        self.assertEqual(consumed["keys"]["p256dh"], "p256dhAAA")
        self.assertEqual(consumed["keys"]["auth"], "authBBB")

    def test_routes_registered_for_post_and_delete(self):
        methods = {}
        for r in self.push_router.router.routes:
            if getattr(r, "path", "") == "/ui/push/subscribe":
                methods.setdefault(r.path, set()).update(r.methods)
        self.assertIn("POST", methods.get("/ui/push/subscribe", set()))
        self.assertIn("DELETE", methods.get("/ui/push/subscribe", set()))


if __name__ == "__main__":
    unittest.main()
