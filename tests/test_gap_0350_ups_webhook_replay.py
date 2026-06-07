"""Offline regression tests for GAP-0350 (SHOP-004 second-pass).

The UPS tracking webhook (``app/routers/ups.py``) previously verified the HMAC
signature, then unconditionally wrote an audit row and called
``apply_tracking_result`` — with NO timestamp-tolerance check and NO event-ID
dedup. A legitimately-signed payload could be replayed indefinitely, re-firing
order/delivery side-effects.

The fix adds:
  1. Event-ID dedup via a conditional ``put_item`` on ``T.billing``
     (``pk=UPS_EVENT_PROCESSED``, ``sk=EID#{event_id}``). A replay of the same
     event_id returns a 200 idempotent ack WITHOUT reprocessing.
  2. An ``x-ups-timestamp`` tolerance window
     (``S.ups_webhook_timestamp_tolerance_seconds``, default 300s) — a stale
     timestamp is rejected with 400 before any processing.

Fully offline/hermetic: a real in-memory DynamoDB ``billing`` table is created
with moto and bound to the EXACT frozen ``T.billing`` handle via
``object.__setattr__`` (restored on cleanup). ``apply_tracking_result`` is
patched to a spy so we can assert it is / isn't called. Signature verification
uses the no-secret dev bypass (``S.ups_webhook_secret = ""`` →
``verify_tracking_webhook_signature`` returns True). The async webhook handler
is driven directly with a fake ``Request`` (the FastAPI TestClient is unusable
in this repo).
"""
from __future__ import annotations

import asyncio
import json
import unittest
from contextlib import ExitStack
from unittest.mock import patch

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
import app.routers.ups as ups_router


def _make_billing_table(ddb):
    return ddb.create_table(
        TableName="billing_test_gap0350",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


class _FakeRequest:
    """Minimal stand-in for starlette.Request for the webhook handler."""

    def __init__(self, body: bytes, headers: dict):
        self._body = body
        # Header lookups in the handler are lowercase; normalize.
        self.headers = {k.lower(): v for k, v in headers.items()}

    async def body(self) -> bytes:
        return self._body

    async def json(self):
        return json.loads(self._body.decode("utf-8")) if self._body else {}


def _call_webhook(payload: dict, headers: dict | None = None):
    raw = json.dumps(payload).encode("utf-8")
    req = _FakeRequest(raw, headers or {})
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(ups_router.ups_tracking_webhook(req))
    finally:
        loop.close()


@unittest.skipIf(mock_aws is None, "moto not installed")
class UpsWebhookReplayTest(unittest.TestCase):
    def setUp(self):
        self._stack = ExitStack()
        self._stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _make_billing_table(ddb)

        # Bind moto table to the frozen handle; restore on cleanup.
        self._orig_billing = T.billing
        object.__setattr__(T, "billing", self.table)
        self.addCleanup(lambda: object.__setattr__(T, "billing", self._orig_billing))

        # No-secret dev bypass for signature verification.
        self._orig_secret = S.ups_webhook_secret
        object.__setattr__(S, "ups_webhook_secret", "")
        self.addCleanup(lambda: object.__setattr__(S, "ups_webhook_secret", self._orig_secret))

        # Ensure a known tolerance window.
        self._orig_tol = S.ups_webhook_timestamp_tolerance_seconds
        object.__setattr__(S, "ups_webhook_timestamp_tolerance_seconds", 300)
        self.addCleanup(
            lambda: object.__setattr__(
                S, "ups_webhook_timestamp_tolerance_seconds", self._orig_tol
            )
        )

        # Spy: count apply_tracking_result calls. The handler imports it lazily
        # from app.services.carrier_tracking, so patch it there.
        self.apply_calls = []

        def _spy_apply(order, result):
            self.apply_calls.append((order, result))
            return order  # non-None => order_updated True

        self._stack.enter_context(
            patch("app.services.carrier_tracking.apply_tracking_result", _spy_apply)
        )
        # Make find_transaction_by_tracking always return an order so the
        # apply path is reachable.
        self._stack.enter_context(
            patch(
                "app.services.purchase_history.find_transaction_by_tracking",
                lambda tn: {"order_id": "o1", "tracking_number": tn},
            )
        )
        self._stack.enter_context(
            patch(
                "app.services.carrier_tracking.map_carrier_status",
                lambda carrier, status: "delivered",
            )
        )
        self.addCleanup(self._stack.close)

    def _dedup_rows(self):
        resp = self.table.query(
            KeyConditionExpression=boto3.dynamodb.conditions.Key("pk").eq(
                "UPS_EVENT_PROCESSED"
            )
        )
        return resp.get("Items", [])

    def test_first_event_is_processed(self):
        payload = {"eventId": "evt-X", "trackingNumber": "1Z999", "status": "DELIVERED"}
        out = _call_webhook(payload)
        self.assertEqual(out["received"], True)
        self.assertEqual(out["duplicate"], False)
        self.assertEqual(out["order_updated"], True)
        self.assertEqual(len(self.apply_calls), 1)
        # Dedup row written.
        rows = self._dedup_rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["sk"], "EID#evt-X")

    def test_replay_same_event_id_not_reprocessed(self):
        payload = {"eventId": "evt-X", "trackingNumber": "1Z999", "status": "DELIVERED"}
        out1 = _call_webhook(payload)
        self.assertEqual(out1["duplicate"], False)
        self.assertEqual(len(self.apply_calls), 1)

        # Replay identical event_id.
        out2 = _call_webhook(payload)
        self.assertEqual(out2["received"], True)
        self.assertEqual(out2["duplicate"], True)
        self.assertEqual(out2["order_updated"], False)
        # apply_tracking_result NOT called a second time.
        self.assertEqual(len(self.apply_calls), 1)
        # Still exactly one dedup row.
        self.assertEqual(len(self._dedup_rows()), 1)

    def test_stale_timestamp_rejected(self):
        from fastapi import HTTPException

        payload = {"eventId": "evt-stale", "trackingNumber": "1Z999"}
        stale = str(now_ts() - 10000)
        with self.assertRaises(HTTPException) as cm:
            _call_webhook(payload, headers={"x-ups-timestamp": stale})
        self.assertEqual(cm.exception.status_code, 400)
        self.assertIn("tolerance", str(cm.exception.detail).lower())
        # apply NOT called; no dedup row written.
        self.assertEqual(len(self.apply_calls), 0)
        self.assertEqual(len(self._dedup_rows()), 0)

    def test_fresh_timestamp_processed(self):
        payload = {"eventId": "evt-fresh", "trackingNumber": "1Z999", "status": "DELIVERED"}
        fresh = str(now_ts() - 60)
        out = _call_webhook(payload, headers={"x-ups-timestamp": fresh})
        self.assertEqual(out["duplicate"], False)
        self.assertEqual(out["order_updated"], True)
        self.assertEqual(len(self.apply_calls), 1)
        self.assertEqual(len(self._dedup_rows()), 1)

    def test_no_event_id_still_processed(self):
        payload = {"trackingNumber": "1Z999", "status": "IN_TRANSIT"}
        out = _call_webhook(payload)
        self.assertEqual(out["received"], True)
        self.assertEqual(out["duplicate"], False)
        # No dedup row (no event id), audit row uses ts#tracking SK.
        self.assertEqual(len(self._dedup_rows()), 0)


if __name__ == "__main__":
    unittest.main()
