"""Regression test for GAP-0028 / SEC-005 (activity-feed identity forgery / IDOR).

The ``POST /ui/activity/feed/record`` endpoint requires an authenticated session,
but historically wrote the activity to the feed identified by ``body.user_id`` —
a caller-controlled value. This let any authenticated user (Alice) forge activity
entries in any other user's (Bob's) feed.

The fix uses the authenticated session subject (``session["user_sub"]``) as the
feed owner, ignoring ``body.user_id``.

This test FAILS before the fix (entry written to Bob's feed) and PASSES after
(entry always attributed to the caller / Alice). It runs fully offline using
moto for DynamoDB — no real AWS. The router handler is invoked directly with a
forged session dict (mirroring the direct-call style of
``tests/test_messaging_routes.py``).
"""

from __future__ import annotations

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

ALICE = "alice_user_sub"
BOB = "bob_user_sub"


@pytest.fixture(autouse=True)
def _mock_env(monkeypatch):
    monkeypatch.setenv("DEV_MODE", "1")
    monkeypatch.setenv("DDB_ENDPOINT_URL", "http://localhost:8001")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("UI_ACCESS_TOKEN_SECRET", "test-secret")
    monkeypatch.setenv("API_KEY_PEPPER", "test-pepper")


@pytest.fixture()
def feed_env():
    """Create a moto-backed ``activity_feed`` table and wire it into the service.

    Yields ``(record_activity_handler, query_feed)`` where ``record_activity_handler``
    is the real router handler and ``query_feed(user_id)`` returns that user's items.
    """
    import boto3
    from moto import mock_aws
    from boto3.dynamodb.conditions import Key

    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        ddb.create_table(
            TableName="activity_feed",
            KeySchema=[
                {"AttributeName": "user_id", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "user_id", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        table = ddb.Table("activity_feed")

        from app.routers import activity_feed as activity_feed_router
        from app.services import activity_feed as activity_feed_service

        # ``T`` is a frozen dataclass — override via object.__setattr__ and
        # restore the original handle afterwards.
        tables = activity_feed_service.T
        original = tables.activity_feed
        object.__setattr__(tables, "activity_feed", table)

        def query_feed(user_id):
            resp = table.query(KeyConditionExpression=Key("user_id").eq(user_id))
            return resp.get("Items", [])

        try:
            yield activity_feed_router.record_activity, query_feed
        finally:
            object.__setattr__(tables, "activity_feed", original)


def test_record_activity_attributed_to_session_not_body(feed_env):
    """Alice (the authenticated caller) tries to forge an entry in Bob's feed by
    passing ``user_id=BOB``. The entry must land in Alice's feed only."""
    from app.routers.activity_feed import RecordActivityIn

    record_activity, query_feed = feed_env

    body = RecordActivityIn(
        user_id=BOB,  # attacker-controlled target
        actor_id=ALICE,
        activity_type="tip",
        target_type="post",
        target_id="post_123",
        metadata={"amount_cents": 10000},
    )
    # The handler enforces auth via require_ui_session; we pass the resolved
    # session dict directly (Alice is the authenticated caller).
    result = record_activity(body=body, session={"user_sub": ALICE})

    assert result["ok"] is True
    activity_id = result["activity_id"]

    # The entry must be attributed to the caller (Alice), regardless of body.user_id.
    alice_ids = {it["activity_id"] for it in query_feed(ALICE)}
    assert activity_id in alice_ids, "Entry must be written to the caller's (Alice's) feed"

    # Bob's feed must NOT be polluted via body.user_id.
    bob_items = query_feed(BOB)
    bob_ids = {it["activity_id"] for it in bob_items}
    assert activity_id not in bob_ids, "Bob's feed must not be polluted via body.user_id"
    assert bob_items == [], "Bob's feed must remain empty"
