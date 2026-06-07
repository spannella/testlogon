"""Offline regression tests for GAP-0331 and GAP-0332 (PLATFORM-018).

Both gaps live in ``finalize_deletion`` in ``app/services/account_deletion.py``,
which wrote stub ``deletion_summary`` counters that were never populated:

GAP-0331 — ``messages_anonymized: 0`` / ``posts_anonymized: 0`` were never
filled. Deleted-user messages kept their real ``sender_id`` and ``text``, and
newsfeed posts kept their real author ``user_id`` and body content. The fix adds
``_anonymize_messages`` and ``_anonymize_posts`` helpers (gated on
``S.account_deletion_destructive``) that tombstone the user's messages/posts.

GAP-0332 — ``subscriptions_cancelled: 0`` was never filled. Active subscriptions
kept a live status after the owner's account was deleted (orphaned billing /
entitlement). The fix adds ``_cancel_active_subscriptions`` (same gating) that
flips each active ``SUB#{id}`` META record to ``status="canceled"``.

Fully offline: real in-memory DynamoDB tables are created with moto (no real
AWS) and the table handles the code uses are patched onto the
``account_deletion`` module — the boto3 table-getter helpers
(``_messages_table`` / ``_participants_table`` / ``_posts_table``) and the ``T``
namespace (``T.subscriptions`` / ``T.account_deletion_requests``).

Each test asserts both branches of the ``account_deletion_destructive`` gate:
- destructive=True  -> data is mutated, counts are non-zero (the fix).
- destructive=False -> nothing is mutated, counts stay 0 (dev/e2e parity).
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


def _make_messages_table(ddb):
    return ddb.create_table(
        TableName="Messages",
        KeySchema=[
            {"AttributeName": "conversation_id", "KeyType": "HASH"},
            {"AttributeName": "message_id", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "conversation_id", "AttributeType": "S"},
            {"AttributeName": "message_id", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_participants_table(ddb):
    return ddb.create_table(
        TableName="Participants",
        KeySchema=[
            {"AttributeName": "user_id", "KeyType": "HASH"},
            {"AttributeName": "conversation_id", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "user_id", "AttributeType": "S"},
            {"AttributeName": "conversation_id", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_posts_table(ddb):
    """app_single_table with the GSI2 (POST_AUTHOR#) index used by _anonymize_posts."""
    return ddb.create_table(
        TableName="app_single_table",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "GSI2PK", "AttributeType": "S"},
            {"AttributeName": "GSI2SK", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "GSI2",
                "KeySchema": [
                    {"AttributeName": "GSI2PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI2SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_subscriptions_table(ddb):
    return ddb.create_table(
        TableName="subscriptions",
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


def _make_requests_table(ddb):
    return ddb.create_table(
        TableName="account_deletion_requests",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "status", "AttributeType": "S"},
            {"AttributeName": "scheduled_for", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByStatusScheduled",
                "KeySchema": [
                    {"AttributeName": "status", "KeyType": "HASH"},
                    {"AttributeName": "scheduled_for", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestFinalizeDeletionAnonymizeAndCancel(unittest.TestCase):
    USER = "test-user-sub-0331"
    CONV = "conv-0331"
    MSG = "m_0331abc"
    POST = "post-0331"
    SUB_AS_SUBSCRIBER = "sub-as-subscriber-0331"
    SUB_AS_CREATOR = "sub-as-creator-0331"
    OTHER_CREATOR = "creator-other-xyz"
    OTHER_SUBSCRIBER = "subscriber-other-xyz"

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")

        self.msgs = _make_messages_table(ddb)
        self.parts = _make_participants_table(ddb)
        self.posts = _make_posts_table(ddb)
        self.subs = _make_subscriptions_table(ddb)
        self.reqs = _make_requests_table(ddb)

        from app.services import account_deletion as ad

        self.ad = ad

        # Patch the boto3 table-getter helpers to return the moto tables.
        self.stack.enter_context(patch.object(ad, "_messages_table", lambda: self.msgs))
        self.stack.enter_context(patch.object(ad, "_participants_table", lambda: self.parts))
        self.stack.enter_context(patch.object(ad, "_posts_table", lambda: self.posts))
        # Patch the T namespace handles the module reads.
        self.stack.enter_context(
            patch.object(
                ad,
                "T",
                SimpleNamespace(
                    subscriptions=self.subs,
                    account_deletion_requests=self.reqs,
                ),
            )
        )

    def _set_destructive(self, value: bool):
        from app.core.settings import S
        # S is a frozen dataclass instance -> object.__setattr__.
        original = S.account_deletion_destructive
        object.__setattr__(S, "account_deletion_destructive", value)
        self.addCleanup(
            lambda: object.__setattr__(S, "account_deletion_destructive", original)
        )

    def _seed_all(self):
        # Message authored by the user.
        self.parts.put_item(Item={"user_id": self.USER, "conversation_id": self.CONV})
        self.msgs.put_item(Item={
            "conversation_id": self.CONV,
            "message_id": self.MSG,
            "sender_id": self.USER,
            "sender_display_name": "Real Name",
            "text": "Hello world",
            "created_at": 1000000,
        })
        # A message by someone else in the same conversation -> must NOT change.
        self.msgs.put_item(Item={
            "conversation_id": self.CONV,
            "message_id": "m_other",
            "sender_id": "someone-else",
            "text": "Untouched",
            "created_at": 1000001,
        })

        # Post authored by the user (GSI2 author index).
        self.posts.put_item(Item={
            "pk": f"POST#{self.POST}",
            "sk": "META",
            "post_id": self.POST,
            "user_id": self.USER,
            "GSI2PK": f"POST_AUTHOR#{self.USER}",
            "GSI2SK": f"1000000#POST#{self.POST}",
            "body": "My secret post",
            "body_plain": "My secret post",
            "body_format": "plain",
        })

        # Active subscription where the user is the SUBSCRIBER.
        self.subs.put_item(Item={
            "pk": f"SUBSCRIBER#{self.USER}",
            "sk": f"SUB#{self.SUB_AS_SUBSCRIBER}",
            "entity": "subscription_index",
        })
        self.subs.put_item(Item={
            "pk": f"SUB#{self.SUB_AS_SUBSCRIBER}",
            "sk": "META",
            "subscription_id": self.SUB_AS_SUBSCRIBER,
            "subscriber_id": self.USER,
            "creator_id": self.OTHER_CREATOR,
            "status": "active",
            "auto_renew": True,
            "plan_id": "plan-001",
        })

        # Active subscription where the user is the CREATOR.
        self.subs.put_item(Item={
            "pk": f"CREATOR#{self.USER}",
            "sk": f"SUB#{self.SUB_AS_CREATOR}",
            "entity": "subscription_index",
        })
        self.subs.put_item(Item={
            "pk": f"SUB#{self.SUB_AS_CREATOR}",
            "sk": "META",
            "subscription_id": self.SUB_AS_CREATOR,
            "subscriber_id": self.OTHER_SUBSCRIBER,
            "creator_id": self.USER,
            "status": "trialing",
            "auto_renew": True,
            "plan_id": "plan-002",
        })

    def _create_and_age_request(self):
        from app.core.time import now_ts
        item = self.ad.create_deletion_request(self.USER, reason="test")
        request_id = item["request_id"]
        self.reqs.update_item(
            Key={"pk": f"USER#{self.USER}", "sk": f"REQUEST#{request_id}"},
            UpdateExpression="SET scheduled_for = :v",
            ExpressionAttributeValues={":v": now_ts() - 1},
        )
        return request_id

    # ------------------------------------------------------------------
    # Destructive=True: the fix runs and mutates everything.
    # ------------------------------------------------------------------
    def test_finalize_anonymizes_and_cancels_when_destructive(self):
        self._set_destructive(True)
        self._seed_all()
        request_id = self._create_and_age_request()

        result = self.ad.finalize_deletion(self.USER, request_id)
        summary = result["deletion_summary"]

        # GAP-0331: messages anonymized.
        self.assertEqual(summary["messages_anonymized"], 1)
        msg = self.msgs.get_item(
            Key={"conversation_id": self.CONV, "message_id": self.MSG}
        )["Item"]
        self.assertEqual(msg["sender_id"], "deleted_user")
        self.assertEqual(msg["text"], "[This message was deleted]")
        self.assertEqual(msg["sender_display_name"], "Deleted User")
        self.assertTrue(msg.get("anonymized"))

        # Other user's message untouched.
        other = self.msgs.get_item(
            Key={"conversation_id": self.CONV, "message_id": "m_other"}
        )["Item"]
        self.assertEqual(other["sender_id"], "someone-else")
        self.assertEqual(other["text"], "Untouched")

        # GAP-0331: posts anonymized.
        self.assertEqual(summary["posts_anonymized"], 1)
        post = self.posts.get_item(
            Key={"pk": f"POST#{self.POST}", "sk": "META"}
        )["Item"]
        self.assertEqual(post["user_id"], "Deleted User")
        self.assertEqual(post["body"], "[This message was deleted]")
        self.assertEqual(post["body_plain"], "[This message was deleted]")
        self.assertTrue(post.get("anonymized"))

        # GAP-0332: both subscriptions cancelled (subscriber + creator side).
        self.assertEqual(summary["subscriptions_cancelled"], 2)
        for sub_id in (self.SUB_AS_SUBSCRIBER, self.SUB_AS_CREATOR):
            meta = self.subs.get_item(
                Key={"pk": f"SUB#{sub_id}", "sk": "META"}
            )["Item"]
            self.assertEqual(meta["status"], "canceled")
            self.assertEqual(meta["auto_renew"], False)
            self.assertEqual(meta.get("cancelled_reason"), "account_deleted")

    # ------------------------------------------------------------------
    # Destructive=False (dev default): nothing is mutated, counts stay 0.
    # ------------------------------------------------------------------
    def test_finalize_is_noop_when_not_destructive(self):
        self._set_destructive(False)
        self._seed_all()
        request_id = self._create_and_age_request()

        result = self.ad.finalize_deletion(self.USER, request_id)
        summary = result["deletion_summary"]

        self.assertEqual(summary["messages_anonymized"], 0)
        self.assertEqual(summary["posts_anonymized"], 0)
        self.assertEqual(summary["subscriptions_cancelled"], 0)

        # Underlying data is untouched.
        msg = self.msgs.get_item(
            Key={"conversation_id": self.CONV, "message_id": self.MSG}
        )["Item"]
        self.assertEqual(msg["sender_id"], self.USER)
        self.assertEqual(msg["text"], "Hello world")
        self.assertNotIn("anonymized", msg)

        post = self.posts.get_item(
            Key={"pk": f"POST#{self.POST}", "sk": "META"}
        )["Item"]
        self.assertEqual(post["user_id"], self.USER)
        self.assertEqual(post["body"], "My secret post")

        for sub_id, expected in (
            (self.SUB_AS_SUBSCRIBER, "active"),
            (self.SUB_AS_CREATOR, "trialing"),
        ):
            meta = self.subs.get_item(
                Key={"pk": f"SUB#{sub_id}", "sk": "META"}
            )["Item"]
            self.assertEqual(meta["status"], expected)

    # ------------------------------------------------------------------
    # Direct helper coverage (independent of finalize wiring).
    # ------------------------------------------------------------------
    def test_helpers_directly(self):
        self._set_destructive(True)
        self._seed_all()
        self.assertEqual(self.ad._anonymize_messages(self.USER), 1)
        self.assertEqual(self.ad._anonymize_posts(self.USER), 1)
        self.assertEqual(self.ad._cancel_active_subscriptions(self.USER), 2)


if __name__ == "__main__":
    unittest.main()
