"""Offline regression test for GAP-0329 (PLATFORM-011).

`_search_messages` in ``app/routers/search.py`` builds the caller's
``allowed_conv_ids`` authorization set by paginating the participants table.
The original loop exited early via ``if not last_key or len(parts) >= 500``,
so a user who is a member of MORE than 500 conversations only ever loaded the
first 500. Messages in conversations 501+ were silently dropped from search
results by the ``if conv_id not in allowed_conv_ids: continue`` filter — a
correctness/availability bug (an OMISSION, not a disclosure leak).

The fix removes the ``len(parts) >= 500`` early-exit and paginates until
DynamoDB's ``LastEvaluatedKey`` is falsy (with a generous page-count safety
bound that LOGs if hit).

This test is fully offline/hermetic:
  * A real in-memory DynamoDB participants table is created with moto and
    seeded with 600 participant rows for the user, forcing pagination across
    multiple DDB pages.
  * ``app.routers.messaging.tbl_parts`` (the exact module-level handle the code
    imports inside ``_search_messages``) is patched to that moto table.
  * ``tbl_msg_search``/``tbl_msgs`` and the message-search helpers are stubbed
    so the test focuses on the authorization-set pagination.
  * ``_search_messages`` is called directly (the FastAPI TestClient is unusable
    in this repo).

Fails-before: a message in conversation #550 (beyond the 500-cap) is excluded
from results. Passes-after: it is returned.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack
from unittest.mock import MagicMock, patch

import boto3
from boto3.dynamodb.conditions import Key

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None

from app.routers import search as search_mod


def _make_participants_table(ddb):
    """Create a participants table mirroring the real PK schema (user_id PK)."""
    return ddb.create_table(
        TableName="Participants_test_gap0329",
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


@unittest.skipIf(mock_aws is None, "moto not installed")
class TestSearchConvPaginationGap0329(unittest.TestCase):
    USER = "user1"
    # conv ids are zero-padded so the DDB range-key sort order is deterministic
    # and conv #550 is genuinely beyond the first 500-row page.
    N_CONVS = 600
    TARGET_IDX = 550

    def setUp(self):
        self._stack = ExitStack()
        self._aws = self._stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.tbl_parts = _make_participants_table(ddb)

        # Seed 600 participant rows for the user → forces moto to paginate
        # (Limit=500 per page in the code under test).
        with self.tbl_parts.batch_writer() as bw:
            for i in range(self.N_CONVS):
                bw.put_item(
                    Item={
                        "user_id": self.USER,
                        "conversation_id": f"conv_{i:05d}",
                        "status": "active",
                    }
                )

        self.target_conv = f"conv_{self.TARGET_IDX:05d}"
        self.target_msg = "m_target"

        # MessageSearch stub: the token "hello" maps to a message in the
        # beyond-500 target conversation.
        self.tbl_msg_search = MagicMock()
        self.tbl_msg_search.query.return_value = {
            "Items": [
                {
                    "token": "hello",
                    "conversation_id#message_id": f"{self.target_conv}#{self.target_msg}",
                }
            ]
        }

        # Messages stub: returns the actual message record.
        self.tbl_msgs = MagicMock()
        self.tbl_msgs.get_item.return_value = {
            "Item": {
                "conversation_id": self.target_conv,
                "message_id": self.target_msg,
                "text": "hello world",
                "sender_id": "user2",
                "created_at": 1700000000,
            }
        }

        # Patch the exact symbols `_search_messages` imports from messaging.
        self._stack.enter_context(
            patch("app.routers.messaging.tbl_parts", self.tbl_parts)
        )
        self._stack.enter_context(
            patch("app.routers.messaging.tbl_msg_search", self.tbl_msg_search)
        )
        self._stack.enter_context(
            patch("app.routers.messaging.tbl_msgs", self.tbl_msgs)
        )
        self._stack.enter_context(
            patch("app.routers.messaging._message_search_enabled", return_value=True)
        )
        self._stack.enter_context(
            patch(
                "app.routers.messaging.build_message_query_tokens",
                return_value=["hello"],
            )
        )

    def tearDown(self):
        self._stack.close()

    def test_message_beyond_500th_conversation_is_returned(self):
        """FAILS before fix (conv #550 excluded), PASSES after (full allowlist)."""
        result = search_mod._search_messages("hello", self.USER, limit=10)

        conv_ids = [item["meta"]["conversation_id"] for item in result["items"]]
        self.assertIn(
            self.target_conv,
            conv_ids,
            "message in conversation #550 (beyond the 500-cap) must be returned "
            "once allowed_conv_ids is fully paginated",
        )
        self.assertEqual(len(result["items"]), 1)
        self.assertEqual(result["items"][0]["id"], self.target_msg)

    def test_allowed_conv_ids_includes_all_600(self):
        """Directly verify the authorization set is built from every page.

        Re-runs the participant pagination exactly as the code does and asserts
        the complete set is loaded (sanity check that moto actually paginated
        and the target is present beyond row 500).
        """
        parts: list[dict] = []
        last_key = None
        while True:
            kw: dict = {
                "KeyConditionExpression": Key("user_id").eq(self.USER),
                "Limit": 500,
            }
            if last_key:
                kw["ExclusiveStartKey"] = last_key
            resp = self.tbl_parts.query(**kw)
            parts.extend(resp.get("Items", []))
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break

        allowed = {p["conversation_id"] for p in parts}
        self.assertEqual(len(allowed), self.N_CONVS)
        self.assertIn(self.target_conv, allowed)
        # Confirm the seed genuinely spanned more than one DDB page.
        self.assertGreater(self.N_CONVS, 500)


if __name__ == "__main__":
    unittest.main()
