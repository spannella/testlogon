"""Regression test for GAP-0134.

`get_bots_for_conversation()` previously queried GSI1 only for direct
``CONV#{conversation_id}`` assignments. Wildcard scope assignments
(``all_dms`` / ``all_groups`` / ``all_broadcasts``) were stored without any
``GSI1PK`` (``_build_assignment_gsi1pk`` returned ``None`` for them), so they
were structurally unreachable and any bot assigned at wildcard scope never
fired.

The fix stores wildcard assignments on GSI1 under a scope bucket
(``SCOPE#ALL_DMS`` etc.) and has ``get_bots_for_conversation`` additionally
query the bucket matching the conversation kind.

This test exercises the real ``assign_bot`` write path and
``get_bots_for_conversation`` read path against moto-backed DynamoDB. It fails
before the fix (the wildcard bot is not returned) and passes after it. Fully
offline — moto + in-memory boto3, no real AWS.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover
    mock_aws = None

from app.core.time import now_ts
from app.services import chat_bot


def _create_tables(ddb):
    chat_bots = ddb.create_table(
        TableName="ChatBots",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "GSI1PK", "AttributeType": "S"},
            {"AttributeName": "GSI1SK", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "GSI1",
                "KeySchema": [
                    {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    bot_assignments = ddb.create_table(
        TableName="BotAssignments",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "GSI1PK", "AttributeType": "S"},
            {"AttributeName": "GSI1SK", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "GSI1",
                "KeySchema": [
                    {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    return SimpleNamespace(chat_bots=chat_bots, bot_assignments=bot_assignments)


def _seed_bot(t, *, creator_id, bot_id, status="active"):
    ts = now_ts()
    t.chat_bots.put_item(
        Item={
            "pk": f"CREATOR#{creator_id}",
            "sk": f"BOT#{bot_id}",
            "bot_id": bot_id,
            "creator_id": creator_id,
            "name": "TestBot",
            "status": status,
            "message_count": 0,
            "created_at": ts,
            "updated_at": ts,
            "GSI1PK": f"BOT#{bot_id}",
            "GSI1SK": "META",
        }
    )


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestGetBotsForConversationWildcardGap0134(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.t = _create_tables(ddb)
        self.stack.enter_context(
            patch.object(
                chat_bot,
                "T",
                SimpleNamespace(
                    chat_bots=self.t.chat_bots,
                    bot_assignments=self.t.bot_assignments,
                ),
            )
        )

    def test_wildcard_all_dms_bot_returned_for_dm_conversation(self):
        """A bot assigned to scope all_dms must be found for a DM conversation.

        FAILS BEFORE FIX: wildcard assignment has no GSI1PK and is unreachable,
        so get_bots_for_conversation returns an empty list.
        """
        creator_id = "creator_001"
        bot_id = "bot_wildcard"
        _seed_bot(self.t, creator_id=creator_id, bot_id=bot_id)

        # Real write path: assign at wildcard scope.
        chat_bot.assign_bot(
            bot_id=bot_id,
            creator_id=creator_id,
            target_type="all_dms",
        )

        result = chat_bot.get_bots_for_conversation(
            conversation_id="conv_dm_001",
            conversation_type="dm",
        )

        self.assertTrue(
            any(b["bot_id"] == bot_id for b in result),
            "Wildcard ALL_DMS bot must be returned for DM conversations",
        )

    def test_wildcard_all_groups_bot_not_returned_for_dm(self):
        """An all_groups bot must NOT fire in a DM conversation."""
        creator_id = "creator_002"
        bot_id = "bot_group"
        _seed_bot(self.t, creator_id=creator_id, bot_id=bot_id)
        chat_bot.assign_bot(
            bot_id=bot_id,
            creator_id=creator_id,
            target_type="all_groups",
        )

        result = chat_bot.get_bots_for_conversation(
            conversation_id="conv_dm_002",
            conversation_type="dm",
        )

        self.assertFalse(
            any(b["bot_id"] == bot_id for b in result),
            "Group-scoped bot must not fire in a DM",
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
