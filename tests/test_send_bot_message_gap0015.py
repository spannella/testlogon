"""Regression test for GAP-0015.

`send_bot_message` previously only incremented a cosmetic counter and returned a
plain dict — it never wrote anything to the Messages table, so bot messages never
appeared in conversations.

This test fails before the fix (no item written to the Messages table, return
dict has no ``message_id``) and passes after it. Fully offline: moto + in-memory
boto3, no real AWS.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch

import boto3
from boto3.dynamodb.conditions import Key

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
    messages = ddb.create_table(
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
    conversations = ddb.create_table(
        TableName="Conversations",
        KeySchema=[{"AttributeName": "conversation_id", "KeyType": "HASH"}],
        AttributeDefinitions=[
            {"AttributeName": "conversation_id", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    return chat_bots, messages, conversations


def _seed_bot(chat_bots, *, creator_id, bot_id, status="active", quick_replies=None):
    item = {
        "pk": f"CREATOR#{creator_id}",
        "sk": f"BOT#{bot_id}",
        "bot_id": bot_id,
        "creator_id": creator_id,
        "name": "TestBot",
        "status": status,
        "avatar_url": "https://cdn.example.com/bot.png",
        "message_count": 0,
        "created_at": now_ts(),
        "updated_at": now_ts(),
        "GSI1PK": f"BOT#{bot_id}",
        "GSI1SK": "META",
    }
    if quick_replies is not None:
        item["quick_replies"] = quick_replies
    chat_bots.put_item(Item=item)


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestSendBotMessageGap0015(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.chat_bots, self.messages, self.conversations = _create_tables(ddb)
        # Point the service at the moto-backed tables.
        self.stack.enter_context(
            patch.object(chat_bot, "T", SimpleNamespace(chat_bots=self.chat_bots))
        )
        self.stack.enter_context(patch.object(chat_bot, "_tbl_messages", self.messages))
        self.stack.enter_context(
            patch.object(chat_bot, "_tbl_conversations", self.conversations)
        )

    def test_writes_real_message_with_bot_fields_and_returns_message_id(self):
        creator_id = "creator_001"
        bot_id = "bot_001"
        convo_id = "conv_bot_write_001"
        _seed_bot(
            self.chat_bots,
            creator_id=creator_id,
            bot_id=bot_id,
            quick_replies=[{"label": "Yes", "value": "yes"}],
        )

        result = chat_bot.send_bot_message(
            bot_id=bot_id, conversation_id=convo_id, text="Hello from TestBot!"
        )

        # Return value must be a real item with a message_id.
        self.assertIsNotNone(result)
        self.assertIn("message_id", result)
        self.assertTrue(result["message_id"].startswith("m_"))

        # The message must be retrievable from the Messages table.
        items = self.messages.query(
            KeyConditionExpression=Key("conversation_id").eq(convo_id)
        ).get("Items", [])
        self.assertEqual(len(items), 1)
        stored = items[0]
        self.assertEqual(stored["message_id"], result["message_id"])
        self.assertEqual(stored["sender_type"], "bot")
        self.assertEqual(stored["bot_id"], bot_id)
        self.assertEqual(stored["bot_name"], "TestBot")
        self.assertEqual(stored["bot_avatar_url"], "https://cdn.example.com/bot.png")
        self.assertEqual(stored["text"], "Hello from TestBot!")
        self.assertEqual(stored["kind"], "text")
        # Bot quick_replies must be persisted so GAP-0014's projection surfaces them.
        self.assertIn("quick_replies", stored)
        self.assertEqual(stored["quick_replies"][0]["label"], "Yes")

        # Conversation last-message metadata must be updated.
        convo = self.conversations.get_item(
            Key={"conversation_id": convo_id}
        ).get("Item", {})
        self.assertEqual(convo.get("last_message_id"), result["message_id"])

    def test_inactive_bot_returns_none_and_writes_nothing(self):
        creator_id = "creator_002"
        bot_id = "bot_002"
        convo_id = "conv_002"
        _seed_bot(
            self.chat_bots, creator_id=creator_id, bot_id=bot_id, status="paused"
        )

        result = chat_bot.send_bot_message(
            bot_id=bot_id, conversation_id=convo_id, text="should not send"
        )

        self.assertIsNone(result)
        items = self.messages.query(
            KeyConditionExpression=Key("conversation_id").eq(convo_id)
        ).get("Items", [])
        self.assertEqual(len(items), 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
