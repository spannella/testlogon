"""Regression test for GAP-0133.

`send_text_message()` persisted and fanned out a message but never invoked the
chat-bot trigger evaluation, so every configured bot was inert for live
conversation messages. The fix adds a best-effort post-send hook,
``_run_bot_trigger_evaluation``, which walks the bots assigned to the
conversation, evaluates their triggers against the incoming message, and
dispatches a bot reply (persisted via ``chat_bot.send_bot_message``, GAP-0015)
for any match.

This test exercises that hook end-to-end against moto-backed DynamoDB tables
(bot, assignment, template, messages, conversations). It fails before the fix
(the hook does not exist / is never wired) and passes after it: a message whose
text matches a keyword trigger causes a bot reply to be written to the Messages
table. Fully offline — moto + in-memory boto3, no real AWS.
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
from app.services import bot_template, chat_bot


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
    bot_templates = ddb.create_table(
        TableName="BotTemplates",
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
    return SimpleNamespace(
        chat_bots=chat_bots,
        bot_assignments=bot_assignments,
        bot_templates=bot_templates,
        messages=messages,
        conversations=conversations,
    )


def _seed_bot(t, *, creator_id, bot_id, trigger_config, status="active"):
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
            "trigger_config": trigger_config,
            "created_at": ts,
            "updated_at": ts,
            "GSI1PK": f"BOT#{bot_id}",
            "GSI1SK": "META",
        }
    )


def _assign_bot_to_conversation(t, *, creator_id, bot_id, conversation_id):
    t.bot_assignments.put_item(
        Item={
            "pk": f"BOT#{bot_id}",
            "sk": f"CONV#{conversation_id}",
            "bot_id": bot_id,
            "creator_id": creator_id,
            "target_type": "conversation",
            "target_id": conversation_id,
            "created_at": now_ts(),
            "GSI1PK": f"CONV#{conversation_id}",
            "GSI1SK": f"BOT#{bot_id}",
        }
    )


def _seed_template(t, *, bot_id, template_id, text):
    t.bot_templates.put_item(
        Item={
            "pk": f"BOT#{bot_id}",
            "sk": f"TEMPLATE#{template_id}",
            "bot_id": bot_id,
            "template_id": template_id,
            "name": "Greeting",
            "text": text,
            "category": "custom",
            "body_format": "plain",
            "created_at": now_ts(),
            "updated_at": now_ts(),
        }
    )


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestBotTriggerHookGap0133(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.t = _create_tables(ddb)

        # Point chat_bot at moto-backed tables (assignments + bots) and the raw
        # Messages/Conversations table handles it resolves at import time.
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
        self.stack.enter_context(patch.object(chat_bot, "_tbl_messages", self.t.messages))
        self.stack.enter_context(
            patch.object(chat_bot, "_tbl_conversations", self.t.conversations)
        )
        # Point bot_template at the moto-backed templates table.
        self.stack.enter_context(
            patch.object(
                bot_template,
                "T",
                SimpleNamespace(bot_templates=self.t.bot_templates),
            )
        )

    def _bot_messages(self, conversation_id):
        items = self.t.messages.query(
            KeyConditionExpression=Key("conversation_id").eq(conversation_id)
        ).get("Items", [])
        return [i for i in items if i.get("sender_type") == "bot"]

    def test_keyword_trigger_persists_bot_reply(self):
        """A live message matching a keyword trigger yields a persisted bot reply."""
        from app.routers.messaging import _run_bot_trigger_evaluation

        creator_id = "creator_001"
        bot_id = "bot_001"
        convo_id = "conv_gap0133_match"
        _seed_bot(
            self.t,
            creator_id=creator_id,
            bot_id=bot_id,
            trigger_config={
                "triggers": [
                    {
                        "type": "keyword",
                        "keywords": ["hello"],
                        "response_template_id": "tmpl_001",
                    }
                ],
                "priority_order": ["keyword"],
            },
        )
        _assign_bot_to_conversation(
            self.t, creator_id=creator_id, bot_id=bot_id, conversation_id=convo_id
        )
        _seed_template(
            self.t, bot_id=bot_id, template_id="tmpl_001", text="Hi there, welcome!"
        )

        # No bot reply exists before the hook runs.
        self.assertEqual(len(self._bot_messages(convo_id)), 0)

        _run_bot_trigger_evaluation(
            conversation_id=convo_id,
            message_item={"text": "hello world", "sender_id": "user_001"},
        )

        bot_msgs = self._bot_messages(convo_id)
        self.assertEqual(len(bot_msgs), 1, "Bot should reply to keyword match")
        self.assertEqual(bot_msgs[0]["bot_id"], bot_id)
        self.assertEqual(bot_msgs[0]["text"], "Hi there, welcome!")

    def test_no_matching_trigger_no_reply(self):
        """A message that matches no trigger produces no bot reply."""
        from app.routers.messaging import _run_bot_trigger_evaluation

        creator_id = "creator_002"
        bot_id = "bot_002"
        convo_id = "conv_gap0133_nomatch"
        _seed_bot(
            self.t,
            creator_id=creator_id,
            bot_id=bot_id,
            trigger_config={
                "triggers": [
                    {
                        "type": "keyword",
                        "keywords": ["goodbye"],
                        "response_template_id": "tmpl_002",
                    }
                ],
                "priority_order": ["keyword"],
            },
        )
        _assign_bot_to_conversation(
            self.t, creator_id=creator_id, bot_id=bot_id, conversation_id=convo_id
        )
        _seed_template(self.t, bot_id=bot_id, template_id="tmpl_002", text="Bye!")

        _run_bot_trigger_evaluation(
            conversation_id=convo_id,
            message_item={"text": "hello world", "sender_id": "user_002"},
        )

        self.assertEqual(len(self._bot_messages(convo_id)), 0)


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestBotTriggerHookWiredIntoSend(unittest.TestCase):
    """The hook must actually be called from send_text_message, not just exist."""

    def test_send_text_message_invokes_bot_trigger_hook(self):
        import inspect

        from app.routers import messaging

        src = inspect.getsource(messaging.send_text_message)
        self.assertIn(
            "_run_bot_trigger_evaluation",
            src,
            "send_text_message must invoke the bot trigger evaluation hook (GAP-0133)",
        )
        # The hook must be guarded so scheduled / encrypted messages are skipped.
        self.assertIn("not is_scheduled and not is_encrypted", src)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
