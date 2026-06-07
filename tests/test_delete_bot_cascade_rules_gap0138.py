"""Regression test for GAP-0138.

``delete_bot()`` previously cascade-deleted only the bot's assignments (from
``T.bot_assignments``) and the main bot record (``CREATOR#{creator_id}`` /
``BOT#{bot_id}`` in ``T.chat_bots``). It left the bot's auto-reply rules
(stored in ``T.chat_bots`` under ``pk=BOT#{bot_id}`` / ``sk=RULE#{rule_id}``)
and its scheduled sends (``T.bot_scheduled_sends`` under ``pk=BOT#{bot_id}`` /
``sk=SCHED#{schedule_id}``) untouched, orphaning them indefinitely.

The fix queries and deletes those per-bot child rows during deletion.

This test exercises the real ``delete_bot`` path against moto-backed
DynamoDB. It FAILS BEFORE the fix (orphaned RULE# items remain) and PASSES
AFTER it. Fully offline — moto + in-memory boto3, no real AWS.
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


def _pk_sk_table(ddb, name):
    return ddb.create_table(
        TableName=name,
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


def _create_tables(ddb):
    return SimpleNamespace(
        chat_bots=_pk_sk_table(ddb, "ChatBots"),
        bot_assignments=_pk_sk_table(ddb, "BotAssignments"),
        bot_scheduled_sends=_pk_sk_table(ddb, "BotScheduledSends"),
    )


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


def _seed_rules(t, *, bot_id, creator_id, count):
    for i in range(count):
        rule_id = f"rule{i:04d}"
        t.chat_bots.put_item(
            Item={
                "pk": f"BOT#{bot_id}",
                "sk": f"RULE#{rule_id}",
                "rule_id": rule_id,
                "bot_id": bot_id,
                "creator_id": creator_id,
                "trigger_pattern": f"pattern{i}",
                "response_template": f"response{i}",
                "GSI1PK": f"BOT#{bot_id}",
                "GSI1SK": f"RULE#{100 + i:08d}#{rule_id}",
            }
        )


def _seed_scheds(t, *, bot_id, count):
    for i in range(count):
        sid = f"sched{i:04d}"
        t.bot_scheduled_sends.put_item(
            Item={
                "pk": f"BOT#{bot_id}",
                "sk": f"SCHED#{sid}",
                "schedule_id": sid,
                "bot_id": bot_id,
                "GSI1PK": "BOTSCHED#PENDING",
                "GSI1SK": now_ts() + i,
            }
        )


def _count_rules(t, bot_id):
    resp = t.chat_bots.query(
        KeyConditionExpression=Key("pk").eq(f"BOT#{bot_id}") & Key("sk").begins_with("RULE#")
    )
    return len(resp.get("Items", []))


def _count_scheds(t, bot_id):
    resp = t.bot_scheduled_sends.query(
        KeyConditionExpression=Key("pk").eq(f"BOT#{bot_id}") & Key("sk").begins_with("SCHED#")
    )
    return len(resp.get("Items", []))


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestDeleteBotCascadeGap0138(unittest.TestCase):
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
                    bot_scheduled_sends=self.t.bot_scheduled_sends,
                ),
            )
        )

    def test_delete_bot_cascades_auto_reply_rules(self):
        """delete_bot() must remove all RULE# items for the bot.

        FAILS BEFORE FIX: 3 orphaned RULE# items remain in T.chat_bots.
        """
        creator_id = "creator_001"
        bot_id = "bot_rules"
        _seed_bot(self.t, creator_id=creator_id, bot_id=bot_id)
        _seed_rules(self.t, bot_id=bot_id, creator_id=creator_id, count=3)
        _seed_scheds(self.t, bot_id=bot_id, count=2)

        self.assertEqual(_count_rules(self.t, bot_id), 3)
        self.assertEqual(_count_scheds(self.t, bot_id), 2)

        result = chat_bot.delete_bot(creator_id=creator_id, bot_id=bot_id)
        self.assertTrue(result)

        self.assertEqual(
            _count_rules(self.t, bot_id), 0,
            "Auto-reply rules must be cascade-deleted; before GAP-0138 fix this was 3",
        )
        self.assertEqual(
            _count_scheds(self.t, bot_id), 0,
            "Scheduled sends must be cascade-deleted; before GAP-0138 fix this was 2",
        )

        # Main bot record is also gone.
        got = self.t.chat_bots.get_item(
            Key={"pk": f"CREATOR#{creator_id}", "sk": f"BOT#{bot_id}"}
        )
        self.assertNotIn("Item", got)

    def test_delete_bot_with_no_rules_still_works(self):
        """A bot with no rules/scheds deletes cleanly (empty cascade)."""
        creator_id = "creator_002"
        bot_id = "bot_norules"
        _seed_bot(self.t, creator_id=creator_id, bot_id=bot_id)

        result = chat_bot.delete_bot(creator_id=creator_id, bot_id=bot_id)
        self.assertTrue(result)
        self.assertEqual(_count_rules(self.t, bot_id), 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
