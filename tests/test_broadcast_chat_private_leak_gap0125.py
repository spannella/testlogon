"""Regression test for GAP-0125.

Private chat messages (``kind="private_chat"``) are written to the shared
``broadcast_chat_messages`` table by ``send_private_chat_message``. Previously
``get_chat_history`` filtered only soft-deleted items, and
``fetch_chat_messages_after`` (the SSE polling path) had no FilterExpression at
all, so private chat messages leaked into the public chat history / SSE stream
for any broadcast viewer.

These tests FAIL before the fix (private message returned by both paths) and
PASS after it (private message excluded; public messages still returned).
Fully offline: moto + in-memory boto3, NO real AWS, exercising real DynamoDB
FilterExpression semantics.
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

from app.services import broadcast_chat_store


def _create_chat_table(ddb):
    return ddb.create_table(
        TableName="BroadcastChatMessages",
        KeySchema=[
            {"AttributeName": "session_id", "KeyType": "HASH"},
            {"AttributeName": "sort_key", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "session_id", "AttributeType": "S"},
            {"AttributeName": "sort_key", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestBroadcastPrivateChatLeakGap0125(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.chat = _create_chat_table(ddb)
        # Point the chat store at the moto-backed table (T is a frozen
        # dataclass, so patch the whole handle rather than one attribute).
        self.stack.enter_context(
            patch.object(
                broadcast_chat_store,
                "T",
                SimpleNamespace(broadcast_chat_messages=self.chat),
            )
        )

        # Public message: no `kind` attribute at all (absence => "text").
        self.chat.put_item(
            Item={
                "session_id": "sess_001",
                "sort_key": "0000000001000000#cm_pub",
                "message_id": "cm_pub",
                "sender_id": "user_a",
                "sender_display_name": "Alice",
                "text": "Hello world",
                "deleted": False,
            }
        )
        # Private chat message: kind="private_chat", must never leak.
        self.chat.put_item(
            Item={
                "session_id": "sess_001",
                "sort_key": "0000000002000000#pcm_priv",
                "message_id": "pcm_priv",
                "sender_id": "user_b",
                "sender_display_name": "Bob",
                "text": "Secret private message",
                "kind": "private_chat",
                "private_chat_id": "chat_001",
                "deleted": False,
            }
        )

    def test_get_chat_history_excludes_private_chat_messages(self):
        result = broadcast_chat_store.get_chat_history("sess_001", limit=100)
        ids = {m["message_id"] for m in result["messages"]}
        texts = {m.get("text") for m in result["messages"]}
        self.assertIn("cm_pub", ids, "public message should appear in history")
        self.assertNotIn(
            "pcm_priv", ids, "private_chat message must NOT appear in public history"
        )
        self.assertNotIn("Secret private message", texts)

    def test_fetch_chat_messages_after_excludes_private_chat_messages(self):
        items = broadcast_chat_store.fetch_chat_messages_after(
            "sess_001", after_sort_key=None, limit=50
        )
        ids = {i.get("message_id") for i in items}
        self.assertIn("cm_pub", ids, "public message should appear in SSE stream")
        self.assertNotIn(
            "pcm_priv", ids, "private_chat message must NOT appear in SSE stream"
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
