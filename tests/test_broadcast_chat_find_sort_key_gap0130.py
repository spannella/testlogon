"""Regression tests for GAP-0130: _find_sort_key was an O(n) Limit=200 partition
scan, silently missing any message beyond the 200 most-recent items.

Offline / in-memory only: uses moto's in-memory DynamoDB (no real AWS). The
broadcast_chat_messages table handle on app.core.tables.T is swapped for a
moto-backed table (carrying the MessageIdIndex GSI) for each test.

Before the fix (Limit=200, ScanIndexForward=False, no GSI), _find_sort_key
returns None for the oldest message in a 201-message partition, because it falls
outside the 200-item read window. After the fix (MessageIdIndex GSI lookup), the
message is found by id regardless of position.
"""
from __future__ import annotations

import boto3
import pytest
from moto import mock_aws


@pytest.fixture
def broadcast_chat_messages_table():
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        ddb.create_table(
            TableName="BroadcastChatMessages",
            KeySchema=[
                {"AttributeName": "session_id", "KeyType": "HASH"},
                {"AttributeName": "sort_key", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "session_id", "AttributeType": "S"},
                {"AttributeName": "sort_key", "AttributeType": "S"},
                {"AttributeName": "message_id", "AttributeType": "S"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "MessageIdIndex",
                    "KeySchema": [
                        {"AttributeName": "message_id", "KeyType": "HASH"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                }
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        import app.core.tables as tables_mod

        table = ddb.Table("BroadcastChatMessages")
        original = tables_mod.T.broadcast_chat_messages
        object.__setattr__(tables_mod.T, "broadcast_chat_messages", table)
        try:
            yield table
        finally:
            object.__setattr__(
                tables_mod.T, "broadcast_chat_messages", original
            )


def test_find_sort_key_locates_old_message_beyond_200(
    broadcast_chat_messages_table,
):
    """FAILS BEFORE FIX: oldest message (position 201) is outside the Limit=200
    newest-first window, so the old scan returns None. PASSES AFTER FIX via GSI."""
    from app.services.broadcast_chat_store import _find_sort_key

    session_id = "sess_deep_test"
    target_message_id = None
    target_sort_key = None

    # Write 201 messages; i==0 is the oldest item in the partition.
    for i in range(201):
        msg_id = f"cm_{i:04d}abc"
        sk = f"{i:016d}#{msg_id}"
        if i == 0:
            target_message_id = msg_id
            target_sort_key = sk
        broadcast_chat_messages_table.put_item(
            Item={
                "session_id": session_id,
                "sort_key": sk,
                "message_id": msg_id,
                "text": f"msg {i}",
            }
        )

    result = _find_sort_key(session_id, target_message_id)
    assert result == target_sort_key, (
        f"Expected sort_key {target_sort_key!r}, got {result!r}. "
        "Old code with Limit=200 returns None for messages beyond position 200."
    )


def test_find_sort_key_does_not_cross_sessions(broadcast_chat_messages_table):
    """The session-ownership guard ensures the returned item belongs to the
    requested session, not a different session sharing a message_id."""
    from app.services.broadcast_chat_store import _find_sort_key

    for sess in ("sess_a", "sess_b"):
        broadcast_chat_messages_table.put_item(
            Item={
                "session_id": sess,
                "sort_key": "0000000000000001#cm_shared",
                "message_id": "cm_shared",
                "text": "shared id",
            }
        )

    result = _find_sort_key("sess_a", "cm_shared")
    assert result is not None
    item = broadcast_chat_messages_table.get_item(
        Key={"session_id": "sess_a", "sort_key": result}
    ).get("Item")
    assert item is not None
    assert item["session_id"] == "sess_a"
