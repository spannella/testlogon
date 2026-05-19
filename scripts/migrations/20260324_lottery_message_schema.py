#!/usr/bin/env python3
from __future__ import annotations

from app.core.aws import ddb
from app.core.settings import S


def _table_exists(table_name: str) -> bool:
    return table_name in set(ddb.meta.client.list_tables().get("TableNames", []))


def _ensure_lottery_message_config_table() -> None:
    client = ddb.meta.client
    table_name = S.lottery_message_config_table_name
    if _table_exists(table_name):
        return

    client.create_table(
        TableName=table_name,
        AttributeDefinitions=[
            {"AttributeName": "message_id", "AttributeType": "S"},
            {"AttributeName": "conversation_id", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "S"},
        ],
        KeySchema=[{"AttributeName": "message_id", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByConversationCreatedAt",
                "KeySchema": [
                    {"AttributeName": "conversation_id", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
    )


def _ensure_lottery_message_unlocks_table() -> None:
    client = ddb.meta.client
    table_name = S.lottery_message_unlocks_table_name
    if _table_exists(table_name):
        return

    client.create_table(
        TableName=table_name,
        AttributeDefinitions=[
            {"AttributeName": "message_id", "AttributeType": "S"},
            {"AttributeName": "recipient_id", "AttributeType": "S"},
            {"AttributeName": "unlocked_at", "AttributeType": "S"},
        ],
        KeySchema=[
            {"AttributeName": "message_id", "KeyType": "HASH"},
            {"AttributeName": "recipient_id", "KeyType": "RANGE"},
        ],
        BillingMode="PAY_PER_REQUEST",
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByRecipientUnlockedAt",
                "KeySchema": [
                    {"AttributeName": "recipient_id", "KeyType": "HASH"},
                    {"AttributeName": "unlocked_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
    )


def migrate() -> None:
    _ensure_lottery_message_config_table()
    _ensure_lottery_message_unlocks_table()


if __name__ == "__main__":
    migrate()
    print("lottery message schema migration complete")
