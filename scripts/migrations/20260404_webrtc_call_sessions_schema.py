#!/usr/bin/env python3
from __future__ import annotations

from app.core.aws import ddb
from app.core.settings import S


def _ensure_table() -> None:
    client = ddb.meta.client
    table_name = S.message_call_sessions_table_name
    if table_name in set(client.list_tables().get("TableNames", [])):
        return

    client.create_table(
        TableName=table_name,
        AttributeDefinitions=[
            {"AttributeName": "call_id", "AttributeType": "S"},
            {"AttributeName": "conversation_id", "AttributeType": "S"},
            {"AttributeName": "caller_user_id", "AttributeType": "S"},
            {"AttributeName": "callee_user_id", "AttributeType": "S"},
            {"AttributeName": "start_ts_sort", "AttributeType": "N"},
        ],
        KeySchema=[{"AttributeName": "call_id", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByConversationStartedAt",
                "KeySchema": [
                    {"AttributeName": "conversation_id", "KeyType": "HASH"},
                    {"AttributeName": "start_ts_sort", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByCallerStartedAt",
                "KeySchema": [
                    {"AttributeName": "caller_user_id", "KeyType": "HASH"},
                    {"AttributeName": "start_ts_sort", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByCalleeStartedAt",
                "KeySchema": [
                    {"AttributeName": "callee_user_id", "KeyType": "HASH"},
                    {"AttributeName": "start_ts_sort", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
    )


def migrate() -> None:
    _ensure_table()


if __name__ == "__main__":
    migrate()
    print("webrtc call sessions schema migration complete")
