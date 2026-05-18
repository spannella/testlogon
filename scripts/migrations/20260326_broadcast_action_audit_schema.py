#!/usr/bin/env python3
from __future__ import annotations

from app.core.aws import ddb
from app.core.settings import S


def _ensure_table() -> None:
    client = ddb.meta.client
    table_name = S.broadcast_action_audit_table_name
    if table_name in set(client.list_tables().get("TableNames", [])):
        return

    client.create_table(
        TableName=table_name,
        AttributeDefinitions=[
            {"AttributeName": "audit_id", "AttributeType": "S"},
            {"AttributeName": "actor", "AttributeType": "S"},
            {"AttributeName": "action", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "S"},
            {"AttributeName": "scope", "AttributeType": "S"},
        ],
        KeySchema=[{"AttributeName": "audit_id", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByActorCreatedAt",
                "KeySchema": [
                    {"AttributeName": "actor", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByActionCreatedAt",
                "KeySchema": [
                    {"AttributeName": "action", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByCreatedAt",
                "KeySchema": [
                    {"AttributeName": "scope", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
    )


def migrate() -> None:
    _ensure_table()


if __name__ == "__main__":
    migrate()
    print("broadcast action audit schema migration complete")
