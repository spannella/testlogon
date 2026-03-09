#!/usr/bin/env python3
from __future__ import annotations

from app.core.aws import ddb
from app.core.settings import S


def _ensure_table() -> None:
    client = ddb.meta.client
    table_name = S.moderation_audit_log_table_name
    if table_name in set(client.list_tables().get("TableNames", [])):
        return

    client.create_table(
        TableName=table_name,
        AttributeDefinitions=[
            {"AttributeName": "audit_id", "AttributeType": "S"},
            {"AttributeName": "ticket_id", "AttributeType": "S"},
            {"AttributeName": "actor_user_id", "AttributeType": "S"},
            {"AttributeName": "action", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "S"},
        ],
        KeySchema=[{"AttributeName": "audit_id", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByTicketCreatedAt",
                "KeySchema": [
                    {"AttributeName": "ticket_id", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByActorCreatedAt",
                "KeySchema": [
                    {"AttributeName": "actor_user_id", "KeyType": "HASH"},
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
        ],
    )


def migrate() -> None:
    _ensure_table()


if __name__ == "__main__":
    migrate()
    print("moderation audit log schema migration complete")
