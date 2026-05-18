#!/usr/bin/env python3
from __future__ import annotations

import os
from typing import Any

DDB_MESSAGE_DRAFTS = os.getenv("DDB_MESSAGE_DRAFTS", "MessageDrafts")
DRAFTS_TTL_ATTR = os.getenv("DRAFTS_TTL_ATTR", "ttl_epoch")


def _list_tables(client: Any) -> set[str]:
    paginator = getattr(client, "get_paginator", None)
    if callable(paginator):
        names: set[str] = set()
        for page in client.get_paginator("list_tables").paginate():
            names.update(page.get("TableNames", []))
        return names
    return set(client.list_tables().get("TableNames", []))


def _ensure_table(client: Any, table_name: str) -> None:
    if table_name in _list_tables(client):
        return

    client.create_table(
        TableName=table_name,
        BillingMode="PAY_PER_REQUEST",
        AttributeDefinitions=[
            {"AttributeName": "owner_user_id", "AttributeType": "S"},
            {"AttributeName": "draft_id", "AttributeType": "S"},
            {"AttributeName": "conversation_owner_key", "AttributeType": "S"},
            {"AttributeName": "updated_at", "AttributeType": "N"},
        ],
        KeySchema=[
            {"AttributeName": "owner_user_id", "KeyType": "HASH"},
            {"AttributeName": "draft_id", "KeyType": "RANGE"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByConversationUpdatedAt",
                "KeySchema": [
                    {"AttributeName": "conversation_owner_key", "KeyType": "HASH"},
                    {"AttributeName": "updated_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByOwnerUpdatedAt",
                "KeySchema": [
                    {"AttributeName": "owner_user_id", "KeyType": "HASH"},
                    {"AttributeName": "updated_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
    )


def _ensure_ttl(client: Any, table_name: str, ttl_attr: str) -> None:
    ttl_desc = client.describe_time_to_live(TableName=table_name).get("TimeToLiveDescription", {})
    status = ttl_desc.get("TimeToLiveStatus", "DISABLED")
    current_attr = ttl_desc.get("AttributeName")

    if status in {"ENABLED", "ENABLING"} and current_attr == ttl_attr:
        return

    client.update_time_to_live(
        TableName=table_name,
        TimeToLiveSpecification={"Enabled": True, "AttributeName": ttl_attr},
    )


def migrate(table_name: str = DDB_MESSAGE_DRAFTS, ttl_attr: str = DRAFTS_TTL_ATTR, *, client: Any | None = None) -> None:
    if client is None:
        from app.core.aws import ddb  # lazy import for environments/tests without boto3

        ddb_client = ddb.meta.client
    else:
        ddb_client = client
    _ensure_table(ddb_client, table_name)
    _ensure_ttl(ddb_client, table_name, ttl_attr)


if __name__ == "__main__":
    migrate()
    print("messaging drafts schema migration complete")
