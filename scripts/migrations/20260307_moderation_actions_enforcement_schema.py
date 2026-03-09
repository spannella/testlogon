#!/usr/bin/env python3
from __future__ import annotations

from app.core.aws import ddb
from app.core.settings import S


def _ensure_table(
    *,
    table_name: str,
    partition_key: str,
    sort_key: str | None,
    gsi: list[dict[str, str]],
) -> None:
    client = ddb.meta.client
    existing = set(client.list_tables().get("TableNames", []))
    if table_name in existing:
        return

    attrs = [{"AttributeName": partition_key, "AttributeType": "S"}]
    if sort_key:
        attrs.append({"AttributeName": sort_key, "AttributeType": "S"})
    for idx in gsi:
        attrs.append({"AttributeName": idx["partition_key"], "AttributeType": "S"})
        if idx.get("sort_key"):
            attrs.append({"AttributeName": idx["sort_key"], "AttributeType": "S"})

    dedup = []
    seen = set()
    for a in attrs:
        k = a["AttributeName"]
        if k in seen:
            continue
        seen.add(k)
        dedup.append(a)

    client.create_table(
        TableName=table_name,
        AttributeDefinitions=dedup,
        KeySchema=[
            {"AttributeName": partition_key, "KeyType": "HASH"},
            *([{"AttributeName": sort_key, "KeyType": "RANGE"}] if sort_key else []),
        ],
        BillingMode="PAY_PER_REQUEST",
        GlobalSecondaryIndexes=[
            {
                "IndexName": idx["index_name"],
                "KeySchema": [
                    {"AttributeName": idx["partition_key"], "KeyType": "HASH"},
                    *([{"AttributeName": idx["sort_key"], "KeyType": "RANGE"}] if idx.get("sort_key") else []),
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
            for idx in gsi
        ],
    )


def migrate() -> None:
    _ensure_table(
        table_name=S.moderation_actions_table_name,
        partition_key="action_id",
        sort_key=None,
        gsi=[
            {"index_name": "ByTicketCreatedAt", "partition_key": "ticket_id", "sort_key": "created_at"},
            {"index_name": "ByActionTypeCreatedAt", "partition_key": "action_type", "sort_key": "created_at"},
            {"index_name": "ByTargetUserCreatedAt", "partition_key": "target_user_id", "sort_key": "created_at"},
        ],
    )
    _ensure_table(
        table_name=S.user_enforcement_history_table_name,
        partition_key="user_id",
        sort_key="enforcement_id",
        gsi=[
            {"index_name": "ByStatusCreatedAt", "partition_key": "status", "sort_key": "created_at"},
            {"index_name": "BySourceTicketCreatedAt", "partition_key": "source_ticket_id", "sort_key": "created_at"},
        ],
    )


if __name__ == "__main__":
    migrate()
    print("moderation actions + enforcement history schema migration complete")
