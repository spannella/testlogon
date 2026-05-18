#!/usr/bin/env python3
from __future__ import annotations

from app.core.aws import ddb
from app.core.settings import S


def migrate() -> None:
    table_name = S.filemgr_mounts_table_name
    if not table_name:
        raise RuntimeError("FILEMGR_MOUNTS_TABLE_NAME is not configured")

    client = ddb.meta.client
    existing = set(client.list_tables().get("TableNames", []))
    if table_name in existing:
        return

    client.create_table(
        TableName=table_name,
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "gsi_owner_pk", "AttributeType": "S"},
            {"AttributeName": "gsi_owner_sk", "AttributeType": "S"},
        ],
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        BillingMode="PAY_PER_REQUEST",
        GlobalSecondaryIndexes=[
            {
                "IndexName": "GSI1",
                "KeySchema": [
                    {"AttributeName": "gsi_owner_pk", "KeyType": "HASH"},
                    {"AttributeName": "gsi_owner_sk", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
    )


if __name__ == "__main__":
    migrate()
    print("file manager mounts schema migration complete")
