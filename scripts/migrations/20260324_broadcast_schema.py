#!/usr/bin/env python3
from __future__ import annotations

from app.core.aws import ddb
from app.core.settings import S


def _ensure_profiles_table() -> None:
    client = ddb.meta.client
    table_name = S.broadcast_profiles_table_name
    if table_name in set(client.list_tables().get("TableNames", [])):
        _ensure_missing_gsis(
            table_name,
            [
                ("ByCreatorCreatedAt", "created_by", "created_at"),
                ("ByRegionName", "region", "name"),
            ],
        )
        return

    client.create_table(
        TableName=table_name,
        AttributeDefinitions=[
            {"AttributeName": "profile_id", "AttributeType": "S"},
            {"AttributeName": "created_by", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "S"},
            {"AttributeName": "region", "AttributeType": "S"},
            {"AttributeName": "name", "AttributeType": "S"},
        ],
        KeySchema=[{"AttributeName": "profile_id", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByCreatorCreatedAt",
                "KeySchema": [
                    {"AttributeName": "created_by", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByRegionName",
                "KeySchema": [
                    {"AttributeName": "region", "KeyType": "HASH"},
                    {"AttributeName": "name", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
    )


def _ensure_sessions_table() -> None:
    client = ddb.meta.client
    table_name = S.broadcast_sessions_table_name
    if table_name in set(client.list_tables().get("TableNames", [])):
        _ensure_missing_gsis(
            table_name,
            [
                ("ByStatusCreatedAt", "status", "created_at"),
                ("ByCreatorCreatedAt", "created_by", "created_at"),
                ("ByProfileCreatedAt", "profile_id", "created_at"),
            ],
        )
        return

    client.create_table(
        TableName=table_name,
        AttributeDefinitions=[
            {"AttributeName": "session_id", "AttributeType": "S"},
            {"AttributeName": "status", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "S"},
            {"AttributeName": "created_by", "AttributeType": "S"},
            {"AttributeName": "profile_id", "AttributeType": "S"},
        ],
        KeySchema=[{"AttributeName": "session_id", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByStatusCreatedAt",
                "KeySchema": [
                    {"AttributeName": "status", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByCreatorCreatedAt",
                "KeySchema": [
                    {"AttributeName": "created_by", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByProfileCreatedAt",
                "KeySchema": [
                    {"AttributeName": "profile_id", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
    )


def _ensure_outputs_table() -> None:
    client = ddb.meta.client
    table_name = S.broadcast_outputs_table_name
    if table_name in set(client.list_tables().get("TableNames", [])):
        _ensure_missing_gsis(
            table_name,
            [
                ("ByUpdatedAt", "scope", "updated_at"),
            ],
        )
        return

    client.create_table(
        TableName=table_name,
        AttributeDefinitions=[
            {"AttributeName": "session_id", "AttributeType": "S"},
            {"AttributeName": "scope", "AttributeType": "S"},
            {"AttributeName": "updated_at", "AttributeType": "S"},
        ],
        KeySchema=[{"AttributeName": "session_id", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByUpdatedAt",
                "KeySchema": [
                    {"AttributeName": "scope", "KeyType": "HASH"},
                    {"AttributeName": "updated_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
    )


def _ensure_missing_gsis(table_name: str, defs: list[tuple[str, str, str]]) -> None:
    client = ddb.meta.client
    desc = client.describe_table(TableName=table_name).get("Table", {})
    existing_indexes = {idx.get("IndexName") for idx in desc.get("GlobalSecondaryIndexes", [])}
    existing_attributes = {attr.get("AttributeName") for attr in desc.get("AttributeDefinitions", [])}
    for index_name, pk, sk in defs:
        if index_name in existing_indexes:
            continue
        attr_defs = []
        for attr_name in (pk, sk):
            if attr_name not in existing_attributes:
                attr_defs.append({"AttributeName": attr_name, "AttributeType": "S"})
        kwargs = {
            "TableName": table_name,
            "GlobalSecondaryIndexUpdates": [
                {
                    "Create": {
                        "IndexName": index_name,
                        "KeySchema": [
                            {"AttributeName": pk, "KeyType": "HASH"},
                            {"AttributeName": sk, "KeyType": "RANGE"},
                        ],
                        "Projection": {"ProjectionType": "ALL"},
                    }
                }
            ],
        }
        if attr_defs:
            kwargs["AttributeDefinitions"] = attr_defs
        client.update_table(**kwargs)
        waiter = client.get_waiter("table_exists")
        waiter.wait(TableName=table_name)


def migrate() -> None:
    _ensure_profiles_table()
    _ensure_sessions_table()
    _ensure_outputs_table()


if __name__ == "__main__":
    migrate()
    print("broadcast schema migration complete")
