#!/usr/bin/env python3
from __future__ import annotations

import os
from typing import Any


def _table_name() -> str:
    from app.core.settings import S

    return S.mass_message_campaigns_table_name


def _ddb_client() -> Any:
    from app.core.aws import ddb

    return ddb.meta.client


def _table_exists(client: Any, table_name: str) -> bool:
    return table_name in set(client.list_tables().get("TableNames", []))


def _create_campaigns_table(client: Any, table_name: str) -> None:
    client.create_table(
        TableName=table_name,
        AttributeDefinitions=[
            {"AttributeName": "campaign_id", "AttributeType": "S"},
            {"AttributeName": "sender_id", "AttributeType": "S"},
            {"AttributeName": "status", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
            {"AttributeName": "send_at", "AttributeType": "N"},
        ],
        KeySchema=[{"AttributeName": "campaign_id", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        GlobalSecondaryIndexes=[
            {
                "IndexName": "BySenderCreatedAt",
                "KeySchema": [
                    {"AttributeName": "sender_id", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByStatusSendAt",
                "KeySchema": [
                    {"AttributeName": "status", "KeyType": "HASH"},
                    {"AttributeName": "send_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
    )


def migrate() -> None:
    client = _ddb_client()
    table_name = _table_name()
    if _table_exists(client, table_name):
        return
    _create_campaigns_table(client, table_name)


def rollback(*, allow_destructive: bool = False) -> None:
    """Drop campaign table in non-production environments.

    Rollback is blocked unless either:
    - `allow_destructive=True` is passed, or
    - `MASS_MESSAGE_MIGRATION_ALLOW_ROLLBACK=1` is set.

    Additionally, rollback is blocked if `APP_ENV` indicates production.
    """

    env = str(os.getenv("APP_ENV", "")).strip().lower()
    if env in {"prod", "production"}:
        raise RuntimeError("rollback blocked in production environment")

    allowed = allow_destructive or os.getenv("MASS_MESSAGE_MIGRATION_ALLOW_ROLLBACK", "0") in {"1", "true", "yes"}
    if not allowed:
        raise RuntimeError("rollback requires explicit opt-in")

    client = _ddb_client()
    table_name = _table_name()
    if not _table_exists(client, table_name):
        return
    client.delete_table(TableName=table_name)


if __name__ == "__main__":
    migrate()
    print("mass message campaigns schema migration complete")
