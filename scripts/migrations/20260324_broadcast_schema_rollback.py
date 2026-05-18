#!/usr/bin/env python3
from __future__ import annotations

from app.core.aws import ddb
from app.core.settings import S


def _delete_if_exists(table_name: str) -> None:
    client = ddb.meta.client
    existing = set(client.list_tables().get("TableNames", []))
    if table_name not in existing:
        return
    client.delete_table(TableName=table_name)
    waiter = client.get_waiter("table_not_exists")
    waiter.wait(TableName=table_name)


def rollback() -> None:
    # Delete leaf dependency first; independent tables can be deleted in any order.
    _delete_if_exists(S.broadcast_outputs_table_name)
    _delete_if_exists(S.broadcast_sessions_table_name)
    _delete_if_exists(S.broadcast_profiles_table_name)


if __name__ == "__main__":
    rollback()
    print("broadcast schema rollback complete")
