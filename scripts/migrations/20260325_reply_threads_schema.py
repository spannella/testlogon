#!/usr/bin/env python3
from __future__ import annotations

import os
import time

from botocore.exceptions import ClientError

from app.core.aws import ddb
from app.core.settings import S
from app.services.messaging_thread_contract import (
    INDEX_BY_CONVERSATION_CREATED_AT,
    INDEX_BY_PARENT_MESSAGE_ID,
    INDEX_BY_ROOT_MESSAGE,
    INDEX_BY_THREAD_CREATED_AT,
    INDEX_BY_THREAD_ROOT_MESSAGE_ID,
    MESSAGE_FIELD_PARENT_ID,
    MESSAGE_FIELD_THREAD_ID,
    MESSAGE_FIELD_THREAD_ROOT_ID,
    THREAD_FIELD_CONVERSATION_ID,
    THREAD_FIELD_CREATED_AT,
    THREAD_FIELD_ID,
    THREAD_FIELD_ROOT_MESSAGE_ID,
)


def _ensure_threads_table() -> None:
    client = ddb.meta.client
    table_name = S.message_threads_table_name
    existing = set(client.list_tables().get("TableNames", []))
    if table_name in existing:
        return

    client.create_table(
        TableName=table_name,
        AttributeDefinitions=[
            {"AttributeName": THREAD_FIELD_ID, "AttributeType": "S"},
            {"AttributeName": THREAD_FIELD_CONVERSATION_ID, "AttributeType": "S"},
            {"AttributeName": THREAD_FIELD_CREATED_AT, "AttributeType": "N"},
            {"AttributeName": THREAD_FIELD_ROOT_MESSAGE_ID, "AttributeType": "S"},
        ],
        KeySchema=[{"AttributeName": THREAD_FIELD_ID, "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        GlobalSecondaryIndexes=[
            {
                "IndexName": INDEX_BY_CONVERSATION_CREATED_AT,
                "KeySchema": [
                    {"AttributeName": THREAD_FIELD_CONVERSATION_ID, "KeyType": "HASH"},
                    {"AttributeName": THREAD_FIELD_CREATED_AT, "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": INDEX_BY_ROOT_MESSAGE,
                "KeySchema": [{"AttributeName": THREAD_FIELD_ROOT_MESSAGE_ID, "KeyType": "HASH"}],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
    )
    _wait_for_table_active(client, table_name)


def _wait_for_table_active(client, table_name: str, *, timeout_seconds: int = 90) -> None:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        status = (
            client.describe_table(TableName=table_name)
            .get("Table", {})
            .get("TableStatus")
        )
        if status == "ACTIVE":
            return
        time.sleep(0.5)
    raise RuntimeError(f"Timed out waiting for table to become ACTIVE: {table_name}")


def _ensure_messages_indexes() -> None:
    client = ddb.meta.client
    table_name = os.getenv("DDB_MESSAGES", "Messages")

    desired = [
        (INDEX_BY_CONVERSATION_CREATED_AT, "conversation_id", "created_at"),
        (INDEX_BY_PARENT_MESSAGE_ID, MESSAGE_FIELD_PARENT_ID, None),
        (INDEX_BY_THREAD_CREATED_AT, MESSAGE_FIELD_THREAD_ID, "created_at"),
        (INDEX_BY_THREAD_ROOT_MESSAGE_ID, MESSAGE_FIELD_THREAD_ROOT_ID, None),
    ]
    for index_name, hash_key, range_key in desired:
        table = client.describe_table(TableName=table_name).get("Table", {})
        existing_indexes = {idx.get("IndexName") for idx in table.get("GlobalSecondaryIndexes", [])}
        existing_attrs = {attr.get("AttributeName") for attr in table.get("AttributeDefinitions", [])}
        if index_name in existing_indexes:
            continue
        attr_defs = []
        if hash_key not in existing_attrs:
            attr_defs.append({"AttributeName": hash_key, "AttributeType": "S"})
            existing_attrs.add(hash_key)
        if range_key and range_key not in existing_attrs:
            attr_defs.append(
                {
                    "AttributeName": range_key,
                    "AttributeType": "N" if range_key == "created_at" else "S",
                }
            )
            existing_attrs.add(range_key)

        key_schema = [{"AttributeName": hash_key, "KeyType": "HASH"}]
        if range_key:
            key_schema.append({"AttributeName": range_key, "KeyType": "RANGE"})

        update_kwargs = {
            "TableName": table_name,
            "GlobalSecondaryIndexUpdates": [
                {
                    "Create": {
                        "IndexName": index_name,
                        "KeySchema": key_schema,
                        "Projection": {"ProjectionType": "ALL"},
                    }
                }
            ],
        }
        if attr_defs:
            update_kwargs["AttributeDefinitions"] = attr_defs
        try:
            client.update_table(**update_kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            message = str(exc.response.get("Error", {}).get("Message", ""))
            already_exists = code == "ValidationException" and (
                "already exists" in message.lower()
                or "duplicate" in message.lower()
            )
            if not already_exists:
                raise
        _wait_for_table_active(client, table_name)


def migrate() -> None:
    _ensure_threads_table()
    _ensure_messages_indexes()


def rollback() -> None:
    client = ddb.meta.client
    threads_table = S.message_threads_table_name
    try:
        client.delete_table(TableName=threads_table)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code != "ResourceNotFoundException":
            raise
    else:
        deadline = time.time() + 90
        while time.time() < deadline:
            try:
                client.describe_table(TableName=threads_table)
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code == "ResourceNotFoundException":
                    return
                raise
            time.sleep(0.5)


if __name__ == "__main__":
    migrate()
    print("reply threads schema migration complete")
