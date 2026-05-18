#!/usr/bin/env python3
from __future__ import annotations

import argparse

from app.core.aws import ddb
from app.core.settings import S


def _existing_tables() -> set[str]:
    return set(ddb.meta.client.list_tables().get("TableNames", []))


def _create_calendar_connections_table() -> None:
    client = ddb.meta.client
    if S.calendar_connections_table_name in _existing_tables():
        return

    client.create_table(
        TableName=S.calendar_connections_table_name,
        AttributeDefinitions=[
            {"AttributeName": "connection_id", "AttributeType": "S"},
            {"AttributeName": "user_provider_key", "AttributeType": "S"},
            {"AttributeName": "status_key", "AttributeType": "S"},
            {"AttributeName": "updated_at", "AttributeType": "S"},
        ],
        KeySchema=[
            {"AttributeName": "connection_id", "KeyType": "HASH"},
        ],
        BillingMode="PAY_PER_REQUEST",
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByUserProviderUpdatedAt",
                "KeySchema": [
                    {"AttributeName": "user_provider_key", "KeyType": "HASH"},
                    {"AttributeName": "updated_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByStatusUpdatedAt",
                "KeySchema": [
                    {"AttributeName": "status_key", "KeyType": "HASH"},
                    {"AttributeName": "updated_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
    )


def _create_external_calendars_table() -> None:
    client = ddb.meta.client
    if S.external_calendars_table_name in _existing_tables():
        return

    client.create_table(
        TableName=S.external_calendars_table_name,
        AttributeDefinitions=[
            {"AttributeName": "external_calendar_id", "AttributeType": "S"},
            {"AttributeName": "connection_id", "AttributeType": "S"},
            {"AttributeName": "updated_at", "AttributeType": "S"},
        ],
        KeySchema=[
            {"AttributeName": "external_calendar_id", "KeyType": "HASH"},
        ],
        BillingMode="PAY_PER_REQUEST",
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByConnectionUpdatedAt",
                "KeySchema": [
                    {"AttributeName": "connection_id", "KeyType": "HASH"},
                    {"AttributeName": "updated_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
    )


def _create_external_event_links_table() -> None:
    client = ddb.meta.client
    if S.external_event_links_table_name in _existing_tables():
        return

    client.create_table(
        TableName=S.external_event_links_table_name,
        AttributeDefinitions=[
            {"AttributeName": "connection_uid_key", "AttributeType": "S"},
            {"AttributeName": "internal_event_id", "AttributeType": "S"},
            {"AttributeName": "updated_at", "AttributeType": "S"},
        ],
        KeySchema=[
            {"AttributeName": "connection_uid_key", "KeyType": "HASH"},
        ],
        BillingMode="PAY_PER_REQUEST",
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByInternalEventUpdatedAt",
                "KeySchema": [
                    {"AttributeName": "internal_event_id", "KeyType": "HASH"},
                    {"AttributeName": "updated_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
    )


def _create_calendar_sync_runs_table() -> None:
    client = ddb.meta.client
    if S.calendar_sync_runs_table_name in _existing_tables():
        return

    client.create_table(
        TableName=S.calendar_sync_runs_table_name,
        AttributeDefinitions=[
            {"AttributeName": "run_id", "AttributeType": "S"},
            {"AttributeName": "connection_id", "AttributeType": "S"},
            {"AttributeName": "status_key", "AttributeType": "S"},
            {"AttributeName": "started_at", "AttributeType": "S"},
        ],
        KeySchema=[
            {"AttributeName": "run_id", "KeyType": "HASH"},
        ],
        BillingMode="PAY_PER_REQUEST",
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByConnectionStartedAt",
                "KeySchema": [
                    {"AttributeName": "connection_id", "KeyType": "HASH"},
                    {"AttributeName": "started_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByStatusStartedAt",
                "KeySchema": [
                    {"AttributeName": "status_key", "KeyType": "HASH"},
                    {"AttributeName": "started_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
    )


def migrate() -> None:
    _create_calendar_connections_table()
    _create_external_calendars_table()
    _create_external_event_links_table()
    _create_calendar_sync_runs_table()


def rollback() -> None:
    client = ddb.meta.client
    existing = _existing_tables()
    for table_name in (
        S.calendar_sync_runs_table_name,
        S.external_event_links_table_name,
        S.external_calendars_table_name,
        S.calendar_connections_table_name,
    ):
        if table_name in existing:
            client.delete_table(TableName=table_name)


def main() -> None:
    parser = argparse.ArgumentParser(description="Calendar integration schema migration")
    parser.add_argument("--rollback", action="store_true", help="Drop tables created by this migration")
    args = parser.parse_args()

    if args.rollback:
        rollback()
        print("calendar integration schema rollback complete")
        return

    migrate()
    print("calendar integration schema migration complete")


if __name__ == "__main__":
    main()
