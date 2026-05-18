#!/usr/bin/env python3
from __future__ import annotations

import sys
from typing import Any

ddb: Any | None = None
S: Any | None = None


def _deps() -> tuple[Any, Any]:
    global ddb, S
    if ddb is None or S is None:
        from app.core.aws import ddb as aws_ddb
        from app.core.settings import S as settings

        ddb = aws_ddb
        S = settings
    return ddb, S


def _ensure_table(table_name: str, *, attrs: list[dict[str, str]], key_schema: list[dict[str, str]], gsis: list[dict] | None = None) -> None:
    ddb_client, _ = _deps()
    client = ddb_client.meta.client
    existing = set(client.list_tables().get("TableNames", []))
    if table_name not in existing:
        kwargs = {
            "TableName": table_name,
            "AttributeDefinitions": attrs,
            "KeySchema": key_schema,
            "BillingMode": "PAY_PER_REQUEST",
        }
        if gsis:
            kwargs["GlobalSecondaryIndexes"] = gsis
        client.create_table(**kwargs)
        return
    if gsis:
        _ensure_missing_gsis(table_name=table_name, desired_gsis=gsis, desired_attrs=attrs)


def _ensure_missing_gsis(*, table_name: str, desired_gsis: list[dict], desired_attrs: list[dict[str, str]]) -> None:
    ddb_client, _ = _deps()
    client = ddb_client.meta.client
    desc = client.describe_table(TableName=table_name).get("Table", {})
    existing_indexes = {idx.get("IndexName") for idx in desc.get("GlobalSecondaryIndexes", [])}
    existing_attrs = {attr.get("AttributeName") for attr in desc.get("AttributeDefinitions", [])}

    attrs_by_name = {item["AttributeName"]: item for item in desired_attrs}

    for gsi in desired_gsis:
        name = gsi.get("IndexName")
        if name in existing_indexes:
            continue

        key_names = [k["AttributeName"] for k in gsi.get("KeySchema", [])]
        new_attrs = [attrs_by_name[n] for n in key_names if n not in existing_attrs and n in attrs_by_name]

        kwargs = {
            "TableName": table_name,
            "GlobalSecondaryIndexUpdates": [{"Create": gsi}],
        }
        if new_attrs:
            kwargs["AttributeDefinitions"] = new_attrs

        client.update_table(**kwargs)
        waiter = client.get_waiter("table_exists")
        waiter.wait(TableName=table_name)


def migrate() -> None:
    _, settings = _deps()
    _ensure_table(
        settings.payment_incidents_table_name,
        attrs=[
            {"AttributeName": "incident_id", "AttributeType": "S"},
            {"AttributeName": "provider_incident_key", "AttributeType": "S"},
            {"AttributeName": "updated_at", "AttributeType": "S"},
            {"AttributeName": "customer_id", "AttributeType": "S"},
            {"AttributeName": "response_due_scope", "AttributeType": "S"},
            {"AttributeName": "response_due_at", "AttributeType": "S"},
        ],
        key_schema=[{"AttributeName": "incident_id", "KeyType": "HASH"}],
        gsis=[
            {
                "IndexName": "ByProviderIncidentUpdatedAt",
                "KeySchema": [
                    {"AttributeName": "provider_incident_key", "KeyType": "HASH"},
                    {"AttributeName": "updated_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByCustomerUpdatedAt",
                "KeySchema": [
                    {"AttributeName": "customer_id", "KeyType": "HASH"},
                    {"AttributeName": "updated_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByResponseDueAt",
                "KeySchema": [
                    {"AttributeName": "response_due_scope", "KeyType": "HASH"},
                    {"AttributeName": "response_due_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
    )

    _ensure_table(
        settings.payment_incident_events_table_name,
        attrs=[
            {"AttributeName": "incident_id", "AttributeType": "S"},
            {"AttributeName": "event_ts_id", "AttributeType": "S"},
        ],
        key_schema=[
            {"AttributeName": "incident_id", "KeyType": "HASH"},
            {"AttributeName": "event_ts_id", "KeyType": "RANGE"},
        ],
    )

    _ensure_table(
        settings.payment_dispute_evidence_table_name,
        attrs=[
            {"AttributeName": "incident_id", "AttributeType": "S"},
            {"AttributeName": "version", "AttributeType": "S"},
        ],
        key_schema=[
            {"AttributeName": "incident_id", "KeyType": "HASH"},
            {"AttributeName": "version", "KeyType": "RANGE"},
        ],
    )

    _ensure_table(
        settings.payment_retry_attempts_table_name,
        attrs=[
            {"AttributeName": "incident_id", "AttributeType": "S"},
            {"AttributeName": "attempt_id", "AttributeType": "S"},
        ],
        key_schema=[
            {"AttributeName": "incident_id", "KeyType": "HASH"},
            {"AttributeName": "attempt_id", "KeyType": "RANGE"},
        ],
    )

    _ensure_table(
        settings.payment_incident_ticket_links_table_name,
        attrs=[
            {"AttributeName": "incident_id", "AttributeType": "S"},
            {"AttributeName": "ticket_id", "AttributeType": "S"},
        ],
        key_schema=[{"AttributeName": "incident_id", "KeyType": "HASH"}],
        gsis=[
            {
                "IndexName": "ByTicketId",
                "KeySchema": [{"AttributeName": "ticket_id", "KeyType": "HASH"}],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
    )


def rollback() -> None:
    ddb_client, settings = _deps()
    client = ddb_client.meta.client
    names = [
        settings.payment_incident_ticket_links_table_name,
        settings.payment_retry_attempts_table_name,
        settings.payment_dispute_evidence_table_name,
        settings.payment_incident_events_table_name,
        settings.payment_incidents_table_name,
    ]
    existing = set(client.list_tables().get("TableNames", []))
    for table_name in names:
        if table_name not in existing:
            continue
        client.delete_table(TableName=table_name)
        waiter = client.get_waiter("table_not_exists")
        waiter.wait(TableName=table_name)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1].strip().lower() in {"down", "rollback"}:
        rollback()
        print("payment incident schema rollback complete")
    else:
        migrate()
        print("payment incident schema migration complete")
