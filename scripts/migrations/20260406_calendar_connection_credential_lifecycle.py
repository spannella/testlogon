#!/usr/bin/env python3
from __future__ import annotations

import argparse
import uuid

from app.core.aws import ddb
from app.core.settings import S

REQUIRED_CONNECTION_COLUMNS = (
    "credential_ref",
    "credential_validation_status",
    "credential_last_validated_at",
    "credential_rotated_at",
)

LEGACY_SECRET_COLUMNS = (
    "credential_ct_b64",
    "app_specific_password",
    "password",
    "secret",
    "secret_ct_b64",
)


def _ensure_secret_table() -> None:
    client = ddb.meta.client
    existing = set(client.list_tables().get("TableNames", []))
    if S.calendar_connection_secrets_table_name in existing:
        return

    client.create_table(
        TableName=S.calendar_connection_secrets_table_name,
        AttributeDefinitions=[
            {"AttributeName": "credential_ref", "AttributeType": "S"},
            {"AttributeName": "provider", "AttributeType": "S"},
            {"AttributeName": "updated_at", "AttributeType": "S"},
        ],
        KeySchema=[
            {"AttributeName": "credential_ref", "KeyType": "HASH"},
        ],
        BillingMode="PAY_PER_REQUEST",
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByProviderUpdatedAt",
                "KeySchema": [
                    {"AttributeName": "provider", "KeyType": "HASH"},
                    {"AttributeName": "updated_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
    )


def _backfill_connection_lifecycle_fields() -> None:
    connections = ddb.Table(S.calendar_connections_table_name)
    secrets = ddb.Table(S.calendar_connection_secrets_table_name)

    items = connections.scan().get("Items", [])
    for item in items:
        updates: dict[str, object] = {}
        remove_columns: list[str] = []

        now = str(item.get("updated_at") or item.get("created_at") or "")
        provider = str(item.get("provider") or "apple_caldav")

        credential_ref = str(item.get("credential_ref") or "").strip()
        if not credential_ref:
            credential_ref = f"cred_{uuid.uuid4().hex}"
            updates["credential_ref"] = credential_ref

        if not item.get("credential_validation_status"):
            updates["credential_validation_status"] = "unknown"
        if "credential_last_validated_at" not in item:
            updates["credential_last_validated_at"] = None
        if "credential_rotated_at" not in item:
            updates["credential_rotated_at"] = None

        # Move encrypted legacy payload out of the connection row into the secrets table.
        legacy_ciphertext = str(item.get("credential_ct_b64") or "").strip()
        if legacy_ciphertext:
            secrets.put_item(
                Item={
                    "credential_ref": credential_ref,
                    "provider": provider,
                    "secret_ct_b64": legacy_ciphertext,
                    "created_at": str(item.get("created_at") or now),
                    "updated_at": now,
                }
            )
            if not item.get("credential_rotated_at"):
                updates["credential_rotated_at"] = now or None

        for column in LEGACY_SECRET_COLUMNS:
            if column in item:
                remove_columns.append(column)

        if not updates and not remove_columns:
            continue

        expr_names: dict[str, str] = {}
        expr_values: dict[str, object] = {}
        set_parts: list[str] = []

        idx = 0
        for key, value in updates.items():
            idx += 1
            nk = f"#k{idx}"
            vk = f":v{idx}"
            expr_names[nk] = key
            expr_values[vk] = value
            set_parts.append(f"{nk} = {vk}")

        update_expr = []
        if set_parts:
            update_expr.append("SET " + ", ".join(set_parts))

        if remove_columns:
            remove_parts: list[str] = []
            for column in remove_columns:
                idx += 1
                nk = f"#k{idx}"
                expr_names[nk] = column
                remove_parts.append(nk)
            update_expr.append("REMOVE " + ", ".join(remove_parts))

        kwargs = {
            "Key": {"connection_id": item["connection_id"]},
            "UpdateExpression": " ".join(update_expr),
            "ExpressionAttributeNames": expr_names,
        }
        if expr_values:
            kwargs["ExpressionAttributeValues"] = expr_values
        connections.update_item(**kwargs)


def migrate() -> None:
    _ensure_secret_table()
    _backfill_connection_lifecycle_fields()


def rollback() -> None:
    client = ddb.meta.client
    existing = set(client.list_tables().get("TableNames", []))
    if S.calendar_connection_secrets_table_name in existing:
        client.delete_table(TableName=S.calendar_connection_secrets_table_name)


def main() -> None:
    parser = argparse.ArgumentParser(description="Calendar connection credential lifecycle migration")
    parser.add_argument("--rollback", action="store_true", help="Drop secret reference table created by migration")
    args = parser.parse_args()

    if args.rollback:
        rollback()
        print("calendar connection credential lifecycle rollback complete")
        return

    migrate()
    print("calendar connection credential lifecycle migration complete")


if __name__ == "__main__":
    main()
