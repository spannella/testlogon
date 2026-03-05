#!/usr/bin/env python3
from __future__ import annotations

from app.core.aws import ddb
from app.core.settings import S


def _ensure_table() -> None:
    client = ddb.meta.client
    existing = set(client.list_tables().get("TableNames", []))
    if S.questionnaire_table_name not in existing:
        client.create_table(
            TableName=S.questionnaire_table_name,
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "gsi_owner_pk", "AttributeType": "S"},
                {"AttributeName": "gsi_owner_sk", "AttributeType": "S"},
                {"AttributeName": "gsi_status_pk", "AttributeType": "S"},
                {"AttributeName": "gsi_status_sk", "AttributeType": "S"},
                {"AttributeName": "gsi_published_pk", "AttributeType": "S"},
                {"AttributeName": "gsi_published_sk", "AttributeType": "S"},
                {"AttributeName": "gsi_response_status_pk", "AttributeType": "S"},
                {"AttributeName": "gsi_response_status_sk", "AttributeType": "S"},
            ],
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            BillingMode="PAY_PER_REQUEST",
            GlobalSecondaryIndexes=[
                {
                    "IndexName": S.questionnaire_owner_index_name,
                    "KeySchema": [
                        {"AttributeName": "gsi_owner_pk", "KeyType": "HASH"},
                        {"AttributeName": "gsi_owner_sk", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
                {
                    "IndexName": S.questionnaire_status_index_name,
                    "KeySchema": [
                        {"AttributeName": "gsi_status_pk", "KeyType": "HASH"},
                        {"AttributeName": "gsi_status_sk", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
                {
                    "IndexName": S.questionnaire_published_index_name,
                    "KeySchema": [
                        {"AttributeName": "gsi_published_pk", "KeyType": "HASH"},
                        {"AttributeName": "gsi_published_sk", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
                {
                    "IndexName": S.questionnaire_response_status_index_name,
                    "KeySchema": [
                        {"AttributeName": "gsi_response_status_pk", "KeyType": "HASH"},
                        {"AttributeName": "gsi_response_status_sk", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
            ],
        )


def _derive_index_attributes(item: dict) -> dict:
    updates: dict[str, str] = {}
    entity_type = item.get("entity_type")
    if entity_type == "questionnaire":
        owner_id = item.get("owner_id")
        status = item.get("status")
        updated_at = item.get("updated_at")
        questionnaire_id = item.get("questionnaire_id")
        if owner_id and updated_at and questionnaire_id:
            updates["gsi_owner_pk"] = f"OWNER#{owner_id}"
            updates["gsi_owner_sk"] = f"UPDATED#{updated_at}#{questionnaire_id}"
        if status and updated_at and questionnaire_id:
            updates["gsi_status_pk"] = f"STATUS#{status}"
            updates["gsi_status_sk"] = f"UPDATED#{updated_at}#{questionnaire_id}"
    elif entity_type == "questionnaire_version":
        slug = item.get("published_slug")
        version_number = item.get("version_number")
        if slug and version_number is not None:
            updates["gsi_published_pk"] = f"PUBLISHED#{slug}"
            updates["gsi_published_sk"] = f"VERSION#{int(version_number):06d}"
    elif entity_type == "response_session":
        status = item.get("status")
        updated = item.get("submitted_at") or item.get("started_at")
        response_session_id = item.get("response_session_id")
        if status and updated and response_session_id:
            updates["gsi_response_status_pk"] = f"RESPONSE_STATUS#{status}"
            updates["gsi_response_status_sk"] = f"UPDATED#{updated}#{response_session_id}"
    return updates


def migrate() -> None:
    _ensure_table()
    table = ddb.Table(S.questionnaire_table_name)
    items = table.scan().get("Items", [])
    for item in items:
        updates = _derive_index_attributes(item)
        if not updates:
            continue
        update_expr = []
        attr_names = {}
        attr_values = {}
        for idx, (k, v) in enumerate(updates.items(), start=1):
            name_key = f"#k{idx}"
            value_key = f":v{idx}"
            attr_names[name_key] = k
            attr_values[value_key] = v
            update_expr.append(f"{name_key} = {value_key}")
        table.update_item(
            Key={"pk": item["pk"], "sk": item["sk"]},
            UpdateExpression="SET " + ", ".join(update_expr),
            ExpressionAttributeNames=attr_names,
            ExpressionAttributeValues=attr_values,
        )


if __name__ == "__main__":
    migrate()
    print("questionnaire schema migration complete")
