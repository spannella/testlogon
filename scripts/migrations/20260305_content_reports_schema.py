#!/usr/bin/env python3
from __future__ import annotations

from botocore.exceptions import ClientError

from app.core.aws import ddb
from app.core.settings import S

ALLOWED_TOPICS = ("sexual", "extortion", "criminal", "spam", "racist")


def _ensure_table() -> None:
    client = ddb.meta.client
    existing = set(client.list_tables().get("TableNames", []))
    if S.content_reports_table_name in existing:
        return

    client.create_table(
        TableName=S.content_reports_table_name,
        AttributeDefinitions=[
            {"AttributeName": "report_id", "AttributeType": "S"},
            {"AttributeName": "content_ref", "AttributeType": "S"},
            {"AttributeName": "reporter_user_id", "AttributeType": "S"},
            {"AttributeName": "created_scope", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "S"},
        ],
        KeySchema=[
            {"AttributeName": "report_id", "KeyType": "HASH"},
        ],
        BillingMode="PAY_PER_REQUEST",
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByContentCreatedAt",
                "KeySchema": [
                    {"AttributeName": "content_ref", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByReporterCreatedAt",
                "KeySchema": [
                    {"AttributeName": "reporter_user_id", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByCreatedAt",
                "KeySchema": [
                    {"AttributeName": "created_scope", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
    )


def _seed_topic_constraints() -> None:
    """Seed allowed-topic sentinel rows used for DB-level condition checks in transact writes."""
    table = ddb.Table(S.content_reports_table_name)
    for topic in ALLOWED_TOPICS:
        try:
            table.put_item(
                Item={
                    "report_id": f"TOPIC#{topic}",
                    "entity_type": "content_report_topic",
                    "topic": topic,
                },
                ConditionExpression="attribute_not_exists(report_id)",
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "ConditionalCheckFailedException":
                raise


def _backfill_index_attributes() -> None:
    table = ddb.Table(S.content_reports_table_name)
    items = table.scan().get("Items", [])
    for item in items:
        if item.get("entity_type") == "content_report_topic":
            continue
        content_type = item.get("content_type")
        content_id = item.get("content_id")
        created_at = item.get("created_at")
        if not content_type or not content_id or not created_at:
            continue

        updates = {
            "content_ref": f"{content_type}#{content_id}",
            "created_scope": "ALL",
        }

        update_expr = []
        attr_names = {}
        attr_values = {}
        for idx, (k, v) in enumerate(updates.items(), start=1):
            nk = f"#k{idx}"
            vk = f":v{idx}"
            attr_names[nk] = k
            attr_values[vk] = v
            update_expr.append(f"{nk} = {vk}")

        table.update_item(
            Key={"report_id": item["report_id"]},
            UpdateExpression="SET " + ", ".join(update_expr),
            ExpressionAttributeNames=attr_names,
            ExpressionAttributeValues=attr_values,
        )


def migrate() -> None:
    _ensure_table()
    _seed_topic_constraints()
    _backfill_index_attributes()


if __name__ == "__main__":
    migrate()
    print("content_reports schema migration complete")
