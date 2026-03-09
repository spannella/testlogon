#!/usr/bin/env python3
from __future__ import annotations

from app.core.aws import ddb
from app.core.settings import S

DEFAULT_STATUS = "open"
DEFAULT_PRIORITY = "medium"
DEFAULT_QUEUE = "general"

TICKET_GSIS = [
    {
        "IndexName": "ByStatusLatestReportAt",
        "PartitionKey": "status",
        "SortKey": "latest_report_at",
    },
    {
        "IndexName": "ByQueueLatestReportAt",
        "PartitionKey": "queue",
        "SortKey": "latest_report_at",
    },
    {
        "IndexName": "ByAssignedAdminLatestReportAt",
        "PartitionKey": "assigned_admin_user_id",
        "SortKey": "latest_report_at",
    },
    {
        "IndexName": "ByLatestReportAt",
        "PartitionKey": "latest_report_scope",
        "SortKey": "latest_report_at",
    },
    {
        "IndexName": "ByContentStatusLatestReportAt",
        "PartitionKey": "content_ref_status",
        "SortKey": "latest_report_at",
    },
]


def _ensure_table() -> None:
    client = ddb.meta.client
    existing = set(client.list_tables().get("TableNames", []))
    if S.moderation_tickets_table_name in existing:
        _ensure_missing_gsis()
        return

    attrs = [{"AttributeName": "ticket_id", "AttributeType": "S"}]
    for gsi in TICKET_GSIS:
        attrs.append({"AttributeName": gsi["PartitionKey"], "AttributeType": "S"})
        attrs.append({"AttributeName": gsi["SortKey"], "AttributeType": "S"})

    # unique while preserving order
    seen = set()
    attr_defs = []
    for item in attrs:
        name = item["AttributeName"]
        if name in seen:
            continue
        seen.add(name)
        attr_defs.append(item)

    client.create_table(
        TableName=S.moderation_tickets_table_name,
        AttributeDefinitions=attr_defs,
        KeySchema=[{"AttributeName": "ticket_id", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        GlobalSecondaryIndexes=[
            {
                "IndexName": gsi["IndexName"],
                "KeySchema": [
                    {"AttributeName": gsi["PartitionKey"], "KeyType": "HASH"},
                    {"AttributeName": gsi["SortKey"], "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
            for gsi in TICKET_GSIS
        ],
    )


def _ensure_missing_gsis() -> None:
    client = ddb.meta.client
    desc = client.describe_table(TableName=S.moderation_tickets_table_name).get("Table", {})
    existing_indexes = {idx.get("IndexName") for idx in desc.get("GlobalSecondaryIndexes", [])}
    existing_attributes = {attr.get("AttributeName") for attr in desc.get("AttributeDefinitions", [])}

    for gsi in TICKET_GSIS:
        if gsi["IndexName"] in existing_indexes:
            continue

        attr_defs = []
        for attr_name in (gsi["PartitionKey"], gsi["SortKey"]):
            if attr_name not in existing_attributes:
                attr_defs.append({"AttributeName": attr_name, "AttributeType": "S"})

        kwargs = {
            "TableName": S.moderation_tickets_table_name,
            "GlobalSecondaryIndexUpdates": [
                {
                    "Create": {
                        "IndexName": gsi["IndexName"],
                        "KeySchema": [
                            {"AttributeName": gsi["PartitionKey"], "KeyType": "HASH"},
                            {"AttributeName": gsi["SortKey"], "KeyType": "RANGE"},
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
        waiter.wait(TableName=S.moderation_tickets_table_name)


def _backfill_defaults() -> None:
    table = ddb.Table(S.moderation_tickets_table_name)
    items = table.scan().get("Items", [])
    for item in items:
        ticket_id = item.get("ticket_id")
        if not ticket_id:
            continue

        content_type = str(item.get("content_type") or "").strip()
        content_id = str(item.get("content_id") or "").strip()
        content_ref = str(item.get("content_ref") or "").strip()

        updates = {}
        if not item.get("status"):
            updates["status"] = DEFAULT_STATUS
        if not item.get("priority"):
            updates["priority"] = DEFAULT_PRIORITY
        if not item.get("queue"):
            updates["queue"] = DEFAULT_QUEUE
        if not item.get("latest_report_at"):
            updates["latest_report_at"] = str(item.get("created_at") or "0")
        if not item.get("latest_report_scope"):
            updates["latest_report_scope"] = "ALL"
        if not content_ref and content_type and content_id:
            content_ref = f"{content_type}#{content_id}"
            updates["content_ref"] = content_ref
        if content_ref and not item.get("content_ref_status"):
            updates["content_ref_status"] = f"{content_ref}#{str(item.get('status') or DEFAULT_STATUS)}"

        if not updates:
            continue

        names = {}
        values = {}
        expr = []
        for i, (k, v) in enumerate(updates.items(), start=1):
            nk = f"#k{i}"
            vk = f":v{i}"
            names[nk] = k
            values[vk] = v
            expr.append(f"{nk} = {vk}")

        table.update_item(
            Key={"ticket_id": ticket_id},
            UpdateExpression="SET " + ", ".join(expr),
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=values,
        )


def migrate() -> None:
    _ensure_table()
    _backfill_defaults()


if __name__ == "__main__":
    migrate()
    print("moderation_tickets schema migration complete")
