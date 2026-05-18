#!/usr/bin/env python3
"""Provision Jira-related GSIs on the tickets table.

Usage examples:
  python scripts/migrations/20260405_jira_ticket_indexes_migration.py --dry-run
  python scripts/migrations/20260405_jira_ticket_indexes_migration.py --apply

By default the script runs in dry-run mode and only prints planned changes.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class RequiredIndex:
    name: str
    partition_key: str
    sort_key: str


def _required_indexes_from_env() -> list[RequiredIndex]:
    return [
        RequiredIndex(
            name=os.environ.get("TICKETS_JIRA_WORKSPACE_INDEX_NAME", "jira_workspace-updated_at-index"),
            partition_key="gsi_jira_workspace_pk",
            sort_key="gsi_jira_workspace_sk",
        ),
        RequiredIndex(
            name=os.environ.get("TICKETS_JIRA_ISSUE_INDEX_NAME", "jira_issue-index"),
            partition_key="gsi_jira_issue_pk",
            sort_key="gsi_jira_issue_sk",
        ),
        RequiredIndex(
            name=os.environ.get("TICKETS_JIRA_SYNC_STATE_INDEX_NAME", "jira_sync_state-updated_at-index"),
            partition_key="gsi_jira_sync_state_pk",
            sort_key="gsi_jira_sync_state_sk",
        ),
    ]


def _tickets_table_name() -> str:
    return os.environ.get("TICKETS_TABLE_NAME", "tickets")


def _describe_table(ddb_client, *, table_name: str) -> dict:
    return ddb_client.describe_table(TableName=table_name)["Table"]


def _existing_index_names(table_desc: dict) -> set[str]:
    return {idx.get("IndexName", "") for idx in table_desc.get("GlobalSecondaryIndexes", []) if idx.get("IndexName")}


def _wait_until_table_active(ddb_client, *, table_name: str, timeout_seconds: int = 1800) -> None:
    started = time.time()
    while True:
        status = _describe_table(ddb_client, table_name=table_name).get("TableStatus")
        if status == "ACTIVE":
            return
        if (time.time() - started) > timeout_seconds:
            raise TimeoutError(f"Timed out waiting for table {table_name} to become ACTIVE")
        time.sleep(5)


def _create_gsi(ddb_client, *, table_name: str, req: RequiredIndex) -> None:
    ddb_client.update_table(
        TableName=table_name,
        AttributeDefinitions=[
            {"AttributeName": req.partition_key, "AttributeType": "S"},
            {"AttributeName": req.sort_key, "AttributeType": "S"},
        ],
        GlobalSecondaryIndexUpdates=[
            {
                "Create": {
                    "IndexName": req.name,
                    "KeySchema": [
                        {"AttributeName": req.partition_key, "KeyType": "HASH"},
                        {"AttributeName": req.sort_key, "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                    "ProvisionedThroughput": {"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
                }
            }
        ],
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Provision Jira GSIs on tickets table")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true", help="Apply changes")
    mode.add_argument("--dry-run", action="store_true", help="Print planned changes only (default)")
    parser.add_argument("--region", default=os.environ.get("AWS_REGION", "us-east-1"))
    args = parser.parse_args()

    do_apply = bool(args.apply)
    table_name = _tickets_table_name()
    required = _required_indexes_from_env()

    try:
        import boto3
    except ModuleNotFoundError:
        print("ERROR: boto3 is required to run this migration script.", file=sys.stderr)
        return 2

    ddb = boto3.client("dynamodb", region_name=args.region)
    try:
        table_desc = _describe_table(ddb, table_name=table_name)
    except Exception as exc:  # pragma: no cover - operational script
        print(f"ERROR: unable to describe table {table_name}: {exc}", file=sys.stderr)
        return 1

    existing = _existing_index_names(table_desc)
    missing = [idx for idx in required if idx.name not in existing]

    print(f"Tickets table: {table_name}")
    print(f"Region: {args.region}")
    print("Required Jira indexes:")
    for idx in required:
        state = "present" if idx.name in existing else "missing"
        print(f"  - {idx.name} ({idx.partition_key}/{idx.sort_key}) [{state}]")

    if not missing:
        print("No changes needed.")
        return 0

    if not do_apply:
        print("Dry-run mode: indexes would be created for missing entries above.")
        return 0

    print("Applying migration...")
    for idx in missing:
        print(f"Creating index: {idx.name}")
        _create_gsi(ddb, table_name=table_name, req=idx)
        _wait_until_table_active(ddb, table_name=table_name)
        print(f"Index active: {idx.name}")

    print("Migration complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
