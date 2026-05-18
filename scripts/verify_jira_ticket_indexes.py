#!/usr/bin/env python3
"""Verify Jira-related GSIs exist on the tickets table.

Exits non-zero if any required Jira index is missing.
"""

from __future__ import annotations

import os
import sys


def _required_indexes() -> list[str]:
    return [
        os.environ.get("TICKETS_JIRA_WORKSPACE_INDEX_NAME", "jira_workspace-updated_at-index"),
        os.environ.get("TICKETS_JIRA_ISSUE_INDEX_NAME", "jira_issue-index"),
        os.environ.get("TICKETS_JIRA_SYNC_STATE_INDEX_NAME", "jira_sync_state-updated_at-index"),
    ]


def main() -> int:
    table_name = os.environ.get("TICKETS_TABLE_NAME", "tickets")
    region = os.environ.get("AWS_REGION", "us-east-1")

    try:
        import boto3
    except ModuleNotFoundError:
        print("ERROR: boto3 is required to run index verification.", file=sys.stderr)
        return 2

    ddb = boto3.client("dynamodb", region_name=region)
    try:
        desc = ddb.describe_table(TableName=table_name)["Table"]
    except Exception as exc:  # pragma: no cover - operational script
        print(f"ERROR: unable to describe {table_name}: {exc}", file=sys.stderr)
        return 1

    existing = {idx.get("IndexName", "") for idx in desc.get("GlobalSecondaryIndexes", []) if idx.get("IndexName")}
    required = _required_indexes()
    missing = [name for name in required if name not in existing]

    print(f"Table: {table_name}")
    print(f"Region: {region}")
    print("Required Jira indexes:")
    for name in required:
        print(f"  - {name}: {'OK' if name in existing else 'MISSING'}")

    if missing:
        print("Verification failed. Missing indexes:", ", ".join(missing), file=sys.stderr)
        return 1

    print("Verification passed. All Jira indexes are present.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
