#!/usr/bin/env python3
from __future__ import annotations

import os
import time
from typing import Dict, List

from botocore.exceptions import ClientError

from app.core.aws import ddb

APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")
INDEX_NAME = os.environ.get("NEWSFEED_SCHEDULE_DUE_INDEX_NAME", "GSI_SCHEDULE_DUE")
INDEX_PK_ATTR = "GSI_SCHEDULE_PK"
INDEX_SK_ATTR = "GSI_SCHEDULE_SK"


def _list_gsi_names(table_desc: Dict[str, object]) -> List[str]:
    gsis = table_desc.get("GlobalSecondaryIndexes") or []
    out: List[str] = []
    for gsi in gsis:
        if isinstance(gsi, dict):
            name = gsi.get("IndexName")
            if isinstance(name, str) and name:
                out.append(name)
    return out


def _table_description() -> Dict[str, object]:
    return ddb.meta.client.describe_table(TableName=APP_TABLE).get("Table", {})


def _wait_for_active(timeout_seconds: int = 600) -> None:
    deadline = time.time() + timeout_seconds
    while True:
        table_desc = _table_description()
        table_status = str(table_desc.get("TableStatus") or "")
        index_statuses = []
        for gsi in table_desc.get("GlobalSecondaryIndexes") or []:
            if isinstance(gsi, dict):
                index_statuses.append(str(gsi.get("IndexStatus") or ""))

        if table_status == "ACTIVE" and all(s == "ACTIVE" for s in index_statuses if s):
            return
        if time.time() >= deadline:
            raise TimeoutError(f"Timed out waiting for table/index ACTIVE status for {APP_TABLE}")
        time.sleep(3)


def migrate() -> str:
    table_desc = _table_description()
    if INDEX_NAME in _list_gsi_names(table_desc):
        return "already_exists"

    try:
        ddb.meta.client.update_table(
            TableName=APP_TABLE,
            AttributeDefinitions=[
                {"AttributeName": INDEX_PK_ATTR, "AttributeType": "S"},
                {"AttributeName": INDEX_SK_ATTR, "AttributeType": "S"},
            ],
            GlobalSecondaryIndexUpdates=[
                {
                    "Create": {
                        "IndexName": INDEX_NAME,
                        "KeySchema": [
                            {"AttributeName": INDEX_PK_ATTR, "KeyType": "HASH"},
                            {"AttributeName": INDEX_SK_ATTR, "KeyType": "RANGE"},
                        ],
                        "Projection": {"ProjectionType": "ALL"},
                    }
                }
            ],
        )
    except ClientError as exc:
        code = str(exc.response.get("Error", {}).get("Code") or "")
        message = str(exc.response.get("Error", {}).get("Message") or "")
        # Safe re-run behavior: if the create was already applied (or being applied), treat as success.
        if code == "ValidationException" and (
            "already exists" in message.lower() or "currently being created" in message.lower()
        ):
            return "already_exists"
        raise

    _wait_for_active()
    return "created"


if __name__ == "__main__":
    outcome = migrate()
    print(f"newsfeed schedule due index migration complete: {outcome}")
