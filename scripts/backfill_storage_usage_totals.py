#!/usr/bin/env python3
from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.core.aws import ddb
from app.core.settings import S
from app.services.usage_metering import period_id_for_datetime

CHECKPOINT_PK = "SYSTEM#USAGE_BACKFILL"
CHECKPOINT_SK = "STORAGE#CHECKPOINT"


def _table():
    if not S.filemgr_table_name:
        raise RuntimeError("FILEMGR_TABLE_NAME is required")
    return ddb.Table(S.filemgr_table_name)


def load_checkpoint(tbl) -> Optional[Dict[str, Any]]:
    resp = tbl.get_item(Key={"PK": CHECKPOINT_PK, "SK": CHECKPOINT_SK})
    return resp.get("Item")


def save_checkpoint(tbl, *, start_key: Optional[Dict[str, Any]], scanned: int, users: int, done: bool) -> None:
    item = {
        "PK": CHECKPOINT_PK,
        "SK": CHECKPOINT_SK,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "scanned": scanned,
        "users": users,
        "done": done,
    }
    if start_key:
        item["last_evaluated_key"] = start_key
    tbl.put_item(Item=item)


def run(limit: int, reset: bool) -> Dict[str, Any]:
    tbl = _table()
    start_key = None
    if not reset:
        cp = load_checkpoint(tbl)
        if cp and cp.get("last_evaluated_key") and not cp.get("done"):
            start_key = cp.get("last_evaluated_key")

    totals = defaultdict(int)
    scanned = 0
    while True:
        kwargs: Dict[str, Any] = {"Limit": limit}
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        resp = tbl.scan(**kwargs)
        items = resp.get("Items", [])
        scanned += len(items)

        for it in items:
            if it.get("entity_type") == "usage_event":
                continue
            sk = str(it.get("SK") or "")
            if not sk.startswith("NODE#"):
                continue
            if it.get("deleted_at"):
                continue
            if it.get("type") != "file":
                continue
            pk = str(it.get("PK") or "")
            if not pk.startswith("USER#"):
                continue
            user_id = pk.replace("USER#", "", 1)
            totals[user_id] += int(it.get("size") or 0)

        start_key = resp.get("LastEvaluatedKey")
        save_checkpoint(tbl, start_key=start_key, scanned=scanned, users=len(totals), done=not bool(start_key))
        if not start_key:
            break

    period_id = period_id_for_datetime(datetime.now(timezone.utc))
    updated = 0
    for user_id, total in totals.items():
        tbl.update_item(
            Key={"PK": f"USER#{user_id}", "SK": f"USAGE#PERIOD#{period_id}"},
            UpdateExpression=(
                "SET entity_type=:e, user_id=:u, period_id=:p, "
                "storage_bytes_current=:c, storage_bytes_peak=if_not_exists(storage_bytes_peak,:z), "
                "storage_byte_seconds=if_not_exists(storage_byte_seconds,:z), "
                "upload_bytes_total=if_not_exists(upload_bytes_total,:z), "
                "download_bytes_total=if_not_exists(download_bytes_total,:z), "
                "updated_at=:t"
            ),
            ExpressionAttributeValues={
                ":e": "usage_period_totals",
                ":u": user_id,
                ":p": period_id,
                ":c": int(total),
                ":z": 0,
                ":t": datetime.now(timezone.utc).isoformat(),
            },
        )
        updated += 1

    return {"period_id": period_id, "users_updated": updated, "scanned": scanned, "resumed_from_checkpoint": not reset}


def main() -> None:
    parser = argparse.ArgumentParser(description="Backfill storage usage totals from existing file nodes.")
    parser.add_argument("--scan-limit", type=int, default=500, help="DynamoDB scan page size")
    parser.add_argument("--reset", action="store_true", help="Ignore existing checkpoint and restart")
    args = parser.parse_args()
    report = run(args.scan_limit, args.reset)
    print(report)


if __name__ == "__main__":
    main()
