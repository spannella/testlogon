#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import time
from typing import Any, Dict, Optional, Tuple

from app.core.aws import ddb

APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")
VALID_LOCK_TYPES = {"fixed_price", "tip_lottery"}


def _table():
    return ddb.Table(APP_TABLE)


def is_post_row(item: Dict[str, Any]) -> bool:
    return item.get("Entity") == "Post" and bool(item.get("post_id"))


def infer_lock_type(item: Dict[str, Any]) -> Optional[str]:
    raw = item.get("lock_type")
    if raw in VALID_LOCK_TYPES:
        return raw
    unlock_price = int(item.get("unlock_price_cents") or 0)
    if unlock_price > 0:
        return "fixed_price"
    return None


def plan_update(item: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    if not is_post_row(item):
        return False, {}
    desired = infer_lock_type(item)
    current = item.get("lock_type")
    if desired == current:
        return False, {}
    if desired is None:
        return False, {}
    return True, {":lt": desired}


def run(*, page_limit: int, dry_run: bool) -> Dict[str, int | bool]:
    started_at = time.time()
    tbl = _table()
    scanned = 0
    eligible = 0
    planned_updates = 0
    applied_updates = 0
    start_key = None

    while True:
        kwargs: Dict[str, Any] = {"Limit": page_limit}
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        resp = tbl.scan(**kwargs)
        items = resp.get("Items", [])
        scanned += len(items)

        for item in items:
            if not is_post_row(item):
                continue
            eligible += 1
            should_update, values = plan_update(item)
            if not should_update:
                continue
            planned_updates += 1
            if dry_run:
                continue
            tbl.update_item(
                Key={"pk": item["pk"], "sk": item["sk"]},
                UpdateExpression="SET lock_type = :lt",
                ExpressionAttributeValues=values,
            )
            applied_updates += 1

        start_key = resp.get("LastEvaluatedKey")
        if not start_key:
            break

    finished_at = time.time()
    return {
        "dry_run": dry_run,
        "scanned": scanned,
        "eligible": eligible,
        "planned_updates": planned_updates,
        "applied_updates": applied_updates,
        "duration_seconds": round(finished_at - started_at, 3),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Backfill newsfeed post lock_type=fixed_price for legacy posts with unlock_price_cents.",
    )
    parser.add_argument("--page-limit", type=int, default=200, help="DynamoDB scan page size")
    parser.add_argument("--dry-run", action="store_true", help="Plan changes without writing updates")
    args = parser.parse_args()
    report = run(page_limit=args.page_limit, dry_run=args.dry_run)
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
