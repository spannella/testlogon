#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from botocore.exceptions import ClientError

from app.core.aws import ddb

APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")
INDEX_PK_ATTR = "GSI_SCHEDULE_PK"
INDEX_SK_ATTR = "GSI_SCHEDULE_SK"
INDEX_PK_VALUE = "SCHEDULED"


@dataclass
class BackfillStats:
    scanned: int = 0
    eligible: int = 0
    updated: int = 0
    dry_run_updates: int = 0
    no_change: int = 0
    malformed: int = 0
    errors: int = 0


def _table():
    return ddb.Table(APP_TABLE)


def _schedule_sort_key(*, publish_at: int, post_id: str) -> str:
    return f"{publish_at:012d}#POST#{post_id}"


def _as_scheduled_post(item: Dict[str, Any]) -> Tuple[bool, Optional[str], Optional[int]]:
    if str(item.get("Entity") or "") != "Post":
        return False, None, None
    post_id = str(item.get("post_id") or "").strip()
    if not post_id:
        return False, None, None
    if str(item.get("status") or "").strip().lower() != "scheduled":
        return False, None, None
    try:
        publish_at = int(item.get("publish_at"))
    except Exception:
        return True, post_id, None
    if publish_at <= 0:
        return True, post_id, None
    return True, post_id, publish_at


def _desired_index_values(*, post_id: str, publish_at: int) -> Dict[str, str]:
    return {
        INDEX_PK_ATTR: INDEX_PK_VALUE,
        INDEX_SK_ATTR: _schedule_sort_key(publish_at=publish_at, post_id=post_id),
    }


def plan_update(item: Dict[str, Any]) -> Tuple[bool, Optional[str], Dict[str, str]]:
    is_candidate, post_id, publish_at = _as_scheduled_post(item)
    if not is_candidate:
        return False, None, {}
    if post_id is None or publish_at is None:
        return False, "invalid_publish_at", {}

    desired = _desired_index_values(post_id=post_id, publish_at=publish_at)
    current_pk = item.get(INDEX_PK_ATTR)
    current_sk = item.get(INDEX_SK_ATTR)
    if current_pk == desired[INDEX_PK_ATTR] and current_sk == desired[INDEX_SK_ATTR]:
        return False, None, {}
    return True, None, desired


def run(*, page_limit: int, max_items: Optional[int], dry_run: bool) -> Dict[str, Any]:
    tbl = _table()
    stats = BackfillStats()
    start_key = None

    while True:
        kwargs: Dict[str, Any] = {"Limit": page_limit}
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        resp = tbl.scan(**kwargs)
        items = resp.get("Items", [])

        if max_items is not None and stats.scanned + len(items) > max_items:
            take = max_items - stats.scanned
            if take <= 0:
                break
            items = items[:take]
            next_key = None
        else:
            next_key = resp.get("LastEvaluatedKey")

        stats.scanned += len(items)

        for item in items:
            should_update, reason, desired = plan_update(item)
            if reason == "invalid_publish_at":
                stats.malformed += 1
                continue
            if not should_update:
                if _as_scheduled_post(item)[0]:
                    stats.eligible += 1
                    stats.no_change += 1
                continue

            stats.eligible += 1
            if dry_run:
                stats.dry_run_updates += 1
                continue

            try:
                tbl.update_item(
                    Key={"pk": item["pk"], "sk": item["sk"]},
                    UpdateExpression=f"SET {INDEX_PK_ATTR} = :pk, {INDEX_SK_ATTR} = :sk",
                    ExpressionAttributeValues={":pk": desired[INDEX_PK_ATTR], ":sk": desired[INDEX_SK_ATTR]},
                )
                stats.updated += 1
            except ClientError:
                stats.errors += 1

        if not next_key:
            break
        start_key = next_key

    return {
        "table": APP_TABLE,
        "dry_run": dry_run,
        "scanned": stats.scanned,
        "eligible": stats.eligible,
        "updated": stats.updated,
        "dry_run_updates": stats.dry_run_updates,
        "no_change": stats.no_change,
        "malformed": stats.malformed,
        "errors": stats.errors,
    }


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Backfill newsfeed schedule due-index attributes on scheduled posts")
    p.add_argument("--page-limit", type=int, default=200)
    p.add_argument("--max-items", type=int, default=None)
    p.add_argument("--dry-run", action="store_true")
    return p.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    report = run(page_limit=max(1, int(args.page_limit)), max_items=args.max_items, dry_run=bool(args.dry_run))
    print(report)
