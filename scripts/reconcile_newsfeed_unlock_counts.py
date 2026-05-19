#!/usr/bin/env python3
from __future__ import annotations

import argparse
import logging
import os
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Dict, Optional

from app.core.aws import ddb

APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")
logger = logging.getLogger("newsfeed_unlock_count_reconcile")


def _table(table_name: str):
    return ddb.Table(table_name)


def _to_int(value: Any, default: int = 0) -> int:
    try:
        if value is None:
            return default
        if isinstance(value, Decimal):
            return int(value)
        return int(value)
    except Exception:
        return default


@dataclass
class ReconcileStats:
    scanned_items: int = 0
    capped_posts: int = 0
    unlocked_records: int = 0
    drift_posts: int = 0
    repaired_posts: int = 0


def reconcile(*, table_name: str, page_size: int, apply: bool, progress_every: int) -> Dict[str, Any]:
    tbl = _table(table_name)
    stats = ReconcileStats()
    start_key = None
    posts: Dict[str, Dict[str, Any]] = {}
    unlocked_cardinality: Dict[str, int] = {}

    while True:
        kwargs: Dict[str, Any] = {"Limit": page_size}
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        resp = tbl.scan(**kwargs)

        for item in resp.get("Items", []):
            stats.scanned_items += 1
            entity = item.get("Entity")
            sk = item.get("sk")
            if entity == "Post" and sk == "META":
                unlock_limit = _to_int(item.get("unlock_limit"), default=0)
                if unlock_limit >= 1:
                    post_id = str(item.get("post_id") or "")
                    if post_id:
                        posts[post_id] = item
                        stats.capped_posts += 1
            elif entity == "Unlock" and bool(item.get("unlocked")):
                post_id = str(item.get("post_id") or "")
                if post_id:
                    unlocked_cardinality[post_id] = unlocked_cardinality.get(post_id, 0) + 1
                    stats.unlocked_records += 1

        if stats.scanned_items % max(1, progress_every) == 0:
            logger.info(
                "newsfeed_unlock_count_reconcile progress",
                extra={
                    "event": "newsfeed_unlock_count_reconcile_progress",
                    "scanned_items": stats.scanned_items,
                    "capped_posts": stats.capped_posts,
                    "unlocked_records": stats.unlocked_records,
                },
            )

        start_key = resp.get("LastEvaluatedKey")
        if not start_key:
            break

    drift: list[Dict[str, Any]] = []
    for post_id, post_item in posts.items():
        stored_unlock_count = max(0, _to_int(post_item.get("unlock_count"), default=0))
        actual_unlock_count = unlocked_cardinality.get(post_id, 0)
        if stored_unlock_count != actual_unlock_count:
            stats.drift_posts += 1
            drift_item = {
                "post_id": post_id,
                "pk": post_item.get("pk"),
                "stored_unlock_count": stored_unlock_count,
                "actual_unlock_count": actual_unlock_count,
                "delta": actual_unlock_count - stored_unlock_count,
            }
            drift.append(drift_item)
            logger.warning(
                "newsfeed unlock_count drift detected",
                extra={"event": "newsfeed_unlock_count_drift", **drift_item},
            )
            if apply:
                tbl.update_item(
                    Key={"pk": post_item["pk"], "sk": post_item["sk"]},
                    UpdateExpression="SET unlock_count = :c",
                    ExpressionAttributeValues={":c": int(actual_unlock_count)},
                )
                stats.repaired_posts += 1
                logger.info(
                    "newsfeed unlock_count drift repaired",
                    extra={"event": "newsfeed_unlock_count_repair", **drift_item},
                )

    logger.info(
        "newsfeed unlock_count reconciliation summary",
        extra={
            "event": "newsfeed_unlock_count_reconcile_summary",
            "table_name": table_name,
            "scanned_items": stats.scanned_items,
            "capped_posts": stats.capped_posts,
            "unlocked_records": stats.unlocked_records,
            "drift_posts": stats.drift_posts,
            "repaired_posts": stats.repaired_posts,
            "mode": "apply" if apply else "check",
        },
    )

    return {
        "table_name": table_name,
        "mode": "apply" if apply else "check",
        "scanned_items": stats.scanned_items,
        "capped_posts": stats.capped_posts,
        "unlocked_records": stats.unlocked_records,
        "drift_posts": stats.drift_posts,
        "repaired_posts": stats.repaired_posts,
        "drift_examples": drift[:20],
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Reconcile Post.unlock_count against Unlock record cardinality (unlocked=true).",
    )
    parser.add_argument("--table-name", default=APP_TABLE, help="DynamoDB table name")
    parser.add_argument("--page-size", type=int, default=500, help="DynamoDB scan page size")
    parser.add_argument("--apply", action="store_true", help="Repair drift by writing actual unlock cardinality")
    parser.add_argument("--progress-every", type=int, default=1000, help="Emit progress log every N scanned items")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, args.log_level), format="%(asctime)s %(levelname)s %(name)s %(message)s")
    report = reconcile(
        table_name=args.table_name,
        page_size=max(1, int(args.page_size)),
        apply=bool(args.apply),
        progress_every=max(1, int(args.progress_every)),
    )
    print(report)


if __name__ == "__main__":
    main()

