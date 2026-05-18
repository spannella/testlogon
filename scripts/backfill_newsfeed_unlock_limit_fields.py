#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import dataclass
from decimal import Decimal
import os
from typing import Any, Dict, Optional

from app.core.aws import ddb

APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")


def _table(table_name: str):
    return ddb.Table(table_name)


def _coerce_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        if isinstance(value, Decimal):
            return int(value)
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, (int, float)):
            return int(value)
        if isinstance(value, str) and value.strip():
            return int(value.strip())
    except Exception:
        return None
    return None


@dataclass
class Counters:
    scanned: int = 0
    posts_seen: int = 0
    updates_needed: int = 0
    updated: int = 0
    capped_missing_unlock_count: int = 0
    capped_invalid_unlock_count: int = 0
    uncapped_orphan_unlock_count: int = 0


def _build_update_plan(item: Dict[str, Any], *, remove_orphan_unlock_count: bool) -> Dict[str, Any]:
    unlock_limit = _coerce_int(item.get("unlock_limit"))
    unlock_count_raw = item.get("unlock_count")
    unlock_count = _coerce_int(unlock_count_raw)

    set_parts: list[str] = []
    remove_parts: list[str] = []
    values: Dict[str, Any] = {}
    reasons: list[str] = []

    if unlock_limit is not None and unlock_limit >= 1:
        normalized = 0 if unlock_count is None or unlock_count < 0 else unlock_count
        if unlock_count != normalized:
            set_parts.append("unlock_count = :unlock_count")
            values[":unlock_count"] = int(normalized)
            reasons.append("capped_post_unlock_count_normalized")
    elif remove_orphan_unlock_count and unlock_count_raw is not None:
        remove_parts.append("unlock_count")
        reasons.append("uncapped_post_orphan_unlock_count_removed")

    return {
        "set_parts": set_parts,
        "remove_parts": remove_parts,
        "values": values,
        "reasons": reasons,
    }


def _scan_posts(tbl, *, page_size: int):
    start_key = None
    while True:
        kwargs: Dict[str, Any] = {"Limit": page_size}
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        resp = tbl.scan(**kwargs)
        for item in resp.get("Items", []):
            if item.get("Entity") == "Post" and item.get("sk") == "META":
                yield item
        start_key = resp.get("LastEvaluatedKey")
        if not start_key:
            break


def run(*, table_name: str, page_size: int, dry_run: bool, remove_orphan_unlock_count: bool, progress_every: int) -> Dict[str, Any]:
    tbl = _table(table_name)
    counters = Counters()

    for item in _scan_posts(tbl, page_size=page_size):
        counters.scanned += 1
        counters.posts_seen += 1

        unlock_limit = _coerce_int(item.get("unlock_limit"))
        unlock_count = _coerce_int(item.get("unlock_count"))
        if unlock_limit is not None and unlock_limit >= 1:
            if item.get("unlock_count") is None:
                counters.capped_missing_unlock_count += 1
            elif unlock_count is None or unlock_count < 0:
                counters.capped_invalid_unlock_count += 1
        elif item.get("unlock_count") is not None:
            counters.uncapped_orphan_unlock_count += 1

        plan = _build_update_plan(item, remove_orphan_unlock_count=remove_orphan_unlock_count)
        if not plan["set_parts"] and not plan["remove_parts"]:
            if counters.posts_seen % progress_every == 0:
                print(f"[progress] scanned_posts={counters.posts_seen} updates={counters.updated}")
            continue

        counters.updates_needed += 1
        if dry_run:
            print(
                f"[dry-run] post_id={item.get('post_id')} pk={item.get('pk')} "
                f"reasons={','.join(plan['reasons'])}"
            )
        else:
            update_expr = ""
            if plan["set_parts"]:
                update_expr += "SET " + ", ".join(plan["set_parts"])
            if plan["remove_parts"]:
                update_expr += (" " if update_expr else "") + "REMOVE " + ", ".join(plan["remove_parts"])
            kwargs: Dict[str, Any] = {
                "Key": {"pk": item["pk"], "sk": item["sk"]},
                "UpdateExpression": update_expr,
            }
            if plan["values"]:
                kwargs["ExpressionAttributeValues"] = plan["values"]
            tbl.update_item(**kwargs)
            counters.updated += 1

        if counters.posts_seen % progress_every == 0:
            print(f"[progress] scanned_posts={counters.posts_seen} updates={counters.updated if not dry_run else counters.updates_needed}")

    verification = verify(table_name=table_name, page_size=page_size)
    report = {
        "table_name": table_name,
        "dry_run": dry_run,
        "scanned_posts": counters.posts_seen,
        "updates_needed": counters.updates_needed,
        "updated": counters.updated,
        "capped_missing_unlock_count": counters.capped_missing_unlock_count,
        "capped_invalid_unlock_count": counters.capped_invalid_unlock_count,
        "uncapped_orphan_unlock_count": counters.uncapped_orphan_unlock_count,
        "verification": verification,
    }
    return report


def verify(*, table_name: str, page_size: int) -> Dict[str, Any]:
    tbl = _table(table_name)
    total_posts = 0
    anomalies = {
        "capped_missing_unlock_count": 0,
        "capped_invalid_unlock_count": 0,
        "uncapped_orphan_unlock_count": 0,
    }
    for item in _scan_posts(tbl, page_size=page_size):
        total_posts += 1
        unlock_limit = _coerce_int(item.get("unlock_limit"))
        unlock_count = _coerce_int(item.get("unlock_count"))
        if unlock_limit is not None and unlock_limit >= 1:
            if item.get("unlock_count") is None:
                anomalies["capped_missing_unlock_count"] += 1
            elif unlock_count is None or unlock_count < 0:
                anomalies["capped_invalid_unlock_count"] += 1
        elif item.get("unlock_count") is not None:
            anomalies["uncapped_orphan_unlock_count"] += 1

    return {
        "total_posts": total_posts,
        **anomalies,
        "ok": all(v == 0 for v in anomalies.values()),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Backfill/normalize legacy unlock-limit fields on newsfeed posts.",
    )
    parser.add_argument("--table-name", default=APP_TABLE, help="DynamoDB table name (default: app_single_table)")
    parser.add_argument("--page-size", type=int, default=250, help="Scan page size")
    parser.add_argument("--apply", action="store_true", help="Apply updates (default is dry-run)")
    parser.add_argument(
        "--keep-orphan-unlock-count",
        action="store_true",
        help="Do not remove unlock_count on uncapped posts",
    )
    parser.add_argument("--progress-every", type=int, default=200, help="Print progress every N scanned posts")
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Run verification checks only (no scan/update plan output)",
    )
    args = parser.parse_args()

    if args.verify_only:
        report = verify(table_name=args.table_name, page_size=args.page_size)
        print(report)
        return

    report = run(
        table_name=args.table_name,
        page_size=args.page_size,
        dry_run=not args.apply,
        remove_orphan_unlock_count=not args.keep_orphan_unlock_count,
        progress_every=max(1, int(args.progress_every)),
    )
    print(report)


if __name__ == "__main__":
    main()
