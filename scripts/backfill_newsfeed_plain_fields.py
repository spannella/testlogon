#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Optional, Tuple

from botocore.exceptions import ClientError

from app.core.aws import ddb

APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")
CHECKPOINT_PK = "SYSTEM#NEWSFEED_BACKFILL"
CHECKPOINT_SK = "CONTENT#PLAIN_FORMAT"
VALID_FORMATS = {"plain", "markdown", "rich"}

RETRYABLE_ERROR_CODES = {
    "ProvisionedThroughputExceededException",
    "ThrottlingException",
    "RequestLimitExceeded",
    "InternalServerError",
    "TransactionConflictException",
}


@dataclass
class BackfillStats:
    scanned: int = 0
    eligible: int = 0
    updated: int = 0
    dry_run_updates: int = 0
    no_change: int = 0
    malformed: int = 0
    errors: int = 0
    retries: int = 0


def _table():
    return ddb.Table(APP_TABLE)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _coerce_text(value: Any) -> Optional[str]:
    if isinstance(value, str):
        value = value.strip()
        return value or None
    return None


def _rich_doc_to_plain_text(doc: Any) -> str:
    parts: list[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            text = node.get("text")
            if isinstance(text, str) and text.strip():
                parts.append(text.strip())
            for child in node.get("content") or []:
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(doc)
    return " ".join(parts).strip()


def infer_body_plain(item: Dict[str, Any]) -> Optional[str]:
    return (
        _coerce_text(item.get("body_plain"))
        or _coerce_text(item.get("body"))
        or _coerce_text(item.get("body_markdown"))
        or (_rich_doc_to_plain_text(item.get("body_rich")) if isinstance(item.get("body_rich"), dict) else None)
    )


def infer_body_format(item: Dict[str, Any]) -> str:
    raw = item.get("body_format")
    if raw in VALID_FORMATS:
        return raw
    if isinstance(item.get("body_rich"), dict):
        return "rich"
    if _coerce_text(item.get("body_markdown")):
        return "markdown"
    return "plain"


def is_newsfeed_content_row(item: Dict[str, Any]) -> bool:
    entity = item.get("Entity")
    return (entity == "Post" and bool(item.get("post_id"))) or (entity == "Comment" and bool(item.get("comment_id")))


def plan_update(item: Dict[str, Any]) -> Tuple[bool, Dict[str, Any], Optional[str]]:
    if not is_newsfeed_content_row(item):
        return False, {}, None

    desired_plain = infer_body_plain(item)
    desired_format = infer_body_format(item)
    if not desired_plain:
        return False, {}, "missing_plain_source"

    current_plain = _coerce_text(item.get("body_plain"))
    current_format = item.get("body_format") if item.get("body_format") in VALID_FORMATS else None

    needs_update = current_plain != desired_plain or current_format != desired_format
    if not needs_update:
        return False, {}, None

    update_values = {":bp": desired_plain, ":bf": desired_format, ":ts": _now_iso()}
    return True, update_values, None


def load_checkpoint(tbl) -> Optional[Dict[str, Any]]:
    resp = tbl.get_item(Key={"pk": CHECKPOINT_PK, "sk": CHECKPOINT_SK})
    return resp.get("Item")


def save_checkpoint(tbl, *, start_key: Optional[Dict[str, Any]], stats: BackfillStats, done: bool) -> None:
    item: Dict[str, Any] = {
        "pk": CHECKPOINT_PK,
        "sk": CHECKPOINT_SK,
        "updated_at": _now_iso(),
        "done": done,
        "scanned": stats.scanned,
        "eligible": stats.eligible,
        "updated": stats.updated,
        "dry_run_updates": stats.dry_run_updates,
        "no_change": stats.no_change,
        "malformed": stats.malformed,
        "errors": stats.errors,
        "retries": stats.retries,
    }
    if start_key:
        item["last_evaluated_key"] = start_key
    tbl.put_item(Item=item)


def _update_with_retry(tbl, *, key: Dict[str, Any], expr_vals: Dict[str, Any], max_retries: int) -> int:
    retries = 0
    for attempt in range(max_retries + 1):
        try:
            tbl.update_item(
                Key=key,
                UpdateExpression="SET body_plain = :bp, body_format = :bf, backfill_updated_at = :ts",
                ExpressionAttributeValues=expr_vals,
            )
            return retries
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in RETRYABLE_ERROR_CODES or attempt == max_retries:
                raise
            retries += 1
            time.sleep(min(0.2 * (2**attempt), 2.0))
    return retries


def _integrity_check(items: Iterable[Dict[str, Any]]) -> int:
    malformed = 0
    for item in items:
        if not is_newsfeed_content_row(item):
            continue
        if not infer_body_plain(item):
            malformed += 1
    return malformed


def run(*, page_limit: int, max_items: Optional[int], reset_checkpoint: bool, dry_run: bool, max_retries: int) -> Dict[str, Any]:
    tbl = _table()
    stats = BackfillStats()
    start_key = None

    if not reset_checkpoint:
        cp = load_checkpoint(tbl)
        if cp and cp.get("last_evaluated_key") and not cp.get("done"):
            start_key = cp.get("last_evaluated_key")

    processed_items: list[Dict[str, Any]] = []

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
            start_key = resp.get("LastEvaluatedKey")
            # force stop after this clipped batch
            next_key = start_key
            stop_after = True
        else:
            next_key = resp.get("LastEvaluatedKey")
            stop_after = False

        stats.scanned += len(items)
        processed_items.extend(items)

        for item in items:
            if not is_newsfeed_content_row(item):
                continue
            stats.eligible += 1
            should_update, expr_vals, reason = plan_update(item)
            if reason == "missing_plain_source":
                stats.malformed += 1
                continue
            if not should_update:
                stats.no_change += 1
                continue

            if dry_run:
                stats.dry_run_updates += 1
                continue

            try:
                key = {"pk": item["pk"], "sk": item["sk"]}
                stats.retries += _update_with_retry(tbl, key=key, expr_vals=expr_vals, max_retries=max_retries)
                stats.updated += 1
            except Exception:
                stats.errors += 1

        done = not bool(next_key) or stop_after
        save_checkpoint(tbl, start_key=next_key if not done else None, stats=stats, done=done)

        if done:
            break
        start_key = next_key

    malformed_check = _integrity_check(processed_items)
    report = {
        "table": APP_TABLE,
        "dry_run": dry_run,
        "page_limit": page_limit,
        "max_items": max_items,
        "stats": stats.__dict__,
        "integrity": {
            "malformed_rows": malformed_check,
            "ok": malformed_check == 0,
        },
    }
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Backfill newsfeed body_plain and default body_format for legacy records.")
    parser.add_argument("--page-limit", type=int, default=200, help="DynamoDB scan page size")
    parser.add_argument("--max-items", type=int, default=None, help="Optional cap for incremental runs")
    parser.add_argument("--reset-checkpoint", action="store_true", help="Start from the beginning")
    parser.add_argument("--dry-run", action="store_true", help="Plan changes without writing updates")
    parser.add_argument("--max-retries", type=int, default=3, help="Retry count for retryable write errors")
    args = parser.parse_args()

    report = run(
        page_limit=args.page_limit,
        max_items=args.max_items,
        reset_checkpoint=args.reset_checkpoint,
        dry_run=args.dry_run,
        max_retries=args.max_retries,
    )
    print(report)

    if report["integrity"]["malformed_rows"] > 0:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
