#!/usr/bin/env python3
from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, Tuple

from app.core.aws import ddb
from app.core.settings import S
from app.services.usage_metering import period_id_for_datetime


def _table():
    if not S.filemgr_table_name:
        raise RuntimeError("FILEMGR_TABLE_NAME is required")
    return ddb.Table(S.filemgr_table_name)


def _scan_all_events(tbl, scan_limit: int) -> list[Dict[str, Any]]:
    out = []
    start_key = None
    while True:
        kwargs: Dict[str, Any] = {"Limit": scan_limit}
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        resp = tbl.scan(**kwargs)
        for it in resp.get("Items", []):
            if it.get("entity_type") == "usage_event":
                out.append(it)
        start_key = resp.get("LastEvaluatedKey")
        if not start_key:
            break
    return out


def recompute(scan_limit: int, apply: bool) -> Dict[str, Any]:
    tbl = _table()
    events = _scan_all_events(tbl, scan_limit)

    period_totals: Dict[Tuple[str, str], Dict[str, int]] = defaultdict(lambda: {
        "upload_bytes_total": 0,
        "download_bytes_total": 0,
        "storage_bytes_current": 0,
        "storage_bytes_peak": 0,
        "storage_byte_seconds": 0,
    })
    daily_totals: Dict[Tuple[str, str], Dict[str, int]] = defaultdict(lambda: {
        "upload_bytes_total": 0,
        "download_bytes_total": 0,
        "storage_bytes_end_of_day": 0,
    })

    for ev in events:
        user_id = ev.get("user_id")
        ts = ev.get("timestamp")
        if not user_id or not ts:
            continue
        dt = datetime.fromisoformat(ts)
        period_id = period_id_for_datetime(dt)
        day = ts[:10]
        b = int(ev.get("bytes") or 0)
        typ = ev.get("event_type")
        key = (user_id, period_id)
        dkey = (user_id, day)
        if typ == "upload":
            period_totals[key]["upload_bytes_total"] += b
            daily_totals[dkey]["upload_bytes_total"] += b
        elif typ == "download":
            period_totals[key]["download_bytes_total"] += b
            daily_totals[dkey]["download_bytes_total"] += b
        elif typ == "storage_delta":
            period_totals[key]["storage_bytes_current"] += b
            daily_totals[dkey]["storage_bytes_end_of_day"] += b
            if period_totals[key]["storage_bytes_current"] > period_totals[key]["storage_bytes_peak"]:
                period_totals[key]["storage_bytes_peak"] = period_totals[key]["storage_bytes_current"]

    mismatches = 0
    if apply:
        now = datetime.now(timezone.utc).isoformat()
        for (user_id, period_id), vals in period_totals.items():
            tbl.put_item(Item={
                "PK": f"USER#{user_id}",
                "SK": f"USAGE#PERIOD#{period_id}",
                "entity_type": "usage_period_totals",
                "user_id": user_id,
                "period_id": period_id,
                **vals,
                "updated_at": now,
            })
        for (user_id, day), vals in daily_totals.items():
            tbl.put_item(Item={
                "PK": f"USER#{user_id}",
                "SK": f"USAGE#DAY#{day}",
                "entity_type": "usage_daily",
                "user_id": user_id,
                "day_utc": day,
                "period_id": day[:7],
                **vals,
                "updated_at": now,
            })
    else:
        # report-only mismatch detection against stored period totals
        for (user_id, period_id), vals in period_totals.items():
            stored = tbl.get_item(Key={"PK": f"USER#{user_id}", "SK": f"USAGE#PERIOD#{period_id}"}).get("Item") or {}
            if int(stored.get("upload_bytes_total") or 0) != vals["upload_bytes_total"]:
                mismatches += 1
            elif int(stored.get("download_bytes_total") or 0) != vals["download_bytes_total"]:
                mismatches += 1
            elif int(stored.get("storage_bytes_current") or 0) != vals["storage_bytes_current"]:
                mismatches += 1

    return {
        "events_scanned": len(events),
        "period_rows": len(period_totals),
        "daily_rows": len(daily_totals),
        "mismatches": mismatches,
        "applied": apply,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Recompute usage aggregates from raw usage events.")
    parser.add_argument("--scan-limit", type=int, default=500)
    parser.add_argument("--apply", action="store_true", help="Write recomputed totals back to table")
    args = parser.parse_args()
    report = recompute(args.scan_limit, args.apply)
    print(report)


if __name__ == "__main__":
    main()
