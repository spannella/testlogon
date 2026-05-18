#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connection_uid_key(*, connection_id: str, external_calendar_id: str, remote_uid: str) -> str:
    return f"{connection_id}#calendar#{external_calendar_id.strip()}#uid#{remote_uid.strip()}"


def _connection_id_for_user(user_sub: str) -> str:
    return f"apple_caldav#user#{str(user_sub or '').strip()}"


def _extract_candidate(event_row: dict[str, Any], *, default_connection_id: str | None = None) -> dict[str, Any] | None:
    internal_event_id = str(
        event_row.get("internal_event_id")
        or event_row.get("event_id")
        or event_row.get("id")
        or ""
    ).strip()
    if not internal_event_id:
        return None

    remote_uid = str(
        event_row.get("apple_remote_uid")
        or event_row.get("remote_uid")
        or event_row.get("external_uid")
        or ""
    ).strip()
    if not remote_uid:
        return None

    external_calendar_id = str(
        event_row.get("apple_external_calendar_id")
        or event_row.get("external_calendar_id")
        or event_row.get("calendar_id")
        or ""
    ).strip()
    if not external_calendar_id:
        return None

    connection_id = str(event_row.get("apple_connection_id") or "").strip()
    if not connection_id:
        user_sub = str(event_row.get("user_sub") or event_row.get("owner") or "").strip()
        if user_sub:
            connection_id = _connection_id_for_user(user_sub)
        elif default_connection_id:
            connection_id = default_connection_id
    if not connection_id:
        return None

    return {
        "connection_id": connection_id,
        "external_calendar_id": external_calendar_id,
        "remote_uid": remote_uid,
        "internal_event_id": internal_event_id,
        "resource_url": str(event_row.get("apple_resource_url") or event_row.get("resource_url") or "").strip() or None,
        "etag": str(event_row.get("apple_etag") or event_row.get("etag") or "").strip() or None,
    }


def run_backfill(
    *,
    apply: bool,
    user_sub: str | None = None,
    connection_id: str | None = None,
    limit: int | None = None,
    ddb_resource: Any | None = None,
    settings: Any | None = None,
) -> dict[str, Any]:
    if ddb_resource is None or settings is None:
        from app.core.aws import ddb as runtime_ddb
        from app.core.settings import S as runtime_settings

        ddb_resource = ddb_resource or runtime_ddb
        settings = settings or runtime_settings

    events_table = ddb_resource.Table(settings.calendar_table_name)
    links_table = ddb_resource.Table(settings.external_event_links_table_name)

    default_connection_id = connection_id or (_connection_id_for_user(user_sub) if user_sub else None)

    events = events_table.scan().get("Items", [])
    if limit is not None and limit > 0:
        events = events[:limit]

    report = {
        "mode": "apply" if apply else "dry_run",
        "scanned": len(events),
        "changed": 0,
        "skipped": 0,
        "errors": 0,
        "reasons": {
            "missing_mapping_fields": 0,
            "existing_link": 0,
            "connection_filter_mismatch": 0,
            "exception": 0,
        },
        "samples": {
            "changed": [],
            "skipped": [],
            "errors": [],
        },
        "generated_at": _now_iso(),
    }

    for row in events:
        try:
            candidate = _extract_candidate(row, default_connection_id=default_connection_id)
            if candidate is None:
                report["skipped"] += 1
                report["reasons"]["missing_mapping_fields"] += 1
                if len(report["samples"]["skipped"]) < 20:
                    report["samples"]["skipped"].append({
                        "reason": "missing_mapping_fields",
                        "event_ref": str(row.get("internal_event_id") or row.get("event_id") or row.get("id") or "unknown"),
                    })
                continue

            if connection_id and candidate["connection_id"] != connection_id:
                report["skipped"] += 1
                report["reasons"]["connection_filter_mismatch"] += 1
                continue

            key = _connection_uid_key(
                connection_id=candidate["connection_id"],
                external_calendar_id=candidate["external_calendar_id"],
                remote_uid=candidate["remote_uid"],
            )
            existing = links_table.get_item(Key={"connection_uid_key": key}).get("Item")
            if existing:
                report["skipped"] += 1
                report["reasons"]["existing_link"] += 1
                continue

            if apply:
                now = _now_iso()
                links_table.put_item(
                    Item={
                        "connection_uid_key": key,
                        "connection_id": candidate["connection_id"],
                        "external_calendar_id": candidate["external_calendar_id"],
                        "remote_uid": candidate["remote_uid"],
                        "internal_event_id": candidate["internal_event_id"],
                        "resource_url": candidate["resource_url"],
                        "etag": candidate["etag"],
                        "last_seen_run_id": f"backfill_{uuid.uuid4().hex}",
                        "created_at": now,
                        "updated_at": now,
                    }
                )

            report["changed"] += 1
            if len(report["samples"]["changed"]) < 20:
                report["samples"]["changed"].append(
                    {
                        "connection_id": candidate["connection_id"],
                        "external_calendar_id": candidate["external_calendar_id"],
                        "remote_uid": candidate["remote_uid"],
                        "internal_event_id": candidate["internal_event_id"],
                    }
                )
        except Exception as exc:  # pragma: no cover - defensive catch for migration robustness
            report["errors"] += 1
            report["reasons"]["exception"] += 1
            if len(report["samples"]["errors"]) < 20:
                report["samples"]["errors"].append({"error": str(exc), "row": str(row)[:1000]})

    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Backfill Apple external event links for pre-existing internal events")
    parser.add_argument("--apply", action="store_true", help="Apply changes (default is dry-run)")
    parser.add_argument("--user-sub", default=None, help="Optional filter to a single user_sub")
    parser.add_argument("--connection-id", default=None, help="Optional filter to a single connection_id")
    parser.add_argument("--limit", type=int, default=0, help="Optional max rows to scan (0 means all)")
    parser.add_argument(
        "--output",
        default="/tmp/calendar_event_link_backfill_report.json",
        help="Path to write JSON audit report",
    )
    args = parser.parse_args()

    report = run_backfill(
        apply=bool(args.apply),
        user_sub=args.user_sub,
        connection_id=args.connection_id,
        limit=args.limit if int(args.limit or 0) > 0 else None,
    )

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(json.dumps({
        "mode": report["mode"],
        "scanned": report["scanned"],
        "changed": report["changed"],
        "skipped": report["skipped"],
        "errors": report["errors"],
        "output": str(out_path),
    }))


if __name__ == "__main__":
    main()
