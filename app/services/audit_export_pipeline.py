"""Audit export pipeline: create jobs, process exports, generate files (ENTERPRISE-004)."""
from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Iterator, Optional

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.audit_adapters import ADAPTERS, VALID_CATEGORIES
from app.services.audit_export import UnifiedAuditEvent

logger = logging.getLogger(__name__)

CSV_COLUMNS = [
    "event_id", "event_type", "event_action", "timestamp", "timestamp_unix",
    "actor_user_id", "actor_role", "actor_ip", "actor_user_agent",
    "target_user_id", "target_resource_type", "target_resource_id",
    "outcome", "metadata", "source_table",
]


def _gen_export_id() -> str:
    return f"exp_{uuid.uuid4().hex}"


def _merge_sorted_events(
    categories: list[str],
    from_ts: int,
    to_ts: int,
    actor: Optional[str] = None,
    target: Optional[str] = None,
    event_actions: Optional[list[str]] = None,
    limit: int = 10_000_000,
) -> Iterator[UnifiedAuditEvent]:
    """Query all adapters and yield events sorted by timestamp ascending."""
    import heapq

    heap: list[tuple[int, int, UnifiedAuditEvent]] = []
    counter = 0

    for category in categories:
        adapter = ADAPTERS.get(category)
        if not adapter:
            continue
        try:
            for event in adapter.query(
                from_ts=from_ts,
                to_ts=to_ts,
                actor=actor,
                target=target,
                event_actions=event_actions,
                limit=limit,
            ):
                heapq.heappush(heap, (event.timestamp_unix, counter, event))
                counter += 1
        except Exception:
            logger.exception("Adapter %s query failed", category)

    yielded = 0
    while heap and yielded < limit:
        _, _, event = heapq.heappop(heap)
        yield event
        yielded += 1


def create_export_job(
    categories: list[str],
    format: str,
    from_ts: int,
    to_ts: int,
    created_by: str,
    actor_user_id: Optional[str] = None,
    target_user_id: Optional[str] = None,
    event_actions: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Create an export job record in DynamoDB and immediately process it (dev mode)."""
    export_id = _gen_export_id()
    now = now_ts()

    item: dict[str, Any] = {
        "export_id": export_id,
        "sk": "META",
        "status": "pending",
        "categories": categories,
        "format": format,
        "from_date": from_ts,
        "to_date": to_ts,
        "created_by": created_by,
        "created_at": now,
        "actor_filter": actor_user_id or "",
        "target_filter": target_user_id or "",
        "event_actions_filter": event_actions or [],
        "event_count": 0,
        "file_size_bytes": 0,
        "events_scanned": 0,
        "events_written": 0,
        "attempt_count": 0,
        "max_attempts": 3,
    }
    T.audit_exports.put_item(Item=item)

    # In dev mode, process the export synchronously and store content inline
    if S.dev_mode:
        _process_export_inline(export_id, item)
        # Re-read the item after processing
        resp = T.audit_exports.get_item(Key={"export_id": export_id, "sk": "META"})
        return resp.get("Item", item)

    return item


def _process_export_inline(export_id: str, job: dict) -> None:
    """Process an export job inline (dev mode): store content as DDB attribute.

    NOTE: DynamoDB has a 400KB item size limit. We cap inline exports at
    _DEV_INLINE_MAX_EVENTS events to stay under this limit.  In production
    the content would be written to S3, not stored in the DDB item.
    """
    _DEV_INLINE_MAX_EVENTS = 500

    try:
        categories = list(job.get("categories", []))
        fmt = job.get("format", "ndjson")
        from_ts = int(job.get("from_date", 0))
        to_ts = int(job.get("to_date", 0))
        actor = job.get("actor_filter") or None
        target = job.get("target_filter") or None
        event_actions = job.get("event_actions_filter") or None
        if isinstance(event_actions, list) and len(event_actions) == 0:
            event_actions = None

        event_count = 0
        sha256 = hashlib.sha256()
        content_parts: list[str] = []

        if fmt == "csv":
            bom = "﻿"
            content_parts.append(bom)
            sha256.update(bom.encode("utf-8"))
            header_buf = io.StringIO()
            csv.writer(header_buf).writerow(CSV_COLUMNS)
            header_line = header_buf.getvalue()
            content_parts.append(header_line)
            sha256.update(header_line.encode("utf-8"))

            for event in _merge_sorted_events(
                categories, from_ts, to_ts, actor, target, event_actions,
                limit=_DEV_INLINE_MAX_EVENTS,
            ):
                row_buf = io.StringIO()
                csv.writer(row_buf).writerow(event.to_csv_row(CSV_COLUMNS))
                line = row_buf.getvalue()
                content_parts.append(line)
                sha256.update(line.encode("utf-8"))
                event_count += 1
        else:
            for event in _merge_sorted_events(
                categories, from_ts, to_ts, actor, target, event_actions,
                limit=_DEV_INLINE_MAX_EVENTS,
            ):
                line = event.to_ndjson_line() + "\n"
                content_parts.append(line)
                sha256.update(line.encode("utf-8"))
                event_count += 1

        content = "".join(content_parts)
        file_size = len(content.encode("utf-8"))
        file_hash = sha256.hexdigest()

        # Build manifest
        manifest = {
            "export_id": export_id,
            "schema_version": "1.0",
            "format": fmt,
            "event_count": event_count,
            "date_range": {
                "from": datetime.fromtimestamp(from_ts, tz=timezone.utc).isoformat(),
                "to": datetime.fromtimestamp(to_ts, tz=timezone.utc).isoformat(),
            },
            "categories": categories,
            "filters": {
                "actor_user_id": actor,
                "target_user_id": target,
                "event_actions": event_actions,
            },
            "file_sha256": file_hash,
            "file_size_bytes": file_size,
            "created_at": datetime.fromtimestamp(now_ts(), tz=timezone.utc).isoformat(),
            "created_by": job.get("created_by", ""),
            "signing_key_id": S.audit_export_signing_key_id,
            "contains_pii": True,
        }
        manifest["signature"] = _compute_manifest_signature(manifest)

        T.audit_exports.update_item(
            Key={"export_id": export_id, "sk": "META"},
            UpdateExpression=(
                "SET #st = :st, completed_at = :ca, event_count = :ec, "
                "file_size_bytes = :fs, manifest_sha256 = :ms, events_written = :ew, "
                "export_content = :content, export_manifest = :manifest"
            ),
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":st": "completed",
                ":ca": now_ts(),
                ":ec": event_count,
                ":fs": file_size,
                ":ms": file_hash,
                ":ew": event_count,
                ":content": content,
                ":manifest": json.dumps(manifest),
            },
        )
    except Exception as exc:
        logger.exception("Inline export job %s failed", export_id)
        T.audit_exports.update_item(
            Key={"export_id": export_id, "sk": "META"},
            UpdateExpression="SET #st = :st, error_message = :em",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":st": "failed",
                ":em": str(exc)[:500],
            },
        )


def _compute_manifest_signature(manifest: dict) -> str:
    signable = {k: v for k, v in manifest.items() if k != "signature"}
    payload = json.dumps(signable, sort_keys=True, default=str)
    sig = hmac.new(
        S.audit_export_signing_key.encode(),
        payload.encode(),
        hashlib.sha256,
    ).hexdigest()
    return f"hmac-sha256:{sig}"


def verify_manifest_signature(manifest: dict) -> bool:
    expected_sig = _compute_manifest_signature(manifest)
    actual_sig = manifest.get("signature", "")
    return hmac.compare_digest(expected_sig, actual_sig)
