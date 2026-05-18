from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import HTTPException

from app.core.tables import T
from app.metrics import record_google_calendar_sync_job, record_google_calendar_sync_latency
from app.services.google_calendar_client import list_google_calendar_events
from app.services.google_calendar_connections import (
    get_calendar_provider_connection,
    update_calendar_provider_connection_sync_status,
)
from app.services.google_calendar_event_mappings import (
    get_event_mapping_by_google_event,
    upsert_event_mapping,
)
from app.services.google_calendar_delete_propagation import handle_google_cancelled_event
from app.services.google_calendar_mappings import list_calendar_provider_mappings
from app.services.google_calendar_sync_full_import import run_google_calendar_full_import_job
from app.services.google_calendar_transform import (
    build_google_event_sync_fingerprint,
    map_google_event_to_internal,
)

logger = logging.getLogger(__name__)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _event_key(event_id: str) -> str:
    return f"event#{event_id}"


def _load_event(calendar_id: str, event_id: str) -> Dict[str, Any] | None:
    return T.calendar.get_item(Key={"calendar_id": calendar_id, "sk": _event_key(event_id)}).get("Item")


def _upsert_internal_event_item(
    *,
    internal_calendar_id: str,
    internal_event_id: str,
    mapped_event: Dict[str, Any],
) -> bool:
    existing = _load_event(internal_calendar_id, internal_event_id)
    now = _iso(_utc_now())
    item = {
        "calendar_id": internal_calendar_id,
        "sk": _event_key(internal_event_id),
        "type": "event",
        "event_id": internal_event_id,
        "name": str(mapped_event.get("name") or "(untitled)"),
        "description": str(mapped_event.get("description") or ""),
        "attendees": list(mapped_event.get("attendees") or []),
        "booking_enabled": False,
        "approval_required": False,
        "status": str(mapped_event.get("status") or "busy"),
        "category": mapped_event.get("category"),
        "recurrence_rule": mapped_event.get("recurrence_rule"),
        "exdates_utc": mapped_event.get("exdates_utc"),
        "recurrence_overrides": mapped_event.get("recurrence_overrides"),
        "timezone": str(mapped_event.get("timezone") or "UTC"),
        "all_day": bool(mapped_event.get("all_day", False)),
        "all_day_date": mapped_event.get("all_day_date"),
        "start_utc": mapped_event.get("start_utc"),
        "end_utc": mapped_event.get("end_utc"),
        "created_at_utc": str((existing or {}).get("created_at_utc") or now),
        "updated_at_utc": now,
    }
    T.calendar.put_item(Item=item)
    return existing is None


def _parse_cursor(raw: str | None) -> Dict[str, str]:
    text = str(raw or "").strip()
    if not text:
        return {}
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return {}
    if not isinstance(payload, dict):
        return {}
    out: Dict[str, str] = {}
    for key, value in payload.items():
        k = str(key or "").strip()
        v = str(value or "").strip()
        if k and v:
            out[k] = v
    return out


def _encode_cursor_map(cursor_map: Dict[str, str]) -> str:
    return json.dumps({k: cursor_map[k] for k in sorted(cursor_map)}, separators=(",", ":"), sort_keys=True)


def _is_invalid_sync_token(exc: HTTPException) -> bool:
    detail = exc.detail if isinstance(exc.detail, dict) else {}
    provider_status = int(detail.get("provider_status_code") or 0) if isinstance(detail, dict) else 0
    message = str(detail.get("message") or "").lower() if isinstance(detail, dict) else str(exc.detail).lower()
    return provider_status == 410 or "sync token" in message and "invalid" in message


def run_google_calendar_incremental_sync_job(
    *,
    user_sub: str,
    connection_id: str,
) -> Dict[str, Any]:
    started = _utc_now()
    connection = get_calendar_provider_connection(
        user_sub=user_sub,
        connection_id=connection_id,
        include_tokens=False,
        include_inactive=False,
    )
    cursor_map = _parse_cursor(connection.get("sync_cursor"))
    next_cursor_map = dict(cursor_map)
    mappings = list_calendar_provider_mappings(user_sub=user_sub, include_inactive=False)
    active_mappings = [m for m in mappings if bool(m.get("active", True))]

    metrics = {
        "user_sub": user_sub,
        "connection_id": connection_id,
        "calendars_total": len(active_mappings),
        "calendars_processed": 0,
        "changed_resources": 0,
        "created": 0,
        "updated": 0,
        "deleted": 0,
        "skipped": 0,
        "errors": 0,
        "warnings": 0,
        "fallback_full_syncs": 0,
        "started_at_utc": _iso(started),
        "finished_at_utc": "",
        "duration_seconds": 0,
    }

    for cal_map in active_mappings:
        internal_calendar_id = str(cal_map.get("internal_calendar_id") or "")
        google_calendar_id = str(cal_map.get("google_calendar_id") or "")
        if not internal_calendar_id or not google_calendar_id:
            continue
        page_token = None
        sync_token = cursor_map.get(google_calendar_id)
        latest_sync_token = sync_token
        calendar_failed = False
        while True:
            try:
                page = list_google_calendar_events(
                    user_sub=user_sub,
                    connection_id=connection_id,
                    google_calendar_id=google_calendar_id,
                    sync_token=sync_token,
                    page_token=page_token,
                )
            except HTTPException as exc:
                if sync_token and _is_invalid_sync_token(exc):
                    run_google_calendar_full_import_job(
                        user_sub=user_sub,
                        connection_id=connection_id,
                    )
                    metrics["fallback_full_syncs"] += 1
                    sync_token = None
                    page_token = None
                    latest_sync_token = None
                    continue
                metrics["errors"] += 1
                calendar_failed = True
                break

            for google_event in page.get("items") or []:
                metrics["changed_resources"] += 1
                try:
                    google_event_id = str(google_event.get("id") or "").strip()
                    if not google_event_id:
                        metrics["skipped"] += 1
                        continue
                    status = str(google_event.get("status") or "").lower()
                    if status == "cancelled":
                        result = handle_google_cancelled_event(
                            user_sub=user_sub,
                            internal_calendar_id=internal_calendar_id,
                            google_calendar_id=google_calendar_id,
                            google_event_id=google_event_id,
                            reason="google_cancelled",
                        )
                        if result.get("deleted"):
                            metrics["deleted"] += 1
                        else:
                            metrics["skipped"] += 1
                        continue

                    mapped = map_google_event_to_internal(google_event=google_event, calendar_timezone="UTC")
                    mapped_event = mapped["event"]
                    metrics["warnings"] += len(mapped.get("warnings") or [])
                    fingerprint = build_google_event_sync_fingerprint(google_event=google_event)
                    provider_etag = str((mapped.get("source_metadata") or {}).get("google_etag") or "")
                    provider_updated = str((mapped.get("source_metadata") or {}).get("google_updated") or "")
                    try:
                        existing_map = get_event_mapping_by_google_event(
                            user_sub=user_sub,
                            google_calendar_id=google_calendar_id,
                            google_event_id=google_event_id,
                            include_inactive=True,
                        )
                    except HTTPException as exc:
                        if exc.status_code != 404:
                            raise
                        existing_map = None

                    if existing_map and str(existing_map.get("sync_fingerprint") or "") == fingerprint:
                        metrics["skipped"] += 1
                        continue

                    internal_event_id = str((existing_map or {}).get("internal_event_id") or "").strip() or uuid.uuid4().hex
                    was_created = _upsert_internal_event_item(
                        internal_calendar_id=internal_calendar_id,
                        internal_event_id=internal_event_id,
                        mapped_event=mapped_event,
                    )
                    if was_created:
                        metrics["created"] += 1
                    else:
                        metrics["updated"] += 1

                    upsert_event_mapping(
                        user_sub=user_sub,
                        internal_calendar_id=internal_calendar_id,
                        internal_event_id=internal_event_id,
                        google_calendar_id=google_calendar_id,
                        google_event_id=google_event_id,
                        provider_etag=provider_etag,
                        sync_fingerprint=fingerprint,
                        last_synced_at_utc=provider_updated or _iso(_utc_now()),
                    )
                except Exception:
                    metrics["errors"] += 1
                    continue

            page_token = str(page.get("nextPageToken") or "").strip() or None
            if page.get("nextSyncToken"):
                latest_sync_token = str(page.get("nextSyncToken") or "").strip() or latest_sync_token
            if not page_token:
                break
            sync_token = None

        if not calendar_failed:
            if latest_sync_token:
                next_cursor_map[google_calendar_id] = latest_sync_token
            metrics["calendars_processed"] += 1

    # Atomic cursor commit only after successful run with no errors.
    if metrics["errors"] == 0:
        update_calendar_provider_connection_sync_status(
            user_sub=user_sub,
            connection_id=connection_id,
            sync_health="healthy",
            last_sync_status="success",
            last_sync_error="",
            sync_cursor=_encode_cursor_map(next_cursor_map),
            reauth_required=False,
            last_sync_at_utc=_iso(_utc_now()),
        )
    else:
        update_calendar_provider_connection_sync_status(
            user_sub=user_sub,
            connection_id=connection_id,
            sync_health="degraded",
            last_sync_status="error",
            last_sync_error="incremental sync completed with errors",
        )

    finished = _utc_now()
    metrics["finished_at_utc"] = _iso(finished)
    metrics["duration_seconds"] = max(0, int((finished - started).total_seconds()))
    record_google_calendar_sync_latency(flow="inbound_incremental", elapsed_seconds=float(metrics["duration_seconds"]))
    record_google_calendar_sync_job(flow="inbound_incremental", state="created", count=int(metrics["created"]))
    record_google_calendar_sync_job(flow="inbound_incremental", state="updated", count=int(metrics["updated"]))
    record_google_calendar_sync_job(flow="inbound_incremental", state="deleted", count=int(metrics["deleted"]))
    record_google_calendar_sync_job(flow="inbound_incremental", state="errors", count=int(metrics["errors"]))
    logger.info(
        "google_calendar_incremental_sync_completed",
        extra={
            "correlation_id": f"gcal:incremental:{user_sub}:{connection_id}:{metrics['started_at_utc']}",
            "user_sub": user_sub,
            "connection_id": connection_id,
            "metrics": metrics,
        },
    )
    return metrics


def handle_google_calendar_incremental_sync_queue_job(job: Dict[str, Any]) -> Dict[str, Any]:
    payload = dict(job or {})
    user_sub = str(payload.get("user_sub") or "").strip()
    connection_id = str(payload.get("connection_id") or "").strip()
    if not user_sub or not connection_id:
        raise HTTPException(status_code=400, detail="user_sub and connection_id are required")
    return run_google_calendar_incremental_sync_job(user_sub=user_sub, connection_id=connection_id)
