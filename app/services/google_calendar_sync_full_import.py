from __future__ import annotations

import uuid
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.metrics import record_google_calendar_sync_job, record_google_calendar_sync_latency
from app.services.google_calendar_client import list_google_calendar_events
from app.services.google_calendar_delete_propagation import handle_google_cancelled_event
from app.services.google_calendar_event_mappings import (
    get_event_mapping,
    get_event_mapping_by_google_event,
    upsert_event_mapping,
)
from app.services.google_calendar_mappings import list_calendar_provider_mappings
from app.services.google_calendar_transform import (
    build_google_event_sync_fingerprint,
    map_google_event_to_internal,
)

logger = logging.getLogger(__name__)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_iso(value: str | None) -> datetime:
    raw = str(value or "").strip()
    if not raw:
        return _utc_now()
    return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc)


def _full_import_past_days() -> int:
    value = int(getattr(S, "google_calendar_full_import_past_days", 365) or 365)
    return max(1, min(3650, value))


def _full_import_future_days() -> int:
    value = int(getattr(S, "google_calendar_full_import_future_days", 365) or 365)
    return max(1, min(3650, value))


def _window_bounds(window_start_utc: str | None, window_end_utc: str | None) -> tuple[str, str]:
    if window_start_utc and window_end_utc:
        return (_iso(_parse_iso(window_start_utc)), _iso(_parse_iso(window_end_utc)))
    now = _utc_now()
    start = now - timedelta(days=_full_import_past_days())
    end = now + timedelta(days=_full_import_future_days())
    return (_iso(start), _iso(end))


def _event_key(event_id: str) -> str:
    return f"event#{event_id}"


def _load_event(calendar_id: str, event_id: str) -> Dict[str, Any] | None:
    return T.calendar.get_item(Key={"calendar_id": calendar_id, "sk": _event_key(event_id)}).get("Item")


def _upsert_internal_event_item(
    *,
    internal_calendar_id: str,
    internal_event_id: str,
    mapped_event: Dict[str, Any],
) -> tuple[Dict[str, Any], bool]:
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
    return item, existing is None


def run_google_calendar_full_import_job(
    *,
    user_sub: str,
    connection_id: str,
    window_start_utc: str | None = None,
    window_end_utc: str | None = None,
) -> Dict[str, Any]:
    started = _utc_now()
    time_min, time_max = _window_bounds(window_start_utc, window_end_utc)
    mappings = list_calendar_provider_mappings(user_sub=user_sub, include_inactive=False)
    active_mappings = [m for m in mappings if bool(m.get("active", True))]

    metrics = {
        "user_sub": user_sub,
        "connection_id": connection_id,
        "window_start_utc": time_min,
        "window_end_utc": time_max,
        "calendars_total": len(active_mappings),
        "calendars_processed": 0,
        "google_events_scanned": 0,
        "created": 0,
        "updated": 0,
        "skipped": 0,
        "errors": 0,
        "warnings": 0,
        "error_samples": [],
        "started_at_utc": _iso(started),
        "finished_at_utc": "",
        "duration_seconds": 0,
    }

    for cal_map in active_mappings:
        internal_calendar_id = str(cal_map.get("internal_calendar_id") or "")
        google_calendar_id = str(cal_map.get("google_calendar_id") or "")
        if not internal_calendar_id or not google_calendar_id:
            continue
        page_token: str | None = None
        while True:
            page = list_google_calendar_events(
                user_sub=user_sub,
                connection_id=connection_id,
                google_calendar_id=google_calendar_id,
                page_token=page_token,
                time_min=time_min,
                time_max=time_max,
            )
            for google_event in page.get("items") or []:
                metrics["google_events_scanned"] += 1
                try:
                    if str(google_event.get("status") or "").lower() == "cancelled":
                        result = handle_google_cancelled_event(
                            user_sub=user_sub,
                            internal_calendar_id=internal_calendar_id,
                            google_calendar_id=google_calendar_id,
                            google_event_id=str(google_event.get("id") or ""),
                            reason="google_cancelled",
                        )
                        if result.get("deleted"):
                            metrics["updated"] += 1
                        else:
                            metrics["skipped"] += 1
                        continue
                    mapped = map_google_event_to_internal(
                        google_event=google_event,
                        calendar_timezone="UTC",
                    )
                    mapped_event = mapped["event"]
                    metrics["warnings"] += len(mapped.get("warnings") or [])
                    google_event_id = str((mapped.get("source_metadata") or {}).get("google_event_id") or "")
                    if not google_event_id:
                        raise HTTPException(status_code=400, detail="google event missing id")
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

                    internal_event_id = (
                        str((existing_map or {}).get("internal_event_id") or "").strip() or uuid.uuid4().hex
                    )
                    _, was_created = _upsert_internal_event_item(
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
                    if existing_map:
                        _ = get_event_mapping(
                            user_sub=user_sub,
                            internal_calendar_id=str(existing_map.get("internal_calendar_id") or internal_calendar_id),
                            internal_event_id=str(existing_map.get("internal_event_id") or internal_event_id),
                            include_inactive=True,
                        )
                except Exception as exc:
                    metrics["errors"] += 1
                    if len(metrics["error_samples"]) < 20:
                        metrics["error_samples"].append(str(exc))
                    continue

            page_token = str(page.get("nextPageToken") or "").strip() or None
            if not page_token:
                break
            metrics["calendars_processed"] += 1

    finished = _utc_now()
    metrics["finished_at_utc"] = _iso(finished)
    metrics["duration_seconds"] = max(0, int((finished - started).total_seconds()))
    record_google_calendar_sync_latency(flow="inbound_full", elapsed_seconds=float(metrics["duration_seconds"]))
    record_google_calendar_sync_job(flow="inbound_full", state="created", count=int(metrics["created"]))
    record_google_calendar_sync_job(flow="inbound_full", state="updated", count=int(metrics["updated"]))
    record_google_calendar_sync_job(flow="inbound_full", state="errors", count=int(metrics["errors"]))
    logger.info(
        "google_calendar_full_import_completed",
        extra={
            "correlation_id": f"gcal:full:{user_sub}:{connection_id}:{metrics['started_at_utc']}",
            "user_sub": user_sub,
            "connection_id": connection_id,
            "metrics": metrics,
        },
    )
    return metrics


def handle_google_calendar_full_import_queue_job(job: Dict[str, Any]) -> Dict[str, Any]:
    payload = dict(job or {})
    user_sub = str(payload.get("user_sub") or "").strip()
    connection_id = str(payload.get("connection_id") or "").strip()
    if not user_sub or not connection_id:
        raise HTTPException(status_code=400, detail="user_sub and connection_id are required")
    return run_google_calendar_full_import_job(
        user_sub=user_sub,
        connection_id=connection_id,
        window_start_utc=str(payload.get("window_start_utc") or "").strip() or None,
        window_end_utc=str(payload.get("window_end_utc") or "").strip() or None,
    )
