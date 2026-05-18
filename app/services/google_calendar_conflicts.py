from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict


def _parse_iso(value: str | None) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def detect_sync_conflict(
    *,
    internal_event_snapshot: Dict[str, Any],
    mapping_snapshot: Dict[str, Any],
    provider_error: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    internal_updated = _parse_iso(str(internal_event_snapshot.get("updated_at_utc") or internal_event_snapshot.get("created_at_utc") or ""))
    last_synced = _parse_iso(str(mapping_snapshot.get("last_synced_at_utc") or ""))
    provider_status = int((provider_error or {}).get("provider_status_code") or 0)
    provider_message = str((provider_error or {}).get("message") or "")

    stale_internal = bool(internal_updated and last_synced and internal_updated > last_synced)
    provider_conflict = provider_status in {409, 412}

    if provider_conflict and stale_internal:
        return {
            "is_conflict": True,
            "reason": "etag_mismatch_with_concurrent_internal_edit",
            "provider_status_code": provider_status,
            "provider_message": provider_message,
        }
    if provider_conflict:
        return {
            "is_conflict": True,
            "reason": "etag_mismatch",
            "provider_status_code": provider_status,
            "provider_message": provider_message,
        }
    return {
        "is_conflict": False,
        "reason": "",
        "provider_status_code": provider_status,
        "provider_message": provider_message,
    }
