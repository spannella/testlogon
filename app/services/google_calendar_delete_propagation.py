from __future__ import annotations

from typing import Any, Dict

from fastapi import HTTPException

from app.core.tables import T
from app.services.google_calendar_event_mappings import (
    get_event_mapping,
    get_event_mapping_by_google_event,
    mark_event_tombstone,
)


def _event_key(event_id: str) -> str:
    return f"event#{event_id}"


def handle_google_cancelled_event(
    *,
    user_sub: str,
    internal_calendar_id: str,
    google_calendar_id: str,
    google_event_id: str,
    reason: str = "google_cancelled",
) -> Dict[str, Any]:
    try:
        mapping = get_event_mapping_by_google_event(
            user_sub=user_sub,
            google_calendar_id=google_calendar_id,
            google_event_id=google_event_id,
            include_inactive=True,
        )
    except HTTPException as exc:
        if exc.status_code == 404:
            return {
                "deleted": False,
                "tombstoned": False,
                "idempotent": True,
                "internal_event_id": "",
                "reason": "mapping_not_found",
            }
        raise

    resolved_internal_calendar_id = str(mapping.get("internal_calendar_id") or internal_calendar_id)
    internal_event_id = str(mapping.get("internal_event_id") or "")
    if not internal_event_id:
        return {
            "deleted": False,
            "tombstoned": False,
            "idempotent": True,
            "internal_event_id": "",
            "reason": "mapping_missing_internal_event",
        }

    tombstoned = bool(mapping.get("tombstone", False))
    if not tombstoned:
        marked = mark_event_tombstone(
            user_sub=user_sub,
            internal_calendar_id=resolved_internal_calendar_id,
            internal_event_id=internal_event_id,
            reason=reason,
        )
        tombstoned = bool(marked.get("tombstone", False))
    else:
        _ = get_event_mapping(
            user_sub=user_sub,
            internal_calendar_id=resolved_internal_calendar_id,
            internal_event_id=internal_event_id,
            include_inactive=True,
        )

    key = {"calendar_id": resolved_internal_calendar_id, "sk": _event_key(internal_event_id)}
    existing = T.calendar.get_item(Key=key).get("Item")
    if not existing:
        return {
            "deleted": False,
            "tombstoned": tombstoned,
            "idempotent": True,
            "internal_event_id": internal_event_id,
            "reason": "event_already_absent",
        }

    T.calendar.delete_item(Key=key)
    return {
        "deleted": True,
        "tombstoned": tombstoned,
        "idempotent": False,
        "internal_event_id": internal_event_id,
        "reason": reason,
    }
