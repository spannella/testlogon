from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable

from app.services.calendar_integrations.credentials import record_apple_conflict_audit


def _parse_ts(value: str | None) -> datetime:
    if not value:
        return datetime.fromtimestamp(0, tz=timezone.utc)
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return datetime.fromtimestamp(0, tz=timezone.utc)


def resolve_apple_event_conflict(
    *,
    local_event: dict[str, Any],
    remote_event: dict[str, Any],
    protected_local_fields: Iterable[str] = ("internal_notes", "color", "labels", "private_metadata"),
) -> dict[str, Any]:
    local_ts = _parse_ts(str(local_event.get("updated_at") or local_event.get("updatedAt") or ""))
    remote_ts = _parse_ts(str(remote_event.get("updated_at") or remote_event.get("updatedAt") or ""))

    if remote_ts > local_ts:
        winner = "remote"
    elif local_ts > remote_ts:
        winner = "local"
    else:
        # deterministic tie-breaker
        winner = "remote"

    base = dict(remote_event if winner == "remote" else local_event)
    for field in protected_local_fields:
        if field in local_event:
            base[field] = local_event.get(field)

    return {
        "winner": winner,
        "merged_event": base,
        "local_updated_at": local_ts.isoformat(),
        "remote_updated_at": remote_ts.isoformat(),
    }


def resolve_and_audit_apple_event_conflict(
    *,
    connection_id: str,
    external_calendar_id: str,
    internal_event_id: str | None,
    remote_uid: str | None,
    local_event: dict[str, Any],
    remote_event: dict[str, Any],
    protected_local_fields: Iterable[str] = ("internal_notes", "color", "labels", "private_metadata"),
) -> dict[str, Any]:
    resolved = resolve_apple_event_conflict(
        local_event=local_event,
        remote_event=remote_event,
        protected_local_fields=protected_local_fields,
    )
    record_apple_conflict_audit(
        connection_id=connection_id,
        external_calendar_id=external_calendar_id,
        internal_event_id=internal_event_id,
        remote_uid=remote_uid,
        resolution=f"{resolved['winner']}_wins_lww",
        local_updated_at=resolved["local_updated_at"],
        remote_updated_at=resolved["remote_updated_at"],
        details={
            "protected_fields": list(protected_local_fields),
            "merged_keys": sorted(list(resolved["merged_event"].keys())),
        },
    )
    return resolved
