from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T


MAPPING_TYPE = "calendar_event_provider_mapping"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _pk(user_sub: str) -> str:
    return f"gcal_evtmap#{user_sub}"


def _sk(internal_calendar_id: str, internal_event_id: str) -> str:
    return f"map#{internal_calendar_id}#{internal_event_id}"


def _table():
    return T.calendar


def _retention_days() -> int:
    raw = int(getattr(S, "google_calendar_event_tombstone_retention_days", 90) or 90)
    return max(1, min(3650, raw))


def _mapping_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "user_sub": str(item.get("user_sub") or ""),
        "internal_calendar_id": str(item.get("internal_calendar_id") or ""),
        "internal_event_id": str(item.get("internal_event_id") or ""),
        "google_calendar_id": str(item.get("google_calendar_id") or ""),
        "google_event_id": str(item.get("google_event_id") or ""),
        "provider_etag": str(item.get("provider_etag") or ""),
        "sync_fingerprint": str(item.get("sync_fingerprint") or ""),
        "last_synced_at_utc": str(item.get("last_synced_at_utc") or ""),
        "active": bool(item.get("active", True)),
        "tombstone": bool(item.get("tombstone", False)),
        "tombstone_reason": str(item.get("tombstone_reason") or ""),
        "tombstone_expires_at_utc": str(item.get("tombstone_expires_at_utc") or ""),
        "updated_at_utc": str(item.get("updated_at_utc") or ""),
        "sync_state": str(item.get("sync_state") or "ok"),
        "conflict_reason": str(item.get("conflict_reason") or ""),
        "conflict_detected_at_utc": str(item.get("conflict_detected_at_utc") or ""),
        "conflict_internal_snapshot": item.get("conflict_internal_snapshot"),
        "conflict_provider_snapshot": item.get("conflict_provider_snapshot"),
    }


def _list_user_items(user_sub: str) -> List[Dict[str, Any]]:
    resp = _table().query(KeyConditionExpression=Key("calendar_id").eq(_pk(user_sub)))
    return [it for it in (resp.get("Items") or []) if it.get("type") == MAPPING_TYPE]


def upsert_event_mapping(
    *,
    user_sub: str,
    internal_calendar_id: str,
    internal_event_id: str,
    google_calendar_id: str,
    google_event_id: str,
    provider_etag: str | None,
    sync_fingerprint: str | None,
    last_synced_at_utc: str | None = None,
) -> Dict[str, Any]:
    if not internal_calendar_id or not internal_event_id or not google_calendar_id or not google_event_id:
        raise HTTPException(status_code=400, detail="mapping ids are required")

    now = _utc_now()
    now_iso = _iso(now)
    existing = _table().get_item(
        Key={"calendar_id": _pk(user_sub), "sk": _sk(internal_calendar_id, internal_event_id)}
    ).get("Item")

    if existing and bool(existing.get("tombstone", False)):
        expires_raw = str(existing.get("tombstone_expires_at_utc") or "")
        if expires_raw:
            try:
                if _parse_iso(expires_raw) > now:
                    raise HTTPException(status_code=409, detail="event mapping is tombstoned and cannot be recreated yet")
            except ValueError:
                raise HTTPException(status_code=409, detail="event mapping is tombstoned and cannot be recreated yet")

    # enforce bi-directional uniqueness for active mappings
    for item in _list_user_items(user_sub):
        if not bool(item.get("active", True)):
            continue
        if (
            str(item.get("google_calendar_id") or "") == google_calendar_id
            and str(item.get("google_event_id") or "") == google_event_id
            and (
                str(item.get("internal_calendar_id") or "") != internal_calendar_id
                or str(item.get("internal_event_id") or "") != internal_event_id
            )
        ):
            raise HTTPException(status_code=409, detail="google event already mapped to another internal event")

    item = {
        "calendar_id": _pk(user_sub),
        "sk": _sk(internal_calendar_id, internal_event_id),
        "type": MAPPING_TYPE,
        "provider": "google",
        "user_sub": user_sub,
        "internal_calendar_id": internal_calendar_id,
        "internal_event_id": internal_event_id,
        "google_calendar_id": google_calendar_id,
        "google_event_id": google_event_id,
        "provider_etag": provider_etag or "",
        "sync_fingerprint": sync_fingerprint or "",
        "last_synced_at_utc": last_synced_at_utc or now_iso,
        "active": True,
        "tombstone": False,
        "tombstone_reason": "",
        "tombstone_expires_at_utc": "",
        "updated_at_utc": now_iso,
        "sync_state": "ok",
        "conflict_reason": "",
        "conflict_detected_at_utc": "",
        "conflict_internal_snapshot": None,
        "conflict_provider_snapshot": None,
    }
    _table().put_item(Item=item)
    return _mapping_out(item)


def mark_event_sync_conflict(
    *,
    user_sub: str,
    internal_calendar_id: str,
    internal_event_id: str,
    reason: str,
    internal_snapshot: Dict[str, Any] | None = None,
    provider_snapshot: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    item = _table().get_item(Key={"calendar_id": _pk(user_sub), "sk": _sk(internal_calendar_id, internal_event_id)}).get("Item")
    if not item or item.get("type") != MAPPING_TYPE:
        raise HTTPException(status_code=404, detail="event mapping not found")
    now_iso = _iso(_utc_now())
    item["sync_state"] = "conflict"
    item["conflict_reason"] = reason or "conflict"
    item["conflict_detected_at_utc"] = now_iso
    item["conflict_internal_snapshot"] = dict(internal_snapshot or {})
    item["conflict_provider_snapshot"] = dict(provider_snapshot or {})
    item["updated_at_utc"] = now_iso
    _table().put_item(Item=item)
    return _mapping_out(item)


def get_event_mapping(
    *,
    user_sub: str,
    internal_calendar_id: str,
    internal_event_id: str,
    include_inactive: bool = False,
) -> Dict[str, Any]:
    item = _table().get_item(Key={"calendar_id": _pk(user_sub), "sk": _sk(internal_calendar_id, internal_event_id)}).get("Item")
    if not item or item.get("type") != MAPPING_TYPE:
        raise HTTPException(status_code=404, detail="event mapping not found")
    if not include_inactive and not bool(item.get("active", True)):
        raise HTTPException(status_code=404, detail="event mapping not found")
    return _mapping_out(item)


def get_event_mapping_by_google_event(
    *,
    user_sub: str,
    google_calendar_id: str,
    google_event_id: str,
    include_inactive: bool = False,
) -> Dict[str, Any]:
    for item in _list_user_items(user_sub):
        if (
            str(item.get("google_calendar_id") or "") == google_calendar_id
            and str(item.get("google_event_id") or "") == google_event_id
        ):
            if not include_inactive and not bool(item.get("active", True)):
                raise HTTPException(status_code=404, detail="event mapping not found")
            return _mapping_out(item)
    raise HTTPException(status_code=404, detail="event mapping not found")


def mark_event_tombstone(
    *,
    user_sub: str,
    internal_calendar_id: str,
    internal_event_id: str,
    reason: str,
) -> Dict[str, Any]:
    item = _table().get_item(Key={"calendar_id": _pk(user_sub), "sk": _sk(internal_calendar_id, internal_event_id)}).get("Item")
    if not item or item.get("type") != MAPPING_TYPE:
        raise HTTPException(status_code=404, detail="event mapping not found")

    now = _utc_now()
    expires_at = now + timedelta(days=_retention_days())
    item["active"] = False
    item["tombstone"] = True
    item["tombstone_reason"] = reason or "deleted"
    item["tombstone_expires_at_utc"] = _iso(expires_at)
    item["updated_at_utc"] = _iso(now)
    _table().put_item(Item=item)
    return _mapping_out(item)


def purge_expired_event_tombstones(*, user_sub: str, now_utc: datetime | None = None) -> int:
    now_dt = now_utc or _utc_now()
    removed = 0
    for item in _list_user_items(user_sub):
        if not bool(item.get("tombstone", False)):
            continue
        expires_raw = str(item.get("tombstone_expires_at_utc") or "")
        if not expires_raw:
            continue
        try:
            expires_at = _parse_iso(expires_raw)
        except ValueError:
            expires_at = now_dt
        if expires_at <= now_dt:
            _table().delete_item(Key={"calendar_id": str(item.get("calendar_id")), "sk": str(item.get("sk"))})
            removed += 1
    return removed
