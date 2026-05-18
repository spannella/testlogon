from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.tables import T
from app.services.google_calendar_audit import emit_google_calendar_audit_event


MAPPING_TYPE = "calendar_provider_mapping"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _pk(user_sub: str) -> str:
    return f"gcal_map#{user_sub}"


def _sk(mapping_id: str) -> str:
    return f"map#{mapping_id}"


def _table():
    return T.calendar


def _load_calendar_meta(calendar_id: str) -> Dict[str, Any]:
    item = _table().get_item(Key={"calendar_id": calendar_id, "sk": "meta"}).get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="calendar not found")
    return item


def _require_calendar_owner(user_sub: str, calendar_id: str) -> None:
    meta = _load_calendar_meta(calendar_id)
    if str(meta.get("owner_user_sub") or "") != user_sub:
        raise HTTPException(status_code=403, detail="calendar owner required for mapping")


def _mapping_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "mapping_id": str(item.get("mapping_id") or ""),
        "provider": "google",
        "user_sub": str(item.get("user_sub") or ""),
        "internal_calendar_id": str(item.get("internal_calendar_id") or ""),
        "google_calendar_id": str(item.get("google_calendar_id") or ""),
        "active": bool(item.get("active", True)),
        "created_at_utc": str(item.get("created_at_utc") or ""),
        "updated_at_utc": str(item.get("updated_at_utc") or ""),
        "unmapped_at_utc": str(item.get("unmapped_at_utc") or ""),
    }


def list_calendar_provider_mappings(*, user_sub: str, include_inactive: bool = False) -> List[Dict[str, Any]]:
    resp = _table().query(
        KeyConditionExpression=Key("calendar_id").eq(_pk(user_sub)),
    )
    items = [it for it in (resp.get("Items") or []) if it.get("type") == MAPPING_TYPE]
    if not include_inactive:
        items = [it for it in items if bool(it.get("active", True))]
    return [_mapping_out(it) for it in items]


def create_calendar_provider_mapping(
    *,
    user_sub: str,
    internal_calendar_id: str,
    google_calendar_id: str,
) -> Dict[str, Any]:
    internal_calendar_id = (internal_calendar_id or "").strip()
    google_calendar_id = (google_calendar_id or "").strip()
    if not internal_calendar_id or not google_calendar_id:
        raise HTTPException(status_code=400, detail="internal_calendar_id and google_calendar_id are required")

    _require_calendar_owner(user_sub, internal_calendar_id)

    existing = list_calendar_provider_mappings(user_sub=user_sub, include_inactive=True)

    for m in existing:
        if m["active"] and m["internal_calendar_id"] == internal_calendar_id:
            raise HTTPException(status_code=409, detail="internal calendar already has an active google mapping")

    for m in existing:
        if m["internal_calendar_id"] == internal_calendar_id and m["google_calendar_id"] == google_calendar_id:
            if m["active"]:
                raise HTTPException(status_code=409, detail="mapping already exists")
            item = _table().get_item(Key={"calendar_id": _pk(user_sub), "sk": _sk(m["mapping_id"])}).get("Item")
            if not item:
                break
            item["active"] = True
            item["unmapped_at_utc"] = ""
            item["updated_at_utc"] = _utc_now_iso()
            _table().put_item(Item=item)
            emit_google_calendar_audit_event(
                event="google_calendar_mapping_reactivated",
                actor_user_sub=user_sub,
                outcome="success",
                target_type="mapping",
                target_id=m["mapping_id"],
                mapping_id=m["mapping_id"],
                internal_calendar_id=internal_calendar_id,
                google_calendar_id=google_calendar_id,
            )
            return _mapping_out(item)

    mapping_id = uuid.uuid4().hex
    now = _utc_now_iso()
    item = {
        "calendar_id": _pk(user_sub),
        "sk": _sk(mapping_id),
        "type": MAPPING_TYPE,
        "provider": "google",
        "mapping_id": mapping_id,
        "user_sub": user_sub,
        "internal_calendar_id": internal_calendar_id,
        "google_calendar_id": google_calendar_id,
        "active": True,
        "created_at_utc": now,
        "updated_at_utc": now,
        "unmapped_at_utc": "",
    }
    _table().put_item(Item=item)
    emit_google_calendar_audit_event(
        event="google_calendar_mapping_created",
        actor_user_sub=user_sub,
        outcome="success",
        target_type="mapping",
        target_id=mapping_id,
        mapping_id=mapping_id,
        internal_calendar_id=internal_calendar_id,
        google_calendar_id=google_calendar_id,
    )
    return _mapping_out(item)


def unmap_calendar_provider_mapping(*, user_sub: str, mapping_id: str) -> Dict[str, Any]:
    item = _table().get_item(Key={"calendar_id": _pk(user_sub), "sk": _sk(mapping_id)}).get("Item")
    if not item or item.get("type") != MAPPING_TYPE:
        raise HTTPException(status_code=404, detail="mapping not found")

    if not bool(item.get("active", True)):
        return _mapping_out(item)

    item["active"] = False
    item["unmapped_at_utc"] = _utc_now_iso()
    item["updated_at_utc"] = _utc_now_iso()
    _table().put_item(Item=item)
    emit_google_calendar_audit_event(
        event="google_calendar_mapping_unmapped",
        actor_user_sub=user_sub,
        outcome="success",
        target_type="mapping",
        target_id=mapping_id,
        mapping_id=mapping_id,
        internal_calendar_id=item.get("internal_calendar_id"),
        google_calendar_id=item.get("google_calendar_id"),
    )
    return _mapping_out(item)
