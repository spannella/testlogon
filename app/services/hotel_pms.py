"""QloApps hotel-PMS service (HTL-001 + HTL-002).

Additive + flag-gated (``HOTEL_PMS_ENABLED``, default OFF). Every public
function calls ``_require_enabled()`` first; when the flag is off the entire
module is dormant and the platform is byte-for-byte unchanged.

SECOPS-007 parity: identical DynamoDB code in dev (moto) and prod (real DDB);
no ``dev_mode`` branch anywhere in this file.
"""
from __future__ import annotations

import hashlib
from typing import Any

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

# ---------------------------------------------------------------------------
# Flag gate (HTL-001)
# ---------------------------------------------------------------------------


def _flag_on() -> bool:
    return bool(getattr(S, "hotel_pms_enabled", False))


def _require_enabled() -> None:
    if not _flag_on():
        raise HTTPException(status_code=404, detail="Hotel PMS is not enabled")


# ---------------------------------------------------------------------------
# Audit wrapper (copied from app/services/inventory.py:92-98)
# ---------------------------------------------------------------------------


def _audit(event: str, user_sub: str, **fields: Any) -> None:
    try:
        from app.services.alerts import audit_event
        audit_event(event, user_sub or "system", None, **fields)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Hotel-level helpers (HTL-001)
# ---------------------------------------------------------------------------


def _hotel_id(owner_sub: str, name: str) -> str:
    return hashlib.sha256(f"{owner_sub}|{name}".encode()).hexdigest()[:32]


def _meta_key(hotel_id: str) -> dict:
    return {"hotel_id": hotel_id, "sk": "META"}


def _to_int(v: Any, default: int = 0) -> int:
    try:
        return int(v) if v is not None else default
    except (TypeError, ValueError):
        return default


def _coerce_hotel(item: dict) -> dict:
    """Coerce Decimal numerics to int for the hotel header row."""
    for field in ("star_rating", "created_at", "updated_at"):
        if field in item:
            item[field] = _to_int(item[field])
    return item


# ---------------------------------------------------------------------------
# Hotel CRUD service functions (HTL-001)
# ---------------------------------------------------------------------------


def create_hotel(
    owner_sub: str,
    *,
    name: str,
    description: str = "",
    star_rating: int = 3,
    address: dict,
    check_in_time: str = "15:00",
    check_out_time: str = "11:00",
    policies: dict | None = None,
    contact: dict | None = None,
    photo_urls: list[str] | None = None,
) -> dict:
    """Create a hotel header row (idempotent on owner_sub+name)."""
    _require_enabled()
    hid = _hotel_id(owner_sub, name)
    ts = now_ts()
    item: dict = {
        "hotel_id": hid,
        "sk": "META",
        "owner_sub": owner_sub,
        "name": name,
        "description": description,
        "star_rating": star_rating,
        "address": address or {},
        "check_in_time": check_in_time,
        "check_out_time": check_out_time,
        "policies": policies or {
            "cancellation_text": "",
            "pet_policy": "",
            "smoking": False,
            "children": True,
        },
        "contact": contact or {"phone": "", "email": "", "website": ""},
        "photo_urls": photo_urls if photo_urls is not None else [],
        "status": "active",
        "created_at": ts,
        "updated_at": ts,
    }
    try:
        T.hotels.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(hotel_id)",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            # Idempotent: return the existing hotel
            existing = get_hotel(hid)
            return existing  # type: ignore[return-value]
        raise
    _audit("hotel.created", owner_sub, hotel_id=hid, name=name)
    return _coerce_hotel(item)


def get_hotel(hotel_id: str) -> dict | None:
    """Return the hotel META row, or None if not found."""
    _require_enabled()
    resp = T.hotels.get_item(Key=_meta_key(hotel_id))
    item = resp.get("Item")
    if item is None:
        return None
    return _coerce_hotel(item)


def update_hotel(hotel_id: str, *, user_sub: str, **kwargs: Any) -> dict:
    """Partially update a hotel header row."""
    _require_enabled()
    existing = get_hotel(hotel_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="Hotel not found")

    allowed = {
        "name", "description", "star_rating", "address",
        "check_in_time", "check_out_time", "policies", "contact", "photo_urls",
    }
    updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
    ts = now_ts()
    updates["updated_at"] = ts

    # Build SET expression
    expr_parts = []
    expr_names: dict = {}
    expr_values: dict = {}
    for i, (k, v) in enumerate(updates.items()):
        # 'name' is a DynamoDB reserved word — use expression attribute name
        alias = f"#f{i}"
        val_alias = f":v{i}"
        expr_names[alias] = k
        expr_values[val_alias] = v
        expr_parts.append(f"{alias} = {val_alias}")

    T.hotels.update_item(
        Key=_meta_key(hotel_id),
        UpdateExpression="SET " + ", ".join(expr_parts),
        ExpressionAttributeNames=expr_names,
        ExpressionAttributeValues=expr_values,
    )
    _audit("hotel.updated", user_sub, hotel_id=hotel_id, fields=list(updates.keys()))
    return get_hotel(hotel_id)  # type: ignore[return-value]


def archive_hotel(hotel_id: str, *, user_sub: str) -> dict:
    """Soft-archive a hotel (status → 'archived')."""
    _require_enabled()
    ts = now_ts()
    T.hotels.update_item(
        Key=_meta_key(hotel_id),
        UpdateExpression="SET #status = :s, updated_at = :u",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={":s": "archived", ":u": ts},
    )
    _audit("hotel.archived", user_sub, hotel_id=hotel_id)
    return get_hotel(hotel_id)  # type: ignore[return-value]


def list_hotels(
    owner_sub: str,
    *,
    status: str | None = None,
    cursor: str | None = None,
    limit: int = 50,
) -> dict:
    """List a hotelier's hotels via GSI_OWNER (newest-first).

    Returns the standard ``{items, count, cursor}`` shape.
    """
    _require_enabled()
    from app.core.cursor import decode_cursor, encode_cursor

    kwargs: dict = {
        "IndexName": "GSI_OWNER",
        "KeyConditionExpression": Key("owner_sub").eq(owner_sub),
        "ScanIndexForward": False,
        "Limit": min(limit, 200),
    }
    if status is not None:
        kwargs["FilterExpression"] = "attribute_exists(#st) AND #st = :sv"
        kwargs.setdefault("ExpressionAttributeNames", {})["#st"] = "status"
        kwargs.setdefault("ExpressionAttributeValues", {})[":sv"] = status
    if cursor:
        lek = decode_cursor(cursor)
        if lek:
            kwargs["ExclusiveStartKey"] = lek

    resp = T.hotels.query(**kwargs)
    items = [_coerce_hotel(i) for i in resp.get("Items", [])]
    next_key = resp.get("LastEvaluatedKey")
    next_cursor = encode_cursor(next_key) if next_key else None
    return {"items": items, "count": len(items), "cursor": next_cursor}


# ---------------------------------------------------------------------------
# Amenity helpers (HTL-002)
# ---------------------------------------------------------------------------


def _amenity_id(name: str) -> str:
    return hashlib.sha256(f"amenity|{name}".encode()).hexdigest()[:32]


def _coerce_amenity(item: dict) -> dict:
    if "created_at" in item:
        item["created_at"] = _to_int(item["created_at"])
    # Normalise empty string icon to None for callers
    if item.get("icon") == "":
        item["icon"] = None
    return item


def _target_partition(target_type: str, target_id: str) -> tuple[Any, str, str]:
    """Resolve a target to (table_handle, pk_attr_name, pk_value).

    ``room_type`` is forward-compatible surface — raises 422 until
    the Room Type cluster wires its partition.
    """
    if target_type == "hotel":
        return (T.hotels, "hotel_id", target_id)
    raise HTTPException(status_code=422, detail="unsupported target_type")


# ---------------------------------------------------------------------------
# Amenity CRUD + attach/detach (HTL-002)
# ---------------------------------------------------------------------------


def create_amenity(*, name: str, category: str, icon: str | None = None, user_sub: str) -> dict:
    """Create a dictionary entry (idempotent on name)."""
    _require_enabled()
    aid = _amenity_id(name)
    ts = now_ts()
    item: dict = {
        "amenity_id": aid,
        "sk": "META",
        "name": name,
        "category": category,
        "icon": icon or "",
        "created_at": ts,
    }
    try:
        T.hotel_amenities.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(amenity_id)",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            resp = T.hotel_amenities.get_item(Key={"amenity_id": aid, "sk": "META"})
            existing = resp.get("Item", item)
            return _coerce_amenity(existing)
        raise
    _audit("hotel.amenity.created", user_sub, amenity_id=aid, name=name)
    return _coerce_amenity(item)


def list_amenities(*, category: str | None = None) -> list[dict]:
    """List dictionary entries, optionally filtered by category."""
    _require_enabled()
    if category is not None:
        resp = T.hotel_amenities.query(
            IndexName="GSI_CATEGORY",
            KeyConditionExpression=Key("category").eq(category),
        )
        items = resp.get("Items", [])
    else:
        # Scan the (tiny global) dictionary filtered to META rows
        resp = T.hotel_amenities.scan(
            FilterExpression="sk = :m",
            ExpressionAttributeValues={":m": "META"},
        )
        items = resp.get("Items", [])
    return sorted([_coerce_amenity(i) for i in items], key=lambda x: x.get("name", ""))


def attach_amenity(
    *, target_type: str, target_id: str, amenity_id: str, user_sub: str
) -> dict:
    """Attach an amenity to a target (idempotent)."""
    _require_enabled()
    # Validate amenity exists
    a_resp = T.hotel_amenities.get_item(Key={"amenity_id": amenity_id, "sk": "META"})
    if not a_resp.get("Item"):
        raise HTTPException(status_code=404, detail="amenity not found")
    # Validate target exists
    table, pk_attr, pk_val = _target_partition(target_type, target_id)
    t_resp = table.get_item(Key={pk_attr: pk_val, "sk": "META"})
    if not t_resp.get("Item"):
        raise HTTPException(status_code=404, detail="target not found")

    ts = now_ts()
    assoc: dict = {
        pk_attr: pk_val,
        "sk": f"AMEN#{amenity_id}",
        "amenity_id": amenity_id,
        "target_type": target_type,
        "created_at": ts,
    }
    try:
        table.put_item(
            Item=assoc,
            ConditionExpression="attribute_not_exists(sk)",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            # Already attached — return existing
            existing_resp = table.get_item(
                Key={pk_attr: pk_val, "sk": f"AMEN#{amenity_id}"}
            )
            existing = existing_resp.get("Item", assoc)
            existing["created_at"] = _to_int(existing.get("created_at", ts))
            return existing
        raise
    _audit(
        "hotel.amenity.attached",
        user_sub,
        amenity_id=amenity_id,
        target_type=target_type,
        target_id=target_id,
    )
    assoc["created_at"] = _to_int(assoc["created_at"])
    return assoc


def detach_amenity(
    *, target_type: str, target_id: str, amenity_id: str, user_sub: str
) -> bool:
    """Detach an amenity from a target. Returns True if deleted, False if absent."""
    _require_enabled()
    table, pk_attr, pk_val = _target_partition(target_type, target_id)
    resp = table.delete_item(
        Key={pk_attr: pk_val, "sk": f"AMEN#{amenity_id}"},
        ReturnValues="ALL_OLD",
    )
    deleted = bool(resp.get("Attributes"))
    if deleted:
        _audit(
            "hotel.amenity.detached",
            user_sub,
            amenity_id=amenity_id,
            target_type=target_type,
            target_id=target_id,
        )
    return deleted


def list_amenities_for(*, target_type: str, target_id: str) -> list[dict]:
    """List amenities associated with a target, hydrated with name/category/icon."""
    _require_enabled()
    table, pk_attr, pk_val = _target_partition(target_type, target_id)
    resp = table.query(
        KeyConditionExpression=Key(pk_attr).eq(pk_val) & Key("sk").begins_with("AMEN#"),
    )
    assoc_rows = resp.get("Items", [])
    if not assoc_rows:
        return []

    # Batch-hydrate from hotel_amenities META rows
    keys = [{"amenity_id": row["amenity_id"], "sk": "META"} for row in assoc_rows]
    batch_resp = T.hotel_amenities.meta.client.batch_get_item(
        RequestItems={
            T.hotel_amenities.name: {"Keys": keys},
        }
    )
    amenity_map = {
        a["amenity_id"]: a
        for a in batch_resp.get("Responses", {}).get(T.hotel_amenities.name, [])
    }

    result = []
    for row in assoc_rows:
        aid = row["amenity_id"]
        meta = amenity_map.get(aid, {})
        entry = {
            "amenity_id": aid,
            "name": meta.get("name", ""),
            "category": meta.get("category", "general"),
            "icon": meta.get("icon") or None,
            "target_type": row.get("target_type", target_type),
            "created_at": _to_int(row.get("created_at", 0)),
        }
        result.append(entry)
    return result
