"""QloApps hotel-PMS service (HTL-001 + HTL-002).

Additive + flag-gated (``HOTEL_PMS_ENABLED``, default OFF). Every public
function calls ``_require_enabled()`` first; when the flag is off the entire
module is dormant and the platform is byte-for-byte unchanged.

SECOPS-007 parity: identical DynamoDB code in dev (moto) and prod (real DDB);
no ``dev_mode`` branch anywhere in this file.
"""
from __future__ import annotations

import hashlib
from uuid import uuid4
from typing import Any

from boto3.dynamodb.conditions import Attr, Key
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


def list_hotels_by_city(city: str, *, status: str = "active") -> dict:
    """List active hotels in a city (case-insensitive ``address.city`` match).

    There is no city GSI on the hotels table, so this scans the META rows and
    filters in Python. Hotels are low-cardinality, so a scan is acceptable here
    and is the storage-layer support for the stay-search ``city`` branch.
    Returns the standard ``{items, count, cursor}`` shape.
    """
    _require_enabled()
    target = (city or "").strip().lower()
    items: list[dict] = []
    scan_kwargs: dict = {
        "FilterExpression": "sk = :meta",
        "ExpressionAttributeValues": {":meta": "META"},
    }
    while True:
        resp = T.hotels.scan(**scan_kwargs)
        for raw in resp.get("Items", []):
            h = _coerce_hotel(raw)
            if status and h.get("status") != status:
                continue
            addr = h.get("address") or {}
            if (addr.get("city") or "").strip().lower() == target:
                items.append(h)
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        scan_kwargs["ExclusiveStartKey"] = lek
    return {"items": items, "count": len(items), "cursor": None}


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
    amenity = a_resp.get("Item")
    if not amenity:
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

    def _decorate(item: dict) -> dict:
        # Enrich the association row with amenity dictionary fields so the
        # response model (name/category/icon) can be populated.
        item["name"] = amenity.get("name", "")
        item["category"] = amenity.get("category", "")
        item["icon"] = amenity.get("icon")
        item["created_at"] = _to_int(item.get("created_at", ts))
        return item

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
            return _decorate(existing)
        raise
    _audit(
        "hotel.amenity.attached",
        user_sub,
        amenity_id=amenity_id,
        target_type=target_type,
        target_id=target_id,
    )
    return _decorate(assoc)


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



# ── HTL-005..009: room types + rooms + housekeeping (appended) ──────────────

def _assert_hotel_owner(hotel_id: str, user_sub: str) -> dict:
    """Read META row; raise 404/403 on missing/wrong owner. Returns the META dict."""
    resp = T.hotels.get_item(Key=_meta_key(hotel_id))
    meta = resp.get("Item")
    if not meta:
        raise HTTPException(status_code=404, detail="Hotel not found")
    if meta.get("owner_sub") != user_sub:
        raise HTTPException(status_code=403, detail="Not the hotel owner")
    return meta


# ---------------------------------------------------------------------------
# HTL-005: Room Type SK helper + Decimal coercion
# ---------------------------------------------------------------------------

_ROOMTYPE_INT_FIELDS = (
    "base_occupancy_adults", "base_occupancy_children", "max_occupancy",
    "size_sqft", "base_nightly_rate_cents", "created_at", "updated_at",
)


def _roomtype_sk(room_type_id: str) -> str:
    return f"ROOMTYPE#{room_type_id}"


def _coerce_room_type(item: dict) -> dict:
    for f in _ROOMTYPE_INT_FIELDS:
        if f in item:
            item[f] = _to_int(item[f])
    if "photo_urls" not in item:
        item["photo_urls"] = []
    return item


# ---------------------------------------------------------------------------
# HTL-005: Room Type CRUD
# ---------------------------------------------------------------------------


def create_room_type(
    hotel_id: str,
    *,
    name: str,
    description: str = "",
    base_occupancy_adults: int,
    base_occupancy_children: int = 0,
    max_occupancy: int,
    bed_type: str,
    size_sqft: int = 0,
    base_nightly_rate_cents: int,
    photo_urls: list[str] | None = None,
    user_sub: str,
) -> dict:
    _require_enabled()
    # Validate parent hotel + ownership
    _assert_hotel_owner(hotel_id, user_sub)
    # Occupancy invariant
    if max_occupancy < base_occupancy_adults + base_occupancy_children:
        raise HTTPException(
            status_code=422,
            detail="max_occupancy must be >= base_occupancy_adults + base_occupancy_children",
        )
    room_type_id = uuid4().hex
    ts = now_ts()
    item: dict = {
        "hotel_id": hotel_id,
        "sk": _roomtype_sk(room_type_id),
        "room_type_id": room_type_id,
        "name": name,
        "description": description,
        "base_occupancy_adults": base_occupancy_adults,
        "base_occupancy_children": base_occupancy_children,
        "max_occupancy": max_occupancy,
        "bed_type": bed_type,
        "size_sqft": size_sqft,
        "base_nightly_rate_cents": base_nightly_rate_cents,
        "photo_urls": photo_urls or [],
        "status": "active",
        "created_at": ts,
        "updated_at": ts,
    }
    T.hotels.put_item(Item=item)
    _audit("hotel.room_type.created", user_sub, hotel_id=hotel_id, room_type_id=room_type_id, name=name)
    return _coerce_room_type(item)


def get_room_type(hotel_id: str, room_type_id: str) -> dict | None:
    _require_enabled()
    resp = T.hotels.get_item(Key={"hotel_id": hotel_id, "sk": _roomtype_sk(room_type_id)})
    item = resp.get("Item")
    return _coerce_room_type(item) if item else None


def list_room_types(
    hotel_id: str,
    *,
    status: str = "active",
    cursor: str | None = None,
    limit: int = 50,
) -> dict:
    _require_enabled()
    from app.core.cursor import decode_cursor, encode_cursor

    kwargs: dict = {
        "IndexName": "GSI_HOTEL_ROOMTYPES",
        "KeyConditionExpression": Key("hotel_id").eq(hotel_id),
        "ScanIndexForward": False,
        "Limit": min(limit, 200),
    }
    if cursor:
        lek = decode_cursor(cursor)
        if lek:
            kwargs["ExclusiveStartKey"] = lek

    resp = T.hotels.query(**kwargs)
    raw_items = resp.get("Items", [])
    # Exclude the META row and any non-ROOMTYPE# rows; apply status filter
    items = []
    for it in raw_items:
        sk = it.get("sk", "")
        if sk == "META" or not sk.startswith("ROOMTYPE#"):
            continue
        if status not in ("all", None) and it.get("status") != status:
            continue
        items.append(_coerce_room_type(it))

    next_key = resp.get("LastEvaluatedKey")
    return {
        "room_types": items,
        "count": len(items),
        "cursor": encode_cursor(next_key) if next_key else None,
    }


def update_room_type(hotel_id: str, room_type_id: str, *, user_sub: str, **kwargs: Any) -> dict:
    _require_enabled()
    existing = get_room_type(hotel_id, room_type_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="Room type not found")
    _assert_hotel_owner(hotel_id, user_sub)

    # Merged occupancy invariant
    adults = _to_int(kwargs.get("base_occupancy_adults", existing.get("base_occupancy_adults", 0)))
    children = _to_int(kwargs.get("base_occupancy_children", existing.get("base_occupancy_children", 0)))
    max_occ = _to_int(kwargs.get("max_occupancy", existing.get("max_occupancy", 1)))
    if max_occ < adults + children:
        raise HTTPException(
            status_code=422,
            detail="max_occupancy must be >= base_occupancy_adults + base_occupancy_children",
        )

    _ALLOWED = {
        "name", "description", "base_occupancy_adults", "base_occupancy_children",
        "max_occupancy", "bed_type", "size_sqft", "base_nightly_rate_cents", "photo_urls",
    }
    updates = {k: v for k, v in kwargs.items() if k in _ALLOWED}
    ts = now_ts()
    # Build UpdateExpression (escape 'name' reserved word)
    expr_parts = []
    expr_names: dict = {}
    expr_values: dict = {":ts": ts}
    for i, (k, v) in enumerate(updates.items()):
        alias = f"#f{i}"
        val_alias = f":v{i}"
        expr_names[alias] = k
        expr_values[val_alias] = v
        expr_parts.append(f"{alias} = {val_alias}")
    expr_parts.append("updated_at = :ts")

    rt_update_kwargs: dict = {
        "Key": {"hotel_id": hotel_id, "sk": _roomtype_sk(room_type_id)},
        "UpdateExpression": "SET " + ", ".join(expr_parts),
        "ExpressionAttributeValues": expr_values,
        "ReturnValues": "ALL_NEW",
    }
    if expr_names:
        rt_update_kwargs["ExpressionAttributeNames"] = expr_names
    resp = T.hotels.update_item(**rt_update_kwargs)
    _audit("hotel.room_type.updated", user_sub, hotel_id=hotel_id, room_type_id=room_type_id, fields=list(updates.keys()))
    return _coerce_room_type(resp["Attributes"])


def archive_room_type(hotel_id: str, room_type_id: str, *, user_sub: str) -> dict:
    _require_enabled()
    existing = get_room_type(hotel_id, room_type_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="Room type not found")
    _assert_hotel_owner(hotel_id, user_sub)
    ts = now_ts()
    resp = T.hotels.update_item(
        Key={"hotel_id": hotel_id, "sk": _roomtype_sk(room_type_id)},
        UpdateExpression="SET #s = :archived, updated_at = :ts",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":archived": "archived", ":ts": ts},
        ReturnValues="ALL_NEW",
    )
    _audit("hotel.room_type.archived", user_sub, hotel_id=hotel_id, room_type_id=room_type_id)
    return _coerce_room_type(resp["Attributes"])


# ---------------------------------------------------------------------------
# HTL-006: Room SK helper + Decimal coercion
# ---------------------------------------------------------------------------

_ROOM_INT_FIELDS = ("floor", "created_at", "updated_at")
_IMMUTABLE_ROOM_FIELDS = {"hotel_id", "sk", "room_id", "created_at", "housekeeping_status"}


def _room_sk(room_id: str) -> str:
    return f"ROOM#{room_id}"


def _coerce_room(item: dict) -> dict:
    for f in _ROOM_INT_FIELDS:
        if f in item:
            item[f] = _to_int(item[f])
    return item


# ---------------------------------------------------------------------------
# HTL-006: Room CRUD
# ---------------------------------------------------------------------------


def create_room(
    hotel_id: str,
    *,
    room_type_id: str,
    room_number: str,
    floor: int,
    status: str = "available",
    user_sub: str,
) -> dict:
    _require_enabled()
    if not room_number:
        raise HTTPException(status_code=422, detail="room_number must not be empty")
    # Validate parent hotel + ownership
    _assert_hotel_owner(hotel_id, user_sub)
    # FK: room_type_id must resolve on this hotel
    if get_room_type(hotel_id, room_type_id) is None:
        raise HTTPException(status_code=404, detail="Room type not found")
    room_id = uuid4().hex
    ts = now_ts()
    item: dict = {
        "hotel_id": hotel_id,
        "sk": _room_sk(room_id),
        "room_id": room_id,
        "room_type_id": room_type_id,
        "room_number": room_number,
        "floor": floor,
        "status": status,
        "housekeeping_status": "clean",
        "created_at": ts,
        "updated_at": ts,
    }
    T.hotel_rooms.put_item(Item=item)
    _audit("hotel.room.created", user_sub, hotel_id=hotel_id, room_id=room_id,
           room_type_id=room_type_id, room_number=room_number)
    return _coerce_room(item)


def get_room(hotel_id: str, room_id: str) -> dict | None:
    _require_enabled()
    resp = T.hotel_rooms.get_item(Key={"hotel_id": hotel_id, "sk": _room_sk(room_id)})
    item = resp.get("Item")
    return _coerce_room(item) if item else None


def list_rooms(
    hotel_id: str,
    *,
    room_type_id: str | None = None,
    status: str | None = None,
    cursor: str | None = None,
    limit: int = 50,
) -> dict:
    _require_enabled()
    from app.core.cursor import decode_cursor, encode_cursor

    limit = min(limit, 200)
    start_key = decode_cursor(cursor) if cursor else None

    if room_type_id is not None:
        # GSI_ROOMTYPE: by room type
        kwargs: dict = {
            "IndexName": "GSI_ROOMTYPE",
            "KeyConditionExpression": Key("room_type_id").eq(room_type_id),
            "ScanIndexForward": False,
        }
    else:
        # Base table: by hotel, only ROOM# rows
        kwargs = {
            "KeyConditionExpression": (
                Key("hotel_id").eq(hotel_id) & Key("sk").begins_with("ROOM#")
            ),
        }

    if status is not None:
        kwargs["FilterExpression"] = Attr("status").eq(status)

    if start_key:
        kwargs["ExclusiveStartKey"] = start_key

    items: list = []
    last_key = None
    # Loop LastEvaluatedKey when filtering (FilterExpression doesn't reduce page size)
    while True:
        resp = T.hotel_rooms.query(**kwargs)
        for it in resp.get("Items", []):
            items.append(_coerce_room(it))
            if len(items) >= limit:
                break
        last_key = resp.get("LastEvaluatedKey")
        if len(items) >= limit or not last_key:
            break
        kwargs["ExclusiveStartKey"] = last_key

    return {
        "rooms": items,
        "count": len(items),
        "cursor": encode_cursor(last_key) if last_key else None,
    }


def update_room(hotel_id: str, room_id: str, *, user_sub: str, **kwargs: Any) -> dict:
    _require_enabled()
    existing = get_room(hotel_id, room_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="Room not found")
    _assert_hotel_owner(hotel_id, user_sub)

    # Drop immutable + protected fields (housekeeping_status routes through set_room_housekeeping_status)
    for drop in list(_IMMUTABLE_ROOM_FIELDS):
        kwargs.pop(drop, None)

    # FK re-validation if room_type_id changes
    if "room_type_id" in kwargs:
        if get_room_type(hotel_id, kwargs["room_type_id"]) is None:
            raise HTTPException(status_code=404, detail="Room type not found")

    if not kwargs:
        # Nothing to update; return existing
        return existing

    ts = now_ts()
    expr_parts = []
    expr_names: dict = {}
    expr_values: dict = {":ts": ts}
    for i, (k, v) in enumerate(kwargs.items()):
        alias = f"#f{i}"
        val_alias = f":v{i}"
        expr_names[alias] = k
        expr_values[val_alias] = v
        expr_parts.append(f"{alias} = {val_alias}")
    expr_parts.append("updated_at = :ts")

    update_kwargs: dict = {
        "Key": {"hotel_id": hotel_id, "sk": _room_sk(room_id)},
        "UpdateExpression": "SET " + ", ".join(expr_parts),
        "ExpressionAttributeValues": expr_values,
        "ReturnValues": "ALL_NEW",
    }
    if expr_names:
        update_kwargs["ExpressionAttributeNames"] = expr_names
    resp = T.hotel_rooms.update_item(**update_kwargs)
    _audit("hotel.room.updated", user_sub, hotel_id=hotel_id, room_id=room_id, fields=list(kwargs.keys()))
    return _coerce_room(resp["Attributes"])


def delete_room(hotel_id: str, room_id: str, *, user_sub: str) -> bool:
    """Hard-delete a room row. Returns True if it existed, False if absent (no-raise)."""
    _require_enabled()
    existing = get_room(hotel_id, room_id)
    if existing is None:
        return False
    # Best-effort ownership check; if parent hotel gone, delete the orphaned row anyway
    try:
        resp = T.hotels.get_item(Key=_meta_key(hotel_id))
        meta = resp.get("Item")
        if meta and meta.get("owner_sub") != user_sub:
            raise HTTPException(status_code=403, detail="Not the hotel owner")
    except HTTPException:
        raise
    except Exception:
        pass
    T.hotel_rooms.delete_item(Key={"hotel_id": hotel_id, "sk": _room_sk(room_id)})
    _audit("hotel.room.deleted", user_sub, hotel_id=hotel_id, room_id=room_id)
    return True


# ---------------------------------------------------------------------------
# HTL-007: Housekeeping status transition
# ---------------------------------------------------------------------------

_VALID_HK_STATUS = {"clean", "dirty", "inspected", "out_of_service"}
_HKTASK_INT_FIELDS = ("due_at", "created_at", "updated_at", "completed_at")


def _hktask_sk(task_id: str) -> str:
    return f"HKTASK#{task_id}"


def _coerce_task(item: dict) -> dict:
    for f in _HKTASK_INT_FIELDS:
        if f in item:
            item[f] = _to_int(item[f])
    # assignee_sub may be absent (sparse GSI — unassigned task); default to ""
    item.setdefault("assignee_sub", "")
    return item


def set_room_housekeeping_status(
    hotel_id: str,
    room_id: str,
    *,
    housekeeping_status: str,
    user_sub: str,
) -> dict:
    _require_enabled()
    if housekeeping_status not in _VALID_HK_STATUS:
        raise HTTPException(status_code=422, detail="Invalid housekeeping status")
    existing = get_room(hotel_id, room_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="Room not found")
    _assert_hotel_owner(hotel_id, user_sub)
    ts = now_ts()
    T.hotel_rooms.update_item(
        Key={"hotel_id": hotel_id, "sk": _room_sk(room_id)},
        UpdateExpression="SET housekeeping_status = :hk, updated_at = :ts",
        ExpressionAttributeValues={":hk": housekeeping_status, ":ts": ts},
    )
    _audit("hotel.room.housekeeping_status", user_sub, hotel_id=hotel_id, room_id=room_id,
           housekeeping_status=housekeeping_status)
    # Re-read and return the updated row
    updated = get_room(hotel_id, room_id)
    return updated  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# HTL-007: Housekeeping task CRUD
# ---------------------------------------------------------------------------


def create_hk_task(
    hotel_id: str,
    *,
    room_id: str,
    assignee_sub: str = "",
    due_at: int = 0,
    notes: str = "",
    user_sub: str,
) -> dict:
    _require_enabled()
    # FK: room must exist on this hotel
    if get_room(hotel_id, room_id) is None:
        raise HTTPException(status_code=404, detail="Room not found")
    _assert_hotel_owner(hotel_id, user_sub)
    task_id = uuid4().hex
    ts = now_ts()
    item: dict = {
        "hotel_id": hotel_id,
        "sk": _hktask_sk(task_id),
        "task_id": task_id,
        "room_id": room_id,
        "status": "open",
        "due_at": int(due_at),
        "notes": notes or "",
        "created_at": ts,
        "updated_at": ts,
        "completed_at": 0,
    }
    # assignee_sub="" means unassigned; omit from item so the row is sparse in
    # GSI_HK_ASSIGNEE (DynamoDB/moto reject empty strings as GSI partition keys).
    # The field is always returned as "" if absent (coerced in _coerce_task).
    if assignee_sub:
        item["assignee_sub"] = assignee_sub
    T.hotel_rooms.put_item(Item=item)
    _audit("hotel.hk_task.created", user_sub, hotel_id=hotel_id, room_id=room_id,
           task_id=task_id, assignee_sub=assignee_sub)
    return _coerce_task(item)


def assign_hk_task(
    hotel_id: str,
    task_id: str,
    *,
    assignee_sub: str,
    user_sub: str,
) -> dict:
    _require_enabled()
    resp = T.hotel_rooms.get_item(Key={"hotel_id": hotel_id, "sk": _hktask_sk(task_id)})
    if not resp.get("Item"):
        raise HTTPException(status_code=404, detail="Task not found")
    _assert_hotel_owner(hotel_id, user_sub)
    ts = now_ts()
    if assignee_sub:
        # Write the assignee — naturally projects the row into GSI_HK_ASSIGNEE
        T.hotel_rooms.update_item(
            Key={"hotel_id": hotel_id, "sk": _hktask_sk(task_id)},
            UpdateExpression="SET assignee_sub = :a, updated_at = :ts",
            ExpressionAttributeValues={":a": assignee_sub, ":ts": ts},
        )
    else:
        # Unassigning: remove the attribute so the row is sparse in GSI_HK_ASSIGNEE
        T.hotel_rooms.update_item(
            Key={"hotel_id": hotel_id, "sk": _hktask_sk(task_id)},
            UpdateExpression="REMOVE assignee_sub SET updated_at = :ts",
            ExpressionAttributeValues={":ts": ts},
        )
    _audit("hotel.hk_task.assigned", user_sub, hotel_id=hotel_id, task_id=task_id,
           assignee_sub=assignee_sub)
    resp2 = T.hotel_rooms.get_item(Key={"hotel_id": hotel_id, "sk": _hktask_sk(task_id)})
    return _coerce_task(resp2["Item"])


def list_hk_tasks(
    hotel_id: str | None = None,
    *,
    status: str | None = None,
    assignee_sub: str | None = None,
    cursor: str | None = None,
    limit: int = 50,
) -> dict:
    _require_enabled()
    if hotel_id is None and assignee_sub is None:
        raise HTTPException(status_code=422, detail="hotel_id or assignee_sub required")

    from app.core.cursor import decode_cursor, encode_cursor

    limit = min(limit, 200)
    start_key = decode_cursor(cursor) if cursor else None

    if assignee_sub is not None:
        # By assignee → GSI_HK_ASSIGNEE
        kwargs: dict = {
            "IndexName": "GSI_HK_ASSIGNEE",
            "KeyConditionExpression": Key("assignee_sub").eq(assignee_sub),
            "ScanIndexForward": False,
        }
        if status is not None:
            kwargs["FilterExpression"] = Attr("status").eq(status) & Attr("sk").begins_with("HKTASK#")
        else:
            kwargs["FilterExpression"] = Attr("sk").begins_with("HKTASK#")
    elif status is not None:
        # By hotel + status → GSI_HK_TASK_STATUS
        kwargs = {
            "IndexName": "GSI_HK_TASK_STATUS",
            "KeyConditionExpression": Key("hotel_id").eq(hotel_id) & Key("status").eq(status),
            "FilterExpression": Attr("sk").begins_with("HKTASK#"),
        }
    else:
        # By hotel (all tasks) → base table PK + begins_with HKTASK#
        kwargs = {
            "KeyConditionExpression": (
                Key("hotel_id").eq(hotel_id) & Key("sk").begins_with("HKTASK#")
            ),
        }

    if start_key:
        kwargs["ExclusiveStartKey"] = start_key

    items: list = []
    last_key = None
    while True:
        resp = T.hotel_rooms.query(**kwargs)
        for it in resp.get("Items", []):
            items.append(_coerce_task(it))
            if len(items) >= limit:
                break
        last_key = resp.get("LastEvaluatedKey")
        if len(items) >= limit or not last_key:
            break
        kwargs["ExclusiveStartKey"] = last_key

    return {
        "tasks": items,
        "count": len(items),
        "cursor": encode_cursor(last_key) if last_key else None,
    }


def complete_hk_task(hotel_id: str, task_id: str, *, user_sub: str) -> dict:
    _require_enabled()
    resp = T.hotel_rooms.get_item(Key={"hotel_id": hotel_id, "sk": _hktask_sk(task_id)})
    if not resp.get("Item"):
        raise HTTPException(status_code=404, detail="Task not found")
    _assert_hotel_owner(hotel_id, user_sub)
    ts = now_ts()
    try:
        T.hotel_rooms.update_item(
            Key={"hotel_id": hotel_id, "sk": _hktask_sk(task_id)},
            UpdateExpression="SET #s = :done, completed_at = :ts, updated_at = :ts",
            ConditionExpression="#s <> :done",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":done": "done", ":ts": ts},
        )
    except ClientError as e:
        if e.response["Error"]["Code"] != "ConditionalCheckFailedException":
            raise
        # Already done — idempotent no-op
    _audit("hotel.hk_task.completed", user_sub, hotel_id=hotel_id, task_id=task_id)
    resp2 = T.hotel_rooms.get_item(Key={"hotel_id": hotel_id, "sk": _hktask_sk(task_id)})
    return _coerce_task(resp2["Item"])
