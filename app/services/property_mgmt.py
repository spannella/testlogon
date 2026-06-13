"""Property management service (open-property vertical, PROP-001..PROP-005).

Additive + flag-gated (``PROPERTY_MGMT_ENABLED``, default OFF). Every
public function calls ``_require_enabled()`` first; when the flag is off all
functions raise HTTP 404 before touching DynamoDB and the platform is
byte-for-byte unchanged.

Zero ``if S.dev_mode`` branches — same DynamoDB code path in dev (moto) and
prod (real DynamoDB). SECOPS-007 parity.

Money safety: no billing table access in PROP-001..PROP-003. ``market_rent_cents``
is informational. Rent ledger (future cluster) will use ``billing_shared.new_ledger_entry``
exclusively — never fork.
"""
from __future__ import annotations

import hashlib
from decimal import Decimal
from typing import Any, Optional
from uuid import uuid4

from fastapi import HTTPException

from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts


# ---------------------------------------------------------------------------
# Flag gate (modeled on app/services/inventory.py:50–57)
# ---------------------------------------------------------------------------

def _flag_on() -> bool:
    return bool(getattr(S, "property_mgmt_enabled", False))


def _require_enabled() -> None:
    if not _flag_on():
        raise HTTPException(status_code=404, detail="Property management is not enabled")


# ---------------------------------------------------------------------------
# Audit wrapper (modeled on app/services/inventory.py:92–98)
# ---------------------------------------------------------------------------

def _audit(event: str, user_sub: str, **fields: Any) -> None:
    try:
        from app.services.alerts import audit_event
        audit_event(event, user_sub or "system", None, **fields)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# ID helpers
# ---------------------------------------------------------------------------

def _property_id(owner_sub: str, name: str) -> str:
    return hashlib.sha256(f"{owner_sub}|{name}".encode()).hexdigest()[:32]


# ---------------------------------------------------------------------------
# Decimal coercion helpers
# ---------------------------------------------------------------------------

def _coerce_property(item: dict) -> dict:
    """Coerce DynamoDB Decimal numerics to Python int on a property META row."""
    for field in ("created_at", "updated_at", "unit_count"):
        if field in item:
            item[field] = int(item[field])
    return item


def _coerce_unit(item: dict) -> dict:
    """Coerce DynamoDB Decimal numerics to Python int/float on a unit row."""
    for field in ("created_at", "updated_at", "market_rent_cents", "bedrooms", "square_footage"):
        if field in item:
            item[field] = int(item[field])
    if "bathrooms" in item:
        item["bathrooms"] = float(item["bathrooms"])
    return item


# ---------------------------------------------------------------------------
# PROP-001: Property CRUD
# ---------------------------------------------------------------------------

def create_property(
    owner_sub: str,
    name: str,
    property_type: str,
    address: dict,
    color_tags: list[str] | None = None,
) -> dict:
    """Create a property (idempotent on owner_sub + name)."""
    _require_enabled()
    pid = _property_id(owner_sub, name)
    ts = now_ts()
    item: dict = {
        "property_id": pid,
        "sk": "META",
        "owner_sub": owner_sub,
        "name": name,
        "property_type": property_type,
        "address": address,
        "color_tags": color_tags or [],
        "occupancy_status": "vacant",
        "unit_count": 0,
        "status": "active",
        "created_at": ts,
        "updated_at": ts,
    }
    try:
        T.properties.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(property_id)",
        )
    except T.properties.meta.client.exceptions.ConditionalCheckFailedException:
        existing = get_property(pid)
        if existing is not None:
            return existing
        return item  # extremely unlikely — just return what we built
    _audit("property.created", owner_sub, property_id=pid, name=name)
    return _coerce_property(item)


def get_property(property_id: str) -> dict | None:
    """Return the property META row, or None if not found."""
    _require_enabled()
    resp = T.properties.get_item(Key={"property_id": property_id, "sk": "META"})
    item = resp.get("Item")
    if item is None:
        return None
    return _coerce_property(item)


def update_property(property_id: str, *, user_sub: str, **kwargs) -> dict:
    """Partially update a property's mutable fields. Raises 404 if absent."""
    _require_enabled()
    existing = get_property(property_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="Property not found")

    ts = now_ts()
    set_parts = ["updated_at = :ts"]
    expr_vals: dict = {":ts": ts}
    expr_names: dict = {}

    for key, val in kwargs.items():
        placeholder = f":{key}"
        name_alias = f"#{key}"
        set_parts.append(f"{name_alias} = {placeholder}")
        expr_vals[placeholder] = val
        expr_names[name_alias] = key

    update_kwargs: dict = {
        "Key": {"property_id": property_id, "sk": "META"},
        "UpdateExpression": "SET " + ", ".join(set_parts),
        "ExpressionAttributeValues": expr_vals,
    }
    if expr_names:
        update_kwargs["ExpressionAttributeNames"] = expr_names

    T.properties.update_item(**update_kwargs)
    _audit("property.updated", user_sub, property_id=property_id, fields=list(kwargs.keys()))
    updated = get_property(property_id)
    return updated  # type: ignore[return-value]


def archive_property(property_id: str, *, user_sub: str) -> dict:
    """Soft-archive a property (status → 'archived'). Raises 404 if absent."""
    _require_enabled()
    existing = get_property(property_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="Property not found")

    ts = now_ts()
    T.properties.update_item(
        Key={"property_id": property_id, "sk": "META"},
        UpdateExpression="SET #s = :s, updated_at = :ts",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "archived", ":ts": ts},
    )
    _audit("property.archived", user_sub, property_id=property_id)
    updated = get_property(property_id)
    return updated  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# PROP-002: Unit CRUD
# ---------------------------------------------------------------------------

def create_unit(
    property_id: str,
    *,
    label: str,
    bedrooms: int,
    bathrooms: float,
    square_footage: int,
    market_rent_cents: int,
    occupancy_status: str = "vacant",
    user_sub: str,
) -> dict:
    """Create a unit under a property. Raises 404/403 if preconditions fail."""
    _require_enabled()

    # Validate parent exists + caller owns it
    meta_resp = T.properties.get_item(Key={"property_id": property_id, "sk": "META"})
    meta = meta_resp.get("Item")
    if meta is None:
        raise HTTPException(status_code=404, detail="Property not found")
    if meta.get("owner_sub") != user_sub:
        raise HTTPException(status_code=403, detail="Not the property owner")

    unit_id = uuid4().hex
    ts = now_ts()
    # DynamoDB does not accept Python float — convert to Decimal for storage.
    unit_item: dict = {
        "property_id": property_id,
        "sk": f"UNIT#{unit_id}",
        "unit_id": unit_id,
        "label": label,
        "bedrooms": bedrooms,
        "bathrooms": Decimal(str(bathrooms)),
        "square_footage": square_footage,
        "market_rent_cents": market_rent_cents,
        "occupancy_status": occupancy_status,
        "created_at": ts,
        "updated_at": ts,
    }
    T.properties.put_item(Item=unit_item)
    # Coerce bathrooms back to float for the in-memory return value
    unit_item["bathrooms"] = float(unit_item["bathrooms"])

    # Atomically increment unit_count on META row
    T.properties.update_item(
        Key={"property_id": property_id, "sk": "META"},
        UpdateExpression="ADD unit_count :one SET updated_at = :ts",
        ExpressionAttributeValues={":one": 1, ":ts": now_ts()},
    )

    _audit("property.unit.created", user_sub, property_id=property_id, unit_id=unit_id, label=label)
    return _coerce_unit(unit_item)


def get_unit(property_id: str, unit_id: str) -> dict | None:
    """Return a unit row, or None if not found."""
    _require_enabled()
    resp = T.properties.get_item(
        Key={"property_id": property_id, "sk": f"UNIT#{unit_id}"}
    )
    item = resp.get("Item")
    if item is None:
        return None
    return _coerce_unit(item)


def list_units(property_id: str) -> list[dict]:
    """Return all units under a property, sorted by label (ascending)."""
    _require_enabled()
    from boto3.dynamodb.conditions import Key as DKey

    items: list[dict] = []
    kwargs: dict = {
        "KeyConditionExpression": DKey("property_id").eq(property_id)
        & DKey("sk").begins_with("UNIT#"),
    }
    while True:
        resp = T.properties.query(**kwargs)
        items.extend(resp.get("Items", []))
        last = resp.get("LastEvaluatedKey")
        if not last:
            break
        kwargs["ExclusiveStartKey"] = last

    coerced = [_coerce_unit(i) for i in items]
    coerced.sort(key=lambda u: u.get("label", "").lower())
    return coerced


def update_unit(
    property_id: str,
    unit_id: str,
    *,
    user_sub: str,
    **kwargs,
) -> dict:
    """Partially update a unit. Raises 404 if unit or parent absent; 403 if not owner."""
    _require_enabled()

    unit = get_unit(property_id, unit_id)
    if unit is None:
        raise HTTPException(status_code=404, detail="Unit not found")

    # Validate parent exists + caller owns it
    meta_resp = T.properties.get_item(Key={"property_id": property_id, "sk": "META"})
    meta = meta_resp.get("Item")
    if meta is None:
        raise HTTPException(status_code=404, detail="Property not found")
    if meta.get("owner_sub") != user_sub:
        raise HTTPException(status_code=403, detail="Not the property owner")

    ts = now_ts()
    set_parts = ["updated_at = :ts"]
    expr_vals: dict = {":ts": ts}
    expr_names: dict = {}

    for key, val in kwargs.items():
        # DynamoDB does not accept Python float — convert bathrooms to Decimal
        if key == "bathrooms" and isinstance(val, float):
            val = Decimal(str(val))
        placeholder = f":{key}"
        name_alias = f"#{key}"
        set_parts.append(f"{name_alias} = {placeholder}")
        expr_vals[placeholder] = val
        expr_names[name_alias] = key

    unit_update_kwargs: dict = {
        "Key": {"property_id": property_id, "sk": f"UNIT#{unit_id}"},
        "UpdateExpression": "SET " + ", ".join(set_parts),
        "ExpressionAttributeValues": expr_vals,
    }
    if expr_names:
        unit_update_kwargs["ExpressionAttributeNames"] = expr_names

    T.properties.update_item(**unit_update_kwargs)

    _audit("property.unit.updated", user_sub, property_id=property_id, unit_id=unit_id, fields=list(kwargs.keys()))

    # Best-effort occupancy roll-up when occupancy_status changes (PROP-003)
    if "occupancy_status" in kwargs:
        try:
            compute_property_occupancy(property_id)  # type: ignore[name-defined]
        except Exception:
            pass

    updated = get_unit(property_id, unit_id)
    return updated  # type: ignore[return-value]


def delete_unit(property_id: str, unit_id: str, *, user_sub: str) -> bool:
    """Delete a unit. Returns False (never raises) if unit not found."""
    _require_enabled()

    unit = get_unit(property_id, unit_id)
    if unit is None:
        return False

    T.properties.delete_item(Key={"property_id": property_id, "sk": f"UNIT#{unit_id}"})

    # Atomically decrement unit_count with floor guard
    try:
        T.properties.update_item(
            Key={"property_id": property_id, "sk": "META"},
            UpdateExpression="ADD unit_count :neg SET updated_at = :ts",
            ConditionExpression="unit_count > :z",
            ExpressionAttributeValues={":neg": -1, ":z": 0, ":ts": now_ts()},
        )
    except Exception:
        # ConditionalCheckFailedException or orphan — swallow
        pass

    _audit("property.unit.deleted", user_sub, property_id=property_id, unit_id=unit_id)
    return True


# ---------------------------------------------------------------------------
# PROP-003: List/filter + occupancy roll-up
# ---------------------------------------------------------------------------

_VALID_STATUSES = {"active", "archived", "all"}
_VALID_PROPERTY_TYPES = {"single_family", "multi_family", "apartment", "commercial"}


def list_properties(
    owner_sub: str,
    *,
    status: str = "active",
    property_type: Optional[str] = None,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> dict:
    """List a landlord's properties via GSI_OWNER (newest-first, paginated)."""
    _require_enabled()

    if status not in _VALID_STATUSES:
        raise HTTPException(status_code=422, detail=f"Invalid status: {status!r}. Must be one of {sorted(_VALID_STATUSES)}")
    if property_type is not None and property_type not in _VALID_PROPERTY_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid property_type: {property_type!r}. Must be one of {sorted(_VALID_PROPERTY_TYPES)}",
        )

    limit = max(1, min(int(limit), 200))
    exclusive_start_key = decode_cursor(cursor)

    from boto3.dynamodb.conditions import Attr, Key as DKey

    query_kwargs: dict = {
        "IndexName": "GSI_OWNER",
        "KeyConditionExpression": DKey("owner_sub").eq(owner_sub),
        "ScanIndexForward": False,
        "Limit": limit,
        "FilterExpression": Attr("sk").eq("META"),
    }
    if exclusive_start_key:
        query_kwargs["ExclusiveStartKey"] = exclusive_start_key

    resp = T.properties.query(**query_kwargs)
    items = resp.get("Items", [])
    last_key = resp.get("LastEvaluatedKey")

    # In-memory secondary filters
    if status != "all":
        items = [i for i in items if i.get("status") == status]
    if property_type is not None:
        items = [i for i in items if i.get("property_type") == property_type]

    next_cursor = encode_cursor(last_key)

    coerced = [_coerce_property(i) for i in items]
    return {"properties": coerced, "count": len(coerced), "cursor": next_cursor}


def compute_property_occupancy(property_id: str) -> dict:
    """Query GSI_UNIT_OCCUPANCY and tally unit occupancy states for one property."""
    _require_enabled()

    from boto3.dynamodb.conditions import Key as DKey

    items: list[dict] = []
    query_kwargs: dict = {
        "IndexName": "GSI_UNIT_OCCUPANCY",
        "KeyConditionExpression": DKey("property_id").eq(property_id),
    }
    while True:
        resp = T.properties.query(**query_kwargs)
        items.extend(resp.get("Items", []))
        last = resp.get("LastEvaluatedKey")
        if not last:
            break
        query_kwargs["ExclusiveStartKey"] = last

    # Filter to unit rows only (exclude META row which also has occupancy_status)
    items = [i for i in items if i.get("sk", "").startswith("UNIT#")]

    counts: dict[str, int] = {"occupied": 0, "vacant": 0, "turnover": 0, "unavailable": 0}
    for item in items:
        s = item.get("occupancy_status", "vacant")
        counts[s] = counts.get(s, 0) + 1

    total = sum(counts.values())

    # Derive roll-up status
    if total > 0 and counts["occupied"] == total:
        derived_status = "occupied"
    elif counts["occupied"] == 0:
        derived_status = "vacant"
    else:
        derived_status = "partial"

    # Best-effort write-back to META row
    try:
        from boto3.dynamodb.conditions import Attr
        T.properties.update_item(
            Key={"property_id": property_id, "sk": "META"},
            UpdateExpression="SET occupancy_status = :s, updated_at = :t",
            ConditionExpression=Attr("property_id").exists(),
            ExpressionAttributeValues={":s": derived_status, ":t": now_ts()},
        )
    except Exception:
        pass  # best-effort; never blocks the response

    occupancy_rate = counts["occupied"] / max(total, 1)

    _audit("property.occupancy_recomputed", "system",
           property_id=property_id, occupancy_status=derived_status)

    return {
        "property_id": property_id,
        "total": total,
        "occupied": counts["occupied"],
        "vacant": counts["vacant"],
        "turnover": counts["turnover"],
        "unavailable": counts["unavailable"],
        "occupancy_status": derived_status,
        "occupancy_rate": occupancy_rate,
    }


def portfolio_occupancy_rollup(owner_sub: str) -> dict:
    """Cross-property occupancy roll-up for one owner's active portfolio."""
    _require_enabled()

    # Collect all active properties (paginate until cursor is None)
    properties: list[dict] = []
    cursor: Optional[str] = None
    while True:
        page = list_properties(owner_sub, status="active", limit=200, cursor=cursor)
        properties.extend(page["properties"])
        cursor = page.get("cursor")
        if not cursor:
            break

    totals: dict = {
        "property_count": len(properties),
        "unit_count": 0,
        "occupied": 0,
        "vacant": 0,
        "turnover": 0,
        "unavailable": 0,
    }

    for prop in properties:
        occ = compute_property_occupancy(prop["property_id"])
        totals["unit_count"] += occ["total"]
        totals["occupied"] += occ["occupied"]
        totals["vacant"] += occ["vacant"]
        totals["turnover"] += occ["turnover"]
        totals["unavailable"] += occ["unavailable"]

    totals["occupancy_rate"] = totals["occupied"] / max(totals["unit_count"], 1)
    return totals
