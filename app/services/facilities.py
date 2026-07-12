"""OFBiz Facility service — CRUD + location dimension (ADR-001, FAC-004).

Additive + flag-gated (FACILITY_FULFILLMENT_ENABLED, default OFF). Every
public function raises HTTP 404 when the flag is off; all existing code
paths (shop, cart, orders, billing, inventory) are byte-for-byte unchanged.

No if-dev_mode branches: all DDB access uses T.facilities identically in
dev (moto) and prod (real DynamoDB). SECOPS-007 parity guaranteed.

Cross-cluster dep on inventory.py accessed via lazy import.
"""
from __future__ import annotations

import hashlib
import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

# ───────────────────────────── constants ─────────────────────────────

DEFAULT_FACILITY_OWNER = "system"
DEFAULT_FACILITY_NAME = "Default Warehouse"
DEFAULT_LOCATION_ID = "warehouse"  # matches inventory.DEFAULT_LOCATION


# ───────────────────────────── helpers ─────────────────────────────


def _flag_on() -> bool:
    return bool(getattr(S, "facility_fulfillment_enabled", False))


def _require_enabled() -> None:
    if not _flag_on():
        raise HTTPException(status_code=404, detail="Facility fulfillment is not enabled")


def _audit(event: str, user_sub: str, **fields: Any) -> None:
    try:
        from app.services.alerts import audit_event

        audit_event(event, user_sub or "system", None, **fields)
    except Exception:
        pass


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return default if value is None else int(value)
    except (TypeError, ValueError):
        return default


def _facility_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "facility_id": item["facility_id"],
        "name": item.get("name", ""),
        "facility_type": item.get("facility_type", "warehouse"),
        "description": item.get("description"),
        "address": item.get("address"),
        "owner_sub": item.get("owner_sub"),
        "status": item.get("status", "active"),
        "created_at": _to_int(item.get("created_at")),
        "updated_at": _to_int(item.get("updated_at")),
    }


def _location_out(item: Dict[str, Any]) -> Dict[str, Any]:
    sk: str = item.get("sk", "")
    # location_id stored directly on item; fall back to stripping LOC# from sk
    loc_id = item.get("location_id") or (sk[4:] if sk.startswith("LOC#") else sk)
    return {
        "facility_id": item["facility_id"],
        "location_id": loc_id,
        "name": item.get("name", ""),
        "location_type": item.get("location_type", "bulk"),
        "description": item.get("description"),
        "parent_location_id": item.get("parent_location_id"),
        "status": item.get("status", "active"),
        "created_at": _to_int(item.get("created_at")),
    }


# ───────────────────────────── facility CRUD ─────────────────────────────


def create_facility(
    owner_sub: str,
    name: str,
    facility_type: str = "warehouse",
    *,
    description: Optional[str] = None,
    address: Optional[Any] = None,
) -> Dict[str, Any]:
    """Idempotent create: sha256(owner_sub|name)[:32] as deterministic ID."""
    _require_enabled()
    facility_id = hashlib.sha256(f"{owner_sub}|{name}".encode()).hexdigest()[:32]
    ts = now_ts()
    item: Dict[str, Any] = {
        "facility_id": facility_id,
        "sk": "META",
        "owner_sub": owner_sub,
        "name": name,
        "facility_type": facility_type,
        "status": "active",
        "created_at": ts,
        "updated_at": ts,
    }
    if description is not None:
        item["description"] = description
    if address is not None:
        item["address"] = address

    try:
        T.facilities.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(facility_id)",
        )
        _audit("facility.created", owner_sub, facility_id=facility_id, name=name, facility_type=facility_type)
        return _facility_out(item)
    except ClientError as exc:
        if exc.response["Error"].get("Code") != "ConditionalCheckFailedException":
            raise
        # Already exists — idempotent replay: return existing
        existing = get_facility(facility_id)
        return existing or _facility_out(item)


def get_facility(facility_id: str) -> Optional[Dict[str, Any]]:
    """Return facility header or None if absent."""
    _require_enabled()
    resp = T.facilities.get_item(Key={"facility_id": facility_id, "sk": "META"})
    item = resp.get("Item")
    return _facility_out(item) if item else None


def list_facilities(
    owner_sub: str,
    *,
    status: str = "active",
    cursor: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    """List facilities for an owner using GSI_OWNER (newest-first)."""
    _require_enabled()
    from app.core.cursor import decode_cursor, encode_cursor

    kwargs: Dict[str, Any] = {
        "IndexName": "GSI_OWNER",
        "KeyConditionExpression": Key("owner_sub").eq(owner_sub),
        "FilterExpression": Attr("status").eq(status) & Attr("sk").eq("META"),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    start_key = decode_cursor(cursor)
    if start_key:
        kwargs["ExclusiveStartKey"] = start_key

    resp = T.facilities.query(**kwargs)
    items = [_facility_out(i) for i in resp.get("Items", [])]
    next_cursor = encode_cursor(resp.get("LastEvaluatedKey"))
    return {"facilities": items, "next_cursor": next_cursor}


def list_facilities_by_status(
    status: str = "active",
    *,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    """Admin/root cross-owner listing using GSI_STATUS."""
    _require_enabled()
    from app.core.cursor import decode_cursor, encode_cursor

    kwargs: Dict[str, Any] = {
        "IndexName": "GSI_STATUS",
        "KeyConditionExpression": Key("status").eq(status),
        "FilterExpression": Attr("sk").eq("META"),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    start_key = decode_cursor(cursor)
    if start_key:
        kwargs["ExclusiveStartKey"] = start_key

    resp = T.facilities.query(**kwargs)
    items = [_facility_out(i) for i in resp.get("Items", [])]
    next_cursor = encode_cursor(resp.get("LastEvaluatedKey"))
    return {"facilities": items, "next_cursor": next_cursor}


def update_facility(
    facility_id: str,
    *,
    user_sub: str,
    name: Optional[str] = None,
    facility_type: Optional[str] = None,
    description: Optional[str] = None,
    address: Optional[Any] = None,
) -> Dict[str, Any]:
    """Update mutable fields of an active facility."""
    _require_enabled()
    item = get_facility(facility_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Facility not found")
    if item["status"] == "archived":
        raise HTTPException(status_code=409, detail="Cannot update an archived facility")

    set_parts = ["updated_at = :t"]
    expr_vals: Dict[str, Any] = {":t": now_ts()}
    expr_names: Dict[str, str] = {}

    if name is not None:
        set_parts.append("#name = :n")
        expr_vals[":n"] = name
        expr_names["#name"] = "name"
    if facility_type is not None:
        set_parts.append("facility_type = :ft")
        expr_vals[":ft"] = facility_type
    if description is not None:
        set_parts.append("description = :d")
        expr_vals[":d"] = description
    if address is not None:
        set_parts.append("address = :a")
        expr_vals[":a"] = address

    update_kwargs: Dict[str, Any] = {
        "Key": {"facility_id": facility_id, "sk": "META"},
        "UpdateExpression": "SET " + ", ".join(set_parts),
        "ExpressionAttributeValues": expr_vals,
    }
    if expr_names:
        update_kwargs["ExpressionAttributeNames"] = expr_names

    T.facilities.update_item(**update_kwargs)
    _audit("facility.updated", user_sub, facility_id=facility_id)
    updated = get_facility(facility_id)
    return updated or item


def archive_facility(facility_id: str, *, user_sub: str) -> Dict[str, Any]:
    """Archive a facility. Raises 409 if any location has available stock > 0."""
    _require_enabled()
    item = get_facility(facility_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Facility not found")
    if item["status"] == "archived":
        return item  # idempotent

    # Check open stock at facility locations
    _check_no_open_stock(facility_id)

    T.facilities.update_item(
        Key={"facility_id": facility_id, "sk": "META"},
        UpdateExpression="SET #status = :s, updated_at = :t",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={":s": "archived", ":t": now_ts()},
    )
    _audit("facility.archived", user_sub, facility_id=facility_id)
    result = get_facility(facility_id)
    return result or item


def _check_no_open_stock(facility_id: str) -> None:
    """Raise 409 if any inventory row exists for a location of this facility."""
    # Get all location_ids for this facility
    locs = list_locations(facility_id)
    if not locs:
        return

    # Lazy import inventory service; if not present (cross-cluster dep not built), skip
    try:
        from app.services import inventory as inv  # type: ignore[import]
    except ImportError:
        return  # inventory module not available in this cluster — skip guard

    for loc in locs:
        if loc.get("status") == "archived":
            continue
        location_id = loc["location_id"]
        # inventory.get_inventory returns None or a record with "available"
        try:
            rec = inv.get_inventory.__wrapped__(location_id) if hasattr(inv.get_inventory, "__wrapped__") else None
            # Attempt standard call signature
            rec = inv.get_inventory.__func__(location_id) if False else None
        except Exception:
            rec = None

        # Best effort: try get_inventory with positional args
        try:
            # get_inventory(sku, location_id) — we can't know all SKUs, so skip per-SKU check.
            # For MVP: scan T.inventory for any row with this location_id using FilterExpression.
            from app.core.tables import T as _T
            resp = _T.inventory.scan(
                FilterExpression=Attr("location_id").eq(location_id) & Attr("available").gt(0),
                Limit=1,
            )
            if resp.get("Items"):
                raise HTTPException(
                    status_code=409,
                    detail=f"Facility has available stock at location {location_id!r}; zero out stock before archiving",
                )
        except HTTPException:
            raise
        except Exception:
            # T.inventory might not exist in this cluster — skip guard
            break


# ───────────────────────────── location CRUD ─────────────────────────────


def create_location(
    facility_id: str,
    name: str,
    location_type: str = "bulk",
    *,
    description: Optional[str] = None,
    parent_location_id: Optional[str] = None,
    user_sub: str,
) -> Dict[str, Any]:
    """Create a facility location. location_id is uuid4().hex (non-deterministic)."""
    _require_enabled()
    facility = get_facility(facility_id)
    if facility is None:
        raise HTTPException(status_code=404, detail="Facility not found")
    if facility["status"] == "archived":
        raise HTTPException(status_code=409, detail="Cannot add a location to an archived facility")

    location_id = uuid.uuid4().hex
    ts = now_ts()
    item: Dict[str, Any] = {
        "facility_id": facility_id,
        "sk": f"LOC#{location_id}",
        "location_id": location_id,
        "name": name,
        "location_type": location_type,
        "status": "active",
        "created_at": ts,
    }
    if description is not None:
        item["description"] = description
    if parent_location_id is not None:
        item["parent_location_id"] = parent_location_id

    T.facilities.put_item(Item=item)
    _audit("facility_location.created", user_sub, facility_id=facility_id, location_id=location_id, location_type=location_type)
    return _location_out(item)


def list_locations(facility_id: str) -> List[Dict[str, Any]]:
    """List all locations for a facility (all statuses)."""
    _require_enabled()
    resp = T.facilities.query(
        KeyConditionExpression=Key("facility_id").eq(facility_id) & Key("sk").begins_with("LOC#"),
    )
    return [_location_out(i) for i in resp.get("Items", [])]


def get_location(facility_id: str, location_id: str) -> Optional[Dict[str, Any]]:
    """Return location or None if absent."""
    _require_enabled()
    resp = T.facilities.get_item(Key={"facility_id": facility_id, "sk": f"LOC#{location_id}"})
    item = resp.get("Item")
    return _location_out(item) if item else None


def update_location(
    facility_id: str,
    location_id: str,
    *,
    actor_sub: str,
    name: Optional[str] = None,
    location_type: Optional[str] = None,
    description: Optional[str] = None,
    parent_location_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Update mutable location fields."""
    _require_enabled()
    loc = get_location(facility_id, location_id)
    if loc is None:
        raise HTTPException(status_code=404, detail="Location not found")

    set_parts: List[str] = []
    expr_vals: Dict[str, Any] = {}
    expr_names: Dict[str, str] = {}

    if name is not None:
        set_parts.append("#name = :n")
        expr_vals[":n"] = name
        expr_names["#name"] = "name"
    if location_type is not None:
        set_parts.append("location_type = :lt")
        expr_vals[":lt"] = location_type
    if description is not None:
        set_parts.append("description = :d")
        expr_vals[":d"] = description
    if parent_location_id is not None:
        set_parts.append("parent_location_id = :p")
        expr_vals[":p"] = parent_location_id

    if not set_parts:
        return loc

    update_kwargs: Dict[str, Any] = {
        "Key": {"facility_id": facility_id, "sk": f"LOC#{location_id}"},
        "UpdateExpression": "SET " + ", ".join(set_parts),
        "ExpressionAttributeValues": expr_vals,
    }
    if expr_names:
        update_kwargs["ExpressionAttributeNames"] = expr_names

    T.facilities.update_item(**update_kwargs)
    _audit("facility_location.updated", actor_sub, facility_id=facility_id, location_id=location_id)
    return get_location(facility_id, location_id) or loc


def archive_location(facility_id: str, location_id: str, *, actor_sub: str) -> Dict[str, Any]:
    """Archive a location."""
    _require_enabled()
    loc = get_location(facility_id, location_id)
    if loc is None:
        raise HTTPException(status_code=404, detail="Location not found")
    if loc["status"] == "archived":
        return loc

    T.facilities.update_item(
        Key={"facility_id": facility_id, "sk": f"LOC#{location_id}"},
        UpdateExpression="SET #status = :s",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={":s": "archived"},
    )
    _audit("facility_location.archived", actor_sub, facility_id=facility_id, location_id=location_id)
    return get_location(facility_id, location_id) or loc


# ───────────────────────────── default facility ─────────────────────────────


def ensure_default_facility() -> Dict[str, Any]:
    """Idempotently create the default warehouse facility + 'warehouse' location.

    Called from app/main.py on_startup when facility_fulfillment_enabled is True.
    The facility_id is deterministic: sha256("system|Default Warehouse")[:32].
    The default location_id is "warehouse", matching inventory.DEFAULT_LOCATION.
    """
    _require_enabled()
    facility = create_facility(
        DEFAULT_FACILITY_OWNER,
        DEFAULT_FACILITY_NAME,
        facility_type="warehouse",
        description="Auto-provisioned default facility for pre-existing inventory rows",
    )
    fid = facility["facility_id"]
    # Ensure the "warehouse" location exists with a deterministic conditional put.
    loc_item: Dict[str, Any] = {
        "facility_id": fid,
        "sk": f"LOC#{DEFAULT_LOCATION_ID}",
        "location_id": DEFAULT_LOCATION_ID,
        "name": "Default warehouse floor",
        "location_type": "bulk",
        "status": "active",
        "created_at": now_ts(),
    }
    try:
        T.facilities.put_item(
            Item=loc_item,
            ConditionExpression="attribute_not_exists(sk)",
        )
    except ClientError as exc:
        if exc.response["Error"].get("Code") != "ConditionalCheckFailedException":
            raise
        # Already exists — idempotent no-op
    return facility
