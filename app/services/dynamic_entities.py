"""Dynamic Entities service (CSN-003).

Runtime JSON-schema registration + generated CRUD for admin-defined entity types.
Flag-gated: S.dynamic_entities_enabled (DYNAMIC_ENTITIES_ENABLED, default OFF).
No new external dependencies — bounded pure-Python schema validation.
"""
from __future__ import annotations

import re
import uuid
from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError
from fastapi import HTTPException, Request

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ENTITY_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{2,39}$")
_PROPERTY_NAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]{0,63}$")

_RESERVED_NAMES = frozenset({
    "users", "billing", "messaging", "calendar", "feed", "tickets",
    "catalog", "sessions", "admin", "internal", "dynamic", "open-data",
    "consents", "subscriptions", "filemanager", "notifications",
    "webhooks", "kyc", "api", "auth", "health", "metrics", "openapi",
})

_ALLOWED_TYPES = frozenset({
    "string", "integer", "number", "boolean", "array", "object",
})

_PY_TYPE_MAP = {
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "array": list,
    "object": dict,
}


# ---------------------------------------------------------------------------
# Schema validation (bounded pure-Python, no jsonschema dependency)
# ---------------------------------------------------------------------------

def _count_depth(schema: dict, current: int = 0) -> int:
    """Recursively count max nesting depth of object/array properties."""
    if current > S.dynamic_entity_max_depth:
        return current
    props = schema.get("properties", {})
    if not isinstance(props, dict):
        return current
    max_d = current
    for pdef in props.values():
        if not isinstance(pdef, dict):
            continue
        t = pdef.get("type", "")
        if t in ("object", "array"):
            max_d = max(max_d, _count_depth(pdef.get("items", pdef), current + 1))
    return max_d


def _validate_schema_registration(json_schema: dict) -> None:
    """Raise HTTP 400 if schema exceeds platform caps or has bad structure."""
    if not isinstance(json_schema, dict) or json_schema.get("type") != "object":
        raise HTTPException(400, {"code": "invalid_schema", "reason": "top-level type must be 'object'"})
    props = json_schema.get("properties", {})
    if not isinstance(props, dict):
        raise HTTPException(400, {"code": "invalid_schema", "reason": "properties must be a dict"})
    if len(props) > S.dynamic_entity_max_properties:
        raise HTTPException(400, {"code": "schema_too_complex", "reason": "too many properties", "cap": "max_properties"})
    for pname in props:
        if not _PROPERTY_NAME_RE.match(pname):
            raise HTTPException(400, {"code": "invalid_schema", "reason": f"property name invalid: {pname}"})
    required = json_schema.get("required", [])
    if not isinstance(required, list):
        raise HTTPException(400, {"code": "invalid_schema", "reason": "required must be a list"})
    if len(required) > S.dynamic_entity_max_required:
        raise HTTPException(400, {"code": "schema_too_complex", "reason": "too many required fields", "cap": "max_required"})
    depth = _count_depth(json_schema)
    if depth > S.dynamic_entity_max_depth:
        raise HTTPException(400, {"code": "schema_too_complex", "reason": "nesting depth exceeded", "cap": "max_depth"})


def _validate_data_against_schema(entity_name: str, data: dict) -> None:
    """Validate row data dict against the stored entity schema; raise 400 on failure."""
    defn = get_entity_def(entity_name)
    if defn is None:
        raise HTTPException(404, {"code": "entity_not_found", "entity_name": entity_name})
    schema = defn.get("json_schema", {})
    props = schema.get("properties", {})
    required = schema.get("required", [])
    for field in required:
        if field not in data:
            raise HTTPException(
                400,
                {"code": "schema_validation_failed", "field": field, "reason": "required"},
            )
    for field, value in data.items():
        if field not in props:
            continue  # open-world: extra fields allowed
        expected_type = props[field].get("type")
        if expected_type and expected_type in _PY_TYPE_MAP:
            py_type = _PY_TYPE_MAP[expected_type]
            # Special-case: booleans are subclass of int in Python
            if expected_type == "integer" and isinstance(value, bool):
                raise HTTPException(
                    400,
                    {"code": "schema_validation_failed", "field": field,
                     "reason": "type_mismatch", "expected": expected_type},
                )
            if not isinstance(value, py_type):
                raise HTTPException(
                    400,
                    {"code": "schema_validation_failed", "field": field,
                     "reason": "type_mismatch", "expected": expected_type},
                )


# ---------------------------------------------------------------------------
# Service functions
# ---------------------------------------------------------------------------

def _item_to_def(item: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(item)
    for f in ("created_at", "updated_at", "version"):
        if f in out and out[f] is not None:
            try:
                out[f] = int(out[f])
            except (TypeError, ValueError):
                pass
    return out


def _item_to_row(item: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(item)
    for f in ("created_at", "updated_at"):
        if f in out and out[f] is not None:
            try:
                out[f] = int(out[f])
            except (TypeError, ValueError):
                pass
    return out


def register_entity(
    admin_sub: str,
    entity_name: str,
    json_schema: dict,
    req: Optional[Request] = None,
    description: Optional[str] = None,
    expected_version: Optional[int] = None,
) -> Dict[str, Any]:
    """Register or update a dynamic entity definition."""
    if not _ENTITY_NAME_RE.match(entity_name):
        raise HTTPException(400, {"code": "invalid_entity_name", "entity_name": entity_name})
    if entity_name in _RESERVED_NAMES:
        raise HTTPException(400, {"code": "reserved_entity_name", "entity_name": entity_name})
    _validate_schema_registration(json_schema)

    now = now_ts()
    existing = get_entity_def(entity_name)
    if existing is None:
        # Create new
        item: Dict[str, Any] = {
            "entity_name": entity_name,
            "sk": "DEF",
            "json_schema": json_schema,
            "description": description,
            "created_by": admin_sub,
            "created_at": now,
            "updated_at": now,
            "version": 1,
        }
        T.dynamic_entity_defs.put_item(Item=item)
        version = 1
    else:
        # Update: conditional on expected_version if provided
        update_expr = "SET json_schema = :schema, updated_at = :now, description = :desc, #v = #v + :one"
        expr_names = {"#v": "version"}
        expr_vals: Dict[str, Any] = {
            ":schema": json_schema,
            ":now": now,
            ":desc": description,
            ":one": 1,
        }
        kwargs: Dict[str, Any] = {
            "Key": {"entity_name": entity_name, "sk": "DEF"},
            "UpdateExpression": update_expr,
            "ExpressionAttributeNames": expr_names,
            "ExpressionAttributeValues": expr_vals,
            "ReturnValues": "ALL_NEW",
        }
        if expected_version is not None:
            kwargs["ConditionExpression"] = Attr("version").eq(expected_version)
            expr_vals[":ev"] = expected_version
        try:
            resp = T.dynamic_entity_defs.update_item(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                raise HTTPException(409, {"code": "version_conflict"})
            raise
        version = int(resp.get("Attributes", {}).get("version", existing.get("version", 1)))
        item = dict(existing)
        item.update({"json_schema": json_schema, "updated_at": now, "description": description, "version": version})

    try:
        from app.services.alerts import audit_event
        audit_event("dynamic_entity.registered", admin_sub, req,
                    entity_name=entity_name, version=version,
                    property_count=len(json_schema.get("properties", {})))
    except Exception:
        pass

    return _item_to_def(item)


def get_entity_def(entity_name: str) -> Optional[Dict[str, Any]]:
    """Load a DEF row; returns None for unknown names."""
    resp = T.dynamic_entity_defs.get_item(Key={"entity_name": entity_name, "sk": "DEF"})
    item = resp.get("Item")
    if not item:
        return None
    return _item_to_def(item)


def list_entity_defs(
    *,
    admin_sub: Optional[str] = None,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    """List entity definitions. admin_sub scopes to ByCreatedAt GSI."""
    from app.core.cursor import decode_cursor, encode_cursor

    defs: List[Dict[str, Any]] = []
    kwargs: Dict[str, Any] = {"Limit": limit}
    if cursor:
        esk = decode_cursor(cursor)
        if esk:
            kwargs["ExclusiveStartKey"] = esk

    if admin_sub:
        kwargs["IndexName"] = S.dynamic_entity_defs_creator_index
        kwargs["KeyConditionExpression"] = Key("created_by").eq(admin_sub)
        resp = T.dynamic_entity_defs.query(**kwargs)
    else:
        resp = T.dynamic_entity_defs.scan(**kwargs)

    for item in resp.get("Items", []):
        defs.append(_item_to_def(item))
    last_key = resp.get("LastEvaluatedKey")

    return {
        "defs": defs,
        "cursor": encode_cursor(last_key) if last_key else None,
    }


def delete_entity(
    admin_sub: str,
    entity_name: str,
    req: Optional[Request] = None,
) -> None:
    """Delete a DEF row and schedule orphaned row reaping via TTL."""
    T.dynamic_entity_defs.delete_item(Key={"entity_name": entity_name, "sk": "DEF"})

    # Schedule orphaned rows for TTL-based reaping
    reap_at = now_ts() + 86400 * 7
    ttl_attr = getattr(S, "ddb_ttl_attr", "ttl_epoch")
    last_key = None
    while True:
        scan_kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("entity_name").eq(entity_name),
            "Limit": 100,
        }
        if last_key:
            scan_kwargs["ExclusiveStartKey"] = last_key
        resp = T.dynamic_entity_rows.query(**scan_kwargs)
        for item in resp.get("Items", []):
            try:
                T.dynamic_entity_rows.update_item(
                    Key={"entity_name": entity_name, "row_id": item["row_id"]},
                    UpdateExpression=f"SET #ttl = :ttl",
                    ExpressionAttributeNames={"#ttl": ttl_attr},
                    ExpressionAttributeValues={":ttl": reap_at},
                )
            except Exception:
                pass
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    try:
        from app.services.alerts import audit_event
        audit_event("dynamic_entity.deleted", admin_sub, req, entity_name=entity_name)
    except Exception:
        pass


def create_row(
    entity_name: str,
    owner_sub: str,
    data: dict,
) -> Dict[str, Any]:
    """Validate data against schema and write a new entity row."""
    defn = get_entity_def(entity_name)
    if defn is None:
        raise HTTPException(404, {"code": "entity_not_found", "entity_name": entity_name})
    _validate_data_against_schema(entity_name, data)

    # Rate limit
    try:
        from app.services.rate_limit import _bucket_limit
        cap = int(getattr(S, "dynamic_entity_row_write_rate_per_hour", 200) or 200)
        if cap > 0:
            key = f"entity:{entity_name}:{owner_sub}"
            sid = "rl#dyn_write"
            if not _bucket_limit(key, sid, cap, 3600):
                from fastapi import HTTPException as FHE
                raise FHE(
                    status_code=429,
                    detail={
                        "code": "dynamic_entity_rate_limited",
                        "limit": cap,
                        "window_seconds": 3600,
                    },
                    headers={"Retry-After": "3600"},
                )
    except HTTPException:
        raise
    except Exception:
        pass

    now = now_ts()
    row_id = "dyn_" + uuid.uuid4().hex
    item: Dict[str, Any] = {
        "entity_name": entity_name,
        "row_id": row_id,
        "owner_sub": owner_sub,
        "data": data,
        "created_at": now,
        "updated_at": now,
    }
    T.dynamic_entity_rows.put_item(Item=item)
    return _item_to_row(item)


def get_row(entity_name: str, row_id: str, owner_sub: str) -> Optional[Dict[str, Any]]:
    """Load row by key. Returns None if not found OR if owner does not match."""
    resp = T.dynamic_entity_rows.get_item(Key={"entity_name": entity_name, "row_id": row_id})
    item = resp.get("Item")
    if not item:
        return None
    if item.get("owner_sub") != owner_sub:
        return None  # Ownership enforced: different user → treat as not found
    return _item_to_row(item)


def list_rows(
    entity_name: str,
    *,
    owner_sub: Optional[str] = None,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    """List rows for an entity. owner_sub scopes via ByOwner GSI."""
    # Verify entity exists
    if get_entity_def(entity_name) is None:
        raise HTTPException(404, {"code": "entity_not_found", "entity_name": entity_name})

    from app.core.cursor import decode_cursor, encode_cursor

    kwargs: Dict[str, Any] = {"Limit": limit}
    if cursor:
        esk = decode_cursor(cursor)
        if esk:
            kwargs["ExclusiveStartKey"] = esk

    if owner_sub:
        kwargs["IndexName"] = S.dynamic_entity_rows_owner_index
        kwargs["KeyConditionExpression"] = Key("owner_sub").eq(owner_sub)
        # Filter to this entity_name
        kwargs["FilterExpression"] = Attr("entity_name").eq(entity_name)
        resp = T.dynamic_entity_rows.query(**kwargs)
    else:
        kwargs["KeyConditionExpression"] = Key("entity_name").eq(entity_name)
        resp = T.dynamic_entity_rows.query(**kwargs)

    rows = [_item_to_row(i) for i in resp.get("Items", [])]
    last_key = resp.get("LastEvaluatedKey")
    return {
        "rows": rows,
        "cursor": encode_cursor(last_key) if last_key else None,
    }


def update_row(
    entity_name: str,
    row_id: str,
    owner_sub: str,
    data: dict,
) -> Dict[str, Any]:
    """Validate data and update an existing row; enforces owner_sub ownership."""
    defn = get_entity_def(entity_name)
    if defn is None:
        raise HTTPException(404, {"code": "entity_not_found", "entity_name": entity_name})
    _validate_data_against_schema(entity_name, data)

    # Rate limit
    try:
        from app.services.rate_limit import _bucket_limit
        cap = int(getattr(S, "dynamic_entity_row_write_rate_per_hour", 200) or 200)
        if cap > 0:
            key = f"entity:{entity_name}:{owner_sub}"
            if not _bucket_limit(key, "rl#dyn_write", cap, 3600):
                from fastapi import HTTPException as FHE
                raise FHE(429, {"code": "dynamic_entity_rate_limited", "limit": cap, "window_seconds": 3600},
                          headers={"Retry-After": "3600"})
    except HTTPException:
        raise
    except Exception:
        pass

    now = now_ts()
    try:
        resp = T.dynamic_entity_rows.update_item(
            Key={"entity_name": entity_name, "row_id": row_id},
            UpdateExpression="SET #data = :data, updated_at = :now",
            ExpressionAttributeNames={"#data": "data"},
            ExpressionAttributeValues={":data": data, ":now": now},
            ConditionExpression=Attr("owner_sub").eq(owner_sub),
            ReturnValues="ALL_NEW",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise HTTPException(404, "not found")
        raise

    return _item_to_row(resp.get("Attributes", {}))


def delete_row(entity_name: str, row_id: str, owner_sub: str) -> None:
    """Delete a row; conditional on owner_sub ownership. 404 on mismatch."""
    try:
        T.dynamic_entity_rows.delete_item(
            Key={"entity_name": entity_name, "row_id": row_id},
            ConditionExpression=Attr("owner_sub").eq(owner_sub),
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise HTTPException(404, "not found")
        raise


# Alias used by CSN-004 proxy connector
validate_against_schema = _validate_data_against_schema
