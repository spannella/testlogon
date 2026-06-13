"""Studio custom fields registry.

STU-011: Per-entity-type custom field definitions with validation.
"""
from __future__ import annotations

import re
from datetime import date as _date
from decimal import Decimal
from typing import Any
from uuid import uuid4

from fastapi import HTTPException

from app.core.cursor import encode_cursor, decode_cursor
from app.core.time import now_ts

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ALLOWED_ENTITY_TYPES: frozenset[str] = frozenset({
    "contact", "ticket", "opportunity", "lead", "case", "project", "account",
})

ALLOWED_FIELD_TYPES: frozenset[str] = frozenset({
    "text", "integer", "decimal", "boolean", "date", "picklist", "multi_picklist",
})

_FIELD_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{2,49}$")

# ---------------------------------------------------------------------------
# Module-level per-entity cache (mirrors billing_config.py:46–54)
# ---------------------------------------------------------------------------
_field_cache: dict[str, list[dict[str, Any]]] = {}
_field_cache_ts: dict[str, int] = {}


def _cache_ttl() -> int:
    from app.core.settings import S
    return S.crm_studio_field_cache_ttl_seconds


def _max_fields() -> int:
    from app.core.settings import S
    return S.crm_studio_max_fields_per_entity


def _invalidate_entity_cache(entity_type: str) -> None:
    _field_cache.pop(entity_type, None)
    _field_cache_ts.pop(entity_type, None)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class FieldAlreadyExistsError(Exception):
    pass


class FieldNotFoundError(Exception):
    pass


class CustomFieldValidationError(ValueError):
    pass


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_table():
    from app.core.tables import T
    return T.crm_studio_fields


def _audit(event: str, actor_sub: str, **kwargs: Any) -> None:
    try:
        from app.services.alerts import audit_event
        audit_event(event, actor_sub, **kwargs)
    except Exception:
        pass


def _load_fields(entity_type: str, include_inactive: bool = False) -> list[dict[str, Any]]:
    """Load field definitions from DDB (or cache for active-only)."""
    ts = now_ts()
    if not include_inactive:
        cached_ts = _field_cache_ts.get(entity_type, 0)
        if ts - cached_ts < _cache_ttl() and entity_type in _field_cache:
            return _field_cache[entity_type]

    from boto3.dynamodb.conditions import Key as DKey
    table = _get_table()

    items: list[dict] = []
    kwargs: dict[str, Any] = {
        "KeyConditionExpression": DKey("entity_type").eq(entity_type),
    }
    while True:
        resp = table.query(**kwargs)
        items.extend(resp.get("Items", []))
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek

    if not include_inactive:
        active = [i for i in items if i.get("is_active", True)]
        _field_cache[entity_type] = active
        _field_cache_ts[entity_type] = ts
        return active

    return items


def _get_picklist_active_values(picklist_name: str) -> list[str] | None:
    """Returns None if the dropdown service is not available."""
    try:
        from app.services.crm_studio_dropdowns import get_active_values  # type: ignore
        return get_active_values(picklist_name)
    except ImportError:
        return None


# ---------------------------------------------------------------------------
# Public service functions
# ---------------------------------------------------------------------------

def create_field(
    actor_sub: str,
    entity_type: str,
    field_key: str,
    label: str,
    field_type: str,
    *,
    required: bool = False,
    default_value: Any = None,
    picklist_name: str | None = None,
    max_length: int = 1000,
    min_value: float | None = None,
    max_value: float | None = None,
    sort_order: int = 0,
) -> dict[str, Any]:
    """Create a new custom field definition."""
    # Validate inputs
    if entity_type not in ALLOWED_ENTITY_TYPES:
        raise ValueError(f"invalid_entity_type: {entity_type}")
    if not _FIELD_KEY_RE.match(field_key):
        raise ValueError(f"invalid_field_key: {field_key}")
    if field_type not in ALLOWED_FIELD_TYPES:
        raise ValueError(f"invalid_field_type: {field_type}")
    if field_type in ("picklist", "multi_picklist") and picklist_name is None:
        raise ValueError("picklist_name_required")

    table = _get_table()

    # Check field limit
    existing_count = len(_load_fields(entity_type, include_inactive=False))
    if existing_count >= _max_fields():
        raise HTTPException(409, {"code": "field_limit_reached", "entity_type": entity_type})

    ts = now_ts()
    item: dict[str, Any] = {
        "entity_type": entity_type,
        "field_key": field_key,
        "label": label,
        "field_type": field_type,
        "required": required,
        "default_value": default_value,
        "picklist_name": picklist_name,
        "max_length": max_length,
        "min_value": min_value,
        "max_value": max_value,
        "sort_order": sort_order,
        "is_active": True,
        "created_by_sub": actor_sub,
        "created_at": ts,
        "updated_by_sub": actor_sub,
        "updated_at": ts,
    }

    from boto3.dynamodb.conditions import Attr
    from botocore.exceptions import ClientError
    try:
        table.put_item(
            Item=item,
            ConditionExpression=Attr("field_key").not_exists(),
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise FieldAlreadyExistsError(f"{entity_type}.{field_key}")
        raise

    _invalidate_entity_cache(entity_type)
    _audit("studio.field.created", actor_sub, entity_type=entity_type, field_key=field_key, field_type=field_type, required=required)
    return item


def update_field(
    actor_sub: str,
    entity_type: str,
    field_key: str,
    *,
    label: str | None = None,
    required: bool | None = None,
    default_value: Any = None,
    max_length: int | None = None,
    min_value: float | None = None,
    max_value: float | None = None,
    sort_order: int | None = None,
    reactivate: bool | None = None,
) -> dict[str, Any]:
    """Partially update mutable field attributes."""
    table = _get_table()

    # Verify existence
    existing = get_field(entity_type, field_key)
    if not existing:
        raise FieldNotFoundError(f"{entity_type}.{field_key}")

    ts = now_ts()
    update_parts = ["#ua = :ua", "#ubs = :ubs"]
    attr_names = {"#ua": "updated_at", "#ubs": "updated_by_sub"}
    attr_values: dict[str, Any] = {":ua": ts, ":ubs": actor_sub}
    changed_attrs = []

    if label is not None:
        update_parts.append("#lbl = :lbl")
        attr_names["#lbl"] = "label"
        attr_values[":lbl"] = label
        changed_attrs.append("label")

    if required is not None:
        update_parts.append("#req = :req")
        attr_names["#req"] = "required"
        attr_values[":req"] = required
        changed_attrs.append("required")

    if default_value is not None:
        update_parts.append("#dv = :dv")
        attr_names["#dv"] = "default_value"
        attr_values[":dv"] = default_value
        changed_attrs.append("default_value")

    if max_length is not None:
        update_parts.append("#ml = :ml")
        attr_names["#ml"] = "max_length"
        attr_values[":ml"] = max_length
        changed_attrs.append("max_length")

    if min_value is not None:
        update_parts.append("#mnv = :mnv")
        attr_names["#mnv"] = "min_value"
        attr_values[":mnv"] = min_value
        changed_attrs.append("min_value")

    if max_value is not None:
        update_parts.append("#mxv = :mxv")
        attr_names["#mxv"] = "max_value"
        attr_values[":mxv"] = max_value
        changed_attrs.append("max_value")

    if sort_order is not None:
        update_parts.append("#so = :so")
        attr_names["#so"] = "sort_order"
        attr_values[":so"] = sort_order
        changed_attrs.append("sort_order")

    if reactivate is True:
        update_parts.append("#ia = :ia")
        attr_names["#ia"] = "is_active"
        attr_values[":ia"] = True
        changed_attrs.append("is_active")
        _audit("studio.field.reactivated", actor_sub, entity_type=entity_type, field_key=field_key)

    table.update_item(
        Key={"entity_type": entity_type, "field_key": field_key},
        UpdateExpression="SET " + ", ".join(update_parts),
        ExpressionAttributeNames=attr_names,
        ExpressionAttributeValues=attr_values,
    )

    _invalidate_entity_cache(entity_type)
    _audit("studio.field.updated", actor_sub, entity_type=entity_type, field_key=field_key, changed_attrs=changed_attrs)
    return get_field(entity_type, field_key)  # type: ignore[return-value]


def delete_field(actor_sub: str, entity_type: str, field_key: str) -> None:
    """Soft-delete: set is_active=False."""
    table = _get_table()

    existing = get_field(entity_type, field_key)
    if not existing:
        raise FieldNotFoundError(f"{entity_type}.{field_key}")

    ts = now_ts()
    table.update_item(
        Key={"entity_type": entity_type, "field_key": field_key},
        UpdateExpression="SET #ia = :ia, #ua = :ua, #ubs = :ubs",
        ExpressionAttributeNames={"#ia": "is_active", "#ua": "updated_at", "#ubs": "updated_by_sub"},
        ExpressionAttributeValues={":ia": False, ":ua": ts, ":ubs": actor_sub},
    )
    _invalidate_entity_cache(entity_type)
    _audit("studio.field.deactivated", actor_sub, entity_type=entity_type, field_key=field_key)


def list_fields(
    entity_type: str,
    include_inactive: bool = False,
    limit: int = 100,
    cursor: str | None = None,
) -> tuple[list[dict[str, Any]], str | None]:
    """List custom fields for an entity type."""
    items = _load_fields(entity_type, include_inactive=include_inactive)
    # Simple cursor pagination over the in-memory list
    start = 0
    if cursor:
        lek = decode_cursor(cursor)
        if lek and "offset" in lek:
            start = int(lek["offset"])
    chunk = items[start:start + limit]
    next_cursor = None
    if start + limit < len(items):
        next_cursor = encode_cursor({"offset": str(start + limit)})
    return chunk, next_cursor


def get_field(entity_type: str, field_key: str) -> dict[str, Any] | None:
    """Get a single field definition."""
    table = _get_table()
    resp = table.get_item(Key={"entity_type": entity_type, "field_key": field_key})
    return resp.get("Item")


def validate_custom_fields(entity_type: str, data: dict[str, Any]) -> dict[str, Any]:
    """
    Validate custom field data against the registry.
    Returns a (possibly coerced) copy of data.
    No-op when CRM_STUDIO_ENABLED=0.
    """
    from app.core.settings import S
    if not S.crm_studio_enabled:
        return data

    fields_list = _load_fields(entity_type, include_inactive=False)
    field_map = {f["field_key"]: f for f in fields_list}

    # Build result dict (copy)
    result = dict(data)
    errors: list[dict[str, Any]] = []

    # Check required fields + apply defaults
    for fk, fdef in field_map.items():
        if fk not in result:
            if fdef.get("required", False):
                errors.append({"field_key": fk, "code": "required_field_missing"})
            elif fdef.get("default_value") is not None:
                result[fk] = fdef["default_value"]

    # Validate provided custom_ keys
    for key, value in list(data.items()):
        if not key.startswith("custom_"):
            continue
        if key not in field_map:
            errors.append({"field_key": key, "code": "unknown_custom_field"})
            continue
        fdef = field_map[key]
        if not fdef.get("is_active", True):
            # Deactivated field: pass through without validation
            continue
        ftype = fdef.get("field_type", "text")
        try:
            result[key] = _coerce_and_validate(key, value, ftype, fdef)
        except CustomFieldValidationError as e:
            errors.append({"field_key": key, "code": str(e)})

    if errors:
        raise CustomFieldValidationError(str({"errors": errors}))

    return result


def _coerce_and_validate(key: str, value: Any, ftype: str, fdef: dict) -> Any:
    """Type-coerce and validate a single custom field value."""
    if ftype == "text":
        if not isinstance(value, str):
            raise CustomFieldValidationError(f"expected_text: {key}")
        max_len = int(fdef.get("max_length", 1000))
        if len(value) > max_len:
            raise CustomFieldValidationError(f"text_too_long: {key}")
        return value

    elif ftype == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            raise CustomFieldValidationError(f"expected_integer: {key}")
        _check_bounds(key, value, fdef)
        return value

    elif ftype == "decimal":
        if not isinstance(value, (int, float, Decimal)):
            raise CustomFieldValidationError(f"expected_decimal: {key}")
        coerced = Decimal(str(value))
        _check_bounds(key, float(coerced), fdef)
        return coerced

    elif ftype == "boolean":
        if not isinstance(value, bool):
            raise CustomFieldValidationError(f"expected_boolean: {key}")
        return value

    elif ftype == "date":
        if not isinstance(value, str):
            raise CustomFieldValidationError(f"expected_date_string: {key}")
        try:
            _date.fromisoformat(value)
        except ValueError:
            raise CustomFieldValidationError(f"invalid_date_format: {key}")
        return value

    elif ftype == "picklist":
        if not isinstance(value, str):
            raise CustomFieldValidationError(f"expected_string: {key}")
        picklist_name = fdef.get("picklist_name")
        if picklist_name:
            active_vals = _get_picklist_active_values(picklist_name)
            if active_vals is not None and value not in active_vals:
                raise CustomFieldValidationError(f"invalid_picklist_value: {key}")
        return value

    elif ftype == "multi_picklist":
        if not isinstance(value, list):
            raise CustomFieldValidationError(f"expected_list: {key}")
        picklist_name = fdef.get("picklist_name")
        active_vals = None
        if picklist_name:
            active_vals = _get_picklist_active_values(picklist_name)
        result = []
        for v in value:
            if not isinstance(v, str):
                raise CustomFieldValidationError(f"expected_string_in_list: {key}")
            if active_vals is not None and v not in active_vals:
                raise CustomFieldValidationError(f"invalid_picklist_value: {key}[{v}]")
            result.append(v)
        return result

    return value


def _check_bounds(key: str, value: float, fdef: dict) -> None:
    min_v = fdef.get("min_value")
    max_v = fdef.get("max_value")
    if min_v is not None and value < float(min_v):
        raise CustomFieldValidationError(f"value_below_minimum: {key}")
    if max_v is not None and value > float(max_v):
        raise CustomFieldValidationError(f"value_above_maximum: {key}")
