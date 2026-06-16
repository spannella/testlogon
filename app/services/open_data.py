"""Open Data service (CSN-005): Branches and ATMs.

Admin write (ROOT-only): create/update/delete Branch and ATM records.
Public read (no auth): list/get active records.

Flag-gated: S.open_data_enabled (OPEN_DATA_ENABLED, default OFF).
No money movement. No SCA. No auth in public read paths.
"""
from __future__ import annotations

import re
import uuid
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException, Request

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts


def _to_decimal(v: Any) -> Any:
    """Convert float to Decimal for DynamoDB storage (mirrors _FloatSafeTable)."""
    if isinstance(v, float):
        return Decimal(str(v))
    return v

_RESOURCE_ID_RE = re.compile(r"^(brn|atm)_[0-9a-f]{32}$")


def _item_to_branch(item: Dict[str, Any]) -> Dict[str, Any]:
    """Convert DDB item to BranchOut-compatible dict."""
    return {
        "branch_id": item.get("resource_id", ""),
        "name": item.get("name", ""),
        "address": {
            "line1": item.get("address_line1", ""),
            "line2": item.get("address_line2"),
            "city": item.get("address_city", ""),
            "region": item.get("address_region"),
            "country": item.get("address_country", ""),
            "postcode": item.get("address_postcode", ""),
        },
        "location": {
            "lat": float(item.get("lat", 0)),
            "lng": float(item.get("lng", 0)),
        },
        "opening_hours": list(item.get("opening_hours", [])),
        "accessibility": list(item.get("accessibility", [])),
        "phone": item.get("phone"),
        "is_active": bool(item.get("is_active", True)),
        "created_at": int(item.get("created_at", 0)),
        "updated_at": int(item.get("updated_at", 0)),
    }


def _item_to_atm(item: Dict[str, Any]) -> Dict[str, Any]:
    """Convert DDB item to AtmOut-compatible dict."""
    return {
        "atm_id": item.get("resource_id", ""),
        "name": item.get("name", ""),
        "address": {
            "line1": item.get("address_line1", ""),
            "line2": item.get("address_line2"),
            "city": item.get("address_city", ""),
            "region": item.get("address_region"),
            "country": item.get("address_country", ""),
            "postcode": item.get("address_postcode", ""),
        },
        "location": {
            "lat": float(item.get("lat", 0)),
            "lng": float(item.get("lng", 0)),
        },
        "is_active": bool(item.get("is_active", True)),
        "has_deposit": bool(item.get("has_deposit", False)),
        "is_accessible": bool(item.get("is_accessible", False)),
        "created_at": int(item.get("created_at", 0)),
        "updated_at": int(item.get("updated_at", 0)),
    }


def _body_to_branch_item(
    body: Any,
    resource_id: str,
    admin_sub: str,
    created_at: Optional[int] = None,
) -> Dict[str, Any]:
    now = now_ts()
    return {
        "kind": "BRANCH",
        "resource_id": resource_id,
        "kind_active": f"BRANCH#{1 if body.is_active else 0}",
        "name": body.name,
        "address_line1": body.address.line1,
        "address_line2": body.address.line2,
        "address_city": body.address.city,
        "address_region": body.address.region,
        "address_country": body.address.country,
        "address_postcode": body.address.postcode,
        "lat": _to_decimal(body.location.lat),
        "lng": _to_decimal(body.location.lng),
        "opening_hours": [oh.model_dump() for oh in (body.opening_hours or [])],
        "accessibility": list(body.accessibility or []),
        "phone": body.phone,
        "is_active": body.is_active,
        "created_by": admin_sub,
        "created_at": created_at if created_at is not None else now,
        "updated_at": now,
    }


def _body_to_atm_item(
    body: Any,
    resource_id: str,
    admin_sub: str,
    created_at: Optional[int] = None,
) -> Dict[str, Any]:
    now = now_ts()
    return {
        "kind": "ATM",
        "resource_id": resource_id,
        "kind_active": f"ATM#{1 if body.is_active else 0}",
        "name": body.name,
        "address_line1": body.address.line1,
        "address_line2": body.address.line2,
        "address_city": body.address.city,
        "address_region": body.address.region,
        "address_country": body.address.country,
        "address_postcode": body.address.postcode,
        "lat": _to_decimal(body.location.lat),
        "lng": _to_decimal(body.location.lng),
        "is_active": body.is_active,
        "has_deposit": body.has_deposit,
        "is_accessible": body.is_accessible,
        "created_by": admin_sub,
        "created_at": created_at if created_at is not None else now,
        "updated_at": now,
    }


def upsert_branch(
    admin_sub: str,
    body: Any,
    req: Optional[Request] = None,
    branch_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Create (POST) or full-replace (PUT) a branch record."""
    created_at: Optional[int] = None
    if branch_id:
        # Preserve created_at on update
        existing = get_branch(branch_id)
        if existing:
            created_at = existing.get("created_at")
    else:
        branch_id = "brn_" + uuid.uuid4().hex

    item = _body_to_branch_item(body, branch_id, admin_sub, created_at)
    T.open_data.put_item(Item=item)

    try:
        from app.services.alerts import audit_event
        audit_event("open_data.branch_upsert", admin_sub, req,
                    resource_id=branch_id, name=body.name)
    except Exception:
        pass

    return _item_to_branch(item)


def upsert_atm(
    admin_sub: str,
    body: Any,
    req: Optional[Request] = None,
    atm_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Create (POST) or full-replace (PUT) an ATM record."""
    created_at: Optional[int] = None
    if atm_id:
        existing = get_atm(atm_id)
        if existing:
            created_at = existing.get("created_at")
    else:
        atm_id = "atm_" + uuid.uuid4().hex

    item = _body_to_atm_item(body, atm_id, admin_sub, created_at)
    T.open_data.put_item(Item=item)

    try:
        from app.services.alerts import audit_event
        audit_event("open_data.atm_upsert", admin_sub, req,
                    resource_id=atm_id, name=body.name)
    except Exception:
        pass

    return _item_to_atm(item)


def get_branch(branch_id: str) -> Optional[Dict[str, Any]]:
    resp = T.open_data.get_item(Key={"kind": "BRANCH", "resource_id": branch_id})
    item = resp.get("Item")
    if not item:
        return None
    return _item_to_branch(item)


def get_atm(atm_id: str) -> Optional[Dict[str, Any]]:
    resp = T.open_data.get_item(Key={"kind": "ATM", "resource_id": atm_id})
    item = resp.get("Item")
    if not item:
        return None
    return _item_to_atm(item)


def list_branches(
    *,
    active_only: bool = True,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """List branches. active_only queries ByActive GSI; else base table."""
    from app.core.cursor import decode_cursor, encode_cursor

    limit = min(limit, getattr(S, "open_data_list_max_limit", 200))
    kwargs: Dict[str, Any] = {"Limit": limit}
    if cursor:
        esk = decode_cursor(cursor)
        if esk:
            kwargs["ExclusiveStartKey"] = esk

    if active_only:
        kwargs["IndexName"] = S.open_data_active_index
        kwargs["KeyConditionExpression"] = Key("kind_active").eq("BRANCH#1")
        resp = T.open_data.query(**kwargs)
    else:
        kwargs["KeyConditionExpression"] = Key("kind").eq("BRANCH")
        resp = T.open_data.query(**kwargs)

    items = [_item_to_branch(i) for i in resp.get("Items", [])]
    last_key = resp.get("LastEvaluatedKey")
    return items, encode_cursor(last_key) if last_key else None


def list_atms(
    *,
    active_only: bool = True,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """List ATMs. active_only queries ByActive GSI; else base table."""
    from app.core.cursor import decode_cursor, encode_cursor

    limit = min(limit, getattr(S, "open_data_list_max_limit", 200))
    kwargs: Dict[str, Any] = {"Limit": limit}
    if cursor:
        esk = decode_cursor(cursor)
        if esk:
            kwargs["ExclusiveStartKey"] = esk

    if active_only:
        kwargs["IndexName"] = S.open_data_active_index
        kwargs["KeyConditionExpression"] = Key("kind_active").eq("ATM#1")
        resp = T.open_data.query(**kwargs)
    else:
        kwargs["KeyConditionExpression"] = Key("kind").eq("ATM")
        resp = T.open_data.query(**kwargs)

    items = [_item_to_atm(i) for i in resp.get("Items", [])]
    last_key = resp.get("LastEvaluatedKey")
    return items, encode_cursor(last_key) if last_key else None


def delete_resource(
    kind: str,
    resource_id: str,
    admin_sub: str,
    req: Optional[Request] = None,
) -> None:
    """Hard-delete a branch or ATM record (idempotent)."""
    T.open_data.delete_item(Key={"kind": kind, "resource_id": resource_id})
    try:
        from app.services.alerts import audit_event
        audit_event("open_data.delete", admin_sub, req,
                    kind=kind, resource_id=resource_id)
    except Exception:
        pass
