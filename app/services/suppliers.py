"""PUR-003 — Supplier (vendor party) CRUD service.

All public functions raise HTTPException(404) when purchasing_scm_enabled is False.
Idempotency: create_supplier derives supplier_id = sha256(f"supplier:{user_sub}:{name}")[:32].
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional

from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _flag_on() -> bool:
    return getattr(S, "purchasing_scm_enabled", False)


def _require_enabled() -> None:
    if not _flag_on():
        raise HTTPException(status_code=404, detail="Purchasing/SCM is not enabled")


def _audit(event: str, user_sub: str, **fields: Any) -> None:
    try:
        from app.services.alerts import audit_event  # lazy — avoids circular imports
        audit_event(event, user_sub, None, **fields)
    except Exception:
        pass


def _supplier_id(user_sub: str, name: str) -> str:
    return hashlib.sha256(f"supplier:{user_sub}:{name}".encode()).hexdigest()[:32]


def _item_to_supplier(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "supplier_id": item.get("supplier_id", ""),
        "name": item.get("name", ""),
        "status": item.get("status", "active"),
        "email": item.get("email"),
        "phone": item.get("phone"),
        "address": item.get("address"),
        "default_currency": item.get("default_currency", "USD"),
        "payment_terms_days": _to_int(item.get("payment_terms_days"), 30),
        "created_by": item.get("created_by", ""),
        "created_at": _to_int(item.get("created_at")),
        "updated_at": _to_int(item.get("updated_at")),
    }


def create_supplier(
    user_sub: str,
    name: str,
    *,
    email: Optional[str] = None,
    phone: Optional[str] = None,
    address: Optional[Dict[str, Any]] = None,
    default_currency: str = "USD",
    payment_terms_days: int = 30,
) -> Dict[str, Any]:
    """Create or idempotently overwrite a supplier record.

    supplier_id = sha256(f"supplier:{user_sub}:{name}")[:32] — deterministic.
    """
    _require_enabled()

    # Normalize phone to E.164 if provided
    if phone:
        try:
            from app.core.normalize import normalize_phone  # lazy
            phone = normalize_phone(phone)
        except Exception:
            pass

    sid = _supplier_id(user_sub, name)
    ts = now_ts()
    item: Dict[str, Any] = {
        "supplier_id": sid,
        "sk": "META",
        "name": name,
        "status": "active",
        "default_currency": default_currency,
        "payment_terms_days": payment_terms_days,
        "created_by": user_sub,
        "created_at": ts,
        "updated_at": ts,
    }
    if email is not None:
        item["email"] = email
    if phone is not None:
        item["phone"] = phone
    if address is not None:
        item["address"] = address

    T.suppliers.put_item(Item=item)
    _audit("supplier_created", user_sub, supplier_id=sid, name=name)
    return _item_to_supplier(item)


def get_supplier(supplier_id: str) -> Optional[Dict[str, Any]]:
    _require_enabled()
    resp = T.suppliers.get_item(Key={"supplier_id": supplier_id, "sk": "META"})
    item = resp.get("Item")
    if not item:
        return None
    return _item_to_supplier(item)


def update_supplier(
    supplier_id: str,
    user_sub: str,
    *,
    name: Optional[str] = None,
    email: Optional[str] = None,
    phone: Optional[str] = None,
    address: Optional[Dict[str, Any]] = None,
    default_currency: Optional[str] = None,
    payment_terms_days: Optional[int] = None,
) -> Dict[str, Any]:
    _require_enabled()

    existing = get_supplier(supplier_id)
    if not existing:
        raise HTTPException(status_code=404, detail="supplier_not_found")

    ts = now_ts()
    expr_parts: List[str] = ["updated_at = :ua"]
    eav: Dict[str, Any] = {":ua": ts}

    if name is not None:
        expr_parts.append("#nm = :nm")
        eav[":nm"] = name
    if email is not None:
        expr_parts.append("email = :em")
        eav[":em"] = email
    if phone is not None:
        try:
            from app.core.normalize import normalize_phone
            phone = normalize_phone(phone)
        except Exception:
            pass
        expr_parts.append("phone = :ph")
        eav[":ph"] = phone
    if address is not None:
        expr_parts.append("address = :addr")
        eav[":addr"] = address
    if default_currency is not None:
        expr_parts.append("default_currency = :cur")
        eav[":cur"] = default_currency
    if payment_terms_days is not None:
        expr_parts.append("payment_terms_days = :ptd")
        eav[":ptd"] = payment_terms_days

    ean: Dict[str, str] = {}
    if name is not None:
        ean["#nm"] = "name"

    kwargs: Dict[str, Any] = {
        "Key": {"supplier_id": supplier_id, "sk": "META"},
        "UpdateExpression": "SET " + ", ".join(expr_parts),
        "ExpressionAttributeValues": eav,
        "ReturnValues": "ALL_NEW",
    }
    if ean:
        kwargs["ExpressionAttributeNames"] = ean

    resp = T.suppliers.update_item(**kwargs)
    updated = resp.get("Attributes", {})
    _audit("supplier_updated", user_sub, supplier_id=supplier_id)
    return _item_to_supplier(updated)


def set_supplier_status(supplier_id: str, status: str, user_sub: str) -> Dict[str, Any]:
    """Set supplier status to 'active' or 'inactive'."""
    _require_enabled()
    if status not in ("active", "inactive"):
        raise HTTPException(status_code=422, detail="status must be 'active' or 'inactive'")

    existing = get_supplier(supplier_id)
    if not existing:
        raise HTTPException(status_code=404, detail="supplier_not_found")

    ts = now_ts()
    resp = T.suppliers.update_item(
        Key={"supplier_id": supplier_id, "sk": "META"},
        UpdateExpression="SET #s = :s, updated_at = :ua",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": status, ":ua": ts},
        ReturnValues="ALL_NEW",
    )
    updated = resp.get("Attributes", {})
    _audit("supplier_status_changed", user_sub, supplier_id=supplier_id, status=status)
    return _item_to_supplier(updated)


def list_suppliers(
    status: str = "active",
    *,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    """Paginate suppliers by status via GSI_STATUS. Returns {'suppliers': [...], 'cursor': ...}."""
    _require_enabled()

    from app.core.cursor import encode_cursor, decode_cursor  # lazy

    kwargs: Dict[str, Any] = {
        "IndexName": "GSI_STATUS",
        "KeyConditionExpression": "#s = :s",
        "ExpressionAttributeNames": {"#s": "status"},
        "ExpressionAttributeValues": {":s": status},
        "Limit": limit,
    }
    if cursor:
        try:
            kwargs["ExclusiveStartKey"] = decode_cursor(cursor)
        except Exception:
            pass

    resp = T.suppliers.query(**kwargs)
    items = resp.get("Items", [])
    last_key = resp.get("LastEvaluatedKey")
    next_cursor = encode_cursor(last_key) if last_key else None

    return {
        "suppliers": [_item_to_supplier(i) for i in items],
        "cursor": next_cursor,
    }
