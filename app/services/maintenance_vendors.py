"""
Maintenance Vendor Directory — WOV-004.

Provides a trade-categorized vendor directory. Delegates to PUR-003
app.services.suppliers when available; falls back to the standalone
maintenance_vendors DynamoDB table when not.

Decision D2: vendors may carry an optional user_sub linking them to a
platform account for on-platform escrow payout (WOV-003).
"""
from __future__ import annotations

import hashlib
import logging
from typing import Any, Dict, Optional

from boto3.dynamodb.conditions import Attr, Key
from fastapi import HTTPException

from app.core.cursor import decode_cursor, encode_cursor
from app.core.tables import T
from app.core.time import now_ts
from app.models import VendorCreateIn, VendorListOut, VendorOut, VendorPatchIn

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Trade-category enum
# ---------------------------------------------------------------------------

VENDOR_TRADE_CATEGORIES: frozenset[str] = frozenset({
    "plumbing",
    "electrical",
    "hvac",
    "handyman",
    "cleaning",
    "landscaping",
    "general",
})

VENDOR_STATUSES: frozenset[str] = frozenset({"active", "inactive"})

# ---------------------------------------------------------------------------
# Flag + audit helpers
# ---------------------------------------------------------------------------


def _require_enabled() -> None:
    from app.core.settings import S
    if not getattr(S, "maintenance_orders_enabled", False):
        raise HTTPException(status_code=404, detail="Maintenance orders not enabled")


def _audit(event: str, user_sub: str, **fields: Any) -> None:
    try:
        from app.services.alerts import audit_event
        audit_event(event, user_sub or "system", None, **fields)
    except Exception:
        pass


def _to_int(value: Any, default: int = 0) -> int:
    try:
        if value is None:
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def _validate_trade_category(tc: str) -> None:
    if tc not in VENDOR_TRADE_CATEGORIES:
        raise HTTPException(
            status_code=422,
            detail={"code": "invalid_trade_category", "allowed": sorted(VENDOR_TRADE_CATEGORIES)},
        )


def _validate_status(status: str) -> None:
    if status not in VENDOR_STATUSES:
        raise HTTPException(
            status_code=422,
            detail={"code": "invalid_vendor_status", "allowed": sorted(VENDOR_STATUSES)},
        )


# ---------------------------------------------------------------------------
# Backend detection (PUR-003 vs standalone)
# ---------------------------------------------------------------------------

_PUR_AVAILABLE: Optional[bool] = None


def _pur_available() -> bool:
    global _PUR_AVAILABLE
    if _PUR_AVAILABLE is None:
        try:
            from app.services.suppliers import get_supplier  # noqa: F401 # type: ignore[import]
            from app.core.settings import S
            _PUR_AVAILABLE = bool(getattr(S, "purchasing_scm_enabled", False))
        except ImportError:
            _PUR_AVAILABLE = False
    return _PUR_AVAILABLE


def _vendor_id_for(actor_sub: str, name: str) -> str:
    return hashlib.sha256(f"supplier:{actor_sub}:{name}".encode()).hexdigest()[:32]


# ---------------------------------------------------------------------------
# Item → VendorOut
# ---------------------------------------------------------------------------


def _item_to_vendor_out(item: Dict[str, Any]) -> VendorOut:
    return VendorOut(
        vendor_id=item.get("vendor_id") or item.get("supplier_id") or item.get("pk", ""),
        name=item.get("name", ""),
        status=item.get("status", "active"),
        trade_category=item.get("trade_category", "general"),
        source=item.get("source", "maintenance_vendor"),
        email=item.get("email"),
        phone=item.get("phone"),
        address=item.get("address"),
        default_currency=item.get("default_currency", "USD"),
        payment_terms_days=_to_int(item.get("payment_terms_days"), 30),
        user_sub=item.get("user_sub") or None,
        created_by=item.get("created_by", ""),
        created_at=_to_int(item.get("created_at", 0)),
        updated_at=_to_int(item.get("updated_at", 0)),
    )


# ---------------------------------------------------------------------------
# Standalone backend helpers
# ---------------------------------------------------------------------------


def _standalone_get(vendor_id: str) -> Optional[Dict[str, Any]]:
    resp = T.maintenance_vendors.get_item(Key={"vendor_id": vendor_id, "sk": "META"})
    return resp.get("Item")


def _standalone_create(actor_sub: str, body: VendorCreateIn) -> VendorOut:
    from app.core.normalize import normalize_phone

    vid = _vendor_id_for(actor_sub, body.name)
    ts = now_ts()
    phone = normalize_phone(body.phone) if body.phone else None

    item: Dict[str, Any] = {
        "vendor_id": vid,
        "sk": "META",
        "name": body.name,
        "status": "active",
        "trade_category": body.trade_category,
        "source": "maintenance_vendor",
        "default_currency": body.default_currency,
        "payment_terms_days": body.payment_terms_days,
        "created_by": actor_sub,
        "created_at": ts,
        "updated_at": ts,
    }
    if body.email:
        item["email"] = body.email
    if phone:
        item["phone"] = phone
    if body.address:
        item["address"] = body.address
    if body.user_sub:
        item["user_sub"] = body.user_sub

    try:
        T.maintenance_vendors.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(vendor_id)",
        )
    except Exception as exc:
        from botocore.exceptions import ClientError
        if isinstance(exc, ClientError) and exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            # Idempotent — re-apply trade_category + source patch
            existing = _standalone_get(vid)
            if existing:
                _standalone_patch_category(vid, body.trade_category, body.user_sub)
                existing = _standalone_get(vid)
                return _item_to_vendor_out(existing)  # type: ignore[arg-type]
        raise

    return _item_to_vendor_out(item)


def _standalone_patch_category(vendor_id: str, trade_category: str, user_sub: Optional[str]) -> None:
    ts = now_ts()
    ue = "SET trade_category = :tc, #src = :s, updated_at = :ts"
    ea_names = {"#src": "source"}
    ea_vals: Dict[str, Any] = {":tc": trade_category, ":s": "maintenance_vendor", ":ts": ts}
    if user_sub:
        ue += ", user_sub = :us"
        ea_vals[":us"] = user_sub
    T.maintenance_vendors.update_item(
        Key={"vendor_id": vendor_id, "sk": "META"},
        UpdateExpression=ue,
        ExpressionAttributeNames=ea_names,
        ExpressionAttributeValues=ea_vals,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def create_vendor(actor_sub: str, body: VendorCreateIn) -> VendorOut:
    _require_enabled()
    _validate_trade_category(body.trade_category)

    from app.core.normalize import normalize_phone

    if _pur_available():
        from app.services.suppliers import create_supplier  # type: ignore[import]
        supplier = create_supplier(
            actor_sub,
            body.name,
            email=body.email,
            phone=body.phone,
            address=body.address,
            default_currency=body.default_currency,
            payment_terms_days=body.payment_terms_days,
        )
        sid = supplier.get("supplier_id") or supplier.get("vendor_id") or ""
        # Patch trade_category + source + user_sub onto the suppliers table
        from app.core.tables import T as _T
        ts = now_ts()
        ue = "SET trade_category = :tc, #src = :s, updated_at = :ts"
        ea_names = {"#src": "source"}
        ea_vals: Dict[str, Any] = {":tc": body.trade_category, ":s": "maintenance_vendor", ":ts": ts}
        if body.user_sub:
            ue += ", user_sub = :us"
            ea_vals[":us"] = body.user_sub
        _T.suppliers.update_item(  # type: ignore[attr-defined]
            Key={"supplier_id": sid, "sk": "META"},
            UpdateExpression=ue,
            ExpressionAttributeNames=ea_names,
            ExpressionAttributeValues=ea_vals,
        )
        item = _T.suppliers.get_item(Key={"supplier_id": sid, "sk": "META"}).get("Item", {})  # type: ignore[attr-defined]
        item["vendor_id"] = sid
        out = _item_to_vendor_out(item)
    else:
        out = _standalone_create(actor_sub, body)

    _audit("maintenance_vendor.created", actor_sub,
           vendor_id=out.vendor_id, trade_category=body.trade_category)
    return out


def get_vendor(vendor_id: str) -> Optional[VendorOut]:
    """
    Direct key lookup — does NOT call _require_enabled() so WOV-002's lazy
    import can use it without double-checking the flag.
    """
    if _pur_available():
        try:
            from app.services.suppliers import get_supplier  # type: ignore[import]
            from app.core.tables import T as _T
            item = _T.suppliers.get_item(Key={"supplier_id": vendor_id, "sk": "META"}).get("Item")  # type: ignore[attr-defined]
            if item is None:
                return None
            item["vendor_id"] = vendor_id
            return _item_to_vendor_out(item)
        except ImportError:
            pass

    item = _standalone_get(vendor_id)
    if item is None:
        return None
    return _item_to_vendor_out(item)


def update_vendor(vendor_id: str, actor_sub: str, body: VendorPatchIn) -> VendorOut:
    _require_enabled()
    if body.trade_category is not None:
        _validate_trade_category(body.trade_category)

    from app.core.normalize import normalize_phone

    item = _standalone_get(vendor_id)
    if item is None and _pur_available():
        try:
            from app.core.tables import T as _T
            item = _T.suppliers.get_item(Key={"supplier_id": vendor_id, "sk": "META"}).get("Item")  # type: ignore[attr-defined]
        except Exception:
            pass

    if item is None:
        raise HTTPException(status_code=404, detail="vendor_not_found")

    ts = now_ts()
    update_parts: list = ["updated_at = :ts"]
    ea_vals: Dict[str, Any] = {":ts": ts}
    ea_names: Dict[str, str] = {}

    if body.name is not None:
        update_parts.append("#nm = :nm")
        ea_names["#nm"] = "name"
        ea_vals[":nm"] = body.name
    if body.trade_category is not None:
        update_parts.append("trade_category = :tc")
        ea_vals[":tc"] = body.trade_category
    if body.email is not None:
        update_parts.append("email = :em")
        ea_vals[":em"] = body.email
    if body.phone is not None:
        update_parts.append("phone = :ph")
        ea_vals[":ph"] = normalize_phone(body.phone) if body.phone else body.phone
    if body.address is not None:
        update_parts.append("address = :ad")
        ea_vals[":ad"] = body.address
    if body.default_currency is not None:
        update_parts.append("default_currency = :dc")
        ea_vals[":dc"] = body.default_currency
    if body.payment_terms_days is not None:
        update_parts.append("payment_terms_days = :ptd")
        ea_vals[":ptd"] = body.payment_terms_days

    ue = "SET " + ", ".join(update_parts)
    remove_attrs: list = []

    # user_sub: None = leave alone; "" = clear; non-empty = set
    if body.user_sub is not None:
        if body.user_sub == "":
            remove_attrs.append("user_sub")
        else:
            ue += ", user_sub = :us"
            ea_vals[":us"] = body.user_sub

    if remove_attrs:
        ue += " REMOVE " + ", ".join(remove_attrs)

    # Use standalone or PUR table
    if _pur_available():
        try:
            from app.core.tables import T as _T
            kwargs: Dict[str, Any] = {
                "Key": {"supplier_id": vendor_id, "sk": "META"},
                "UpdateExpression": ue,
                "ExpressionAttributeValues": ea_vals,
            }
            if ea_names:
                kwargs["ExpressionAttributeNames"] = ea_names
            _T.suppliers.update_item(**kwargs)  # type: ignore[attr-defined]
            updated_item = _T.suppliers.get_item(Key={"supplier_id": vendor_id, "sk": "META"}).get("Item", {})  # type: ignore[attr-defined]
            updated_item["vendor_id"] = vendor_id
        except Exception:
            updated_item = item
    else:
        kwargs = {
            "Key": {"vendor_id": vendor_id, "sk": "META"},
            "UpdateExpression": ue,
            "ExpressionAttributeValues": ea_vals,
        }
        if ea_names:
            kwargs["ExpressionAttributeNames"] = ea_names
        T.maintenance_vendors.update_item(**kwargs)
        updated_item = _standalone_get(vendor_id) or item

    out = _item_to_vendor_out(updated_item)
    _audit("maintenance_vendor.updated", actor_sub, vendor_id=vendor_id)
    return out


def set_vendor_status(vendor_id: str, status: str, actor_sub: str) -> VendorOut:
    _require_enabled()
    _validate_status(status)

    item = _standalone_get(vendor_id)
    if item is None and _pur_available():
        try:
            from app.core.tables import T as _T
            item = _T.suppliers.get_item(Key={"supplier_id": vendor_id, "sk": "META"}).get("Item")  # type: ignore[attr-defined]
        except Exception:
            pass

    if item is None:
        raise HTTPException(status_code=404, detail="vendor_not_found")

    ts = now_ts()
    if _pur_available():
        try:
            from app.core.tables import T as _T
            _T.suppliers.update_item(  # type: ignore[attr-defined]
                Key={"supplier_id": vendor_id, "sk": "META"},
                UpdateExpression="SET #st = :s, updated_at = :ts",
                ExpressionAttributeNames={"#st": "status"},
                ExpressionAttributeValues={":s": status, ":ts": ts},
            )
            updated_item = _T.suppliers.get_item(Key={"supplier_id": vendor_id, "sk": "META"}).get("Item", item)  # type: ignore[attr-defined]
            updated_item["vendor_id"] = vendor_id
        except Exception:
            updated_item = item
    else:
        T.maintenance_vendors.update_item(
            Key={"vendor_id": vendor_id, "sk": "META"},
            UpdateExpression="SET #st = :s, updated_at = :ts",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={":s": status, ":ts": ts},
        )
        updated_item = _standalone_get(vendor_id) or item

    out = _item_to_vendor_out(updated_item)
    _audit("maintenance_vendor.status_changed", actor_sub, vendor_id=vendor_id, status=status)
    return out


def list_vendors(
    status: str = "active",
    *,
    trade_category: Optional[str] = None,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> VendorListOut:
    _require_enabled()
    if limit > 200:
        limit = 200

    kwargs: Dict[str, Any] = {
        "ScanIndexForward": False,
        "Limit": limit,
        "KeyConditionExpression": Key("status").eq(status),
    }
    if cursor:
        start_key = decode_cursor(cursor)
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key

    # Build filter: always source="maintenance_vendor", optionally trade_category
    filter_expr = Attr("source").eq("maintenance_vendor")
    if trade_category:
        filter_expr = filter_expr & Attr("trade_category").eq(trade_category)
    kwargs["FilterExpression"] = filter_expr

    if _pur_available():
        try:
            from app.core.tables import T as _T
            kwargs["IndexName"] = "GSI_STATUS"
            resp = _T.suppliers.query(**kwargs)  # type: ignore[attr-defined]
            for it in resp.get("Items", []):
                it["vendor_id"] = it.get("supplier_id", it.get("vendor_id", ""))
        except Exception:
            resp = {"Items": [], "LastEvaluatedKey": None}
    else:
        kwargs["IndexName"] = "GSI_VENDOR_STATUS"
        resp = T.maintenance_vendors.query(**kwargs)

    vendors = [_item_to_vendor_out(i) for i in resp.get("Items", [])]
    return VendorListOut(
        vendors=vendors,
        count=len(vendors),
        cursor=encode_cursor(resp.get("LastEvaluatedKey")),
    )
