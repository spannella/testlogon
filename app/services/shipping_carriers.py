"""Carrier & ship-method catalog service (SHP-004).

Owns the shipping_carriers DynamoDB table: carrier header rows (sk=CARRIER#)
and method rows (sk=METHOD#{method_code}). Provides CRUD + idempotent seed.
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

# Carrier codes that have tracking URL templates.
# Lazy-imported to avoid circular deps; kept here for easy reference.
SUPPORTED_CARRIER_CODES = {"ups", "fedex", "usps", "dhl", "manual"}
SUPPORTED_METHOD_CODES = {"ground", "express", "overnight", "economy", "flat_rate"}


def _online_tracking(carrier_code: str) -> bool:
    """Return True iff carrier_code is in CARRIER_TRACKING_URLS."""
    try:
        from app.services.carrier_tracking import CARRIER_TRACKING_URLS
        return carrier_code in CARRIER_TRACKING_URLS
    except ImportError:
        return carrier_code in {"ups", "fedex", "usps", "dhl"}


def _carrier_id(carrier_code: str) -> str:
    return hashlib.sha256(carrier_code.encode("utf-8")).hexdigest()[:16]


def _require_enabled() -> None:
    if not getattr(S, "shipping_enabled", False):
        raise HTTPException(status_code=404, detail="Shipping is not enabled")


def _audit(event: str, actor: str, **fields: Any) -> None:
    try:
        from app.services.alerts import audit_event
        audit_event(event, actor, None, **fields)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Carrier CRUD
# ---------------------------------------------------------------------------

def create_carrier(
    carrier_code: str,
    display_name: str,
    *,
    actor: str = "system",
) -> Dict[str, Any]:
    _require_enabled()
    if carrier_code not in SUPPORTED_CARRIER_CODES:
        raise HTTPException(status_code=422, detail=f"Unknown carrier_code: {carrier_code}")
    cid = _carrier_id(carrier_code)
    ts = now_ts()
    item: Dict[str, Any] = {
        "carrier_id": cid,
        "sk": "CARRIER#",
        "carrier_code": carrier_code,
        "display_name": display_name,
        "online_tracking": _online_tracking(carrier_code),
        "enabled": True,
        "created_at": ts,
        "updated_at": ts,
    }
    try:
        T.shipping_carriers.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(carrier_id)",
        )
    except T.shipping_carriers.meta.client.exceptions.ConditionalCheckFailedException:
        raise HTTPException(status_code=409, detail="Carrier already exists")
    _audit("shipping.carrier.created", actor, carrier_code=carrier_code, carrier_id=cid)
    return item


def get_carrier(carrier_id: str) -> Optional[Dict[str, Any]]:
    _require_enabled()
    resp = T.shipping_carriers.get_item(Key={"carrier_id": carrier_id, "sk": "CARRIER#"})
    return resp.get("Item")


def get_carrier_by_code(carrier_code: str) -> Optional[Dict[str, Any]]:
    _require_enabled()
    resp = T.shipping_carriers.query(
        IndexName="GSI_CODE",
        KeyConditionExpression=Key("carrier_code").eq(carrier_code) & Key("sk").eq("CARRIER#"),
    )
    items = resp.get("Items", [])
    return items[0] if items else None


def list_carriers(*, enabled_only: bool = True) -> List[Dict[str, Any]]:
    _require_enabled()
    # Scan for all CARRIER# rows
    resp = T.shipping_carriers.scan(
        FilterExpression="sk = :sk",
        ExpressionAttributeValues={":sk": "CARRIER#"},
    )
    items = resp.get("Items", [])
    if enabled_only:
        items = [i for i in items if i.get("enabled", True)]
    return sorted(items, key=lambda x: x.get("carrier_code", ""))


def update_carrier(carrier_id: str, *, patch: Dict[str, Any], actor: str = "system") -> Dict[str, Any]:
    _require_enabled()
    allowed = {"display_name", "enabled"}
    updates = {k: v for k, v in patch.items() if k in allowed}
    if not updates:
        item = get_carrier(carrier_id)
        if not item:
            raise HTTPException(status_code=404, detail="Carrier not found")
        return item
    updates["updated_at"] = now_ts()
    set_parts = ", ".join(f"#f_{k} = :v_{k}" for k in updates)
    names = {f"#f_{k}": k for k in updates}
    values = {f":v_{k}": v for k, v in updates.items()}
    T.shipping_carriers.update_item(
        Key={"carrier_id": carrier_id, "sk": "CARRIER#"},
        UpdateExpression=f"SET {set_parts}",
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
    )
    _audit("shipping.carrier.updated", actor, carrier_id=carrier_id)
    item = get_carrier(carrier_id)
    if not item:
        raise HTTPException(status_code=404, detail="Carrier not found")
    return item


def disable_carrier(carrier_id: str, *, actor: str = "system") -> None:
    _require_enabled()
    T.shipping_carriers.update_item(
        Key={"carrier_id": carrier_id, "sk": "CARRIER#"},
        UpdateExpression="SET #e = :f, updated_at = :ts",
        ExpressionAttributeNames={"#e": "enabled"},
        ExpressionAttributeValues={":f": False, ":ts": now_ts()},
    )
    _audit("shipping.carrier.disabled", actor, carrier_id=carrier_id)


# ---------------------------------------------------------------------------
# Method CRUD
# ---------------------------------------------------------------------------

def add_method(
    carrier_id: str,
    method_code: str,
    method_label: str,
    *,
    base_rate_cents: int,
    currency: Optional[str] = None,
    transit_days_min: Optional[int] = None,
    transit_days_max: Optional[int] = None,
    actor: str = "system",
) -> Dict[str, Any]:
    _require_enabled()
    if method_code not in SUPPORTED_METHOD_CODES:
        raise HTTPException(status_code=422, detail=f"Unknown method_code: {method_code}")
    carrier = get_carrier(carrier_id)
    if not carrier:
        raise HTTPException(status_code=404, detail="Carrier not found")
    if currency is None:
        currency = getattr(S, "shipping_default_currency", "usd")
    ts = now_ts()
    sk = f"METHOD#{method_code}"
    item: Dict[str, Any] = {
        "carrier_id": carrier_id,
        "sk": sk,
        "carrier_code": carrier["carrier_code"],
        "method_code": method_code,
        "method_label": method_label,
        "base_rate_cents": base_rate_cents,
        "currency": currency,
        "online_tracking": carrier.get("online_tracking", False),
        "enabled": True,
        "created_at": ts,
        "updated_at": ts,
    }
    if transit_days_min is not None:
        item["transit_days_min"] = transit_days_min
    if transit_days_max is not None:
        item["transit_days_max"] = transit_days_max
    try:
        T.shipping_carriers.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(carrier_id)",
        )
    except T.shipping_carriers.meta.client.exceptions.ConditionalCheckFailedException:
        raise HTTPException(status_code=409, detail="Method already exists for this carrier")
    _audit("shipping.method.added", actor, carrier_id=carrier_id, method_code=method_code)
    return item


def get_method(carrier_id: str, method_code: str) -> Optional[Dict[str, Any]]:
    _require_enabled()
    resp = T.shipping_carriers.get_item(
        Key={"carrier_id": carrier_id, "sk": f"METHOD#{method_code}"}
    )
    return resp.get("Item")


def list_methods(carrier_id: str, *, enabled_only: bool = False) -> List[Dict[str, Any]]:
    _require_enabled()
    resp = T.shipping_carriers.query(
        KeyConditionExpression=Key("carrier_id").eq(carrier_id) & Key("sk").begins_with("METHOD#"),
    )
    items = resp.get("Items", [])
    if enabled_only:
        items = [i for i in items if i.get("enabled", True)]
    return sorted(items, key=lambda x: x.get("method_code", ""))


def list_enabled_methods_all_carriers() -> List[Dict[str, Any]]:
    """Return all enabled methods across all enabled carriers."""
    _require_enabled()
    resp = T.shipping_carriers.scan(
        FilterExpression="begins_with(sk, :pfx) AND #e = :t",
        ExpressionAttributeNames={"#e": "enabled"},
        ExpressionAttributeValues={":pfx": "METHOD#", ":t": True},
    )
    return resp.get("Items", [])


def update_method(
    carrier_id: str,
    method_code: str,
    *,
    patch: Dict[str, Any],
    actor: str = "system",
) -> Dict[str, Any]:
    _require_enabled()
    allowed = {"method_label", "base_rate_cents", "currency", "transit_days_min",
               "transit_days_max", "enabled"}
    updates = {k: v for k, v in patch.items() if k in allowed}
    if not updates:
        item = get_method(carrier_id, method_code)
        if not item:
            raise HTTPException(status_code=404, detail="Method not found")
        return item
    updates["updated_at"] = now_ts()
    set_parts = ", ".join(f"#f_{k} = :v_{k}" for k in updates)
    names = {f"#f_{k}": k for k in updates}
    values = {f":v_{k}": v for k, v in updates.items()}
    T.shipping_carriers.update_item(
        Key={"carrier_id": carrier_id, "sk": f"METHOD#{method_code}"},
        UpdateExpression=f"SET {set_parts}",
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
    )
    _audit("shipping.method.updated", actor, carrier_id=carrier_id, method_code=method_code)
    item = get_method(carrier_id, method_code)
    if not item:
        raise HTTPException(status_code=404, detail="Method not found")
    return item


def disable_method(carrier_id: str, method_code: str, *, actor: str = "system") -> None:
    _require_enabled()
    T.shipping_carriers.update_item(
        Key={"carrier_id": carrier_id, "sk": f"METHOD#{method_code}"},
        UpdateExpression="SET #e = :f, updated_at = :ts",
        ExpressionAttributeNames={"#e": "enabled"},
        ExpressionAttributeValues={":f": False, ":ts": now_ts()},
    )
    _audit("shipping.method.disabled", actor, carrier_id=carrier_id, method_code=method_code)


# ---------------------------------------------------------------------------
# Idempotent seed
# ---------------------------------------------------------------------------

# Default seed data.  base_rate_cents in USD cents.
_SEED_DATA = [
    {
        "carrier_code": "ups", "display_name": "UPS",
        "methods": [
            {"method_code": "ground",    "method_label": "UPS Ground",    "base_rate_cents": 899,  "transit_days_min": 3, "transit_days_max": 5},
            {"method_code": "express",   "method_label": "UPS 2-Day Air", "base_rate_cents": 1899, "transit_days_min": 2, "transit_days_max": 2},
            {"method_code": "overnight", "method_label": "UPS Next Day",  "base_rate_cents": 2999, "transit_days_min": 1, "transit_days_max": 1},
        ],
    },
    {
        "carrier_code": "fedex", "display_name": "FedEx",
        "methods": [
            {"method_code": "ground",    "method_label": "FedEx Ground",    "base_rate_cents": 799,  "transit_days_min": 3, "transit_days_max": 7},
            {"method_code": "express",   "method_label": "FedEx 2-Day",     "base_rate_cents": 1799, "transit_days_min": 2, "transit_days_max": 2},
            {"method_code": "overnight", "method_label": "FedEx Priority",  "base_rate_cents": 2899, "transit_days_min": 1, "transit_days_max": 1},
            {"method_code": "economy",   "method_label": "FedEx Economy",   "base_rate_cents": 599,  "transit_days_min": 5, "transit_days_max": 10},
        ],
    },
    {
        "carrier_code": "usps", "display_name": "USPS",
        "methods": [
            {"method_code": "ground",    "method_label": "USPS Ground Advantage", "base_rate_cents": 499,  "transit_days_min": 2, "transit_days_max": 5},
            {"method_code": "economy",   "method_label": "USPS Media Mail",       "base_rate_cents": 299,  "transit_days_min": 7, "transit_days_max": 14},
        ],
    },
    {
        "carrier_code": "dhl", "display_name": "DHL",
        "methods": [
            {"method_code": "express",   "method_label": "DHL Express",  "base_rate_cents": 2199, "transit_days_min": 1, "transit_days_max": 3},
            {"method_code": "economy",   "method_label": "DHL Economy",  "base_rate_cents": 999,  "transit_days_min": 5, "transit_days_max": 10},
        ],
    },
    {
        "carrier_code": "manual", "display_name": "Manual / Other",
        "methods": [
            {"method_code": "flat_rate", "method_label": "Flat Rate",   "base_rate_cents": 0},
        ],
    },
]


def seed_default_carriers() -> None:
    """Idempotent seed: writes default carriers + methods.

    Uses attribute_not_exists condition — second call is a no-op.
    Runs outside of the shipping_enabled gate so it can be called at startup.
    """
    cur = getattr(S, "shipping_default_currency", "usd")
    ts = now_ts()
    for entry in _SEED_DATA:
        cc = entry["carrier_code"]
        cid = _carrier_id(cc)
        carrier_item: Dict[str, Any] = {
            "carrier_id": cid,
            "sk": "CARRIER#",
            "carrier_code": cc,
            "display_name": entry["display_name"],
            "online_tracking": _online_tracking(cc),
            "enabled": True,
            "created_at": ts,
            "updated_at": ts,
        }
        try:
            T.shipping_carriers.put_item(
                Item=carrier_item,
                ConditionExpression="attribute_not_exists(carrier_id)",
            )
        except Exception:
            pass  # already exists — idempotent

        for m in entry["methods"]:
            method_item: Dict[str, Any] = {
                "carrier_id": cid,
                "sk": f"METHOD#{m['method_code']}",
                "carrier_code": cc,
                "method_code": m["method_code"],
                "method_label": m["method_label"],
                "base_rate_cents": m["base_rate_cents"],
                "currency": cur,
                "online_tracking": _online_tracking(cc),
                "enabled": True,
                "created_at": ts,
                "updated_at": ts,
            }
            if m.get("transit_days_min") is not None:
                method_item["transit_days_min"] = m["transit_days_min"]
            if m.get("transit_days_max") is not None:
                method_item["transit_days_max"] = m["transit_days_max"]
            try:
                T.shipping_carriers.put_item(
                    Item=method_item,
                    ConditionExpression="attribute_not_exists(carrier_id)",
                )
            except Exception:
                pass  # already exists — idempotent
