from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import HTTPException

from app.core.tables import T
from app.models import FileBundleCheckoutSessionIn, FileBundleSkuCreateIn


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_utc(text: str, field: str) -> datetime:
    raw = str(text or "").strip()
    if not raw:
        raise HTTPException(400, f"{field} is required")
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(raw)
    except Exception as exc:
        raise HTTPException(400, f"{field} must be ISO8601 datetime") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _bundle_key(sku: str) -> Dict[str, str]:
    return {"PK": f"SKU#{sku}", "SK": "LATEST"}


def create_file_bundle_sku(author_id: str, body: FileBundleSkuCreateIn) -> Dict[str, Any]:
    date_start = _parse_utc(body.date_start, "date_start")
    date_end = _parse_utc(body.date_end, "date_end")
    if date_end <= date_start:
        raise HTTPException(400, "date_end must be after date_start")
    if body.access_mode == "rental" and not body.rental_duration_hours:
        raise HTTPException(400, "rental_duration_hours is required for rental bundles")
    if body.access_mode == "purchase" and body.rental_duration_hours:
        raise HTTPException(400, "rental_duration_hours must not be set for purchase bundles")

    now = _now_iso()
    item = {
        **_bundle_key(body.sku),
        "entity": "file_bundle_sku",
        "product_type": "file_bundle",
        "sku": body.sku,
        "display_name": body.display_name,
        "amount_cents": int(body.amount_cents),
        "currency": body.currency.upper(),
        "billing_model": "rental" if body.access_mode == "rental" else "one_time",
        "access_mode": body.access_mode,
        "date_start": date_start.isoformat(),
        "date_end": date_end.isoformat(),
        "rental_duration_hours": int(body.rental_duration_hours) if body.rental_duration_hours else None,
        "created_at": now,
        "created_by": author_id,
        "updated_at": now,
    }
    T.catalog_products.put_item(Item=item)
    return item


def _load_file_bundle_sku(sku: str) -> Dict[str, Any]:
    item = T.catalog_products.get_item(Key=_bundle_key(sku)).get("Item")
    if not item or item.get("entity") != "file_bundle_sku":
        raise HTTPException(404, "File bundle SKU not found")
    return item


def create_file_bundle_checkout_session(user_id: str, body: FileBundleCheckoutSessionIn) -> Dict[str, Any]:
    sku = _load_file_bundle_sku(body.sku)
    req_start = _parse_utc(body.date_start, "date_start")
    req_end = _parse_utc(body.date_end, "date_end")
    if req_end <= req_start:
        raise HTTPException(400, "date_end must be after date_start")

    sku_start = _parse_utc(str(sku.get("date_start") or ""), "sku.date_start")
    sku_end = _parse_utc(str(sku.get("date_end") or ""), "sku.date_end")

    if req_start < sku_start or req_end > sku_end:
        raise HTTPException(400, "Requested date range must be within SKU date window")

    access_mode = str(body.access_mode)
    if access_mode != str(sku.get("access_mode")):
        raise HTTPException(400, "Requested access_mode does not match SKU configuration")
    if access_mode == "rental" and not sku.get("rental_duration_hours"):
        raise HTTPException(400, "Rental SKU is missing rental_duration_hours configuration")

    order_id = uuid.uuid4().hex
    checkout_session_id = f"chk_{uuid.uuid4().hex}"
    now = _now_iso()

    T.orders.put_item(
        Item={
            "order_id": order_id,
            "user_id": user_id,
            "status": "pending_payment",
            "created_at": now,
            "updated_at": now,
            "source": "file_bundle_checkout",
            "checkout_session_id": checkout_session_id,
            "currency": sku.get("currency", "USD"),
            "amount_cents": int(sku.get("amount_cents") or 0),
        }
    )
    T.order_items.put_item(
        Item={
            "order_id": order_id,
            "item_id": "1",
            "sku": sku["sku"],
            "product_type": "file_bundle",
            "scope": {
                "selection_type": "date_range",
                "date_start": req_start.isoformat(),
                "date_end": req_end.isoformat(),
                "access_mode": access_mode,
            },
            "rental_duration_hours": int(sku.get("rental_duration_hours") or 0) if access_mode == "rental" else 0,
            "created_at": now,
        }
    )

    return {
        "checkout_session_id": checkout_session_id,
        "order_id": order_id,
        "status": "pending_payment",
        "sku": sku["sku"],
        "amount_cents": int(sku.get("amount_cents") or 0),
        "currency": str(sku.get("currency") or "USD"),
        "access_mode": access_mode,
    }
