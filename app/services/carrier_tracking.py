"""Carrier tracking URL construction, auto-detection, and status mapping."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional


# ── Tracking URL Templates ────────────────────────────────────────

CARRIER_TRACKING_URLS: Dict[str, str] = {
    "ups": "https://www.ups.com/track?tracknum={tracking_number}",
    "fedex": "https://www.fedex.com/fedextrack/?trknbr={tracking_number}",
    "usps": "https://tools.usps.com/go/TrackConfirmAction?tLabels={tracking_number}",
    "dhl": "https://www.dhl.com/us-en/home/tracking/tracking-parcel.html?submit=1&tracking-id={tracking_number}",
}

# ── Carrier Detection Patterns ────────────────────────────────────

# UPS: 1Z + 16 alphanumeric characters (18 total)
_UPS_PATTERN = re.compile(r"^1Z[A-Z0-9]{16}$", re.IGNORECASE)

# FedEx: 12, 15, 20, or 22 digits
_FEDEX_LENGTHS = {12, 15, 20, 22}

# USPS: 20, 22, 30, or 34 digits (or starts with specific prefixes)
_USPS_LENGTHS = {20, 22, 30, 34}
_USPS_PREFIXES = ("94", "92", "93", "70", "23", "13")

# DHL: 10 digits or starts with JD/JJD followed by digits
_DHL_PATTERN = re.compile(r"^(JJD?\d{18,20}|\d{10})$", re.IGNORECASE)


def build_tracking_url(carrier: str, tracking_number: str) -> Optional[str]:
    """Construct a tracking URL for the given carrier and tracking number.

    Returns full tracking URL string, or None if carrier is unknown.
    """
    if not carrier or not tracking_number:
        return None
    template = CARRIER_TRACKING_URLS.get(carrier.lower().strip())
    if not template:
        return None
    return template.format(tracking_number=tracking_number.strip())


def detect_carrier(tracking_number: str) -> Optional[str]:
    """Auto-detect carrier from tracking number format.

    Detection rules (applied in order):
        1. UPS: starts with "1Z" + 16 alphanumeric = 18 chars total
        2. DHL: starts with JD/JJD + digits, or exactly 10 digits
        3. FedEx: 12, 15, 20, or 22 digits (all numeric)
        4. USPS: 20, 22, 30, or 34 digits OR starts with 94/92/93/70/23/13
        5. Unknown: None
    """
    tn = tracking_number.strip().upper()
    if not tn:
        return None

    # UPS: 1Z prefix + 16 alphanumeric
    if _UPS_PATTERN.match(tn):
        return "ups"

    # DHL: JD/JJD prefix or exactly 10 digits
    if _DHL_PATTERN.match(tn):
        return "dhl"

    # Numeric-only patterns
    if tn.isdigit():
        length = len(tn)
        # FedEx lengths that don't overlap with USPS
        if length in _FEDEX_LENGTHS and length not in _USPS_LENGTHS:
            return "fedex"
        # USPS lengths
        if length in _USPS_LENGTHS:
            return "usps"
        # USPS prefixes (for other lengths)
        if any(tn.startswith(p) for p in _USPS_PREFIXES):
            return "usps"

    return None


def map_carrier_status(carrier: str, raw_status: str) -> str:
    """Normalize carrier-specific status codes to our internal status enum.

    Internal statuses: label_created, picked_up, in_transit,
                       out_for_delivery, delivered, exception, returned.
    """
    status_lower = (raw_status or "").lower().strip()

    # UPS status mapping
    if carrier == "ups":
        if status_lower in ("label created", "manifest pickup", "billing information received"):
            return "label_created"
        if status_lower in ("picked up", "package picked up", "origin scan"):
            return "picked_up"
        if status_lower in ("in transit", "in-transit", "departed facility", "arrived at facility"):
            return "in_transit"
        if status_lower in ("out for delivery",):
            return "out_for_delivery"
        if status_lower in ("delivered",):
            return "delivered"
        if status_lower in ("exception", "returned to sender", "undeliverable"):
            return "exception"

    # Default mapping
    if "deliver" in status_lower:
        return "delivered"
    if "transit" in status_lower:
        return "in_transit"
    if "out for" in status_lower:
        return "out_for_delivery"
    if "picked" in status_lower or "pickup" in status_lower:
        return "picked_up"

    return "in_transit"  # safe default


# ── Order shipping status update (SHOP-004) ───────────────────────
#
# These helpers apply a carrier tracking result to an order's shipping
# sub-record. Used by both the webhook receiver and the polling layer so
# the two share a single code path. They reuse update_shipping() from the
# purchase_history service (which itself reuses detect_carrier /
# build_tracking_url) and fire the seller delivery alert on delivery.

# Internal statuses that mean the package is still moving and worth polling.
ACTIVE_TRACKING_STATUSES = {
    "shipped",
    "label_created",
    "picked_up",
    "in_transit",
    "out_for_delivery",
}


def apply_tracking_result(
    order: Dict[str, Any],
    result: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Apply a normalized carrier tracking result to an order's shipping record.

    ``order`` is a full purchase-transaction DynamoDB item (must include
    ``user_sub`` / ``buyer_id`` and ``txn_id``). ``result`` is a normalized
    tracking response with at least a ``status`` field, and optionally
    ``status_description``, ``events``, ``estimated_delivery`` and
    ``delivered_at``.

    Returns the updated transaction info dict if the order was changed, or
    ``None`` if nothing changed (status unchanged → idempotent, no update).
    """
    # Imported lazily to avoid a circular import (purchase_history imports
    # build_tracking_url / detect_carrier from this module).
    from app.core.time import now_ts
    from app.services.purchase_history import update_shipping

    shipping = dict(order.get("shipping") or {})
    new_status = (result.get("status") or "").strip()
    if not new_status:
        return None

    old_status = (shipping.get("status") or "").strip()
    delivered_already = old_status == "delivered"

    # Idempotent: don't re-write or re-alert when nothing changed.
    if new_status == old_status:
        return None

    shipping["status"] = new_status
    if result.get("status_description"):
        shipping["status_description"] = result["status_description"]
    if result.get("estimated_delivery"):
        shipping["estimated_delivery"] = result["estimated_delivery"]
    events = result.get("events")
    if events:
        # Cap at 20 stored events to bound item size.
        shipping["carrier_events"] = list(events)[:20]
    shipping["last_carrier_check"] = now_ts()
    if new_status == "delivered":
        shipping["delivered_at"] = now_ts()

    buyer_sub = order.get("user_sub") or order.get("buyer_id")
    txn_id = order.get("txn_id")
    if not buyer_sub or not txn_id:
        return None

    info = update_shipping(str(buyer_sub), str(txn_id), shipping)

    # Fire the seller delivery alert exactly once on the transition to
    # "delivered" (skip if it was already delivered).
    if new_status == "delivered" and not delivered_already:
        send_delivery_alert(order, shipping.get("tracking_number"))

    return info


def send_delivery_alert(order: Dict[str, Any], tracking_number: Optional[str]) -> None:
    """Alert the seller (and buyer) that a package was delivered.

    Reuses the existing alerts system (write_alert). Best effort — never
    raises into the caller.
    """
    from app.services.alerts import write_alert

    txn_id = str(order.get("txn_id") or "")
    buyer_sub = str(order.get("user_sub") or order.get("buyer_id") or "")
    # Seller may be stored under a few keys depending on order shape.
    seller_sub = str(
        order.get("seller_sub")
        or order.get("seller_id")
        or (order.get("metadata") or {}).get("seller_sub")
        or ""
    )
    tn = str(tracking_number or "")

    details = {
        "alert_type": "delivery_confirmed",
        "txn_id": txn_id,
        "tracking_number": tn,
    }

    targets = [s for s in (seller_sub, buyer_sub) if s]
    # Avoid double-alerting when buyer == seller.
    seen: set = set()
    for sub in targets:
        if sub in seen:
            continue
        seen.add(sub)
        try:
            write_alert(
                sub,
                event="delivery_confirmed",
                outcome="success",
                title="Package delivered",
                details=details,
            )
        except Exception:
            pass
