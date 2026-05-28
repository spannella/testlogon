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
