"""Mock carrier tracking endpoints for dev/test.

Provides a seedable in-memory tracking state and lookup endpoint
for all supported carriers (not just UPS).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException

from app.core.settings import S
from app.services.carrier_tracking import CARRIER_TRACKING_URLS

router = APIRouter(tags=["mock", "carrier-tracking"])


def _mock_enabled() -> bool:
    return S.dev_mode


# ── In-memory state ───────────────────────────────────────────────

_TRACKING_STATE: Dict[str, Dict[str, Any]] = {}


def _state_key(carrier: str, tracking_number: str) -> str:
    return f"{carrier.lower()}:{tracking_number}"


# ── Seed endpoint ─────────────────────────────────────────────────

@router.post("/mock/carrier-tracking/seed")
def mock_carrier_tracking_seed(body: Dict[str, Any]) -> Dict[str, Any]:
    """Seed mock tracking data for testing.

    Body:
        carrier: str (e.g. "ups", "fedex", "usps", "dhl")
        tracking_number: str
        status: str (label_created, in_transit, out_for_delivery, delivered, exception)
        status_description: str (optional, human-readable)
        estimated_delivery: str (optional, ISO date)
        delivered_at: str (optional, ISO datetime)
        events: list (optional, carrier events)
    """
    if not _mock_enabled():
        raise HTTPException(404, "Not found")

    carrier = body.get("carrier", "").lower().strip()
    tracking_number = body.get("tracking_number", "").strip()

    if not carrier or not tracking_number:
        raise HTTPException(400, "carrier and tracking_number are required")

    if carrier not in CARRIER_TRACKING_URLS:
        raise HTTPException(422, f"Unknown carrier: {carrier}")

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    status = body.get("status", "in_transit")
    status_description = body.get("status_description", status.replace("_", " ").title())

    entry: Dict[str, Any] = {
        "tracking_number": tracking_number,
        "carrier": carrier,
        "status": status,
        "status_description": status_description,
        "estimated_delivery": body.get("estimated_delivery", "2026-06-05"),
        "delivered_at": body.get("delivered_at") if status == "delivered" else None,
        "events": body.get("events") or [
            {
                "timestamp": now_iso,
                "description": status_description,
                "location": "Mock City, MC, US",
            },
        ],
    }

    key = _state_key(carrier, tracking_number)
    _TRACKING_STATE[key] = entry
    return {"ok": True, "key": key}


# ── Lookup endpoint ───────────────────────────────────────────────

@router.get("/mock/carrier-tracking/{carrier}/{tracking_number}")
def mock_carrier_tracking_get(carrier: str, tracking_number: str) -> Dict[str, Any]:
    """Get mock tracking status for a carrier and tracking number.

    Returns seeded data if available, otherwise generates a default response
    based on the tracking number's last digit (same pattern as the UPS mock).
    """
    if not _mock_enabled():
        raise HTTPException(404, "Not found")

    carrier_lower = carrier.lower().strip()
    if carrier_lower not in CARRIER_TRACKING_URLS:
        raise HTTPException(422, f"Unknown carrier: {carrier_lower}")

    key = _state_key(carrier_lower, tracking_number.strip())

    # Return seeded data if available
    if key in _TRACKING_STATE:
        return _TRACKING_STATE[key]

    # Check if any seeded data exists at all -- if none, return 404 for explicit tracking
    # (This allows tests to verify that non-existent tracking numbers return 404)
    if tracking_number.strip() not in [v["tracking_number"] for v in _TRACKING_STATE.values()]:
        raise HTTPException(404, f"No tracking data for {carrier_lower}/{tracking_number}")

    raise HTTPException(404, f"No tracking data for {carrier_lower}/{tracking_number}")


# ── Reset (for test cleanup) ──────────────────────────────────────

@router.post("/mock/carrier-tracking/reset")
def mock_carrier_tracking_reset() -> Dict[str, Any]:
    """Clear all seeded tracking data."""
    if not _mock_enabled():
        raise HTTPException(404, "Not found")
    _TRACKING_STATE.clear()
    return {"ok": True}
