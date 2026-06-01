"""Carrier tracking poll endpoints (SHOP-004).

Exposes a deterministic, synchronous "poll now" so E2E tests don't depend on a
background timer:

    POST /ui/shop/tracking/transactions/{txn_id}/poll
        Buyer/seller polls their own order against the carrier API; applies any
        status change and returns the refreshed tracking view.

    POST /ui/shop/tracking/poll-now
        Admin/root trigger: polls a batch of all in-flight orders.

Reuses carrier_tracking_poller (which reuses carrier_tracking +
purchase_history.update_shipping).
"""
from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, Query

from app.auth.policy import require_admin_or_root
from app.services.carrier_tracking import build_tracking_url
from app.services.carrier_tracking_poller import poll_all, poll_one
from app.services.purchase_history import get_transaction_info
from app.services.sessions import require_ui_session

carrier_tracking_poller_router = APIRouter(prefix="/ui/shop/tracking", tags=["carrier-tracking"])


def _tracking_view(user_sub: str, txn_id: str) -> Dict[str, Any]:
    info = get_transaction_info(user_sub, txn_id)
    shipping = info.get("shipping") or {}
    carrier = shipping.get("carrier")
    tracking_number = shipping.get("tracking_number")
    tracking_url = (
        build_tracking_url(carrier, tracking_number)
        if carrier and tracking_number
        else None
    )
    return {
        "txn_id": txn_id,
        "carrier": carrier,
        "tracking_number": tracking_number,
        "tracking_url": tracking_url,
        "status": shipping.get("status"),
        "status_description": shipping.get("status_description"),
        "estimated_delivery": shipping.get("estimated_delivery"),
        "delivered_at": shipping.get("delivered_at"),
        "carrier_events": shipping.get("carrier_events"),
        "last_carrier_check": shipping.get("last_carrier_check"),
    }


@carrier_tracking_poller_router.post("/transactions/{txn_id}/poll")
async def ui_poll_transaction(txn_id: str, ctx=Depends(require_ui_session)) -> Dict[str, Any]:
    """Poll the carrier for this order and apply any status change.

    Returns the poll outcome plus the refreshed tracking view.
    """
    user_sub = ctx["user_sub"]
    poll = poll_one(user_sub, txn_id)
    return {"poll": poll, "tracking": _tracking_view(user_sub, txn_id)}


@carrier_tracking_poller_router.post("/poll-now")
async def admin_poll_now(
    limit: int = Query(50, ge=1, le=500),
    user=Depends(require_admin_or_root),
) -> Dict[str, Any]:
    """Admin/root: poll a batch of in-flight orders against the carrier API."""
    _ = user
    return poll_all(limit=limit)
