"""Carrier-API polling + order-update layer (SHOP-004).

This module polls the (mock, in dev) carrier tracking API for an order's
tracking number and applies the resulting status to the order's shipping
record via ``carrier_tracking.apply_tracking_result``.

It is deliberately deterministic: a single poll for a given order reads the
current seeded mock carrier state and applies it. The "poll now" admin/root
endpoint drives this synchronously so E2E tests don't depend on a background
timer. An optional background loop (disabled by default, gated by
``carrier_tracking_poll_enabled``) reuses the exact same per-order code path.

Reuses (does NOT reimplement):
    - carrier_tracking.build_tracking_url / detect_carrier / map_carrier_status
    - carrier_tracking.apply_tracking_result / send_delivery_alert
    - purchase_history.update_shipping (via apply_tracking_result)
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional

from app.core.settings import S
from app.core.tables import T
from app.services.carrier_tracking import (
    ACTIVE_TRACKING_STATUSES,
    apply_tracking_result,
    map_carrier_status,
)

logger = logging.getLogger(__name__)


def _lookup_carrier_state(carrier: str, tracking_number: str) -> Optional[Dict[str, Any]]:
    """Read the current mock carrier tracking state for a tracking number.

    Returns the seeded mock entry (normalized response shape) or None when no
    tracking data has been seeded for this carrier + tracking number.
    """
    from app.routers.carrier_tracking_mock import _TRACKING_STATE, _state_key

    if not carrier or not tracking_number:
        return None
    return _TRACKING_STATE.get(_state_key(carrier, tracking_number))


def poll_order(order: Dict[str, Any]) -> Dict[str, Any]:
    """Poll the carrier for a single order and apply any status change.

    Returns a result dict describing what happened:
        {
            "txn_id": str,
            "polled": bool,        # True if carrier had tracking data
            "updated": bool,       # True if the order shipping changed
            "old_status": str | None,
            "new_status": str | None,
            "reason": str,         # short machine-readable explanation
        }
    """
    txn_id = str(order.get("txn_id") or "")
    shipping = order.get("shipping") or {}
    carrier = (shipping.get("carrier") or "").lower().strip()
    tracking_number = (shipping.get("tracking_number") or "").strip()
    old_status = (shipping.get("status") or "").strip() or None

    base = {
        "txn_id": txn_id,
        "polled": False,
        "updated": False,
        "old_status": old_status,
        "new_status": old_status,
    }

    if not carrier or not tracking_number:
        return {**base, "reason": "no_tracking_info"}

    state = _lookup_carrier_state(carrier, tracking_number)
    if not state:
        return {**base, "reason": "no_carrier_data"}

    # Normalize the carrier status into our internal enum. The mock already
    # stores internal-style statuses, but route through map_carrier_status so
    # real carrier descriptions are handled identically.
    raw_status = state.get("status") or state.get("status_description") or ""
    normalized = map_carrier_status(carrier, raw_status)
    # The mock stores internal statuses directly (e.g. "out_for_delivery"); if
    # the raw value is already a known internal status, keep it verbatim.
    if (state.get("status") or "") in (
        ACTIVE_TRACKING_STATUSES | {"delivered", "exception", "returned"}
    ):
        normalized = state["status"]

    result = {
        "status": normalized,
        "status_description": state.get("status_description"),
        "estimated_delivery": state.get("estimated_delivery"),
        "delivered_at": state.get("delivered_at"),
        "events": state.get("events"),
    }

    info = apply_tracking_result(order, result)
    new_status = normalized
    if info is None:
        return {
            **base,
            "polled": True,
            "updated": False,
            "new_status": new_status,
            "reason": "unchanged",
        }

    return {
        "txn_id": txn_id,
        "polled": True,
        "updated": True,
        "old_status": old_status,
        "new_status": new_status,
        "reason": "updated",
    }


def poll_one(user_sub: str, txn_id: str) -> Dict[str, Any]:
    """Poll a single order owned by ``user_sub`` and apply any status change."""
    from app.services.purchase_history import get_transaction_item

    order = get_transaction_item(user_sub, txn_id)
    return poll_order(order)


def get_pollable_orders(limit: int) -> List[Dict[str, Any]]:
    """Scan for orders that have a tracking number and are still in flight.

    Sparse: only items that carry a top-level ``tracking_number`` attribute
    (written by ``update_shipping``) are returned. Filtered down to orders
    whose shipping status is still active (or unset/shipped).
    """
    orders: List[Dict[str, Any]] = []
    scan_kwargs: Dict[str, Any] = {
        "FilterExpression": "attribute_exists(tracking_number)",
    }
    last_key = None
    while True:
        if last_key:
            scan_kwargs["ExclusiveStartKey"] = last_key
        resp = T.purchase_transactions.scan(**scan_kwargs)
        for item in resp.get("Items", []):
            status = ((item.get("shipping") or {}).get("status") or "").strip()
            if status and status not in ACTIVE_TRACKING_STATUSES:
                continue
            orders.append(item)
            if len(orders) >= limit:
                return orders
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    return orders


def poll_all(limit: Optional[int] = None) -> Dict[str, Any]:
    """Poll a batch of in-flight orders. Used by the admin "poll now" trigger.

    Deterministic: reads currently-seeded carrier state and applies it. Returns
    a summary plus a per-order list of results.
    """
    cap = limit or int(S.carrier_tracking_poll_batch_size)
    orders = get_pollable_orders(cap)
    results: List[Dict[str, Any]] = []
    updated = 0
    for order in orders:
        try:
            res = poll_order(order)
        except Exception:
            logger.exception("Error polling order %s", order.get("txn_id"))
            continue
        results.append(res)
        if res.get("updated"):
            updated += 1
    return {
        "checked": len(orders),
        "updated": updated,
        "results": results,
    }


async def carrier_polling_loop() -> None:
    """Background loop that periodically polls in-flight orders.

    Disabled unless ``carrier_tracking_poll_enabled`` is set. Reuses poll_all.
    """
    interval = max(1, int(S.carrier_tracking_poll_interval_minutes)) * 60
    while True:
        try:
            poll_all()
        except Exception:
            logger.exception("Error in carrier polling cycle")
        await asyncio.sleep(interval)


def start_carrier_polling_task() -> None:
    """Register the carrier polling loop as an asyncio background task.

    No-op unless ``carrier_tracking_poll_enabled`` is set. The synchronous
    "poll now" endpoint is the primary (deterministic) trigger; this loop is an
    optional fallback for non-webhook carriers.
    """
    if not S.carrier_tracking_poll_enabled:
        return
    asyncio.create_task(carrier_polling_loop())
