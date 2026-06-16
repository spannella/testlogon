"""ECM-002/004/005/006/007/008/010 — Store integration layer.

This module is the thin gate/wrapper that enriches storefront responses
(catalog browse, live availability, pricing breakdown, order fulfillment)
by calling sibling services via lazy imports and graceful degrade.

RULE-2 compliance: every sibling call is guarded by its own flag via
_integration_enabled(sub_flag) AND getattr(S, "<sibling>_flag", False).

Design principles:
- Pure read-merge layer; no DynamoDB writes of its own
- _safe_upstream and _safe_upstream_async swallow all exceptions → degraded legacy output
- No dev_mode branches — SECOPS-007 parity
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable, Dict, List, Optional, TypeVar

from app.core.settings import S

logger = logging.getLogger(__name__)

_T = TypeVar("_T")

# Sub-flag name → Settings attribute name mapping (ECM-002)
_SUB_FLAG_ATTRS: Dict[str, str] = {
    "live_availability": "store_show_live_availability",
    "pricing_rules": "store_apply_pricing_rules",
    "fulfillment_status": "store_show_fulfillment_status",
    "variant_selection": "store_variant_selection_enabled",
    "cart_reservations": "store_cart_reservations_enabled",
}


# ── ECM-002: Gate helpers ──────────────────────────────────────────────────


def _integration_enabled(sub_flag: Optional[str] = None) -> bool:
    """Return True iff STORE_INTEGRATION_ENABLED is on AND, when sub_flag is
    provided, the named per-surface sub-flag is also on.

    sub_flag must be one of: "live_availability", "pricing_rules",
    "fulfillment_status", "variant_selection", "cart_reservations", or None.

    Uses getattr with a False default so callers written before the settings
    fields existed still degrade gracefully.
    """
    if not getattr(S, "store_integration_enabled", False):
        return False
    if sub_flag is None:
        return True
    attr = _SUB_FLAG_ATTRS.get(sub_flag)
    if attr is None:
        logger.warning("_integration_enabled: unknown sub_flag %r", sub_flag)
        return False
    return bool(getattr(S, attr, False))


def _safe_upstream(call: Callable[[], _T], default: _T) -> _T:
    """Invoke call(); on any exception log at WARNING and return default.

    Guarantees upstream failures never propagate into browse/cart/checkout.
    Synchronous only — use _safe_upstream_async for coroutines.
    """
    try:
        return call()
    except Exception:
        logger.warning(
            "_safe_upstream: upstream call failed, returning default",
            exc_info=True,
        )
        return default


async def _safe_upstream_async(coro: Any, default: _T) -> _T:
    """Await a coroutine; on any exception log at WARNING and return default."""
    try:
        return await coro
    except Exception:
        logger.warning(
            "_safe_upstream_async: upstream call failed, returning default",
            exc_info=True,
        )
        return default


# ── ECM-004: Variant enrichment ────────────────────────────────────────────


def _build_storefront_variant(variant_dict: dict, parent_price_cents: int) -> Any:
    """Construct a StorefrontVariantOut from a PRD-007 variant dict."""
    from app.models import StorefrontVariantOut  # local import avoids circular at module level

    effective_price = max(0, parent_price_cents + int(variant_dict.get("price_delta_cents", 0)))
    return StorefrontVariantOut(
        variant_id=variant_dict["variant_id"],
        sku=variant_dict["sku"],
        option_selections=dict(variant_dict.get("feature_values") or {}),
        price_cents=effective_price,
        availability=None,  # populated by ECM-005 in a second pass
    )


def _fetch_variants(parent_item_id: str, parent_price_cents: Any) -> List[Any]:
    """Call PRD-007 product_variants.list_variants; returns List[StorefrontVariantOut].

    Lazy import so ECM-004 is deployable before PRD-007 is merged.
    ModuleNotFoundError is caught by _safe_upstream.
    """
    try:
        from app.services import product_variants  # noqa: F401 – lazy
    except ImportError:
        raise

    # ECM-014 §13 decision: also self-resolve product type from T.product_depth TYPE row
    # if PRD-008 has not yet pre-populated the catalog dict.
    # This is purely additive and is skipped if product_variants is not available.
    # list_variants returns (rows, last_evaluated_key) — unpack first element.
    raw_variants, _lek = product_variants.list_variants(parent_item_id)  # type: ignore[name-defined]
    base_price = int(parent_price_cents or 0)
    return [_build_storefront_variant(v, base_price) for v in raw_variants]


def enrich_catalog_item(item: dict, *, viewer: dict) -> Any:
    """Return a CatalogItemOut enriched with variant topology.

    When STORE_VARIANT_SELECTION_ENABLED is off OR the item is not a virtual
    product OR the upstream call fails, returns the legacy CatalogItemOut unchanged.
    Guaranteed to never raise.
    """
    from app.routers.catalog import _catalog_item_out  # lazy import avoids circular

    if not _integration_enabled("variant_selection"):
        return _catalog_item_out(item)

    product_type = item.get("product_type")

    # If product_type not set on the T.catalog row (pre-PRD-003 items), check T.product_depth
    if product_type is None and getattr(S, "product_depth_enabled", False):
        product_type = _safe_upstream(
            lambda: _lookup_product_type(item.get("item_id", "")),
            default=None,
        )

    if product_type != "virtual":
        return _catalog_item_out(item)

    parent_item_id = item.get("item_id", "")
    variants: List[Any] = _safe_upstream(
        lambda: _fetch_variants(parent_item_id, item.get("price_cents", 0)),
        default=[],
    )

    base = _catalog_item_out(item)
    return base.model_copy(update={"variants": variants or None})


def _lookup_product_type(item_id: str) -> Optional[str]:
    """Look up the product type from T.product_depth TYPE row (PRD-007/PRD-008 path)."""
    from app.core.tables import T  # local to avoid circular

    resp = T.product_depth.get_item(  # type: ignore[attr-defined]
        Key={"PK": f"ITEM#{item_id}", "SK": "TYPE"}
    )
    row = resp.get("Item")
    if not row:
        return None
    return str(row.get("product_type") or "standalone")


# ── ECM-005: Live availability projection ──────────────────────────────────


def _avail_from_inventory_row(row: dict, catalog_stock_count: Optional[int] = None) -> Any:
    """Build StorefrontAvailabilityOut from an inventory service record dict."""
    from app.models import StorefrontAvailabilityOut

    on_hand = int(row.get("on_hand", 0))
    reserved = int(row.get("reserved", 0))
    available = on_hand - reserved
    reorder_point = int(row.get("reorder_point", getattr(S, "catalog_default_low_stock_threshold", 5)))

    if available <= 0:
        stock_status = "out_of_stock"
        low_stock = False
    elif available <= reorder_point:
        stock_status = "low_stock"
        low_stock = True
    else:
        stock_status = "in_stock"
        low_stock = False

    return StorefrontAvailabilityOut(
        available=available,
        on_hand=on_hand,
        reserved=reserved,
        low_stock=low_stock,
        stock_status=stock_status,
    )


def _avail_from_stock_count(stock_count: Optional[int], low_stock_threshold: int = 5) -> Any:
    """Build StorefrontAvailabilityOut from a legacy catalog stock_count scalar."""
    from app.models import StorefrontAvailabilityOut

    threshold = low_stock_threshold or getattr(S, "catalog_default_low_stock_threshold", 5)
    if stock_count is None:
        return StorefrontAvailabilityOut(
            available=9999, on_hand=9999, reserved=0,
            low_stock=False, stock_status="unlimited",
        )
    sc = int(stock_count)
    if sc <= 0:
        return StorefrontAvailabilityOut(
            available=0, on_hand=0, reserved=0,
            low_stock=False, stock_status="out_of_stock",
        )
    low_stock = sc <= threshold
    return StorefrontAvailabilityOut(
        available=sc, on_hand=sc, reserved=0,
        low_stock=low_stock,
        stock_status="low_stock" if low_stock else "in_stock",
    )


def availability_for_skus(
    skus: List[str],
    *,
    location_id: str = "default",
) -> Dict[str, Any]:
    """Batch-read StorefrontAvailabilityOut for a list of SKUs.

    When STORE_SHOW_LIVE_AVAILABILITY is off OR inventory_reservations_enabled
    is off, returns an empty dict (callers fall back to stock_count).

    RULE-2: guards on both ECM sub-flag AND sibling inventory flag.
    """
    if not _integration_enabled("live_availability"):
        return {}
    if not getattr(S, "inventory_reservations_enabled", False):
        return {}
    if not skus:
        return {}

    return _safe_upstream(lambda: _batch_get_inventory(skus, location_id), default={})


def _batch_get_inventory(skus: List[str], location_id: str) -> Dict[str, Any]:
    """Issue a BatchGetItem against T.inventory for the given SKU list."""
    from app.core.tables import T  # local

    location_sk = f"LOC#{location_id}"
    keys = [{"sku": s, "location_sk": location_sk} for s in skus[:100]]

    table_name = getattr(S, "inventory_table_name", "inventory")
    response = T.inventory.meta.client.batch_get_item(  # type: ignore[attr-defined]
        RequestItems={table_name: {"Keys": keys}}
    )
    rows = response.get("Responses", {}).get(table_name, [])
    result: Dict[str, Any] = {}
    for row in rows:
        sku = row.get("sku", "")
        result[sku] = _avail_from_inventory_row(row)
    return result


def _apply_live_availability(item_out: Any, avail_map: Dict[str, Any]) -> Any:
    """Rebind stock_status/stock_count/availability on a CatalogItemOut from the map.

    Falls through to the existing scalar when the SKU is absent from the map.
    """
    if not avail_map:
        return item_out

    # Use item_id as the SKU key (ECM-005 convention)
    sku = getattr(item_out, "item_id", None)
    avail = avail_map.get(sku)
    if avail is None:
        return item_out

    return item_out.model_copy(update={
        "stock_status": avail.stock_status,
        "stock_count": avail.available,
        "availability": avail,
    })


# ── ECM-006: Pricing breakdown ─────────────────────────────────────────────


def get_cart_pricing_breakdown(user_sub: str, cart_id: str) -> Any:
    """Apply pricing rules and return CartPricingBreakdownOut.

    When STORE_APPLY_PRICING_RULES is off OR pricing_rules_enabled is off,
    returns a plain CartPricingBreakdownOut with no rule lines and
    final_total_cents == subtotal_cents.

    RULE-2: guards on both ECM sub-flag AND sibling pricing_rules flag.
    """
    from app.models import CartPricingBreakdownOut
    from app.services.shoppingcart import cart_total_cents, list_items as sc_list_items  # type: ignore

    items = _safe_upstream(lambda: sc_list_items(user_sub, cart_id), default=[])
    subtotal = sum(int(i.get("line_total_cents", 0)) for i in items)

    if not _integration_enabled("pricing_rules"):
        return CartPricingBreakdownOut(
            cart_id=cart_id,
            subtotal_cents=subtotal,
            applied_rules=[],
            discount_cents=0,
            final_total_cents=subtotal,
        )

    if not getattr(S, "pricing_rules_enabled", False):
        return CartPricingBreakdownOut(
            cart_id=cart_id,
            subtotal_cents=subtotal,
            applied_rules=[],
            discount_cents=0,
            final_total_cents=subtotal,
        )

    # Lazy import: pricing_rules is owned by OFB-019 — may not exist yet
    result = _safe_upstream(
        lambda: _apply_pricing_rules(user_sub, cart_id, items, subtotal),
        default=None,
    )
    if result is None:
        return CartPricingBreakdownOut(
            cart_id=cart_id,
            subtotal_cents=subtotal,
            applied_rules=[],
            discount_cents=0,
            final_total_cents=subtotal,
        )
    return result


def _apply_pricing_rules(
    user_sub: str,
    cart_id: str,
    items: List[dict],
    subtotal: int,
) -> Any:
    """Delegate to OFB-019 pricing_rules service (lazy import)."""
    from app.models import AppliedPricingRuleLineOut, CartPricingBreakdownOut

    try:
        from app.services import pricing_rules  # type: ignore[attr-defined]
    except ImportError:
        raise

    rule_result = pricing_rules.apply_rules(items, user_sub)  # type: ignore[attr-defined]

    applied: List[AppliedPricingRuleLineOut] = []
    discount = 0
    for rl in (rule_result.get("rule_lines") or []):
        line = AppliedPricingRuleLineOut(
            rule_id=rl.get("rule_id", ""),
            rule_name=rl.get("rule_name", ""),
            discount_type=rl.get("discount_type", "fixed_amount"),
            discount_cents=int(rl.get("discount_cents", 0)),
            applies_to_skus=rl.get("applies_to_skus") or [],
        )
        applied.append(line)
        discount += line.discount_cents

    discount = min(discount, subtotal)  # clamp
    return CartPricingBreakdownOut(
        cart_id=cart_id,
        subtotal_cents=subtotal,
        applied_rules=applied,
        discount_cents=discount,
        final_total_cents=subtotal - discount,
    )


# ── ECM-007: Order fulfillment status ──────────────────────────────────────


def get_order_fulfillment_status(order_id: str, *, user_sub: str) -> Any:
    """Return OrderFulfillmentStatusOut for a buyer's order.

    When STORE_SHOW_FULFILLMENT_STATUS is off, returns the minimal shape with
    all optional fields None.

    RULE-2: guards on both ECM sub-flag AND sibling order/shipping flags.
    Security: ownership check against user_sub before returning.
    """
    from app.models import OrderFulfillmentStatusOut
    from app.core.tables import T  # local

    # Base shape — always returned (flags off → only order_id populated)
    empty = OrderFulfillmentStatusOut(
        order_id=order_id,
        lifecycle_status=None,
        fulfillment_status=None,
        ship_groups=[],
        tracking_numbers=[],
    )

    if not _integration_enabled("fulfillment_status"):
        return empty

    # Ownership check via orders table
    order = _safe_upstream(lambda: _get_order(order_id, user_sub), default=None)
    if order is None:
        return empty

    lifecycle_status: Optional[str] = None
    fulfillment_status: Optional[str] = None

    # ORD lifecycle (ORD-005/007 — flag-gated)
    if getattr(S, "order_lifecycle_enabled", False):
        lifecycle_status = _safe_upstream(
            lambda: _get_lifecycle_status(order_id, user_sub),
            default=None,
        )

    # SHP shipping (SHP-010/012/014 — flag-gated)
    ship_groups: List[Any] = []
    tracking_numbers: List[str] = []
    if getattr(S, "shipping_enabled", False):
        sg_result = _safe_upstream(
            lambda: _get_ship_groups(order_id, user_sub),
            default=([], []),
        )
        ship_groups, tracking_numbers = sg_result

    # fulfillment_status derived from ship_groups if not provided by SHP
    if ship_groups:
        statuses = [sg.status for sg in ship_groups]
        if all(s == "delivered" for s in statuses):
            fulfillment_status = "delivered"
        elif any(s == "shipped" for s in statuses):
            fulfillment_status = "shipped"
        elif any(s in ("picked", "packed") for s in statuses):
            fulfillment_status = "processing"
        else:
            fulfillment_status = "pending"

    return OrderFulfillmentStatusOut(
        order_id=order_id,
        lifecycle_status=lifecycle_status,
        fulfillment_status=fulfillment_status,
        ship_groups=ship_groups,
        tracking_numbers=tracking_numbers,
    )


def _get_order(order_id: str, user_sub: str) -> Optional[dict]:
    """Read an order from T.orders and enforce ownership."""
    from app.core.tables import T

    resp = T.orders.get_item(  # type: ignore[attr-defined]
        Key={"order_id": order_id}
    )
    row = resp.get("Item")
    if not row:
        return None
    # Ownership check — never return another user's order
    if str(row.get("user_sub") or row.get("user_id") or "") != user_sub:
        return None
    return row


def _get_lifecycle_status(order_id: str, user_sub: str) -> Optional[str]:
    """Call ORD-005 order_lifecycle service (lazy import)."""
    try:
        from app.services import order_lifecycle  # type: ignore[attr-defined]
    except ImportError:
        raise

    result = order_lifecycle.get_order_lifecycle(order_id)  # type: ignore[attr-defined]
    return result.get("lifecycle_status") if result else None


def _get_ship_groups(order_id: str, user_sub: str) -> tuple:
    """Call SHP-010 shipments service (lazy import)."""
    from app.models import ShipGroupFulfillmentOut

    try:
        from app.services import shipments  # type: ignore[attr-defined]
    except ImportError:
        raise

    raw_groups = shipments.list_ship_groups(order_id)  # type: ignore[attr-defined]
    groups: List[ShipGroupFulfillmentOut] = []
    tracking: List[str] = []
    for sg in (raw_groups or []):
        g = ShipGroupFulfillmentOut(
            ship_group_id=sg.get("ship_group_id", ""),
            status=sg.get("status", "pending"),
            items=sg.get("items") or [],
            carrier=sg.get("carrier"),
            tracking_number=sg.get("tracking_number"),
            shipped_at=sg.get("shipped_at"),
            estimated_delivery=sg.get("estimated_delivery"),
        )
        groups.append(g)
        if g.tracking_number:
            tracking.append(g.tracking_number)
    # Deduplicate tracking numbers
    seen: set = set()
    tracking = [t for t in tracking if not (t in seen or seen.add(t))]  # type: ignore[func-returns-value]
    return groups, tracking


# ── ECM-008: Soft reservation lifecycle at cart add/remove ────────────────


def _reservations_enabled_for_sku(sku: str) -> bool:  # noqa: ARG001
    """Return True iff both the master inventory flag AND the ECM cart-reservation
    sub-flag are on. The sku param is present for future per-SKU overrides."""
    return (
        getattr(S, "inventory_reservations_enabled", False)
        and _integration_enabled("cart_reservations")
    )


def reserve_for_cart(
    *,
    user_sub: str,
    cart_id: str,
    sku: str,
    quantity: int,
    location_id: str = "default",
) -> Optional[str]:
    """Place a soft reservation for cart_id/sku; return reservation_id or None.

    Failure is swallowed — cart add always succeeds even if reservation fails.
    """
    if not _reservations_enabled_for_sku(sku):
        return None

    return _safe_upstream(
        lambda: _do_reserve(user_sub, cart_id, sku, quantity, location_id),
        default=None,
    )


def _reservation_id_for(cart_id: str, sku: str) -> str:
    """Deterministic reservation ID: sha256(cart_id#sku)[:16]."""
    import hashlib
    return hashlib.sha256(f"{cart_id}#{sku}".encode()).hexdigest()[:16]


def _do_reserve(
    user_sub: str,
    cart_id: str,
    sku: str,
    quantity: int,
    location_id: str,
) -> Optional[str]:
    """Call inventory.reserve with a deterministic reservation_id."""
    try:
        from app.services import inventory as inv_svc  # type: ignore[attr-defined]
    except ImportError:
        raise

    reservation_id = _reservation_id_for(cart_id, sku)
    ttl = getattr(S, "cart_ttl_days", 30) * 86400

    inv_svc.reserve(  # type: ignore[attr-defined]
        sku,
        quantity,
        location_id=location_id,
        cart_id=cart_id,
        user_sub=user_sub,
        ttl_seconds=ttl,
        reservation_id=reservation_id,
    )
    return reservation_id


def release_cart_reservations(
    *,
    user_sub: str,
    cart_id: str,
    skus: Optional[List[str]] = None,
) -> None:
    """Release all active reservations for a cart (called on delete_cart or checkout).

    Failure is swallowed — cart delete always succeeds even if release fails.
    """
    if not getattr(S, "inventory_reservations_enabled", False):
        return
    if not _integration_enabled("cart_reservations"):
        return

    _safe_upstream(
        lambda: _do_release_cart(user_sub, cart_id, skus),
        default=None,
    )


def _do_release_cart(
    user_sub: str,
    cart_id: str,
    skus: Optional[List[str]] = None,
) -> None:
    """List active reservations for the cart and release each one."""
    try:
        from app.services import inventory as inv_svc  # type: ignore[attr-defined]
    except ImportError:
        raise

    from app.core.tables import T

    # Query GSI_CART on the reservations table for this cart_id
    resp = T.reservations.query(  # type: ignore[attr-defined]
        IndexName="GSI_CART",
        KeyConditionExpression="cart_id = :cid",
        FilterExpression="#st = :active",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":cid": cart_id, ":active": "active"},
    )
    rows = resp.get("Items", [])
    for row in rows:
        res_id = row.get("reservation_id") or str(row.get("PK", "")).removeprefix("RES#")
        if skus and row.get("sku") not in skus:
            continue
        try:
            inv_svc.release_reservation(  # type: ignore[attr-defined]
                res_id,
                reason="cart_deleted",
                user_sub=user_sub,
                terminal_status="released",
            )
        except Exception:
            logger.warning("release_cart_reservations: failed to release %s", res_id, exc_info=True)


def commit_cart_reservations(
    *,
    user_sub: str,
    cart_id: str,
    items: List[dict],
) -> bool:
    """At purchase time: commit (or fall back to scalar decrement) per item.

    Returns True if ALL reservations committed via the inventory service,
    False if the scalar-decrement path was used (flag off or no reservation found).
    """
    if not _reservations_enabled_for_sku("__any__"):
        return False

    return bool(_safe_upstream(
        lambda: _do_commit_cart(user_sub, cart_id, items),
        default=False,
    ))


def _do_commit_cart(user_sub: str, cart_id: str, items: List[dict]) -> bool:
    """Commit each reservation; fall back to scalar path if no reservation exists."""
    try:
        from app.services import inventory as inv_svc  # type: ignore[attr-defined]
    except ImportError:
        raise

    all_committed = True
    for item in items:
        sku = item.get("sku") or item.get("item_id") or ""
        if not sku:
            continue
        reservation_id = _reservation_id_for(cart_id, sku)
        try:
            inv_svc.commit_reservation(reservation_id)  # type: ignore[attr-defined]
        except Exception:
            logger.warning(
                "commit_cart_reservations: could not commit %s for sku=%s — "
                "scalar decrement path will be used",
                reservation_id, sku,
            )
            all_committed = False
    return all_committed


# ── ECM-010: Cart total with pricing rules wired ───────────────────────────


def cart_total_with_breakdown(
    user_sub: str,
    cart_id: str,
) -> Dict[str, Any]:
    """Return a dict suitable for ShoppingCartTotalOut, optionally enriched with
    CartPricingBreakdownOut when STORE_APPLY_PRICING_RULES is on.

    When the flag is off, the result is identical to the existing plain-sum path.
    """
    from app.services.shoppingcart import cart_total_cents  # type: ignore

    total = cart_total_cents(user_sub, cart_id)
    if not _integration_enabled("pricing_rules"):
        return {"cart_id": cart_id, "total_cents": total, "currency": "USD", "pricing_breakdown": None}

    breakdown = _safe_upstream(
        lambda: get_cart_pricing_breakdown(user_sub, cart_id),
        default=None,
    )
    # Use authoritative total from breakdown when available
    if breakdown is not None:
        total = breakdown.final_total_cents
    return {
        "cart_id": cart_id,
        "total_cents": total,
        "currency": "USD",
        "pricing_breakdown": breakdown,
    }
