"""Shipping rate estimation engine (SHP-006).

Built-in deterministic estimator with optional UPS Rating API seam.
Stateless: reads from shipping_carriers (via shipping_carriers service), writes nothing.
"""
from __future__ import annotations

import hashlib
import math
from datetime import date, timedelta
from typing import Any, Dict, List, Optional

from fastapi import HTTPException

from app.core.settings import S
from app.core.time import now_ts

# Weight-based increment ladder: method_code → sorted list of (min_oz, cents_per_lb)
_WEIGHT_LADDER: Dict[str, List[tuple]] = {
    "ground":    [(0, 15), (160, 25)],
    "express":   [(0, 45), (160, 65)],
    "overnight": [(0, 80), (160, 120)],
    "economy":   [(0, 10), (160, 18)],
    "flat_rate": [(0, 0)],
}


def _require_enabled() -> None:
    if not getattr(S, "shipping_enabled", False):
        raise HTTPException(status_code=404, detail="Shipping is not enabled")
    if not getattr(S, "shipping_rate_estimation_enabled", False):
        raise HTTPException(status_code=404, detail="Shipping rate estimation is not enabled")


def _cents_per_lb_for(method_code: str, total_oz: int) -> int:
    ladder = _WEIGHT_LADDER.get(method_code, [(0, 0)])
    chosen = 0
    for min_oz, rate in sorted(ladder, key=lambda x: x[0]):
        if total_oz >= min_oz:
            chosen = rate
    return chosen


def _calc_rate(method: Dict[str, Any], total_oz: int, dim_weight_oz: Optional[int] = None) -> int:
    """Compute final rate in cents for a given method and weight."""
    billed_oz = total_oz
    if dim_weight_oz is not None:
        billed_oz = max(total_oz, dim_weight_oz)
    base = int(method.get("base_rate_cents", 0))
    method_code = method.get("method_code", "flat_rate")
    cpl = _cents_per_lb_for(method_code, billed_oz)
    # incremental = cpl × ceil(billed_oz / 16)  [per pound]
    lbs = math.ceil(billed_oz / 16) if billed_oz > 0 else 0
    return base + cpl * lbs


def _estimate_delivery(method: Dict[str, Any]) -> Optional[str]:
    """Return ISO date string estimate based on transit_days_max."""
    days = method.get("transit_days_max")
    if days is None:
        days = method.get("transit_days_min")
    if days is None:
        return None
    est = date.today() + timedelta(days=int(days))
    return est.isoformat()


def estimate_rates(
    *,
    carrier_code: Optional[str] = None,
    method_code: Optional[str] = None,
    weight_oz: int = 0,
    destination_zip: str = "",
    origin_zip: Optional[str] = None,
    user_sub: str = "anonymous",
) -> Dict[str, Any]:
    """Return a ShippingRateQuote for the given parameters.

    If carrier_code + method_code are supplied, returns a single option.
    Otherwise returns all enabled methods across all carriers.
    """
    _require_enabled()

    # Lazy import to avoid circular deps at module load
    from app.services.shipping_carriers import list_enabled_methods_all_carriers, get_method, _carrier_id

    if carrier_code and method_code:
        # Single-method estimate
        cid = _carrier_id(carrier_code)
        method = get_method(cid, method_code)
        if not method or not method.get("enabled", True):
            methods: List[Dict[str, Any]] = []
        else:
            methods = [method]
    else:
        methods = list_enabled_methods_all_carriers()
        if carrier_code:
            methods = [m for m in methods if m.get("carrier_code") == carrier_code]
        if method_code:
            methods = [m for m in methods if m.get("method_code") == method_code]

    dim_divisor = getattr(S, "shipping_dim_divisor", 139)
    currency = getattr(S, "shipping_default_currency", "usd")

    options: List[Dict[str, Any]] = []
    for m in methods:
        rate = _calc_rate(m, weight_oz)
        opt: Dict[str, Any] = {
            "carrier_code": m.get("carrier_code", ""),
            "method_code": m.get("method_code", ""),
            "rate_cents": rate,
            "currency": m.get("currency", currency),
            "transit_days_min": m.get("transit_days_min"),
            "transit_days_max": m.get("transit_days_max"),
            "estimated_delivery": _estimate_delivery(m),
        }
        options.append(opt)

    request_id = hashlib.sha256(
        f"{carrier_code or ''}|{method_code or ''}|{weight_oz}|{destination_zip}".encode()
    ).hexdigest()[:16]

    # Audit
    try:
        from app.services.alerts import audit_event
        audit_event("shipping_rate.estimated", user_sub, None,
                    weight_oz=weight_oz, destination_zip=destination_zip,
                    options_count=len(options))
    except Exception:
        pass

    return {
        "request_id": request_id,
        "options": options,
        "currency": currency,
        "generated_at": now_ts(),
    }


def estimate_rates_for_line_items(
    *,
    destination: Dict[str, Any],
    line_items: List[Dict[str, Any]],
    user_sub: str = "anonymous",
) -> Dict[str, Any]:
    """Estimate rates for a cart/order by summing line-item weights."""
    _require_enabled()
    default_weight = getattr(S, "shipping_default_item_weight_oz", 16)
    total_oz = 0
    for li in line_items:
        qty = int(li.get("quantity", 1))
        weight = li.get("weight_oz") or li.get("shipping_weight_oz") or default_weight
        total_oz += qty * int(weight)

    destination_zip = str(destination.get("postal_code", destination.get("zip", "")))
    return estimate_rates(
        weight_oz=total_oz,
        destination_zip=destination_zip,
        user_sub=user_sub,
    )
