from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import HTTPException

from app.core.settings import S


@dataclass(frozen=True)
class RoutePriceTier:
    up_to_calls: int
    price_per_call_micros: int


@dataclass(frozen=True)
class RoutePrice:
    price_per_call_micros: int
    tiers: List[RoutePriceTier]


@dataclass(frozen=True)
class PricingCatalogVersion:
    pricing_catalog_version: str
    effective_at: int
    routes: Dict[str, RoutePrice]
    default_route: Optional[RoutePrice]


@dataclass(frozen=True)
class ResolvedRoutePricing:
    pricing_catalog_version: str
    effective_at: int
    route_id: str
    matched_route_id: str
    unit_price_micros: int


def _parse_effective_at(raw: Any) -> int:
    if raw is None:
        return 0
    if isinstance(raw, (int, float)):
        return int(raw)
    text = str(raw).strip()
    if not text:
        return 0
    if text.isdigit():
        return int(text)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def _parse_route_price(raw: Any) -> RoutePrice:
    data = raw if isinstance(raw, dict) else {}
    base = max(0, int(data.get("price_per_call_micros") or 0))
    tiers_raw = data.get("tiers") if isinstance(data.get("tiers"), list) else []
    tiers: List[RoutePriceTier] = []
    for row in tiers_raw:
        if not isinstance(row, dict):
            continue
        up_to = int(row.get("up_to_calls") or 0)
        price = max(0, int(row.get("price_per_call_micros") or 0))
        if up_to > 0:
            tiers.append(RoutePriceTier(up_to_calls=up_to, price_per_call_micros=price))
    tiers.sort(key=lambda x: x.up_to_calls)
    return RoutePrice(price_per_call_micros=base, tiers=tiers)


def _default_catalog() -> List[PricingCatalogVersion]:
    v = str(getattr(S, "api_usage_default_pricing_catalog_version", "v1") or "v1")
    return [
        PricingCatalogVersion(
            pricing_catalog_version=v,
            effective_at=0,
            routes={},
            default_route=RoutePrice(price_per_call_micros=0, tiers=[]),
        )
    ]


def load_api_pricing_catalog() -> List[PricingCatalogVersion]:
    raw = str(getattr(S, "api_usage_pricing_catalog", "") or "")
    if not raw.strip():
        return _default_catalog()
    try:
        payload = json.loads(raw)
    except Exception as exc:
        raise ValueError("invalid API_USAGE_PRICING_CATALOG json") from exc
    versions_raw = payload.get("versions") if isinstance(payload, dict) else []
    if not isinstance(versions_raw, list):
        raise ValueError("API_USAGE_PRICING_CATALOG must contain versions[]")

    out: List[PricingCatalogVersion] = []
    for row in versions_raw:
        if not isinstance(row, dict):
            continue
        version = str(row.get("pricing_catalog_version") or "").strip()
        if not version:
            continue
        effective_at = _parse_effective_at(row.get("effective_at"))
        routes_raw = row.get("routes") if isinstance(row.get("routes"), dict) else {}
        routes = {str(k): _parse_route_price(v) for k, v in routes_raw.items()}
        default_route = _parse_route_price(row.get("default_route")) if isinstance(row.get("default_route"), dict) else None
        out.append(
            PricingCatalogVersion(
                pricing_catalog_version=version,
                effective_at=effective_at,
                routes=routes,
                default_route=default_route,
            )
        )

    if not out:
        return _default_catalog()
    out.sort(key=lambda x: (x.effective_at, x.pricing_catalog_version))
    return out


def resolve_catalog_version(*, event_ts: int, pricing_catalog_version: str | None = None, catalog: List[PricingCatalogVersion] | None = None) -> PricingCatalogVersion:
    items = catalog or load_api_pricing_catalog()
    if pricing_catalog_version:
        for entry in items:
            if entry.pricing_catalog_version == pricing_catalog_version:
                return entry
        raise HTTPException(400, "Unknown pricing catalog version")

    ts = int(event_ts)
    selected = None
    for entry in items:
        if entry.effective_at <= ts:
            selected = entry
    if selected is not None:
        return selected
    return items[0]


def _resolve_tier_price(route: RoutePrice, *, call_number_in_period: int) -> int:
    idx = max(1, int(call_number_in_period))
    for tier in route.tiers:
        if idx <= tier.up_to_calls:
            return tier.price_per_call_micros
    return route.price_per_call_micros


def resolve_route_pricing(
    *,
    route_id: str,
    event_ts: int,
    call_number_in_period: int = 1,
    pricing_catalog_version: str | None = None,
    catalog: List[PricingCatalogVersion] | None = None,
) -> ResolvedRoutePricing:
    behavior = str(getattr(S, "api_usage_pricing_missing_route_behavior", "default_route") or "default_route").strip().lower()
    entry = resolve_catalog_version(event_ts=event_ts, pricing_catalog_version=pricing_catalog_version, catalog=catalog)

    direct = entry.routes.get(route_id)
    if direct is not None:
        return ResolvedRoutePricing(
            pricing_catalog_version=entry.pricing_catalog_version,
            effective_at=entry.effective_at,
            route_id=route_id,
            matched_route_id=route_id,
            unit_price_micros=_resolve_tier_price(direct, call_number_in_period=call_number_in_period),
        )

    if behavior == "error":
        raise HTTPException(400, "Missing route pricing entry")
    if behavior == "zero_price":
        return ResolvedRoutePricing(
            pricing_catalog_version=entry.pricing_catalog_version,
            effective_at=entry.effective_at,
            route_id=route_id,
            matched_route_id="<zero_price_fallback>",
            unit_price_micros=0,
        )

    fallback = entry.default_route or RoutePrice(price_per_call_micros=0, tiers=[])
    return ResolvedRoutePricing(
        pricing_catalog_version=entry.pricing_catalog_version,
        effective_at=entry.effective_at,
        route_id=route_id,
        matched_route_id="<default_route>",
        unit_price_micros=_resolve_tier_price(fallback, call_number_in_period=call_number_in_period),
    )
