"""EVT-006 + EVT-007: CRM Maps router — /ui/crm/maps.

Exposes:
- GET /ui/crm/maps/feature-flags  (EVT-007: ungated, always returns flag state)
- GET /ui/crm/maps/contacts/proximity  (EVT-006: Haversine radius search)

Route ordering: /feature-flags is declared BEFORE /contacts/proximity so the
literal segment "feature-flags" is not captured as a path parameter.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request

from app.core.settings import S
from app.models import CrmMapFeatureFlagsOut, ProximityResultItem, ProximitySearchOut
from app.services.crm_geocoding import proximity_search, rate_limit_proximity_search
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/crm/maps", tags=["crm_maps"])


def _require_proximity_enabled() -> None:
    """Raise 404 when either proximity-search or geocoding flag is off."""
    if not S.crm_proximity_search_enabled or not S.crm_geocoding_enabled:
        raise HTTPException(404, "Proximity search not enabled")


# ---------------------------------------------------------------------------
# EVT-007: GET /ui/crm/maps/feature-flags
# Declared FIRST — must precede any /{param} routes to avoid capture.
# ---------------------------------------------------------------------------

@router.get("/feature-flags", response_model=CrmMapFeatureFlagsOut)
def get_crm_map_feature_flags(
    ctx: Dict = Depends(require_ui_session),
) -> CrmMapFeatureFlagsOut:
    """Return feature-flag state and map defaults for the CRM map frontend.

    This endpoint is intentionally NOT gated by the feature flag so the
    frontend can always learn whether the feature is enabled and render the
    appropriate placeholder.  Best-effort audit write on each call.
    """
    try:
        from app.services.alerts import audit_event  # lazy import
        audit_event("crm_map_viewed", ctx["user_sub"])
    except Exception:
        pass

    return CrmMapFeatureFlagsOut(
        crm_geocoding_enabled=S.crm_geocoding_enabled,
        default_lat=S.crm_map_default_lat,
        default_lng=S.crm_map_default_lng,
        default_radius_km=S.crm_map_default_radius_km,
        max_radius_km=S.crm_map_max_radius_km,
        max_pins=S.crm_map_max_pins,
    )


# ---------------------------------------------------------------------------
# EVT-006: GET /ui/crm/maps/contacts/proximity
# ---------------------------------------------------------------------------

@router.get("/contacts/proximity", response_model=ProximitySearchOut)
def get_proximity_contacts(
    request: Request,
    lat: float,
    lng: float,
    radius_km: float,
    limit: int = 50,
    entity_type: str = "address",
    ctx: Dict = Depends(require_ui_session),
) -> ProximitySearchOut:
    """Return geocoded address items within radius_km of (lat, lng).

    Query params:
        lat         Centre-point latitude  [-90, 90]
        lng         Centre-point longitude [-180, 180]
        radius_km   Search radius in km    (0, crm_proximity_search_max_radius_km]
        limit       Max results 1-200 (default 50)
        entity_type "address" (default) or "party"

    Errors:
        400  lat/lng out of range, radius out of range, invalid entity_type
        404  flags off
        429  rate limit exceeded
    """
    _require_proximity_enabled()

    # Validate lat/lng
    if not (-90.0 <= lat <= 90.0):
        raise HTTPException(400, "lat must be in [-90, 90]")
    if not (-180.0 <= lng <= 180.0):
        raise HTTPException(400, "lng must be in [-180, 180]")

    # Validate radius
    if not (0 < radius_km <= S.crm_proximity_search_max_radius_km):
        raise HTTPException(
            400,
            f"radius_km must be in (0, {S.crm_proximity_search_max_radius_km}]",
        )

    # Clamp limit
    limit = max(1, min(200, limit))

    user_sub: str = ctx["user_sub"]

    # Rate limit
    rate_limit_proximity_search(user_sub)

    # Call service
    try:
        raw_results = proximity_search(user_sub, lat, lng, radius_km, limit, entity_type)
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    results = [
        ProximityResultItem(
            entity_type=r["entity_type"],
            entity_id=r["entity_id"],
            name=r["name"],
            lat=r["lat"],
            lng=r["lng"],
            distance_km=r["distance_km"],
            address_id=r.get("address_id"),
            city=r.get("city"),
            country=r.get("country"),
        )
        for r in raw_results
    ]

    # Best-effort audit
    try:
        from app.services.alerts import audit_event  # lazy import
        audit_event(
            "crm_proximity_search",
            user_sub,
            request=request,
            lat=lat,
            lng=lng,
            radius_km=radius_km,
            result_count=len(results),
        )
    except Exception:
        pass

    return ProximitySearchOut(
        results=results,
        count=len(results),
        center_lat=lat,
        center_lng=lng,
        radius_km=radius_km,
        entity_type=entity_type,
    )
