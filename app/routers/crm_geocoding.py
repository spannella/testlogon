"""EVT-005: CRM Geocoding router — /ui/crm/geocoding.

Exposes explicit re-geocode (PATCH) and geocoded-address list (GET)
endpoints gated behind the crm_geocoding_enabled flag.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request

from app.core.settings import S
from app.models import GeocodedAddressListOut, GeocodedAddressOut
from app.services.addresses import get_address
from app.services.crm_geocoding import apply_geocode_to_address, list_geocoded_addresses
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/crm/geocoding", tags=["crm_geocoding"])


def _require_crm_geocoding_enabled() -> None:
    """Raise 404 when the CRM geocoding feature flag is off."""
    if not S.crm_geocoding_enabled:
        raise HTTPException(404, "CRM geocoding is not enabled")


def _item_to_geocoded_out(item: dict) -> GeocodedAddressOut:
    return GeocodedAddressOut(
        address_id=item["address_id"],
        lat=float(item["lat"]),
        lng=float(item["lng"]),
        geocoded_at=int(item["geocoded_at"]),
        line1=item.get("line1"),
        city=item.get("city"),
        state=item.get("state"),
        postal_code=item.get("postal_code"),
        country=item.get("country"),
    )


@router.patch("/addresses/{address_id}", response_model=GeocodedAddressOut)
async def patch_geocode_address(
    address_id: str,
    ctx: Dict = Depends(require_ui_session),
) -> GeocodedAddressOut:
    """Explicit on-demand re-geocode of a saved address.

    - 404 when flag off
    - 404 when address not found / not owned by caller
    - 422 when address has no geocodable fields
    """
    _require_crm_geocoding_enabled()
    user_sub: str = ctx["user_sub"]

    # Raises 404 if not found or not owned by caller (partition key guard).
    get_address(user_sub, address_id)

    # Rate-limit the explicit PATCH endpoint.
    try:
        from app.services.rate_limit import _bucket_limit  # lazy import
        ok = _bucket_limit(user_sub, "rl#geocode", 20, 60)
        if not ok:
            raise HTTPException(429, "Geocode rate limit exceeded; try again shortly")
    except HTTPException:
        raise
    except Exception:
        pass  # rate-limit failure is best-effort

    updated = apply_geocode_to_address(user_sub, address_id)
    if updated is None or "lat" not in updated:
        raise HTTPException(422, "Address could not be geocoded")

    return _item_to_geocoded_out(updated)


@router.get("/addresses", response_model=GeocodedAddressListOut)
async def get_geocoded_addresses(
    ctx: Dict = Depends(require_ui_session),
) -> GeocodedAddressListOut:
    """List all of the caller's addresses that carry geocoded coordinates."""
    _require_crm_geocoding_enabled()
    user_sub: str = ctx["user_sub"]

    items = list_geocoded_addresses(user_sub)
    addresses = [_item_to_geocoded_out(item) for item in items]
    return GeocodedAddressListOut(addresses=addresses, count=len(addresses))
