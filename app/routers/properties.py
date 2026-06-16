"""Property management router (open-property vertical, PROP-004).

Additive + flag-gated (``PROPERTY_MGMT_ENABLED``, default OFF). Every
handler calls ``_require_enabled()`` first; when the flag is off all
endpoints return 404 and the platform is byte-for-byte unchanged.

Auth split (mirrors app/routers/inventory.py):
  * Read endpoints  → ``require_ui_session``          (any authenticated user)
  * Write endpoints → ``require_admin_or_root_csrf``  (ADMIN | ROOT + CSRF)

Route-declaration order: ``/portfolio/occupancy`` (static) MUST be declared
before ``/{property_id}`` (dynamic) so FastAPI does not capture the literal
``portfolio`` segment as a path parameter.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root_csrf
from app.models import (
    PortfolioOccupancyOut,
    PropertyIn,
    PropertyListOut,
    PropertyOccupancyOut,
    PropertyOut,
    PropertyUpdateIn,
    UnitIn,
    UnitOut,
    UnitUpdateIn,
)
from app.services import property_mgmt as prop
from app.services.sessions import require_ui_session

properties_router = APIRouter(prefix="/ui/properties", tags=["properties"])


def _require_enabled() -> None:
    prop._require_enabled()


# ---------------------------------------------------------------------------
# Static routes FIRST (before any /{property_id} dynamic captures)
# ---------------------------------------------------------------------------

@properties_router.get("/portfolio/occupancy", response_model=PortfolioOccupancyOut)
async def get_portfolio_occupancy(
    session=Depends(require_ui_session),
) -> PortfolioOccupancyOut:
    _require_enabled()
    result = prop.portfolio_occupancy_rollup(owner_sub=session["user_sub"])
    return PortfolioOccupancyOut(**result)


@properties_router.get("", response_model=PropertyListOut)
async def list_properties(
    status: str = "active",
    property_type: Optional[str] = None,
    cursor: Optional[str] = None,
    limit: int = 50,
    session=Depends(require_ui_session),
) -> PropertyListOut:
    _require_enabled()
    result = prop.list_properties(
        owner_sub=session["user_sub"],
        status=status,
        property_type=property_type,
        cursor=cursor,
        limit=limit,
    )
    return PropertyListOut(**result)


@properties_router.post("", response_model=PropertyOut, status_code=201)
async def create_property(
    body: PropertyIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> PropertyOut:
    _require_enabled()
    item = prop.create_property(
        owner_sub=user.sub,
        name=body.name,
        property_type=body.property_type,
        address=body.address.model_dump(),
        color_tags=body.color_tags,
    )
    return PropertyOut(**item)


# ---------------------------------------------------------------------------
# Dynamic routes: /{property_id} and its sub-paths
# ---------------------------------------------------------------------------

@properties_router.get("/{property_id}/occupancy", response_model=PropertyOccupancyOut)
async def get_property_occupancy(
    property_id: str,
    session=Depends(require_ui_session),
) -> PropertyOccupancyOut:
    _require_enabled()
    result = prop.compute_property_occupancy(property_id)
    return PropertyOccupancyOut(**result)


@properties_router.get("/{property_id}/units", response_model=list[UnitOut])
async def list_units(
    property_id: str,
    session=Depends(require_ui_session),
) -> list[UnitOut]:
    _require_enabled()
    units = prop.list_units(property_id)
    return [UnitOut(**u) for u in units]


@properties_router.post("/{property_id}/units", response_model=UnitOut, status_code=201)
async def create_unit(
    property_id: str,
    body: UnitIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> UnitOut:
    _require_enabled()
    item = prop.create_unit(
        property_id,
        label=body.label,
        bedrooms=body.bedrooms,
        bathrooms=body.bathrooms,
        square_footage=body.square_footage,
        market_rent_cents=body.market_rent_cents,
        occupancy_status=body.occupancy_status,
        user_sub=user.sub,
    )
    return UnitOut(**item)


@properties_router.get("/{property_id}/units/{unit_id}", response_model=UnitOut)
async def get_unit(
    property_id: str,
    unit_id: str,
    session=Depends(require_ui_session),
) -> UnitOut:
    _require_enabled()
    item = prop.get_unit(property_id, unit_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Unit not found")
    return UnitOut(**item)


@properties_router.put("/{property_id}/units/{unit_id}", response_model=UnitOut)
async def update_unit(
    property_id: str,
    unit_id: str,
    body: UnitUpdateIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> UnitOut:
    _require_enabled()
    kwargs = {k: v for k, v in body.model_dump().items() if v is not None}
    item = prop.update_unit(property_id, unit_id, user_sub=user.sub, **kwargs)
    return UnitOut(**item)


@properties_router.delete("/{property_id}/units/{unit_id}")
async def delete_unit(
    property_id: str,
    unit_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> dict:
    _require_enabled()
    ok = prop.delete_unit(property_id, unit_id, user_sub=user.sub)
    return {"ok": ok}


@properties_router.get("/{property_id}", response_model=PropertyOut)
async def get_property(
    property_id: str,
    session=Depends(require_ui_session),
) -> PropertyOut:
    _require_enabled()
    item = prop.get_property(property_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Property not found")
    return PropertyOut(**item)


@properties_router.put("/{property_id}", response_model=PropertyOut)
async def update_property(
    property_id: str,
    body: PropertyUpdateIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> PropertyOut:
    _require_enabled()
    kwargs = {k: v for k, v in body.model_dump().items() if v is not None}
    if "address" in kwargs and hasattr(kwargs["address"], "model_dump"):
        kwargs["address"] = kwargs["address"].model_dump()
    item = prop.update_property(property_id, user_sub=user.sub, **kwargs)
    return PropertyOut(**item)


@properties_router.delete("/{property_id}", response_model=PropertyOut)
async def archive_property(
    property_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> PropertyOut:
    _require_enabled()
    item = prop.archive_property(property_id, user_sub=user.sub)
    return PropertyOut(**item)
