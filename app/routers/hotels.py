"""Hotel-PMS router (QloApps hospitality vertical, HTL-003).

Additive + flag-gated (``HOTEL_PMS_ENABLED``, default OFF). Every handler
calls ``_require_enabled()`` first; when the flag is off all endpoints return
404 and the platform is byte-for-byte unchanged (the router is still mounted,
exactly like ``host_inventory_router`` — app/main.py).

Auth split (mirrors app/routers/inventory.py:37,48,65,81 in the main repo):
  * Read endpoints  → ``require_ui_session``          (any authenticated user)
  * Write endpoints → ``require_admin_or_root_csrf``  (ADMIN | ROOT + CSRF)

Route order (CLAUDE.md path-param-capture gotcha): the literal ``/amenities``
routes are declared BEFORE the dynamic ``/{hotel_id}`` routes.

SECOPS-007: no ``if S.dev_mode`` branch anywhere in this file.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root_csrf
from app.models import (
    AmenityAssociationOut, AmenityAttachIn, AmenityIn, AmenityOut,
    CancellationPolicyIn, CancellationPolicyOut, HotelKpisOut,
    HotelIn, HotelOut, HotelUpdateIn,
)
from app.services import hotel_pms as svc
from app.services import hotel_cancellation as canc_svc
from app.services import hotel_reports as reports_svc
from app.services.sessions import require_ui_session

hotels_router = APIRouter(prefix="/ui/hotels", tags=["hotels"])

_VALID_STATUS = {"active", "archived"}


def _require_enabled() -> None:
    svc._require_enabled()


# ---------------------------------------------------------------------------
# 1. GET /ui/hotels — list the caller's hotels (owner-scoped via GSI_OWNER)
# ---------------------------------------------------------------------------

@hotels_router.get("")
async def list_hotels_endpoint(
    status: Optional[str] = None,
    cursor: Optional[str] = None,
    limit: int = 50,
    session=Depends(require_ui_session),
) -> dict:
    _require_enabled()
    if status is not None and status not in _VALID_STATUS:
        raise HTTPException(status_code=422, detail="invalid status filter")
    return svc.list_hotels(
        owner_sub=session["user_sub"],
        status=status,
        cursor=cursor,
        limit=limit,
    )


# ---------------------------------------------------------------------------
# 2. POST /ui/hotels — create a hotel (idempotent on owner+name)
# ---------------------------------------------------------------------------

@hotels_router.post("", response_model=HotelOut, status_code=201)
async def create_hotel_endpoint(
    body: HotelIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> HotelOut:
    _require_enabled()
    item = svc.create_hotel(
        owner_sub=user.sub,
        name=body.name,
        description=body.description,
        star_rating=body.star_rating,
        address=body.address.model_dump(),
        check_in_time=body.check_in_time,
        check_out_time=body.check_out_time,
        policies=body.policies.model_dump(),
        contact=body.contact.model_dump(),
        photo_urls=body.photo_urls,
    )
    return HotelOut(**item)


# ---------------------------------------------------------------------------
# 3. GET /ui/hotels/amenities  — list the amenity dictionary
#    *** DECLARED BEFORE /{hotel_id} to prevent path-param capture ***
# ---------------------------------------------------------------------------

@hotels_router.get("/amenities", response_model=list[AmenityOut])
async def list_amenities_endpoint(
    category: Optional[str] = None,
    session=Depends(require_ui_session),
) -> list[AmenityOut]:
    _require_enabled()
    return [AmenityOut(**a) for a in svc.list_amenities(category=category)]


# ---------------------------------------------------------------------------
# 4. POST /ui/hotels/amenities — create a dictionary entry (idempotent on name)
# ---------------------------------------------------------------------------

@hotels_router.post("/amenities", response_model=AmenityOut, status_code=201)
async def create_amenity_endpoint(
    body: AmenityIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> AmenityOut:
    _require_enabled()
    item = svc.create_amenity(
        name=body.name, category=body.category, icon=body.icon, user_sub=user.sub,
    )
    return AmenityOut(**item)


# ---------------------------------------------------------------------------
# 5. POST /ui/hotels/amenities/attach — attach an amenity to a target
# ---------------------------------------------------------------------------

@hotels_router.post("/amenities/attach", response_model=AmenityAssociationOut)
async def attach_amenity_endpoint(
    body: AmenityAttachIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> AmenityAssociationOut:
    _require_enabled()
    item = svc.attach_amenity(
        target_type=body.target_type,
        target_id=body.target_id,
        amenity_id=body.amenity_id,
        user_sub=user.sub,
    )
    return AmenityAssociationOut(**item)


# ---------------------------------------------------------------------------
# 6. POST /ui/hotels/amenities/detach — detach (idempotent no-raise)
# ---------------------------------------------------------------------------

@hotels_router.post("/amenities/detach")
async def detach_amenity_endpoint(
    body: AmenityAttachIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> dict:
    _require_enabled()
    ok = svc.detach_amenity(
        target_type=body.target_type,
        target_id=body.target_id,
        amenity_id=body.amenity_id,
        user_sub=user.sub,
    )
    return {"ok": ok}


# ---------------------------------------------------------------------------
# 7. GET /ui/hotels/{hotel_id} — read a single hotel
#    *** FIRST dynamic route (declared after all /amenities* routes) ***
# ---------------------------------------------------------------------------

@hotels_router.get("/{hotel_id}", response_model=HotelOut)
async def get_hotel_endpoint(
    hotel_id: str,
    session=Depends(require_ui_session),
) -> HotelOut:
    _require_enabled()
    item = svc.get_hotel(hotel_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Hotel not found")
    return HotelOut(**item)


# ---------------------------------------------------------------------------
# 8. PUT /ui/hotels/{hotel_id} — partial update
# ---------------------------------------------------------------------------

@hotels_router.put("/{hotel_id}", response_model=HotelOut)
async def update_hotel_endpoint(
    hotel_id: str,
    body: HotelUpdateIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> HotelOut:
    _require_enabled()
    raw = body.model_dump()
    kwargs = {k: v for k, v in raw.items() if v is not None}
    # Serialize nested Pydantic models to plain dicts
    for nested in ("address", "policies", "contact"):
        if nested in kwargs and hasattr(kwargs[nested], "model_dump"):
            kwargs[nested] = kwargs[nested].model_dump()
    item = svc.update_hotel(hotel_id, user_sub=user.sub, **kwargs)
    return HotelOut(**item)


# ---------------------------------------------------------------------------
# 9. DELETE /ui/hotels/{hotel_id} — soft-archive
# ---------------------------------------------------------------------------

@hotels_router.delete("/{hotel_id}", response_model=HotelOut)
async def archive_hotel_endpoint(
    hotel_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> HotelOut:
    _require_enabled()
    item = svc.archive_hotel(hotel_id, user_sub=user.sub)
    return HotelOut(**item)


# ---------------------------------------------------------------------------
# 10. GET /ui/hotels/{hotel_id}/amenities — list a hotel's attached amenities
# ---------------------------------------------------------------------------

@hotels_router.get("/{hotel_id}/amenities", response_model=list[AmenityAssociationOut])
async def list_hotel_amenities_endpoint(
    hotel_id: str,
    session=Depends(require_ui_session),
) -> list[AmenityAssociationOut]:
    _require_enabled()
    rows = svc.list_amenities_for(target_type="hotel", target_id=hotel_id)
    return [AmenityAssociationOut(**r) for r in rows]


# ---------------------------------------------------------------------------
# HTL-034 — cancellation policy CRUD (PUT write / GET read)
# Extra path segment → no capture conflict with the bare /{hotel_id} routes.
# ---------------------------------------------------------------------------

@hotels_router.put("/{hotel_id}/cancellation-policy", response_model=CancellationPolicyOut)
async def put_cancellation_policy(
    hotel_id: str,
    body: CancellationPolicyIn,
    scope: str = "default",
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> CancellationPolicyOut:
    _require_enabled()
    row = canc_svc.upsert_cancellation_policy(
        hotel_id,
        scope=scope,
        free_until_days_before=body.free_until_days_before,
        penalty_pct=body.penalty_pct,
        penalty_fixed_cents=body.penalty_fixed_cents,
        no_show_fee_cents=body.no_show_fee_cents,
        user_sub=user.sub,
    )
    return CancellationPolicyOut(**row)


@hotels_router.get("/{hotel_id}/cancellation-policy", response_model=CancellationPolicyOut)
async def get_cancellation_policy_endpoint(
    hotel_id: str,
    scope: str = "default",
    session=Depends(require_ui_session),
) -> CancellationPolicyOut:
    _require_enabled()
    row = canc_svc.get_cancellation_policy(hotel_id, scope)
    if row is None:
        raise HTTPException(status_code=404, detail="cancellation policy not found")
    return CancellationPolicyOut(**row)


# ---------------------------------------------------------------------------
# HTL-035 — hotel KPI report (occupancy / ADR / RevPAR)
# ---------------------------------------------------------------------------

@hotels_router.get("/{hotel_id}/reports/kpis", response_model=HotelKpisOut)
async def get_hotel_kpis(
    hotel_id: str,
    from_ts: int,
    to_ts: int,
    session=Depends(require_ui_session),
) -> HotelKpisOut:
    _require_enabled()
    row = reports_svc.compute_hotel_kpis(hotel_id, from_ts=from_ts, to_ts=to_ts)
    return HotelKpisOut(**row)
