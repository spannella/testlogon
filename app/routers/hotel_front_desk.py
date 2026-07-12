"""Hotel front-desk router (QloApps hotel vertical, HTL-024).

Additive + flag-gated (``HOTEL_PMS_ENABLED``, default OFF).  Every handler
calls ``_require_enabled()`` first; when the flag is off all endpoints return
404 and the platform is byte-for-byte unchanged (mirrors
``app/routers/inventory.py:31-33``).

Auth split (mirrors app/routers/inventory.py:37,48,65,81):
  * Read endpoints  → ``require_ui_session``        (any authenticated user)
  * Write endpoints → ``require_admin_or_root_csrf`` (ADMIN | ROOT + CSRF)

Route ordering — literal sub-routes declared BEFORE the dynamic
``/{reservation_id}/...`` group (FastAPI matches in declaration order;
mirrors the KYC /templates-before-/{case_id} and audit-export
/schedules-before-/{export_id} conventions; CLAUDE.md cross-cutting rule).
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root_csrf
from app.models import (
    AssignRoomIn,
    FrontDeskActionOut,
    FrontDeskListOut,
    OccupancySnapshotOut,
    RoomMoveIn,
    WalkInBookingIn,
)
from app.services import hotel_front_desk as fd
from app.services.sessions import require_ui_session

hotel_front_desk_router = APIRouter(prefix="/ui/hotels", tags=["hotel-front-desk"])


def _require_enabled() -> None:
    fd._require_enabled()


# ---------------------------------------------------------------------------
# Literal (static) sub-routes — MUST be declared before the dynamic
# /{reservation_id}/... routes.
# ---------------------------------------------------------------------------


@hotel_front_desk_router.get(
    "/{hotel_id}/front-desk/arrivals",
    response_model=FrontDeskListOut,
    summary="Today's arriving reservations",
)
async def get_arrivals(
    hotel_id: str,
    date: Optional[str] = None,
    cursor: Optional[str] = None,
    limit: int = 50,
    session=Depends(require_ui_session),
) -> FrontDeskListOut:
    _require_enabled()
    result = fd.arrivals_today(hotel_id, date=date, cursor=cursor, limit=limit)
    return FrontDeskListOut(**result)


@hotel_front_desk_router.get(
    "/{hotel_id}/front-desk/departures",
    response_model=FrontDeskListOut,
    summary="Today's departing reservations",
)
async def get_departures(
    hotel_id: str,
    date: Optional[str] = None,
    cursor: Optional[str] = None,
    limit: int = 50,
    session=Depends(require_ui_session),
) -> FrontDeskListOut:
    _require_enabled()
    return FrontDeskListOut(**fd.departures_today(hotel_id, date=date, cursor=cursor, limit=limit))


@hotel_front_desk_router.get(
    "/{hotel_id}/front-desk/in-house",
    response_model=FrontDeskListOut,
    summary="All currently checked-in reservations",
)
async def get_in_house(
    hotel_id: str,
    cursor: Optional[str] = None,
    limit: int = 50,
    session=Depends(require_ui_session),
) -> FrontDeskListOut:
    _require_enabled()
    return FrontDeskListOut(**fd.in_house(hotel_id, cursor=cursor, limit=limit))


@hotel_front_desk_router.get(
    "/{hotel_id}/front-desk/occupancy",
    response_model=OccupancySnapshotOut,
    summary="Live occupancy snapshot",
)
async def get_occupancy(
    hotel_id: str,
    date: Optional[str] = None,
    session=Depends(require_ui_session),
) -> OccupancySnapshotOut:
    _require_enabled()
    return OccupancySnapshotOut(**fd.occupancy_snapshot(hotel_id, date=date))


@hotel_front_desk_router.post(
    "/{hotel_id}/front-desk/walk-in",
    response_model=FrontDeskActionOut,
    status_code=201,
    summary="Walk-in booking: create + immediately check in",
)
async def walk_in(
    hotel_id: str,
    body: WalkInBookingIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> FrontDeskActionOut:
    _require_enabled()
    result = fd.walk_in_booking(
        hotel_id,
        room_type_id=body.room_type_id,
        checkin=body.checkin,
        checkout=body.checkout,
        occupancy_adults=body.occupancy_adults,
        occupancy_children=body.occupancy_children,
        guest_name=body.guest_name,
        guest_sub=body.guest_sub,
        assigned_room_ids=body.assigned_room_ids,
        total_cents=body.total_cents,
        user_sub=user.sub,
    )
    return FrontDeskActionOut(**result)


# ---------------------------------------------------------------------------
# Dynamic sub-routes — declared AFTER the literal routes above.
# ---------------------------------------------------------------------------


@hotel_front_desk_router.post(
    "/{hotel_id}/front-desk/reservations/{reservation_id}/assign-room",
    response_model=FrontDeskActionOut,
    summary="Set physical room(s) on a reservation",
)
async def assign_room(
    hotel_id: str,
    reservation_id: str,
    body: AssignRoomIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> FrontDeskActionOut:
    _require_enabled()
    result = fd.assign_room(
        hotel_id,
        reservation_id,
        assigned_room_ids=body.assigned_room_ids,
        version=body.version,
        user_sub=user.sub,
    )
    return FrontDeskActionOut(**result)


@hotel_front_desk_router.post(
    "/{hotel_id}/front-desk/reservations/{reservation_id}/change-room",
    response_model=FrontDeskActionOut,
    summary="Swap the room assignment set on a reservation",
)
async def change_room(
    hotel_id: str,
    reservation_id: str,
    body: AssignRoomIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> FrontDeskActionOut:
    _require_enabled()
    result = fd.change_room(
        hotel_id,
        reservation_id,
        assigned_room_ids=body.assigned_room_ids,
        version=body.version,
        user_sub=user.sub,
    )
    return FrontDeskActionOut(**result)


@hotel_front_desk_router.post(
    "/{hotel_id}/front-desk/reservations/{reservation_id}/room-move",
    response_model=FrontDeskActionOut,
    summary="Relocate a checked-in guest to a different room",
)
async def room_move(
    hotel_id: str,
    reservation_id: str,
    body: RoomMoveIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> FrontDeskActionOut:
    _require_enabled()
    result = fd.room_move(
        hotel_id,
        reservation_id,
        from_room_id=body.from_room_id,
        to_room_id=body.to_room_id,
        version=body.version,
        user_sub=user.sub,
    )
    return FrontDeskActionOut(**result)
