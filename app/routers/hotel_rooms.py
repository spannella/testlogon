"""QloApps Hotel-PMS router — room-types / rooms / housekeeping (HTL-008).

Sibling-router variant: prefix ``/ui/hotels``, tag ``hotels``. Registered in
``app/main.py`` next to ``host_inventory_router``. In the integrated tree the
HTL-001 ``hotels_router`` in ``app/routers/hotels.py`` may share the same
prefix — FastAPI merges two routers on the same prefix cleanly.

Every handler calls ``_require_enabled()`` first; when ``HOTEL_PMS_ENABLED``
is ``false`` (the default) all 15 endpoints return HTTP 404 and the platform
is byte-for-byte unchanged.

Auth split (mirrors app/routers/inventory.py):
  * Read endpoints  → ``require_ui_session``          (any authenticated user)
  * Write endpoints → ``require_admin_or_root_csrf``  (ADMIN | ROOT + CSRF)

Route-declaration order (CLAUDE.md literal-before-dynamic gotcha):
  1. ``/{hotel_id}/room-types`` (list + create) — literal sub-tree root
  2. ``/{hotel_id}/room-types/{room_type_id}`` — dynamic
  3. ``/{hotel_id}/rooms`` (list + create)
  4. ``/{hotel_id}/rooms/{room_id}/housekeeping`` — literal suffix FIRST
  5. ``/{hotel_id}/rooms/{room_id}`` — bare dynamic AFTER suffix
  6. ``/{hotel_id}/housekeeping/tasks`` (list + create)
  7. ``/{hotel_id}/housekeeping/tasks/{task_id}/assign``   — literal suffix
  8. ``/{hotel_id}/housekeeping/tasks/{task_id}/complete`` — literal suffix

SECOPS-007: no ``if S.dev_mode`` branch anywhere in this file.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root_csrf
from app.models import (
    HkTaskAssignIn,
    HkTaskIn,
    HkTaskOut,
    HousekeepingStatusIn,
    RoomIn,
    RoomOut,
    RoomTypeIn,
    RoomTypeOut,
    RoomTypeUpdateIn,
    RoomUpdateIn,
)
from app.services import hotel_pms
from app.services.sessions import require_ui_session

hotel_rooms_router = APIRouter(prefix="/ui/hotels", tags=["hotels"])


def _require_enabled() -> None:
    hotel_pms._require_enabled()


# ============================================================
# Room Types (HTL-005)
# ============================================================

@hotel_rooms_router.get("/{hotel_id}/room-types")
async def list_room_types(
    hotel_id: str,
    status: str = "active",
    cursor: Optional[str] = None,
    limit: int = 50,
    session=Depends(require_ui_session),
) -> dict:
    _require_enabled()
    return hotel_pms.list_room_types(hotel_id, status=status, cursor=cursor, limit=limit)


@hotel_rooms_router.post("/{hotel_id}/room-types", response_model=RoomTypeOut, status_code=201)
async def create_room_type(
    hotel_id: str,
    body: RoomTypeIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> RoomTypeOut:
    _require_enabled()
    item = hotel_pms.create_room_type(
        hotel_id,
        name=body.name,
        description=body.description,
        base_occupancy_adults=body.base_occupancy_adults,
        base_occupancy_children=body.base_occupancy_children,
        max_occupancy=body.max_occupancy,
        bed_type=body.bed_type,
        size_sqft=body.size_sqft,
        base_nightly_rate_cents=body.base_nightly_rate_cents,
        photo_urls=body.photo_urls,
        user_sub=user.sub,
    )
    return RoomTypeOut(**item)


@hotel_rooms_router.get("/{hotel_id}/room-types/{room_type_id}", response_model=RoomTypeOut)
async def get_room_type(
    hotel_id: str,
    room_type_id: str,
    session=Depends(require_ui_session),
) -> RoomTypeOut:
    _require_enabled()
    item = hotel_pms.get_room_type(hotel_id, room_type_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Room type not found")
    return RoomTypeOut(**item)


@hotel_rooms_router.put("/{hotel_id}/room-types/{room_type_id}", response_model=RoomTypeOut)
async def update_room_type(
    hotel_id: str,
    room_type_id: str,
    body: RoomTypeUpdateIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> RoomTypeOut:
    _require_enabled()
    kwargs = {k: v for k, v in body.model_dump().items() if v is not None}
    item = hotel_pms.update_room_type(hotel_id, room_type_id, user_sub=user.sub, **kwargs)
    return RoomTypeOut(**item)


@hotel_rooms_router.delete("/{hotel_id}/room-types/{room_type_id}", response_model=RoomTypeOut)
async def archive_room_type(
    hotel_id: str,
    room_type_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> RoomTypeOut:
    _require_enabled()
    item = hotel_pms.archive_room_type(hotel_id, room_type_id, user_sub=user.sub)
    return RoomTypeOut(**item)


# ============================================================
# Rooms (HTL-006)
# ============================================================

@hotel_rooms_router.get("/{hotel_id}/rooms")
async def list_rooms(
    hotel_id: str,
    room_type_id: Optional[str] = None,
    status: Optional[str] = None,
    cursor: Optional[str] = None,
    limit: int = 50,
    session=Depends(require_ui_session),
) -> dict:
    _require_enabled()
    return hotel_pms.list_rooms(
        hotel_id, room_type_id=room_type_id, status=status, cursor=cursor, limit=limit
    )


@hotel_rooms_router.post("/{hotel_id}/rooms", response_model=RoomOut, status_code=201)
async def create_room(
    hotel_id: str,
    body: RoomIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> RoomOut:
    _require_enabled()
    item = hotel_pms.create_room(
        hotel_id,
        room_type_id=body.room_type_id,
        room_number=body.room_number,
        floor=body.floor,
        status=body.status,
        user_sub=user.sub,
    )
    return RoomOut(**item)


# IMPORTANT: literal-suffix route declared BEFORE the bare /{room_id} group
@hotel_rooms_router.put("/{hotel_id}/rooms/{room_id}/housekeeping", response_model=RoomOut)
async def set_room_housekeeping(
    hotel_id: str,
    room_id: str,
    body: HousekeepingStatusIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> RoomOut:
    _require_enabled()
    item = hotel_pms.set_room_housekeeping_status(
        hotel_id, room_id, housekeeping_status=body.housekeeping_status, user_sub=user.sub
    )
    return RoomOut(**item)


@hotel_rooms_router.get("/{hotel_id}/rooms/{room_id}", response_model=RoomOut)
async def get_room(
    hotel_id: str,
    room_id: str,
    session=Depends(require_ui_session),
) -> RoomOut:
    _require_enabled()
    item = hotel_pms.get_room(hotel_id, room_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Room not found")
    return RoomOut(**item)


@hotel_rooms_router.put("/{hotel_id}/rooms/{room_id}", response_model=RoomOut)
async def update_room(
    hotel_id: str,
    room_id: str,
    body: RoomUpdateIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> RoomOut:
    _require_enabled()
    kwargs = {k: v for k, v in body.model_dump().items() if v is not None}
    item = hotel_pms.update_room(hotel_id, room_id, user_sub=user.sub, **kwargs)
    return RoomOut(**item)


@hotel_rooms_router.delete("/{hotel_id}/rooms/{room_id}")
async def delete_room(
    hotel_id: str,
    room_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> dict:
    _require_enabled()
    ok = hotel_pms.delete_room(hotel_id, room_id, user_sub=user.sub)
    return {"ok": ok}


# ============================================================
# Housekeeping tasks (HTL-007)
# ============================================================

@hotel_rooms_router.get("/{hotel_id}/housekeeping/tasks")
async def list_hk_tasks(
    hotel_id: str,
    status: Optional[str] = None,
    assignee_sub: Optional[str] = None,
    cursor: Optional[str] = None,
    limit: int = 50,
    session=Depends(require_ui_session),
) -> dict:
    _require_enabled()
    return hotel_pms.list_hk_tasks(
        hotel_id=hotel_id, status=status, assignee_sub=assignee_sub, cursor=cursor, limit=limit
    )


@hotel_rooms_router.post("/{hotel_id}/housekeeping/tasks", response_model=HkTaskOut, status_code=201)
async def create_hk_task(
    hotel_id: str,
    body: HkTaskIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> HkTaskOut:
    _require_enabled()
    item = hotel_pms.create_hk_task(
        hotel_id,
        room_id=body.room_id,
        assignee_sub=body.assignee_sub or "",
        due_at=body.due_at or 0,
        notes=body.notes or "",
        user_sub=user.sub,
    )
    return HkTaskOut(**item)


# literal-suffix routes declared before any bare /{task_id} route
@hotel_rooms_router.put(
    "/{hotel_id}/housekeeping/tasks/{task_id}/assign", response_model=HkTaskOut
)
async def assign_hk_task(
    hotel_id: str,
    task_id: str,
    body: HkTaskAssignIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> HkTaskOut:
    _require_enabled()
    item = hotel_pms.assign_hk_task(
        hotel_id, task_id, assignee_sub=body.assignee_sub, user_sub=user.sub
    )
    return HkTaskOut(**item)


@hotel_rooms_router.put(
    "/{hotel_id}/housekeeping/tasks/{task_id}/complete", response_model=HkTaskOut
)
async def complete_hk_task(
    hotel_id: str,
    task_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> HkTaskOut:
    _require_enabled()
    item = hotel_pms.complete_hk_task(hotel_id, task_id, user_sub=user.sub)
    return HkTaskOut(**item)
