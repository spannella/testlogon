"""Hotel availability router (QloApps PMS vertical, HTL-012).

Additive + flag-gated (``HOTEL_PMS_ENABLED``, default OFF). Every handler
calls ``_require_enabled()`` first; when the flag is off all endpoints
return 404 and the platform is byte-for-byte unchanged.

Auth split (mirrors app/routers/inventory.py):
  * Read endpoints  → ``require_ui_session``        (any authenticated user)
  * Write endpoints → ``require_admin_or_root_csrf`` (ADMIN | ROOT + CSRF)

Route ordering: the three literal-segment routes (``/availability/calendar``,
``/availability/check``, ``/availability/holds/{hold_id}/release``) are
declared BEFORE the dynamic ``/availability/{room_type_id}`` route. FastAPI
matches in declaration order; the wrong order would silently capture
``calendar`` / ``check`` / ``holds`` as a ``room_type_id`` path parameter.
"""
from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root_csrf
from app.models import (
    AvailabilityDayOut,
    AvailabilitySetIn,
    HoldOut,
    HoldRoomsIn,
    MinMaxSetIn,
    OverbookingSetIn,
)
from app.services import hotel_availability as ha
from app.services.sessions import require_ui_session

hotel_availability_router = APIRouter(prefix="/ui/hotels", tags=["hotel-availability"])


def _require_enabled() -> None:
    """Delegate to the service-layer flag guard (mirrors inventory router :32-33)."""
    ha._require_enabled()


# ─────────────────────────────────────────────────────────────────────────────
# LITERAL ROUTES FIRST (declared before dynamic /{room_type_id})
# ─────────────────────────────────────────────────────────────────────────────


@hotel_availability_router.get("/{hotel_id}/availability/calendar")
async def get_availability_calendar(
    hotel_id: str,
    start_date: str,
    end_date: str,
    session=Depends(require_ui_session),
) -> dict:
    """Hotel-wide availability calendar across ALL room types for a date range.

    Queries GSI_HOTEL_DATE — no full table scan. Returns a map of
    room_type_id → list[AvailabilityDayOut]. Missing dates (unseeded) do not
    appear in the list (the FE grid renders them as zero/sold-out).
    """
    _require_enabled()
    return ha.availability_calendar(hotel_id, start_date, end_date)


@hotel_availability_router.get("/{hotel_id}/availability/check")
async def check_availability(
    hotel_id: str,
    room_type_id: str,
    checkin: str,
    checkout: str,
    rooms_needed: int = 1,
    session=Depends(require_ui_session),
) -> dict:
    """Booking-time span-intersection check.

    Returns available (bool) only when EVERY night of [checkin, checkout)
    has remaining >= rooms_needed. A single short / missing night flips the
    whole stay to unavailable (the intersection across the span).
    """
    _require_enabled()
    return ha.check_availability(hotel_id, room_type_id, checkin, checkout, rooms_needed)


@hotel_availability_router.post(
    "/{hotel_id}/availability/holds/{hold_id}/release",
    response_model=HoldOut,
)
async def release_hold(
    hotel_id: str,
    hold_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> HoldOut:
    """Release an active hold (idempotent — double-release is a no-op).

    Restores ``held`` on every date the hold touched, via status-CAS.
    """
    _require_enabled()
    item = ha.release_hold(hold_id, user_sub=user.sub)
    return HoldOut(**item)


# ─────────────────────────────────────────────────────────────────────────────
# DYNAMIC ROUTE — declared AFTER the literals
# ─────────────────────────────────────────────────────────────────────────────


@hotel_availability_router.get(
    "/{hotel_id}/availability/{room_type_id}",
    response_model=List[AvailabilityDayOut],
)
async def get_room_type_availability(
    hotel_id: str,
    room_type_id: str,
    checkin: str,
    checkout: str,
    session=Depends(require_ui_session),
) -> List[AvailabilityDayOut]:
    """Per-night availability rows for the stay span [checkin, checkout).

    Checkout night is excluded (the guest does not occupy a room on the
    departure night). Never-seeded dates surface as zeroed virtual rows
    (available=0, sold-out) — not errors.
    """
    _require_enabled()
    rows = ha.get_availability(hotel_id, room_type_id, checkin, checkout)
    return [AvailabilityDayOut(**r) for r in rows]


@hotel_availability_router.put(
    "/{hotel_id}/availability/{room_type_id}/total-rooms",
    response_model=List[AvailabilityDayOut],
)
async def set_total_rooms(
    hotel_id: str,
    room_type_id: str,
    body: AvailabilitySetIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> List[AvailabilityDayOut]:
    """Seed / set total_rooms per date over a range, preserving live counters.

    Read-merge per date: overwrites total_rooms but preserves existing
    booked / held / overbooking_allowance / min / max on each date row.
    """
    _require_enabled()
    rows = ha.set_total_rooms(
        hotel_id,
        room_type_id,
        body.start_date,
        body.end_date,
        body.total_rooms,
        user_sub=user.sub,
    )
    return [AvailabilityDayOut(**r) for r in rows]


@hotel_availability_router.post(
    "/{hotel_id}/availability/{room_type_id}/hold",
    response_model=HoldOut,
)
async def hold_rooms(
    hotel_id: str,
    room_type_id: str,
    body: HoldRoomsIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> HoldOut:
    """Block / hold rooms across all nights of [checkin, checkout).

    All-or-nothing: any sold-out night → 409 + compensating rollback (no
    partial hold persists). Supports overbooking_allowance and
    min_availability floor in the per-night condition.
    """
    _require_enabled()
    item = ha.hold_rooms(
        hotel_id,
        room_type_id,
        body.checkin,
        body.checkout,
        body.quantity,
        user_sub=user.sub,
        ttl_seconds=body.ttl_seconds,
    )
    return HoldOut(**item)


@hotel_availability_router.put(
    "/{hotel_id}/availability/{room_type_id}/overbooking",
    response_model=List[AvailabilityDayOut],
)
async def set_overbooking(
    hotel_id: str,
    room_type_id: str,
    body: OverbookingSetIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> List[AvailabilityDayOut]:
    """Set overbooking_allowance per date over a control range."""
    _require_enabled()
    rows = ha.set_overbooking_allowance(
        hotel_id,
        room_type_id,
        body.start_date,
        body.end_date,
        body.allowance,
        user_sub=user.sub,
    )
    return [AvailabilityDayOut(**r) for r in rows]


@hotel_availability_router.put(
    "/{hotel_id}/availability/{room_type_id}/min-max",
    response_model=List[AvailabilityDayOut],
)
async def set_min_max(
    hotel_id: str,
    room_type_id: str,
    body: MinMaxSetIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> List[AvailabilityDayOut]:
    """Set min_availability and/or max_availability per date over a control range."""
    _require_enabled()
    rows = ha.set_min_max_availability(
        hotel_id,
        room_type_id,
        body.start_date,
        body.end_date,
        min_availability=body.min_availability,
        max_availability=body.max_availability,
        user_sub=user.sub,
    )
    return [AvailabilityDayOut(**r) for r in rows]
