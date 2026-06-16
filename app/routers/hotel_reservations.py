"""Hotel reservation router (QloApps hotel-PMS vertical, HTL-020).

Additive + flag-gated (``HOTEL_PMS_ENABLED``, default OFF).  Every handler
calls ``_require_enabled()`` first; when the flag is off all endpoints return
404 and the platform is byte-for-byte unchanged.

Auth split (mirrors app/routers/inventory.py):
  * Read endpoints            → ``require_ui_session``         (any authenticated user)
  * Write/lifecycle endpoints → ``require_admin_or_root_csrf`` (ADMIN | ROOT + CSRF)

Read-only stay-search (``POST /ui/hotel-search``) uses POST-with-body but read auth.

Route-declaration order (literal-before-dynamic, mirrors KYC /templates-before-/{case_id}):
  1. /hotel-search (independent literal)
  2. /hotels/{hotel_id}/reservations  (collection POST + GET)
  3. /hotels/{hotel_id}/reservations/{reservation_id}/history  (literal sub-route)
  4. /hotels/{hotel_id}/reservations/{reservation_id}/confirm  (literal sub-route)
  5. /hotels/{hotel_id}/reservations/{reservation_id}/check-in  (literal sub-route)
  6. /hotels/{hotel_id}/reservations/{reservation_id}/check-out  (literal sub-route)
  7. /hotels/{hotel_id}/reservations/{reservation_id}/cancel  (literal sub-route)
  8. /hotels/{hotel_id}/reservations/{reservation_id}/no-show  (literal sub-route)
  9. /hotels/{hotel_id}/reservations/{reservation_id}  GET  (bare dynamic — last)
  10. /hotels/{hotel_id}/reservations/{reservation_id}  PUT  (bare dynamic — last)
"""
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root_csrf
from app.models import (
    ReservationCreateIn,
    ReservationModifyIn,
    ReservationActionIn,
    StayReservationOut,
    StaySearchIn,
    StaySearchResult,
)
from app.services import hotel_reservations as svc
from app.services.sessions import require_ui_session

hotel_reservations_router = APIRouter(prefix="/ui", tags=["hotel-reservations"])


def _require_enabled() -> None:
    svc._require_enabled()


# ---------------------------------------------------------------------------
# 1. POST /ui/hotel-search — read-only stay-search funnel
# ---------------------------------------------------------------------------

@hotel_reservations_router.post("/hotel-search", response_model=StaySearchResult)
async def hotel_search(
    body: StaySearchIn,
    session=Depends(require_ui_session),
) -> StaySearchResult:
    _require_enabled()
    result = svc.search_stays(
        hotel_id=body.hotel_id,
        city=body.city,
        checkin=body.checkin,
        checkout=body.checkout,
        adults=body.adults,
        children=body.children,
        rooms=body.rooms,
    )
    return result


# ---------------------------------------------------------------------------
# 2. POST /ui/hotels/{hotel_id}/reservations — create reservation
# ---------------------------------------------------------------------------

@hotel_reservations_router.post(
    "/hotels/{hotel_id}/reservations",
    response_model=StayReservationOut,
    status_code=201,
)
async def create_reservation(
    hotel_id: str,
    body: ReservationCreateIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> StayReservationOut:
    _require_enabled()
    item = svc.create_reservation(
        hotel_id=hotel_id,   # path param is authoritative
        guest_party_id=body.guest_party_id,
        room_type_id=body.room_type_id,
        checkin=body.checkin,
        checkout=body.checkout,
        adults=body.adults,
        children=body.children,
        rooms=body.rooms,
        deposit_cents=body.deposit_cents,
        user_sub=user.sub,
    )
    return StayReservationOut(**item)


# ---------------------------------------------------------------------------
# 3. GET /ui/hotels/{hotel_id}/reservations — list reservations
# ---------------------------------------------------------------------------

@hotel_reservations_router.get("/hotels/{hotel_id}/reservations")
async def list_reservations(
    hotel_id: str,
    status: Optional[str] = None,
    checkin_from: Optional[str] = None,
    checkin_to: Optional[str] = None,
    cursor: Optional[str] = None,
    limit: int = 50,
    session=Depends(require_ui_session),
) -> dict:
    _require_enabled()
    return svc.list_reservations(
        hotel_id,
        status=status,
        checkin_from=checkin_from,
        checkin_to=checkin_to,
        cursor=cursor,
        limit=limit,
    )


# ---------------------------------------------------------------------------
# 4. GET /ui/hotels/{hotel_id}/reservations/{reservation_id}/history
#    (literal sub-route — declared before bare {reservation_id})
# ---------------------------------------------------------------------------

@hotel_reservations_router.get(
    "/hotels/{hotel_id}/reservations/{reservation_id}/history"
)
async def reservation_history(
    hotel_id: str,
    reservation_id: str,
    session=Depends(require_ui_session),
) -> dict:
    _require_enabled()
    existing = svc.get_reservation(reservation_id)
    if existing is None or existing.get("hotel_id") != hotel_id:
        raise HTTPException(status_code=404, detail="Reservation not found")
    return svc.list_reservation_history(reservation_id)


# ---------------------------------------------------------------------------
# 5. POST /ui/hotels/{hotel_id}/reservations/{reservation_id}/confirm
#    (idempotent no-op — reserved for future draft→confirmed step)
# ---------------------------------------------------------------------------

@hotel_reservations_router.post(
    "/hotels/{hotel_id}/reservations/{reservation_id}/confirm",
    response_model=StayReservationOut,
)
async def confirm_reservation(
    hotel_id: str,
    reservation_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> StayReservationOut:
    _require_enabled()
    existing = svc.get_reservation(reservation_id)
    if existing is None or existing.get("hotel_id") != hotel_id:
        raise HTTPException(status_code=404, detail="Reservation not found")
    return StayReservationOut(**existing)


# ---------------------------------------------------------------------------
# 6. POST /ui/hotels/{hotel_id}/reservations/{reservation_id}/check-in
# ---------------------------------------------------------------------------

@hotel_reservations_router.post(
    "/hotels/{hotel_id}/reservations/{reservation_id}/check-in",
    response_model=StayReservationOut,
)
async def check_in_reservation(
    hotel_id: str,
    reservation_id: str,
    body: ReservationActionIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> StayReservationOut:
    _require_enabled()
    existing = svc.get_reservation(reservation_id)
    if existing is None or existing.get("hotel_id") != hotel_id:
        raise HTTPException(status_code=404, detail="Reservation not found")
    item = svc.transition_reservation(
        reservation_id,
        "checked_in",
        actor=user.sub,
        reason=body.reason or "",
        assigned_room_ids=body.assigned_room_ids,
    )
    return StayReservationOut(**item)


# ---------------------------------------------------------------------------
# 7. POST /ui/hotels/{hotel_id}/reservations/{reservation_id}/check-out
# ---------------------------------------------------------------------------

@hotel_reservations_router.post(
    "/hotels/{hotel_id}/reservations/{reservation_id}/check-out",
    response_model=StayReservationOut,
)
async def check_out_reservation(
    hotel_id: str,
    reservation_id: str,
    body: Optional[ReservationActionIn] = None,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> StayReservationOut:
    _require_enabled()
    existing = svc.get_reservation(reservation_id)
    if existing is None or existing.get("hotel_id") != hotel_id:
        raise HTTPException(status_code=404, detail="Reservation not found")
    item = svc.transition_reservation(
        reservation_id,
        "checked_out",
        actor=user.sub,
        reason=(body.reason if body else "") or "",
    )
    return StayReservationOut(**item)


# ---------------------------------------------------------------------------
# 8. POST /ui/hotels/{hotel_id}/reservations/{reservation_id}/cancel
# ---------------------------------------------------------------------------

@hotel_reservations_router.post(
    "/hotels/{hotel_id}/reservations/{reservation_id}/cancel",
    response_model=StayReservationOut,
)
async def cancel_reservation(
    hotel_id: str,
    reservation_id: str,
    body: Optional[ReservationActionIn] = None,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> StayReservationOut:
    _require_enabled()
    existing = svc.get_reservation(reservation_id)
    if existing is None or existing.get("hotel_id") != hotel_id:
        raise HTTPException(status_code=404, detail="Reservation not found")
    item = svc.transition_reservation(
        reservation_id,
        "cancelled",
        actor=user.sub,
        reason=(body.reason if body else "") or "",
    )
    # HTL-034: compute + post the cancellation refund (release inventory, one
    # refund ledger row). Idempotent + best-effort — the FSM has already blocked
    # a double-cancel, and a refund-posting hiccup must NOT undo the cancellation.
    try:
        from app.services import hotel_cancellation as _canc
        _policy = _canc.resolve_policy_for_reservation(existing)
        _canc.apply_cancellation(existing, _policy, actor_sub=user.sub)
    except Exception:
        pass
    return StayReservationOut(**item)


# ---------------------------------------------------------------------------
# 9. POST /ui/hotels/{hotel_id}/reservations/{reservation_id}/no-show
# ---------------------------------------------------------------------------

@hotel_reservations_router.post(
    "/hotels/{hotel_id}/reservations/{reservation_id}/no-show",
    response_model=StayReservationOut,
)
async def no_show_reservation(
    hotel_id: str,
    reservation_id: str,
    body: Optional[ReservationActionIn] = None,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> StayReservationOut:
    _require_enabled()
    existing = svc.get_reservation(reservation_id)
    if existing is None or existing.get("hotel_id") != hotel_id:
        raise HTTPException(status_code=404, detail="Reservation not found")
    item = svc.transition_reservation(
        reservation_id,
        "no_show",
        actor=user.sub,
        reason=(body.reason if body else "") or "",
    )
    # HTL-034: post the no-show fee (one charge ledger row, no inventory release).
    # Idempotent + best-effort; the FSM blocks a repeat no_show transition.
    try:
        from app.services import hotel_cancellation as _canc
        _policy = _canc.resolve_policy_for_reservation(existing)
        _canc.apply_no_show(existing, _policy, actor_sub=user.sub)
    except Exception:
        pass
    return StayReservationOut(**item)


# ---------------------------------------------------------------------------
# 10. GET /ui/hotels/{hotel_id}/reservations/{reservation_id}
#     (bare dynamic — declared AFTER all literal sub-routes)
# ---------------------------------------------------------------------------

@hotel_reservations_router.get(
    "/hotels/{hotel_id}/reservations/{reservation_id}",
    response_model=StayReservationOut,
)
async def get_reservation(
    hotel_id: str,
    reservation_id: str,
    session=Depends(require_ui_session),
) -> StayReservationOut:
    _require_enabled()
    item = svc.get_reservation(reservation_id)
    if item is None or item.get("hotel_id") != hotel_id:
        raise HTTPException(status_code=404, detail="Reservation not found")
    return StayReservationOut(**item)


# ---------------------------------------------------------------------------
# 11. PUT /ui/hotels/{hotel_id}/reservations/{reservation_id}
#     (bare dynamic — declared AFTER all literal sub-routes)
# ---------------------------------------------------------------------------

@hotel_reservations_router.put(
    "/hotels/{hotel_id}/reservations/{reservation_id}",
    response_model=StayReservationOut,
)
async def modify_reservation(
    hotel_id: str,
    reservation_id: str,
    body: ReservationModifyIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> StayReservationOut:
    _require_enabled()
    existing = svc.get_reservation(reservation_id)
    if existing is None or existing.get("hotel_id") != hotel_id:
        raise HTTPException(status_code=404, detail="Reservation not found")
    item = svc.modify_reservation(
        reservation_id,
        checkin=body.checkin,
        checkout=body.checkout,
        room_type_id=body.room_type_id,
        adults=body.adults,
        children=body.children,
        rooms=body.rooms,
        actor=user.sub,
    )
    return StayReservationOut(**item)
