"""
app/routers/booking_engine.py
QloApps Booking-Engine Storefront public router (HTL-025 .. HTL-027)

All endpoints are unauthenticated (no Depends(require_ui_session)).
The router is registered in app/main.py next to the other public routers.
Every handler calls _require_enabled() first — 404 when HOTEL_PMS_ENABLED=false.

Declaration order (CLAUDE.md / FastAPI matching gotcha):
  1. GET  /booking-engine/search         (literal, HTL-026)
  2. POST /booking-engine/cart           (literal, HTL-027)
  3. POST /booking-engine/cart/{id}/rooms    (HTL-027)
  4. POST /booking-engine/cart/{id}/guest   (HTL-027)
  5. POST /booking-engine/cart/{id}/checkout (HTL-027)
  6. GET  /booking-engine/cart/{id}         (HTL-027)
  7. GET  /booking-engine/hotels/{id}       (HTL-025)
  8. GET  /booking-engine/hotels/{id}/room-types (HTL-025)

Literal /search and /cart routes are declared BEFORE the dynamic /hotels/{hotel_id}
so FastAPI never captures "search" or "cart" as a path param.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request

from app.core.settings import S
from app.models import (
    AddRoomToCartIn,
    BookingCartOut,
    BookingCheckoutIn,
    BookingCheckoutResult,
    BookingStayQuoteOut,
    GuestDetailsIn,
    PublicHotelOut,
    PublicRoomTypeListOut,
)
from app.services import hotel_storefront
from app.services.rate_limit import _bucket_limit

booking_engine_router = APIRouter(prefix="/booking-engine", tags=["booking_engine"])


# ---------------------------------------------------------------------------
# Rate-limit helpers
# ---------------------------------------------------------------------------

def _rate_limit_search_or_429(request: Request) -> None:
    ip = (request.client.host if request.client else "") or "unknown"
    sid = f"rl#booking_search#{ip}"
    win = int(getattr(S, "hotel_booking_search_rl_window", 3600))
    max_n = int(getattr(S, "hotel_booking_search_rl_max", 60))
    if not _bucket_limit(f"ip#{ip}", sid, max_n, win):
        raise HTTPException(
            status_code=429,
            detail="Too many searches; slow down and try again shortly.",
            headers={"Retry-After": str(win)},
        )


def _rate_limit_cart_or_429(request: Request) -> None:
    ip = (request.client.host if request.client else "") or "unknown"
    sid = "booking_cart"
    subj = f"booking_rl:{ip}"
    cap = int(getattr(S, "hotel_booking_cart_rl_max", 120))
    win = int(getattr(S, "hotel_booking_cart_rl_window", 3600))
    if not _bucket_limit(subj, sid, cap, win):
        raise HTTPException(
            status_code=429,
            detail="Too many requests",
            headers={"Retry-After": str(win)},
        )


def _rate_limit_checkout_or_429(request: Request) -> None:
    ip = (request.client.host if request.client else "") or "unknown"
    sid = "booking_checkout"
    subj = f"booking_rl:{ip}"
    cap = int(getattr(S, "hotel_booking_checkout_rl_max", 20))
    win = int(getattr(S, "hotel_booking_checkout_rl_window", 3600))
    if not _bucket_limit(subj, sid, cap, win):
        raise HTTPException(
            status_code=429,
            detail="Too many requests",
            headers={"Retry-After": str(win)},
        )


# ---------------------------------------------------------------------------
# 1. GET /booking-engine/search  (HTL-026) — literal route, declared first
# ---------------------------------------------------------------------------

@booking_engine_router.get("/search", response_model=BookingStayQuoteOut)
async def booking_engine_search(
    request: Request,
    hotel: str = Query(..., description="hotel_id of a published hotel"),
    checkin: str = Query(..., description="ISO date YYYY-MM-DD (inclusive)"),
    checkout: str = Query(..., description="ISO date YYYY-MM-DD (exclusive)"),
    adults: int = Query(1, ge=1, le=16),
    children: int = Query(0, ge=0, le=16),
    rooms: int = Query(1, ge=1),
) -> BookingStayQuoteOut:
    hotel_storefront._require_enabled()
    _rate_limit_search_or_429(request)
    quote = hotel_storefront.quote_stay(
        hotel_id=hotel,
        checkin=checkin,
        checkout=checkout,
        adults=adults,
        children=children,
        rooms=rooms,
    )
    return BookingStayQuoteOut(**quote)


# ---------------------------------------------------------------------------
# 2. POST /booking-engine/cart  (HTL-027) — literal route, declared before dynamic
# ---------------------------------------------------------------------------

@booking_engine_router.post("/cart", response_model=BookingCartOut)
async def booking_engine_create_cart(
    request: Request,
    hotel_id: str = Query(..., description="hotel_id of a published hotel"),
) -> BookingCartOut:
    hotel_storefront._require_enabled()
    _rate_limit_cart_or_429(request)
    result = hotel_storefront.create_booking_cart(hotel_id=hotel_id)
    return BookingCartOut(**result)


# ---------------------------------------------------------------------------
# 3. POST /booking-engine/cart/{booking_cart_id}/rooms  (HTL-027)
# ---------------------------------------------------------------------------

@booking_engine_router.post("/cart/{booking_cart_id}/rooms", response_model=BookingCartOut)
async def booking_engine_add_room(
    request: Request,
    booking_cart_id: str,
    body: AddRoomToCartIn,
) -> BookingCartOut:
    hotel_storefront._require_enabled()
    _rate_limit_cart_or_429(request)
    result = hotel_storefront.add_room_to_cart(
        booking_cart_id=booking_cart_id,
        hotel_id=body.hotel_id,
        room_type_id=body.room_type_id,
        checkin=body.checkin,
        checkout=body.checkout,
        adults=body.adults,
        children=body.children,
        rooms=body.rooms,
    )
    return BookingCartOut(**result)


# ---------------------------------------------------------------------------
# 4. POST /booking-engine/cart/{booking_cart_id}/guest  (HTL-027)
# ---------------------------------------------------------------------------

@booking_engine_router.post("/cart/{booking_cart_id}/guest", response_model=BookingCartOut)
async def booking_engine_set_guest(
    request: Request,
    booking_cart_id: str,
    body: GuestDetailsIn,
) -> BookingCartOut:
    hotel_storefront._require_enabled()
    _rate_limit_cart_or_429(request)
    addr = body.address.model_dump() if body.address else None
    result = hotel_storefront.set_guest_details(
        booking_cart_id=booking_cart_id,
        name=body.name,
        email=body.email,
        phone=body.phone,
        address=addr,
    )
    return BookingCartOut(**result)


# ---------------------------------------------------------------------------
# 5. POST /booking-engine/cart/{booking_cart_id}/checkout  (HTL-027)
# ---------------------------------------------------------------------------

@booking_engine_router.post("/cart/{booking_cart_id}/checkout", response_model=BookingCheckoutResult)
async def booking_engine_checkout(
    request: Request,
    booking_cart_id: str,
    body: BookingCheckoutIn,
) -> BookingCheckoutResult:
    hotel_storefront._require_enabled()
    _rate_limit_checkout_or_429(request)
    result = hotel_storefront.checkout_booking_cart(
        booking_cart_id=booking_cart_id,
        payment_method_token=body.payment_method_token,
        idempotency_key=body.idempotency_key,
        req=request,
    )
    return BookingCheckoutResult(**result)


# ---------------------------------------------------------------------------
# 6. GET /booking-engine/cart/{booking_cart_id}  (HTL-027)
# ---------------------------------------------------------------------------

@booking_engine_router.get("/cart/{booking_cart_id}", response_model=BookingCartOut)
async def booking_engine_get_cart(
    booking_cart_id: str,
) -> BookingCartOut:
    hotel_storefront._require_enabled()
    result = hotel_storefront.get_booking_cart(booking_cart_id)
    return BookingCartOut(**result)


# ---------------------------------------------------------------------------
# 7. GET /booking-engine/hotels/{hotel_id}  (HTL-025) — dynamic route, declared AFTER literals
# ---------------------------------------------------------------------------

@booking_engine_router.get("/hotels/{hotel_id}", response_model=PublicHotelOut)
async def booking_engine_get_hotel(
    hotel_id: str,
) -> PublicHotelOut:
    hotel_storefront._require_enabled()
    result = hotel_storefront.public_get_hotel(hotel_id)
    return PublicHotelOut(**result)


# ---------------------------------------------------------------------------
# 8. GET /booking-engine/hotels/{hotel_id}/room-types  (HTL-025)
# ---------------------------------------------------------------------------

@booking_engine_router.get("/hotels/{hotel_id}/room-types", response_model=PublicRoomTypeListOut)
async def booking_engine_list_room_types(
    hotel_id: str,
) -> PublicRoomTypeListOut:
    hotel_storefront._require_enabled()
    result = hotel_storefront.public_list_room_types(hotel_id)
    return PublicRoomTypeListOut(**result)
