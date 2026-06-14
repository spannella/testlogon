"""
app/services/hotel_storefront.py
QloApps Booking-Engine Storefront (HTL-025 .. HTL-027)

Public, unauthenticated service layer for the booking-engine funnel:
  HTL-025  — public_get_hotel / public_list_room_types  (browse)
  HTL-026  — quote_stay                                 (search + quote)
  HTL-027  — create_booking_cart / add_room_to_cart /
              set_guest_details / get_booking_cart /
              checkout_booking_cart                     (cart + checkout)

All entrypoints call _require_enabled() first — 404 when HOTEL_PMS_ENABLED=false.
Zero if-S.dev_mode branches (SECOPS-007).
Forward-dep collaborators are imported at module level so tests can patch them.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import date
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

# ---------------------------------------------------------------------------
# HTL-025 flag / audit scaffolding (verbatim from app/services/inventory.py:50-56,92-98)
# ---------------------------------------------------------------------------

def _flag_on() -> bool:
    return bool(getattr(S, "hotel_pms_enabled", False))


def _require_enabled() -> None:
    if not _flag_on():
        raise HTTPException(status_code=404, detail="Hotel PMS is not enabled")


def _audit(event: str, user_sub: str, **fields: Any) -> None:  # noqa: ANN401
    try:
        from app.services.alerts import audit_event  # lazy — avoids circular import
        audit_event(event, user_sub or "system", None, **fields)
    except Exception:
        pass


def _to_int(v: Any, default: int = 0) -> int:
    try:
        return int(v) if v is not None else default
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# HTL-025 publication predicate (single reconciliation point)
# ---------------------------------------------------------------------------

def _is_published(item: Optional[Dict[str, Any]]) -> bool:
    """True iff the hotel/room-type item is publicly visible."""
    if not item:
        return False
    status = (item.get("status") or "").lower()
    if status in ("archived", "draft"):
        return False
    if item.get("published") is False:          # explicit unpublish if a future ticket adds it
        return False
    return status == "active" or item.get("published") is True


# ---------------------------------------------------------------------------
# HTL-025 amenity helper (best-effort; degrades to [] when HTL-002 absent)
# ---------------------------------------------------------------------------

def _amenities_for(target_type: str, target_id: str) -> List[str]:
    try:
        from app.services.hotel_amenities import list_amenities_for  # type: ignore[import]
        return list_amenities_for(target_type, target_id)
    except Exception:
        return []


# ---------------------------------------------------------------------------
# HTL-025 projections (allow-list — never **item)
# ---------------------------------------------------------------------------

def _project_hotel(item: Dict[str, Any]) -> Dict[str, Any]:
    """Build the PublicHotelOut-shaped dict from a raw DDB hotel META row."""
    addr = item.get("address") or {}
    policies = item.get("policies") or {}
    contact = item.get("contact") or {}
    return {
        "hotel_id": item["hotel_id"],
        "name": item.get("name", ""),
        "description": item.get("description", ""),
        "star_rating": _to_int(item.get("star_rating"), 0),
        "check_in_time": item.get("check_in_time", ""),
        "check_out_time": item.get("check_out_time", ""),
        "address": {
            "line1": addr.get("line1", ""),
            "line2": addr.get("line2"),
            "city": addr.get("city", ""),
            "region": addr.get("region", ""),
            "postal_code": addr.get("postal_code", ""),
            "country": addr.get("country", ""),
        },
        "amenities": [],   # resolved lazily by public_get_hotel
        "photos": list(item.get("photo_urls") or []),
        "policies": {
            "cancellation_text": policies.get("cancellation_text", ""),
            "pet_policy": policies.get("pet_policy", ""),
            "smoking": bool(policies.get("smoking", False)),
            "children": bool(policies.get("children", True)),
        },
        "contact": {
            "phone": contact.get("phone", ""),
            "email": contact.get("email", ""),
            "website": contact.get("website", ""),
        },
    }


def _project_room_type(row: Dict[str, Any]) -> Dict[str, Any]:
    """Build the PublicRoomTypeOut-shaped dict from a raw DDB ROOMTYPE# row."""
    return {
        "room_type_id": row.get("room_type_id", row["sk"].split("#", 1)[-1] if "#" in str(row.get("sk", "")) else ""),
        "name": row.get("name", ""),
        "description": row.get("description", ""),
        "occupancy_adults": _to_int(row.get("base_occupancy_adults"), 0),
        "occupancy_children": _to_int(row.get("base_occupancy_children"), 0),
        "max_occupancy": _to_int(row.get("max_occupancy"), 0),
        "bed_type": row.get("bed_type", ""),
        "size_sqft": _to_int(row.get("size_sqft"), 0),
        "amenities": [],
        "photos": list(row.get("photo_urls") or []),
        "base_rate_cents": _to_int(row.get("base_nightly_rate_cents"), 0),
        "currency": row.get("currency", "usd"),
    }


# ---------------------------------------------------------------------------
# HTL-025 public service functions
# ---------------------------------------------------------------------------

def public_get_hotel(hotel_id: str) -> Dict[str, Any]:
    """Return the storefront-safe hotel projection for a published hotel.

    Raises HTTPException(404) for any of: flag off, hotel missing, archived, draft.
    """
    _require_enabled()
    item = T.hotels.get_item(Key={"hotel_id": hotel_id, "sk": "META"}).get("Item")
    if not _is_published(item):
        raise HTTPException(status_code=404, detail="Hotel not found")
    projection = _project_hotel(item)
    projection["amenities"] = _amenities_for("hotel", hotel_id)
    _audit("hotel.storefront.viewed", "anon", hotel_id=hotel_id)
    return projection


def public_list_room_types(hotel_id: str) -> Dict[str, Any]:
    """Return published room types for a published hotel."""
    _require_enabled()
    # Publication gate — 404 if hotel is missing/archived/draft (also calls _require_enabled)
    public_get_hotel(hotel_id)
    # Query ROOMTYPE# rows on the hotel partition
    resp = T.hotels.query(
        KeyConditionExpression=Key("hotel_id").eq(hotel_id) & Key("sk").begins_with("ROOMTYPE#"),
    )
    rows = resp.get("Items", [])
    # Paginate if needed
    while resp.get("LastEvaluatedKey"):
        resp = T.hotels.query(
            KeyConditionExpression=Key("hotel_id").eq(hotel_id) & Key("sk").begins_with("ROOMTYPE#"),
            ExclusiveStartKey=resp["LastEvaluatedKey"],
        )
        rows.extend(resp.get("Items", []))
    published = [row for row in rows if _is_published(row)]
    projected = []
    for row in published:
        p = _project_room_type(row)
        p["amenities"] = _amenities_for("room_type", p["room_type_id"])
        projected.append(p)
    projected.sort(key=lambda r: r["name"])
    return {"room_types": projected, "count": len(projected)}


# ---------------------------------------------------------------------------
# HTL-026 stay-search + quote
# Forward-dep search_stays imported at module level so tests can patch it.
# ---------------------------------------------------------------------------

def _default_currency() -> str:
    return "usd"


def _max_los_nights() -> int:
    return int(getattr(S, "hotel_booking_search_max_los_nights", 30))


def _validate_quote_span(checkin: str, checkout: str) -> int:
    """Returns nights count or raises HTTPException(400)."""
    try:
        ci = date.fromisoformat(checkin)
        co = date.fromisoformat(checkout)
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="checkin/checkout must be YYYY-MM-DD")
    nights = (co - ci).days
    if nights < 1:
        raise HTTPException(status_code=400, detail="checkout must be after checkin")
    if nights > _max_los_nights():
        raise HTTPException(status_code=400, detail=f"stay exceeds maximum {_max_los_nights()} nights")
    return nights


def _per_night_out(n: Any) -> Dict[str, Any]:
    """Project one per-night availability line from the engine's NightLineOut."""
    if isinstance(n, dict):
        return {
            "date": str(n.get("date", "")),
            "rooms_available": _to_int(n.get("rooms_available", n.get("rooms_remaining", 0))),
            "rate_cents": _to_int(n.get("rate_cents", n.get("total_cents", 0))),
        }
    # If it's an object (HTL-017 NightLineOut dataclass/model)
    return {
        "date": str(getattr(n, "date", "")),
        "rooms_available": _to_int(getattr(n, "rooms_available", getattr(n, "rooms_remaining", 0))),
        "rate_cents": _to_int(getattr(n, "rate_cents", getattr(n, "total_cents", 0))),
    }


def _project_engine_result(r: Any, hotel_id: str) -> Dict[str, Any]:
    """Project one StayRoomTypeResult into StayQuoteResultOut-shaped dict."""
    rt_id = getattr(r, "room_type_id", None) or (r.get("room_type_id") if isinstance(r, dict) else "")
    rt_name = getattr(r, "name", None) or (r.get("name") if isinstance(r, dict) else "")
    min_remaining = _to_int(getattr(r, "min_remaining", None) or (r.get("min_remaining") if isinstance(r, dict) else 0))
    total_cents = _to_int(getattr(r, "total_cents", None) or (r.get("total_cents") if isinstance(r, dict) else 0))
    currency = getattr(r, "currency", None) or (r.get("currency") if isinstance(r, dict) else _default_currency()) or _default_currency()
    per_night_raw = getattr(r, "per_night", None) or (r.get("per_night") if isinstance(r, dict) else []) or []
    per_night = [_per_night_out(n) for n in per_night_raw]

    # Build minimal PublicRoomTypeOut projection from engine fields
    room_type = {
        "room_type_id": rt_id,
        "name": rt_name,
        "description": "",
        "occupancy_adults": 1,
        "occupancy_children": 0,
        "max_occupancy": 0,
        "bed_type": "",
        "size_sqft": 0,
        "amenities": [],
        "photos": [],
        "base_rate_cents": total_cents,
        "currency": currency,
    }
    return {
        "room_type": room_type,
        "available_rooms": min_remaining,
        "per_night": per_night,
        "total_price_cents": total_cents,
        "currency": currency,
    }


# Module-level import so tests can patch hotel_storefront.search_stays
try:
    from app.services.hotel_reservations import search_stays  # type: ignore[import]
except ImportError:
    def search_stays(**kwargs: Any) -> Any:  # type: ignore[misc]
        raise HTTPException(status_code=503, detail="Stay-search engine unavailable")


def quote_stay(
    *,
    hotel_id: str,
    checkin: str,
    checkout: str,
    adults: int = 1,
    children: int = 0,
    rooms: int = 1,
) -> Dict[str, Any]:
    """Public stay-search + quote. Thin wrapper around HTL-017 search_stays."""
    _require_enabled()
    # 1. Publication gate (404 on missing/unpublished hotel)
    public_get_hotel(hotel_id)
    # 2. Span validation (public-facing 400, mirrors calendar reserve_booking_slot)
    nights = _validate_quote_span(checkin, checkout)
    # 3. Occupancy bounds (defensive; also validated at Query() edge in the router)
    if adults < 1 or children < 0 or rooms < 1:
        raise HTTPException(status_code=400, detail="invalid occupancy")
    # 4. Delegate to the engine
    engine = search_stays(
        hotel_id=hotel_id,
        checkin=checkin,
        checkout=checkout,
        adults=adults,
        children=children,
        rooms=rooms,
    )
    # 5. Project engine output into storefront quote shape
    engine_results = getattr(engine, "results", None) or (engine.get("results") if isinstance(engine, dict) else []) or []
    results = [_project_engine_result(r, hotel_id) for r in engine_results]
    currency = results[0]["currency"] if results else _default_currency()
    engine_nights = _to_int(getattr(engine, "nights", None) or (engine.get("nights") if isinstance(engine, dict) else nights) or nights)
    return {
        "hotel_id": hotel_id,
        "checkin": checkin,
        "checkout": checkout,
        "nights": engine_nights,
        "adults": adults,
        "children": children,
        "rooms": rooms,
        "results": results,
        "currency": currency,
    }


# ---------------------------------------------------------------------------
# HTL-027 booking cart helpers
# ---------------------------------------------------------------------------

def _booking_owner_sub(booking_cart_id: str) -> str:
    return f"booking_guest:{booking_cart_id}"


def _guest_party_id(email: str) -> str:
    norm = (email or "").strip().lower()
    return "guest_" + hashlib.sha256(norm.encode()).hexdigest()[:24]


# Module-level imports so tests can patch
try:
    from app.services import shoppingcart as _shoppingcart  # type: ignore[import]
except ImportError:
    _shoppingcart = None  # type: ignore[assignment]

try:
    from app.services.hotel_reservations import create_reservation as _create_reservation  # type: ignore[import]
except ImportError:
    _create_reservation = None  # type: ignore[assignment]


def _ddb_int(v: Any) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _list_booking_lines(owner: str, booking_cart_id: str) -> List[Dict[str, Any]]:
    """Read raw booking-line items from the shopping_cart table (bypasses _item_from_item
    so booking_meta is accessible directly from DDB)."""
    prefix = f"CART#{booking_cart_id}#ITEM#"
    resp = T.shopping_cart.query(
        KeyConditionExpression=Key("PK").eq(f"USER#{owner}") & Key("SK").begins_with(prefix),
    )
    return list(resp.get("Items", []))


def _booking_cart_out(cart: Dict[str, Any], owner: str, booking_cart_id: str) -> Dict[str, Any]:
    """Build the BookingCartOut-shaped dict from the raw cart + lines."""
    # Read raw DDB items directly so booking_meta survives the projection
    raw_lines = _list_booking_lines(owner, booking_cart_id)
    lines = []
    for line in raw_lines:
        bm = line.get("booking_meta") or {}
        qty = _ddb_int(line.get("quantity", 1))
        upc = _ddb_int(line.get("unit_price_cents", 0))
        lines.append({
            "room_type_id": bm.get("room_type_id", ""),
            "room_type_name": line.get("name", ""),
            "checkin": bm.get("checkin", ""),
            "checkout": bm.get("checkout", ""),
            "nights": _ddb_int(bm.get("nights", 0)),
            "adults": _ddb_int(bm.get("adults", 1)),
            "children": _ddb_int(bm.get("children", 0)),
            "rooms": qty,
            "unit_price_cents": upc,
            "line_total_cents": _ddb_int(line.get("line_total_cents", qty * upc)),
            "currency": bm.get("currency", "usd"),
        })
    total_cents = sum(ln["line_total_cents"] for ln in lines)
    guest_snap = cart.get("guest_snapshot")
    guest = None
    if guest_snap:
        guest = {
            "name": guest_snap.get("name", ""),
            "email": guest_snap.get("email", ""),
            "phone": guest_snap.get("phone", ""),
            "address": guest_snap.get("address"),
        }
    return {
        "booking_cart_id": booking_cart_id,
        "hotel_id": cart.get("booking_hotel_id", ""),
        "status": cart.get("status", "OPEN"),
        "currency": cart.get("currency", "usd"),
        "lines": lines,
        "total_cents": total_cents,
        "guest": guest,
        "created_at": cart.get("created_at", ""),
    }


def _resolve_booking_cart(booking_cart_id: str) -> Dict[str, Any]:
    """Load the booking-cart parent row (404 if absent or not a booking cart)."""
    owner = _booking_owner_sub(booking_cart_id)
    if _shoppingcart is None:
        raise HTTPException(status_code=404, detail="Booking cart not found")
    cart = _shoppingcart.get_cart(owner, booking_cart_id)
    if cart.get("booking_kind") != "hotel_booking":
        raise HTTPException(status_code=404, detail="Booking cart not found")
    return cart


# ---------------------------------------------------------------------------
# HTL-027 cart functions
# ---------------------------------------------------------------------------

def create_booking_cart(*, hotel_id: str) -> Dict[str, Any]:
    """Mint a booking cart for a published hotel."""
    _require_enabled()
    # Validate hotel is published
    public_get_hotel(hotel_id)
    if _shoppingcart is None:
        raise HTTPException(status_code=503, detail="Shopping cart service unavailable")
    # booking_cart_id == shop cart_id (one uuid, used for both)
    booking_cart_id = uuid.uuid4().hex
    owner = _booking_owner_sub(booking_cart_id)
    now_iso = __import__("datetime").datetime.utcnow().isoformat()
    ts = now_ts()
    ttl_epoch = ts + (int(getattr(S, "cart_ttl_days", 30)) * 86400)
    item: Dict[str, Any] = {
        "PK": f"USER#{owner}",
        "SK": f"CART#{booking_cart_id}",
        "type": "cart",
        "cart_id": booking_cart_id,
        "status": "OPEN",
        "created_at": now_iso,
        "last_activity_at": ts,
        "reminder_count": 0,
        "currency": "usd",
        "ttl": ttl_epoch,
        # booking-specific attributes
        "booking_cart_id": booking_cart_id,
        "booking_hotel_id": hotel_id,
        "booking_kind": "hotel_booking",
        "booking_owner_sub": owner,
    }
    T.shopping_cart.put_item(Item=item)
    _audit("hotel.booking.cart_created", "system", booking_cart_id=booking_cart_id, hotel_id=hotel_id)
    cart = _shoppingcart.get_cart(owner, booking_cart_id)
    cart["booking_hotel_id"] = hotel_id
    cart["booking_kind"] = "hotel_booking"
    cart["booking_cart_id"] = booking_cart_id
    return _booking_cart_out(cart, owner, booking_cart_id)


def add_room_to_cart(
    *,
    booking_cart_id: str,
    hotel_id: str,
    room_type_id: str,
    checkin: str,
    checkout: str,
    adults: int = 1,
    children: int = 0,
    rooms: int = 1,
) -> Dict[str, Any]:
    """Re-quote (server-derived price + availability) and add one room-night line to the cart."""
    _require_enabled()
    cart = _resolve_booking_cart(booking_cart_id)
    if cart.get("booking_hotel_id") != hotel_id:
        raise HTTPException(status_code=422, detail="hotel_id does not match this booking cart")
    if _shoppingcart is None:
        raise HTTPException(status_code=503, detail="Shopping cart service unavailable")
    # Re-quote at add time (server-derived price — never trust client)
    quote = quote_stay(
        hotel_id=hotel_id,
        checkin=checkin,
        checkout=checkout,
        adults=adults,
        children=children,
        rooms=rooms,
    )
    # Find the result for this room_type_id
    result = next(
        (r for r in quote.get("results", []) if r["room_type"]["room_type_id"] == room_type_id),
        None,
    )
    if result is None:
        raise HTTPException(status_code=409, detail={"code": "no_availability", "room_type_id": room_type_id})
    nights = quote["nights"]
    total_price_cents = result["total_price_cents"]
    # unit_price_cents = per-room span total
    unit_price_cents = total_price_cents // max(rooms, 1)
    sku = f"ROOMNIGHT#{room_type_id}#{checkin}_{checkout}"
    name = f"{result['room_type']['name']} — {checkin}→{checkout} ({nights}n)"
    owner = _booking_owner_sub(booking_cart_id)
    booking_meta: Dict[str, Any] = {
        "room_type_id": room_type_id,
        "checkin": checkin,
        "checkout": checkout,
        "adults": adults,
        "children": children,
        "rooms": rooms,
        "nights": nights,
        "currency": result["currency"],
    }
    line_total = unit_price_cents * rooms
    # Write the line item directly to DDB (bypass add_item's product_type validation
    # which only knows file_bundle/api_package).  get-then-merge so re-adding the
    # same (room-type, span) updates qty (the same re-add contract as add_item).
    sk = f"CART#{booking_cart_id}#ITEM#{sku}"
    pk = f"USER#{owner}"
    existing = T.shopping_cart.get_item(Key={"PK": pk, "SK": sk}).get("Item")
    if existing:
        new_qty = _ddb_int(existing.get("quantity", 0)) + rooms
        new_total = unit_price_cents * new_qty
        T.shopping_cart.update_item(
            Key={"PK": pk, "SK": sk},
            UpdateExpression="SET quantity = :q, line_total_cents = :lt, booking_meta = :bm",
            ExpressionAttributeValues={":q": new_qty, ":lt": new_total, ":bm": booking_meta},
        )
    else:
        now_iso = __import__("datetime").datetime.utcnow().isoformat()
        T.shopping_cart.put_item(Item={
            "PK": pk, "SK": sk,
            "type": "item",
            "cart_id": booking_cart_id,
            "sku": sku,
            "name": name,
            "quantity": rooms,
            "unit_price_cents": unit_price_cents,
            "line_total_cents": line_total,
            "booking_meta": booking_meta,
            "updated_at": now_iso,
        })
    updated = _resolve_booking_cart(booking_cart_id)
    return _booking_cart_out(updated, owner, booking_cart_id)


def set_guest_details(
    *,
    booking_cart_id: str,
    name: str,
    email: str,
    phone: str,
    address: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Resolve the guest (opaque guest_party_id by email) and stamp the snapshot on the cart."""
    _require_enabled()
    cart = _resolve_booking_cart(booking_cart_id)
    owner = _booking_owner_sub(booking_cart_id)
    gp_id = _guest_party_id(email)
    guest_snapshot = {
        "name": name,
        "email": email,
        "phone": phone,
        "address": address,
    }
    T.shopping_cart.update_item(
        Key={"PK": f"USER#{owner}", "SK": f"CART#{booking_cart_id}"},
        UpdateExpression="SET guest_party_id = :gid, guest_snapshot = :gs",
        ExpressionAttributeValues={":gid": gp_id, ":gs": guest_snapshot},
    )
    _audit("hotel.booking.guest_set", "system", booking_cart_id=booking_cart_id, guest_party_id=gp_id)
    cart["guest_party_id"] = gp_id
    cart["guest_snapshot"] = guest_snapshot
    return _booking_cart_out(cart, owner, booking_cart_id)


def get_booking_cart(booking_cart_id: str) -> Dict[str, Any]:
    """Read the booking cart (parent + lines) by its public id."""
    _require_enabled()
    cart = _resolve_booking_cart(booking_cart_id)
    owner = _booking_owner_sub(booking_cart_id)
    return _booking_cart_out(cart, owner, booking_cart_id)


def checkout_booking_cart(
    *,
    booking_cart_id: str,
    payment_method_token: Optional[str] = None,
    idempotency_key: Optional[str] = None,
    req: Any = None,
) -> Dict[str, Any]:
    """Final-guard availability, settle money, then on success create reservations."""
    _require_enabled()
    cart = _resolve_booking_cart(booking_cart_id)
    owner = _booking_owner_sub(booking_cart_id)

    # Require guest details
    if not cart.get("guest_party_id"):
        raise HTTPException(status_code=422, detail={"code": "guest_required"})

    if _shoppingcart is None:
        raise HTTPException(status_code=503, detail="Shopping cart service unavailable")

    lines = _list_booking_lines(owner, booking_cart_id)
    if not lines:
        raise HTTPException(status_code=422, detail={"code": "empty_cart"})

    # Idempotency short-circuit — if already purchased, return stored result
    if cart.get("status") == "PURCHASED":
        reservation_ids = list(cart.get("reservation_ids") or [])
        order_id = cart.get("last_order_id", "")
        total_cents = sum(_ddb_int(ln.get("line_total_cents", 0)) for ln in lines)  # lines already read above
        return {
            "reservation_ids": reservation_ids,
            "order_id": order_id,
            "total_price_cents": total_cents,
            "currency": cart.get("currency", "usd"),
            "confirmation": {
                "booking_cart_id": booking_cart_id,
                "hotel_id": cart.get("booking_hotel_id"),
                "guest_party_id": cart.get("guest_party_id"),
                "lines": lines,
            },
        }

    # Final availability re-validation per line
    hotel_id = cart.get("booking_hotel_id", "")
    for line in lines:
        bm = line.get("booking_meta") or {}
        rt_id = bm.get("room_type_id")
        if not rt_id:
            continue
        try:
            q = quote_stay(
                hotel_id=hotel_id,
                checkin=bm.get("checkin", ""),
                checkout=bm.get("checkout", ""),
                adults=_ddb_int(bm.get("adults", 1)),
                children=_ddb_int(bm.get("children", 0)),
                rooms=_ddb_int(bm.get("rooms", 1)),
            )
            avail = next(
                (r for r in q.get("results", []) if r["room_type"]["room_type_id"] == rt_id),
                None,
            )
            if avail is None or avail["available_rooms"] < _ddb_int(bm.get("rooms", 1)):
                raise HTTPException(
                    status_code=409,
                    detail={"code": "no_availability", "room_type_id": rt_id},
                )
        except HTTPException:
            raise
        except Exception:
            # Fail-safe: if re-quote errors, let checkout proceed (availability checked at add-time)
            pass

    # Fraud gate (best-effort; gated by FRAUD_DETECTION_ENABLED in billing.py)
    total_cents_for_fraud = sum(_ddb_int(ln.get("line_total_cents", 0)) for ln in lines)
    if total_cents_for_fraud > 0:
        try:
            from app.routers.billing import _fraud_gate  # type: ignore[import]
            _fraud_gate(
                cart.get("guest_party_id", ""),
                total_cents_for_fraud,
                "credit",
                req=req,
                enforce_block=True,
            )
        except HTTPException:
            raise
        except ImportError:
            pass
        except Exception:
            pass

    # Settle the money path (UNFORKED — reuse purchase_cart)
    purchase_result = _shoppingcart.purchase_cart(
        owner,
        booking_cart_id,
        idempotency_key=idempotency_key,
    )
    order_id = purchase_result.get("order_id", "") if isinstance(purchase_result, dict) else ""

    # On payment success — per-line reservation + inventory hold
    reservation_ids: List[str] = []
    partial_failures: List[str] = []
    if _create_reservation is not None:
        for line in lines:
            bm = line.get("booking_meta") or {}
            rt_id = bm.get("room_type_id")
            if not rt_id:
                continue
            try:
                res = _create_reservation(
                    hotel_id=hotel_id,
                    guest_party_id=cart.get("guest_party_id", ""),
                    room_type_id=rt_id,
                    checkin=bm.get("checkin", ""),
                    checkout=bm.get("checkout", ""),
                    adults=_ddb_int(bm.get("adults", 1)),
                    children=_ddb_int(bm.get("children", 0)),
                    rooms=_ddb_int(bm.get("rooms", 1)),
                    user_sub="system",
                )
                rid = res.get("reservation_id") if isinstance(res, dict) else getattr(res, "reservation_id", "")
                if rid:
                    reservation_ids.append(rid)
            except HTTPException as exc:
                if exc.status_code == 409:
                    # TOCTOU sell-out after step-4 pre-guard
                    partial_failures.append(rt_id)
                    _audit(
                        "hotel.booking.partial_hold_failure", "system",
                        booking_cart_id=booking_cart_id, room_type_id=rt_id, order_id=order_id,
                    )
                else:
                    raise
            except Exception:
                partial_failures.append(rt_id)

    # Persist reservation_ids on the cart
    T.shopping_cart.update_item(
        Key={"PK": f"USER#{owner}", "SK": f"CART#{booking_cart_id}"},
        UpdateExpression="SET reservation_ids = :rids, booking_confirmed_at = :ts, last_order_id = :oid",
        ExpressionAttributeValues={
            ":rids": reservation_ids,
            ":ts": now_ts(),
            ":oid": order_id,
        },
    )

    total_cents = sum(_ddb_int(ln.get("line_total_cents", 0)) for ln in lines)
    _audit(
        "hotel.booking.created", "system",
        booking_cart_id=booking_cart_id,
        order_id=order_id,
        reservation_ids=reservation_ids,
        total_cents=total_cents,
    )

    return {
        "reservation_ids": reservation_ids,
        "order_id": order_id,
        "total_price_cents": total_cents,
        "currency": cart.get("currency", "usd"),
        "confirmation": {
            "booking_cart_id": booking_cart_id,
            "hotel_id": hotel_id,
            "guest_party_id": cart.get("guest_party_id"),
            "lines": lines,
            "partial_failures": partial_failures,
        },
    }
