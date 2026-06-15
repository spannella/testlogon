"""Hotel reservation service (QloApps hotel-PMS vertical, HTL-017..HTL-019).

Additive + flag-gated, default OFF (``HOTEL_PMS_ENABLED``).  Every public
entrypoint calls ``_require_enabled()`` first — when the flag is off the
function raises HTTP 404 before any DynamoDB access and the platform is
byte-for-byte unchanged.

Forward-dep modules (HTL-011/012/015/005/001/006) are imported **at module
level** so hermetic tests can patch them at the ``hotel_reservations``
namespace.  When those clusters are not yet merged in a worktree the
try/except ImportError block installs a lightweight stub so this module is
still importable.
"""
from __future__ import annotations

import hashlib
from datetime import date
from typing import Any, List, Optional
from uuid import uuid4

from fastapi import HTTPException

from app.core.settings import S
from app.core.time import now_ts

# ---------------------------------------------------------------------------
# Forward-dep module imports (lazy-ref — call by id, never re-implement).
# Imported at module level so hermetic tests can monkeypatch the namespace.
# ---------------------------------------------------------------------------

try:
    from app.services import hotel_availability as ha          # HTL-010/012 + HTL-011
except ImportError:
    import types
    ha = types.SimpleNamespace(
        check_availability=lambda *a, **k: (_ for _ in ()).throw(HTTPException(503, "hotel_availability not available")),  # noqa
        hold_rooms=lambda *a, **k: (_ for _ in ()).throw(HTTPException(503, "hotel_availability not available")),  # noqa
        release_hold=lambda *a, **k: None,
    )

try:
    from app.services import hotel_pms                          # HTL-001/005/006
except ImportError:
    import types as _types
    hotel_pms = _types.SimpleNamespace(
        list_hotels=lambda *a, **k: {"hotels": [], "count": 0, "cursor": None},
        list_room_types=lambda *a, **k: {"room_types": [], "count": 0, "cursor": None},
        set_room_status=lambda *a, **k: None,
    )

try:
    from app.services import hotel_rate_plans                   # HTL-015
except ImportError:
    import types as _types2
    hotel_rate_plans = _types2.SimpleNamespace(
        compute_stay_price=lambda *a, **k: (_ for _ in ()).throw(HTTPException(503, "hotel_rate_plans not available")),  # noqa
    )

from app.core import tables as _tables_mod                     # for T handle

# ---------------------------------------------------------------------------
# Feature-flag gate (verbatim from app/services/inventory.py:50-56 pattern,
# reading the master HOTEL_PMS_ENABLED flag landed by HTL-001).
# ---------------------------------------------------------------------------


def _flag_on() -> bool:
    return bool(getattr(S, "hotel_pms_enabled", False))


def _require_enabled() -> None:
    if not _flag_on():
        raise HTTPException(status_code=404, detail="Hotel PMS is not enabled")


# ---------------------------------------------------------------------------
# Audit wrapper (verbatim from app/services/inventory.py:92-98).
# ---------------------------------------------------------------------------


def _audit(event: str, user_sub: str, **fields: Any) -> None:
    try:
        from app.services.alerts import audit_event  # type: ignore[import]
        audit_event(event, user_sub or "system", None, **fields)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _T():
    """Return the live Tables singleton (indirected so tests can freeze it)."""
    return _tables_mod.T


def _validate_span(checkin: str, checkout: str) -> int:
    """Parse YYYY-MM-DD span, enforce >= 1 night, return night count.

    nights = count of dates in [checkin, checkout) (checkout exclusive).
    """
    try:
        ci = date.fromisoformat(checkin)
        co = date.fromisoformat(checkout)
    except (ValueError, TypeError):
        raise HTTPException(status_code=422, detail="checkin/checkout must be YYYY-MM-DD")
    nights = (co - ci).days
    if nights < 1:
        raise HTTPException(status_code=422, detail="checkout must be after checkin")
    return nights


def _reservation_out(item: dict) -> dict:
    """Coerce DynamoDB Decimal numerics to plain int and return clean dict."""
    _int_fields = (
        "nights", "adults", "children", "rooms",
        "total_cents", "deposit_cents", "version",
        "created_at", "updated_at",
    )
    out = dict(item)
    for f in _int_fields:
        if f in out:
            try:
                out[f] = int(out[f])
            except (TypeError, ValueError):
                pass
    out.setdefault("assigned_room_ids", [])
    out.setdefault("currency", "usd")
    return out


# ---------------------------------------------------------------------------
# HTL-017 — Stay-search engine (read-only)
# ---------------------------------------------------------------------------

def search_stays(
    *,
    hotel_id: Optional[str] = None,
    city: Optional[str] = None,
    checkin: str,
    checkout: str,
    adults: int,
    children: int = 0,
    rooms: int = 1,
) -> Any:
    """Read-only stay search.  Pure composition over HTL-012 + HTL-015.  No DDB writes."""
    from app.models import StayRoomTypeResult, StaySearchResult  # local import avoids circular

    _require_enabled()

    # Validate inputs
    if not (hotel_id or city):
        raise HTTPException(status_code=422, detail="one of hotel_id or city is required")
    if adults < 1:
        raise HTTPException(status_code=422, detail="adults must be >= 1")
    if children < 0:
        raise HTTPException(status_code=422, detail="children must be >= 0")
    if rooms < 1:
        raise HTTPException(status_code=422, detail="rooms must be >= 1")
    nights = _validate_span(checkin, checkout)

    # Resolve candidate (hotel_id, room_type) pairs
    candidates: List[tuple] = []   # (hid, rt_dict)

    if hotel_id:
        # hotel_id takes precedence over city
        room_types = _list_all_room_types(hotel_id)
        for rt in room_types:
            candidates.append((hotel_id, rt))
    else:
        # city branch
        hotels_resp = hotel_pms.list_hotels_by_city(city)
        hotels = hotels_resp.get("items", []) if isinstance(hotels_resp, dict) else hotels_resp
        for h in hotels:
            hid = h["hotel_id"] if isinstance(h, dict) else h
            room_types = _list_all_room_types(hid)
            for rt in room_types:
                candidates.append((hid, rt))

    results: List[StayRoomTypeResult] = []

    for hid, rt in candidates:
        rt_id = rt["room_type_id"] if isinstance(rt, dict) else rt

        # Availability check (intersection across whole span)
        avail = ha.check_availability(hid, rt_id, checkin, checkout, rooms_needed=rooms)
        if not avail["available"]:
            continue   # partial-span sold-out → exclude

        # Price (catch 422 LOS rejection → exclude that room type)
        try:
            price = hotel_rate_plans.compute_stay_price(
                hid, rt_id, checkin, checkout, adults, children, rooms
            )
        except HTTPException as exc:
            if exc.status_code == 422:
                continue   # LOS rule rejection (stay too short / too long) → skip
            raise

        rt_name = rt["name"] if isinstance(rt, dict) else rt_id
        results.append(StayRoomTypeResult(
            hotel_id=hid,
            room_type_id=rt_id,
            name=rt_name,
            available=True,
            min_remaining=int(avail["min_remaining"]),
            rooms=rooms,
            per_night=price.per_night,
            total_cents=int(price.total_cents),
            currency=price.currency,
            applied_rule_ids=list(price.applied_rule_ids),
        ))

    # Sort cheapest-first with deterministic tiebreak by room_type_id
    results.sort(key=lambda r: (r.total_cents, r.room_type_id))

    return StaySearchResult(
        checkin=checkin,
        checkout=checkout,
        nights=nights,
        adults=adults,
        children=children,
        rooms=rooms,
        results=results,
        result_count=len(results),
    )


def _list_all_room_types(hotel_id: str) -> List[dict]:
    """Enumerate ALL active room types for a hotel (cursor-loop for pagination)."""
    all_rts: List[dict] = []
    cursor = None
    while True:
        resp = hotel_pms.list_room_types(hotel_id, cursor=cursor)
        page = resp.get("room_types", []) if isinstance(resp, dict) else resp
        all_rts.extend(page)
        cursor = resp.get("cursor") if isinstance(resp, dict) else None
        if not cursor:
            break
    return all_rts


# ---------------------------------------------------------------------------
# HTL-018 — Reservation entity (create + read)
# ---------------------------------------------------------------------------

def create_reservation(
    *,
    hotel_id: str,
    guest_party_id: str,
    room_type_id: str,
    checkin: str,
    checkout: str,
    adults: int,
    children: int = 0,
    rooms: int = 1,
    deposit_cents: int = 0,
    user_sub: str,
) -> dict:
    """Create a confirmed reservation: re-check availability, compute price, hold
    inventory across the whole span, then write the META header (version=1)."""
    _require_enabled()

    # 1. Validate span
    nights = _validate_span(checkin, checkout)

    # 2. Re-check availability at book time
    avail = ha.check_availability(hotel_id, room_type_id, checkin, checkout, rooms_needed=rooms)
    if not avail["available"]:
        raise HTTPException(status_code=409, detail={"code": "no_availability"})

    # 3. Compute price (propagate 422 LOS violations — before any hold)
    price = hotel_rate_plans.compute_stay_price(
        hotel_id, room_type_id, checkin, checkout, adults, children, rooms
    )
    total_cents = int(price.total_cents)
    currency = (price.currency or "usd").lower()

    # 4. Atomically hold inventory across the span
    hold = ha.hold_rooms(
        hotel_id, room_type_id, checkin, checkout,
        quantity=rooms, user_sub=user_sub,
    )
    hold_id = hold["hold_id"]

    # 5. Mint and write header
    reservation_id = "res_" + uuid4().hex[:16]
    ts = now_ts()
    item = {
        "reservation_id": reservation_id,
        "sk": "META",
        "hotel_id": hotel_id,
        "guest_party_id": guest_party_id,
        "room_type_id": room_type_id,
        "assigned_room_ids": [],
        "checkin": checkin,
        "checkout": checkout,
        "nights": nights,
        "adults": adults,
        "children": children,
        "rooms": rooms,
        "total_cents": total_cents,
        "deposit_cents": deposit_cents,
        "currency": currency,
        "status": "confirmed",
        "hold_id": hold_id,
        "version": 1,
        "created_at": ts,
        "updated_at": ts,
    }

    try:
        _T().hotel_reservations.put_item(Item=item)
    except Exception:
        # Best-effort release hold to avoid orphaning room-nights
        try:
            ha.release_hold(
                hold_id,
                reason="reservation_write_failed",
                user_sub=user_sub,
                terminal_status="released",
            )
        except Exception:
            pass
        raise

    # 6. Best-effort initial history row
    try:
        _record_history(
            reservation_id, None, "confirmed",
            actor=user_sub, reason="reservation created",
        )
    except Exception:
        pass

    # 7. Audit
    _audit(
        "hotel.reservation.created", user_sub,
        reservation_id=reservation_id,
        hotel_id=hotel_id,
        total_cents=total_cents,
        hold_id=hold_id,
    )

    return _reservation_out(item)


def get_reservation(reservation_id: str) -> Optional[dict]:
    """Read the reservation header (SK=META).  Returns None (→ 404 at the router) if absent."""
    _require_enabled()
    resp = _T().hotel_reservations.get_item(
        Key={"reservation_id": reservation_id, "sk": "META"}
    )
    item = resp.get("Item")
    if item is None:
        return None
    return _reservation_out(item)


def list_reservations(
    hotel_id: str,
    *,
    status: Optional[str] = None,
    checkin_from: Optional[str] = None,
    checkin_to: Optional[str] = None,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> dict:
    """List reservations for a hotel via GSI_HOTEL_STATUS or GSI_HOTEL_ARRIVALS."""
    from app.core.cursor import encode_cursor, decode_cursor
    from boto3.dynamodb.conditions import Key

    _require_enabled()
    limit = min(limit, 200)
    esk = decode_cursor(cursor)

    _VALID_STATUSES = {"confirmed", "checked_in", "checked_out", "cancelled", "no_show"}
    if status is not None and status not in _VALID_STATUSES:
        raise HTTPException(status_code=422, detail=f"invalid status: {status}")

    kwargs: dict = {
        "IndexName": "GSI_HOTEL_STATUS" if status else "GSI_HOTEL_ARRIVALS",
        "Limit": limit,
        "ScanIndexForward": True,
    }
    if status:
        kwargs["KeyConditionExpression"] = (
            Key("hotel_id").eq(hotel_id) & Key("status").eq(status)
        )
    else:
        kce = Key("hotel_id").eq(hotel_id)
        if checkin_from and checkin_to:
            kce = kce & Key("checkin").between(checkin_from, checkin_to)
        elif checkin_from:
            kce = kce & Key("checkin").gte(checkin_from)
        elif checkin_to:
            kce = kce & Key("checkin").lte(checkin_to)
        kwargs["KeyConditionExpression"] = kce
    if esk:
        kwargs["ExclusiveStartKey"] = esk

    resp = _T().hotel_reservations.query(**kwargs)
    items = [_reservation_out(i) for i in resp.get("Items", [])]
    return {
        "reservations": items,
        "count": len(items),
        "cursor": encode_cursor(resp.get("LastEvaluatedKey")),
    }


# ---------------------------------------------------------------------------
# HTL-019 — Reservation lifecycle state machine + history
# ---------------------------------------------------------------------------

_RESERVATION_TRANSITIONS: dict[str, set] = {
    "confirmed":   {"checked_in", "cancelled", "no_show"},
    "checked_in":  {"checked_out"},
    "checked_out": set(),   # terminal
    "cancelled":   set(),   # terminal
    "no_show":     set(),   # terminal
}

_TERMINAL_STATES = frozenset({"checked_out", "cancelled", "no_show"})


def _is_conditional_conflict(exc: Any) -> bool:
    """ConditionalCheckFailedException detector (clone of kyc_cases.py:113)."""
    return str(exc.response.get("Error", {}).get("Code", "")) == "ConditionalCheckFailedException"


def _hist_event_id(reservation_id: str, from_status: Optional[str], to_status: str, actor: str) -> str:
    raw = f"{reservation_id}|{from_status}|{to_status}|{actor}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _record_history(
    reservation_id: str,
    from_status: Optional[str],
    to_status: str,
    *,
    actor: str,
    reason: str = "",
    ts: Optional[int] = None,
) -> None:
    """Best-effort append of a HIST# child row on the reservation partition."""
    ts_val = ts or now_ts()
    event_id = _hist_event_id(reservation_id, from_status, to_status, actor)
    try:
        _T().hotel_reservations.put_item(
            Item={
                "reservation_id": reservation_id,
                "sk": f"HIST#{ts_val:020d}#{event_id}",
                "event_id": event_id,
                "from_status": from_status or "",
                "to_status": to_status,
                "actor": actor or "system",
                "reason": reason or "",
                "ts": int(ts_val),
            },
            ConditionExpression="attribute_not_exists(sk)",
        )
    except Exception:
        pass   # HIST failure never rolls back the transition


def transition_reservation(
    reservation_id: str,
    target_status: str,
    *,
    actor: str,
    reason: str = "",
    assigned_room_ids: Optional[List[str]] = None,
) -> dict:
    """Single transition entry point for the reservation lifecycle state machine."""
    from botocore.exceptions import ClientError
    from boto3.dynamodb.conditions import Attr

    _require_enabled()

    # Read current
    item = get_reservation(reservation_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Reservation not found")

    current = item["status"]
    expected_version = int(item["version"])

    # Validate edge (in Python before any DDB call)
    if target_status not in _RESERVATION_TRANSITIONS.get(current, set()):
        raise HTTPException(
            status_code=409,
            detail={
                "code": "invalid_status_transition",
                "from": current,
                "to": target_status,
            },
        )

    # Per-target side-effects (before CAS write)
    if target_status == "checked_in":
        if not assigned_room_ids:
            raise HTTPException(
                status_code=422, detail="assigned_room_ids required for check-in"
            )
        if len(assigned_room_ids) != int(item["rooms"]):
            raise HTTPException(
                status_code=422, detail="assigned_room_ids must match rooms"
            )
        # Best-effort flip each physical room to occupied
        for rid in assigned_room_ids:
            try:
                hotel_pms.set_room_status(rid, "occupied")
            except Exception:
                pass

    elif target_status == "checked_out":
        # Best-effort flip each assigned room to dirty (housekeeping)
        for rid in item.get("assigned_room_ids", []):
            try:
                hotel_pms.set_room_status(rid, "dirty")
            except Exception:
                pass
        # checkout does NOT release the hold (hold = consumed booking)

    elif target_status in ("cancelled", "no_show"):
        # Release held inventory (best-effort — release failure must NOT block cancel/no-show)
        hold_id = item.get("hold_id")
        if hold_id:
            try:
                ha.release_hold(
                    hold_id,
                    reason=target_status,
                    user_sub=actor,
                    terminal_status="released",
                )
            except Exception:
                pass

    # version-gated conditional update_item (KYC/ORD CAS pattern)
    set_parts = ["#status = :target", "version = version + :one", "updated_at = :now"]
    values: dict = {":target": target_status, ":one": 1, ":now": now_ts(), ":ver": expected_version}
    names: dict = {"#status": "status"}
    if target_status == "checked_in":
        set_parts.append("assigned_room_ids = :rooms_assigned")
        values[":rooms_assigned"] = list(assigned_room_ids or [])

    try:
        resp = _T().hotel_reservations.update_item(
            Key={"reservation_id": reservation_id, "sk": "META"},
            UpdateExpression="SET " + ", ".join(set_parts),
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=values,
            ConditionExpression="version = :ver",
            ReturnValues="ALL_NEW",
        )
    except ClientError as exc:
        if _is_conditional_conflict(exc):
            raise HTTPException(
                status_code=409, detail={"code": "concurrent_update"}
            ) from exc
        raise

    # Best-effort history row
    _record_history(
        reservation_id, current, target_status,
        actor=actor, reason=reason,
    )

    # Audit
    _audit(
        "hotel.reservation.status_changed", actor,
        reservation_id=reservation_id,
        from_status=current,
        to_status=target_status,
    )

    # Return updated header
    updated = get_reservation(reservation_id)
    if updated is None:
        # Fallback: reconstruct from update response
        return _reservation_out(resp.get("Attributes", item))
    return updated


def modify_reservation(
    reservation_id: str,
    *,
    checkin: Optional[str] = None,
    checkout: Optional[str] = None,
    room_type_id: Optional[str] = None,
    adults: Optional[int] = None,
    children: Optional[int] = None,
    rooms: Optional[int] = None,
    actor: str,
) -> dict:
    """Re-date / re-room a confirmed reservation."""
    from botocore.exceptions import ClientError

    _require_enabled()

    item = get_reservation(reservation_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Reservation not found")

    if item["status"] != "confirmed":
        raise HTTPException(
            status_code=409,
            detail={"code": "not_modifiable", "status": item["status"]},
        )

    expected_version = int(item["version"])

    # Compute effective values (fall back to current)
    new_checkin = checkin or item["checkin"]
    new_checkout = checkout or item["checkout"]
    new_room_type_id = room_type_id or item["room_type_id"]
    new_adults = adults if adults is not None else int(item["adults"])
    new_children = children if children is not None else int(item["children"])
    new_rooms = rooms if rooms is not None else int(item["rooms"])

    # Validate new span
    new_nights = _validate_span(new_checkin, new_checkout)

    # Re-check availability for the new span
    avail = ha.check_availability(
        item["hotel_id"], new_room_type_id,
        new_checkin, new_checkout, rooms_needed=new_rooms,
    )
    if not avail["available"]:
        raise HTTPException(status_code=409, detail={"code": "no_availability"})

    # Swap hold: new-before-old (never an un-held window)
    try:
        new_hold = ha.hold_rooms(
            item["hotel_id"], new_room_type_id,
            new_checkin, new_checkout,
            quantity=new_rooms, user_sub=actor,
        )
    except HTTPException as exc:
        if exc.status_code == 409:
            raise HTTPException(status_code=409, detail={"code": "no_availability"}) from exc
        raise
    new_hold_id = new_hold["hold_id"]
    old_hold_id = item.get("hold_id")

    # Re-price the new span
    price = hotel_rate_plans.compute_stay_price(
        item["hotel_id"], new_room_type_id,
        new_checkin, new_checkout, new_adults, new_children, new_rooms,
    )
    new_total_cents = int(price.total_cents)
    new_currency = (price.currency or "usd").lower()

    # version-gated CAS write
    ts = now_ts()
    try:
        _T().hotel_reservations.update_item(
            Key={"reservation_id": reservation_id, "sk": "META"},
            UpdateExpression=(
                "SET checkin = :ci, checkout = :co, nights = :n, "
                "room_type_id = :rt, adults = :ad, children = :ch, rooms = :ro, "
                "total_cents = :tc, currency = :cur, hold_id = :hid, "
                "version = version + :one, updated_at = :now"
            ),
            ExpressionAttributeValues={
                ":ci": new_checkin,
                ":co": new_checkout,
                ":n": new_nights,
                ":rt": new_room_type_id,
                ":ad": new_adults,
                ":ch": new_children,
                ":ro": new_rooms,
                ":tc": new_total_cents,
                ":cur": new_currency,
                ":hid": new_hold_id,
                ":one": 1,
                ":now": ts,
                ":ver": expected_version,
            },
            ConditionExpression="version = :ver",
        )
    except ClientError as exc:
        if _is_conditional_conflict(exc):
            # Best-effort release the NEW hold (old hold is untouched)
            try:
                ha.release_hold(
                    new_hold_id,
                    reason="modify_cas_failed",
                    user_sub=actor,
                    terminal_status="released",
                )
            except Exception:
                pass
            raise HTTPException(
                status_code=409, detail={"code": "concurrent_update"}
            ) from exc
        raise

    # Release old hold (best-effort, after CAS succeeds)
    if old_hold_id and old_hold_id != new_hold_id:
        try:
            ha.release_hold(
                old_hold_id,
                reason="modified",
                user_sub=actor,
                terminal_status="released",
            )
        except Exception:
            pass

    # Best-effort history + audit
    _record_history(
        reservation_id, "confirmed", "modified",
        actor=actor, reason="dates/room modified",
    )
    _audit(
        "hotel.reservation.modified", actor,
        reservation_id=reservation_id,
        new_checkin=new_checkin,
        new_checkout=new_checkout,
    )

    updated = get_reservation(reservation_id)
    return updated or item


def list_reservation_history(
    reservation_id: str,
    *,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> dict:
    """HIST# child rows newest-first; returns {history, count, cursor}."""
    from app.core.cursor import encode_cursor, decode_cursor
    from boto3.dynamodb.conditions import Key

    _require_enabled()
    esk = decode_cursor(cursor)
    kwargs: dict = {
        "KeyConditionExpression": (
            Key("reservation_id").eq(reservation_id) & Key("sk").begins_with("HIST#")
        ),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if esk:
        kwargs["ExclusiveStartKey"] = esk

    resp = _T().hotel_reservations.query(**kwargs)
    history = []
    for row in resp.get("Items", []):
        history.append({
            "event_id": row.get("event_id", ""),
            "from_status": row.get("from_status", ""),
            "to_status": row.get("to_status", ""),
            "actor": row.get("actor", "system"),
            "reason": row.get("reason", ""),
            "ts": int(row.get("ts", 0)),
        })

    return {
        "history": history,
        "count": len(history),
        "cursor": encode_cursor(resp.get("LastEvaluatedKey")),
    }
