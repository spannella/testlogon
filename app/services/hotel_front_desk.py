"""Hotel front-desk service (QloApps hotel vertical, HTL-022..023).

Additive + flag-gated (``HOTEL_PMS_ENABLED``, default OFF).  Every public
function calls ``_require_enabled()`` first; when the flag is off the call
raises HTTP 404 before any DynamoDB access and the platform is byte-for-byte
unchanged (mirrors ``app/services/inventory.py:50-56``).

HTL-022 — read queries: arrivals_today / departures_today / in_house /
           occupancy_snapshot (four GSI-backed read-only functions).
HTL-023 — action service: walk_in_booking / assign_room / change_room /
           room_move (four mutating orchestration functions).

SECOPS-007 parity: zero ``if S.dev_mode`` branches — the same ``T.*`` handles
and the same DynamoDB code path run in dev (boto3 intercepted by moto in-
process) and in prod (real DynamoDB).  No new table and no new GSI; only the
HTL-018 ``hotel_reservations`` (``GSI_HOTEL_ARRIVALS``, ``GSI_HOTEL_STATUS``)
and the HTL-006 ``hotel_rooms`` (``GSI_HK_STATUS``) tables are queried.
"""
from __future__ import annotations

from typing import Any, List, Optional

import boto3
from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

# ---------------------------------------------------------------------------
# Module helpers (copied from app/services/inventory.py:50-56,92-98)
# ---------------------------------------------------------------------------


def _flag_on() -> bool:
    return bool(getattr(S, "hotel_pms_enabled", False))


def _require_enabled() -> None:
    if not _flag_on():
        raise HTTPException(status_code=404, detail="Hotel PMS is not enabled")


def _audit(event: str, user_sub: str, **fields: Any) -> None:
    """Best-effort audit emit (swallows all exceptions)."""
    try:
        from app.services.alerts import audit_event
        audit_event(event, user_sub or "system", None, **fields)
    except Exception:
        pass


def _to_int(value: Any, default: int = 0) -> int:
    """Coerce a DynamoDB Decimal / None / str to int (cf. inventory.py:67-73)."""
    try:
        return default if value is None else int(value)
    except (TypeError, ValueError):
        return default


def _today() -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(now_ts(), tz=timezone.utc).strftime("%Y-%m-%d")


def _days_between(checkin: str, checkout: str) -> int:
    from datetime import date
    try:
        a = date.fromisoformat(checkin)
        b = date.fromisoformat(checkout)
        return max((b - a).days, 0)
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# HTL-022: projection helper
# ---------------------------------------------------------------------------


def _row_from_reservation(item: dict) -> dict:
    """Project a hotel_reservations META item into a FrontDeskRow-shaped dict."""
    checkin = item.get("checkin", "")
    checkout = item.get("checkout", "")
    nights_raw = _to_int(item.get("nights"))
    nights = nights_raw if nights_raw > 0 else _days_between(checkin, checkout)
    guest_sub = item.get("guest_party_id", item.get("guest_sub", ""))
    guest_name = item.get("guest_name") or guest_sub
    assigned_room_ids = list(item.get("assigned_room_ids") or [])
    return {
        "reservation_id": item.get("reservation_id", ""),
        "hotel_id": item.get("hotel_id", ""),
        "room_type_id": item.get("room_type_id", ""),
        "guest_name": guest_name,
        "guest_sub": guest_sub,
        "checkin": checkin,
        "checkout": checkout,
        "status": item.get("status", "confirmed"),
        "nights": nights,
        "occupancy_adults": _to_int(item.get("adults", item.get("occupancy_adults")), 1),
        "occupancy_children": _to_int(item.get("children", item.get("occupancy_children")), 0),
        "assigned_room_ids": assigned_room_ids,
        "total_cents": _to_int(item.get("total_cents")),
    }


# ---------------------------------------------------------------------------
# HTL-022: read queries
# ---------------------------------------------------------------------------


def arrivals_today(
    hotel_id: str,
    *,
    date: Optional[str] = None,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> dict:
    """Return confirmed reservations arriving on *date* for *hotel_id*.

    Uses GSI_HOTEL_ARRIVALS (PK=hotel_id, SK=checkin) + FilterExpression
    status==confirmed.  Returns ``{rows, count, cursor}``.
    """
    _require_enabled()
    date = date or _today()
    limit = max(1, min(int(limit), 200))
    esk = decode_cursor(cursor)

    kwargs: dict = {
        "IndexName": "GSI_HOTEL_ARRIVALS",
        "KeyConditionExpression": Key("hotel_id").eq(hotel_id) & Key("checkin").eq(date),
        "FilterExpression": Attr("status").eq("confirmed"),
        "Limit": limit,
    }
    if esk is not None:
        kwargs["ExclusiveStartKey"] = esk

    resp = T.hotel_reservations.query(**kwargs)
    rows = [_row_from_reservation(i) for i in resp.get("Items", [])]
    next_cursor = encode_cursor(resp.get("LastEvaluatedKey"))
    return {"rows": rows, "count": len(rows), "cursor": next_cursor}


def departures_today(
    hotel_id: str,
    *,
    date: Optional[str] = None,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> dict:
    """Return checked-in reservations departing on *date* for *hotel_id*.

    There is no checkout GSI in HTL-018, so this queries GSI_HOTEL_STATUS
    (status==checked_in) and filters checkout==date in-memory.  Per the CLAUDE.md
    FilterExpression-pagination note, the implementation loops LastEvaluatedKey
    until ``limit`` matches are collected or the partition is exhausted.
    """
    _require_enabled()
    date = date or _today()
    limit = max(1, min(int(limit), 200))
    esk = decode_cursor(cursor)

    rows: List[dict] = []
    last_esk: Any = None

    while True:
        kwargs: dict = {
            "IndexName": "GSI_HOTEL_STATUS",
            "KeyConditionExpression": Key("hotel_id").eq(hotel_id) & Key("status").eq("checked_in"),
            "FilterExpression": Attr("checkout").eq(date),
            "Limit": limit,
        }
        if esk is not None:
            kwargs["ExclusiveStartKey"] = esk

        resp = T.hotel_reservations.query(**kwargs)
        for item in resp.get("Items", []):
            rows.append(_row_from_reservation(item))
            if len(rows) >= limit:
                break

        last_esk = resp.get("LastEvaluatedKey")
        if len(rows) >= limit or last_esk is None:
            break
        esk = last_esk

    next_cursor = encode_cursor(last_esk if len(rows) >= limit else None)
    return {"rows": rows, "count": len(rows), "cursor": next_cursor}


def in_house(
    hotel_id: str,
    *,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> dict:
    """Return all currently checked-in reservations for *hotel_id*.

    Uses GSI_HOTEL_STATUS (PK=hotel_id, SK=status, value==checked_in).
    """
    _require_enabled()
    limit = max(1, min(int(limit), 200))
    esk = decode_cursor(cursor)

    kwargs: dict = {
        "IndexName": "GSI_HOTEL_STATUS",
        "KeyConditionExpression": Key("hotel_id").eq(hotel_id) & Key("status").eq("checked_in"),
        "Limit": limit,
    }
    if esk is not None:
        kwargs["ExclusiveStartKey"] = esk

    resp = T.hotel_reservations.query(**kwargs)
    rows = [_row_from_reservation(i) for i in resp.get("Items", [])]
    next_cursor = encode_cursor(resp.get("LastEvaluatedKey"))
    return {"rows": rows, "count": len(rows), "cursor": next_cursor}


def occupancy_snapshot(hotel_id: str, *, date: Optional[str] = None) -> dict:
    """Compute the live occupancy snapshot for *hotel_id* on *date*.

    Returns rooms_total / rooms_occupied / rooms_available / rooms_out_of_service,
    occupancy_rate (0..1, divide-by-zero-safe), and arrivals / departures /
    in_house counts.  Pure GSI aggregation — no write side-effect.
    """
    _require_enabled()
    date = date or _today()

    # ── Physical rooms total (PK query, not a table scan) ──
    room_items: List[dict] = []
    esk: Any = None
    while True:
        kwargs: dict = {
            "KeyConditionExpression": Key("hotel_id").eq(hotel_id) & Key("sk").begins_with("ROOM#"),
        }
        if esk is not None:
            kwargs["ExclusiveStartKey"] = esk
        resp = T.hotel_rooms.query(**kwargs)
        room_items.extend(resp.get("Items", []))
        esk = resp.get("LastEvaluatedKey")
        if esk is None:
            break
    rooms_total = len(room_items)

    # ── Out-of-service rooms (GSI_HK_STATUS) ──
    rooms_out_of_service = 0
    esk = None
    while True:
        kwargs = {
            "IndexName": "GSI_HK_STATUS",
            "KeyConditionExpression": Key("hotel_id").eq(hotel_id) & Key("housekeeping_status").eq("out_of_service"),
        }
        if esk is not None:
            kwargs["ExclusiveStartKey"] = esk
        resp = T.hotel_rooms.query(**kwargs)
        rooms_out_of_service += len(resp.get("Items", []))
        esk = resp.get("LastEvaluatedKey")
        if esk is None:
            break

    # ── Occupied rooms: distinct union of assigned_room_ids across checked-in ──
    assigned_set: set = set()
    in_house_count = 0
    esk = None
    while True:
        kwargs = {
            "IndexName": "GSI_HOTEL_STATUS",
            "KeyConditionExpression": Key("hotel_id").eq(hotel_id) & Key("status").eq("checked_in"),
        }
        if esk is not None:
            kwargs["ExclusiveStartKey"] = esk
        resp = T.hotel_reservations.query(**kwargs)
        for item in resp.get("Items", []):
            in_house_count += 1
            for rid in (item.get("assigned_room_ids") or []):
                assigned_set.add(rid)
        esk = resp.get("LastEvaluatedKey")
        if esk is None:
            break

    rooms_occupied = len(assigned_set)
    rooms_available = max(rooms_total - rooms_occupied - rooms_out_of_service, 0)
    occupancy_rate = rooms_occupied / max(rooms_total, 1)

    # ── Counts — single-page (limit=200) for arrivals/departures ──
    arrivals_count = arrivals_today(hotel_id, date=date, limit=200)["count"]
    departures_count = departures_today(hotel_id, date=date, limit=200)["count"]

    return {
        "hotel_id": hotel_id,
        "date": date,
        "rooms_total": rooms_total,
        "rooms_occupied": rooms_occupied,
        "rooms_available": rooms_available,
        "rooms_out_of_service": rooms_out_of_service,
        "occupancy_rate": occupancy_rate,
        "arrivals_count": arrivals_count,
        "departures_count": departures_count,
        "in_house_count": in_house_count,
    }


# ---------------------------------------------------------------------------
# HTL-023: action service — forward-dep collaborators (lazy-ref by id)
# ---------------------------------------------------------------------------
# Imported inside functions via lazy try/except so this module loads even
# when the collaborator clusters (HTL-018 / HTL-019 / HTL-007) are absent.


def _get_reservation(reservation_id: str) -> dict:
    """Read the META row for *reservation_id*; raises 404 if absent."""
    resp = T.hotel_reservations.get_item(
        Key={"reservation_id": reservation_id, "sk": "META"}
    )
    item = resp.get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Reservation not found")
    return item


def _flip_room_hk(hotel_id: str, room_id: str, housekeeping_status: str, user_sub: str) -> None:
    """Call the HTL-007 housekeeping setter (best-effort, never raises)."""
    try:
        from app.services import hotel_pms as room_inventory  # type: ignore[import]
        room_inventory.set_room_housekeeping_status(
            hotel_id, room_id,
            housekeeping_status=housekeeping_status,
            user_sub=user_sub,
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# HTL-023: walk_in_booking
# ---------------------------------------------------------------------------


def walk_in_booking(
    hotel_id: str,
    *,
    room_type_id: str,
    checkin: str,
    checkout: str,
    occupancy_adults: int,
    occupancy_children: int,
    guest_name: str,
    guest_sub: Optional[str] = None,
    assigned_room_ids: Optional[List[str]] = None,
    total_cents: Optional[int] = None,
    user_sub: str,
    **rate: Any,
) -> dict:
    """Create a walk-in reservation and immediately check it in.

    Delegates create to HTL-018 ``create_reservation`` and check-in to the
    HTL-019 ``transition_reservation`` entrypoint (per the landed spec
    reconciliation in HTL-023 §2.9).  Never re-implements availability or
    pricing logic.
    """
    _require_enabled()

    # ── Create (HTL-018 forward dep) ──
    try:
        from app.services import hotel_reservations as reservations  # type: ignore[import]
        res = reservations.create_reservation(
            hotel_id=hotel_id,
            guest_party_id=guest_sub or user_sub,
            room_type_id=room_type_id,
            checkin=checkin,
            checkout=checkout,
            adults=occupancy_adults,
            children=occupancy_children,
            rooms=1,
            user_sub=user_sub,
            **rate,
        )
    except ImportError:
        raise HTTPException(status_code=503, detail="Hotel reservations service unavailable")

    reservation_id = res["reservation_id"]

    # ── Check-in (HTL-019 forward dep — generic transition_reservation) ──
    try:
        from app.services import hotel_reservations as reservations  # type: ignore[import]
        checked = reservations.transition_reservation(
            reservation_id,
            "checked_in",
            actor=user_sub,
            assigned_room_ids=assigned_room_ids or [],
        )
    except ImportError:
        # Graceful fallback: re-read the created reservation
        checked = _get_reservation(reservation_id)

    # ── Best-effort room housekeeping flip ──
    if assigned_room_ids:
        for rid in assigned_room_ids:
            _flip_room_hk(hotel_id, rid, "dirty", user_sub)

    _audit(
        "hotel.frontdesk.walk_in",
        user_sub,
        hotel_id=hotel_id,
        reservation_id=reservation_id,
        room_type_id=room_type_id,
        assigned_room_ids=assigned_room_ids or [],
    )

    return {
        "reservation": _row_from_reservation(checked),
        "affected_rooms": [],
    }


# ---------------------------------------------------------------------------
# HTL-023: assign_room
# ---------------------------------------------------------------------------


def assign_room(
    hotel_id: str,
    reservation_id: str,
    *,
    assigned_room_ids: List[str],
    version: int,
    user_sub: str,
) -> dict:
    """Set the physical room assignment on a reservation (version-gated CAS)."""
    _require_enabled()

    _get_reservation(reservation_id)  # 404 guard

    # Version-gated assignment write
    try:
        T.hotel_reservations.update_item(
            Key={"reservation_id": reservation_id, "sk": "META"},
            UpdateExpression="SET assigned_room_ids = :rids, updated_at = :ts ADD #version :one",
            ConditionExpression="#version = :v",
            ExpressionAttributeNames={"#version": "version"},
            ExpressionAttributeValues={
                ":rids": assigned_room_ids,
                ":ts": now_ts(),
                ":one": 1,
                ":v": int(version),
            },
        )
    except ClientError as exc:
        if exc.response["Error"].get("Code") == "ConditionalCheckFailedException":
            raise HTTPException(status_code=409, detail="Reservation was modified concurrently")
        raise

    # Flip each assigned room to occupied (dirty) — best-effort
    for rid in assigned_room_ids:
        _flip_room_hk(hotel_id, rid, "dirty", user_sub)

    _audit(
        "hotel.frontdesk.assign_room",
        user_sub,
        hotel_id=hotel_id,
        reservation_id=reservation_id,
        assigned_room_ids=assigned_room_ids,
    )

    updated = _get_reservation(reservation_id)
    return {"reservation": _row_from_reservation(updated), "affected_rooms": []}


# ---------------------------------------------------------------------------
# HTL-023: change_room
# ---------------------------------------------------------------------------


def change_room(
    hotel_id: str,
    reservation_id: str,
    *,
    assigned_room_ids: List[str],
    version: int,
    user_sub: str,
) -> dict:
    """Swap the room assignment set on a reservation (symmetric-diff room flips)."""
    _require_enabled()

    item = _get_reservation(reservation_id)
    prior = set(item.get("assigned_room_ids") or [])
    new_set = set(assigned_room_ids)
    freed = prior - new_set   # rooms dropped → flip to clean
    added = new_set - prior   # rooms added  → flip to dirty

    # Version-gated assignment write
    try:
        T.hotel_reservations.update_item(
            Key={"reservation_id": reservation_id, "sk": "META"},
            UpdateExpression="SET assigned_room_ids = :rids, updated_at = :ts ADD #version :one",
            ConditionExpression="#version = :v",
            ExpressionAttributeNames={"#version": "version"},
            ExpressionAttributeValues={
                ":rids": assigned_room_ids,
                ":ts": now_ts(),
                ":one": 1,
                ":v": int(version),
            },
        )
    except ClientError as exc:
        if exc.response["Error"].get("Code") == "ConditionalCheckFailedException":
            raise HTTPException(status_code=409, detail="Reservation was modified concurrently")
        raise

    # Best-effort room flips
    for rid in freed:
        _flip_room_hk(hotel_id, rid, "clean", user_sub)
    for rid in added:
        _flip_room_hk(hotel_id, rid, "dirty", user_sub)

    _audit(
        "hotel.frontdesk.change_room",
        user_sub,
        hotel_id=hotel_id,
        reservation_id=reservation_id,
        freed=list(freed),
        added=list(added),
    )

    updated = _get_reservation(reservation_id)
    return {"reservation": _row_from_reservation(updated), "affected_rooms": []}


# ---------------------------------------------------------------------------
# HTL-023: room_move
# ---------------------------------------------------------------------------


def room_move(
    hotel_id: str,
    reservation_id: str,
    *,
    from_room_id: str,
    to_room_id: str,
    version: int,
    user_sub: str,
) -> dict:
    """Relocate a single checked-in guest from one room to another."""
    _require_enabled()

    item = _get_reservation(reservation_id)

    # Validate reservation is checked-in
    if item.get("status") != "checked_in":
        raise HTTPException(status_code=409, detail="Reservation is not checked in")

    current_rooms = list(item.get("assigned_room_ids") or [])
    if from_room_id not in current_rooms:
        raise HTTPException(status_code=404, detail="from_room_id is not assigned to this reservation")

    # Compute new assignment (swap exactly one id)
    new_rooms = [to_room_id if r == from_room_id else r for r in current_rooms]

    # Version-gated write
    try:
        T.hotel_reservations.update_item(
            Key={"reservation_id": reservation_id, "sk": "META"},
            UpdateExpression="SET assigned_room_ids = :rids, updated_at = :ts ADD #version :one",
            ConditionExpression="#version = :v",
            ExpressionAttributeNames={"#version": "version"},
            ExpressionAttributeValues={
                ":rids": new_rooms,
                ":ts": now_ts(),
                ":one": 1,
                ":v": int(version),
            },
        )
    except ClientError as exc:
        if exc.response["Error"].get("Code") == "ConditionalCheckFailedException":
            raise HTTPException(status_code=409, detail="Reservation was modified concurrently")
        raise

    # Best-effort room flips
    _flip_room_hk(hotel_id, from_room_id, "clean", user_sub)
    _flip_room_hk(hotel_id, to_room_id, "dirty", user_sub)

    _audit(
        "hotel.frontdesk.room_move",
        user_sub,
        hotel_id=hotel_id,
        reservation_id=reservation_id,
        from_room_id=from_room_id,
        to_room_id=to_room_id,
    )

    updated = _get_reservation(reservation_id)
    return {"reservation": _row_from_reservation(updated), "affected_rooms": []}
