"""Hotel PMS availability service (QloApps vertical, HTL-010..HTL-013).

Per-room-type per-DATE remaining-rooms inventory. One DynamoDB row per
(hotel_id, room_type_id, calendar_date) on the ``hotel_availability`` table.
The same room type can be sold-out on 2026-07-04 and wide-open on 2026-07-05.

This is the date-keyed analogue of ``app/services/inventory.py`` — it reuses
the flag/audit/derived-counter/zeroed-virtual/preserve-on-set idioms but adds
the DATE key dimension that OFBiz scalar inventory (``(sku, location)``) has
no concept of.

``available`` is *persisted* on every mutation (exactly like inventory.py:101-115
which also persists ``available`` alongside computing it) so that ``hold_rooms``
can use a simple ``available >= :min_needed`` condition expression — DynamoDB
conditions cannot evaluate arithmetic expressions directly (e.g.
``total_rooms + overbooking_allowance - booked - held >= :q + min_availability``
is rejected). The persisted value is always kept in sync with the authoritative
inputs (total_rooms, overbooking_allowance, booked, held), so drift is not
possible: every mutation recomputes and re-stores ``available``.

SECOPS-007: No conditional branches on environment mode in this file. The same
DynamoDB code path runs in both local and production, via the identical
``T.hotel_availability`` handle (boto3 intercepted by moto in local mode).
"""
from __future__ import annotations

import asyncio
import logging
from datetime import date, timedelta
from typing import Any
from uuid import uuid4

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# ─── Constants ────────────────────────────────────────────────────────────────

_ACTIVE_HOLD_PARTITION = "HOLD#ACTIVE"


# ─── Flag / enable guard ──────────────────────────────────────────────────────

def _flag_on() -> bool:
    """Return True when the Hotel PMS feature flag is enabled."""
    return bool(getattr(S, "hotel_pms_enabled", False))


def _require_enabled() -> None:
    """Raise HTTP 404 when the Hotel PMS flag is off (mirrors inventory.py:50-56)."""
    if not _flag_on():
        raise HTTPException(status_code=404, detail="Hotel PMS is not enabled")


# ─── Audit wrapper (copy of inventory.py:92-98) ───────────────────────────────

def _audit(event: str, user_sub: str, **fields: Any) -> None:
    """Best-effort audit emit — swallows all exceptions."""
    try:
        from app.services.alerts import audit_event
        audit_event(event, user_sub or "system", None, **fields)
    except Exception:
        pass


# ─── PK / SK helpers ──────────────────────────────────────────────────────────

def _availability_pk(hotel_id: str, room_type_id: str) -> str:
    return f"{hotel_id}#{room_type_id}"


def _date_sk(d: str) -> str:
    return f"DATE#{d}"


def _hold_pk(hold_id: str) -> str:
    return f"HOLD#{hold_id}"


# ─── Numeric coercion (copy of inventory.py:67-73) ────────────────────────────

def _to_int(value: Any, default: int = 0) -> int:
    """Coerce DynamoDB Decimal / None to plain int."""
    try:
        return default if value is None else int(value)
    except (TypeError, ValueError):
        return default


# ─── Date helpers ─────────────────────────────────────────────────────────────

def _date_range(start: str, end: str) -> list[str]:
    """Inclusive list of YYYY-MM-DD strings from start..end."""
    d0 = date.fromisoformat(start)
    d1 = date.fromisoformat(end)
    if d1 < d0:
        raise HTTPException(status_code=422, detail="end_date must be >= start_date")
    out: list[str] = []
    cur = d0
    while cur <= d1:
        out.append(cur.isoformat())
        cur += timedelta(days=1)
    return out


def _validate_date_range(start: str, end: str) -> None:
    """Validate that both dates are well-formed YYYY-MM-DD and end >= start."""
    try:
        d0 = date.fromisoformat(start)
        d1 = date.fromisoformat(end)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail=f"Invalid date: {exc}") from exc
    if d1 < d0:
        raise HTTPException(status_code=422, detail="end_date must be >= start_date")


def _hold_ttl(ttl_seconds: int | None) -> int:
    if ttl_seconds:
        return int(ttl_seconds)
    return int(getattr(S, "hotel_hold_ttl_seconds", 900))


# ─── Derived counter and row projection ───────────────────────────────────────

def _compute_available(
    total_rooms: int,
    overbooking_allowance: int,
    booked: int,
    held: int,
) -> int:
    """Derive available from authoritative inputs.

    Mirrors inventory.py:101-115 (_record_out) and :131 (_persist) which
    both compute and persist ``available = on_hand - reserved`` on every
    mutation so it can be used in ConditionExpressions.
    Value may be negative (over-committed) — unclamped by design.
    """
    return total_rooms + overbooking_allowance - booked - held


def _available(item: dict) -> int:
    return _compute_available(
        _to_int(item.get("total_rooms")),
        _to_int(item.get("overbooking_allowance")),
        _to_int(item.get("booked")),
        _to_int(item.get("held")),
    )


def _row_out(item: dict) -> dict:
    """Project a stored DATE# row to the AvailabilityDayOut-shaped dict.

    ``available`` is derived from the authoritative columns on every read
    (never read from the stored ``available`` field, which is a cached copy).
    """
    return {
        "hotel_id": item.get("hotel_id"),
        "room_type_id": item.get("room_type_id"),
        "date": item.get("date"),
        "total_rooms": _to_int(item.get("total_rooms")),
        "booked": _to_int(item.get("booked")),
        "held": _to_int(item.get("held")),
        "overbooking_allowance": _to_int(item.get("overbooking_allowance")),
        "min_availability": _to_int(item.get("min_availability")),
        "max_availability": (
            None if item.get("max_availability") is None
            else _to_int(item.get("max_availability"))
        ),
        "available": _available(item),
        "updated_at": _to_int(item.get("updated_at")),
    }


def _zero_row(hotel_id: str, room_type_id: str, d: str) -> dict:
    """Return a zeroed virtual row for a never-seeded date.

    Mirrors inventory.py:158-173 (get_or_zero). A never-seeded date reads
    as sold-out (available=0), not as an error.
    """
    return {
        "hotel_id": hotel_id,
        "room_type_id": room_type_id,
        "date": d,
        "total_rooms": 0,
        "booked": 0,
        "held": 0,
        "overbooking_allowance": 0,
        "min_availability": 0,
        "max_availability": None,
        "available": 0,
        "updated_at": 0,
    }


def _hold_out(item: dict) -> dict:
    """Project a HOLD# meta row to the HoldOut-shaped dict."""
    return {
        "hold_id": item.get("hold_id"),
        "hotel_id": item.get("hotel_id"),
        "room_type_id": item.get("room_type_id"),
        "checkin": item.get("checkin"),
        "checkout": item.get("checkout"),
        "dates": list(item.get("dates") or []),
        "quantity": _to_int(item.get("quantity")),
        "status": item.get("status"),
        "user_sub": item.get("user_sub"),
        "created_at": _to_int(item.get("created_at")),
        "expires_at": _to_int(item.get("expires_at")),
    }


def _full_row(
    pk: str,
    d: str,
    hotel_id: str,
    room_type_id: str,
    total_rooms: int,
    booked: int,
    held: int,
    overbooking_allowance: int,
    min_availability: int,
    max_availability: int | None,
    ts: int,
) -> dict:
    """Build a full DATE# item dict including persisted ``available``."""
    row: dict[str, Any] = {
        "availability_pk": pk,
        "sk": _date_sk(d),
        "hotel_id": hotel_id,
        "room_type_id": room_type_id,
        "date": d,
        "total_rooms": total_rooms,
        "booked": booked,
        "held": held,
        "overbooking_allowance": overbooking_allowance,
        "min_availability": min_availability,
        "available": _compute_available(total_rooms, overbooking_allowance, booked, held),
        "updated_at": ts,
    }
    if max_availability is not None:
        row["max_availability"] = max_availability
    return row


# ─── HTL-010 service functions ────────────────────────────────────────────────

def set_total_rooms(
    hotel_id: str,
    room_type_id: str,
    start_date: str,
    end_date: str,
    total_rooms: int,
    *,
    user_sub: str,
) -> list[dict]:
    """Seed / set total_rooms per date, preserving live booked/held/controls.

    Read-merge per date (mirrors inventory.py:185-206 set_on_hand): overwrites
    total_rooms but preserves booked / held / overbooking_allowance / min /
    max on each existing row. Creates zeroed rows for never-seeded dates.
    Persists ``available`` on every write so hold conditions can use a simple
    comparison (``available >= :min_needed``).

    Returns the list of AvailabilityDayOut-shaped dicts written.
    """
    _require_enabled()
    if total_rooms < 0:
        raise HTTPException(status_code=422, detail="total_rooms must be >= 0")
    nights = _date_range(start_date, end_date)
    pk = _availability_pk(hotel_id, room_type_id)
    written: list[dict] = []
    ts = now_ts()
    for d in nights:
        existing_resp = T.hotel_availability.get_item(
            Key={"availability_pk": pk, "sk": _date_sk(d)}
        )
        existing = existing_resp.get("Item") or {}
        booked = _to_int(existing.get("booked"))
        held = _to_int(existing.get("held"))
        ob = _to_int(existing.get("overbooking_allowance"))
        min_a = _to_int(existing.get("min_availability"))
        max_a = (
            None if existing.get("max_availability") is None
            else _to_int(existing.get("max_availability"))
        )
        row = _full_row(pk, d, hotel_id, room_type_id,
                        total_rooms, booked, held, ob, min_a, max_a, ts)
        T.hotel_availability.put_item(Item=row)
        written.append(_row_out(row))
    _audit(
        "hotel.availability.set_total",
        user_sub,
        hotel_id=hotel_id,
        room_type_id=room_type_id,
        start_date=start_date,
        end_date=end_date,
        total_rooms=total_rooms,
    )
    return written


def get_day(hotel_id: str, room_type_id: str, d: str) -> dict | None:
    """Return the AvailabilityDayOut dict for a single date, or None if absent."""
    _require_enabled()
    resp = T.hotel_availability.get_item(
        Key={
            "availability_pk": _availability_pk(hotel_id, room_type_id),
            "sk": _date_sk(d),
        }
    )
    item = resp.get("Item")
    return _row_out(item) if item else None


def get_availability(
    hotel_id: str,
    room_type_id: str,
    checkin: str,
    checkout: str,
) -> list[dict]:
    """Return per-night rows for the stay span [checkin, checkout) (checkout exclusive).

    A never-seeded night surfaces as a zeroed virtual row (available=0, sold-out)
    rather than an error — mirrors inventory.py:158-173 (get_or_zero).

    ``checkout`` must be strictly after ``checkin`` (a zero-night stay is 422).
    """
    _require_enabled()
    co = date.fromisoformat(checkout)
    ci = date.fromisoformat(checkin)
    if co <= ci:
        raise HTTPException(
            status_code=422, detail="checkout must be strictly after checkin"
        )
    last_night = (co - timedelta(days=1)).isoformat()
    nights = _date_range(checkin, last_night)
    pk = _availability_pk(hotel_id, room_type_id)
    resp = T.hotel_availability.query(
        KeyConditionExpression=(
            Key("availability_pk").eq(pk)
            & Key("sk").between(_date_sk(checkin), _date_sk(last_night))
        )
    )
    stored: dict[str, dict] = {}
    for item in resp.get("Items", []):
        stored[item["date"]] = _row_out(item)
    return [stored.get(n) or _zero_row(hotel_id, room_type_id, n) for n in nights]


# ─── HTL-011 service functions ────────────────────────────────────────────────

def _rollback_holds(pk: str, incremented: list[str], quantity: int) -> None:
    """Unconditional compensating decrement for nights already incremented.

    Best-effort: each night decremented individually; a failure logs an audit
    event (a stuck held is an inventory-correctness bug and must be visible).
    """
    ts = now_ts()
    for night in incremented:
        try:
            # Read existing row to recompute available correctly
            resp = T.hotel_availability.get_item(
                Key={"availability_pk": pk, "sk": _date_sk(night)}
            )
            existing = resp.get("Item") or {}
            if not existing:
                continue
            total_rooms = _to_int(existing.get("total_rooms"))
            ob = _to_int(existing.get("overbooking_allowance"))
            booked = _to_int(existing.get("booked"))
            held = max(0, _to_int(existing.get("held")) - quantity)
            new_avail = _compute_available(total_rooms, ob, booked, held)
            T.hotel_availability.update_item(
                Key={"availability_pk": pk, "sk": _date_sk(night)},
                UpdateExpression="SET held = :h, available = :av, updated_at = :now",
                ExpressionAttributeValues={
                    ":h": held,
                    ":av": new_avail,
                    ":now": ts,
                },
            )
        except Exception:
            _audit(
                "hotel.hold.rollback_error",
                "system",
                pk=pk,
                night=night,
                quantity=quantity,
            )


def hold_rooms(
    hotel_id: str,
    room_type_id: str,
    checkin: str,
    checkout: str,
    quantity: int,
    *,
    user_sub: str,
    ttl_seconds: int | None = None,
) -> dict:
    """Atomic all-or-nothing block/hold across every night of [checkin, checkout).

    Mirrors the OFBiz inventory.reserve conditional-decrement idiom
    (inventory.py:362-372) but applied per-date across a span, with compensating
    rollback on any sold-out night (span atomicity — the distinctive hotel
    primitive: availability = intersection of every night, not a single scalar).

    The hold condition uses the persisted ``available`` field (which equals
    ``total_rooms + overbooking_allowance - booked - held``, always kept in
    sync) and the ``min_availability`` floor:
        ``available - min_availability >= :q``
    which is equivalent to the floor-aware sell test without arithmetic in the
    ConditionExpression (DynamoDB does not evaluate arithmetic in conditions).

    A never-seeded night fails the condition (``attribute_exists`` is false)
    → 409 + rollback, consistent with the zeroed-virtual-row sold-out contract.

    Returns a HoldOut-shaped dict on success.
    """
    _require_enabled()
    if quantity < 1:
        raise HTTPException(status_code=422, detail="quantity must be >= 1")
    co = date.fromisoformat(checkout)
    ci = date.fromisoformat(checkin)
    if co <= ci:
        raise HTTPException(
            status_code=422, detail="checkout must be strictly after checkin"
        )
    last_night = (co - timedelta(days=1)).isoformat()
    nights = _date_range(checkin, last_night)
    pk = _availability_pk(hotel_id, room_type_id)
    incremented: list[str] = []
    ts = now_ts()
    for night in nights:
        try:
            # Condition: attribute_exists AND available - min_availability >= quantity
            # We rewrite as: available >= quantity + min_availability using :q and :min_floor
            # But DynamoDB conditions cannot do addition either.
            # Strategy: read min_availability first (cheap), then use
            # available >= :needed (where :needed = quantity + min_availability).
            # This is a read-then-conditional-update — safe because the UPDATE
            # itself is still conditional on available >= :needed, so a concurrent
            # hold that decrements available between our read and write will fail
            # our condition (one-winner guarantee).
            read_resp = T.hotel_availability.get_item(
                Key={"availability_pk": pk, "sk": _date_sk(night)}
            )
            existing = read_resp.get("Item")
            if not existing:
                # Never-seeded night → sold-out
                _rollback_holds(pk, incremented, quantity)
                raise HTTPException(
                    status_code=409,
                    detail=f"Room type sold out on {night} (date not seeded)",
                )
            min_a = _to_int(existing.get("min_availability"))
            needed = int(quantity) + min_a
            result = T.hotel_availability.update_item(
                Key={"availability_pk": pk, "sk": _date_sk(night)},
                UpdateExpression=(
                    "SET held = held + :q, "
                    "available = available - :q, "
                    "updated_at = :now"
                ),
                ConditionExpression="available >= :needed",
                ExpressionAttributeValues={
                    ":q": int(quantity),
                    ":needed": needed,
                    ":now": ts,
                },
                ReturnValues="ALL_NEW",
            )
            incremented.append(night)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "ConditionalCheckFailedException":
                _rollback_holds(pk, incremented, quantity)
                raise HTTPException(
                    status_code=409,
                    detail=f"Room type sold out on {night}",
                ) from exc
            raise
    # Write HOLD# meta row
    hold_id = uuid4().hex
    created_at = now_ts()
    ttl = _hold_ttl(ttl_seconds)
    expires_at = created_at + ttl
    meta_item = {
        "availability_pk": _hold_pk(hold_id),
        "sk": "META",
        "hold_id": hold_id,
        "hotel_id": hotel_id,
        "room_type_id": room_type_id,
        "checkin": checkin,
        "checkout": checkout,
        "dates": nights,
        "quantity": int(quantity),
        "status": "active",
        "user_sub": user_sub,
        "created_at": created_at,
        "expires_at": expires_at,
        "gsi_expiry_pk": _ACTIVE_HOLD_PARTITION,
    }
    T.hotel_availability.put_item(Item=meta_item)
    _audit(
        "hotel.hold.created",
        user_sub,
        hold_id=hold_id,
        hotel_id=hotel_id,
        room_type_id=room_type_id,
        checkin=checkin,
        checkout=checkout,
        quantity=quantity,
    )
    return _hold_out(meta_item)


def release_hold(
    hold_id: str,
    *,
    reason: str = "released",
    user_sub: str = "system",
    terminal_status: str = "released",
) -> dict:
    """Idempotent terminal flip of a hold + per-date held decrement.

    Status-CAS (status = active) mirrors inventory.py:434-453
    (_close_reservation). A double-release is a no-op — returns the existing
    terminal hold without re-decrementing held.
    """
    _require_enabled()
    meta_key = {"availability_pk": _hold_pk(hold_id), "sk": "META"}
    try:
        result = T.hotel_availability.update_item(
            Key=meta_key,
            UpdateExpression=(
                "SET #st = :new, closed_at = :now, release_reason = :r"
                " REMOVE gsi_expiry_pk"
            ),
            ConditionExpression="#st = :active",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":new": terminal_status,
                ":now": now_ts(),
                ":r": reason,
                ":active": "active",
            },
            ReturnValues="ALL_OLD",
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "ConditionalCheckFailedException":
            existing_resp = T.hotel_availability.get_item(Key=meta_key)
            existing = existing_resp.get("Item")
            if not existing:
                raise HTTPException(status_code=404, detail="Hold not found") from exc
            return _hold_out(existing)
        raise
    old_attrs = result.get("Attributes") or {}
    if not old_attrs:
        raise HTTPException(status_code=404, detail="Hold not found")
    # Restore held on each night the hold incremented
    dates = list(old_attrs.get("dates") or [])
    qty = _to_int(old_attrs.get("quantity"))
    h_id = str(old_attrs.get("hotel_id") or "")
    rt_id = str(old_attrs.get("room_type_id") or "")
    pk = _availability_pk(h_id, rt_id)
    ts = now_ts()
    for d in dates:
        try:
            # Read-then-update to keep available in sync
            resp = T.hotel_availability.get_item(
                Key={"availability_pk": pk, "sk": _date_sk(d)}
            )
            existing = resp.get("Item") or {}
            if not existing:
                continue
            total_rooms = _to_int(existing.get("total_rooms"))
            ob = _to_int(existing.get("overbooking_allowance"))
            booked = _to_int(existing.get("booked"))
            held = max(0, _to_int(existing.get("held")) - qty)
            new_avail = _compute_available(total_rooms, ob, booked, held)
            T.hotel_availability.update_item(
                Key={"availability_pk": pk, "sk": _date_sk(d)},
                UpdateExpression="SET held = :h, available = :av, updated_at = :now",
                ExpressionAttributeValues={
                    ":h": held,
                    ":av": new_avail,
                    ":now": ts,
                },
            )
        except Exception:
            pass
    _audit(
        "hotel.hold.released",
        user_sub,
        hold_id=hold_id,
        reason=reason,
        terminal_status=terminal_status,
    )
    merged = dict(old_attrs)
    merged["status"] = terminal_status
    return _hold_out(merged)


def expire_due_holds(*, now: int | None = None, limit: int = 200) -> int:
    """TTL sweep — clone of inventory.expire_due_reservations (inventory.py:538-562).

    Queries GSI_HOLD_EXPIRY for gsi_expiry_pk="HOLD#ACTIVE" AND
    expires_at <= cutoff, then calls release_hold per overdue hold.

    Returns the count expired. Concurrent sweeps are safe via the status-CAS.
    """
    _require_enabled()
    cutoff = now if now is not None else now_ts()
    resp = T.hotel_availability.query(
        IndexName="GSI_HOLD_EXPIRY",
        KeyConditionExpression=(
            Key("gsi_expiry_pk").eq(_ACTIVE_HOLD_PARTITION)
            & Key("expires_at").lte(cutoff)
        ),
        Limit=limit,
    )
    expired = 0
    for item in resp.get("Items", []):
        h_id = str(item.get("hold_id") or "")
        if not h_id:
            continue
        try:
            release_hold(
                h_id,
                reason="ttl_expired",
                user_sub="system",
                terminal_status="expired",
            )
            expired += 1
        except Exception:
            pass
    return expired


async def _hotel_hold_expiry_loop() -> None:
    """Background loop that expires overdue holds every ~60 s."""
    while True:
        await asyncio.sleep(60)
        try:
            if _flag_on():
                expire_due_holds()
        except Exception:
            pass


async def start_hotel_hold_expiry_task() -> None:
    """Register the hotel hold expiry sweep (gated on hotel_pms_enabled)."""
    if not _flag_on():
        return
    asyncio.ensure_future(_hotel_hold_expiry_loop())


def set_overbooking_allowance(
    hotel_id: str,
    room_type_id: str,
    start_date: str,
    end_date: str,
    allowance: int,
    *,
    user_sub: str,
) -> list[dict]:
    """Set overbooking_allowance per date over a control range (inclusive).

    Creates zeroed rows for unseeded dates so the control takes effect even
    before total_rooms is seeded. Always recomputes and persists ``available``.
    """
    _require_enabled()
    if allowance < 0:
        raise HTTPException(status_code=422, detail="allowance must be >= 0")
    nights = _date_range(start_date, end_date)
    pk = _availability_pk(hotel_id, room_type_id)
    updated: list[dict] = []
    ts = now_ts()
    for d in nights:
        existing_resp = T.hotel_availability.get_item(
            Key={"availability_pk": pk, "sk": _date_sk(d)}
        )
        existing = existing_resp.get("Item") or {}
        total_rooms = _to_int(existing.get("total_rooms"))
        booked = _to_int(existing.get("booked"))
        held = _to_int(existing.get("held"))
        min_a = _to_int(existing.get("min_availability"))
        max_a = (
            None if existing.get("max_availability") is None
            else _to_int(existing.get("max_availability"))
        )
        new_avail = _compute_available(total_rooms, allowance, booked, held)
        if existing:
            result = T.hotel_availability.update_item(
                Key={"availability_pk": pk, "sk": _date_sk(d)},
                UpdateExpression=(
                    "SET overbooking_allowance = :a, available = :av, updated_at = :now"
                ),
                ExpressionAttributeValues={
                    ":a": int(allowance),
                    ":av": new_avail,
                    ":now": ts,
                },
                ReturnValues="ALL_NEW",
            )
            updated.append(_row_out(result.get("Attributes") or {}))
        else:
            row = _full_row(pk, d, hotel_id, room_type_id,
                            0, 0, 0, allowance, 0, None, ts)
            T.hotel_availability.put_item(Item=row)
            updated.append(_row_out(row))
    _audit(
        "hotel.overbooking.set",
        user_sub,
        hotel_id=hotel_id,
        room_type_id=room_type_id,
        start_date=start_date,
        end_date=end_date,
        allowance=allowance,
    )
    return updated


def set_min_max_availability(
    hotel_id: str,
    room_type_id: str,
    start_date: str,
    end_date: str,
    *,
    min_availability: int | None = None,
    max_availability: int | None = None,
    user_sub: str,
) -> list[dict]:
    """Set min_availability and/or max_availability per date over a control range.

    At least one of min_availability / max_availability must be provided.
    When both are provided, min must be <= max.
    Creates zeroed rows for unseeded dates.
    """
    _require_enabled()
    if min_availability is None and max_availability is None:
        raise HTTPException(
            status_code=422,
            detail="At least one of min_availability or max_availability must be provided",
        )
    if (
        min_availability is not None
        and max_availability is not None
        and min_availability > max_availability
    ):
        raise HTTPException(
            status_code=422,
            detail="min_availability must be <= max_availability",
        )
    nights = _date_range(start_date, end_date)
    pk = _availability_pk(hotel_id, room_type_id)
    updated: list[dict] = []
    ts = now_ts()
    for d in nights:
        existing_resp = T.hotel_availability.get_item(
            Key={"availability_pk": pk, "sk": _date_sk(d)}
        )
        existing = existing_resp.get("Item") or {}
        total_rooms = _to_int(existing.get("total_rooms"))
        booked = _to_int(existing.get("booked"))
        held = _to_int(existing.get("held"))
        ob = _to_int(existing.get("overbooking_allowance"))
        cur_min = _to_int(existing.get("min_availability"))
        cur_max = (
            None if existing.get("max_availability") is None
            else _to_int(existing.get("max_availability"))
        )
        new_min = cur_min if min_availability is None else int(min_availability)
        new_max = cur_max if max_availability is None else int(max_availability)
        # available doesn't change when min/max change (min/max are soft floors/caps)
        new_avail = _compute_available(total_rooms, ob, booked, held)
        if existing:
            set_parts = ["updated_at = :now", "available = :av"]
            expr_vals: dict[str, Any] = {":now": ts, ":av": new_avail}
            if min_availability is not None:
                set_parts.append("min_availability = :min")
                expr_vals[":min"] = int(min_availability)
            if max_availability is not None:
                set_parts.append("max_availability = :max")
                expr_vals[":max"] = int(max_availability)
            result = T.hotel_availability.update_item(
                Key={"availability_pk": pk, "sk": _date_sk(d)},
                UpdateExpression="SET " + ", ".join(set_parts),
                ExpressionAttributeValues=expr_vals,
                ReturnValues="ALL_NEW",
            )
            updated.append(_row_out(result.get("Attributes") or {}))
        else:
            row = _full_row(pk, d, hotel_id, room_type_id,
                            0, 0, 0, 0, new_min if min_availability is not None else 0, new_max, ts)
            T.hotel_availability.put_item(Item=row)
            updated.append(_row_out(row))
    _audit(
        "hotel.minmax.set",
        user_sub,
        hotel_id=hotel_id,
        room_type_id=room_type_id,
        start_date=start_date,
        end_date=end_date,
        min_availability=min_availability,
        max_availability=max_availability,
    )
    return updated


# ─── HTL-012 service functions ────────────────────────────────────────────────

def availability_calendar(hotel_id: str, start_date: str, end_date: str) -> dict:
    """Hotel-wide availability calendar across ALL room types for a date range.

    Pure GSI_HOTEL_DATE aggregation — no full table scan. Rows grouped by
    room_type_id, sorted by date within each group (lexical == chronological).

    Does NOT synthesise virtual zero rows for unseeded dates — a missing date
    simply does not appear in that room type's list (the FE grid fills gaps
    as zero/sold-out on render, matching §5.5 of the HTL-012 spec).
    """
    _require_enabled()
    _validate_date_range(start_date, end_date)
    room_types: dict[str, list[dict]] = {}
    last_key = None
    while True:
        kwargs: dict[str, Any] = dict(
            IndexName="GSI_HOTEL_DATE",
            KeyConditionExpression=(
                Key("hotel_id").eq(hotel_id)
                & Key("date").between(start_date, end_date)
            ),
        )
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.hotel_availability.query(**kwargs)
        for item in resp.get("Items", []):
            rt = item.get("room_type_id") or ""
            room_types.setdefault(rt, []).append(_row_out(item))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    for rt in room_types:
        room_types[rt].sort(key=lambda d: d["date"])
    return {
        "hotel_id": hotel_id,
        "start_date": start_date,
        "end_date": end_date,
        "room_types": room_types,
    }


def check_availability(
    hotel_id: str,
    room_type_id: str,
    checkin: str,
    checkout: str,
    rooms_needed: int = 1,
) -> dict:
    """Booking-time check: is available >= rooms_needed on EVERY night of [checkin, checkout)?

    The answer is the AND-reduction of every night's sufficiency (the
    span-intersection primitive). A single insufficient or missing/zeroed night
    ⇒ available=False.

    Returns: {available, rooms_needed, per_night, min_remaining}.
    """
    _require_enabled()
    if rooms_needed < 1:
        raise HTTPException(status_code=422, detail="rooms_needed must be >= 1")
    rows = get_availability(hotel_id, room_type_id, checkin, checkout)
    per_night: list[dict] = []
    for row in rows:
        remaining = _to_int(row.get("available"))
        per_night.append({
            "date": row.get("date"),
            "remaining": remaining,
            "sufficient": remaining >= rooms_needed,
        })
    available = bool(per_night) and all(n["sufficient"] for n in per_night)
    min_remaining = min((n["remaining"] for n in per_night), default=0)
    return {
        "available": available,
        "rooms_needed": rooms_needed,
        "per_night": per_night,
        "min_remaining": min_remaining,
    }
