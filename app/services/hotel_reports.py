"""hotel_reports.py — HTL-035 Hotel KPI report service.

Pure read-only aggregation over HTL-018 reservation GSIs + HTL-010 availability GSI.
No new DynamoDB table, no new GSI, no new write.
No if-S.dev_mode branch (SECOPS-007 parity).
"""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from typing import Any

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

# ---------------------------------------------------------------------------
# Flag / audit / coercion helpers (copied verbatim from inventory.py)
# ---------------------------------------------------------------------------


def _flag_on() -> bool:
    return bool(getattr(S, "hotel_pms_enabled", False))


def _require_enabled() -> None:
    if not _flag_on():
        raise HTTPException(status_code=404, detail="Hotel PMS is not enabled")


def _audit(event: str, user_sub: str, **fields: Any) -> None:
    try:
        from app.services.alerts import audit_event  # noqa: F401
        audit_event(event, user_sub or "system", None, **fields)
    except Exception:
        pass


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return default if value is None else int(value)
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# Date helpers
# ---------------------------------------------------------------------------


def _date_str(epoch: int) -> str:
    """Convert epoch seconds to YYYY-MM-DD (midnight UTC)."""
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d")


def _date_range(start: str, end_exclusive: str) -> list[str]:
    """Half-open [start, end_exclusive) list of YYYY-MM-DD strings (billable nights)."""
    d0 = date.fromisoformat(start)
    d1 = date.fromisoformat(end_exclusive)
    out: list[str] = []
    cur = d0
    while cur < d1:
        out.append(cur.isoformat())
        cur += timedelta(days=1)
    return out


# ---------------------------------------------------------------------------
# GSI pagination helper
# ---------------------------------------------------------------------------


def _query_all(table: Any, index_name: str, key_cond: Any) -> list[dict]:
    """Query a GSI, looping on LastEvaluatedKey until exhausted."""
    items: list[dict] = []
    lek = None
    while True:
        kwargs: dict = {"IndexName": index_name, "KeyConditionExpression": key_cond}
        if lek:
            kwargs["ExclusiveStartKey"] = lek
        resp = table.query(**kwargs)
        items.extend(resp.get("Items", []))
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            return items


# ---------------------------------------------------------------------------
# Main KPI computation
# ---------------------------------------------------------------------------


def compute_hotel_kpis(hotel_id: str, *, from_ts: int, to_ts: int) -> dict:
    """Pure aggregation over the HTL-018 reservation GSI + HTL-010 availability GSI.

    _require_enabled() raises 404 when HOTEL_PMS_ENABLED off.
    Raises 422 on inverted or oversized range.
    No scan, no new table, no DDB write.
    """
    _require_enabled()

    # --- Validate range ---
    if to_ts <= from_ts:
        raise HTTPException(status_code=422, detail="to must be after from")
    range_days = (to_ts - from_ts) // 86400
    max_days = _to_int(getattr(S, "hotel_kpi_max_range_days", 366), 366)
    if range_days > max_days:
        raise HTTPException(status_code=422, detail="range too large")

    from_date = _date_str(from_ts)
    to_date_excl = _date_str(to_ts)
    nights = _date_range(from_date, to_date_excl)
    if not nights:
        return _empty_kpis(hotel_id, from_ts, to_ts)

    nights_set = set(nights)
    last_night = nights[-1]

    # --- rooms_available from GSI_HOTEL_DATE ---
    rooms_available = 0
    avail_rows = _query_all(
        T.hotel_availability,
        "GSI_HOTEL_DATE",
        Key("hotel_id").eq(hotel_id) & Key("date").between(from_date, last_night),
    )
    for row in avail_rows:
        if row.get("date") in nights_set:
            rooms_available += _to_int(row.get("total_rooms"))

    # --- fetch in-range reservations from GSI_HOTEL_ARRIVALS ---
    max_stay = _to_int(getattr(S, "hotel_kpi_max_stay_nights", 370), 370)
    from_ext_ts = from_ts - max_stay * 86400
    from_ext = _date_str(from_ext_ts)

    res_rows = _query_all(
        T.hotel_reservations,
        "GSI_HOTEL_ARRIVALS",
        Key("hotel_id").eq(hotel_id) & Key("checkin").between(from_ext, to_date_excl),
    )

    # --- per-reservation aggregation ---
    rooms_sold = 0
    room_revenue_cents = 0
    arrivals = 0
    departures = 0
    currencies: list[str] = []

    for r in res_rows:
        status = str(r.get("status", ""))
        checkin = str(r.get("checkin", ""))
        checkout = str(r.get("checkout", ""))

        # arrivals / departures: exclude cancelled (include no_show per spec §5.4)
        if status not in {"cancelled", "no_show"}:
            if from_date <= checkin < to_date_excl:
                arrivals += 1
            if from_date <= checkout < to_date_excl:
                departures += 1

        # room-night sale: exclude cancelled AND no_show
        if status in {"cancelled", "no_show"}:
            continue

        # in-range night intersection
        if not checkin or not checkout:
            continue
        try:
            r_nights = _date_range(checkin, checkout)
        except (ValueError, TypeError):
            continue

        in_range = [d for d in r_nights if from_date <= d < to_date_excl]
        n_in = len(in_range)
        if n_in == 0:
            continue

        rooms = _to_int(r.get("rooms"), 1) or 1
        rooms_sold += n_in * rooms

        # revenue pro-rate
        total_nights = _to_int(r.get("nights")) or len(r_nights) or 1
        total_cents = _to_int(r.get("total_cents"))
        room_revenue_cents += (total_cents * n_in) // total_nights

        # currency tracking
        cur = str(r.get("currency", "")).lower()
        if cur:
            currencies.append(cur)

    # --- KPI computations ---
    occupancy_pct = round(rooms_sold / max(rooms_available, 1) * 100, 1)
    adr_cents = room_revenue_cents // max(rooms_sold, 1)
    revpar_cents = room_revenue_cents // max(rooms_available, 1)

    # currency: most common non-empty or fallback "usd"
    currency = "usd"
    if currencies:
        from collections import Counter
        currency = Counter(currencies).most_common(1)[0][0]

    return {
        "hotel_id": hotel_id,
        "from_ts": from_ts,
        "to_ts": to_ts,
        "rooms_available": rooms_available,
        "rooms_sold": rooms_sold,
        "occupancy_pct": occupancy_pct,
        "room_revenue_cents": room_revenue_cents,
        "adr_cents": adr_cents,
        "revpar_cents": revpar_cents,
        "arrivals": arrivals,
        "departures": departures,
        "currency": currency,
    }


def _empty_kpis(hotel_id: str, from_ts: int, to_ts: int) -> dict:
    return {
        "hotel_id": hotel_id,
        "from_ts": from_ts,
        "to_ts": to_ts,
        "rooms_available": 0,
        "rooms_sold": 0,
        "occupancy_pct": 0.0,
        "room_revenue_cents": 0,
        "adr_cents": 0,
        "revpar_cents": 0,
        "arrivals": 0,
        "departures": 0,
        "currency": "usd",
    }


# ---------------------------------------------------------------------------
# HTL-036 dashlet provider hook (forward-compatible; no-op when RPT not merged)
# ---------------------------------------------------------------------------


def _provider_hotel_kpis(user_sub: str, config: dict) -> dict:
    """Dashlet provider for hotel_kpis dashlet type.

    Returns a zero-KPI dict on any error (never 500s). Gated by HOTEL_PMS_ENABLED.
    """
    try:
        hotel_id = str(config.get("hotel_id", ""))
        period_days = int(config.get("period_days", 30))
        to_ts = now_ts()
        from_ts = to_ts - period_days * 86400
        return compute_hotel_kpis(hotel_id, from_ts=from_ts, to_ts=to_ts)
    except Exception:
        return {
            "hotel_id": config.get("hotel_id", ""),
            "from_ts": 0,
            "to_ts": 0,
            "rooms_available": 0,
            "rooms_sold": 0,
            "occupancy_pct": 0.0,
            "room_revenue_cents": 0,
            "adr_cents": 0,
            "revpar_cents": 0,
            "arrivals": 0,
            "departures": 0,
            "currency": "usd",
        }


# Register the dashlet type if RPT-006 registry is available (forward-compatible).
try:
    from app.services.crm_dashlet_data import VALID_DASHLET_TYPES  # type: ignore[import-not-found]
    if "hotel_kpis" not in VALID_DASHLET_TYPES:
        VALID_DASHLET_TYPES.add("hotel_kpis")  # type: ignore[union-attr]
except Exception:
    pass
