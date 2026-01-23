from __future__ import annotations

import uuid
from datetime import datetime, date, timedelta, timezone
from typing import Any, Dict, Iterable, List

from boto3.dynamodb.conditions import Key
from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.tables import T
from app.models import CalendarCreateIn, CalendarOut, EventCreateIn, EventOut, OpeningsOut
from app.services.sessions import require_ui_session

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover - fallback for older Python
    ZoneInfo = None

router = APIRouter(prefix="/ui", tags=["calendar"])


def _require_zoneinfo() -> None:
    if ZoneInfo is None:
        raise HTTPException(status_code=500, detail="zoneinfo not available. Use Python 3.9+.")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_iso_dt(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid datetime: {value}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def parse_iso_date(value: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid date: {value}") from exc


def overlap(a0: datetime, a1: datetime, b0: datetime, b1: datetime) -> bool:
    return a0 < b1 and b0 < a1


def merge_intervals(intervals: Iterable[tuple[datetime, datetime]]) -> list[tuple[datetime, datetime]]:
    ordered = sorted(intervals, key=lambda pair: pair[0])
    if not ordered:
        return []
    merged: list[tuple[datetime, datetime]] = [ordered[0]]
    for start, end in ordered[1:]:
        prev_start, prev_end = merged[-1]
        if start <= prev_end:
            merged[-1] = (prev_start, max(prev_end, end))
        else:
            merged.append((start, end))
    return merged


def invert_intervals(busy: list[tuple[datetime, datetime]], start: datetime, end: datetime) -> list[tuple[datetime, datetime]]:
    clipped = [(max(s, start), min(e, end)) for s, e in busy if overlap(s, e, start, end)]
    merged = merge_intervals(clipped)
    free: list[tuple[datetime, datetime]] = []
    cur = start
    for s, e in merged:
        if cur < s:
            free.append((cur, s))
        cur = max(cur, e)
    if cur < end:
        free.append((cur, end))
    return free


def _calendar_keys(calendar_id: str) -> Dict[str, str]:
    return {"calendar_id": calendar_id, "sk": "meta"}


def _event_key(event_id: str) -> str:
    return f"event#{event_id}"


def _normalize_event_times(calendar_tz: str, payload: EventCreateIn) -> Dict[str, Any]:
    _require_zoneinfo()
    tz_name = payload.timezone or calendar_tz
    try:
        ZoneInfo(tz_name)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid timezone") from exc

    if payload.all_day:
        if not payload.all_day_date:
            raise HTTPException(status_code=400, detail="all_day_date is required for all-day events")
        all_day_date = parse_iso_date(payload.all_day_date).isoformat()
        return {"all_day": True, "timezone": tz_name, "all_day_date": all_day_date, "start_utc": None, "end_utc": None}

    if not payload.start_utc or not payload.end_utc:
        raise HTTPException(status_code=400, detail="start_utc and end_utc are required for timed events")
    start = parse_iso_dt(payload.start_utc)
    end = parse_iso_dt(payload.end_utc)
    if end <= start:
        raise HTTPException(status_code=400, detail="end_utc must be after start_utc")
    return {
        "all_day": False,
        "timezone": tz_name,
        "start_utc": iso_utc(start),
        "end_utc": iso_utc(end),
        "all_day_date": None,
    }


def _event_to_busy_interval(event: Dict[str, Any]) -> tuple[datetime, datetime]:
    if event.get("all_day"):
        _require_zoneinfo()
        tz = ZoneInfo(event["timezone"])
        d = parse_iso_date(event["all_day_date"])
        local_start = datetime(d.year, d.month, d.day, 0, 0, 0, tzinfo=tz)
        local_end = local_start + timedelta(days=1)
        return local_start.astimezone(timezone.utc), local_end.astimezone(timezone.utc)
    return parse_iso_dt(event["start_utc"]), parse_iso_dt(event["end_utc"])


def _load_calendar(calendar_id: str, user_sub: str) -> Dict[str, Any]:
    meta = T.calendar.get_item(Key=_calendar_keys(calendar_id)).get("Item")
    if not meta:
        raise HTTPException(status_code=404, detail="Calendar not found")
    if meta.get("owner_user_sub") != user_sub:
        raise HTTPException(status_code=403, detail="Calendar access denied")
    return meta


def _list_events(calendar_id: str) -> List[Dict[str, Any]]:
    response = T.calendar.query(
        KeyConditionExpression=Key("calendar_id").eq(calendar_id) & Key("sk").begins_with("event#"),
        ScanIndexForward=True,
    )
    return response.get("Items", [])


def _event_out(item: Dict[str, Any], calendar_id: str) -> EventOut:
    return EventOut(
        event_id=item["event_id"],
        calendar_id=calendar_id,
        name=item["name"],
        description=item.get("description", ""),
        timezone=item.get("timezone", "UTC"),
        start_utc=item.get("start_utc"),
        end_utc=item.get("end_utc"),
        all_day=item.get("all_day", False),
        all_day_date=item.get("all_day_date"),
        created_at_utc=item.get("created_at_utc", ""),
    )


@router.post("/calendars", response_model=CalendarOut)
async def create_calendar(body: CalendarCreateIn, ctx: Dict[str, str] = Depends(require_ui_session)):
    calendar_id = uuid.uuid4().hex
    now = iso_utc(utc_now())
    item = {
        "calendar_id": calendar_id,
        "sk": "meta",
        "type": "calendar",
        "name": body.name,
        "timezone": body.timezone,
        "owner_user_sub": ctx["user_sub"],
        "created_at_utc": now,
    }
    T.calendar.put_item(Item=item)
    return CalendarOut(
        calendar_id=calendar_id,
        name=body.name,
        timezone=body.timezone,
        owner_user_id=ctx["user_sub"],
        created_at_utc=now,
    )


@router.post("/calendars/{calendar_id}/events", response_model=EventOut)
async def create_event(
    calendar_id: str,
    body: EventCreateIn,
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    meta = _load_calendar(calendar_id, ctx["user_sub"])
    normalized = _normalize_event_times(meta["timezone"], body)
    event_id = uuid.uuid4().hex
    now = iso_utc(utc_now())
    item = {
        "calendar_id": calendar_id,
        "sk": _event_key(event_id),
        "type": "event",
        "event_id": event_id,
        "name": body.name,
        "description": body.description,
        "created_at_utc": now,
        **normalized,
    }
    T.calendar.put_item(Item=item)
    return EventOut(
        event_id=event_id,
        calendar_id=calendar_id,
        name=body.name,
        description=body.description,
        timezone=normalized["timezone"],
        start_utc=normalized["start_utc"],
        end_utc=normalized["end_utc"],
        all_day=normalized["all_day"],
        all_day_date=normalized["all_day_date"],
        created_at_utc=now,
    )


@router.get("/calendars/{calendar_id}/events", response_model=list[EventOut])
async def list_events(calendar_id: str, ctx: Dict[str, str] = Depends(require_ui_session)):
    _load_calendar(calendar_id, ctx["user_sub"])
    return [_event_out(item, calendar_id) for item in _list_events(calendar_id)]


@router.get("/calendars/{calendar_id}/openings", response_model=list[OpeningsOut])
async def list_openings(
    calendar_id: str,
    start_utc: str = Query(..., description="Start window in ISO-8601 UTC"),
    end_utc: str = Query(..., description="End window in ISO-8601 UTC"),
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    _load_calendar(calendar_id, ctx["user_sub"])
    window_start = parse_iso_dt(start_utc)
    window_end = parse_iso_dt(end_utc)
    if window_end <= window_start:
        raise HTTPException(status_code=400, detail="end_utc must be after start_utc")
    busy = [_event_to_busy_interval(event) for event in _list_events(calendar_id)]
    free = invert_intervals(busy, window_start, window_end)
    return [OpeningsOut(start_utc=iso_utc(s), end_utc=iso_utc(e)) for s, e in free]
