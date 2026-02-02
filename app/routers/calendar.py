from __future__ import annotations

import uuid
from datetime import datetime, date, time, timedelta, timezone
from typing import Annotated, Any, Dict, Iterable, List

from boto3.dynamodb.conditions import Attr, Key
from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.tables import T
from app.models import (
    BookingLinkCreateIn,
    BookingLinkOut,
    BookingRequestIn,
    CalendarCreateIn,
    CalendarOut,
    CalendarUpdateIn,
    EventsPageOut,
    EventCreateIn,
    EventOut,
    EventUpdateIn,
    OpeningsOut,
    RecurrenceRule,
    TeamAvailabilityIn,
)
from app.services.alerts import audit_event
from app.services.sessions import require_ui_session

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover - fallback for older Python
    ZoneInfo = None

router = APIRouter(prefix="/ui", tags=["calendar"])
public_router = APIRouter(prefix="/booking", tags=["booking"])


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


WEEKDAY_NAMES = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
RRULE_WEEKDAY_MAP = {"MO": 0, "TU": 1, "WE": 2, "TH": 3, "FR": 4, "SA": 5, "SU": 6}


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


def parse_availability_window(start_utc: str, end_utc: str) -> tuple[datetime, datetime]:
    window_start = parse_iso_dt(start_utc)
    window_end = parse_iso_dt(end_utc)
    if window_end <= window_start:
        raise HTTPException(status_code=400, detail="end_utc must be after start_utc")
    return window_start, window_end


def _calendar_keys(calendar_id: str) -> Dict[str, str]:
    return {"calendar_id": calendar_id, "sk": "meta"}


def _event_key(event_id: str) -> str:
    return f"event#{event_id}"


def _booking_link_key(link_id: str) -> str:
    return f"booking#{link_id}"


def _load_event(calendar_id: str, event_id: str) -> Dict[str, Any]:
    item = T.calendar.get_item(Key={"calendar_id": calendar_id, "sk": _event_key(event_id)}).get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Event not found")
    return item


def _load_booking_link(link_id: str) -> Dict[str, Any]:
    response = T.calendar.scan(
        FilterExpression=Attr("sk").eq(_booking_link_key(link_id)) & Attr("type").eq("booking_link"),
        Limit=1,
    )
    items = response.get("Items", [])
    if not items:
        raise HTTPException(status_code=404, detail="Booking link not found")
    return items[0]


def _load_calendar_public(calendar_id: str) -> Dict[str, Any]:
    meta = T.calendar.get_item(Key=_calendar_keys(calendar_id)).get("Item")
    if not meta:
        raise HTTPException(status_code=404, detail="Calendar not found")
    return meta


def _validate_timezone(tz_name: str) -> None:
    _require_zoneinfo()
    try:
        ZoneInfo(tz_name)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid timezone") from exc


def _parse_hhmm(value: str) -> time:
    try:
        return time.fromisoformat(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid time: {value}") from exc


def _validate_working_hours(working_hours: Dict[str, list[Dict[str, str]]] | None) -> None:
    if working_hours is None:
        return
    for day, windows in working_hours.items():
        if day not in WEEKDAY_NAMES:
            raise HTTPException(status_code=400, detail=f"Invalid weekday: {day}")
        for window in windows:
            start = _parse_hhmm(window["start"])
            end = _parse_hhmm(window["end"])
            if end <= start:
                raise HTTPException(status_code=400, detail="working_hours end must be after start")


def _normalize_buffers(buffer_before_minutes: int, buffer_after_minutes: int) -> tuple[int, int]:
    if buffer_before_minutes < 0 or buffer_after_minutes < 0:
        raise HTTPException(status_code=400, detail="Buffers must be non-negative")
    return buffer_before_minutes, buffer_after_minutes


def _validate_booking_settings(booking_enabled: bool, approval_required: bool) -> None:
    if approval_required and not booking_enabled:
        raise HTTPException(status_code=400, detail="approval_required requires booking_enabled")


def _normalize_event_status(status: str) -> str:
    normalized = status.lower().strip()
    allowed = {"busy", "tentative", "free", "out_of_office"}
    if normalized not in allowed:
        raise HTTPException(status_code=400, detail="Invalid event status")
    return normalized


def _is_busy_status(status: str) -> bool:
    return _normalize_event_status(status) not in {"free", "tentative"}


def _normalize_recurrence_rule(rule: RecurrenceRule | None) -> RecurrenceRule | None:
    if rule is None:
        return None
    if rule.until_utc:
        _ = parse_iso_dt(rule.until_utc)
    return rule


def _normalize_event_times(calendar_tz: str, payload: EventCreateIn) -> Dict[str, Any]:
    tz_name = payload.timezone or calendar_tz
    _validate_timezone(tz_name)

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


def _event_to_busy_interval(event: Dict[str, Any]) -> tuple[datetime, datetime] | None:
    status = str(event.get("status", "busy"))
    if not _is_busy_status(status):
        return None
    if event.get("all_day"):
        _require_zoneinfo()
        tz = ZoneInfo(event["timezone"])
        d = parse_iso_date(event["all_day_date"])
        local_start = datetime(d.year, d.month, d.day, 0, 0, 0, tzinfo=tz)
        local_end = local_start + timedelta(days=1)
        return local_start.astimezone(timezone.utc), local_end.astimezone(timezone.utc)
    return parse_iso_dt(event["start_utc"]), parse_iso_dt(event["end_utc"])


def _event_payload_interval(normalized: Dict[str, Any]) -> tuple[datetime, datetime]:
    if normalized.get("all_day"):
        event = {
            "all_day": True,
            "timezone": normalized["timezone"],
            "all_day_date": normalized["all_day_date"],
            "status": normalized.get("status", "busy"),
        }
    else:
        event = {
            "all_day": False,
            "start_utc": normalized["start_utc"],
            "end_utc": normalized["end_utc"],
            "status": normalized.get("status", "busy"),
        }
    interval = _event_to_busy_interval(event)
    if interval is None:
        raise HTTPException(status_code=400, detail="Non-busy events cannot be used for conflict checks")
    return interval


def _event_time_interval(event: Dict[str, Any]) -> tuple[datetime, datetime]:
    if event.get("all_day"):
        _require_zoneinfo()
        tz = ZoneInfo(event["timezone"])
        d = parse_iso_date(event["all_day_date"])
        local_start = datetime(d.year, d.month, d.day, 0, 0, 0, tzinfo=tz)
        local_end = local_start + timedelta(days=1)
        return local_start.astimezone(timezone.utc), local_end.astimezone(timezone.utc)
    return parse_iso_dt(event["start_utc"]), parse_iso_dt(event["end_utc"])


def _expand_rrule(
    series_start_utc: datetime,
    series_end_utc: datetime,
    rrule: RecurrenceRule,
    window_start: datetime,
    window_end: datetime,
) -> list[tuple[datetime, datetime]]:
    if window_end <= window_start:
        return []
    until = parse_iso_dt(rrule.until_utc) if rrule.until_utc else None
    remaining = rrule.count
    duration = series_end_utc - series_start_utc
    occs: list[tuple[datetime, datetime]] = []
    if rrule.freq == "DAILY":
        dt = series_start_utc
        step = timedelta(days=rrule.interval)
        while True:
            if until and dt > until:
                break
            if remaining is not None and remaining <= 0:
                break
            occ_start = dt
            occ_end = dt + duration
            if overlap(occ_start, occ_end, window_start, window_end):
                occs.append((occ_start, occ_end))
            dt = dt + step
            if remaining is not None:
                remaining -= 1
            if dt > window_end + timedelta(days=1):
                break
    elif rrule.freq == "WEEKLY":
        bydays = rrule.byday or [list(RRULE_WEEKDAY_MAP.keys())[series_start_utc.weekday()]]
        by_idxs = sorted({RRULE_WEEKDAY_MAP[d] for d in bydays})
        week0_date = series_start_utc.date() - timedelta(days=series_start_utc.weekday())
        week_start = datetime(
            week0_date.year,
            week0_date.month,
            week0_date.day,
            series_start_utc.hour,
            series_start_utc.minute,
            series_start_utc.second,
            series_start_utc.microsecond,
            tzinfo=timezone.utc,
        )
        while True:
            for wi in by_idxs:
                cand = week_start + timedelta(days=wi)
                if cand < series_start_utc:
                    continue
                if until and cand > until:
                    return sorted(occs, key=lambda x: x[0])
                if remaining is not None and remaining <= 0:
                    return sorted(occs, key=lambda x: x[0])
                occ_start = cand
                occ_end = cand + duration
                if overlap(occ_start, occ_end, window_start, window_end):
                    occs.append((occ_start, occ_end))
                if remaining is not None:
                    remaining -= 1
            week_start = week_start + timedelta(weeks=rrule.interval)
            if until and week_start > until + timedelta(days=7):
                break
            if week_start > window_end + timedelta(days=7):
                break
    elif rrule.freq == "MONTHLY":
        def add_months(d: datetime, months: int) -> datetime | None:
            y = d.year + (d.month - 1 + months) // 12
            m = (d.month - 1 + months) % 12 + 1
            try:
                return d.replace(year=y, month=m, day=d.day)
            except ValueError:
                return None
        k = 0
        cur = series_start_utc
        while True:
            if until and cur > until:
                break
            if remaining is not None and remaining <= 0:
                break
            occ_start = cur
            occ_end = cur + duration
            if overlap(occ_start, occ_end, window_start, window_end):
                occs.append((occ_start, occ_end))
            if remaining is not None:
                remaining -= 1
            k += rrule.interval
            nxt = add_months(series_start_utc, k)
            if nxt is None:
                continue
            cur = nxt
            if cur > window_end + timedelta(days=31):
                break
    return sorted(occs, key=lambda x: x[0])


def _expand_event_occurrences(
    event: Dict[str, Any],
    window_start: datetime,
    window_end: datetime,
) -> list[Dict[str, Any]]:
    rule_data = event.get("recurrence_rule")
    if not rule_data:
        return [event]
    rule = RecurrenceRule(**rule_data)
    series_start, series_end = _event_time_interval(event)
    occs = _expand_rrule(series_start, series_end, rule, window_start, window_end)
    if not occs:
        return []
    tz = ZoneInfo(event.get("timezone", "UTC"))
    occurrences: list[Dict[str, Any]] = []
    for occ_start, occ_end in occs:
        occ = {**event}
        if event.get("all_day"):
            local_date = occ_start.astimezone(tz).date()
            occ["all_day_date"] = local_date.isoformat()
            occ["start_utc"] = None
            occ["end_utc"] = None
        else:
            occ["start_utc"] = iso_utc(occ_start)
            occ["end_utc"] = iso_utc(occ_end)
        occurrences.append(occ)
    return occurrences


def _ensure_no_conflicts(
    calendar_id: str,
    normalized: Dict[str, Any],
    *,
    exclude_event_id: str | None = None,
) -> None:
    requested_start, requested_end = _event_payload_interval(normalized)
    for event in _list_events(calendar_id)[0]:
        if exclude_event_id and event.get("event_id") == exclude_event_id:
            continue
        if event.get("recurrence_rule"):
            occurrences = _expand_event_occurrences(event, requested_start, requested_end)
            for occ in occurrences:
                interval = _event_to_busy_interval(occ)
                if interval is None:
                    continue
                start, end = interval
                if overlap(requested_start, requested_end, start, end):
                    raise HTTPException(status_code=409, detail="Event conflicts with an existing event")
        else:
            interval = _event_to_busy_interval(event)
            if interval is None:
                continue
            start, end = interval
            if overlap(requested_start, requested_end, start, end):
                raise HTTPException(status_code=409, detail="Event conflicts with an existing event")


def _load_calendar(calendar_id: str, user_sub: str) -> Dict[str, Any]:
    meta = T.calendar.get_item(Key=_calendar_keys(calendar_id)).get("Item")
    if not meta:
        raise HTTPException(status_code=404, detail="Calendar not found")
    if meta.get("owner_user_sub") != user_sub:
        raise HTTPException(status_code=403, detail="Calendar access denied")
    return meta


def _list_events(
    calendar_id: str,
    *,
    start_utc: datetime | None = None,
    end_utc: datetime | None = None,
    limit: int | None = None,
    cursor: str | None = None,
) -> tuple[list[Dict[str, Any]], str | None]:
    items: list[Dict[str, Any]] = []
    last_cursor = cursor
    remaining = limit
    while True:
        query_kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("calendar_id").eq(calendar_id) & Key("sk").begins_with("event#"),
            "ScanIndexForward": True,
        }
        if last_cursor:
            query_kwargs["ExclusiveStartKey"] = {"calendar_id": calendar_id, "sk": last_cursor}
        if remaining:
            query_kwargs["Limit"] = min(200, remaining)
        response = T.calendar.query(**query_kwargs)
        page_items = response.get("Items", [])
        for event in page_items:
            if (start_utc or end_utc) and not event.get("recurrence_rule"):
                event_start, event_end = _event_time_interval(event)
                if start_utc and event_end <= start_utc:
                    continue
                if end_utc and event_start >= end_utc:
                    continue
            items.append(event)
            if remaining:
                remaining -= 1
                if remaining == 0:
                    last_cursor = event.get("sk") or _event_key(event["event_id"])
                    return items, last_cursor
        last_evaluated = response.get("LastEvaluatedKey")
        if not last_evaluated:
            return items, None
        last_cursor = last_evaluated.get("sk")


def _apply_buffers(
    busy: list[tuple[datetime, datetime]],
    buffer_before_minutes: int,
    buffer_after_minutes: int,
) -> list[tuple[datetime, datetime]]:
    if not busy:
        return []
    before = timedelta(minutes=buffer_before_minutes)
    after = timedelta(minutes=buffer_after_minutes)
    adjusted = [(start - before, end + after) for start, end in busy]
    return merge_intervals(adjusted)


def _working_hours_intervals(
    working_hours: Dict[str, list[Dict[str, str]]],
    tz_name: str,
    window_start: datetime,
    window_end: datetime,
) -> list[tuple[datetime, datetime]]:
    _require_zoneinfo()
    tz = ZoneInfo(tz_name)
    intervals: list[tuple[datetime, datetime]] = []
    cur_day = window_start.astimezone(tz).date()
    end_day = window_end.astimezone(tz).date()
    while cur_day <= end_day:
        weekday = WEEKDAY_NAMES[cur_day.weekday()]
        for window in working_hours.get(weekday, []):
            start_time = _parse_hhmm(window["start"])
            end_time = _parse_hhmm(window["end"])
            local_start = datetime.combine(cur_day, start_time, tzinfo=tz)
            local_end = datetime.combine(cur_day, end_time, tzinfo=tz)
            intervals.append((local_start.astimezone(timezone.utc), local_end.astimezone(timezone.utc)))
        cur_day += timedelta(days=1)
    return intervals


def _calendar_openings(meta: Dict[str, Any], window_start: datetime, window_end: datetime) -> list[tuple[datetime, datetime]]:
    busy: list[tuple[datetime, datetime]] = []
    for event in _list_events(meta["calendar_id"])[0]:
        expanded = _expand_event_occurrences(event, window_start, window_end)
        for occ in expanded:
            interval = _event_to_busy_interval(occ)
            if interval is not None:
                busy.append(interval)
    buffer_before, buffer_after = _normalize_buffers(
        int(meta.get("buffer_before_minutes", 0)),
        int(meta.get("buffer_after_minutes", 0)),
    )
    busy = _apply_buffers(busy, buffer_before, buffer_after)
    working_hours = meta.get("working_hours")
    if not working_hours:
        return invert_intervals(busy, window_start, window_end)
    windows = _working_hours_intervals(working_hours, meta.get("timezone", "UTC"), window_start, window_end)
    free: list[tuple[datetime, datetime]] = []
    for start, end in windows:
        free.extend(invert_intervals(busy, max(start, window_start), min(end, window_end)))
    return merge_intervals(free)


def _slot_in_openings(
    openings: list[tuple[datetime, datetime]],
    slot_start: datetime,
    slot_end: datetime,
) -> bool:
    return any(slot_start >= start and slot_end <= end for start, end in openings)


def _filter_openings_by_duration(
    openings: list[tuple[datetime, datetime]],
    duration_minutes: int,
) -> list[tuple[datetime, datetime]]:
    duration = timedelta(minutes=duration_minutes)
    return [(start, end) for start, end in openings if end - start >= duration]


def _intersect_intervals(
    left: list[tuple[datetime, datetime]],
    right: list[tuple[datetime, datetime]],
) -> list[tuple[datetime, datetime]]:
    if not left or not right:
        return []
    result: list[tuple[datetime, datetime]] = []
    i = j = 0
    left_sorted = sorted(left, key=lambda pair: pair[0])
    right_sorted = sorted(right, key=lambda pair: pair[0])
    while i < len(left_sorted) and j < len(right_sorted):
        start = max(left_sorted[i][0], right_sorted[j][0])
        end = min(left_sorted[i][1], right_sorted[j][1])
        if start < end:
            result.append((start, end))
        if left_sorted[i][1] < right_sorted[j][1]:
            i += 1
        else:
            j += 1
    return result


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
        attendees=item.get("attendees", []),
        booking_enabled=item.get("booking_enabled", False),
        approval_required=item.get("approval_required", False),
        status=item.get("status", "busy"),
        category=item.get("category"),
        recurrence_rule=item.get("recurrence_rule"),
        created_at_utc=item.get("created_at_utc", ""),
    )


@router.post("/calendars", response_model=CalendarOut)
async def create_calendar(body: CalendarCreateIn, ctx: Dict[str, str] = Depends(require_ui_session)):
    calendar_id = uuid.uuid4().hex
    now = iso_utc(utc_now())
    _validate_timezone(body.timezone)
    _validate_working_hours(body.working_hours)
    buffer_before, buffer_after = _normalize_buffers(body.buffer_before_minutes, body.buffer_after_minutes)
    item = {
        "calendar_id": calendar_id,
        "sk": "meta",
        "type": "calendar",
        "name": body.name,
        "timezone": body.timezone,
        "conflict_detection": body.conflict_detection,
        "working_hours": body.working_hours,
        "buffer_before_minutes": buffer_before,
        "buffer_after_minutes": buffer_after,
        "owner_user_sub": ctx["user_sub"],
        "created_at_utc": now,
    }
    T.calendar.put_item(Item=item)
    return CalendarOut(
        calendar_id=calendar_id,
        name=body.name,
        timezone=body.timezone,
        conflict_detection=body.conflict_detection,
        working_hours=body.working_hours,
        buffer_before_minutes=buffer_before,
        buffer_after_minutes=buffer_after,
        owner_user_id=ctx["user_sub"],
        created_at_utc=now,
    )


@router.post("/calendars/{calendar_id}/events", response_model=EventOut)
async def create_event(
    calendar_id: str,
    body: EventCreateIn,
    force: bool = Query(False, description="Allow conflicts when true"),
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    meta = _load_calendar(calendar_id, ctx["user_sub"])
    _validate_booking_settings(body.booking_enabled, body.approval_required)
    status = _normalize_event_status(body.status)
    recurrence_rule = _normalize_recurrence_rule(body.recurrence_rule)
    normalized = _normalize_event_times(meta["timezone"], body)
    normalized["status"] = status
    if meta.get("conflict_detection") and not force and _is_busy_status(status):
        _ensure_no_conflicts(calendar_id, normalized)
    event_id = uuid.uuid4().hex
    now = iso_utc(utc_now())
    item = {
        "calendar_id": calendar_id,
        "sk": _event_key(event_id),
        "type": "event",
        "event_id": event_id,
        "name": body.name,
        "description": body.description,
        "attendees": body.attendees,
        "booking_enabled": body.booking_enabled,
        "approval_required": body.approval_required,
        "status": status,
        "category": body.category,
        "recurrence_rule": recurrence_rule.model_dump() if recurrence_rule else None,
        "created_at_utc": now,
        **normalized,
    }
    T.calendar.put_item(Item=item)
    audit_event(
        "calendar_event_create",
        ctx["user_sub"],
        None,
        outcome="success",
        calendar_id=calendar_id,
        event_id=event_id,
        name=body.name,
        timezone=normalized["timezone"],
        start_utc=normalized["start_utc"],
        end_utc=normalized["end_utc"],
        all_day=normalized["all_day"],
        all_day_date=normalized["all_day_date"],
        status=status,
    )
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
        attendees=body.attendees,
        booking_enabled=body.booking_enabled,
        approval_required=body.approval_required,
        status=status,
        category=body.category,
        recurrence_rule=recurrence_rule,
        created_at_utc=now,
    )


@router.post("/calendars/{calendar_id}/booking_links", response_model=BookingLinkOut)
async def create_booking_link(
    calendar_id: str,
    body: BookingLinkCreateIn,
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    meta = _load_calendar(calendar_id, ctx["user_sub"])
    tz_name = body.timezone or meta.get("timezone", "UTC")
    _validate_timezone(tz_name)
    link_id = uuid.uuid4().hex
    now = iso_utc(utc_now())
    item = {
        "calendar_id": calendar_id,
        "sk": _booking_link_key(link_id),
        "type": "booking_link",
        "link_id": link_id,
        "name": body.name,
        "duration_minutes": int(body.duration_minutes),
        "timezone": tz_name,
        "created_at_utc": now,
        "owner_user_sub": meta.get("owner_user_sub"),
    }
    T.calendar.put_item(Item=item)
    return BookingLinkOut(
        link_id=link_id,
        calendar_id=calendar_id,
        name=body.name,
        duration_minutes=int(body.duration_minutes),
        timezone=tz_name,
        created_at_utc=now,
        public_url=f"/booking/{link_id}",
    )


@router.get("/calendars/{calendar_id}/events", response_model=EventsPageOut)
async def list_events(
    calendar_id: str,
    start_utc: Annotated[
        str | None,
        Query(description="Filter events starting after this UTC timestamp"),
    ] = None,
    end_utc: Annotated[
        str | None,
        Query(description="Filter events ending before this UTC timestamp"),
    ] = None,
    limit: Annotated[int | None, Query(ge=1, le=200)] = None,
    cursor: Annotated[str | None, Query(description="Pagination cursor")] = None,
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    _load_calendar(calendar_id, ctx["user_sub"])
    start_dt = parse_iso_dt(start_utc) if start_utc else None
    end_dt = parse_iso_dt(end_utc) if end_utc else None
    items, next_cursor = _list_events(
        calendar_id,
        start_utc=start_dt,
        end_utc=end_dt,
        limit=limit,
        cursor=cursor,
    )
    if start_dt and end_dt:
        expanded: list[Dict[str, Any]] = []
        for item in items:
            expanded.extend(_expand_event_occurrences(item, start_dt, end_dt))
        items = expanded
    return EventsPageOut(
        events=[_event_out(item, calendar_id) for item in items],
        next_cursor=next_cursor,
    )


@router.patch("/calendars/{calendar_id}", response_model=CalendarOut)
async def update_calendar(
    calendar_id: str,
    body: CalendarUpdateIn,
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    meta = _load_calendar(calendar_id, ctx["user_sub"])
    name = body.name if body.name is not None else meta.get("name", "")
    timezone_name = body.timezone if body.timezone is not None else meta.get("timezone", "UTC")
    if body.timezone is not None:
        _validate_timezone(timezone_name)
    working_hours = body.working_hours if body.working_hours is not None else meta.get("working_hours")
    _validate_working_hours(working_hours)
    buffer_before = (
        body.buffer_before_minutes
        if body.buffer_before_minutes is not None
        else int(meta.get("buffer_before_minutes", 0))
    )
    buffer_after = (
        body.buffer_after_minutes
        if body.buffer_after_minutes is not None
        else int(meta.get("buffer_after_minutes", 0))
    )
    buffer_before, buffer_after = _normalize_buffers(buffer_before, buffer_after)
    conflict_detection = (
        meta.get("conflict_detection", False)
        if body.conflict_detection is None
        else body.conflict_detection
    )
    updated = {
        **meta,
        "name": name,
        "timezone": timezone_name,
        "conflict_detection": conflict_detection,
        "working_hours": working_hours,
        "buffer_before_minutes": buffer_before,
        "buffer_after_minutes": buffer_after,
    }
    T.calendar.put_item(Item=updated)
    return CalendarOut(
        calendar_id=calendar_id,
        name=updated["name"],
        timezone=updated["timezone"],
        conflict_detection=updated.get("conflict_detection", False),
        working_hours=updated.get("working_hours"),
        buffer_before_minutes=int(updated.get("buffer_before_minutes", 0)),
        buffer_after_minutes=int(updated.get("buffer_after_minutes", 0)),
        owner_user_id=updated["owner_user_sub"],
        created_at_utc=updated.get("created_at_utc", ""),
    )


@router.patch("/calendars/{calendar_id}/events/{event_id}", response_model=EventOut)
async def update_event(
    calendar_id: str,
    event_id: str,
    body: EventUpdateIn,
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    meta = _load_calendar(calendar_id, ctx["user_sub"])
    item = _load_event(calendar_id, event_id)
    raw_recurrence = body.recurrence_rule if body.recurrence_rule is not None else item.get("recurrence_rule")
    recurrence_rule = RecurrenceRule(**raw_recurrence) if raw_recurrence else None
    payload = EventCreateIn(
        name=body.name if body.name is not None else item["name"],
        description=body.description if body.description is not None else item.get("description", ""),
        timezone=body.timezone if body.timezone is not None else item.get("timezone"),
        start_utc=body.start_utc if body.start_utc is not None else item.get("start_utc"),
        end_utc=body.end_utc if body.end_utc is not None else item.get("end_utc"),
        all_day=body.all_day if body.all_day is not None else item.get("all_day", False),
        all_day_date=body.all_day_date if body.all_day_date is not None else item.get("all_day_date"),
        attendees=body.attendees if body.attendees is not None else item.get("attendees", []),
        booking_enabled=(
            body.booking_enabled if body.booking_enabled is not None else item.get("booking_enabled", False)
        ),
        approval_required=(
            body.approval_required if body.approval_required is not None else item.get("approval_required", False)
        ),
        status=body.status if body.status is not None else item.get("status", "busy"),
        category=body.category if body.category is not None else item.get("category"),
        recurrence_rule=recurrence_rule,
    )
    _validate_booking_settings(payload.booking_enabled, payload.approval_required)
    status = _normalize_event_status(payload.status)
    recurrence_rule = _normalize_recurrence_rule(payload.recurrence_rule)
    normalized = _normalize_event_times(meta["timezone"], payload)
    normalized["status"] = status
    if meta.get("conflict_detection") and _is_busy_status(status):
        _ensure_no_conflicts(calendar_id, normalized, exclude_event_id=event_id)
    updated = {
        **item,
        "name": payload.name,
        "description": payload.description,
        "attendees": payload.attendees,
        "booking_enabled": payload.booking_enabled,
        "approval_required": payload.approval_required,
        "status": status,
        "category": payload.category,
        "recurrence_rule": recurrence_rule.model_dump() if recurrence_rule else None,
        **normalized,
    }
    T.calendar.put_item(Item=updated)
    audit_event(
        "calendar_event_update",
        ctx["user_sub"],
        None,
        outcome="success",
        calendar_id=calendar_id,
        event_id=event_id,
        name=updated["name"],
        timezone=updated.get("timezone", "UTC"),
        start_utc=updated.get("start_utc"),
        end_utc=updated.get("end_utc"),
        all_day=updated.get("all_day", False),
        all_day_date=updated.get("all_day_date"),
        status=updated.get("status", "busy"),
    )
    return _event_out(updated, calendar_id)


@router.delete("/calendars/{calendar_id}/events/{event_id}")
async def delete_event(
    calendar_id: str,
    event_id: str,
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    _load_calendar(calendar_id, ctx["user_sub"])
    item = _load_event(calendar_id, event_id)
    T.calendar.delete_item(Key={"calendar_id": calendar_id, "sk": _event_key(event_id)})
    audit_event(
        "calendar_event_delete",
        ctx["user_sub"],
        None,
        outcome="success",
        calendar_id=calendar_id,
        event_id=event_id,
        name=item.get("name"),
        timezone=item.get("timezone", "UTC"),
        start_utc=item.get("start_utc"),
        end_utc=item.get("end_utc"),
        all_day=item.get("all_day", False),
        all_day_date=item.get("all_day_date"),
        status=item.get("status", "busy"),
    )
    return {"ok": True}


@router.delete("/calendars/{calendar_id}")
async def delete_calendar(calendar_id: str, ctx: Dict[str, str] = Depends(require_ui_session)):
    _load_calendar(calendar_id, ctx["user_sub"])
    events, _ = _list_events(calendar_id)
    with T.calendar.batch_writer() as batch:
        batch.delete_item(Key={"calendar_id": calendar_id, "sk": "meta"})
        for event in events:
            event_sk = event.get("sk") or _event_key(event["event_id"])
            batch.delete_item(Key={"calendar_id": calendar_id, "sk": event_sk})
    return {"ok": True}


@router.get("/calendars/{calendar_id}/openings", response_model=list[OpeningsOut])
async def list_openings(
    calendar_id: str,
    start_utc: str = Query(..., description="Start window in ISO-8601 UTC"),
    end_utc: str = Query(..., description="End window in ISO-8601 UTC"),
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    window_start, window_end = parse_availability_window(start_utc, end_utc)
    meta = _load_calendar(calendar_id, ctx["user_sub"])
    free = _calendar_openings(meta, window_start, window_end)
    return [OpeningsOut(start_utc=iso_utc(s), end_utc=iso_utc(e)) for s, e in free]


@router.post("/calendars/availability", response_model=list[OpeningsOut])
async def list_team_openings(body: TeamAvailabilityIn, ctx: Dict[str, str] = Depends(require_ui_session)):
    window_start, window_end = parse_availability_window(body.start_utc, body.end_utc)
    if not body.calendar_ids:
        raise HTTPException(status_code=400, detail="calendar_ids is required")
    combined: list[tuple[datetime, datetime]] | None = None
    for calendar_id in body.calendar_ids:
        meta = _load_calendar(calendar_id, ctx["user_sub"])
        openings = _calendar_openings(meta, window_start, window_end)
        combined = openings if combined is None else _intersect_intervals(combined, openings)
    free = combined or []
    return [OpeningsOut(start_utc=iso_utc(s), end_utc=iso_utc(e)) for s, e in free]


@public_router.get("/{link_id}", response_model=BookingLinkOut)
async def get_booking_link(link_id: str):
    link = _load_booking_link(link_id)
    return BookingLinkOut(
        link_id=link["link_id"],
        calendar_id=link["calendar_id"],
        name=link.get("name", ""),
        duration_minutes=int(link.get("duration_minutes", 0)),
        timezone=link.get("timezone", "UTC"),
        created_at_utc=link.get("created_at_utc", ""),
        public_url=f"/booking/{link_id}",
    )


@public_router.get("/{link_id}/openings", response_model=list[OpeningsOut])
async def list_booking_openings(
    link_id: str,
    start_utc: str = Query(..., description="Start window in ISO-8601 UTC"),
    end_utc: str = Query(..., description="End window in ISO-8601 UTC"),
    limit: int | None = Query(None, ge=1, le=200),
):
    link = _load_booking_link(link_id)
    meta = _load_calendar_public(link["calendar_id"])
    window_start, window_end = parse_availability_window(start_utc, end_utc)
    openings = _calendar_openings(meta, window_start, window_end)
    openings = _filter_openings_by_duration(openings, int(link.get("duration_minutes", 0)))
    if limit is not None:
        openings = openings[:limit]
    return [OpeningsOut(start_utc=iso_utc(s), end_utc=iso_utc(e)) for s, e in openings]


@public_router.post("/{link_id}/reserve", response_model=EventOut)
async def reserve_booking_slot(link_id: str, body: BookingRequestIn):
    link = _load_booking_link(link_id)
    meta = _load_calendar_public(link["calendar_id"])
    start_dt = parse_iso_dt(body.start_utc)
    end_dt = parse_iso_dt(body.end_utc)
    duration = end_dt - start_dt
    if duration.total_seconds() <= 0:
        raise HTTPException(status_code=400, detail="end_utc must be after start_utc")
    expected = timedelta(minutes=int(link.get("duration_minutes", 0)))
    if expected and duration != expected:
        raise HTTPException(status_code=400, detail="Slot duration does not match booking link")
    openings = _calendar_openings(meta, start_dt, end_dt)
    if not _slot_in_openings(openings, start_dt, end_dt):
        raise HTTPException(status_code=409, detail="Requested slot is no longer available")
    tz_name = body.timezone or link.get("timezone") or meta.get("timezone", "UTC")
    _validate_timezone(tz_name)
    payload = EventCreateIn(
        name=body.name or link.get("name", "Booking"),
        description=body.description or "",
        timezone=tz_name,
        start_utc=body.start_utc,
        end_utc=body.end_utc,
        all_day=False,
        all_day_date=None,
        attendees=[],
        booking_enabled=False,
        approval_required=False,
        status="busy",
        category="booking",
        recurrence_rule=None,
    )
    status = _normalize_event_status(payload.status)
    normalized = _normalize_event_times(meta.get("timezone", "UTC"), payload)
    normalized["status"] = status
    if meta.get("conflict_detection") and _is_busy_status(status):
        _ensure_no_conflicts(meta["calendar_id"], normalized)
    event_id = uuid.uuid4().hex
    now = iso_utc(utc_now())
    item = {
        "calendar_id": meta["calendar_id"],
        "sk": _event_key(event_id),
        "type": "event",
        "event_id": event_id,
        "name": payload.name,
        "description": payload.description,
        "attendees": payload.attendees,
        "booking_enabled": payload.booking_enabled,
        "approval_required": payload.approval_required,
        "status": status,
        "category": payload.category,
        "recurrence_rule": None,
        "booking_link_id": link_id,
        "created_at_utc": now,
        **normalized,
    }
    T.calendar.put_item(Item=item)
    if body.notify and meta.get("owner_user_sub"):
        audit_event(
            "calendar_booking_created",
            meta["owner_user_sub"],
            None,
            outcome="success",
            booking_link_id=link_id,
            event_id=event_id,
        )
    return _event_out(item, meta["calendar_id"])
