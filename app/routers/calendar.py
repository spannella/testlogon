from __future__ import annotations

import uuid
from datetime import datetime, date, time, timedelta, timezone
from typing import Annotated, Any, Dict, Iterable, List

from boto3.dynamodb.conditions import Attr, Key
from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.settings import S
from app.core.tables import T
from app.models import (
    AppleCalendarConnectIn,
    AppleCalendarConnectionOut,
    AppleCalendarExternalCalendarOut,
    AppleCalendarImportRunOut,
    AppleCalendarInitialImportIn,
    AppleCalendarSyncNowOut,
    AppleCalendarSelectionUpdateIn,
    AppleCalendarStatusOut,
    BookingLinkCreateIn,
    BookingLinkOut,
    BookingRequestIn,
    CalendarAccessOut,
    CalendarCreateIn,
    CalendarOut,
    CalendarShareIn,
    CalendarShareOut,
    CalendarUpdateIn,
    EventConflictPreviewIn,
    EventConflictPreviewOut,
    EventsPageOut,
    EventCreateIn,
    GoogleCalendarConnectCallbackOut,
    GoogleCalendarConnectStartOut,
    GoogleCalendarDisconnectOut,
    GoogleCalendarIntegrationStatusOut,
    GoogleCalendarMappingCreateIn,
    GoogleCalendarMappingOut,
    GoogleCalendarProviderCalendarsOut,
    GoogleCalendarProviderCalendarOut,
    GoogleCalendarSyncRunOut,
    EventOccurrenceOverrideIn,
    EventOut,
    EventUpdateIn,
    EventSuggestionsIn,
    OpeningsOut,
    RecurrenceRule,
    TeamAvailabilityIn,
)
from app.services.calendar_integrations.base import CalendarIntegrationError, CalendarIntegrationErrorCode
from app.services.calendar_integrations.credentials import upsert_apple_caldav_credential
from app.services.calendar_integrations.credentials import get_apple_caldav_status
from app.services.calendar_integrations.credentials import disconnect_apple_caldav_credential
from app.services.calendar_integrations.credentials import (
    enqueue_apple_caldav_initial_import,
    list_apple_caldav_calendars,
    select_apple_caldav_calendars,
    trigger_apple_caldav_sync_now,
)
from app.services.calendar_integrations.registry import get_provider_services
from app.services.alerts import audit_event
from app.services.google_calendar_flags import (
    is_google_calendar_sync_enabled_for_user,
    is_google_calendar_writeback_enabled_for_user,
    require_google_calendar_sync_enabled_for_user,
    rollout_mode,
    rollout_percent,
)
from app.services.google_calendar_event_mappings import get_event_mapping
from app.services.google_calendar_client import list_google_calendars
from app.services.google_calendar_connections import get_calendar_provider_connection
from app.services.google_calendar_mappings import create_calendar_provider_mapping, list_calendar_provider_mappings
from app.services.google_calendar_oauth import create_connect_start_state, handle_connect_callback, handle_disconnect
from app.services.google_calendar_outbound_jobs import enqueue_google_calendar_outbound_sync_job
from app.services.google_calendar_sync_full_import import run_google_calendar_full_import_job
from app.services.google_calendar_sync_incremental import run_google_calendar_incremental_sync_job
from app.services.google_calendar_audit import emit_google_calendar_audit_event
from app.services.rate_limit import rate_limit_admin_action
from app.services.sessions import require_ui_session

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover - fallback for older Python
    ZoneInfo = None

router = APIRouter(prefix="/ui", tags=["calendar"])
public_router = APIRouter(prefix="/booking", tags=["booking"])
public_event_router = APIRouter(prefix="/calendar/public", tags=["calendar_public"])
integration_router = APIRouter(prefix="/calendar/integrations/apple", tags=["calendar_integrations"])


def _map_calendar_integration_error(exc: CalendarIntegrationError) -> HTTPException:
    if exc.code == CalendarIntegrationErrorCode.AUTH:
        return HTTPException(status_code=401, detail=exc.detail)
    if exc.code == CalendarIntegrationErrorCode.PROTOCOL:
        return HTTPException(status_code=503, detail=exc.detail)
    if exc.code == CalendarIntegrationErrorCode.NETWORK:
        return HTTPException(status_code=502, detail=exc.detail)
    return HTTPException(status_code=500, detail=exc.detail)


@integration_router.post("/connect", response_model=AppleCalendarConnectionOut)
async def connect_apple_calendar(
    body: AppleCalendarConnectIn,
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    provider_services = get_provider_services("apple_caldav")
    if provider_services is None:
        raise HTTPException(status_code=503, detail="Apple CalDAV provider not available")

    try:
        provider_services.connection.validate_credentials(username=body.username, secret=body.app_specific_password)
    except CalendarIntegrationError as exc:
        raise _map_calendar_integration_error(exc) from exc

    connected = upsert_apple_caldav_credential(
        user_sub=ctx["user_sub"],
        username=body.username,
        app_specific_password=body.app_specific_password,
        credential_validation_status="valid",
    )
    return AppleCalendarConnectionOut(**connected)


@integration_router.get("/status", response_model=AppleCalendarStatusOut)
async def apple_calendar_status(
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    status = get_apple_caldav_status(user_sub=ctx["user_sub"])
    return AppleCalendarStatusOut(**status)


@integration_router.post("/disconnect", response_model=AppleCalendarConnectionOut)
async def apple_calendar_disconnect(
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    disconnected = disconnect_apple_caldav_credential(user_sub=ctx["user_sub"])
    return AppleCalendarConnectionOut(**disconnected)


@integration_router.get("/calendars", response_model=List[AppleCalendarExternalCalendarOut])
async def list_apple_calendars(
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    calendars = list_apple_caldav_calendars(user_sub=ctx["user_sub"])
    return [AppleCalendarExternalCalendarOut(**it) for it in calendars]


@integration_router.post("/calendars/select", response_model=List[AppleCalendarExternalCalendarOut])
async def select_apple_calendars(
    body: AppleCalendarSelectionUpdateIn,
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    selected = select_apple_caldav_calendars(
        user_sub=ctx["user_sub"],
        calendars=[c.model_dump() for c in body.calendars],
    )
    return [AppleCalendarExternalCalendarOut(**it) for it in selected]


@integration_router.post("/import/initial", response_model=List[AppleCalendarImportRunOut])
async def start_apple_initial_import(
    body: AppleCalendarInitialImportIn,
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    runs = enqueue_apple_caldav_initial_import(
        user_sub=ctx["user_sub"],
        external_calendar_ids=body.external_calendar_ids,
        lookback_days=body.lookback_days,
        lookahead_days=body.lookahead_days,
    )
    return [AppleCalendarImportRunOut(**it) for it in runs]


@integration_router.post("/sync/now", response_model=AppleCalendarSyncNowOut)
async def sync_apple_now(
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    out = trigger_apple_caldav_sync_now(user_sub=ctx["user_sub"])
    return AppleCalendarSyncNowOut(**out)


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


def _share_key(user_sub: str) -> str:
    return f"share#{user_sub}"


def _access_partition(user_sub: str) -> str:
    return f"user#{user_sub}"


def _access_key(calendar_id: str) -> str:
    return f"calendar#{calendar_id}"


def _load_event(calendar_id: str, event_id: str) -> Dict[str, Any]:
    item = T.calendar.get_item(Key={"calendar_id": calendar_id, "sk": _event_key(event_id)}).get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Event not found")
    return item


def _load_booking_link(link_id: str) -> Dict[str, Any]:
    # First try: query by known calendar_id approach won't work without knowing calendar_id.
    # Use scan without Limit so all pages are checked.
    # Note: DynamoDB Limit on scan limits *examined* items, not returned items.
    # We must paginate to find the booking link across the whole table.
    sk_val = _booking_link_key(link_id)
    last_evaluated_key = None
    while True:
        scan_kwargs: Dict[str, Any] = {
            "FilterExpression": Attr("sk").eq(sk_val) & Attr("type").eq("booking_link"),
        }
        if last_evaluated_key:
            scan_kwargs["ExclusiveStartKey"] = last_evaluated_key
        response = T.calendar.scan(**scan_kwargs)
        items = response.get("Items", [])
        if items:
            return items[0]
        last_evaluated_key = response.get("LastEvaluatedKey")
        if not last_evaluated_key:
            break
    raise HTTPException(status_code=404, detail="Booking link not found")


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


def _serialize_working_hours(working_hours: Dict[str, Any] | None) -> Dict[str, list[Dict[str, str]]] | None:
    """Convert working_hours dict (possibly containing Pydantic models) to plain dicts for DynamoDB storage."""
    if working_hours is None:
        return None
    serialized: Dict[str, list[Dict[str, str]]] = {}
    for day, windows in working_hours.items():
        serialized[day] = []
        for window in windows:
            if hasattr(window, "model_dump"):
                serialized[day].append(window.model_dump())
            elif hasattr(window, "dict"):
                serialized[day].append(window.dict())
            elif isinstance(window, dict):
                serialized[day].append(window)
            else:
                serialized[day].append({"start": window.start, "end": window.end})
    return serialized


def _validate_working_hours(working_hours: Dict[str, Any] | None) -> None:
    if working_hours is None:
        return
    for day, windows in working_hours.items():
        if day not in WEEKDAY_NAMES:
            raise HTTPException(status_code=400, detail=f"Invalid weekday: {day}")
        for window in windows:
            # Support both Pydantic model instances and plain dicts
            if hasattr(window, "start") and hasattr(window, "end"):
                start_val = window.start
                end_val = window.end
            else:
                start_val = window["start"]
                end_val = window["end"]
            start = _parse_hhmm(start_val)
            end = _parse_hhmm(end_val)
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
    if rule.bymonthday:
        for day in rule.bymonthday:
            if day == 0 or day < -31 or day > 31:
                raise HTTPException(status_code=400, detail="Invalid bymonthday value")
    if rule.bysetpos:
        for pos in rule.bysetpos:
            if pos == 0 or pos < -31 or pos > 31:
                raise HTTPException(status_code=400, detail="Invalid bysetpos value")
    return rule


def _normalize_exdates(exdates: list[str] | None, tz_name: str) -> list[str] | None:
    if not exdates:
        return None
    _validate_timezone(tz_name)
    tz = ZoneInfo(tz_name)
    normalized: list[str] = []
    for value in exdates:
        if not value:
            continue
        try:
            parsed = parse_iso_dt(value)
        except HTTPException:
            try:
                parsed_date = parse_iso_date(value)
            except HTTPException:
                raise
            parsed = datetime(parsed_date.year, parsed_date.month, parsed_date.day, 0, 0, 0, tzinfo=tz).astimezone(timezone.utc)
        normalized.append(iso_utc(parsed))
    return sorted(set(normalized))


def _normalize_occurrence_override(calendar_tz: str, override: EventOccurrenceOverrideIn) -> Dict[str, Any]:
    tz_name = override.timezone or calendar_tz
    _validate_timezone(tz_name)
    normalized: Dict[str, Any] = {
        "name": override.name,
        "description": override.description,
        "timezone": tz_name,
        "status": override.status,
        "category": override.category,
    }
    if override.all_day is not None:
        normalized["all_day"] = override.all_day
    if override.all_day_date:
        _ = parse_iso_date(override.all_day_date)
        normalized["all_day_date"] = override.all_day_date
    if normalized.get("all_day") and not normalized.get("all_day_date"):
        raise HTTPException(status_code=400, detail="all_day_date is required for all-day overrides")
    if override.start_utc:
        normalized["start_utc"] = iso_utc(parse_iso_dt(override.start_utc))
    if override.end_utc:
        normalized["end_utc"] = iso_utc(parse_iso_dt(override.end_utc))
    if normalized.get("start_utc") and normalized.get("end_utc"):
        start = parse_iso_dt(normalized["start_utc"])
        end = parse_iso_dt(normalized["end_utc"])
        if end <= start:
            raise HTTPException(status_code=400, detail="end_utc must be after start_utc")
    return {k: v for k, v in normalized.items() if v is not None}


def _normalize_overrides(
    overrides: Dict[str, EventOccurrenceOverrideIn] | None,
    calendar_tz: str,
) -> Dict[str, Dict[str, Any]] | None:
    if not overrides:
        return None
    normalized: Dict[str, Dict[str, Any]] = {}
    for key, value in overrides.items():
        if not key:
            continue
        occ_key = iso_utc(parse_iso_dt(key))
        normalized[occ_key] = _normalize_occurrence_override(calendar_tz, value)
    return normalized or None


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
        def month_last_day(year: int, month: int) -> int:
            next_month = datetime(year + (month // 12), ((month % 12) + 1), 1, tzinfo=timezone.utc)
            last_day = (next_month - timedelta(days=1)).day
            return last_day

        def add_months(year: int, month: int, months: int) -> tuple[int, int]:
            total = (year * 12 + (month - 1)) + months
            return total // 12, total % 12 + 1

        def candidate_dates(year: int, month: int) -> list[date]:
            last_day = month_last_day(year, month)
            if rrule.bymonthday:
                days: list[int] = []
                for day in rrule.bymonthday:
                    if day > 0 and day <= last_day:
                        days.append(day)
                    elif day < 0:
                        target = last_day + day + 1
                        if target >= 1:
                            days.append(target)
                return [date(year, month, d) for d in sorted(set(days))]
            bydays = rrule.byday or [list(RRULE_WEEKDAY_MAP.keys())[series_start_utc.weekday()]]
            weekday_idxs = sorted({RRULE_WEEKDAY_MAP[d] for d in bydays})
            dates = [
                date(year, month, day)
                for day in range(1, last_day + 1)
                if date(year, month, day).weekday() in weekday_idxs
            ]
            if rrule.bysetpos:
                selected: list[date] = []
                for pos in rrule.bysetpos:
                    if pos > 0 and pos <= len(dates):
                        selected.append(dates[pos - 1])
                    elif pos < 0 and abs(pos) <= len(dates):
                        selected.append(dates[pos])
                return selected
            return dates

        start_year = series_start_utc.year
        start_month = series_start_utc.month
        month_offset = 0
        while True:
            year, month = add_months(start_year, start_month, month_offset)
            for cand in candidate_dates(year, month):
                occ_start = datetime(
                    cand.year,
                    cand.month,
                    cand.day,
                    series_start_utc.hour,
                    series_start_utc.minute,
                    series_start_utc.second,
                    series_start_utc.microsecond,
                    tzinfo=timezone.utc,
                )
                if occ_start < series_start_utc:
                    continue
                if until and occ_start > until:
                    return sorted(occs, key=lambda x: x[0])
                if remaining is not None and remaining <= 0:
                    return sorted(occs, key=lambda x: x[0])
                occ_end = occ_start + duration
                if overlap(occ_start, occ_end, window_start, window_end):
                    occs.append((occ_start, occ_end))
                if remaining is not None:
                    remaining -= 1
            month_offset += rrule.interval
            if until and datetime(year, month, 1, tzinfo=timezone.utc) > until + timedelta(days=31):
                break
            if datetime(year, month, 1, tzinfo=timezone.utc) > window_end + timedelta(days=31):
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
    exdates = {str(value) for value in (event.get("exdates_utc") or [])}
    overrides = event.get("recurrence_overrides") or {}
    occurrences: list[Dict[str, Any]] = []
    for occ_start, occ_end in occs:
        occ_key = iso_utc(occ_start)
        if occ_key in exdates:
            continue
        occ = {**event}
        if event.get("all_day"):
            local_date = occ_start.astimezone(tz).date()
            occ["all_day_date"] = local_date.isoformat()
            occ["start_utc"] = None
            occ["end_utc"] = None
        else:
            occ["start_utc"] = iso_utc(occ_start)
            occ["end_utc"] = iso_utc(occ_end)
        override = overrides.get(occ_key)
        if isinstance(override, dict):
            occ.update(override)
        try:
            occ_interval = _event_time_interval(occ)
        except Exception:
            occ_interval = None
        if occ_interval:
            start, end = occ_interval
            if not overlap(start, end, window_start, window_end):
                continue
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


def _find_conflicts(
    calendar_id: str,
    normalized: Dict[str, Any],
    *,
    exclude_event_id: str | None = None,
) -> tuple[list[Dict[str, Any]], datetime, datetime]:
    requested_start, requested_end = _event_payload_interval(normalized)
    if not _is_busy_status(normalized.get("status", "busy")):
        return [], requested_start, requested_end
    conflicts: list[Dict[str, Any]] = []
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
                    conflicts.append(occ)
        else:
            interval = _event_to_busy_interval(event)
            if interval is None:
                continue
            start, end = interval
            if overlap(requested_start, requested_end, start, end):
                conflicts.append(event)
    return conflicts, requested_start, requested_end


def _suggest_slots(
    openings: list[tuple[datetime, datetime]],
    duration: timedelta,
    limit: int,
) -> list[tuple[datetime, datetime]]:
    suggestions: list[tuple[datetime, datetime]] = []
    for start, end in openings:
        if end - start < duration:
            continue
        suggestions.append((start, start + duration))
        if len(suggestions) >= limit:
            break
    return suggestions


def _load_calendar_access(calendar_id: str, user_sub: str, *, write: bool = False) -> Dict[str, Any]:
    meta = T.calendar.get_item(Key=_calendar_keys(calendar_id)).get("Item")
    if not meta:
        raise HTTPException(status_code=404, detail="Calendar not found")
    if meta.get("owner_user_sub") == user_sub:
        return meta
    share = T.calendar.get_item(Key={"calendar_id": calendar_id, "sk": _share_key(user_sub)}).get("Item")
    if not share:
        raise HTTPException(status_code=403, detail="Calendar access denied")
    permission = share.get("permission", "read")
    if write and permission != "write":
        raise HTTPException(status_code=403, detail="Calendar write access denied")
    return meta


def _require_calendar_owner(calendar_id: str, user_sub: str) -> Dict[str, Any]:
    meta = T.calendar.get_item(Key=_calendar_keys(calendar_id)).get("Item")
    if not meta:
        raise HTTPException(status_code=404, detail="Calendar not found")
    if meta.get("owner_user_sub") != user_sub:
        raise HTTPException(status_code=403, detail="Calendar owner access denied")
    return meta


def _calendar_access_item(user_sub: str, calendar_id: str, permission: str) -> Dict[str, Any]:
    return {
        "calendar_id": _access_partition(user_sub),
        "sk": _access_key(calendar_id),
        "type": "calendar_access",
        "target_calendar_id": calendar_id,
        "permission": permission,
        "created_at_utc": iso_utc(utc_now()),
    }


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


def _event_out(item: Dict[str, Any], calendar_id: str, user_sub: str | None = None) -> EventOut:
    sync_state = None
    sync_conflict_reason = None
    sync_conflict_detected_at_utc = None
    if user_sub:
        try:
            mapping = get_event_mapping(
                user_sub=user_sub,
                internal_calendar_id=calendar_id,
                internal_event_id=str(item.get("event_id") or ""),
                include_inactive=True,
            )
            sync_state = str(mapping.get("sync_state") or "ok")
            sync_conflict_reason = str(mapping.get("conflict_reason") or "") or None
            sync_conflict_detected_at_utc = str(mapping.get("conflict_detected_at_utc") or "") or None
        except HTTPException:
            pass
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
        exdates_utc=item.get("exdates_utc"),
        recurrence_overrides=item.get("recurrence_overrides"),
        created_at_utc=item.get("created_at_utc", ""),
        sync_state=sync_state,
        sync_conflict_reason=sync_conflict_reason,
        sync_conflict_detected_at_utc=sync_conflict_detected_at_utc,
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
        "working_hours": _serialize_working_hours(body.working_hours),
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


def _build_calendar_list(user_sub: str) -> list[CalendarAccessOut]:
    """Return all calendars accessible to the user (owned + shared)."""
    access_response = T.calendar.query(
        KeyConditionExpression=Key("calendar_id").eq(_access_partition(user_sub)) & Key("sk").begins_with("calendar#"),
        ScanIndexForward=True,
    )
    access_items = access_response.get("Items", [])
    access_by_calendar = {item.get("target_calendar_id"): item for item in access_items if item.get("target_calendar_id")}
    owner_scan = T.calendar.scan(
        FilterExpression=Attr("sk").eq("meta")
        & Attr("type").eq("calendar")
        & Attr("owner_user_sub").eq(user_sub)
    )
    for item in owner_scan.get("Items", []):
        calendar_id = item.get("calendar_id")
        if not calendar_id or calendar_id in access_by_calendar:
            continue
        access_item = _calendar_access_item(user_sub, calendar_id, "owner")
        access_by_calendar[calendar_id] = access_item
        T.calendar.put_item(Item=access_item)
    result: list[CalendarAccessOut] = []
    for calendar_id, access in access_by_calendar.items():
        if not calendar_id:
            continue
        meta = T.calendar.get_item(Key=_calendar_keys(calendar_id)).get("Item")
        if not meta:
            continue
        permission = access.get("permission", "read")
        result.append(
            CalendarAccessOut(
                calendar_id=calendar_id,
                name=meta.get("name", ""),
                timezone=meta.get("timezone", "UTC"),
                owner_user_id=meta.get("owner_user_sub", ""),
                permission=permission if permission in {"owner", "read", "write"} else "read",
            )
        )
    return result


def _create_default_calendar(user_sub: str) -> CalendarAccessOut:
    """Create and return a default 'My Calendar' for the user."""
    calendar_id = uuid.uuid4().hex
    now = iso_utc(utc_now())
    item = {
        "calendar_id": calendar_id,
        "sk": "meta",
        "type": "calendar",
        "name": "My Calendar",
        "timezone": "UTC",
        "conflict_detection": False,
        "working_hours": None,
        "buffer_before_minutes": 0,
        "buffer_after_minutes": 0,
        "owner_user_sub": user_sub,
        "created_at_utc": now,
    }
    T.calendar.put_item(Item=item)
    access_item = _calendar_access_item(user_sub, calendar_id, "owner")
    T.calendar.put_item(Item=access_item)
    return CalendarAccessOut(
        calendar_id=calendar_id,
        name="My Calendar",
        timezone="UTC",
        owner_user_id=user_sub,
        permission="owner",
    )


@router.get("/calendars", response_model=list[CalendarAccessOut])
async def list_calendars(ctx: Dict[str, str] = Depends(require_ui_session)):
    result = _build_calendar_list(ctx["user_sub"])
    if not result:
        result = [_create_default_calendar(ctx["user_sub"])]
    return result


@router.post("/calendar/integrations/google/connect/start", response_model=GoogleCalendarConnectStartOut)
async def google_calendar_connect_start(ctx: Dict[str, str] = Depends(require_ui_session)):
    user_sub = str(ctx.get("user_sub") or "")
    require_google_calendar_sync_enabled_for_user(user_sub)
    out = create_connect_start_state(user_sub=user_sub)
    emit_google_calendar_audit_event(
        event="google_calendar_connect_start",
        actor_user_sub=user_sub,
        outcome="success",
        target_type="connection",
        target_id="oauth_state",
        oauth_state=out.get("state"),
    )
    return GoogleCalendarConnectStartOut(**out)


@router.get("/calendar/integrations/google/connect/callback", response_model=GoogleCalendarConnectCallbackOut)
async def google_calendar_connect_callback(
    code: str | None = Query(default=None),
    state: str | None = Query(default=None),
    error: str | None = Query(default=None),
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    user_sub = str(ctx.get("user_sub") or "")
    require_google_calendar_sync_enabled_for_user(user_sub)

    if error:
        emit_google_calendar_audit_event(
            event="google_calendar_connect_callback",
            actor_user_sub=user_sub,
            outcome="failure",
            target_type="connection",
            target_id="oauth_callback",
            reason="authorization_denied",
        )
        raise HTTPException(status_code=400, detail="google authorization was denied")
    if not code or not state:
        emit_google_calendar_audit_event(
            event="google_calendar_connect_callback",
            actor_user_sub=user_sub,
            outcome="failure",
            target_type="connection",
            target_id="oauth_callback",
            reason="missing_callback_params",
        )
        raise HTTPException(status_code=400, detail="missing oauth callback parameters")
    try:
        out = handle_connect_callback(user_sub=user_sub, state=state, code=code)
    except HTTPException:
        emit_google_calendar_audit_event(
            event="google_calendar_connect_callback",
            actor_user_sub=user_sub,
            outcome="failure",
            target_type="connection",
            target_id="oauth_callback",
            reason="callback_processing_failed",
        )
        raise
    emit_google_calendar_audit_event(
        event="google_calendar_connect_callback",
        actor_user_sub=user_sub,
        outcome="success",
        target_type="connection",
        target_id=str(out.get("connection_id") or "google-primary"),
        account_email=str(out.get("account_email") or ""),
    )
    return GoogleCalendarConnectCallbackOut(**out)


@router.post("/calendar/integrations/google/disconnect", response_model=GoogleCalendarDisconnectOut)
async def google_calendar_disconnect(
    connection_id: str | None = Query(default=None),
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    user_sub = str(ctx.get("user_sub") or "")
    require_google_calendar_sync_enabled_for_user(user_sub)
    resolved_connection_id = connection_id or str(getattr(S, "google_calendar_connection_default_id", "google-primary") or "google-primary")
    try:
        out = handle_disconnect(user_sub=user_sub, connection_id=resolved_connection_id)
    except HTTPException:
        emit_google_calendar_audit_event(
            event="google_calendar_disconnect",
            actor_user_sub=user_sub,
            outcome="failure",
            target_type="connection",
            target_id=resolved_connection_id,
        )
        raise
    emit_google_calendar_audit_event(
        event="google_calendar_disconnect",
        actor_user_sub=user_sub,
        outcome="success",
        target_type="connection",
        target_id=resolved_connection_id,
        revoked=bool(out.get("revoked")),
        revoke_status=str(out.get("revoke_status") or ""),
    )
    return GoogleCalendarDisconnectOut(**out)


@router.get("/calendar/integrations/google/status", response_model=GoogleCalendarIntegrationStatusOut)
async def google_calendar_integration_status(ctx: Dict[str, str] = Depends(require_ui_session)):
    user_sub = str(ctx.get("user_sub") or "")
    require_google_calendar_sync_enabled_for_user(user_sub)
    connection_id = str(getattr(S, "google_calendar_connection_default_id", "google-primary") or "google-primary")
    connection = None
    try:
        connection = get_calendar_provider_connection(
            user_sub=user_sub,
            connection_id=connection_id,
            include_tokens=False,
            include_inactive=True,
        )
    except HTTPException:
        connection = None
    return GoogleCalendarIntegrationStatusOut(
        sync_enabled=True,
        writeback_enabled=is_google_calendar_writeback_enabled_for_user(user_sub),
        rollout_mode=rollout_mode(),
        rollout_percent=rollout_percent(),
        in_rollout_cohort=is_google_calendar_sync_enabled_for_user(user_sub),
        connection_active=bool((connection or {}).get("active", False)),
        sync_health=str((connection or {}).get("sync_health") or "unknown"),
        last_sync_status=str((connection or {}).get("last_sync_status") or "never_synced"),
        last_sync_at_utc=str((connection or {}).get("last_sync_at_utc") or ""),
        reauth_required=bool((connection or {}).get("reauth_required", False)),
    )


@router.get("/calendar/integrations/google/calendars", response_model=GoogleCalendarProviderCalendarsOut)
async def google_calendar_provider_calendars(ctx: Dict[str, str] = Depends(require_ui_session)):
    user_sub = str(ctx.get("user_sub") or "")
    require_google_calendar_sync_enabled_for_user(user_sub)
    connection_id = str(getattr(S, "google_calendar_connection_default_id", "google-primary") or "google-primary")
    provider = list_google_calendars(user_sub=user_sub, connection_id=connection_id)
    mappings = list_calendar_provider_mappings(user_sub=user_sub, include_inactive=False)
    mapped_by_google = {
        str(m.get("google_calendar_id") or ""): str(m.get("internal_calendar_id") or "")
        for m in mappings
        if bool(m.get("active", True))
    }
    out = []
    for item in provider.get("items") or []:
        gcal_id = str(item.get("id") or "")
        out.append(
            GoogleCalendarProviderCalendarOut(
                google_calendar_id=gcal_id,
                summary=str(item.get("summary") or item.get("id") or ""),
                access_role=str(item.get("accessRole") or ""),
                primary=bool(item.get("primary", False)),
                mapped_internal_calendar_id=mapped_by_google.get(gcal_id),
            )
        )
    return GoogleCalendarProviderCalendarsOut(calendars=out)


@router.post("/calendar/integrations/google/mappings", response_model=GoogleCalendarMappingOut)
async def google_calendar_create_mapping(
    body: GoogleCalendarMappingCreateIn,
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    user_sub = str(ctx.get("user_sub") or "")
    require_google_calendar_sync_enabled_for_user(user_sub)
    created = create_calendar_provider_mapping(
        user_sub=user_sub,
        internal_calendar_id=body.internal_calendar_id,
        google_calendar_id=body.google_calendar_id,
    )
    return GoogleCalendarMappingOut(**created)


@router.post("/calendar/integrations/google/sync/run", response_model=GoogleCalendarSyncRunOut)
async def google_calendar_manual_sync_run(
    mode: str = Query(default="incremental"),
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    user_sub = str(ctx.get("user_sub") or "")
    require_google_calendar_sync_enabled_for_user(user_sub)
    # Reuse existing privileged-action limiter to prevent abuse.
    rate_limit_admin_action(user_sub, "google_calendar_sync_run")

    connection_id = str(getattr(S, "google_calendar_connection_default_id", "google-primary") or "google-primary")
    resolved_mode = "full" if str(mode).lower().strip() == "full" else "incremental"
    try:
        if resolved_mode == "full":
            metrics = run_google_calendar_full_import_job(user_sub=user_sub, connection_id=connection_id)
        else:
            metrics = run_google_calendar_incremental_sync_job(user_sub=user_sub, connection_id=connection_id)
    except HTTPException as exc:
        emit_google_calendar_audit_event(
            event="google_calendar_manual_sync_run",
            actor_user_sub=user_sub,
            outcome="failure",
            target_type="connection",
            target_id=connection_id,
            mode=resolved_mode,
            reason=str(exc.detail),
        )
        raise
    audit_event(
        "google_calendar_manual_sync_run",
        user_sub,
        None,
        outcome="success",
        mode=resolved_mode,
        connection_id=connection_id,
        processed=int(metrics.get("calendars_processed") or 0),
        errors=int(metrics.get("errors") or 0),
    )
    emit_google_calendar_audit_event(
        event="google_calendar_manual_sync_run",
        actor_user_sub=user_sub,
        outcome="success",
        target_type="connection",
        target_id=connection_id,
        mode=resolved_mode,
        processed=int(metrics.get("calendars_processed") or 0),
        errors=int(metrics.get("errors") or 0),
    )
    return GoogleCalendarSyncRunOut(accepted=True, mode=resolved_mode, rate_limited=False, metrics=metrics)


@router.post("/calendars/{calendar_id}/shares", response_model=CalendarShareOut)
async def share_calendar(
    calendar_id: str,
    body: CalendarShareIn,
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    _require_calendar_owner(calendar_id, ctx["user_sub"])
    if body.user_sub == ctx["user_sub"]:
        raise HTTPException(status_code=400, detail="Cannot share a calendar with yourself")
    now = iso_utc(utc_now())
    item = {
        "calendar_id": calendar_id,
        "sk": _share_key(body.user_sub),
        "type": "calendar_share",
        "user_sub": body.user_sub,
        "permission": body.permission,
        "created_at_utc": now,
        "granted_by": ctx["user_sub"],
    }
    T.calendar.put_item(Item=item)
    T.calendar.put_item(Item=_calendar_access_item(body.user_sub, calendar_id, body.permission))
    audit_event(
        "calendar_share_create",
        ctx["user_sub"],
        None,
        outcome="success",
        calendar_id=calendar_id,
        shared_with=body.user_sub,
        permission=body.permission,
    )
    return CalendarShareOut(
        calendar_id=calendar_id,
        user_sub=body.user_sub,
        permission=body.permission,
        created_at_utc=now,
    )


@router.get("/calendars/{calendar_id}/shares", response_model=list[CalendarShareOut])
async def list_calendar_shares(
    calendar_id: str,
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    _require_calendar_owner(calendar_id, ctx["user_sub"])
    response = T.calendar.query(
        KeyConditionExpression=Key("calendar_id").eq(calendar_id) & Key("sk").begins_with("share#"),
        ScanIndexForward=True,
    )
    items = response.get("Items", [])
    return [
        CalendarShareOut(
            calendar_id=calendar_id,
            user_sub=item.get("user_sub", ""),
            permission=item.get("permission", "read"),
            created_at_utc=item.get("created_at_utc", ""),
        )
        for item in items
    ]


@router.delete("/calendars/{calendar_id}/shares/{user_sub}")
async def delete_calendar_share(
    calendar_id: str,
    user_sub: str,
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    _require_calendar_owner(calendar_id, ctx["user_sub"])
    T.calendar.delete_item(Key={"calendar_id": calendar_id, "sk": _share_key(user_sub)})
    T.calendar.delete_item(Key={"calendar_id": _access_partition(user_sub), "sk": _access_key(calendar_id)})
    audit_event(
        "calendar_share_delete",
        ctx["user_sub"],
        None,
        outcome="success",
        calendar_id=calendar_id,
        shared_with=user_sub,
    )
    return {"ok": True}


@router.post("/calendars/{calendar_id}/events/conflicts", response_model=EventConflictPreviewOut)
async def preview_event_conflicts(
    calendar_id: str,
    body: EventConflictPreviewIn,
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    meta = _load_calendar_access(calendar_id, ctx["user_sub"], write=True)
    _validate_booking_settings(body.booking_enabled, body.approval_required)
    status = _normalize_event_status(body.status)
    recurrence_rule = _normalize_recurrence_rule(body.recurrence_rule)
    normalized = _normalize_event_times(meta["timezone"], body)
    normalized["status"] = status
    event_snapshot = {
        "all_day": normalized["all_day"],
        "timezone": normalized["timezone"],
        "all_day_date": normalized["all_day_date"],
        "start_utc": normalized["start_utc"],
        "end_utc": normalized["end_utc"],
    }
    requested_start, requested_end = _event_time_interval(event_snapshot)
    conflicts: list[Dict[str, Any]] = []
    if _is_busy_status(status):
        conflicts, requested_start, requested_end = _find_conflicts(
            calendar_id,
            normalized,
            exclude_event_id=body.event_id,
        )
    return EventConflictPreviewOut(
        requested_start_utc=iso_utc(requested_start),
        requested_end_utc=iso_utc(requested_end),
        timezone=normalized["timezone"],
        conflicts=[_event_out(item, calendar_id, user_sub=ctx["user_sub"]) for item in conflicts],
    )


@router.post("/calendars/{calendar_id}/events/suggestions", response_model=list[OpeningsOut])
async def suggest_event_slots(
    calendar_id: str,
    body: EventSuggestionsIn,
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    meta = _load_calendar_access(calendar_id, ctx["user_sub"], write=True)
    start_dt = parse_iso_dt(body.start_utc)
    end_dt = parse_iso_dt(body.end_utc)
    if end_dt <= start_dt:
        raise HTTPException(status_code=400, detail="end_utc must be after start_utc")
    duration_minutes = body.duration_minutes
    if duration_minutes is None:
        duration_minutes = int((end_dt - start_dt).total_seconds() / 60)
    if duration_minutes <= 0:
        raise HTTPException(status_code=400, detail="duration_minutes must be positive")
    window_end = start_dt + timedelta(days=body.window_days or 7)
    if window_end <= start_dt:
        raise HTTPException(status_code=400, detail="window_days must be positive")
    openings = _calendar_openings(meta, start_dt, window_end)
    suggestions = _suggest_slots(openings, timedelta(minutes=duration_minutes), body.limit or 5)
    return [OpeningsOut(start_utc=iso_utc(s), end_utc=iso_utc(e)) for s, e in suggestions]


@router.post("/calendars/{calendar_id}/events/{event_id}/occurrences/{occurrence_start}/exclude", response_model=EventOut)
async def exclude_event_occurrence(
    calendar_id: str,
    event_id: str,
    occurrence_start: str,
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    _load_calendar_access(calendar_id, ctx["user_sub"], write=True)
    item = _load_event(calendar_id, event_id)
    occ_key = iso_utc(parse_iso_dt(occurrence_start))
    exdates = _normalize_exdates(item.get("exdates_utc") or [], item.get("timezone", "UTC")) or []
    if occ_key not in exdates:
        exdates.append(occ_key)
    updated = {**item, "exdates_utc": sorted(set(exdates))}
    T.calendar.put_item(Item=updated)
    return _event_out(updated, calendar_id, user_sub=ctx["user_sub"])


@router.post("/calendars/{calendar_id}/events/{event_id}/occurrences/{occurrence_start}/override", response_model=EventOut)
async def override_event_occurrence(
    calendar_id: str,
    event_id: str,
    occurrence_start: str,
    body: EventOccurrenceOverrideIn,
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    _load_calendar_access(calendar_id, ctx["user_sub"], write=True)
    item = _load_event(calendar_id, event_id)
    occ_key = iso_utc(parse_iso_dt(occurrence_start))
    overrides = item.get("recurrence_overrides") or {}
    overrides[occ_key] = _normalize_occurrence_override(item.get("timezone", "UTC"), body)
    updated = {**item, "recurrence_overrides": overrides}
    T.calendar.put_item(Item=updated)
    return _event_out(updated, calendar_id, user_sub=ctx["user_sub"])


@router.delete("/calendars/{calendar_id}/events/{event_id}/occurrences/{occurrence_start}", response_model=EventOut)
async def clear_event_occurrence_exception(
    calendar_id: str,
    event_id: str,
    occurrence_start: str,
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    _load_calendar_access(calendar_id, ctx["user_sub"], write=True)
    item = _load_event(calendar_id, event_id)
    occ_key = iso_utc(parse_iso_dt(occurrence_start))
    exdates = _normalize_exdates(item.get("exdates_utc") or [], item.get("timezone", "UTC")) or []
    overrides = item.get("recurrence_overrides") or {}
    if occ_key in exdates:
        exdates = [value for value in exdates if value != occ_key]
    if occ_key in overrides:
        overrides.pop(occ_key, None)
    updated = {**item, "exdates_utc": exdates or None, "recurrence_overrides": overrides or None}
    T.calendar.put_item(Item=updated)
    return _event_out(updated, calendar_id, user_sub=ctx["user_sub"])


@router.post("/calendars/{calendar_id}/events", response_model=EventOut)
async def create_event(
    calendar_id: str,
    body: EventCreateIn,
    force: bool = Query(False, description="Allow conflicts when true"),
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    meta = _load_calendar_access(calendar_id, ctx["user_sub"], write=True)
    _validate_booking_settings(body.booking_enabled, body.approval_required)
    status = _normalize_event_status(body.status)
    recurrence_rule = _normalize_recurrence_rule(body.recurrence_rule)
    normalized = _normalize_event_times(meta["timezone"], body)
    normalized["status"] = status
    exdates = _normalize_exdates(body.exdates_utc, normalized["timezone"])
    overrides = _normalize_overrides(body.recurrence_overrides, normalized["timezone"])
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
        "exdates_utc": exdates,
        "recurrence_overrides": overrides,
        "created_at_utc": now,
        "updated_at_utc": now,
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
    enqueue_google_calendar_outbound_sync_job(
        owner_user_sub=str(meta.get("owner_user_sub") or ctx["user_sub"]),
        actor_user_sub=ctx["user_sub"],
        action="create",
        internal_calendar_id=calendar_id,
        internal_event_id=event_id,
        event_snapshot=item,
        source="calendar_event_create",
    )
    return _event_out(item, calendar_id, user_sub=ctx["user_sub"])


@router.post("/calendars/{calendar_id}/booking_links", response_model=BookingLinkOut)
async def create_booking_link(
    calendar_id: str,
    body: BookingLinkCreateIn,
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    meta = _load_calendar_access(calendar_id, ctx["user_sub"], write=True)
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


@router.get("/calendars/{calendar_id}/booking_links", response_model=list[BookingLinkOut])
async def list_booking_links(
    calendar_id: str,
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    _load_calendar_access(calendar_id, ctx["user_sub"])
    response = T.calendar.query(
        KeyConditionExpression=Key("calendar_id").eq(calendar_id) & Key("sk").begins_with("booking#"),
        ScanIndexForward=True,
    )
    items = response.get("Items", [])
    return [
        BookingLinkOut(
            link_id=item["link_id"],
            calendar_id=calendar_id,
            name=item.get("name", ""),
            duration_minutes=int(item.get("duration_minutes", 0)),
            timezone=item.get("timezone", "UTC"),
            created_at_utc=item.get("created_at_utc", ""),
            public_url=f"/booking/{item['link_id']}",
        )
        for item in items
    ]


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
    _load_calendar_access(calendar_id, ctx["user_sub"])
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
        events=[_event_out(item, calendar_id, user_sub=ctx["user_sub"]) for item in items],
        next_cursor=next_cursor,
    )


@router.patch("/calendars/{calendar_id}", response_model=CalendarOut)
async def update_calendar(
    calendar_id: str,
    body: CalendarUpdateIn,
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    meta = _require_calendar_owner(calendar_id, ctx["user_sub"])
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
    working_hours = _serialize_working_hours(working_hours)
    updated = {
        **meta,
        "name": name,
        "timezone": timezone_name,
        "conflict_detection": conflict_detection,
        "working_hours": working_hours,
        "buffer_before_minutes": buffer_before,
        "buffer_after_minutes": buffer_after,
    }
    updated["updated_at_utc"] = iso_utc(utc_now())
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
    meta = _load_calendar_access(calendar_id, ctx["user_sub"], write=True)
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
        exdates_utc=body.exdates_utc if body.exdates_utc is not None else item.get("exdates_utc"),
        recurrence_overrides=(
            body.recurrence_overrides if body.recurrence_overrides is not None else item.get("recurrence_overrides")
        ),
    )
    _validate_booking_settings(payload.booking_enabled, payload.approval_required)
    status = _normalize_event_status(payload.status)
    recurrence_rule = _normalize_recurrence_rule(payload.recurrence_rule)
    normalized = _normalize_event_times(meta["timezone"], payload)
    normalized["status"] = status
    exdates = _normalize_exdates(payload.exdates_utc, normalized["timezone"])
    overrides = _normalize_overrides(payload.recurrence_overrides, normalized["timezone"])
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
        "exdates_utc": exdates,
        "recurrence_overrides": overrides,
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
    enqueue_google_calendar_outbound_sync_job(
        owner_user_sub=str(meta.get("owner_user_sub") or ctx["user_sub"]),
        actor_user_sub=ctx["user_sub"],
        action="update",
        internal_calendar_id=calendar_id,
        internal_event_id=event_id,
        event_snapshot=updated,
        source="calendar_event_update",
    )
    return _event_out(updated, calendar_id, user_sub=ctx["user_sub"])


@router.delete("/calendars/{calendar_id}/events/{event_id}")
async def delete_event(
    calendar_id: str,
    event_id: str,
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    meta = _load_calendar_access(calendar_id, ctx["user_sub"], write=True)
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
    delete_snapshot = {
        "event_id": event_id,
        "calendar_id": calendar_id,
        "status": item.get("status", "busy"),
        "start_utc": item.get("start_utc"),
        "end_utc": item.get("end_utc"),
        "all_day": item.get("all_day", False),
        "all_day_date": item.get("all_day_date"),
        "updated_at_utc": iso_utc(utc_now()),
    }
    enqueue_google_calendar_outbound_sync_job(
        owner_user_sub=str(meta.get("owner_user_sub") or ctx["user_sub"]),
        actor_user_sub=ctx["user_sub"],
        action="delete",
        internal_calendar_id=calendar_id,
        internal_event_id=event_id,
        event_snapshot=delete_snapshot,
        source="calendar_event_delete",
    )
    return {"ok": True}


@router.delete("/calendars/{calendar_id}")
async def delete_calendar(calendar_id: str, ctx: Dict[str, str] = Depends(require_ui_session)):
    _require_calendar_owner(calendar_id, ctx["user_sub"])
    events, _ = _list_events(calendar_id)
    share_response = T.calendar.query(
        KeyConditionExpression=Key("calendar_id").eq(calendar_id) & Key("sk").begins_with("share#"),
        ScanIndexForward=True,
    )
    shares = share_response.get("Items", [])
    with T.calendar.batch_writer() as batch:
        batch.delete_item(Key={"calendar_id": calendar_id, "sk": "meta"})
        for event in events:
            event_sk = event.get("sk") or _event_key(event["event_id"])
            batch.delete_item(Key={"calendar_id": calendar_id, "sk": event_sk})
        for share in shares:
            user_sub = share.get("user_sub")
            if user_sub:
                batch.delete_item(Key={"calendar_id": _access_partition(user_sub), "sk": _access_key(calendar_id)})
            batch.delete_item(Key={"calendar_id": calendar_id, "sk": share.get("sk")})
        batch.delete_item(Key={"calendar_id": _access_partition(ctx["user_sub"]), "sk": _access_key(calendar_id)})
    return {"ok": True}


@router.get("/calendars/{calendar_id}/openings", response_model=list[OpeningsOut])
async def list_openings(
    calendar_id: str,
    start_utc: str = Query(..., description="Start window in ISO-8601 UTC"),
    end_utc: str = Query(..., description="End window in ISO-8601 UTC"),
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    window_start, window_end = parse_availability_window(start_utc, end_utc)
    meta = _load_calendar_access(calendar_id, ctx["user_sub"])
    free = _calendar_openings(meta, window_start, window_end)
    return [OpeningsOut(start_utc=iso_utc(s), end_utc=iso_utc(e)) for s, e in free]


@router.post("/calendars/availability", response_model=list[OpeningsOut])
async def list_team_openings(body: TeamAvailabilityIn, ctx: Dict[str, str] = Depends(require_ui_session)):
    window_start, window_end = parse_availability_window(body.start_utc, body.end_utc)
    if not body.calendar_ids:
        raise HTTPException(status_code=400, detail="calendar_ids is required")
    combined: list[tuple[datetime, datetime]] | None = None
    for calendar_id in body.calendar_ids:
        meta = _load_calendar_access(calendar_id, ctx["user_sub"])
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
    return _event_out(item, meta["calendar_id"], user_sub=ctx["user_sub"])


# ─── iCal helper ─────────────────────────────────────────────────

def _build_ics(evt: dict, event_id: str) -> str:
    """Build an iCalendar (.ics) file string from an event dict."""
    def fmt_dt(s: str) -> str:
        dt = parse_iso_dt(s).astimezone(timezone.utc)
        return dt.strftime("%Y%m%dT%H%M%SZ")

    lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//TestLogon//EN",
        "CALSCALE:GREGORIAN",
        "BEGIN:VEVENT",
        f"UID:{event_id}@testlogon",
    ]
    if evt.get("all_day") and evt.get("all_day_date"):
        d = evt["all_day_date"].replace("-", "")
        end_d = (date.fromisoformat(evt["all_day_date"]) + timedelta(days=1)).strftime("%Y%m%d")
        lines += [f"DTSTART;VALUE=DATE:{d}", f"DTEND;VALUE=DATE:{end_d}"]
    elif evt.get("start_utc"):
        lines.append(f"DTSTART:{fmt_dt(evt['start_utc'])}")
        if evt.get("end_utc"):
            lines.append(f"DTEND:{fmt_dt(evt['end_utc'])}")
    lines.append(f"SUMMARY:{evt.get('name', '')}")
    if evt.get("description"):
        lines.append(f"DESCRIPTION:{evt['description'].replace(chr(10), chr(92) + 'n')}")
    lines += ["END:VEVENT", "END:VCALENDAR"]
    return "\r\n".join(lines) + "\r\n"


# ─── Public event endpoints (no auth) ───────────────────────────

@public_event_router.get("/event/{calendar_id}/{event_id}")
def get_public_event(calendar_id: str, event_id: str):
    evt = T.calendar.get_item(Key={"calendar_id": calendar_id, "sk": f"event#{event_id}"}).get("Item")
    if not evt:
        raise HTTPException(404, "Event not found")
    return {
        "event_id": evt.get("event_id") or event_id,
        "calendar_id": calendar_id,
        "name": evt.get("name"),
        "start_utc": evt.get("start_utc"),
        "end_utc": evt.get("end_utc"),
        "all_day": bool(evt.get("all_day", False)),
        "all_day_date": evt.get("all_day_date"),
        "timezone": evt.get("timezone", "UTC"),
        "description": evt.get("description"),
    }


@public_event_router.get("/event/{calendar_id}/{event_id}/ical")
def download_public_ical(calendar_id: str, event_id: str):
    from fastapi.responses import Response
    evt = T.calendar.get_item(Key={"calendar_id": calendar_id, "sk": f"event#{event_id}"}).get("Item")
    if not evt:
        raise HTTPException(404, "Event not found")
    ics = _build_ics(evt, event_id)
    safe = "".join(c for c in evt.get("name", "event") if c.isalnum() or c in " -_")[:40].strip()
    return Response(
        content=ics,
        media_type="text/calendar",
        headers={"Content-Disposition": f'attachment; filename="{safe or "event"}.ics"'},
    )


# ─── Authenticated iCal download ────────────────────────────────

@router.get("/calendars/{calendar_id}/events/{event_id}/ical")
async def download_event_ical(
    calendar_id: str,
    event_id: str,
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    from fastapi.responses import Response
    _load_calendar_access(calendar_id, ctx["user_sub"])
    evt = T.calendar.get_item(Key={"calendar_id": calendar_id, "sk": f"event#{event_id}"}).get("Item")
    if not evt:
        raise HTTPException(404, "Event not found")
    ics = _build_ics(evt, event_id)
    safe = "".join(c for c in evt.get("name", "event") if c.isalnum() or c in " -_")[:40].strip()
    return Response(
        content=ics,
        media_type="text/calendar",
        headers={"Content-Disposition": f'attachment; filename="{safe or "event"}.ics"'},
    )
