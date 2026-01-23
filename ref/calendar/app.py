import os
import uuid
from datetime import datetime, date, timedelta, timezone
from typing import Optional, List, Dict, Any, Literal, Tuple, Set

import boto3
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key

from fastapi import FastAPI, Header, HTTPException, Depends, Query
from pydantic import BaseModel, Field

try:
    from zoneinfo import ZoneInfo
except ImportError:
    ZoneInfo = None


# =============================================================================
# Config
# =============================================================================
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
SCHED_TABLE = os.environ.get("SCHED_TABLE", "")
if not SCHED_TABLE:
    raise RuntimeError("Missing env var SCHED_TABLE")

ddb = boto3.resource("dynamodb", region_name=AWS_REGION)
tbl = ddb.Table(SCHED_TABLE)

app = FastAPI(title="Scheduling API (FastAPI + DynamoDB)")


# =============================================================================
# Auth helper
# =============================================================================
def get_user_id(x_user_id: Optional[str] = Header(default=None, alias="X-User-Id")) -> str:
    if not x_user_id:
        raise HTTPException(status_code=401, detail="Missing X-User-Id header")
    return x_user_id


# =============================================================================
# Time helpers
# =============================================================================
def _require_zoneinfo():
    if ZoneInfo is None:
        raise HTTPException(status_code=500, detail="zoneinfo not available. Use Python 3.9+.")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_iso_dt(s: str) -> datetime:
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        raise HTTPException(status_code=400, detail=f"Invalid datetime: {s}")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def parse_iso_date(s: str) -> date:
    try:
        return date.fromisoformat(s)
    except Exception:
        raise HTTPException(status_code=400, detail=f"Invalid date: {s}")


def overlap(a0: datetime, a1: datetime, b0: datetime, b1: datetime) -> bool:
    return a0 < b1 and b0 < a1


def merge_intervals(intervals: List[Tuple[datetime, datetime]]) -> List[Tuple[datetime, datetime]]:
    if not intervals:
        return []
    intervals = sorted(intervals, key=lambda x: x[0])
    out = [intervals[0]]
    for s, e in intervals[1:]:
        ps, pe = out[-1]
        if s <= pe:
            out[-1] = (ps, max(pe, e))
        else:
            out.append((s, e))
    return out


def invert_intervals(busy: List[Tuple[datetime, datetime]], start: datetime, end: datetime) -> List[Tuple[datetime, datetime]]:
    busy = merge_intervals([(max(s, start), min(e, end)) for s, e in busy if overlap(s, e, start, end)])
    free: List[Tuple[datetime, datetime]] = []
    cur = start
    for s, e in busy:
        if cur < s:
            free.append((cur, s))
        cur = max(cur, e)
    if cur < end:
        free.append((cur, end))
    return free


# =============================================================================
# DynamoDB keys + helpers
# =============================================================================
def pk_cal(calendar_id: str) -> str:
    return f"CAL#{calendar_id}"


def sk_meta() -> str:
    return "META"


def sk_mem(user_id: str) -> str:
    return f"MEM#{user_id}"


def sk_evt(event_id: str) -> str:
    return f"EVT#{event_id}"


def sk_ser(series_id: str) -> str:
    return f"SER#{series_id}"


def sk_ovr(series_id: str, occ_start_utc: str) -> str:
    return f"OVR#{series_id}#{occ_start_utc}"


def pk_usr(user_id: str) -> str:
    return f"USR#{user_id}"


def sk_profile() -> str:
    return "PROFILE"


def sk_inv(calendar_id: str, kind: str, obj_id: str) -> str:
    return f"INV#{calendar_id}#{kind}#{obj_id}"


def ddb_put_item(item: Dict[str, Any]) -> None:
    try:
        tbl.put_item(Item=item)
    except ClientError as e:
        msg = e.response.get("Error", {}).get("Message", str(e))
        raise HTTPException(status_code=500, detail=f"DynamoDB error: {msg}")


def ddb_get_item(PK: str, SK: str) -> Optional[Dict[str, Any]]:
    try:
        resp = tbl.get_item(Key={"PK": PK, "SK": SK})
    except ClientError as e:
        msg = e.response.get("Error", {}).get("Message", str(e))
        raise HTTPException(status_code=500, detail=f"DynamoDB error: {msg}")
    return resp.get("Item")


def ddb_delete_item(PK: str, SK: str) -> None:
    try:
        tbl.delete_item(Key={"PK": PK, "SK": SK})
    except ClientError as e:
        msg = e.response.get("Error", {}).get("Message", str(e))
        raise HTTPException(status_code=500, detail=f"DynamoDB error: {msg}")


def ddb_query_pk(PK_value: str) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    eks = None
    while True:
        kwargs = {"KeyConditionExpression": Key("PK").eq(PK_value)}
        if eks:
            kwargs["ExclusiveStartKey"] = eks
        try:
            resp = tbl.query(**kwargs)
        except ClientError as e:
            msg = e.response.get("Error", {}).get("Message", str(e))
            raise HTTPException(status_code=500, detail=f"DynamoDB error: {msg}")
        items.extend(resp.get("Items", []))
        eks = resp.get("LastEvaluatedKey")
        if not eks:
            break
    return items


def require_calendar_access(calendar_id: str, user_id: str) -> Dict[str, Any]:
    meta = ddb_get_item(pk_cal(calendar_id), sk_meta())
    if not meta or meta.get("type") != "calendar":
        raise HTTPException(status_code=404, detail="Calendar not found")

    if meta["owner_user_id"] == user_id:
        return {"meta": meta, "role": "owner"}

    mem = ddb_get_item(pk_cal(calendar_id), sk_mem(user_id))
    if not mem:
        raise HTTPException(status_code=403, detail="No access to calendar")
    return {"meta": meta, "role": mem.get("role", "viewer")}


def require_editor(calendar_id: str, user_id: str) -> Dict[str, Any]:
    info = require_calendar_access(calendar_id, user_id)
    if info["role"] not in ("owner", "editor"):
        raise HTTPException(status_code=403, detail="Editor access required")
    return info


# =============================================================================
# RRULE (minimal subset)
# =============================================================================
class RRule(BaseModel):
    freq: Literal["DAILY", "WEEKLY", "MONTHLY"]
    interval: int = Field(default=1, ge=1)
    until_utc: Optional[str] = None
    count: Optional[int] = Field(default=None, ge=1)
    byday: Optional[List[Literal["MO", "TU", "WE", "TH", "FR", "SA", "SU"]]] = None


WEEKDAY_MAP = {"MO": 0, "TU": 1, "WE": 2, "TH": 3, "FR": 4, "SA": 5, "SU": 6}


def expand_rrule(
    series_start_utc: datetime,
    series_end_utc: datetime,
    rrule: RRule,
    window_start: datetime,
    window_end: datetime,
) -> List[Tuple[datetime, datetime]]:
    if window_end <= window_start:
        return []

    until = parse_iso_dt(rrule.until_utc) if rrule.until_utc else None
    remaining = rrule.count
    duration = series_end_utc - series_start_utc
    occs: List[Tuple[datetime, datetime]] = []

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
        bydays = rrule.byday or [list(WEEKDAY_MAP.keys())[series_start_utc.weekday()]]
        by_idxs = sorted({WEEKDAY_MAP[d] for d in bydays})

        # week baseline aligned to Monday but preserves DTSTART time-of-day
        week0_date = series_start_utc.date() - timedelta(days=series_start_utc.weekday())
        week_start = datetime(
            week0_date.year, week0_date.month, week0_date.day,
            series_start_utc.hour, series_start_utc.minute, series_start_utc.second, series_start_utc.microsecond,
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
        def add_months(d: datetime, months: int) -> Optional[datetime]:
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


# =============================================================================
# Invitation status
# =============================================================================
INV_STATUSES: Set[str] = {"pending", "accepted", "declined", "tentative"}


# =============================================================================
# API Models
# =============================================================================
class CalendarCreateIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    timezone: str = Field(default="UTC", max_length=64)


class CalendarOut(BaseModel):
    calendar_id: str
    name: str
    timezone: str
    owner_user_id: str
    created_at_utc: str


class CalendarShareIn(BaseModel):
    user_id: str
    role: Literal["viewer", "editor"] = "viewer"


class CalendarTimezoneIn(BaseModel):
    timezone: str = Field(max_length=64)


class PrimaryCalendarSetIn(BaseModel):
    calendar_id: str


class EventCreateIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=5000)
    timezone: Optional[str] = Field(default=None, max_length=64)

    start_utc: Optional[str] = None
    end_utc: Optional[str] = None

    all_day: bool = False
    all_day_date: Optional[str] = None  # YYYY-MM-DD (in event timezone)

    invitees: List[str] = Field(default_factory=list)


class EventUpdateIn(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    description: Optional[str] = Field(default=None, max_length=5000)
    timezone: Optional[str] = Field(default=None, max_length=64)


class RescheduleIn(BaseModel):
    new_start_utc: Optional[str] = None
    new_end_utc: Optional[str] = None
    new_all_day: Optional[bool] = None
    new_all_day_date: Optional[str] = None

    # For series single-occurrence overrides / cancel
    occurrence_start_utc: Optional[str] = None


class RecurringCreateIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=5000)
    timezone: Optional[str] = Field(default=None, max_length=64)

    start_utc: str
    end_utc: str
    rrule: RRule

    invitees: List[str] = Field(default_factory=list)


class InviteUsersIn(BaseModel):
    user_ids: List[str] = Field(min_length=1)
    note: Optional[str] = None


class InvitationRespondIn(BaseModel):
    status: Literal["accepted", "declined", "tentative"]


class SeriesCancelOccurrenceIn(BaseModel):
    occurrence_start_utc: str


class OpeningsOut(BaseModel):
    start_utc: str
    end_utc: str


class AvailabilityRequest(BaseModel):
    user_ids: List[str] = Field(min_length=1)
    start_utc: str
    end_utc: str
    min_minutes: int = Field(default=30, ge=1, le=7 * 24 * 60)


class AvailabilitySegment(BaseModel):
    start_utc: str
    end_utc: str
    available_user_ids: List[str] = Field(default_factory=list)


# =============================================================================
# Primary calendar profile helpers
# =============================================================================
def get_primary_calendar_id(user_id: str) -> Optional[str]:
    prof = ddb_get_item(pk_usr(user_id), sk_profile())
    if not prof:
        return None
    return prof.get("primary_calendar_id")


def set_primary_calendar_id_if_empty(user_id: str, calendar_id: str) -> None:
    prof = ddb_get_item(pk_usr(user_id), sk_profile())
    if prof and prof.get("primary_calendar_id"):
        return
    ddb_put_item({
        "PK": pk_usr(user_id),
        "SK": sk_profile(),
        "type": "user_profile",
        "user_id": user_id,
        "primary_calendar_id": calendar_id,
        "updated_at_utc": iso_utc(utc_now()),
    })


# =============================================================================
# Event time normalization
# =============================================================================
def normalize_event_times(
    calendar_tz: str,
    all_day: bool,
    start_utc: Optional[str],
    end_utc: Optional[str],
    all_day_date: Optional[str],
    event_tz: Optional[str],
) -> Dict[str, Any]:
    _require_zoneinfo()
    tz = event_tz or calendar_tz
    try:
        ZoneInfo(tz)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid timezone")

    if all_day:
        if not all_day_date:
            raise HTTPException(status_code=400, detail="all_day_date is required for all-day events")
        d = parse_iso_date(all_day_date)
        return {"all_day": True, "timezone": tz, "all_day_date": d.isoformat()}

    if not start_utc or not end_utc:
        raise HTTPException(status_code=400, detail="start_utc and end_utc are required for timed events")
    s = parse_iso_dt(start_utc)
    e = parse_iso_dt(end_utc)
    if e <= s:
        raise HTTPException(status_code=400, detail="end_utc must be after start_utc")
    return {"all_day": False, "timezone": tz, "start_utc": iso_utc(s), "end_utc": iso_utc(e)}


def all_day_to_busy_interval(all_day_date_str: str, tz_name: str) -> Tuple[datetime, datetime]:
    _require_zoneinfo()
    tz = ZoneInfo(tz_name)
    d = parse_iso_date(all_day_date_str)
    local_start = datetime(d.year, d.month, d.day, 0, 0, 0, tzinfo=tz)
    local_end = local_start + timedelta(days=1)
    return (local_start.astimezone(timezone.utc), local_end.astimezone(timezone.utc))


def item_to_busy_interval(item: Dict[str, Any]) -> Tuple[datetime, datetime]:
    if item.get("all_day"):
        return all_day_to_busy_interval(item["all_day_date"], item["timezone"])
    return (parse_iso_dt(item["start_utc"]), parse_iso_dt(item["end_utc"]))


# =============================================================================
# Invitation / invitees helpers
# invitees stored as: { user_id: {status, invited_at_utc, responded_at_utc?} }
# Also store invitee inbox items under PK=USR#{invitee}
# =============================================================================
def _invite_many(
    calendar_id: str,
    kind: Literal["event", "series"],
    obj_id: str,
    obj_name: str,
    from_user_id: str,
    invitees_map: Dict[str, Any],
    user_ids: List[str],
) -> Dict[str, Any]:
    now = iso_utc(utc_now())
    for u in user_ids:
        st = (invitees_map.get(u) or {}).get("status")
        if st in ("pending", "accepted", "tentative"):
            continue
        invitees_map[u] = {"status": "pending", "invited_at_utc": now}
        ddb_put_item({
            "PK": pk_usr(u),
            "SK": sk_inv(calendar_id, kind, obj_id),
            "type": "invitation",
            "user_id": u,
            "calendar_id": calendar_id,
            "kind": kind,
            "event_id": obj_id if kind == "event" else None,
            "series_id": obj_id if kind == "series" else None,
            "status": "pending",
            "invited_at_utc": now,
            "from_user_id": from_user_id,
            "name": obj_name,
        })
    return invitees_map


def _uninvite_one(
    calendar_id: str,
    kind: Literal["event", "series"],
    obj_id: str,
    invitees_map: Dict[str, Any],
    other_user_id: str,
) -> Dict[str, Any]:
    invitees_map.pop(other_user_id, None)
    ddb_delete_item(pk_usr(other_user_id), sk_inv(calendar_id, kind, obj_id))
    return invitees_map


def _load_target_object(calendar_id: str, kind: Literal["event", "series"], obj_id: str) -> Dict[str, Any]:
    if kind == "event":
        it = ddb_get_item(pk_cal(calendar_id), sk_evt(obj_id))
        if not it or it.get("type") != "event":
            raise HTTPException(status_code=404, detail="Event not found")
        return it
    it = ddb_get_item(pk_cal(calendar_id), sk_ser(obj_id))
    if not it or it.get("type") != "series":
        raise HTTPException(status_code=404, detail="Series not found")
    return it


# =============================================================================
# Calendar endpoints
# =============================================================================
@app.post("/calendars", response_model=CalendarOut)
def create_calendar(body: CalendarCreateIn, user_id: str = Depends(get_user_id)):
    _require_zoneinfo()
    try:
        ZoneInfo(body.timezone)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid timezone")

    calendar_id = str(uuid.uuid4())
    now = utc_now()

    meta = {
        "PK": pk_cal(calendar_id),
        "SK": sk_meta(),
        "type": "calendar",
        "calendar_id": calendar_id,
        "name": body.name,
        "timezone": body.timezone,
        "owner_user_id": user_id,
        "created_at_utc": iso_utc(now),
    }

    owner_mem = {
        "PK": pk_cal(calendar_id),
        "SK": sk_mem(user_id),
        "type": "membership",
        "calendar_id": calendar_id,
        "user_id": user_id,
        "role": "editor",
        "created_at_utc": iso_utc(now),
    }

    ddb_put_item(meta)
    ddb_put_item(owner_mem)
    set_primary_calendar_id_if_empty(user_id, calendar_id)

    return CalendarOut(
        calendar_id=calendar_id,
        name=body.name,
        timezone=body.timezone,
        owner_user_id=user_id,
        created_at_utc=iso_utc(now),
    )


@app.delete("/calendars/{calendar_id}")
def remove_calendar(calendar_id: str, user_id: str = Depends(get_user_id)):
    info = require_calendar_access(calendar_id, user_id)
    if info["role"] != "owner":
        raise HTTPException(status_code=403, detail="Only owner can delete calendar")

    items = ddb_query_pk(pk_cal(calendar_id))
    for it in items:
        ddb_delete_item(it["PK"], it["SK"])
    return {"ok": True}


@app.post("/calendars/{calendar_id}/timezone")
def change_calendar_timezone(calendar_id: str, body: CalendarTimezoneIn, user_id: str = Depends(get_user_id)):
    _require_zoneinfo()
    require_editor(calendar_id, user_id)
    try:
        ZoneInfo(body.timezone)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid timezone")

    meta = ddb_get_item(pk_cal(calendar_id), sk_meta())
    if not meta:
        raise HTTPException(status_code=404, detail="Calendar not found")
    meta["timezone"] = body.timezone
    meta["updated_at_utc"] = iso_utc(utc_now())
    ddb_put_item(meta)
    return {"ok": True, "timezone": body.timezone}


@app.post("/calendars/{calendar_id}/share")
def share_calendar(calendar_id: str, body: CalendarShareIn, user_id: str = Depends(get_user_id)):
    meta = ddb_get_item(pk_cal(calendar_id), sk_meta())
    if not meta:
        raise HTTPException(status_code=404, detail="Calendar not found")
    if meta["owner_user_id"] != user_id:
        raise HTTPException(status_code=403, detail="Only owner can share calendar")

    mem = {
        "PK": pk_cal(calendar_id),
        "SK": sk_mem(body.user_id),
        "type": "membership",
        "calendar_id": calendar_id,
        "user_id": body.user_id,
        "role": body.role,
        "created_at_utc": iso_utc(utc_now()),
    }
    ddb_put_item(mem)
    return {"ok": True}


@app.delete("/calendars/{calendar_id}/share/{other_user_id}")
def unshare_calendar(calendar_id: str, other_user_id: str, user_id: str = Depends(get_user_id)):
    meta = ddb_get_item(pk_cal(calendar_id), sk_meta())
    if not meta:
        raise HTTPException(status_code=404, detail="Calendar not found")
    if meta["owner_user_id"] != user_id:
        raise HTTPException(status_code=403, detail="Only owner can unshare calendar")
    if other_user_id == user_id:
        raise HTTPException(status_code=400, detail="Cannot remove owner")

    ddb_delete_item(pk_cal(calendar_id), sk_mem(other_user_id))
    return {"ok": True}


# =============================================================================
# Primary calendar endpoints
# =============================================================================
@app.get("/me/primary_calendar")
def get_my_primary_calendar(user_id: str = Depends(get_user_id)):
    return {"primary_calendar_id": get_primary_calendar_id(user_id)}


@app.post("/me/primary_calendar")
def set_my_primary_calendar(body: PrimaryCalendarSetIn, user_id: str = Depends(get_user_id)):
    require_calendar_access(body.calendar_id, user_id)
    ddb_put_item({
        "PK": pk_usr(user_id),
        "SK": sk_profile(),
        "type": "user_profile",
        "user_id": user_id,
        "primary_calendar_id": body.calendar_id,
        "updated_at_utc": iso_utc(utc_now()),
    })
    return {"ok": True}


# =============================================================================
# One-off events
# =============================================================================
@app.post("/calendars/{calendar_id}/events")
def add_event(calendar_id: str, body: EventCreateIn, user_id: str = Depends(get_user_id)):
    info = require_editor(calendar_id, user_id)
    cal_tz = info["meta"]["timezone"]

    norm = normalize_event_times(
        calendar_tz=cal_tz,
        all_day=body.all_day,
        start_utc=body.start_utc,
        end_utc=body.end_utc,
        all_day_date=body.all_day_date,
        event_tz=body.timezone,
    )

    event_id = str(uuid.uuid4())
    now = utc_now()

    item = {
        "PK": pk_cal(calendar_id),
        "SK": sk_evt(event_id),
        "type": "event",
        "calendar_id": calendar_id,
        "event_id": event_id,
        "name": body.name,
        "description": body.description,
        "invitees": {},  # map user_id -> status blob
        "created_by": user_id,
        "created_at_utc": iso_utc(now),
        **norm,
    }

    # Create invitation state + inbox items
    item["invitees"] = _invite_many(
        calendar_id=calendar_id,
        kind="event",
        obj_id=event_id,
        obj_name=body.name,
        from_user_id=user_id,
        invitees_map=item["invitees"],
        user_ids=body.invitees,
    )

    ddb_put_item(item)
    return {"ok": True, "event_id": event_id}


@app.delete("/calendars/{calendar_id}/events/{event_id}")
def remove_event(calendar_id: str, event_id: str, user_id: str = Depends(get_user_id)):
    require_editor(calendar_id, user_id)
    it = ddb_get_item(pk_cal(calendar_id), sk_evt(event_id))
    if not it or it.get("type") != "event":
        raise HTTPException(status_code=404, detail="Event not found")

    # clean up invite inbox items
    inv_map = it.get("invitees") or {}
    for u in list(inv_map.keys()):
        ddb_delete_item(pk_usr(u), sk_inv(calendar_id, "event", event_id))

    ddb_delete_item(pk_cal(calendar_id), sk_evt(event_id))
    return {"ok": True}


@app.patch("/calendars/{calendar_id}/events/{event_id}")
def update_event(calendar_id: str, event_id: str, body: EventUpdateIn, user_id: str = Depends(get_user_id)):
    require_editor(calendar_id, user_id)
    it = ddb_get_item(pk_cal(calendar_id), sk_evt(event_id))
    if not it or it.get("type") != "event":
        raise HTTPException(status_code=404, detail="Event not found")

    if body.name is not None:
        it["name"] = body.name
    if body.description is not None:
        it["description"] = body.description
    if body.timezone is not None:
        _require_zoneinfo()
        try:
            ZoneInfo(body.timezone)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid timezone")
        it["timezone"] = body.timezone

    it["updated_at_utc"] = iso_utc(utc_now())
    ddb_put_item(it)
    return {"ok": True}


@app.post("/calendars/{calendar_id}/events/{event_id}/reschedule")
def reschedule_event(calendar_id: str, event_id: str, body: RescheduleIn, user_id: str = Depends(get_user_id)):
    info = require_editor(calendar_id, user_id)
    cal_tz = info["meta"]["timezone"]

    it = ddb_get_item(pk_cal(calendar_id), sk_evt(event_id))
    if not it or it.get("type") != "event":
        raise HTTPException(status_code=404, detail="Event not found")

    new_all_day = body.new_all_day if body.new_all_day is not None else it.get("all_day", False)
    new_tz = it.get("timezone", cal_tz)

    norm = normalize_event_times(
        calendar_tz=cal_tz,
        all_day=new_all_day,
        start_utc=body.new_start_utc if not new_all_day else None,
        end_utc=body.new_end_utc if not new_all_day else None,
        all_day_date=body.new_all_day_date if new_all_day else None,
        event_tz=new_tz,
    )

    for k in ["start_utc", "end_utc", "all_day_date", "all_day"]:
        it.pop(k, None)
    it.update(norm)
    it["updated_at_utc"] = iso_utc(utc_now())
    ddb_put_item(it)
    return {"ok": True}


# =============================================================================
# Recurring series
# =============================================================================
@app.post("/calendars/{calendar_id}/series")
def add_repeating_event(calendar_id: str, body: RecurringCreateIn, user_id: str = Depends(get_user_id)):
    info = require_editor(calendar_id, user_id)
    cal_tz = info["meta"]["timezone"]

    _require_zoneinfo()
    tz = body.timezone or cal_tz
    try:
        ZoneInfo(tz)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid timezone")

    s = parse_iso_dt(body.start_utc)
    e = parse_iso_dt(body.end_utc)
    if e <= s:
        raise HTTPException(status_code=400, detail="end_utc must be after start_utc")

    if body.rrule.until_utc:
        _ = parse_iso_dt(body.rrule.until_utc)

    series_id = str(uuid.uuid4())
    now = utc_now()

    item = {
        "PK": pk_cal(calendar_id),
        "SK": sk_ser(series_id),
        "type": "series",
        "calendar_id": calendar_id,
        "series_id": series_id,
        "name": body.name,
        "description": body.description,
        "timezone": tz,
        "start_utc": iso_utc(s),
        "end_utc": iso_utc(e),
        "rrule": body.rrule.model_dump(),
        "invitees": {},
        "created_by": user_id,
        "created_at_utc": iso_utc(now),
    }

    item["invitees"] = _invite_many(
        calendar_id=calendar_id,
        kind="series",
        obj_id=series_id,
        obj_name=body.name,
        from_user_id=user_id,
        invitees_map=item["invitees"],
        user_ids=body.invitees,
    )

    ddb_put_item(item)
    return {"ok": True, "series_id": series_id}


@app.patch("/calendars/{calendar_id}/series/{series_id}")
def update_series(calendar_id: str, series_id: str, body: EventUpdateIn, user_id: str = Depends(get_user_id)):
    require_editor(calendar_id, user_id)
    it = ddb_get_item(pk_cal(calendar_id), sk_ser(series_id))
    if not it or it.get("type") != "series":
        raise HTTPException(status_code=404, detail="Series not found")

    if body.name is not None:
        it["name"] = body.name
    if body.description is not None:
        it["description"] = body.description
    if body.timezone is not None:
        _require_zoneinfo()
        try:
            ZoneInfo(body.timezone)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid timezone")
        it["timezone"] = body.timezone

    it["updated_at_utc"] = iso_utc(utc_now())
    ddb_put_item(it)
    return {"ok": True}


@app.delete("/calendars/{calendar_id}/series/{series_id}")
def remove_repeating_event(calendar_id: str, series_id: str, user_id: str = Depends(get_user_id)):
    require_editor(calendar_id, user_id)
    it = ddb_get_item(pk_cal(calendar_id), sk_ser(series_id))
    if not it or it.get("type") != "series":
        raise HTTPException(status_code=404, detail="Series not found")

    # delete series + all overrides
    items = ddb_query_pk(pk_cal(calendar_id))
    for x in items:
        if x["SK"] == sk_ser(series_id) or x["SK"].startswith(f"OVR#{series_id}#"):
            ddb_delete_item(x["PK"], x["SK"])

    # clean up invite inbox items
    inv_map = it.get("invitees") or {}
    for u in list(inv_map.keys()):
        ddb_delete_item(pk_usr(u), sk_inv(calendar_id, "series", series_id))

    return {"ok": True}


@app.post("/calendars/{calendar_id}/series/{series_id}/reschedule")
def reschedule_series_occurrence(calendar_id: str, series_id: str, body: RescheduleIn, user_id: str = Depends(get_user_id)):
    """
    Reschedule a SINGLE occurrence in a series by writing an override item:
      - occurrence_start_utc: required (which instance you are changing)
      - new_start_utc/new_end_utc: required
    """
    info = require_editor(calendar_id, user_id)
    cal_tz = info["meta"]["timezone"]

    series = ddb_get_item(pk_cal(calendar_id), sk_ser(series_id))
    if not series or series.get("type") != "series":
        raise HTTPException(status_code=404, detail="Series not found")

    if not body.occurrence_start_utc:
        raise HTTPException(status_code=400, detail="occurrence_start_utc is required for series reschedule")
    if not body.new_start_utc or not body.new_end_utc:
        raise HTTPException(status_code=400, detail="new_start_utc and new_end_utc are required")

    occ_start = iso_utc(parse_iso_dt(body.occurrence_start_utc))

    norm = normalize_event_times(
        calendar_tz=cal_tz,
        all_day=False,
        start_utc=body.new_start_utc,
        end_utc=body.new_end_utc,
        all_day_date=None,
        event_tz=series.get("timezone", cal_tz),
    )

    override = {
        "PK": pk_cal(calendar_id),
        "SK": sk_ovr(series_id, occ_start),
        "type": "override",
        "calendar_id": calendar_id,
        "series_id": series_id,
        "occurrence_start_utc": occ_start,
        "cancelled": False,
        "name": series.get("name", ""),
        "description": series.get("description", ""),
        "timezone": series.get("timezone", cal_tz),
        "invitees": series.get("invitees", {}),
        **norm,
        "updated_at_utc": iso_utc(utc_now()),
    }
    ddb_put_item(override)
    return {"ok": True}


@app.post("/calendars/{calendar_id}/series/{series_id}/cancel_occurrence")
def cancel_series_occurrence(calendar_id: str, series_id: str, body: SeriesCancelOccurrenceIn, user_id: str = Depends(get_user_id)):
    require_editor(calendar_id, user_id)
    series = ddb_get_item(pk_cal(calendar_id), sk_ser(series_id))
    if not series or series.get("type") != "series":
        raise HTTPException(status_code=404, detail="Series not found")

    occ_start = iso_utc(parse_iso_dt(body.occurrence_start_utc))
    cancel_override = {
        "PK": pk_cal(calendar_id),
        "SK": sk_ovr(series_id, occ_start),
        "type": "override",
        "calendar_id": calendar_id,
        "series_id": series_id,
        "occurrence_start_utc": occ_start,
        "cancelled": True,
        "updated_at_utc": iso_utc(utc_now()),
    }
    ddb_put_item(cancel_override)
    return {"ok": True}


@app.delete("/calendars/{calendar_id}/series/{series_id}/override")
def remove_series_override(calendar_id: str, series_id: str, occurrence_start_utc: str = Query(...), user_id: str = Depends(get_user_id)):
    require_editor(calendar_id, user_id)
    occ = iso_utc(parse_iso_dt(occurrence_start_utc))
    ddb_delete_item(pk_cal(calendar_id), sk_ovr(series_id, occ))
    return {"ok": True}


# =============================================================================
# Invitation flow endpoints
# =============================================================================
@app.get("/me/invitations")
def list_my_invitations(
    status: Optional[str] = Query(default=None, description="pending|accepted|declined|tentative"),
    user_id: str = Depends(get_user_id),
):
    if status and status not in INV_STATUSES:
        raise HTTPException(status_code=400, detail="Invalid status")

    items = ddb_query_pk(pk_usr(user_id))
    invs = [x for x in items if x.get("type") == "invitation"]
    if status:
        invs = [x for x in invs if x.get("status") == status]
    invs.sort(key=lambda x: x.get("invited_at_utc", ""))
    return {"items": invs}


@app.post("/calendars/{calendar_id}/{kind}/{obj_id}/invite")
def invite_users(
    calendar_id: str,
    kind: Literal["event", "series"],
    obj_id: str,
    body: InviteUsersIn,
    user_id: str = Depends(get_user_id),
):
    require_editor(calendar_id, user_id)
    obj = _load_target_object(calendar_id, kind, obj_id)

    inv_map = obj.get("invitees") or {}
    obj_name = obj.get("name", "")

    inv_map = _invite_many(
        calendar_id=calendar_id,
        kind=kind,
        obj_id=obj_id,
        obj_name=obj_name,
        from_user_id=user_id,
        invitees_map=inv_map,
        user_ids=body.user_ids,
    )
    obj["invitees"] = inv_map
    obj["updated_at_utc"] = iso_utc(utc_now())
    ddb_put_item(obj)
    return {"ok": True}


@app.post("/calendars/{calendar_id}/{kind}/{obj_id}/uninvite/{other_user_id}")
def uninvite_user(
    calendar_id: str,
    kind: Literal["event", "series"],
    obj_id: str,
    other_user_id: str,
    user_id: str = Depends(get_user_id),
):
    require_editor(calendar_id, user_id)
    obj = _load_target_object(calendar_id, kind, obj_id)

    inv_map = obj.get("invitees") or {}
    inv_map = _uninvite_one(calendar_id, kind, obj_id, inv_map, other_user_id)

    obj["invitees"] = inv_map
    obj["updated_at_utc"] = iso_utc(utc_now())
    ddb_put_item(obj)
    return {"ok": True}


@app.post("/calendars/{calendar_id}/{kind}/{obj_id}/respond")
def respond_invitation(
    calendar_id: str,
    kind: Literal["event", "series"],
    obj_id: str,
    body: InvitationRespondIn,
    user_id: str = Depends(get_user_id),
):
    inv_item = ddb_get_item(pk_usr(user_id), sk_inv(calendar_id, kind, obj_id))
    obj = _load_target_object(calendar_id, kind, obj_id)

    inv_map = obj.get("invitees") or {}
    if user_id not in inv_map and not inv_item:
        raise HTTPException(status_code=403, detail="No invitation found")

    now = iso_utc(utc_now())
    inv_map.setdefault(user_id, {"invited_at_utc": now, "status": "pending"})
    inv_map[user_id]["status"] = body.status
    inv_map[user_id]["responded_at_utc"] = now

    obj["invitees"] = inv_map
    obj["updated_at_utc"] = now
    ddb_put_item(obj)

    invited_at = (inv_item.get("invited_at_utc") if inv_item else inv_map[user_id].get("invited_at_utc", now))
    ddb_put_item({
        "PK": pk_usr(user_id),
        "SK": sk_inv(calendar_id, kind, obj_id),
        "type": "invitation",
        "user_id": user_id,
        "calendar_id": calendar_id,
        "kind": kind,
        "event_id": obj_id if kind == "event" else None,
        "series_id": obj_id if kind == "series" else None,
        "status": body.status,
        "responded_at_utc": now,
        "invited_at_utc": invited_at,
        "name": obj.get("name", ""),
    })
    return {"ok": True, "status": body.status}


# =============================================================================
# View events + openings (expand recurring, apply overrides, suppress cancelled)
# =============================================================================
def collect_events_in_window(calendar_id: str, window_start: datetime, window_end: datetime) -> List[Dict[str, Any]]:
    items = ddb_query_pk(pk_cal(calendar_id))

    oneoffs = [it for it in items if it.get("type") == "event"]
    series = [it for it in items if it.get("type") == "series"]
    overrides = [it for it in items if it.get("type") == "override"]

    # index overrides by (series_id, occurrence_start_utc)
    ovr_map: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for o in overrides:
        ovr_map[(o["series_id"], o["occurrence_start_utc"])] = o

    out: List[Dict[str, Any]] = []

    # one-offs
    for e in oneoffs:
        if e.get("all_day"):
            bs, be = item_to_busy_interval(e)
            if overlap(bs, be, window_start, window_end):
                out.append({
                    "kind": "event",
                    "id": e["event_id"],
                    "name": e.get("name", ""),
                    "description": e.get("description", ""),
                    "timezone": e.get("timezone", "UTC"),
                    "invitees": e.get("invitees", {}),
                    "all_day": True,
                    "all_day_date": e["all_day_date"],
                    "busy_start_utc": iso_utc(bs),
                    "busy_end_utc": iso_utc(be),
                })
        else:
            s = parse_iso_dt(e["start_utc"])
            t = parse_iso_dt(e["end_utc"])
            if overlap(s, t, window_start, window_end):
                out.append({
                    "kind": "event",
                    "id": e["event_id"],
                    "name": e.get("name", ""),
                    "description": e.get("description", ""),
                    "timezone": e.get("timezone", "UTC"),
                    "invitees": e.get("invitees", {}),
                    "all_day": False,
                    "start_utc": e["start_utc"],
                    "end_utc": e["end_utc"],
                })

    # series expanded
    for s in series:
        dt0 = parse_iso_dt(s["start_utc"])
        dt1 = parse_iso_dt(s["end_utc"])
        rr = RRule(**s["rrule"])
        occs = expand_rrule(dt0, dt1, rr, window_start, window_end)

        for occ_start, occ_end in occs:
            occ_key = (s["series_id"], iso_utc(occ_start))
            if occ_key in ovr_map:
                o = ovr_map[occ_key]
                if o.get("cancelled") is True:
                    continue  # suppressed occurrence

                os = parse_iso_dt(o["start_utc"])
                oe = parse_iso_dt(o["end_utc"])
                if overlap(os, oe, window_start, window_end):
                    out.append({
                        "kind": "series",
                        "id": s["series_id"],
                        "occurrence_start_utc": o["occurrence_start_utc"],
                        "name": o.get("name", s.get("name", "")),
                        "description": o.get("description", s.get("description", "")),
                        "timezone": o.get("timezone", s.get("timezone", "UTC")),
                        "invitees": o.get("invitees", s.get("invitees", {})),
                        "all_day": False,
                        "start_utc": o["start_utc"],
                        "end_utc": o["end_utc"],
                        "overridden": True,
                    })
            else:
                out.append({
                    "kind": "series",
                    "id": s["series_id"],
                    "occurrence_start_utc": iso_utc(occ_start),
                    "name": s.get("name", ""),
                    "description": s.get("description", ""),
                    "timezone": s.get("timezone", "UTC"),
                    "invitees": s.get("invitees", {}),
                    "all_day": False,
                    "start_utc": iso_utc(occ_start),
                    "end_utc": iso_utc(occ_end),
                    "overridden": False,
                })

    def sort_key(x: Dict[str, Any]) -> int:
        if x.get("all_day"):
            return int(parse_iso_dt(x["busy_start_utc"]).timestamp() * 1000)
        return int(parse_iso_dt(x["start_utc"]).timestamp() * 1000)

    return sorted(out, key=sort_key)


@app.get("/calendars/{calendar_id}/events")
def view_events(
    calendar_id: str,
    start_utc: str = Query(...),
    end_utc: str = Query(...),
    user_id: str = Depends(get_user_id),
):
    require_calendar_access(calendar_id, user_id)
    ws = parse_iso_dt(start_utc)
    we = parse_iso_dt(end_utc)
    if we <= ws:
        raise HTTPException(status_code=400, detail="end_utc must be after start_utc")
    inst = collect_events_in_window(calendar_id, ws, we)
    return {"calendar_id": calendar_id, "start_utc": iso_utc(ws), "end_utc": iso_utc(we), "items": inst}


@app.get("/calendars/{calendar_id}/openings", response_model=List[OpeningsOut])
def view_openings(
    calendar_id: str,
    start_utc: str = Query(...),
    end_utc: str = Query(...),
    min_minutes: int = Query(default=30, ge=1, le=7 * 24 * 60),
    user_id: str = Depends(get_user_id),
):
    require_calendar_access(calendar_id, user_id)
    ws = parse_iso_dt(start_utc)
    we = parse_iso_dt(end_utc)
    if we <= ws:
        raise HTTPException(status_code=400, detail="end_utc must be after start_utc")

    inst = collect_events_in_window(calendar_id, ws, we)
    busy: List[Tuple[datetime, datetime]] = []
    for x in inst:
        if x.get("all_day"):
            busy.append((parse_iso_dt(x["busy_start_utc"]), parse_iso_dt(x["busy_end_utc"])))
        else:
            busy.append((parse_iso_dt(x["start_utc"]), parse_iso_dt(x["end_utc"])))

    free = invert_intervals(busy, ws, we)
    min_dur = timedelta(minutes=min_minutes)
    return [
        OpeningsOut(start_utc=iso_utc(s), end_utc=iso_utc(e))
        for s, e in free
        if (e - s) >= min_dur
    ]


# =============================================================================
# Availability APIs (ALL free, ANY free + who)
# Uses each user's primary calendar.
# =============================================================================
def intersect_two(a: List[Tuple[datetime, datetime]], b: List[Tuple[datetime, datetime]]) -> List[Tuple[datetime, datetime]]:
    out: List[Tuple[datetime, datetime]] = []
    i = j = 0
    while i < len(a) and j < len(b):
        s1, e1 = a[i]
        s2, e2 = b[j]
        s = max(s1, s2)
        e = min(e1, e2)
        if s < e:
            out.append((s, e))
        if e1 <= e2:
            i += 1
        else:
            j += 1
    return out


def get_user_free_intervals(user_id: str, ws: datetime, we: datetime) -> List[Tuple[datetime, datetime]]:
    cal_id = get_primary_calendar_id(user_id)
    if not cal_id:
        return []
    inst = collect_events_in_window(cal_id, ws, we)
    busy: List[Tuple[datetime, datetime]] = []
    for x in inst:
        if x.get("all_day"):
            busy.append((parse_iso_dt(x["busy_start_utc"]), parse_iso_dt(x["busy_end_utc"])))
        else:
            busy.append((parse_iso_dt(x["start_utc"]), parse_iso_dt(x["end_utc"])))
    return invert_intervals(busy, ws, we)


@app.post("/availability/all")
def availability_all(body: AvailabilityRequest, requester_user_id: str = Depends(get_user_id)):
    ws = parse_iso_dt(body.start_utc)
    we = parse_iso_dt(body.end_utc)
    if we <= ws:
        raise HTTPException(status_code=400, detail="end_utc must be after start_utc")

    min_dur = timedelta(minutes=body.min_minutes)
    cur: List[Tuple[datetime, datetime]] = [(ws, we)]

    for u in body.user_ids:
        free_u = get_user_free_intervals(u, ws, we)
        cur = intersect_two(cur, free_u)
        if not cur:
            break

    cur = [(s, e) for s, e in cur if (e - s) >= min_dur]
    return [{"start_utc": iso_utc(s), "end_utc": iso_utc(e)} for s, e in cur]


@app.post("/availability/any", response_model=List[AvailabilitySegment])
def availability_any(body: AvailabilityRequest, requester_user_id: str = Depends(get_user_id)):
    ws = parse_iso_dt(body.start_utc)
    we = parse_iso_dt(body.end_utc)
    if we <= ws:
        raise HTTPException(status_code=400, detail="end_utc must be after start_utc")
    min_dur = timedelta(minutes=body.min_minutes)

    # sweep events: (time, typ, user)
    events: List[Tuple[datetime, str, str]] = []
    for u in body.user_ids:
        free_u = get_user_free_intervals(u, ws, we)
        for s, e in free_u:
            s2 = max(s, ws)
            e2 = min(e, we)
            if s2 < e2:
                events.append((s2, "start", u))
                events.append((e2, "end", u))

    if not events:
        return []

    events.sort(key=lambda x: (x[0], 0 if x[1] == "end" else 1))

    available: Set[str] = set()
    segments: List[AvailabilitySegment] = []

    prev_t = ws
    idx = 0

    # apply events exactly at ws
    while idx < len(events) and events[idx][0] == ws:
        _, typ, u = events[idx]
        if typ == "start":
            available.add(u)
        else:
            available.discard(u)
        idx += 1

    while idx < len(events):
        t = events[idx][0]
        if prev_t < t and available and (t - prev_t) >= min_dur:
            segments.append(AvailabilitySegment(
                start_utc=iso_utc(prev_t),
                end_utc=iso_utc(t),
                available_user_ids=sorted(available),
            ))

        while idx < len(events) and events[idx][0] == t:
            _, typ, u = events[idx]
            if typ == "start":
                available.add(u)
            else:
                available.discard(u)
            idx += 1

        prev_t = t

    if prev_t < we and available and (we - prev_t) >= min_dur:
        segments.append(AvailabilitySegment(
            start_utc=iso_utc(prev_t),
            end_utc=iso_utc(we),
            available_user_ids=sorted(available),
        ))

    return segments


# =============================================================================
# Local dev:
#   uvicorn app:app --reload --port 8000
# =============================================================================
