from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List

from fastapi import HTTPException

from app.models import EventCreateIn, RecurrenceRule


def _iso_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_dt(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _normalize_google_status(status: str | None, warnings: List[str]) -> str:
    normalized = str(status or "confirmed").strip().lower()
    if normalized == "tentative":
        return "tentative"
    if normalized == "cancelled":
        warnings.append("google status 'cancelled' is mapped to internal 'free'")
        return "free"
    if normalized in {"confirmed", ""}:
        return "busy"
    warnings.append(f"unsupported google status '{normalized}', defaulted to 'busy'")
    return "busy"


def _google_time_to_internal(start: Dict[str, Any], end: Dict[str, Any], fallback_tz: str, warnings: List[str]) -> Dict[str, Any]:
    if start.get("date") and end.get("date"):
        tz_name = str(start.get("timeZone") or end.get("timeZone") or fallback_tz or "UTC")
        return {
            "all_day": True,
            "all_day_date": str(start.get("date")),
            "timezone": tz_name,
            "start_utc": None,
            "end_utc": None,
        }

    start_dt = str(start.get("dateTime") or "")
    end_dt = str(end.get("dateTime") or "")
    if not start_dt or not end_dt:
        raise HTTPException(status_code=400, detail="google event is missing start/end datetime")
    tz_name = str(start.get("timeZone") or end.get("timeZone") or fallback_tz or "UTC")
    try:
        start_utc = _iso_utc(_parse_dt(start_dt))
        end_utc = _iso_utc(_parse_dt(end_dt))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="google event contains invalid datetime format") from exc
    if end_utc <= start_utc:
        warnings.append("google event end time is not after start time")
    return {
        "all_day": False,
        "all_day_date": None,
        "timezone": tz_name,
        "start_utc": start_utc,
        "end_utc": end_utc,
    }


def _parse_rrule(rrule_line: str, warnings: List[str]) -> RecurrenceRule | None:
    if not rrule_line:
        return None
    raw = rrule_line.removeprefix("RRULE:").strip()
    parts = {}
    for token in [chunk for chunk in raw.split(";") if chunk]:
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        parts[key.upper()] = value
    freq = str(parts.get("FREQ") or "").upper()
    if freq not in {"DAILY", "WEEKLY", "MONTHLY"}:
        warnings.append(f"unsupported recurrence FREQ '{freq}'")
        return None
    byday = [chunk.strip().upper() for chunk in str(parts.get("BYDAY") or "").split(",") if chunk.strip()]
    bymonthday = [int(chunk) for chunk in str(parts.get("BYMONTHDAY") or "").split(",") if chunk.strip()]
    bysetpos = [int(chunk) for chunk in str(parts.get("BYSETPOS") or "").split(",") if chunk.strip()]
    until = str(parts.get("UNTIL") or "").strip()
    until_utc = None
    if until:
        # Google UNTIL commonly uses YYYYMMDDTHHMMSSZ
        try:
            if "T" in until:
                until_dt = datetime.strptime(until, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
                until_utc = _iso_utc(until_dt)
        except ValueError:
            warnings.append("unsupported RRULE UNTIL format")
    count = int(parts["COUNT"]) if parts.get("COUNT") else None
    return RecurrenceRule(
        freq=freq,
        interval=int(parts.get("INTERVAL") or 1),
        until_utc=until_utc,
        count=count,
        byday=byday or None,
        bymonthday=bymonthday or None,
        bysetpos=bysetpos or None,
    )


def _extract_exdates(recurrence: List[str], warnings: List[str]) -> List[str] | None:
    out: List[str] = []
    for line in recurrence:
        if not line.startswith("EXDATE"):
            continue
        try:
            _, value = line.split(":", 1)
        except ValueError:
            warnings.append("malformed EXDATE line")
            continue
        for raw in [part.strip() for part in value.split(",") if part.strip()]:
            try:
                dt = datetime.strptime(raw, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
                out.append(_iso_utc(dt))
            except ValueError:
                warnings.append("unsupported EXDATE format")
    return sorted(set(out)) or None


def map_google_event_to_internal(*, google_event: Dict[str, Any], calendar_timezone: str = "UTC") -> Dict[str, Any]:
    warnings: List[str] = []
    start = google_event.get("start") if isinstance(google_event.get("start"), dict) else {}
    end = google_event.get("end") if isinstance(google_event.get("end"), dict) else {}
    normalized_times = _google_time_to_internal(start, end, calendar_timezone, warnings)
    recurrence = google_event.get("recurrence") if isinstance(google_event.get("recurrence"), list) else []
    rrule_line = next((str(line) for line in recurrence if str(line).startswith("RRULE:")), "")
    recurrence_rule = _parse_rrule(rrule_line, warnings)
    exdates_utc = _extract_exdates([str(line) for line in recurrence], warnings)

    payload = EventCreateIn(
        name=str(google_event.get("summary") or "(untitled)"),
        description=str(google_event.get("description") or ""),
        timezone=normalized_times["timezone"],
        start_utc=normalized_times["start_utc"],
        end_utc=normalized_times["end_utc"],
        all_day=normalized_times["all_day"],
        all_day_date=normalized_times["all_day_date"],
        attendees=[
            str((attendee or {}).get("email") or "")
            for attendee in (google_event.get("attendees") or [])
            if str((attendee or {}).get("email") or "")
        ],
        booking_enabled=False,
        approval_required=False,
        status=_normalize_google_status(google_event.get("status"), warnings),
        category=None,
        recurrence_rule=recurrence_rule,
        exdates_utc=exdates_utc,
        recurrence_overrides=None,
    )

    metadata = {
        "google_event_id": str(google_event.get("id") or ""),
        "google_recurring_event_id": str(google_event.get("recurringEventId") or ""),
        "google_original_start_time": google_event.get("originalStartTime"),
        "google_etag": str(google_event.get("etag") or ""),
        "google_updated": str(google_event.get("updated") or ""),
        "google_sequence": int(google_event.get("sequence") or 0),
        "google_status": str(google_event.get("status") or ""),
    }
    return {"event": payload.model_dump(), "source_metadata": metadata, "warnings": sorted(set(warnings))}


def map_internal_event_to_google(*, internal_event: Dict[str, Any]) -> Dict[str, Any]:
    warnings: List[str] = []
    status = str(internal_event.get("status") or "busy").strip().lower()
    google_status = "confirmed"
    transparency = "opaque"
    if status == "tentative":
        google_status = "tentative"
    elif status == "free":
        google_status = "confirmed"
        transparency = "transparent"
    elif status == "out_of_office":
        google_status = "confirmed"
    elif status != "busy":
        warnings.append(f"unsupported internal status '{status}', defaulted to confirmed/opaque")

    body: Dict[str, Any] = {
        "summary": str(internal_event.get("name") or "(untitled)"),
        "description": str(internal_event.get("description") or ""),
        "status": google_status,
        "transparency": transparency,
    }
    timezone_name = str(internal_event.get("timezone") or "UTC")
    if bool(internal_event.get("all_day")):
        body["start"] = {"date": str(internal_event.get("all_day_date")), "timeZone": timezone_name}
        body["end"] = {"date": str(internal_event.get("all_day_date")), "timeZone": timezone_name}
    else:
        body["start"] = {"dateTime": str(internal_event.get("start_utc")), "timeZone": timezone_name}
        body["end"] = {"dateTime": str(internal_event.get("end_utc")), "timeZone": timezone_name}

    recurrence_rule = internal_event.get("recurrence_rule") if isinstance(internal_event.get("recurrence_rule"), dict) else None
    exdates = internal_event.get("exdates_utc") if isinstance(internal_event.get("exdates_utc"), list) else []
    recurrence: List[str] = []
    if recurrence_rule:
        parts = [f"FREQ={str(recurrence_rule.get('freq') or '').upper()}"]
        interval = int(recurrence_rule.get("interval") or 1)
        if interval != 1:
            parts.append(f"INTERVAL={interval}")
        if recurrence_rule.get("count"):
            parts.append(f"COUNT={int(recurrence_rule['count'])}")
        if recurrence_rule.get("until_utc"):
            try:
                until = _parse_dt(str(recurrence_rule["until_utc"]))
                parts.append(f"UNTIL={until.strftime('%Y%m%dT%H%M%SZ')}")
            except ValueError:
                warnings.append("recurrence until_utc could not be formatted")
        if recurrence_rule.get("byday"):
            parts.append("BYDAY=" + ",".join(sorted(str(d).upper() for d in recurrence_rule["byday"])))
        if recurrence_rule.get("bymonthday"):
            parts.append("BYMONTHDAY=" + ",".join(str(int(v)) for v in sorted(recurrence_rule["bymonthday"])))
        if recurrence_rule.get("bysetpos"):
            parts.append("BYSETPOS=" + ",".join(str(int(v)) for v in sorted(recurrence_rule["bysetpos"])))
        recurrence.append("RRULE:" + ";".join(parts))
    if exdates:
        stamp_values = []
        for value in exdates:
            try:
                stamp_values.append(_parse_dt(str(value)).strftime("%Y%m%dT%H%M%SZ"))
            except ValueError:
                warnings.append("unsupported exdate value omitted")
        if stamp_values:
            recurrence.append("EXDATE:" + ",".join(sorted(set(stamp_values))))
    if recurrence:
        body["recurrence"] = recurrence

    return {"google_event": body, "warnings": sorted(set(warnings))}


def build_google_event_sync_fingerprint(*, google_event: Dict[str, Any]) -> str:
    projected = {
        "id": str(google_event.get("id") or ""),
        "etag": str(google_event.get("etag") or ""),
        "updated": str(google_event.get("updated") or ""),
        "status": str(google_event.get("status") or ""),
        "summary": str(google_event.get("summary") or ""),
        "description": str(google_event.get("description") or ""),
        "start": google_event.get("start"),
        "end": google_event.get("end"),
        "recurrence": google_event.get("recurrence") if isinstance(google_event.get("recurrence"), list) else [],
        "attendees": sorted(
            str((attendee or {}).get("email") or "")
            for attendee in (google_event.get("attendees") or [])
            if str((attendee or {}).get("email") or "")
        ),
    }
    canonical = json.dumps(projected, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
