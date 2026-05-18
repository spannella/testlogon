from __future__ import annotations

import base64
import ipaddress
import socket
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib import parse as urlparse
from urllib import error as urlerror
from urllib import request as urlrequest
import xml.etree.ElementTree as ET

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover - fallback for older Python
    ZoneInfo = None

from app.services.calendar_integrations.base import (
    CalendarConnectionService,
    CalendarIntegrationError,
    CalendarIntegrationErrorCode,
    CalendarProvider,
    CalendarProviderConfig,
    CalendarSyncService,
)
from app.services.calendar_integrations.credentials import (
    assert_apple_caldav_connection_active,
    get_apple_caldav_connection_by_connection_id,
    get_apple_caldav_calendar_sync_state,
    get_apple_caldav_event_link,
    get_apple_caldav_event_link_by_resource_url,
    get_apple_caldav_event_link_by_internal_event,
    mark_apple_caldav_event_link_deleted,
    record_apple_caldav_sync_run_result,
    record_apple_conflict_audit,
    upsert_apple_caldav_event_link,
)

def _record_calendar_metric(metric_name: str, **kwargs: Any) -> None:
    try:
        from app import metrics as _metrics

        metric_fn = getattr(_metrics, metric_name, None)
        if callable(metric_fn):
            metric_fn(**kwargs)
    except Exception:
        return


def _probe_caldav_credentials(*, base_url: str, username: str, secret: str, timeout_seconds: float) -> None:
    auth_raw = f"{username}:{secret}".encode("utf-8")
    auth_token = base64.b64encode(auth_raw).decode("ascii")
    req = urlrequest.Request(
        f"{(base_url or '').rstrip('/')}/",
        method="GET",
        headers={
            "Authorization": f"Basic {auth_token}",
            "Depth": "0",
        },
    )
    with urlrequest.urlopen(req, timeout=timeout_seconds) as _:
        return


def _parse_caldav_discovery_xml(*, payload: bytes, base_url: str) -> list[dict[str, str]]:
    root = ET.fromstring(payload)
    ns = {
        "d": "DAV:",
        "c": "urn:ietf:params:xml:ns:caldav",
    }
    calendars: list[dict[str, str]] = []
    base = (base_url or "").rstrip("/")

    for response in root.findall("d:response", ns):
        href = response.findtext("d:href", default="", namespaces=ns).strip()
        display_name = response.findtext(
            "d:propstat/d:prop/d:displayname",
            default="",
            namespaces=ns,
        ).strip()
        resource_type = response.find("d:propstat/d:prop/d:resourcetype", ns)
        has_calendar_type = resource_type is not None and resource_type.find("c:calendar", ns) is not None
        if not href or not has_calendar_type:
            continue
        full_url = urlparse.urljoin(f"{base}/", href)
        calendar_id = href.rstrip("/").split("/")[-1] or full_url.rstrip("/").split("/")[-1]
        calendars.append(
            {
                "calendar_id": calendar_id,
                "calendar_url": full_url,
                "display_name": display_name or calendar_id,
            }
        )
    return calendars


def _discover_caldav_collections(*, base_url: str, username: str, secret: str, timeout_seconds: float) -> list[dict[str, str]]:
    auth_raw = f"{username}:{secret}".encode("utf-8")
    auth_token = base64.b64encode(auth_raw).decode("ascii")
    body = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">'
        "<d:prop><d:displayname/><d:resourcetype/></d:prop>"
        "</d:propfind>"
    ).encode("utf-8")
    req = urlrequest.Request(
        f"{(base_url or '').rstrip('/')}/",
        method="PROPFIND",
        data=body,
        headers={
            "Authorization": f"Basic {auth_token}",
            "Depth": "1",
            "Content-Type": "application/xml; charset=utf-8",
        },
    )
    with urlrequest.urlopen(req, timeout=timeout_seconds) as resp:
        payload = resp.read()
    return _parse_caldav_discovery_xml(payload=payload, base_url=base_url)


def _is_forbidden_egress_host(hostname: str) -> bool:
    normalized = str(hostname or "").strip().lower()
    if not normalized:
        return True
    if normalized in {"localhost", "localhost.localdomain"}:
        return True
    try:
        addr = ipaddress.ip_address(normalized)
    except ValueError:
        return False
    return bool(
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def _assert_safe_caldav_base_url(base_url: str) -> None:
    parsed = urlparse.urlparse(str(base_url or "").strip())
    if parsed.scheme.lower() != "https":
        raise CalendarIntegrationError(
            code=CalendarIntegrationErrorCode.PROTOCOL,
            detail="Apple CalDAV base URL must use https",
            retriable=False,
        )
    if parsed.username or parsed.password:
        raise CalendarIntegrationError(
            code=CalendarIntegrationErrorCode.PROTOCOL,
            detail="Apple CalDAV base URL must not include embedded credentials",
            retriable=False,
        )
    host = parsed.hostname or ""
    if _is_forbidden_egress_host(host):
        raise CalendarIntegrationError(
            code=CalendarIntegrationErrorCode.PROTOCOL,
            detail="Apple CalDAV base URL host is not allowed",
            retriable=False,
        )

    try:
        resolved = socket.getaddrinfo(host, parsed.port or 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        # Defer DNS errors to the normal probe path which returns a retriable
        # network error. This block is only for SSRF egress safety checks.
        return
    for info in resolved:
        sockaddr = info[4] if len(info) > 4 else ()
        ip = str(sockaddr[0]) if sockaddr else ""
        if _is_forbidden_egress_host(ip):
            raise CalendarIntegrationError(
                code=CalendarIntegrationErrorCode.PROTOCOL,
                detail="Apple CalDAV base URL resolved to a forbidden address",
                retriable=False,
            )


def _assert_safe_caldav_resource_url(*, base_url: str, resource_url: str) -> None:
    parsed_resource = urlparse.urlparse(str(resource_url or "").strip())
    if parsed_resource.scheme.lower() != "https":
        raise CalendarIntegrationError(
            code=CalendarIntegrationErrorCode.PROTOCOL,
            detail="Apple CalDAV resource URL must use https",
            retriable=False,
        )
    resource_host = str(parsed_resource.hostname or "").strip().lower()
    if _is_forbidden_egress_host(resource_host):
        raise CalendarIntegrationError(
            code=CalendarIntegrationErrorCode.PROTOCOL,
            detail="Apple CalDAV resource URL host is not allowed",
            retriable=False,
        )
    parsed_base = urlparse.urlparse(str(base_url or "").strip())
    base_host = str(parsed_base.hostname or "").strip().lower()
    if base_host and resource_host and base_host != resource_host:
        raise CalendarIntegrationError(
            code=CalendarIntegrationErrorCode.PROTOCOL,
            detail="Apple CalDAV resource URL host must match configured base URL host",
            retriable=False,
        )


def _unfold_ical_lines(ical_text: str) -> list[str]:
    lines: list[str] = []
    for raw_line in (ical_text or "").splitlines():
        if not raw_line:
            continue
        if raw_line.startswith((" ", "\t")) and lines:
            lines[-1] = f"{lines[-1]}{raw_line[1:]}"
            continue
        lines.append(raw_line)
    return lines


def _parse_ical_property(line: str) -> tuple[str, dict[str, str], str]:
    head, sep, value = line.partition(":")
    if not sep:
        return line.strip().upper(), {}, ""

    parts = head.split(";")
    name = parts[0].strip().upper()
    params: dict[str, str] = {}
    for part in parts[1:]:
        k, eq, v = part.partition("=")
        if not eq:
            continue
        params[k.strip().upper()] = v.strip()
    return name, params, value


def _decode_ical_text(value: str) -> str:
    return (
        str(value or "")
        .replace("\\n", "\n")
        .replace("\\N", "\n")
        .replace("\\,", ",")
        .replace("\\;", ";")
        .replace("\\\\", "\\")
        .strip()
    )


def _map_status(status_raw: str | None) -> str:
    normalized = str(status_raw or "").strip().upper()
    if normalized == "TENTATIVE":
        return "tentative"
    if normalized == "CANCELLED":
        return "cancelled"
    if normalized in {"CONFIRMED", ""}:
        return "busy"
    return "busy"


def _status_to_ical(status: str | None) -> str:
    normalized = str(status or "").strip().lower()
    if normalized == "tentative":
        return "TENTATIVE"
    if normalized == "cancelled":
        return "CANCELLED"
    return "CONFIRMED"


def _format_ical_text(value: str | None) -> str:
    return (
        str(value or "")
        .replace("\\", "\\\\")
        .replace("\n", "\\n")
        .replace(",", "\\,")
        .replace(";", "\\;")
    )


def _stable_uid_for_internal_event(event: dict[str, Any], existing_uid: str | None = None) -> str:
    provided = str(existing_uid or event.get("remote_uid") or event.get("uid") or "").strip()
    if provided:
        return provided
    internal_id = str(event.get("internal_event_id") or event.get("event_id") or event.get("id") or "").strip()
    if internal_id:
        return f"{internal_id}@internal.calendar.local"
    return f"generated-{uuid.uuid4().hex}@internal.calendar.local"


def _parse_rrule_value(value: str, parse_errors: list[dict[str, str]]) -> dict[str, Any] | None:
    parts: dict[str, str] = {}
    for segment in str(value or "").split(";"):
        key, eq, val = segment.partition("=")
        if not eq:
            continue
        parts[key.strip().upper()] = val.strip()

    freq = parts.get("FREQ", "").upper()
    if freq not in {"DAILY", "WEEKLY", "MONTHLY"}:
        parse_errors.append(
            {
                "code": "unsupported_recurrence",
                "field": "RRULE",
                "message": "Only DAILY, WEEKLY, and MONTHLY recurrence frequencies are supported",
            }
        )
        return None

    unsupported_keys = set(parts.keys()) - {"FREQ", "INTERVAL", "UNTIL", "COUNT", "BYDAY", "BYMONTHDAY"}
    if unsupported_keys:
        parse_errors.append(
            {
                "code": "unsupported_recurrence",
                "field": "RRULE",
                "message": f"Unsupported RRULE components: {', '.join(sorted(unsupported_keys))}",
            }
        )
        return None

    interval_raw = str(parts.get("INTERVAL", "1") or "1").strip()
    try:
        interval = int(interval_raw)
    except ValueError:
        parse_errors.append(
            {"code": "invalid_recurrence_value", "field": "RRULE", "message": "INTERVAL must be an integer"}
        )
        return None
    if interval < 1:
        parse_errors.append(
            {"code": "invalid_recurrence_value", "field": "RRULE", "message": "INTERVAL must be >= 1"}
        )
        return None

    rule: dict[str, Any] = {"freq": freq, "interval": interval}
    if parts.get("COUNT"):
        count_raw = str(parts["COUNT"]).strip()
        try:
            count = int(count_raw)
        except ValueError:
            parse_errors.append(
                {"code": "invalid_recurrence_value", "field": "RRULE", "message": "COUNT must be an integer"}
            )
            return None
        if count < 1:
            parse_errors.append(
                {"code": "invalid_recurrence_value", "field": "RRULE", "message": "COUNT must be >= 1"}
            )
            return None
        rule["count"] = count
    if parts.get("UNTIL"):
        until = parts["UNTIL"]
        if until.endswith("Z") and len(until) == 16:
            parsed = datetime.strptime(until, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
            rule["until_utc"] = parsed.isoformat().replace("+00:00", "Z")
        else:
            parse_errors.append(
                {"code": "unsupported_recurrence", "field": "RRULE", "message": "UNTIL must be UTC datetime in YYYYMMDDTHHMMSSZ format"}
            )
            return None
    if parts.get("BYDAY"):
        rule["byday"] = [item.strip().upper() for item in parts["BYDAY"].split(",") if item.strip()]
    if parts.get("BYMONTHDAY"):
        bymonthdays: list[int] = []
        for item in parts["BYMONTHDAY"].split(","):
            normalized = item.strip()
            if not normalized:
                continue
            try:
                day = int(normalized)
            except ValueError:
                parse_errors.append(
                    {"code": "invalid_recurrence_value", "field": "RRULE", "message": "BYMONTHDAY values must be integers"}
                )
                return None
            if day == 0 or day < -31 or day > 31:
                parse_errors.append(
                    {"code": "invalid_recurrence_value", "field": "RRULE", "message": "BYMONTHDAY values must be between -31 and 31, excluding 0"}
                )
                return None
            bymonthdays.append(day)
        rule["bymonthday"] = bymonthdays
    return rule


def _serialize_rrule_value(rule: dict[str, Any]) -> str:
    freq = str(rule.get("freq") or "").upper()
    if freq not in {"DAILY", "WEEKLY", "MONTHLY"}:
        raise ValueError("Unsupported recurrence frequency. Only DAILY, WEEKLY, MONTHLY are supported.")

    unsupported = [k for k in rule.keys() if k not in {"freq", "interval", "until_utc", "count", "byday", "bymonthday"}]
    if unsupported:
        raise ValueError(f"Unsupported recurrence pattern fields: {', '.join(sorted(unsupported))}")

    parts = [f"FREQ={freq}", f"INTERVAL={int(rule.get('interval') or 1)}"]
    if rule.get("count") is not None:
        parts.append(f"COUNT={int(rule['count'])}")
    if rule.get("until_utc"):
        until = datetime.fromisoformat(str(rule["until_utc"]).replace("Z", "+00:00")).astimezone(timezone.utc)
        parts.append(f"UNTIL={until.strftime('%Y%m%dT%H%M%SZ')}")
    if rule.get("byday"):
        if freq != "WEEKLY":
            raise ValueError("BYDAY is only supported for WEEKLY recurrence in phase 1.")
        parts.append("BYDAY=" + ",".join([str(v).upper() for v in rule.get("byday") or []]))
    if rule.get("bymonthday"):
        if freq != "MONTHLY":
            raise ValueError("BYMONTHDAY is only supported for MONTHLY recurrence in phase 1.")
        parts.append("BYMONTHDAY=" + ",".join([str(int(v)) for v in rule.get("bymonthday") or []]))
    return ";".join(parts)


def _format_ical_utc_timestamp(value: str) -> str:
    dt = datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(timezone.utc)
    return dt.strftime("%Y%m%dT%H%M%SZ")


def _parse_ical_timestamp_to_utc(value: str, tzid: str | None, parse_errors: list[dict[str, str]], field: str) -> str | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    if raw.endswith("Z"):
        try:
            dt = datetime.strptime(raw, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
            return dt.isoformat().replace("+00:00", "Z")
        except ValueError:
            parse_errors.append({"code": "invalid_datetime", "field": field, "message": f"Invalid UTC datetime: {raw}"})
            return None
    try:
        dt = datetime.strptime(raw, "%Y%m%dT%H%M%S")
    except ValueError:
        parse_errors.append({"code": "invalid_datetime", "field": field, "message": f"Invalid datetime: {raw}"})
        return None
    if ZoneInfo is None:
        parse_errors.append({"code": "unsupported_timezone", "field": field, "message": "zoneinfo module unavailable"})
        return None
    timezone_name = str(tzid or "UTC")
    try:
        return dt.replace(tzinfo=ZoneInfo(timezone_name)).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except Exception:
        parse_errors.append({"code": "invalid_timezone", "field": field, "message": f"Invalid TZID: {timezone_name}"})
        return None


def serialize_internal_event_to_ical(
    *,
    event: dict[str, Any],
    existing_uid: str | None = None,
    default_timezone: str = "UTC",
) -> dict[str, str]:
    uid = _stable_uid_for_internal_event(event, existing_uid=existing_uid)
    tz_name = str(event.get("timezone") or default_timezone or "UTC")
    all_day = bool(event.get("all_day"))

    lines: list[str] = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//OpenKBS//Apple CalDAV Integration//EN",
        "BEGIN:VEVENT",
        f"UID:{uid}",
        f"SUMMARY:{_format_ical_text(str(event.get('name') or 'Untitled'))}",
        f"DESCRIPTION:{_format_ical_text(str(event.get('description') or ''))}",
        f"LOCATION:{_format_ical_text(str(event.get('location') or ''))}",
        f"STATUS:{_status_to_ical(str(event.get('status') or 'busy'))}",
    ]

    if all_day:
        all_day_date = str(event.get("all_day_date") or "").strip()
        if len(all_day_date) != 10:
            raise ValueError("all_day_date must be YYYY-MM-DD for all-day events")
        ymd = all_day_date.replace("-", "")
        next_day = datetime.strptime(ymd, "%Y%m%d").replace(tzinfo=timezone.utc) + timedelta(days=1)
        lines.append(f"DTSTART;VALUE=DATE:{ymd}")
        lines.append(f"DTEND;VALUE=DATE:{next_day.strftime('%Y%m%d')}")
    else:
        start_utc = str(event.get("start_utc") or "").strip()
        end_utc = str(event.get("end_utc") or "").strip()
        if not start_utc or not end_utc:
            raise ValueError("start_utc and end_utc are required for timed events")

        start_dt = datetime.fromisoformat(start_utc.replace("Z", "+00:00")).astimezone(timezone.utc)
        end_dt = datetime.fromisoformat(end_utc.replace("Z", "+00:00")).astimezone(timezone.utc)
        if ZoneInfo is not None:
            try:
                start_local = start_dt.astimezone(ZoneInfo(tz_name))
                end_local = end_dt.astimezone(ZoneInfo(tz_name))
                lines.append(f"DTSTART;TZID={tz_name}:{start_local.strftime('%Y%m%dT%H%M%S')}")
                lines.append(f"DTEND;TZID={tz_name}:{end_local.strftime('%Y%m%dT%H%M%S')}")
            except Exception:
                lines.append(f"DTSTART:{start_dt.strftime('%Y%m%dT%H%M%SZ')}")
                lines.append(f"DTEND:{end_dt.strftime('%Y%m%dT%H%M%SZ')}")
        else:
            lines.append(f"DTSTART:{start_dt.strftime('%Y%m%dT%H%M%SZ')}")
            lines.append(f"DTEND:{end_dt.strftime('%Y%m%dT%H%M%SZ')}")

    recurrence_rule = event.get("recurrence_rule")
    if recurrence_rule:
        lines.append(f"RRULE:{_serialize_rrule_value(dict(recurrence_rule))}")
    recurrence_id_utc = str(event.get("recurrence_id_utc") or "").strip()
    if recurrence_id_utc:
        lines.append(f"RECURRENCE-ID:{_format_ical_utc_timestamp(recurrence_id_utc)}")
    exdates_utc = list(event.get("exdates_utc") or [])
    if exdates_utc:
        values = ",".join([_format_ical_utc_timestamp(str(v)) for v in exdates_utc if str(v).strip()])
        if values:
            lines.append(f"EXDATE:{values}")

    lines.extend(["END:VEVENT", "END:VCALENDAR", ""])
    return {"uid": uid, "ical": "\r\n".join(lines)}


def _parse_ical_dt_value(
    *,
    name: str,
    value: str,
    tzid: str | None,
    default_timezone: str,
    parse_errors: list[dict[str, str]],
) -> tuple[str | None, str]:
    raw = str(value or "").strip()
    if not raw:
        parse_errors.append({"code": "invalid_datetime", "field": name, "message": "Value is empty"})
        return None, default_timezone

    if len(raw) == 8 and raw.isdigit():
        # all-day date-only value handled by caller
        return None, str(tzid or default_timezone or "UTC")

    fmt = "%Y%m%dT%H%M%SZ" if raw.endswith("Z") else "%Y%m%dT%H%M%S"
    try:
        parsed = datetime.strptime(raw, fmt)
    except ValueError:
        parse_errors.append({"code": "invalid_datetime", "field": name, "message": f"Unsupported datetime format: {raw}"})
        return None, str(tzid or default_timezone or "UTC")

    timezone_name = str(tzid or default_timezone or "UTC").strip() or "UTC"
    if raw.endswith("Z"):
        aware = parsed.replace(tzinfo=timezone.utc)
        return aware.isoformat().replace("+00:00", "Z"), "UTC"

    if ZoneInfo is None:
        parse_errors.append({"code": "unsupported_timezone", "field": name, "message": "zoneinfo module unavailable"})
        return None, timezone_name

    try:
        aware = parsed.replace(tzinfo=ZoneInfo(timezone_name)).astimezone(timezone.utc)
    except Exception:
        parse_errors.append({"code": "invalid_timezone", "field": name, "message": f"Invalid TZID: {timezone_name}"})
        return None, timezone_name
    return aware.isoformat().replace("+00:00", "Z"), timezone_name


def map_ical_to_internal_events(*, ical_payload: bytes | str, default_timezone: str = "UTC") -> dict[str, Any]:
    payload_text = ical_payload.decode("utf-8", errors="replace") if isinstance(ical_payload, bytes) else str(ical_payload or "")
    lines = _unfold_ical_lines(payload_text)

    events: list[dict[str, Any]] = []
    top_level_errors: list[dict[str, str]] = []
    in_event = False
    event_lines: list[str] = []

    for line in lines:
        upper = line.strip().upper()
        if upper == "BEGIN:VEVENT":
            in_event = True
            event_lines = []
            continue
        if upper == "END:VEVENT":
            if in_event:
                events.append(_map_single_vevent(event_lines=event_lines, default_timezone=default_timezone))
            in_event = False
            event_lines = []
            continue
        if in_event:
            event_lines.append(line)

    if in_event:
        top_level_errors.append({"code": "invalid_ical", "message": "Unclosed VEVENT block"})

    return {"events": events, "errors": top_level_errors}


def _map_single_vevent(*, event_lines: list[str], default_timezone: str) -> dict[str, Any]:
    summary = ""
    description = ""
    location = ""
    uid = ""
    status_raw = ""
    dtstart_value: str | None = None
    dtstart_params: dict[str, str] = {}
    dtend_value: str | None = None
    dtend_params: dict[str, str] = {}
    parse_errors: list[dict[str, str]] = []
    recurrence_rule: dict[str, Any] | None = None
    recurrence_id_utc: str | None = None
    exdates_utc: list[str] = []

    for line in event_lines:
        name, params, value = _parse_ical_property(line)
        if name == "SUMMARY":
            summary = _decode_ical_text(value)
        elif name == "DESCRIPTION":
            description = _decode_ical_text(value)
        elif name == "LOCATION":
            location = _decode_ical_text(value)
        elif name == "UID":
            uid = str(value or "").strip()
        elif name == "STATUS":
            status_raw = str(value or "").strip()
        elif name == "DTSTART":
            dtstart_value = str(value or "").strip()
            dtstart_params = params
        elif name == "DTEND":
            dtend_value = str(value or "").strip()
            dtend_params = params
        elif name == "RRULE":
            recurrence_rule = _parse_rrule_value(value, parse_errors)
        elif name == "RECURRENCE-ID":
            recurrence_id_utc = _parse_ical_timestamp_to_utc(
                value=value,
                tzid=params.get("TZID"),
                parse_errors=parse_errors,
                field="RECURRENCE-ID",
            )
        elif name == "EXDATE":
            for item in str(value or "").split(","):
                parsed = _parse_ical_timestamp_to_utc(
                    value=item.strip(),
                    tzid=params.get("TZID"),
                    parse_errors=parse_errors,
                    field="EXDATE",
                )
                if parsed:
                    exdates_utc.append(parsed)

    if not uid:
        parse_errors.append({"code": "missing_required_field", "field": "UID", "message": "VEVENT UID is required"})

    all_day = bool(dtstart_value and (dtstart_params.get("VALUE", "").upper() == "DATE" or len(dtstart_value) == 8))
    timezone_name = str(dtstart_params.get("TZID") or default_timezone or "UTC")
    all_day_date: str | None = None
    start_utc: str | None = None
    end_utc: str | None = None

    if dtstart_value:
        if all_day:
            if len(dtstart_value) == 8 and dtstart_value.isdigit():
                all_day_date = f"{dtstart_value[0:4]}-{dtstart_value[4:6]}-{dtstart_value[6:8]}"
            else:
                parse_errors.append(
                    {"code": "invalid_date", "field": "DTSTART", "message": f"Invalid all-day DTSTART value: {dtstart_value}"}
                )
        else:
            start_utc, timezone_name = _parse_ical_dt_value(
                name="DTSTART",
                value=dtstart_value,
                tzid=dtstart_params.get("TZID"),
                default_timezone=default_timezone,
                parse_errors=parse_errors,
            )
    else:
        parse_errors.append({"code": "missing_required_field", "field": "DTSTART", "message": "VEVENT DTSTART is required"})

    if dtend_value and not all_day:
        end_utc, timezone_name = _parse_ical_dt_value(
            name="DTEND",
            value=dtend_value,
            tzid=dtend_params.get("TZID") or dtstart_params.get("TZID"),
            default_timezone=default_timezone,
            parse_errors=parse_errors,
        )
    elif dtend_value and all_day:
        # DATE-style DTEND is optional for our internal all-day representation.
        pass

    if status_raw and status_raw.strip().upper() not in {"CONFIRMED", "TENTATIVE", "CANCELLED"}:
        parse_errors.append(
            {"code": "unsupported_status", "field": "STATUS", "message": f"Unsupported STATUS value: {status_raw}"}
        )

    return {
        "remote_uid": uid,
        "name": summary or uid or "Untitled",
        "description": description,
        "location": location,
        "timezone": timezone_name,
        "all_day": all_day,
        "all_day_date": all_day_date,
        "start_utc": None if all_day else start_utc,
        "end_utc": None if all_day else end_utc,
        "status": _map_status(status_raw),
        "recurrence_rule": recurrence_rule,
        "recurrence_id_utc": recurrence_id_utc,
        "exdates_utc": exdates_utc,
        "is_detached_instance": recurrence_id_utc is not None,
        "parse_errors": parse_errors,
    }


class AppleCalDavConnectionService(CalendarConnectionService):
    provider = CalendarProvider.APPLE_CALDAV

    def __init__(self, config: CalendarProviderConfig) -> None:
        self.config = config

    def validate_credentials(self, *, username: str, secret: str) -> None:
        if not self.config.enabled:
            raise CalendarIntegrationError(
                code=CalendarIntegrationErrorCode.PROTOCOL,
                detail="Apple CalDAV integration is disabled",
                retriable=False,
            )
        if not username.strip() or not secret.strip():
            raise CalendarIntegrationError(
                code=CalendarIntegrationErrorCode.AUTH,
                detail="Both username and app-specific password are required",
                retriable=False,
            )
        _assert_safe_caldav_base_url(self.config.base_url)
        try:
            _probe_caldav_credentials(
                base_url=self.config.base_url,
                username=username.strip(),
                secret=secret.strip(),
                timeout_seconds=max(float(self.config.connect_timeout_seconds), 1.0),
            )
        except urlerror.HTTPError as exc:
            if exc.code in (401, 403):
                _record_calendar_metric("record_calendar_sync_auth_failure", provider=self.provider.value)
                raise CalendarIntegrationError(
                    code=CalendarIntegrationErrorCode.AUTH,
                    detail="Apple credentials invalid or app-specific password is not authorized",
                    retriable=False,
                ) from exc
            raise CalendarIntegrationError(
                code=CalendarIntegrationErrorCode.PROTOCOL,
                detail=f"Apple CalDAV probe failed with HTTP {exc.code}",
                retriable=False,
            ) from exc
        except (urlerror.URLError, TimeoutError, socket.timeout) as exc:
            raise CalendarIntegrationError(
                code=CalendarIntegrationErrorCode.NETWORK,
                detail="Apple CalDAV probe failed due to network timeout/connectivity issue",
                retriable=True,
            ) from exc

    def discover_calendars(self, *, username: str, secret: str) -> list[dict[str, Any]]:
        self.validate_credentials(username=username, secret=secret)
        try:
            discovered = _discover_caldav_collections(
                base_url=self.config.base_url,
                username=username.strip(),
                secret=secret.strip(),
                timeout_seconds=max(float(self.config.read_timeout_seconds), 1.0),
            )
        except urlerror.HTTPError as exc:
            # Graceful empty result for inaccessible/empty collections.
            if exc.code in (403, 404):
                return []
            raise CalendarIntegrationError(
                code=CalendarIntegrationErrorCode.PROTOCOL,
                detail=f"Apple CalDAV discovery failed with HTTP {exc.code}",
                retriable=False,
            ) from exc
        except (urlerror.URLError, TimeoutError, socket.timeout) as exc:
            raise CalendarIntegrationError(
                code=CalendarIntegrationErrorCode.NETWORK,
                detail="Apple CalDAV discovery failed due to network timeout/connectivity issue",
                retriable=True,
            ) from exc

        normalized: list[dict[str, Any]] = []
        for item in discovered:
            normalized.append(
                {
                    "calendar_id": str(item.get("calendar_id") or "").strip(),
                    "calendar_url": str(item.get("calendar_url") or "").strip(),
                    "display_name": str(item.get("display_name") or "").strip(),
                }
            )
        return [it for it in normalized if it["calendar_id"] and it["calendar_url"]]


class AppleCalDavSyncService(CalendarSyncService):
    provider = CalendarProvider.APPLE_CALDAV

    def __init__(self, config: CalendarProviderConfig) -> None:
        self.config = config

    def _is_sync_token_recoverable_error(self, exc: CalendarIntegrationError) -> bool:
        if exc.code != CalendarIntegrationErrorCode.PROTOCOL:
            return False
        detail = str(exc.detail or "").lower()
        return any(
            marker in detail
            for marker in (
                "sync-token",
                "sync token",
                "valid-sync-token",
                "invalidsync",
                "token expired",
                "http 409",
                "http 410",
                " 409",
                " 410",
            )
        )

    def pull_changes(self, *, connection_id: str, calendar_id: str) -> dict[str, int]:
        started_monotonic = time.monotonic()
        if not self.config.enabled:
            raise CalendarIntegrationError(
                code=CalendarIntegrationErrorCode.PROTOCOL,
                detail="Apple CalDAV integration is disabled",
                retriable=False,
            )
        try:
            assert_apple_caldav_connection_active(connection_id=connection_id)
        except ValueError as exc:
            raise CalendarIntegrationError(
                code=CalendarIntegrationErrorCode.PROTOCOL,
                detail=str(exc),
                retriable=False,
            ) from exc
        run_id = f"run_{uuid.uuid4().hex}"
        started_at = datetime.now(timezone.utc).isoformat()
        sync_state = get_apple_caldav_calendar_sync_state(
            connection_id=connection_id,
            external_calendar_id=calendar_id,
        )

        mode = "time_window"
        try:
            if str(sync_state.get("sync_token") or "").strip():
                mode = "sync_token"
                try:
                    remote = self._pull_with_sync_token(
                        connection_id=connection_id,
                        calendar_id=calendar_id,
                        sync_token=str(sync_state.get("sync_token") or ""),
                        calendar_url=str(sync_state.get("calendar_url") or "") or None,
                    )
                except CalendarIntegrationError as exc:
                    if self._is_sync_token_recoverable_error(exc):
                        mode = "ctag_window_fallback"
                        remote = self._pull_with_ctag_or_window(
                            connection_id=connection_id,
                            calendar_id=calendar_id,
                            ctag=str(sync_state.get("ctag") or ""),
                            calendar_url=str(sync_state.get("calendar_url") or "") or None,
                        )
                    else:
                        raise
            else:
                mode = "ctag_window"
                remote = self._pull_with_ctag_or_window(
                    connection_id=connection_id,
                    calendar_id=calendar_id,
                    ctag=str(sync_state.get("ctag") or ""),
                    calendar_url=str(sync_state.get("calendar_url") or "") or None,
                )

            stats = self._reconcile_remote_changes(
                connection_id=connection_id,
                calendar_id=calendar_id,
                run_id=run_id,
                remote_payload=remote,
            )
            record_apple_caldav_sync_run_result(
                run_id=run_id,
                connection_id=connection_id,
                external_calendar_id=calendar_id,
                status="success",
                started_at=started_at,
                sync_token=remote.get("next_sync_token"),
                ctag=remote.get("next_ctag"),
            )
            _record_calendar_metric("record_calendar_sync_run", provider=self.provider.value, mode=mode, outcome="success")
            _record_calendar_metric(
                "record_calendar_sync_latency",
                provider=self.provider.value,
                operation="pull",
                outcome="success",
                elapsed_seconds=time.monotonic() - started_monotonic,
            )
            return stats
        except CalendarIntegrationError:
            record_apple_caldav_sync_run_result(
                run_id=run_id,
                connection_id=connection_id,
                external_calendar_id=calendar_id,
                status="failed",
                started_at=started_at,
                error=f"pull_mode={mode}",
            )
            _record_calendar_metric("record_calendar_sync_run", provider=self.provider.value, mode=mode, outcome="error")
            _record_calendar_metric(
                "record_calendar_sync_latency",
                provider=self.provider.value,
                operation="pull",
                outcome="error",
                elapsed_seconds=time.monotonic() - started_monotonic,
            )
            raise
        except Exception as exc:
            record_apple_caldav_sync_run_result(
                run_id=run_id,
                connection_id=connection_id,
                external_calendar_id=calendar_id,
                status="failed",
                started_at=started_at,
                error=str(exc),
            )
            _record_calendar_metric("record_calendar_sync_run", provider=self.provider.value, mode=mode, outcome="error")
            _record_calendar_metric(
                "record_calendar_sync_latency",
                provider=self.provider.value,
                operation="pull",
                outcome="error",
                elapsed_seconds=time.monotonic() - started_monotonic,
            )
            raise CalendarIntegrationError(
                code=CalendarIntegrationErrorCode.PROTOCOL,
                detail=f"Apple CalDAV pull sync failed: {exc}",
                retriable=False,
            ) from exc

    def _pull_with_sync_token(
        self,
        *,
        connection_id: str,
        calendar_id: str,
        sync_token: str,
        calendar_url: str | None = None,
    ) -> dict[str, Any]:
        try:
            connection = get_apple_caldav_connection_by_connection_id(connection_id=connection_id, include_secret=True)
        except (KeyError, ValueError) as exc:
            raise CalendarIntegrationError(
                code=CalendarIntegrationErrorCode.AUTH,
                detail="Apple CalDAV pull credentials are unavailable",
                retriable=False,
            ) from exc
        username = str(connection.get("username") or "").strip()
        secret = str(connection.get("app_specific_password") or "").strip()
        if not username or not secret:
            raise CalendarIntegrationError(
                code=CalendarIntegrationErrorCode.AUTH,
                detail="Apple CalDAV pull credentials are incomplete",
                retriable=False,
            )

        auth_token = base64.b64encode(f"{username}:{secret}".encode("utf-8")).decode("ascii")
        target_calendar_url = str(calendar_url or "").strip() or f"{(self.config.base_url or '').rstrip('/')}/calendars/{calendar_id}/"
        body = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<d:sync-collection xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">'
            "<d:sync-token>"
            f"{_format_ical_text(sync_token)}"
            "</d:sync-token>"
            "<d:sync-level>1</d:sync-level>"
            "<d:prop><d:getetag/><c:calendar-data/></d:prop>"
            "</d:sync-collection>"
        ).encode("utf-8")
        req = urlrequest.Request(
            target_calendar_url,
            method="REPORT",
            data=body,
            headers={
                "Authorization": f"Basic {auth_token}",
                "Depth": "1",
                "Content-Type": "application/xml; charset=utf-8",
            },
        )
        try:
            with urlrequest.urlopen(req, timeout=max(float(self.config.read_timeout_seconds), 1.0)) as resp:
                payload = resp.read()
        except urlerror.HTTPError as exc:
            if exc.code in (409, 410):
                raise CalendarIntegrationError(
                    code=CalendarIntegrationErrorCode.PROTOCOL,
                    detail=f"sync-token invalidated with HTTP {exc.code}",
                    retriable=False,
                ) from exc
            raise CalendarIntegrationError(
                code=CalendarIntegrationErrorCode.PROTOCOL,
                detail=f"Apple CalDAV sync-token REPORT failed with HTTP {exc.code}",
                retriable=False,
            ) from exc
        except (urlerror.URLError, TimeoutError, socket.timeout) as exc:
            raise CalendarIntegrationError(
                code=CalendarIntegrationErrorCode.NETWORK,
                detail="Apple CalDAV sync-token REPORT failed due to network timeout/connectivity issue",
                retriable=True,
            ) from exc

        ns = {"d": "DAV:", "c": "urn:ietf:params:xml:ns:caldav"}
        try:
            root = ET.fromstring(payload)
        except ET.ParseError as exc:
            raise CalendarIntegrationError(
                code=CalendarIntegrationErrorCode.PROTOCOL,
                detail="Apple CalDAV sync-token REPORT returned malformed XML",
                retriable=False,
            ) from exc

        created: list[dict[str, Any]] = []
        updated: list[dict[str, Any]] = []
        deleted: list[dict[str, Any]] = []
        for response in root.findall("d:response", ns):
            href = str(response.findtext("d:href", default="", namespaces=ns) or "").strip()
            status_values = [str(response.findtext("d:status", default="", namespaces=ns) or "")]
            for node in response.findall("d:propstat/d:status", ns):
                status_values.append(str(node.text or ""))
            status_text = " ".join(status_values).lower()
            etag = str(response.findtext("d:propstat/d:prop/d:getetag", default="", namespaces=ns) or "").strip()
            calendar_data = str(response.findtext("d:propstat/d:prop/c:calendar-data", default="", namespaces=ns) or "")
            href_resource_url = urlparse.urljoin(f"{(self.config.base_url or '').rstrip('/')}/", href.lstrip("/"))
            remote_uid_from_href = href.rstrip("/").split("/")[-1].replace(".ics", "")

            if "404" in status_text:
                existing_by_url = get_apple_caldav_event_link_by_resource_url(
                    connection_id=connection_id,
                    external_calendar_id=calendar_id,
                    resource_url=href_resource_url,
                )
                deleted_uid = str(existing_by_url.get("remote_uid") or "").strip() if existing_by_url else remote_uid_from_href
                if deleted_uid:
                    deleted.append({"remote_uid": deleted_uid})
                continue
            if not calendar_data.strip():
                continue

            mapped = map_ical_to_internal_events(ical_payload=calendar_data)
            for event in list(mapped.get("events") or []):
                remote_uid = str(event.get("remote_uid") or "").strip()
                if not remote_uid:
                    continue
                event["etag"] = etag or event.get("etag")
                event["resource_url"] = href_resource_url
                existing = get_apple_caldav_event_link(
                    connection_id=connection_id,
                    external_calendar_id=calendar_id,
                    remote_uid=remote_uid,
                )
                if existing:
                    updated.append(event)
                else:
                    created.append(event)

        next_sync_token = str(root.findtext("d:sync-token", default="", namespaces=ns) or "").strip() or sync_token
        return {"created": created, "updated": updated, "deleted": deleted, "next_sync_token": next_sync_token, "next_ctag": None}

    def _pull_with_ctag_or_window(
        self,
        *,
        connection_id: str,
        calendar_id: str,
        ctag: str,
        calendar_url: str | None = None,
    ) -> dict[str, Any]:
        try:
            connection = get_apple_caldav_connection_by_connection_id(connection_id=connection_id, include_secret=True)
        except (KeyError, ValueError) as exc:
            raise CalendarIntegrationError(
                code=CalendarIntegrationErrorCode.AUTH,
                detail="Apple CalDAV pull credentials are unavailable",
                retriable=False,
            ) from exc
        username = str(connection.get("username") or "").strip()
        secret = str(connection.get("app_specific_password") or "").strip()
        if not username or not secret:
            raise CalendarIntegrationError(
                code=CalendarIntegrationErrorCode.AUTH,
                detail="Apple CalDAV pull credentials are incomplete",
                retriable=False,
            )

        now = datetime.now(timezone.utc)
        window_start = (now - timedelta(days=90)).strftime("%Y%m%dT%H%M%SZ")
        window_end = (now + timedelta(days=365)).strftime("%Y%m%dT%H%M%SZ")
        auth_token = base64.b64encode(f"{username}:{secret}".encode("utf-8")).decode("ascii")
        target_calendar_url = str(calendar_url or "").strip() or f"{(self.config.base_url or '').rstrip('/')}/calendars/{calendar_id}/"

        # Lightweight ctag probe to avoid full REPORT scans when nothing changed.
        ctag_probe_body = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<d:propfind xmlns:d="DAV:" xmlns:cs="http://calendarserver.org/ns/">'
            "<d:prop><cs:getctag/><d:getetag/></d:prop>"
            "</d:propfind>"
        ).encode("utf-8")
        ctag_probe_req = urlrequest.Request(
            target_calendar_url,
            method="PROPFIND",
            data=ctag_probe_body,
            headers={
                "Authorization": f"Basic {auth_token}",
                "Depth": "0",
                "Content-Type": "application/xml; charset=utf-8",
            },
        )
        current_ctag = ""
        try:
            with urlrequest.urlopen(ctag_probe_req, timeout=max(float(self.config.connect_timeout_seconds), 1.0)) as probe_resp:
                probe_payload = probe_resp.read()
            probe_root = ET.fromstring(probe_payload)
            probe_ns = {"d": "DAV:", "cs": "http://calendarserver.org/ns/"}
            current_ctag = (
                str(probe_root.findtext(".//cs:getctag", default="", namespaces=probe_ns) or "").strip()
                or str(probe_root.findtext(".//d:getetag", default="", namespaces=probe_ns) or "").strip()
            )
        except Exception:
            current_ctag = ""

        if ctag and current_ctag and str(ctag).strip() == current_ctag:
            return {"created": [], "updated": [], "deleted": [], "next_sync_token": None, "next_ctag": current_ctag}

        body = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">'
            "<d:prop><d:getetag/><c:calendar-data/></d:prop>"
            "<c:filter><c:comp-filter name=\"VCALENDAR\"><c:comp-filter name=\"VEVENT\">"
            f"<c:time-range start=\"{window_start}\" end=\"{window_end}\"/>"
            "</c:comp-filter></c:comp-filter></c:filter>"
            "</c:calendar-query>"
        ).encode("utf-8")
        req = urlrequest.Request(
            target_calendar_url,
            method="REPORT",
            data=body,
            headers={
                "Authorization": f"Basic {auth_token}",
                "Depth": "1",
                "Content-Type": "application/xml; charset=utf-8",
            },
        )
        try:
            with urlrequest.urlopen(req, timeout=max(float(self.config.read_timeout_seconds), 1.0)) as resp:
                payload = resp.read()
                resp_headers = getattr(resp, "headers", {}) or {}
                response_ctag = (
                    str(resp_headers.get("X-Apple-Calendar-CTag") or "").strip()
                    or str(resp_headers.get("CTag") or "").strip()
                    or str(resp_headers.get("ETag") or "").strip()
                )
        except urlerror.HTTPError as exc:
            raise CalendarIntegrationError(
                code=CalendarIntegrationErrorCode.PROTOCOL,
                detail=f"Apple CalDAV pull REPORT failed with HTTP {exc.code}",
                retriable=False,
            ) from exc
        except (urlerror.URLError, TimeoutError, socket.timeout) as exc:
            raise CalendarIntegrationError(
                code=CalendarIntegrationErrorCode.NETWORK,
                detail="Apple CalDAV pull REPORT failed due to network timeout/connectivity issue",
                retriable=True,
            ) from exc

        ns = {"d": "DAV:", "c": "urn:ietf:params:xml:ns:caldav", "cs": "http://calendarserver.org/ns/"}
        try:
            root = ET.fromstring(payload)
        except ET.ParseError as exc:
            raise CalendarIntegrationError(
                code=CalendarIntegrationErrorCode.PROTOCOL,
                detail="Apple CalDAV pull REPORT returned malformed XML",
                retriable=False,
            ) from exc
        created: list[dict[str, Any]] = []
        updated: list[dict[str, Any]] = []
        next_ctag = str(response_ctag or "")
        for response in root.findall("d:response", ns):
            href = str(response.findtext("d:href", default="", namespaces=ns) or "").strip()
            etag = str(response.findtext("d:propstat/d:prop/d:getetag", default="", namespaces=ns) or "").strip()
            response_ctag_prop = str(response.findtext("d:propstat/d:prop/cs:getctag", default="", namespaces=ns) or "").strip()
            if response_ctag_prop:
                next_ctag = response_ctag_prop
            calendar_data = str(response.findtext("d:propstat/d:prop/c:calendar-data", default="", namespaces=ns) or "")
            if not calendar_data.strip():
                continue
            mapped = map_ical_to_internal_events(ical_payload=calendar_data)
            for event in list(mapped.get("events") or []):
                remote_uid = str(event.get("remote_uid") or "").strip()
                if not remote_uid:
                    continue
                event["etag"] = etag or event.get("etag")
                event["resource_url"] = urlparse.urljoin(f"{(self.config.base_url or '').rstrip('/')}/", href.lstrip("/"))
                existing = get_apple_caldav_event_link(
                    connection_id=connection_id,
                    external_calendar_id=calendar_id,
                    remote_uid=remote_uid,
                )
                if existing:
                    updated.append(event)
                else:
                    created.append(event)

        return {"created": created, "updated": updated, "deleted": [], "next_sync_token": None, "next_ctag": next_ctag or ctag or None}

    def _reconcile_remote_changes(
        self,
        *,
        connection_id: str,
        calendar_id: str,
        run_id: str,
        remote_payload: dict[str, Any],
    ) -> dict[str, int]:
        created = 0
        updated = 0
        deleted = 0

        for event in list(remote_payload.get("created") or []):
            remote_uid = str(event.get("remote_uid") or event.get("uid") or "").strip()
            if not remote_uid:
                continue
            internal_event_id = self._upsert_internal_event_from_remote(
                connection_id=connection_id,
                calendar_id=calendar_id,
                remote_event=event,
                existing_internal_event_id=None,
            )
            upsert_apple_caldav_event_link(
                connection_id=connection_id,
                external_calendar_id=calendar_id,
                remote_uid=remote_uid,
                internal_event_id=internal_event_id,
                run_id=run_id,
                resource_url=event.get("resource_url"),
                etag=event.get("etag"),
            )
            created += 1

        for event in list(remote_payload.get("updated") or []):
            remote_uid = str(event.get("remote_uid") or event.get("uid") or "").strip()
            if not remote_uid:
                continue
            link = get_apple_caldav_event_link(
                connection_id=connection_id,
                external_calendar_id=calendar_id,
                remote_uid=remote_uid,
            ) or {}
            internal_event_id = self._upsert_internal_event_from_remote(
                connection_id=connection_id,
                calendar_id=calendar_id,
                remote_event=event,
                existing_internal_event_id=str(link.get("internal_event_id") or "") or None,
            )
            upsert_apple_caldav_event_link(
                connection_id=connection_id,
                external_calendar_id=calendar_id,
                remote_uid=remote_uid,
                internal_event_id=internal_event_id,
                run_id=run_id,
                resource_url=event.get("resource_url"),
                etag=event.get("etag"),
            )
            updated += 1

        for event in list(remote_payload.get("deleted") or []):
            remote_uid = str(event.get("remote_uid") or event.get("uid") or "").strip()
            if not remote_uid:
                continue
            link = get_apple_caldav_event_link(
                connection_id=connection_id,
                external_calendar_id=calendar_id,
                remote_uid=remote_uid,
            ) or {}
            internal_event_id = str(link.get("internal_event_id") or "")
            if internal_event_id:
                self._soft_delete_internal_event(
                    connection_id=connection_id,
                    calendar_id=calendar_id,
                    internal_event_id=internal_event_id,
                )
            mark_apple_caldav_event_link_deleted(
                connection_id=connection_id,
                external_calendar_id=calendar_id,
                remote_uid=remote_uid,
                run_id=run_id,
            )
            deleted += 1

        return {"created": created, "updated": updated, "deleted": deleted}

    def _upsert_internal_event_from_remote(
        self,
        *,
        connection_id: str,
        calendar_id: str,
        remote_event: dict[str, Any],
        existing_internal_event_id: str | None = None,
    ) -> str:
        # TODO(TKT-ICAL-014/TKT-ICAL-016): persist into internal calendar event store.
        if existing_internal_event_id:
            return existing_internal_event_id
        return f"int_{uuid.uuid4().hex}"

    def _soft_delete_internal_event(self, *, connection_id: str, calendar_id: str, internal_event_id: str) -> None:
        # TODO(TKT-ICAL-016): implement soft-delete/cancel policy against internal event store.
        return

    def push_event(self, *, connection_id: str, calendar_id: str, event: dict[str, Any]) -> dict[str, Any]:
        started_monotonic = time.monotonic()
        if not self.config.enabled:
            raise CalendarIntegrationError(
                code=CalendarIntegrationErrorCode.PROTOCOL,
                detail="Apple CalDAV integration is disabled",
                retriable=False,
            )
        try:
            assert_apple_caldav_connection_active(connection_id=connection_id)
        except ValueError as exc:
            raise CalendarIntegrationError(
                code=CalendarIntegrationErrorCode.PROTOCOL,
                detail=str(exc),
                retriable=False,
            ) from exc
        operation = str(event.get("operation") or "upsert").strip().lower()
        internal_event_id = str(event.get("internal_event_id") or event.get("event_id") or "").strip()
        existing_link = None
        if internal_event_id:
            existing_link = get_apple_caldav_event_link_by_internal_event(
                connection_id=connection_id,
                external_calendar_id=calendar_id,
                internal_event_id=internal_event_id,
            )
        if not existing_link and str(event.get("remote_uid") or "").strip():
            existing_link = get_apple_caldav_event_link(
                connection_id=connection_id,
                external_calendar_id=calendar_id,
                remote_uid=str(event.get("remote_uid") or ""),
            )

        if operation == "delete":
            out = self._push_delete(
                connection_id=connection_id,
                calendar_id=calendar_id,
                event=event,
                existing_link=existing_link,
            )
        else:
            out = self._push_upsert(
                connection_id=connection_id,
                calendar_id=calendar_id,
                event=event,
                existing_link=existing_link,
            )

        status = str(out.get("status") or "unknown").lower()
        outcome = "success" if status in {"ok", "noop"} else "error"
        if status == "conflict":
            outcome = "conflict"
            _record_calendar_metric(
                "record_calendar_sync_conflict",
                provider=self.provider.value,
                reason=str(out.get("conflict_reason") or "unknown"),
                operation=operation,
            )
        _record_calendar_metric("record_calendar_sync_run", provider=self.provider.value, mode="push", outcome=outcome)
        _record_calendar_metric(
            "record_calendar_sync_latency",
            provider=self.provider.value,
            operation="push",
            outcome=outcome,
            elapsed_seconds=time.monotonic() - started_monotonic,
        )
        return out

    def _push_upsert(
        self,
        *,
        connection_id: str,
        calendar_id: str,
        event: dict[str, Any],
        existing_link: dict[str, Any] | None,
    ) -> dict[str, Any]:
        serialized = serialize_internal_event_to_ical(
            event=event,
            existing_uid=str(existing_link.get("remote_uid") or "") if existing_link else None,
            default_timezone=str(event.get("timezone") or "UTC"),
        )
        uid = serialized["uid"]
        resource_url = str(existing_link.get("resource_url") or "") if existing_link else self._build_resource_url(calendar_id=calendar_id, uid=uid)
        if_match = str(existing_link.get("etag") or "").strip() if existing_link else None

        try:
            remote_write = self._caldav_upsert_event(
                connection_id=connection_id,
                calendar_id=calendar_id,
                resource_url=resource_url,
                ical_payload=serialized["ical"],
                if_match=if_match,
            )
        except CalendarIntegrationError as exc:
            if "etag_mismatch" in str(exc.detail).lower() or "precondition" in str(exc.detail).lower():
                record_apple_conflict_audit(
                    connection_id=connection_id,
                    external_calendar_id=calendar_id,
                    internal_event_id=str(event.get("internal_event_id") or event.get("event_id") or None),
                    remote_uid=uid,
                    resolution="remote_wins_etag_conflict",
                    local_updated_at=str(event.get("updated_at") or ""),
                    remote_updated_at=None,
                    details={"operation": "update", "reason": "etag_mismatch"},
                )
                return {
                    "provider": self.provider.value,
                    "connection_id": connection_id,
                    "calendar_id": calendar_id,
                    "status": "conflict",
                    "conflict_reason": "etag_mismatch",
                    "remote_uid": uid,
                }
            raise

        remote_url = str(remote_write.get("resource_url") or resource_url)
        remote_etag = str(remote_write.get("etag") or "")
        upsert_apple_caldav_event_link(
            connection_id=connection_id,
            external_calendar_id=calendar_id,
            remote_uid=uid,
            internal_event_id=str(event.get("internal_event_id") or event.get("event_id") or uid),
            run_id=f"push_{uuid.uuid4().hex}",
            resource_url=remote_url,
            etag=remote_etag,
        )
        return {
            "provider": self.provider.value,
            "connection_id": connection_id,
            "calendar_id": calendar_id,
            "status": "ok",
            "operation": "upsert",
            "remote_uid": uid,
            "resource_url": remote_url,
            "etag": remote_etag,
        }

    def _push_delete(
        self,
        *,
        connection_id: str,
        calendar_id: str,
        event: dict[str, Any],
        existing_link: dict[str, Any] | None,
    ) -> dict[str, Any]:
        if not existing_link:
            return {
                "provider": self.provider.value,
                "connection_id": connection_id,
                "calendar_id": calendar_id,
                "status": "noop",
                "operation": "delete",
            }
        recurrence_id_utc = str(event.get("recurrence_id_utc") or "").strip()
        if recurrence_id_utc:
            exdate_patch = self._build_exdate_patch_ical(
                uid=str(existing_link.get("remote_uid") or ""),
                recurrence_id_utc=recurrence_id_utc,
            )
            self._caldav_upsert_event(
                connection_id=connection_id,
                calendar_id=calendar_id,
                resource_url=str(existing_link.get("resource_url") or ""),
                ical_payload=exdate_patch,
                if_match=str(existing_link.get("etag") or "").strip() or None,
            )
            return {
                "provider": self.provider.value,
                "connection_id": connection_id,
                "calendar_id": calendar_id,
                "status": "ok",
                "operation": "delete_instance",
                "remote_uid": str(existing_link.get("remote_uid") or ""),
                "recurrence_id_utc": recurrence_id_utc,
            }
        resource_url = str(existing_link.get("resource_url") or "")
        if_match = str(existing_link.get("etag") or "").strip() or None
        remote_uid = str(existing_link.get("remote_uid") or "")

        try:
            self._caldav_delete_event(
                connection_id=connection_id,
                calendar_id=calendar_id,
                resource_url=resource_url,
                if_match=if_match,
            )
        except CalendarIntegrationError as exc:
            if "etag_mismatch" in str(exc.detail).lower() or "precondition" in str(exc.detail).lower():
                record_apple_conflict_audit(
                    connection_id=connection_id,
                    external_calendar_id=calendar_id,
                    internal_event_id=str(existing_link.get("internal_event_id") or None),
                    remote_uid=remote_uid,
                    resolution="remote_wins_etag_conflict",
                    local_updated_at=str(event.get("updated_at") or ""),
                    remote_updated_at=None,
                    details={"operation": "delete", "reason": "etag_mismatch"},
                )
                return {
                    "provider": self.provider.value,
                    "connection_id": connection_id,
                    "calendar_id": calendar_id,
                    "status": "conflict",
                    "operation": "delete",
                    "conflict_reason": "etag_mismatch",
                    "remote_uid": remote_uid,
                }
            raise

        mark_apple_caldav_event_link_deleted(
            connection_id=connection_id,
            external_calendar_id=calendar_id,
            remote_uid=remote_uid,
            run_id=f"push_{uuid.uuid4().hex}",
        )
        return {
            "provider": self.provider.value,
            "connection_id": connection_id,
            "calendar_id": calendar_id,
            "status": "ok",
            "operation": "delete",
            "remote_uid": remote_uid,
        }

    def _build_exdate_patch_ical(self, *, uid: str, recurrence_id_utc: str) -> str:
        lines = [
            "BEGIN:VCALENDAR",
            "VERSION:2.0",
            "PRODID:-//OpenKBS//Apple CalDAV Integration//EN",
            "BEGIN:VEVENT",
            f"UID:{uid}",
            f"EXDATE:{_format_ical_utc_timestamp(recurrence_id_utc)}",
            "END:VEVENT",
            "END:VCALENDAR",
            "",
        ]
        return "\r\n".join(lines)

    def _build_resource_url(self, *, calendar_id: str, uid: str) -> str:
        base = (self.config.base_url or "https://caldav.icloud.com").rstrip("/")
        return f"{base}/calendars/{calendar_id}/{uid}.ics"

    def _caldav_upsert_event(
        self,
        *,
        connection_id: str | None = None,
        calendar_id: str,
        resource_url: str,
        ical_payload: str,
        if_match: str | None,
    ) -> dict[str, Any]:
        if not connection_id:
            return {"resource_url": resource_url, "etag": f"etag-{uuid.uuid4().hex}"}

        try:
            connection = get_apple_caldav_connection_by_connection_id(connection_id=connection_id, include_secret=True)
        except (KeyError, ValueError) as exc:
            raise CalendarIntegrationError(
                code=CalendarIntegrationErrorCode.AUTH,
                detail="Apple CalDAV connection credentials are unavailable",
                retriable=False,
            ) from exc
        username = str(connection.get("username") or "").strip()
        secret = str(connection.get("app_specific_password") or "").strip()
        if not username or not secret:
            raise CalendarIntegrationError(
                code=CalendarIntegrationErrorCode.AUTH,
                detail="Apple CalDAV connection credentials are incomplete",
                retriable=False,
            )
        _assert_safe_caldav_resource_url(base_url=self.config.base_url, resource_url=resource_url)
        auth_token = base64.b64encode(f"{username}:{secret}".encode("utf-8")).decode("ascii")

        headers = {
            "Authorization": f"Basic {auth_token}",
            "Content-Type": "text/calendar; charset=utf-8",
        }
        if if_match:
            headers["If-Match"] = str(if_match).strip()
        else:
            headers["If-None-Match"] = "*"

        req = urlrequest.Request(
            str(resource_url or "").strip(),
            method="PUT",
            data=(ical_payload or "").encode("utf-8"),
            headers=headers,
        )
        try:
            with urlrequest.urlopen(req, timeout=max(float(self.config.read_timeout_seconds), 1.0)) as resp:
                out_url = str(resp.geturl() or resource_url)
                out_etag = str(resp.headers.get("ETag") or "").strip() or f"etag-{uuid.uuid4().hex}"
                return {"resource_url": out_url, "etag": out_etag}
        except urlerror.HTTPError as exc:
            if exc.code == 412:
                raise CalendarIntegrationError(
                    code=CalendarIntegrationErrorCode.PROTOCOL,
                    detail="etag_mismatch precondition failed",
                    retriable=False,
                ) from exc
            raise CalendarIntegrationError(
                code=CalendarIntegrationErrorCode.PROTOCOL,
                detail=f"Apple CalDAV push upsert failed with HTTP {exc.code}",
                retriable=False,
            ) from exc
        except (urlerror.URLError, TimeoutError, socket.timeout) as exc:
            raise CalendarIntegrationError(
                code=CalendarIntegrationErrorCode.NETWORK,
                detail="Apple CalDAV push upsert failed due to network timeout/connectivity issue",
                retriable=True,
            ) from exc

    def _caldav_delete_event(
        self,
        *,
        connection_id: str | None = None,
        calendar_id: str,
        resource_url: str,
        if_match: str | None,
    ) -> None:
        if not connection_id:
            return

        try:
            connection = get_apple_caldav_connection_by_connection_id(connection_id=connection_id, include_secret=True)
        except (KeyError, ValueError) as exc:
            raise CalendarIntegrationError(
                code=CalendarIntegrationErrorCode.AUTH,
                detail="Apple CalDAV connection credentials are unavailable",
                retriable=False,
            ) from exc
        username = str(connection.get("username") or "").strip()
        secret = str(connection.get("app_specific_password") or "").strip()
        if not username or not secret:
            raise CalendarIntegrationError(
                code=CalendarIntegrationErrorCode.AUTH,
                detail="Apple CalDAV connection credentials are incomplete",
                retriable=False,
            )
        _assert_safe_caldav_resource_url(base_url=self.config.base_url, resource_url=resource_url)
        auth_token = base64.b64encode(f"{username}:{secret}".encode("utf-8")).decode("ascii")

        headers = {"Authorization": f"Basic {auth_token}"}
        if if_match:
            headers["If-Match"] = str(if_match).strip()
        req = urlrequest.Request(
            str(resource_url or "").strip(),
            method="DELETE",
            headers=headers,
        )
        try:
            with urlrequest.urlopen(req, timeout=max(float(self.config.read_timeout_seconds), 1.0)):
                return
        except urlerror.HTTPError as exc:
            if exc.code in (404, 410):
                return
            if exc.code == 412:
                raise CalendarIntegrationError(
                    code=CalendarIntegrationErrorCode.PROTOCOL,
                    detail="etag_mismatch precondition failed",
                    retriable=False,
                ) from exc
            raise CalendarIntegrationError(
                code=CalendarIntegrationErrorCode.PROTOCOL,
                detail=f"Apple CalDAV delete failed with HTTP {exc.code}",
                retriable=False,
            ) from exc
        except (urlerror.URLError, TimeoutError, socket.timeout) as exc:
            raise CalendarIntegrationError(
                code=CalendarIntegrationErrorCode.NETWORK,
                detail="Apple CalDAV delete failed due to network timeout/connectivity issue",
                retriable=True,
            ) from exc
