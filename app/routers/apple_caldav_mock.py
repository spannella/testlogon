"""Stateful mock for Apple CalDAV (iCloud) endpoints used by calendar_integrations/apple_caldav.py."""
from __future__ import annotations

import base64
import uuid
from typing import Any, Dict, List, Optional
from xml.etree.ElementTree import Element, SubElement, tostring

from fastapi import APIRouter, HTTPException, Request, Response

from app.core.settings import S

router = APIRouter(tags=["mock"])

_CREDENTIALS: Dict[str, str] = {}
_CALENDARS: Dict[str, Dict[str, Any]] = {}
_EVENTS: Dict[str, Dict[str, str]] = {}
_CTAGS: Dict[str, str] = {}
_SYNC_TOKENS: Dict[str, str] = {}
_EVENTS_SINCE: Dict[str, List[Dict[str, Any]]] = {}

_DAV_NS = "DAV:"
_CALDAV_NS = "urn:ietf:params:xml:ns:caldav"


def _ensure_mock_enabled() -> None:
    if not getattr(S, "apple_caldav_mock_enabled", False):
        raise HTTPException(404, "Not found")


def _check_basic_auth(request: Request) -> str:
    auth = request.headers.get("Authorization", "")
    if not auth.lower().startswith("basic "):
        raise HTTPException(401, "Unauthorized")
    try:
        decoded = base64.b64decode(auth.split(" ", 1)[1]).decode("utf-8")
        username, password = decoded.split(":", 1)
    except Exception:
        raise HTTPException(401, "Unauthorized")
    expected = _CREDENTIALS.get(username)
    if expected is None or expected != password:
        raise HTTPException(401, "Invalid credentials")
    return username


def _make_multistatus(responses: list[tuple[str, list[tuple[str, str, Optional[str]]]]]) -> bytes:
    ms = Element("d:multistatus")
    ms.set("xmlns:d", _DAV_NS)
    ms.set("xmlns:c", _CALDAV_NS)
    for href, props in responses:
        resp_el = SubElement(ms, "d:response")
        href_el = SubElement(resp_el, "d:href")
        href_el.text = href
        propstat = SubElement(resp_el, "d:propstat")
        prop_el = SubElement(propstat, "d:prop")
        for pname, pval, ns in props:
            if ns:
                child = SubElement(prop_el, pname)
                child.set("xmlns", ns) if False else None
                if pname == "d:resourcetype":
                    if pval == "calendar":
                        SubElement(child, "d:collection")
                        SubElement(child, "c:calendar")
                    elif pval == "collection":
                        SubElement(child, "d:collection")
                else:
                    child.text = pval
            else:
                child = SubElement(prop_el, pname)
                if pname == "d:resourcetype":
                    if pval == "calendar":
                        SubElement(child, "d:collection")
                        SubElement(child, "c:calendar")
                    elif pval == "collection":
                        SubElement(child, "d:collection")
                else:
                    child.text = pval
        status_el = SubElement(propstat, "d:status")
        status_el.text = "HTTP/1.1 200 OK"
    return b'<?xml version="1.0" encoding="utf-8"?>\n' + tostring(ms, encoding="unicode").encode("utf-8")


def _make_sync_response(
    events: list[tuple[str, str, str, bool]],
    sync_token: str,
) -> bytes:
    ms = Element("d:multistatus")
    ms.set("xmlns:d", _DAV_NS)
    ms.set("xmlns:c", _CALDAV_NS)
    for href, etag, ical_data, is_deleted in events:
        resp_el = SubElement(ms, "d:response")
        href_el = SubElement(resp_el, "d:href")
        href_el.text = href
        if is_deleted:
            status_el = SubElement(resp_el, "d:status")
            status_el.text = "HTTP/1.1 404 Not Found"
        else:
            propstat = SubElement(resp_el, "d:propstat")
            prop_el = SubElement(propstat, "d:prop")
            etag_el = SubElement(prop_el, "d:getetag")
            etag_el.text = etag
            cal_data_el = SubElement(prop_el, "c:calendar-data")
            cal_data_el.text = ical_data
            status_el = SubElement(propstat, "d:status")
            status_el.text = "HTTP/1.1 200 OK"
    sync_el = SubElement(ms, "d:sync-token")
    sync_el.text = sync_token
    return b'<?xml version="1.0" encoding="utf-8"?>\n' + tostring(ms, encoding="unicode").encode("utf-8")


def _make_simple_ical(uid: str, summary: str = "Mock Event", dtstart: str = "20260101T120000Z", dtend: str = "20260101T130000Z") -> str:
    return (
        "BEGIN:VCALENDAR\r\n"
        "VERSION:2.0\r\n"
        "PRODID:-//Mock//Mock//EN\r\n"
        "BEGIN:VEVENT\r\n"
        f"UID:{uid}\r\n"
        f"DTSTART:{dtstart}\r\n"
        f"DTEND:{dtend}\r\n"
        f"SUMMARY:{summary}\r\n"
        "END:VEVENT\r\n"
        "END:VCALENDAR\r\n"
    )


@router.api_route("/mock/apple-caldav/", methods=["GET"], include_in_schema=False)
async def probe_credentials(request: Request):
    _ensure_mock_enabled()
    _check_basic_auth(request)
    return Response(status_code=200)


@router.api_route("/mock/apple-caldav/", methods=["PROPFIND"], include_in_schema=False)
async def propfind_root(request: Request):
    _ensure_mock_enabled()
    _check_basic_auth(request)
    responses: list[tuple[str, list[tuple[str, str, Optional[str]]]]] = []
    responses.append(("/mock/apple-caldav/", [("d:resourcetype", "collection", None)]))
    for cal_id, cal_data in _CALENDARS.items():
        display_name = cal_data.get("display_name", cal_id)
        responses.append((
            f"/mock/apple-caldav/calendars/{cal_id}/",
            [
                ("d:resourcetype", "calendar", None),
                ("d:displayname", display_name, None),
            ],
        ))
    body = _make_multistatus(responses)
    return Response(content=body, status_code=207, media_type="application/xml; charset=utf-8")


@router.api_route("/mock/apple-caldav/calendars/{calendar_id}/", methods=["PROPFIND"], include_in_schema=False)
async def propfind_calendar(request: Request, calendar_id: str):
    _ensure_mock_enabled()
    _check_basic_auth(request)
    if calendar_id not in _CALENDARS:
        raise HTTPException(404, "Calendar not found")
    ctag = _CTAGS.get(calendar_id, "ctag-initial")
    responses: list[tuple[str, list[tuple[str, str, Optional[str]]]]] = []
    responses.append((
        f"/mock/apple-caldav/calendars/{calendar_id}/",
        [
            ("d:resourcetype", "calendar", None),
            ("d:displayname", _CALENDARS[calendar_id].get("display_name", calendar_id), None),
            ("cs:getctag", ctag, None),
        ],
    ))
    body = _make_multistatus(responses)
    return Response(content=body, status_code=207, media_type="application/xml; charset=utf-8")


@router.api_route("/mock/apple-caldav/calendars/{calendar_id}/", methods=["REPORT"], include_in_schema=False)
async def report_calendar(request: Request, calendar_id: str):
    _ensure_mock_enabled()
    _check_basic_auth(request)
    if calendar_id not in _CALENDARS:
        raise HTTPException(404, "Calendar not found")

    request_body = await request.body()
    body_str = request_body.decode("utf-8", errors="replace")
    is_sync_collection = "sync-collection" in body_str

    if is_sync_collection:
        import xml.etree.ElementTree as ET
        try:
            root = ET.fromstring(request_body)
        except ET.ParseError:
            raise HTTPException(400, "Invalid XML")
        ns = {"d": _DAV_NS}
        old_sync_token = (root.findtext("d:sync-token", default="", namespaces=ns) or "").strip()
        changes = _EVENTS_SINCE.get(old_sync_token, [])
        event_tuples: list[tuple[str, str, str, bool]] = []
        for change in changes:
            uid = change["uid"]
            href = f"/mock/apple-caldav/calendars/{calendar_id}/{uid}.ics"
            if change.get("deleted"):
                event_tuples.append((href, "", "", True))
            else:
                ical = change.get("ical_data") or _EVENTS.get(f"{calendar_id}:{uid}", {}).get("ical_data", "")
                etag = change.get("etag", f'"{uid}-etag"')
                event_tuples.append((href, etag, ical, False))
        current_token = _SYNC_TOKENS.get(calendar_id, f"sync-token-{calendar_id}-0")
        body = _make_sync_response(event_tuples, current_token)
        return Response(content=body, status_code=207, media_type="application/xml; charset=utf-8")

    event_tuples = []
    prefix = f"{calendar_id}:"
    for key, evt_data in _EVENTS.items():
        if key.startswith(prefix):
            uid = key[len(prefix):]
            href = f"/mock/apple-caldav/calendars/{calendar_id}/{uid}.ics"
            ical = evt_data.get("ical_data", _make_simple_ical(uid))
            etag = evt_data.get("etag", f'"{uid}-etag"')
            event_tuples.append((href, etag, ical, False))
    current_token = _SYNC_TOKENS.get(calendar_id, f"sync-token-{calendar_id}-0")
    body = _make_sync_response(event_tuples, current_token)
    return Response(content=body, status_code=207, media_type="application/xml; charset=utf-8")


@router.api_route("/mock/apple-caldav/calendars/{calendar_id}/{uid_ics}", methods=["PUT"], include_in_schema=False)
async def put_event(request: Request, calendar_id: str, uid_ics: str):
    _ensure_mock_enabled()
    _check_basic_auth(request)
    if calendar_id not in _CALENDARS:
        raise HTTPException(404, "Calendar not found")
    uid = uid_ics.replace(".ics", "")
    ical_data = (await request.body()).decode("utf-8", errors="replace")
    key = f"{calendar_id}:{uid}"
    etag = f'"{uid}-{uuid.uuid4().hex[:8]}"'
    _EVENTS[key] = {"uid": uid, "ical_data": ical_data, "etag": etag, "calendar_id": calendar_id}
    old_token = _SYNC_TOKENS.get(calendar_id, f"sync-token-{calendar_id}-0")
    new_token = f"sync-token-{calendar_id}-{uuid.uuid4().hex[:8]}"
    _SYNC_TOKENS[calendar_id] = new_token
    _CTAGS[calendar_id] = f"ctag-{uuid.uuid4().hex[:8]}"
    _EVENTS_SINCE.setdefault(old_token, []).append({"uid": uid, "ical_data": ical_data, "etag": etag})
    return Response(status_code=201, headers={"ETag": etag})


@router.api_route("/mock/apple-caldav/calendars/{calendar_id}/{uid_ics}", methods=["DELETE"], include_in_schema=False)
async def delete_event(request: Request, calendar_id: str, uid_ics: str):
    _ensure_mock_enabled()
    _check_basic_auth(request)
    uid = uid_ics.replace(".ics", "")
    key = f"{calendar_id}:{uid}"
    _EVENTS.pop(key, None)
    old_token = _SYNC_TOKENS.get(calendar_id, f"sync-token-{calendar_id}-0")
    new_token = f"sync-token-{calendar_id}-{uuid.uuid4().hex[:8]}"
    _SYNC_TOKENS[calendar_id] = new_token
    _CTAGS[calendar_id] = f"ctag-{uuid.uuid4().hex[:8]}"
    _EVENTS_SINCE.setdefault(old_token, []).append({"uid": uid, "deleted": True})
    return Response(status_code=204)


@router.post("/mock/apple-caldav/seed")
async def seed_caldav(request: Request):
    _ensure_mock_enabled()
    data = await request.json()
    if "credentials" in data:
        for username, password in data["credentials"].items():
            _CREDENTIALS[username] = password
    if "calendars" in data:
        for cal_id, cal_data in data["calendars"].items():
            _CALENDARS[cal_id] = cal_data if isinstance(cal_data, dict) else {"display_name": str(cal_data)}
            _CTAGS.setdefault(cal_id, f"ctag-initial-{cal_id}")
            _SYNC_TOKENS.setdefault(cal_id, f"sync-token-{cal_id}-0")
    if "events" in data:
        for key, evt in data["events"].items():
            if isinstance(evt, str):
                cal_id, uid = key.split(":", 1) if ":" in key else ("default", key)
                _EVENTS[key] = {"uid": uid, "ical_data": evt, "etag": f'"{uid}-etag"', "calendar_id": cal_id}
            else:
                _EVENTS[key] = evt
    return {"ok": True, "credentials": len(_CREDENTIALS), "calendars": len(_CALENDARS), "events": len(_EVENTS)}


@router.post("/mock/apple-caldav/reset")
async def reset_caldav():
    _ensure_mock_enabled()
    _CREDENTIALS.clear()
    _CALENDARS.clear()
    _EVENTS.clear()
    _CTAGS.clear()
    _SYNC_TOKENS.clear()
    _EVENTS_SINCE.clear()
    return {"ok": True}
