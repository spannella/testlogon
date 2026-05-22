"""Stateful mock for Google Calendar API and OAuth endpoints."""
from __future__ import annotations

import hashlib
import uuid
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException, Request, Response

from app.core.settings import S
from app.core.time import now_ts

router = APIRouter(tags=["mock"])

_TOKENS: Dict[str, Dict[str, Any]] = {}
_USERS: Dict[str, Dict[str, Any]] = {}
_CALENDARS: Dict[str, Dict[str, Any]] = {}
_EVENTS: Dict[str, Dict[str, Dict[str, Any]]] = {}
_SYNC_TOKENS: Dict[str, str] = {}
_EVENT_CHANGES: Dict[str, List[Dict[str, Any]]] = {}


def _ensure_mock_enabled() -> None:
    if not S.google_calendar_mock_enabled:
        raise HTTPException(404, "Not found")


def _extract_bearer_token(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(401, "Missing bearer token")
    return auth.split(" ", 1)[1].strip()


def _validate_token(request: Request) -> str:
    token = _extract_bearer_token(request)
    if token.startswith("mock-"):
        return token
    if token not in _TOKENS:
        raise HTTPException(401, "Invalid or expired token")
    entry = _TOKENS[token]
    if entry.get("expires_at", 0) and entry["expires_at"] < now_ts():
        raise HTTPException(401, "Token expired")
    return token


def _new_sync_token(calendar_id: str) -> str:
    token = f"sync_{uuid.uuid4().hex[:16]}"
    _SYNC_TOKENS[calendar_id] = token
    _EVENT_CHANGES[token] = []
    return token


def _record_change(calendar_id: str, event: Dict[str, Any]) -> None:
    current = _SYNC_TOKENS.get(calendar_id)
    if current and current in _EVENT_CHANGES:
        _EVENT_CHANGES[current].append(event)


# ---------------------------------------------------------------------------
# OAuth endpoints
# ---------------------------------------------------------------------------

@router.post("/mock/google-calendar/oauth/token")
async def google_oauth_token(request: Request) -> Dict[str, Any]:
    _ensure_mock_enabled()
    form = await request.form()
    grant_type = str(form.get("grant_type") or "")
    client_id = str(form.get("client_id") or "")
    client_secret = str(form.get("client_secret") or "")

    if not client_id or not client_secret:
        raise HTTPException(401, "Missing client credentials")

    if grant_type == "authorization_code":
        code = str(form.get("code") or "")
        if not code:
            raise HTTPException(400, "Missing code")
        access_token = f"mock-at-{hashlib.sha256(f'{code}:{now_ts()}'.encode()).hexdigest()[:20]}"
        refresh_token = f"mock-rt-{hashlib.sha256(f'{code}:refresh'.encode()).hexdigest()[:20]}"
    elif grant_type == "refresh_token":
        refresh_token_in = str(form.get("refresh_token") or "")
        if not refresh_token_in:
            raise HTTPException(400, "Missing refresh_token")
        access_token = f"mock-at-{hashlib.sha256(f'{refresh_token_in}:{now_ts()}'.encode()).hexdigest()[:20]}"
        refresh_token = refresh_token_in
    else:
        raise HTTPException(400, f"Unsupported grant_type: {grant_type}")

    expires_in = 3600
    user_email = ""
    for tok_data in _TOKENS.values():
        if tok_data.get("refresh_token") == (form.get("refresh_token") or ""):
            user_email = tok_data.get("user_email", "")
            break

    _TOKENS[access_token] = {
        "refresh_token": refresh_token,
        "expires_at": now_ts() + expires_in,
        "user_email": user_email,
    }

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_in": expires_in,
        "token_type": "Bearer",
        "scope": "openid email profile https://www.googleapis.com/auth/calendar.events",
    }


@router.get("/mock/google-calendar/oauth/userinfo")
async def google_oauth_userinfo(request: Request) -> Dict[str, Any]:
    _ensure_mock_enabled()
    token = _extract_bearer_token(request)

    if token in _USERS:
        return _USERS[token]

    if token in _TOKENS:
        email = _TOKENS[token].get("user_email", "")
        for user_data in _USERS.values():
            if user_data.get("email") == email:
                return user_data

    # If any seeded user exists, return the first one as a fallback.
    if _USERS:
        return next(iter(_USERS.values()))

    return {
        "sub": f"google-{hashlib.sha256(token.encode()).hexdigest()[:12]}",
        "email": f"mock-{token[:8]}@gmail.com",
        "email_verified": True,
        "name": "Mock User",
        "picture": "",
    }


@router.post("/mock/google-calendar/oauth/revoke")
async def google_oauth_revoke(request: Request) -> Dict[str, Any]:
    _ensure_mock_enabled()
    form = await request.form()
    token = str(form.get("token") or "")
    _TOKENS.pop(token, None)
    return {"ok": True}


# ---------------------------------------------------------------------------
# Calendar API endpoints
# ---------------------------------------------------------------------------

@router.get("/mock/google-calendar/calendar/v3/users/me/calendarList")
async def google_calendar_list(request: Request) -> Dict[str, Any]:
    _ensure_mock_enabled()
    _validate_token(request)
    items = list(_CALENDARS.values())
    return {"kind": "calendar#calendarList", "items": items}


@router.get("/mock/google-calendar/calendar/v3/calendars/{calendar_id}/events")
async def google_events_list(calendar_id: str, request: Request) -> Dict[str, Any]:
    _ensure_mock_enabled()
    _validate_token(request)

    sync_token_param = request.query_params.get("syncToken")

    if sync_token_param:
        changes = _EVENT_CHANGES.get(sync_token_param, [])
        next_sync = _new_sync_token(calendar_id)
        return {
            "kind": "calendar#events",
            "items": changes,
            "nextSyncToken": next_sync,
        }

    cal_events = _EVENTS.get(calendar_id, {})
    items = list(cal_events.values())
    next_sync = _new_sync_token(calendar_id)
    return {
        "kind": "calendar#events",
        "items": items,
        "nextSyncToken": next_sync,
    }


@router.post("/mock/google-calendar/calendar/v3/calendars/{calendar_id}/events")
async def google_event_create(calendar_id: str, request: Request) -> Dict[str, Any]:
    _ensure_mock_enabled()
    _validate_token(request)
    body = await request.json()

    event_id = body.get("id") or uuid.uuid4().hex
    event = {
        "kind": "calendar#event",
        "id": event_id,
        "status": "confirmed",
        "calendarId": calendar_id,
        "created": f"{now_ts()}",
        "updated": f"{now_ts()}",
        **body,
        "id": event_id,
    }

    if calendar_id not in _EVENTS:
        _EVENTS[calendar_id] = {}
    _EVENTS[calendar_id][event_id] = event
    _record_change(calendar_id, event)
    return event


@router.patch("/mock/google-calendar/calendar/v3/calendars/{calendar_id}/events/{event_id}")
async def google_event_patch(calendar_id: str, event_id: str, request: Request) -> Dict[str, Any]:
    _ensure_mock_enabled()
    _validate_token(request)
    body = await request.json()

    cal_events = _EVENTS.get(calendar_id, {})
    existing = cal_events.get(event_id)
    if not existing:
        raise HTTPException(404, "Event not found")

    existing.update(body)
    existing["updated"] = f"{now_ts()}"
    _record_change(calendar_id, existing)
    return existing


@router.delete("/mock/google-calendar/calendar/v3/calendars/{calendar_id}/events/{event_id}")
async def google_event_delete(calendar_id: str, event_id: str, request: Request) -> Response:
    _ensure_mock_enabled()
    _validate_token(request)

    cal_events = _EVENTS.get(calendar_id, {})
    removed = cal_events.pop(event_id, None)
    if not removed:
        raise HTTPException(404, "Event not found")

    tombstone = {"id": event_id, "status": "cancelled", "calendarId": calendar_id}
    _record_change(calendar_id, tombstone)
    return Response(status_code=204)


@router.post("/mock/google-calendar/calendar/v3/calendars/{calendar_id}/events/watch")
async def google_events_watch(calendar_id: str, request: Request) -> Dict[str, Any]:
    _ensure_mock_enabled()
    _validate_token(request)
    body = await request.json()

    return {
        "kind": "api#channel",
        "id": body.get("id", uuid.uuid4().hex),
        "resourceId": uuid.uuid4().hex,
        "resourceUri": f"/calendars/{calendar_id}/events",
        "expiration": str((now_ts() + 86400) * 1000),
    }


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

@router.post("/mock/google-calendar/seed")
async def google_mock_seed(request: Request) -> Dict[str, Any]:
    _ensure_mock_enabled()
    body = await request.json()

    if "tokens" in body and isinstance(body["tokens"], dict):
        _TOKENS.update(body["tokens"])
    if "users" in body and isinstance(body["users"], dict):
        _USERS.update(body["users"])
    if "calendars" in body and isinstance(body["calendars"], dict):
        _CALENDARS.update(body["calendars"])
    if "events" in body and isinstance(body["events"], dict):
        for cal_id, cal_events in body["events"].items():
            if cal_id not in _EVENTS:
                _EVENTS[cal_id] = {}
            if isinstance(cal_events, dict):
                _EVENTS[cal_id].update(cal_events)

    return {"ok": True}


@router.post("/mock/google-calendar/reset")
async def google_mock_reset() -> Dict[str, Any]:
    _ensure_mock_enabled()
    _TOKENS.clear()
    _USERS.clear()
    _CALENDARS.clear()
    _EVENTS.clear()
    _SYNC_TOKENS.clear()
    _EVENT_CHANGES.clear()
    return {"ok": True}
