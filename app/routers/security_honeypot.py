"""Decoy / honeypot endpoint router (HNY-008).

DEFENSIVE-only. Registers plausible-but-fake paths that common scanners probe
(wp-login, phpMyAdmin, .env, etc.). These paths do NOT exist in the real app;
hitting one records a ``honeypot_hit`` security event and returns a benign,
realistic-looking failure so the caller cannot tell it is a trap.

Registration is gated on ``S.honeypot_endpoints_enabled``; when off, the router
is NOT mounted and probing these paths 404s like any other unknown path. None
of these paths shadow a real application route.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request, Response

from app.services import security_events

router = APIRouter(tags=["security-honeypot"])
logger = logging.getLogger(__name__)

# Decoy paths chosen to mimic common scanner targets. Verified not to collide
# with any real route registered in app/main.py.
_DECOY_PATHS = [
    "/wp-login.php",
    "/wp-admin",
    "/admin.php",
    "/phpmyadmin",
    "/.env",
    "/config.php",
    "/.git/config",
    "/api/v1/admin/login",
]

_FAKE_LOGIN_HTML = (
    "<!doctype html><html><head><title>Sign in</title></head>"
    "<body><form method=post action=''>"
    "<input name=username placeholder=Username>"
    "<input type=password name=password placeholder=Password>"
    "<button type=submit>Sign in</button>"
    "</form></body></html>"
)


def _record(request: Request, path: str) -> None:
    security_events.safe_record(
        kind="honeypot_hit",
        severity="medium",
        request=request,
        decoy_path=path,
        method=request.method,
    )


async def _handle(request: Request) -> Response:
    _record(request, request.url.path)
    # Generic, realistic failure. Never reveal it is a trap.
    return Response(content=_FAKE_LOGIN_HTML, status_code=401, media_type="text/html")


def _register() -> None:
    for path in _DECOY_PATHS:
        # Accept GET + POST (scanners probe both).
        router.add_api_route(path, _handle, methods=["GET", "POST"], include_in_schema=False)


_register()
