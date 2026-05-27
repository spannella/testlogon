"""
Rate limiting middleware -- Layer 1 (global IP) + Layer 2 per-endpoint-group
+ dependency factory (PLATFORM-001).
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, Optional, Tuple

import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from app.core.normalize import client_ip_from_request
from app.core.settings import S
from app.core.time import now_ts
from app.services.rate_limit_config import get_group_config, match_path_to_group
from app.services.rate_limit_dashboard import log_rate_limit_event
from app.services.rate_limit_store import (
    check_rate_limit,
    is_allowlisted,
    is_blocked,
)
from app.services.sessions import require_ui_session

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Fire-and-forget event logging helper
# ---------------------------------------------------------------------------

def _log_event_async(
    group: str,
    identity_type: str,
    identity_value: str,
    path: str,
    method: str,
    status: str,
    count: int = 0,
    limit: int = 0,
) -> None:
    """Schedule event logging without blocking the request."""
    try:
        loop = asyncio.get_running_loop()
        loop.run_in_executor(None, lambda: log_rate_limit_event(
            endpoint_group=group,
            identity_type=identity_type,
            identity_value=identity_value,
            endpoint=path,
            method=method,
            status=status,
            count=count,
            limit=limit,
        ))
    except Exception:
        # Best-effort; never fail the request due to logging
        pass


def _extract_user_from_request(request: Request) -> Tuple[str, str]:
    """
    Lightweight user extraction from the access-token cookie.

    Returns (user_sub, role).  Falls back to ("", "") when no valid cookie
    is present.  This does **not** validate the session in DDB; it only
    reads the signed JWT from the cookie for rate-limit keying purposes.
    """
    try:
        access_cookie_name = getattr(S, "ui_access_token_cookie_name", "")
        access_secret = getattr(S, "ui_access_token_secret", "")
        if not access_cookie_name or not access_secret:
            return ("", "")
        cookies = getattr(request, "cookies", {}) or {}
        token = cookies.get(access_cookie_name)
        if not token:
            return ("", "")
        payload = jwt.decode(token, access_secret, algorithms=["HS256"])
        user_sub = str(payload.get("sub", ""))
        role = str(payload.get("role", "user")).lower()
        return (user_sub, role)
    except Exception:
        return ("", "")


# ---------------------------------------------------------------------------
# Layer 1: Global IP rate limit middleware
# ---------------------------------------------------------------------------

def rate_limit_middleware_factory():
    """Return the ASGI middleware callable for Layer 1 global IP rate limiting
    **plus** Layer 2 per-endpoint-group checking (based on path matching)."""

    async def _middleware(request: Request, call_next):
        if not S.rate_limit_global_enabled:
            response = await call_next(request)
            return response

        ip = client_ip_from_request(request)
        remaining = -1
        reset = 0

        # 1. Blocklist check (immediate 403)
        try:
            if is_blocked(ip):
                _log_event_async("global_ip", "ip", ip, request.url.path, request.method, "blocked")
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Forbidden"},
                )
        except Exception:
            if not S.rate_limit_fail_open:
                return JSONResponse(status_code=503, content={"detail": "Rate limit service unavailable"})

        # 2. Allowlist check (skip rate limit if allowlisted)
        allowlisted = False
        try:
            allowlisted = is_allowlisted(ip)
        except Exception:
            pass

        if not allowlisted:
            # Layer 1: Global IP limit
            try:
                allowed, remaining, reset = check_rate_limit(
                    pk=f"IP#{ip}",
                    window_seconds=S.rate_limit_global_ip_window_seconds,
                    max_requests=S.rate_limit_global_ip_max_requests,
                )
            except Exception:
                if S.rate_limit_fail_open:
                    allowed, remaining, reset = True, -1, 0
                else:
                    return JSONResponse(
                        status_code=503,
                        content={"detail": "Rate limit service unavailable"},
                    )

            if not allowed:
                retry_after = max(1, reset - now_ts())
                _log_event_async(
                    "global_ip", "ip", ip, request.url.path, request.method, "rejected",
                    count=S.rate_limit_global_ip_max_requests + 1,
                    limit=S.rate_limit_global_ip_max_requests,
                )
                return JSONResponse(
                    status_code=429,
                    content={
                        "detail": {
                            "code": "rate_limited",
                            "group": "global_ip",
                            "retry_after": retry_after,
                            "message": f"Too many requests. Please wait {retry_after} seconds before retrying.",
                        }
                    },
                    headers={
                        "Retry-After": str(retry_after),
                        "X-RateLimit-Limit": str(S.rate_limit_global_ip_max_requests),
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": str(reset),
                    },
                )

        # ------------------------------------------------------------------
        # Layer 2: Per-endpoint-group rate limiting (inside middleware)
        # ------------------------------------------------------------------
        if S.rate_limit_per_endpoint_enabled:
            group_name = match_path_to_group(request.url.path)
            if group_name:
                try:
                    group_cfg = get_group_config(group_name)
                except Exception:
                    group_cfg = None

                if group_cfg:
                    user_sub, role = _extract_user_from_request(request)

                    bypass_roles = [str(r).lower() for r in group_cfg.get("bypass_roles", [])]
                    skip = role in bypass_roles

                    if not skip:
                        # Per-user check
                        if user_sub:
                            window = group_cfg.get("window_seconds", 60)
                            max_per_user = group_cfg.get("max_requests_per_user", 120)
                            try:
                                u_allowed, u_remaining, u_reset = check_rate_limit(
                                    pk=f"ENDPOINT#{group_name}#USER#{user_sub}",
                                    window_seconds=window,
                                    max_requests=max_per_user,
                                )
                            except Exception:
                                if S.rate_limit_fail_open:
                                    u_allowed, u_remaining, u_reset = True, -1, 0
                                else:
                                    return JSONResponse(
                                        status_code=503,
                                        content={"detail": "Rate limit service unavailable"},
                                    )

                            if not u_allowed:
                                retry_after = max(1, u_reset - now_ts())
                                _log_event_async(
                                    group_name, "user", user_sub,
                                    request.url.path, request.method, "rejected",
                                    count=max_per_user + 1, limit=max_per_user,
                                )
                                return JSONResponse(
                                    status_code=429,
                                    content={
                                        "detail": {
                                            "code": "rate_limited",
                                            "group": group_name,
                                            "retry_after": retry_after,
                                            "message": f"Too many requests. Please wait {retry_after} seconds before retrying.",
                                        }
                                    },
                                    headers={
                                        "Retry-After": str(retry_after),
                                        "X-RateLimit-Limit": str(max_per_user),
                                        "X-RateLimit-Remaining": "0",
                                        "X-RateLimit-Reset": str(u_reset),
                                    },
                                )

                        # Per-IP check (endpoint group)
                        window = group_cfg.get("window_seconds", 60)
                        max_per_ip = group_cfg.get("max_requests_per_ip", 200)
                        try:
                            ip_allowed, ip_remaining, ip_reset = check_rate_limit(
                                pk=f"ENDPOINT#{group_name}#IP#{ip}",
                                window_seconds=window,
                                max_requests=max_per_ip,
                            )
                        except Exception:
                            if S.rate_limit_fail_open:
                                ip_allowed, ip_remaining, ip_reset = True, -1, 0
                            else:
                                return JSONResponse(
                                    status_code=503,
                                    content={"detail": "Rate limit service unavailable"},
                                )

                        if not ip_allowed:
                            retry_after = max(1, ip_reset - now_ts())
                            _log_event_async(
                                group_name, "ip", ip,
                                request.url.path, request.method, "rejected",
                                count=max_per_ip + 1, limit=max_per_ip,
                            )
                            return JSONResponse(
                                status_code=429,
                                content={
                                    "detail": {
                                        "code": "rate_limited",
                                        "group": group_name,
                                        "retry_after": retry_after,
                                        "message": f"Too many requests. Please wait {retry_after} seconds before retrying.",
                                    }
                                },
                                headers={
                                    "Retry-After": str(retry_after),
                                    "X-RateLimit-Limit": str(max_per_ip),
                                    "X-RateLimit-Remaining": "0",
                                    "X-RateLimit-Reset": str(ip_reset),
                                },
                            )

        response = await call_next(request)

        # Inject rate-limit headers on successful responses if we have the data
        if not allowlisted and S.rate_limit_global_enabled:
            try:
                response.headers["X-RateLimit-Limit"] = str(S.rate_limit_global_ip_max_requests)
                if remaining >= 0:
                    response.headers["X-RateLimit-Remaining"] = str(remaining)
                if reset > 0:
                    response.headers["X-RateLimit-Reset"] = str(reset)
            except Exception:
                pass

        return response

    return _middleware


# ---------------------------------------------------------------------------
# Layer 2: Per-endpoint group rate limit dependency (for explicit router use)
# ---------------------------------------------------------------------------

def rate_limit_group(group: str):
    """
    FastAPI dependency factory for per-endpoint-group rate limiting.

    Usage in a router::

        @router.post("/messages", dependencies=[rate_limit_group("messaging")])
        async def send_message(...): ...

    Or as a router-wide dependency::

        router = APIRouter(dependencies=[rate_limit_group("messaging")])
    """

    def _check(request: Request, ctx: dict = Depends(require_ui_session)):
        if not S.rate_limit_per_endpoint_enabled:
            return

        user_sub = ctx.get("user_sub", "")
        role = str(ctx.get("role", "user")).lower()
        ip = client_ip_from_request(request)

        try:
            config = get_group_config(group)
        except Exception:
            if S.rate_limit_fail_open:
                return
            raise HTTPException(status_code=503, detail="Rate limit service unavailable")

        bypass_roles = [str(r).lower() for r in config.get("bypass_roles", [])]
        if role in bypass_roles:
            return

        # Per-user check
        if user_sub:
            window = config.get("window_seconds", 60)
            max_per_user = config.get("max_requests_per_user", 120)
            try:
                allowed, remaining, reset = check_rate_limit(
                    pk=f"ENDPOINT#{group}#USER#{user_sub}",
                    window_seconds=window,
                    max_requests=max_per_user,
                )
            except Exception:
                if S.rate_limit_fail_open:
                    return
                raise HTTPException(status_code=503, detail="Rate limit service unavailable")

            if not allowed:
                retry_after = max(1, reset - now_ts())
                _log_event_async(
                    group, "user", user_sub, request.url.path, request.method, "rejected",
                    count=max_per_user + 1, limit=max_per_user,
                )
                raise HTTPException(
                    status_code=429,
                    detail={
                        "code": "rate_limited",
                        "group": group,
                        "retry_after": retry_after,
                        "message": f"Too many requests. Please wait {retry_after} seconds before retrying.",
                    },
                    headers={
                        "Retry-After": str(retry_after),
                        "X-RateLimit-Limit": str(max_per_user),
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": str(reset),
                    },
                )

        # Per-IP check
        window = config.get("window_seconds", 60)
        max_per_ip = config.get("max_requests_per_ip", 200)
        try:
            allowed, remaining, reset = check_rate_limit(
                pk=f"ENDPOINT#{group}#IP#{ip}",
                window_seconds=window,
                max_requests=max_per_ip,
            )
        except Exception:
            if S.rate_limit_fail_open:
                return
            raise HTTPException(status_code=503, detail="Rate limit service unavailable")

        if not allowed:
            retry_after = max(1, reset - now_ts())
            _log_event_async(
                group, "ip", ip, request.url.path, request.method, "rejected",
                count=max_per_ip + 1, limit=max_per_ip,
            )
            raise HTTPException(
                status_code=429,
                detail={
                    "code": "rate_limited",
                    "group": group,
                    "retry_after": retry_after,
                    "message": f"Too many requests. Please wait {retry_after} seconds before retrying.",
                },
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(max_per_ip),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(reset),
                },
            )

    return Depends(_check)
