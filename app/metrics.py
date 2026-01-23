from __future__ import annotations

import time
from typing import Callable, Optional

from fastapi import Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, Info, generate_latest

REQUEST_COUNT = Counter(
    "http_requests_total",
    "Total HTTP requests",
    ["method", "path", "status"],
)
LOGIN_SUCCESSES = Counter(
    "login_success_total",
    "Total successful logins",
)
LOGIN_FAILURES = Counter(
    "login_failure_total",
    "Total failed logins",
)
MFA_SUCCESSES = Counter(
    "mfa_success_total",
    "Total successful MFA checks",
)
MFA_FAILURES = Counter(
    "mfa_failure_total",
    "Total failed MFA checks",
)
NEW_USERS = Counter(
    "new_users_total",
    "Total new users observed",
)
ACTIVE_SESSIONS = Gauge(
    "active_sessions",
    "Active sessions in this process",
)
ACTIVE_USERS = Gauge(
    "active_users",
    "Active users with at least one session in this process",
)
REQUEST_ERRORS = Counter(
    "http_request_errors_total",
    "Total HTTP requests resulting in server errors",
    ["method", "path", "status"],
)
REQUEST_LATENCY = Histogram(
    "http_request_duration_seconds",
    "HTTP request latency in seconds",
    ["method", "path"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
)
REQUEST_SIZE = Histogram(
    "http_request_size_bytes",
    "HTTP request size in bytes",
    ["method", "path"],
    buckets=(0, 100, 500, 1_000, 5_000, 10_000, 50_000, 100_000, 500_000, 1_000_000),
)
RESPONSE_SIZE = Histogram(
    "http_response_size_bytes",
    "HTTP response size in bytes",
    ["method", "path", "status"],
    buckets=(0, 100, 500, 1_000, 5_000, 10_000, 50_000, 100_000, 500_000, 1_000_000),
)
IN_PROGRESS = Gauge(
    "http_requests_in_progress",
    "In-progress HTTP requests",
    ["method", "path"],
)
UPTIME_SECONDS = Gauge(
    "app_uptime_seconds",
    "Application uptime in seconds",
)
APP_INFO = Info(
    "app",
    "Application metadata",
)

_START_TIME = time.monotonic()
_ACTIVE_SESSIONS_BY_USER: dict[str, int] = {}
_ACTIVE_SESSIONS_COUNT = 0


def _route_path(request: Request) -> str:
    route = request.scope.get("route")
    if route and getattr(route, "path", None):
        return route.path
    return request.url.path


def _get_content_length(value: Optional[str]) -> Optional[int]:
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def record_auth_event(alert_type: str) -> None:
    if alert_type == "login_success":
        LOGIN_SUCCESSES.inc()
    elif alert_type == "login_failure":
        LOGIN_FAILURES.inc()
    elif alert_type == "mfa_success":
        MFA_SUCCESSES.inc()
    elif alert_type == "mfa_failure":
        MFA_FAILURES.inc()


def record_session_created(user_sub: str, is_new_user: bool) -> None:
    global _ACTIVE_SESSIONS_COUNT
    _ACTIVE_SESSIONS_COUNT += 1
    ACTIVE_SESSIONS.set(_ACTIVE_SESSIONS_COUNT)
    if is_new_user:
        NEW_USERS.inc()
    current = _ACTIVE_SESSIONS_BY_USER.get(user_sub, 0) + 1
    _ACTIVE_SESSIONS_BY_USER[user_sub] = current
    ACTIVE_USERS.set(len(_ACTIVE_SESSIONS_BY_USER))


def record_session_revoked(user_sub: str) -> None:
    global _ACTIVE_SESSIONS_COUNT
    if _ACTIVE_SESSIONS_COUNT > 0:
        _ACTIVE_SESSIONS_COUNT -= 1
    ACTIVE_SESSIONS.set(_ACTIVE_SESSIONS_COUNT)
    current = _ACTIVE_SESSIONS_BY_USER.get(user_sub, 0) - 1
    if current <= 0:
        _ACTIVE_SESSIONS_BY_USER.pop(user_sub, None)
    else:
        _ACTIVE_SESSIONS_BY_USER[user_sub] = current
    ACTIVE_USERS.set(len(_ACTIVE_SESSIONS_BY_USER))


async def metrics_middleware(request: Request, call_next: Callable[[Request], Response]) -> Response:
    path = _route_path(request)
    method = request.method
    request_size = _get_content_length(request.headers.get("content-length"))
    start = time.perf_counter()
    IN_PROGRESS.labels(method=method, path=path).inc()
    status_code = 500
    try:
        response = await call_next(request)
        status_code = response.status_code
        return response
    finally:
        IN_PROGRESS.labels(method=method, path=path).dec()
        elapsed = time.perf_counter() - start
        REQUEST_LATENCY.labels(method=method, path=path).observe(elapsed)
        REQUEST_COUNT.labels(method=method, path=path, status=str(status_code)).inc()
        if request_size is not None:
            REQUEST_SIZE.labels(method=method, path=path).observe(request_size)
        response_size = _get_content_length(response.headers.get("content-length") if "response" in locals() else None)
        if response_size is not None:
            RESPONSE_SIZE.labels(method=method, path=path, status=str(status_code)).observe(response_size)
        if status_code >= 500:
            REQUEST_ERRORS.labels(method=method, path=path, status=str(status_code)).inc()


def set_app_info(name: str, version: str) -> None:
    APP_INFO.info({"name": name, "version": version})


def metrics_endpoint() -> Response:
    UPTIME_SECONDS.set(time.monotonic() - _START_TIME)
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
