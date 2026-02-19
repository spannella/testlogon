from __future__ import annotations

import os
import time
from typing import Callable, Optional

from fastapi import Request, Response

_APP_ENV = os.environ.get("APP_ENV", "development").lower()
_PROD_ENVS = {"prod", "production"}
_METRICS_ENABLED = _APP_ENV in _PROD_ENVS
METRICS_ENABLED = _METRICS_ENABLED

if _METRICS_ENABLED:
    try:
        from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, Info, generate_latest
    except ImportError as exc:  # pragma: no cover - hard failure in prod misconfig
        raise RuntimeError("prometheus_client must be installed in production mode") from exc
else:
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"

    class _NoopMetric:
        def labels(self, **_kwargs: str) -> "_NoopMetric":
            return self

        def inc(self, _value: float = 1.0) -> None:
            return None

        def observe(self, _value: float) -> None:
            return None

        def set(self, _value: float) -> None:
            return None

        def info(self, _value: dict[str, str]) -> None:
            return None

    def Counter(*_args: object, **_kwargs: object) -> _NoopMetric:
        return _NoopMetric()

    def Gauge(*_args: object, **_kwargs: object) -> _NoopMetric:
        return _NoopMetric()

    def Histogram(*_args: object, **_kwargs: object) -> _NoopMetric:
        return _NoopMetric()

    def Info(*_args: object, **_kwargs: object) -> _NoopMetric:
        return _NoopMetric()

    def generate_latest() -> bytes:
        return b""

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
FILEMGR_PURGE_RESULTS = Counter(
    "filemgr_purge_results_total",
    "File manager purge outcomes",
    ["scope", "outcome", "mode"],
)
FILEMGR_OPERATION_LATENCY = Histogram(
    "filemgr_operation_duration_seconds",
    "File manager operation latency in seconds",
    ["operation"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30),
)
FILEMGR_BYTES = Counter(
    "filemgr_transfer_bytes_total",
    "File manager bytes transferred",
    ["direction", "operation"],
)
FILEMGR_SEARCH_PATH = Counter(
    "filemgr_search_path_total",
    "File manager search execution path",
    ["operation", "path"],
)
FILEMGR_PURGE_DURATION = Histogram(
    "filemgr_purge_duration_seconds",
    "File manager purge run duration in seconds",
    ["scope", "mode"],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60),
)
FILEMGR_PURGE_THROUGHPUT = Counter(
    "filemgr_purge_items_total",
    "File manager purge processed items",
    ["scope", "mode", "outcome"],
)
FILEMGR_ENCRYPTION_EVENTS = Counter(
    "filemgr_encryption_events_total",
    "File manager encryption-related events",
    ["event", "encrypted", "reason"],
)
FILEMGR_SHARED_ENCRYPTED_DOWNLOADS = Counter(
    "filemgr_shared_encrypted_downloads_total",
    "File manager shared download attempts split by encryption/outcome",
    ["encrypted", "outcome"],
)
FILEMGR_PREVIEW_ATTEMPTS = Counter(
    "filemgr_preview_attempts_total",
    "File manager preview attempts by kind/outcome",
    ["kind", "outcome", "reason"],
)
FILEMGR_PREVIEW_LATENCY = Histogram(
    "filemgr_preview_latency_seconds",
    "File manager preview latency by kind",
    ["kind"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30),
)
FILEMGR_PREVIEW_BYTES = Counter(
    "filemgr_preview_bytes_total",
    "File manager preview bytes streamed by kind",
    ["kind"],
)
FILEMGR_PREVIEW_FALLBACK = Counter(
    "filemgr_preview_fallback_total",
    "File manager preview fallback outcomes by kind/reason",
    ["kind", "reason"],
)
USAGE_METERING_EVENTS = Counter(
    "usage_metering_events_total",
    "Usage metering event outcomes",
    ["event_type", "source", "outcome"],
)
USAGE_METERING_BYTES = Counter(
    "usage_metering_bytes_total",
    "Usage bytes observed by metering pipeline",
    ["event_type", "source"],
)
USAGE_METERING_EVENTS_BY_PERIOD = Counter(
    "usage_metering_events_by_period_total",
    "Usage metering event outcomes split by source and billing period",
    ["event_type", "source", "outcome", "period_id"],
)
USAGE_METERING_BYTES_BY_PERIOD = Counter(
    "usage_metering_bytes_by_period_total",
    "Usage bytes observed by metering pipeline split by source and billing period",
    ["event_type", "source", "period_id"],
)
USAGE_SURFACE_UNITS = Counter(
    "usage_surface_units_total",
    "Usage unit counters by source family, dimension and billing period",
    ["source_family", "dimension", "period_id"],
)
USAGE_SURFACE_TRANSFER_BYTES = Counter(
    "usage_surface_transfer_bytes_total",
    "Usage transfer bytes by source family, direction and billing period",
    ["source_family", "direction", "period_id"],
)
USAGE_METERING_PIPELINE_ERRORS = Counter(
    "usage_metering_pipeline_errors_total",
    "Usage metering pipeline errors",
    ["stage"],
)
USAGE_METERING_PIPELINE_LATENCY = Histogram(
    "usage_metering_pipeline_duration_seconds",
    "Usage metering pipeline latency in seconds",
    ["stage"],
    buckets=(0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5),
)
ADMIN_SCOPE_DENIED = Counter(
    "admin_scope_denied_total",
    "Denied admin scope authorization checks by route, required scope, and profile type",
    ["route", "required_scope", "admin_profile_type"],
)
ONCE_MEDIA_SEND_EVENTS = Counter(
    "messaging_once_media_send_total",
    "Once-media send events by media kind/policy and rollout cohort",
    ["media_kind", "consumption_policy", "cohort"],
)
ONCE_MEDIA_GRANT_EVENTS = Counter(
    "messaging_once_media_grant_total",
    "Once-media grant endpoint outcomes by media kind/reason/cohort",
    ["media_kind", "outcome", "reason", "cohort"],
)
ONCE_MEDIA_GRANT_LATENCY = Histogram(
    "messaging_once_media_grant_latency_seconds",
    "Once-media attachment grant issuance latency",
    ["media_kind", "outcome", "cohort"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5),
)
ONCE_MEDIA_CONSUME_EVENTS = Counter(
    "messaging_once_media_consume_total",
    "Once-media consume outcomes by media kind/reason/cohort",
    ["media_kind", "outcome", "reason", "cohort"],
)
ONCE_MEDIA_CONFLICT_EVENTS = Counter(
    "messaging_once_media_conflicts_total",
    "Once-media consume conflict/race outcomes by media kind/cohort",
    ["media_kind", "cohort"],
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



def record_usage_metering_event(event_type: str, source: str, outcome: str, *, period_id: Optional[str] = None) -> None:
    USAGE_METERING_EVENTS.labels(event_type=event_type, source=source, outcome=outcome).inc()
    if period_id:
        USAGE_METERING_EVENTS_BY_PERIOD.labels(
            event_type=event_type,
            source=source,
            outcome=outcome,
            period_id=period_id,
        ).inc()


def record_usage_metering_bytes(event_type: str, source: str, nbytes: int, *, period_id: Optional[str] = None) -> None:
    if nbytes == 0:
        return
    value = float(abs(int(nbytes)))
    USAGE_METERING_BYTES.labels(event_type=event_type, source=source).inc(value)
    if period_id:
        USAGE_METERING_BYTES_BY_PERIOD.labels(event_type=event_type, source=source, period_id=period_id).inc(value)


def record_usage_surface_units(source_family: str, dimension: str, count: int, *, period_id: Optional[str] = None) -> None:
    if count <= 0 or not period_id:
        return
    USAGE_SURFACE_UNITS.labels(source_family=source_family, dimension=dimension, period_id=period_id).inc(float(count))


def record_usage_surface_transfer_bytes(source_family: str, direction: str, nbytes: int, *, period_id: Optional[str] = None) -> None:
    if nbytes <= 0 or not period_id:
        return
    USAGE_SURFACE_TRANSFER_BYTES.labels(source_family=source_family, direction=direction, period_id=period_id).inc(float(nbytes))


def record_usage_metering_pipeline_error(stage: str) -> None:
    USAGE_METERING_PIPELINE_ERRORS.labels(stage=stage).inc()


def record_usage_metering_pipeline_latency(stage: str, elapsed_seconds: float) -> None:
    USAGE_METERING_PIPELINE_LATENCY.labels(stage=stage).observe(max(0.0, float(elapsed_seconds)))


def record_admin_scope_denied(*, route: str, required_scope: str, admin_profile_type: str) -> None:
    ADMIN_SCOPE_DENIED.labels(
        route=route or "unknown",
        required_scope=required_scope or "unknown",
        admin_profile_type=admin_profile_type or "unknown",
    ).inc()


def _normalize_once_media_kind(media_kind: str) -> str:
    kind = (media_kind or "unknown").strip().lower()
    return kind if kind in {"image", "video", "audio"} else "unknown"


def _normalize_once_media_policy(consumption_policy: str) -> str:
    policy = (consumption_policy or "unknown").strip().lower()
    return policy if policy in {"view_once", "listen_once"} else "unknown"


def _normalize_once_media_outcome(outcome: str) -> str:
    value = (outcome or "error").strip().lower()
    return value if value in {"success", "error"} else "error"


def _normalize_cohort(cohort: str) -> str:
    value = (cohort or "default").strip().lower()
    if not value:
        return "default"
    return value[:32]


def _normalize_reason(reason: str) -> str:
    value = (reason or "none").strip().lower()
    if not value:
        return "none"
    return value[:48]


def record_once_media_send(*, media_kind: str, consumption_policy: str, cohort: str = "default") -> None:
    ONCE_MEDIA_SEND_EVENTS.labels(
        media_kind=_normalize_once_media_kind(media_kind),
        consumption_policy=_normalize_once_media_policy(consumption_policy),
        cohort=_normalize_cohort(cohort),
    ).inc()


def record_once_media_grant(*, media_kind: str, outcome: str, reason: str = "none", cohort: str = "default") -> None:
    ONCE_MEDIA_GRANT_EVENTS.labels(
        media_kind=_normalize_once_media_kind(media_kind),
        outcome=_normalize_once_media_outcome(outcome),
        reason=_normalize_reason(reason),
        cohort=_normalize_cohort(cohort),
    ).inc()


def record_once_media_grant_latency(*, media_kind: str, outcome: str, elapsed_seconds: float, cohort: str = "default") -> None:
    ONCE_MEDIA_GRANT_LATENCY.labels(
        media_kind=_normalize_once_media_kind(media_kind),
        outcome=_normalize_once_media_outcome(outcome),
        cohort=_normalize_cohort(cohort),
    ).observe(max(0.0, float(elapsed_seconds)))


def record_once_media_consume(*, media_kind: str, outcome: str, reason: str = "none", cohort: str = "default") -> None:
    ONCE_MEDIA_CONSUME_EVENTS.labels(
        media_kind=_normalize_once_media_kind(media_kind),
        outcome=_normalize_once_media_outcome(outcome),
        reason=_normalize_reason(reason),
        cohort=_normalize_cohort(cohort),
    ).inc()


def record_once_media_conflict(*, media_kind: str, cohort: str = "default") -> None:
    ONCE_MEDIA_CONFLICT_EVENTS.labels(
        media_kind=_normalize_once_media_kind(media_kind),
        cohort=_normalize_cohort(cohort),
    ).inc()

def set_app_info(name: str, version: str) -> None:
    APP_INFO.info({"name": name, "version": version})



def record_filemgr_operation_latency(operation: str, elapsed_seconds: float) -> None:
    FILEMGR_OPERATION_LATENCY.labels(operation=operation).observe(max(0.0, float(elapsed_seconds)))


def record_filemgr_bytes(direction: str, operation: str, nbytes: int) -> None:
    if nbytes <= 0:
        return
    FILEMGR_BYTES.labels(direction=direction, operation=operation).inc(float(nbytes))


def record_filemgr_search_path(operation: str, path: str) -> None:
    FILEMGR_SEARCH_PATH.labels(operation=operation, path=path).inc()


def record_filemgr_purge_run(
    scope: str,
    mode: str,
    *,
    purged: int,
    skipped: int,
    errors: int,
    elapsed_seconds: float,
) -> None:
    FILEMGR_PURGE_DURATION.labels(scope=scope, mode=mode).observe(max(0.0, float(elapsed_seconds)))
    if purged:
        FILEMGR_PURGE_THROUGHPUT.labels(scope=scope, mode=mode, outcome="purged").inc(float(purged))
    if skipped:
        FILEMGR_PURGE_THROUGHPUT.labels(scope=scope, mode=mode, outcome="skipped").inc(float(skipped))
    if errors:
        FILEMGR_PURGE_THROUGHPUT.labels(scope=scope, mode=mode, outcome="error").inc(float(errors))


def record_filemgr_encryption_event(event: str, *, encrypted: bool, reason: str = "") -> None:
    FILEMGR_ENCRYPTION_EVENTS.labels(
        event=event,
        encrypted="true" if encrypted else "false",
        reason=reason or "none",
    ).inc()


def record_filemgr_shared_download(*, encrypted: bool, outcome: str = "attempt") -> None:
    FILEMGR_SHARED_ENCRYPTED_DOWNLOADS.labels(
        encrypted="true" if encrypted else "false",
        outcome=outcome or "attempt",
    ).inc()


def record_filemgr_preview_attempt(*, kind: str, outcome: str, reason: str = "none") -> None:
    FILEMGR_PREVIEW_ATTEMPTS.labels(
        kind=(kind or "none").lower(),
        outcome=(outcome or "error").lower(),
        reason=(reason or "none").lower(),
    ).inc()


def record_filemgr_preview_latency(*, kind: str, elapsed_seconds: float) -> None:
    FILEMGR_PREVIEW_LATENCY.labels(kind=(kind or "none").lower()).observe(max(0.0, float(elapsed_seconds)))


def record_filemgr_preview_bytes(*, kind: str, nbytes: int) -> None:
    if nbytes <= 0:
        return
    FILEMGR_PREVIEW_BYTES.labels(kind=(kind or "none").lower()).inc(float(nbytes))


def record_filemgr_preview_fallback(*, kind: str, reason: str) -> None:
    FILEMGR_PREVIEW_FALLBACK.labels(
        kind=(kind or "none").lower(),
        reason=(reason or "unknown").lower(),
    ).inc()

def metrics_endpoint() -> Response:
    UPTIME_SECONDS.set(time.monotonic() - _START_TIME)
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
