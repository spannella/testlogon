from __future__ import annotations

import logging
import os
import threading
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any

import jwt

from app.metrics import record_vnc_bridge_failure, record_vnc_session_duration, record_vnc_session_event
from app.services.alerts import audit_event
from app.services.vnc_bridge_lifecycle import BridgeLifecycleError, BridgeLifecycleManager
from app.services.vnc_observability import log_vnc_event, vnc_trace_span

CANONICAL_CAPABILITY_KEYS = ("clipboard", "file_transfer", "drag_drop_upload")
logger = logging.getLogger("app.vnc.sessions")


@dataclass(frozen=True)
class TargetConfig:
    target_id: str
    ws_url: str
    allowed_users: tuple[str, ...]
    capabilities: dict[str, bool] | None = None
    transfer_fallback: dict[str, str] | None = None


class VncSessionError(Exception):
    def __init__(self, *, http_status: int, code: str, message: str, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.http_status = http_status
        self.code = code
        self.message = message
        self.details = details or {}


class VncSessionStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sessions: dict[str, dict[str, Any]] = {}
        self._consumed_jti_exp: dict[str, int] = {}

    def create(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self._sessions[payload["session_id"]] = dict(payload)
            return dict(payload)

    def get(self, session_id: str) -> dict[str, Any] | None:
        with self._lock:
            item = self._sessions.get(session_id)
            return dict(item) if item else None

    def close(self, session_id: str, *, reason: str = "user_disconnect") -> dict[str, Any] | None:
        with self._lock:
            item = self._sessions.get(session_id)
            if not item:
                return None
            closed = dict(item)
            closed["state"] = "closed"
            closed["closed_at"] = int(time.time())
            closed["close_reason"] = reason
            self._sessions[session_id] = closed
            return dict(closed)

    def consume_jti_once(self, *, jti: str, expires_at: int) -> bool:
        now = int(time.time())
        with self._lock:
            stale = [key for key, exp in self._consumed_jti_exp.items() if exp <= now]
            for key in stale:
                self._consumed_jti_exp.pop(key, None)

            if jti in self._consumed_jti_exp:
                return False
            self._consumed_jti_exp[jti] = expires_at
            return True


class VncBootstrapRateLimiter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[str, deque[int]] = defaultdict(deque)

    def consume(self, *, key: str, limit: int, window_seconds: int) -> bool:
        now = int(time.time())
        with self._lock:
            q = self._entries[key]
            while q and (now - q[0]) >= window_seconds:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True


STORE = VncSessionStore()
RATE_LIMITER = VncBootstrapRateLimiter()
BRIDGE = BridgeLifecycleManager(
    idle_timeout_seconds=int(os.environ.get("VNC_SESSION_IDLE_TIMEOUT_SECONDS", "300")),
    max_duration_seconds=int(os.environ.get("VNC_SESSION_MAX_DURATION_SECONDS", "3600")),
)


def _now() -> int:
    return int(time.time())


def _is_dev_environment() -> bool:
    env = os.environ.get("APP_ENV") or os.environ.get("ENV") or "dev"
    return env.strip().lower() in {"dev", "local", "test"}


def _token_secret() -> str:
    return os.environ.get("VNC_SESSION_TOKEN_SECRET", "dev-vnc-session-secret")


def _token_ttl_seconds() -> int:
    raw = os.environ.get("VNC_SESSION_TOKEN_TTL_SECONDS", "300")
    try:
        parsed = int(raw)
    except ValueError:
        parsed = 300
    return max(60, min(parsed, 300))


def _bootstrap_rate_limit() -> tuple[int, int]:
    raw_limit = os.environ.get("VNC_BOOTSTRAP_RATE_LIMIT_COUNT", "10")
    raw_window = os.environ.get("VNC_BOOTSTRAP_RATE_LIMIT_WINDOW_SECONDS", "60")
    try:
        limit = int(raw_limit)
    except ValueError:
        limit = 10
    try:
        window = int(raw_window)
    except ValueError:
        window = 60
    return max(1, limit), max(1, window)


def session_timeout_policy() -> dict[str, int]:
    idle_timeout = BRIDGE._idle_timeout_seconds  # noqa: SLF001
    max_duration = BRIDGE._max_duration_seconds  # noqa: SLF001
    raw_warning = os.environ.get("VNC_SESSION_TIMEOUT_WARNING_SECONDS", "60")
    try:
        warning_seconds = int(raw_warning)
    except ValueError:
        warning_seconds = 60
    upper_bound = max(5, min(idle_timeout, max_duration) - 1)
    warning_seconds = max(5, min(warning_seconds, upper_bound))
    return {
        "idle_timeout_seconds": int(idle_timeout),
        "max_session_duration_seconds": int(max_duration),
        "warning_seconds": int(warning_seconds),
    }


def _env_flag(name: str, *, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _ensure_vnc_feature_enabled() -> None:
    enabled = _env_flag("VNC_FEATURE_ENABLED", default=True)
    kill_switch = _env_flag("VNC_FEATURE_KILL_SWITCH", default=False)
    if enabled and not kill_switch:
        return
    raise VncSessionError(
        http_status=503,
        code="VNC_FEATURE_DISABLED",
        message="VNC remote desktop feature is currently disabled",
    )


def _runtime_capability_gates() -> dict[str, bool]:
    return {
        "clipboard": _env_flag("VNC_RUNTIME_CLIPBOARD_ENABLED", default=True),
        "file_transfer": _env_flag("VNC_RUNTIME_FILE_TRANSFER_ENABLED", default=True),
        "drag_drop_upload": _env_flag("VNC_RUNTIME_DRAG_DROP_UPLOAD_ENABLED", default=True),
    }


def resolve_session_capabilities(target: TargetConfig) -> dict[str, bool]:
    inventory_caps = target.capabilities or {}
    runtime_gates = _runtime_capability_gates()

    resolved: dict[str, bool] = {}
    for key in CANONICAL_CAPABILITY_KEYS:
        resolved[key] = bool(inventory_caps.get(key, False)) and bool(runtime_gates.get(key, False))

    if not resolved["file_transfer"]:
        resolved["drag_drop_upload"] = False
    return resolved


def _default_targets() -> dict[str, TargetConfig]:
    return {
        "demo": TargetConfig(
            target_id="demo",
            ws_url=os.environ.get("VNC_DEMO_WS_URL", "ws://localhost:6080/websockify"),
            allowed_users=("*",),
            capabilities={
                "clipboard": True,
                "file_transfer": False,
                "drag_drop_upload": False,
            },
            transfer_fallback={
                "method": "object_upload_link",
                "label": "Secure Upload Link",
                "instructions": "Upload files to the secure link and retrieve them from the remote host download directory.",
                "url": os.environ.get("VNC_FALLBACK_OBJECT_UPLOAD_URL", "https://uploads.example.internal/vnc"),
            },
        ),
        "ops-admin": TargetConfig(
            target_id="ops-admin",
            ws_url=os.environ.get("VNC_OPS_WS_URL", "wss://ops-admin.example.internal/websockify"),
            allowed_users=("role:admin", "role:root"),
            capabilities={
                "clipboard": True,
                "file_transfer": True,
                "drag_drop_upload": True,
            },
            transfer_fallback={
                "method": "sftp",
                "label": "SFTP",
                "instructions": "Use SFTP with your session username and drop files into /tmp/inbox on the target.",
                "url": os.environ.get("VNC_FALLBACK_SFTP_URL", "sftp://ops-admin.example.internal/tmp/inbox"),
            },
        ),
    }


def _resolve_target(target_id: str) -> TargetConfig:
    inventory = _default_targets()
    target = inventory.get(target_id)
    if not target:
        raise VncSessionError(
            http_status=404,
            code="VNC_TARGET_NOT_FOUND",
            message="requested VNC target is not registered",
            details={"target_id": target_id},
        )
    return target


def _normalize_role(role: str | None) -> str:
    return (role or "user").strip().lower() or "user"


def _ensure_authorized(target: TargetConfig, user_sub: str, user_role: str) -> None:
    allowed = set(target.allowed_users)
    if "*" in allowed:
        return

    normalized_role = _normalize_role(user_role)
    role_entries = {f"role:{normalized_role}", normalized_role}

    if user_sub in allowed or any(entry in allowed for entry in role_entries):
        return

    raise VncSessionError(
        http_status=403,
        code="VNC_AUTH_UNAUTHORIZED",
        message="user is not authorized for this VNC target",
        details={"target_id": target.target_id},
    )


def _validate_secure_transport(*, ws_url: str) -> None:
    if _is_dev_environment():
        return
    if not ws_url.startswith("wss://"):
        raise VncSessionError(
            http_status=500,
            code="VNC_TLS_REQUIRED",
            message="non-TLS VNC bridge URL is not allowed outside dev/test",
            details={"ws_url": ws_url},
        )


def _enforce_bootstrap_rate_limit(*, user_sub: str, target_id: str) -> None:
    limit, window = _bootstrap_rate_limit()
    key = f"{user_sub}:{target_id}"
    allowed = RATE_LIMITER.consume(key=key, limit=limit, window_seconds=window)
    if not allowed:
        raise VncSessionError(
            http_status=429,
            code="VNC_RATE_LIMITED",
            message="too many VNC session bootstrap attempts",
            details={"target_id": target_id, "limit": limit, "window_seconds": window},
        )


def mint_connect_token(*, user_sub: str, session_id: str, target_id: str, issued_at: int, expires_at: int) -> str:
    jti = f"jti_{uuid.uuid4().hex}"
    return jwt.encode(
        {
            "sub": user_sub,
            "sid": session_id,
            "target_id": target_id,
            "iat": issued_at,
            "exp": expires_at,
            "aud": "vnc-bridge",
            "jti": jti,
        },
        _token_secret(),
        algorithm="HS256",
    )


def verify_connect_token(*, token: str, expected_session_id: str, expected_target_id: str) -> dict[str, Any]:
    try:
        claims = jwt.decode(
            token,
            _token_secret(),
            algorithms=["HS256"],
            audience="vnc-bridge",
        )
    except jwt.ExpiredSignatureError as exc:
        raise VncSessionError(
            http_status=401,
            code="VNC_TOKEN_EXPIRED",
            message="VNC connect token is expired",
        ) from exc
    except jwt.PyJWTError as exc:
        raise VncSessionError(
            http_status=401,
            code="VNC_TOKEN_INVALID",
            message="VNC connect token is invalid",
        ) from exc

    sid = str(claims.get("sid") or "")
    if sid != expected_session_id:
        raise VncSessionError(
            http_status=401,
            code="VNC_TOKEN_INVALID",
            message="VNC connect token does not match session",
            details={"expected_session_id": expected_session_id},
        )

    target_id = str(claims.get("target_id") or "")
    if target_id != expected_target_id:
        raise VncSessionError(
            http_status=401,
            code="VNC_TOKEN_INVALID",
            message="VNC connect token does not match target",
            details={"expected_target_id": expected_target_id},
        )

    jti = str(claims.get("jti") or "")
    exp = int(claims.get("exp") or 0)
    if not jti or exp <= 0:
        raise VncSessionError(
            http_status=401,
            code="VNC_TOKEN_INVALID",
            message="VNC connect token missing replay-protection fields",
        )

    consumed = STORE.consume_jti_once(jti=jti, expires_at=exp)
    if not consumed:
        raise VncSessionError(
            http_status=401,
            code="VNC_TOKEN_INVALID",
            message="VNC connect token has already been used",
            details={"reason": "replay_detected"},
        )

    return claims


def _cleanup_expired_sessions() -> None:
    expired = BRIDGE.cleanup_expired()
    for session_id in expired:
        bridge_state = BRIDGE.get(session_id) or {}
        reason = str(bridge_state.get("close_reason") or "timeout_or_max_duration")
        closed = STORE.close(session_id, reason=reason)
        if not closed:
            continue
        user_sub = str(closed.get("user_sub") or "unknown")
        target_id = str(closed.get("target_id") or "unknown")
        created_at = int(closed.get("created_at") or _now())
        elapsed = max(0, _now() - created_at)
        record_vnc_session_event(action="stop", outcome="timeout", target_id=target_id, error_code="VNC_SESSION_TERMINATED")
        record_vnc_session_duration(target_id=target_id, outcome="timeout", elapsed_seconds=float(elapsed))
        audit_event(
            "vnc_session_terminated",
            user_sub,
            outcome="success",
            session_id=session_id,
            target_id=target_id,
            reason=reason,
            error_code="VNC_SESSION_TERMINATED",
            duration_seconds=elapsed,
        )
        log_vnc_event(
            "session_timeout_terminated",
            session_id=session_id,
            target_id=target_id,
            user_sub=user_sub,
            reason=reason,
            duration_seconds=elapsed,
        )


def create_session(*, user_sub: str, target_id: str, user_role: str = "user") -> dict[str, Any]:
    started_at = time.monotonic()
    with vnc_trace_span("vnc.bootstrap", user_sub=user_sub, target_id=target_id):
        _cleanup_expired_sessions()
        _ensure_vnc_feature_enabled()
        target = _resolve_target(target_id)
        _ensure_authorized(target, user_sub, user_role)
        _enforce_bootstrap_rate_limit(user_sub=user_sub, target_id=target.target_id)
        _validate_secure_transport(ws_url=target.ws_url)

        issued_at = _now()
        expires_at = issued_at + _token_ttl_seconds()
        session_id = f"vnc_{uuid.uuid4().hex}"

        BRIDGE.start_creating(session_id=session_id, user_sub=user_sub, target_id=target.target_id)
        try:
            with vnc_trace_span("vnc.bridge_connect", session_id=session_id, target_id=target.target_id):
                BRIDGE.validate_target_ws_url(ws_url=target.ws_url)
        except BridgeLifecycleError as exc:
            BRIDGE.mark_failed(session_id=session_id, failure_code=exc.code)
            record_vnc_session_event(action="start", outcome="failure", target_id=target.target_id, error_code=exc.code)
            record_vnc_bridge_failure(target_id=target.target_id, error_code=exc.code)
            log_vnc_event(
                "session_start_failed",
                session_id=session_id,
                target_id=target.target_id,
                user_sub=user_sub,
                error_code=exc.code,
            )
            raise VncSessionError(
                http_status=502,
                code=exc.code,
                message=exc.message,
                details={"target_id": target.target_id},
            ) from exc
        except Exception as exc:
            BRIDGE.mark_failed(session_id=session_id, failure_code="VNC_INTERNAL_ERROR")
            record_vnc_session_event(action="start", outcome="failure", target_id=target.target_id, error_code="VNC_INTERNAL_ERROR")
            record_vnc_bridge_failure(target_id=target.target_id, error_code="VNC_INTERNAL_ERROR")
            logger.exception("vnc_bridge_setup_failed", extra={"session_id": session_id, "target_id": target.target_id})
            raise VncSessionError(
                http_status=500,
                code="VNC_INTERNAL_ERROR",
                message="unexpected bridge setup failure",
                details={"target_id": target.target_id},
            ) from exc

        token = mint_connect_token(
            user_sub=user_sub,
            session_id=session_id,
            target_id=target.target_id,
            issued_at=issued_at,
            expires_at=expires_at,
        )

        BRIDGE.mark_active(session_id=session_id)
        session = STORE.create(
            {
                "session_id": session_id,
                "user_sub": user_sub,
                "target_id": target.target_id,
                "ws_url": target.ws_url,
                "capabilities": resolve_session_capabilities(target),
                "expires_at": expires_at,
                "created_at": issued_at,
                "state": "active",
                "connect_params": {"token": token},
                "timeout_policy": session_timeout_policy(),
            }
        )

    record_vnc_session_event(action="start", outcome="success", target_id=target.target_id)
    log_vnc_event(
        "session_started",
        session_id=session_id,
        target_id=target.target_id,
        user_sub=user_sub,
        duration_ms=int((time.monotonic() - started_at) * 1000),
    )
    return session


def get_transfer_fallback(*, user_sub: str, session_id: str) -> dict[str, Any]:
    _cleanup_expired_sessions()
    session = STORE.get(session_id)
    if not session:
        raise VncSessionError(
            http_status=404,
            code="VNC_SESSION_NOT_FOUND",
            message="VNC session not found",
            details={"session_id": session_id},
        )
    if session.get("user_sub") != user_sub:
        raise VncSessionError(
            http_status=403,
            code="VNC_AUTH_UNAUTHORIZED",
            message="user is not authorized for this VNC session",
            details={"session_id": session_id},
        )

    capabilities = session.get("capabilities") or {}
    if bool(capabilities.get("file_transfer", False)):
        raise VncSessionError(
            http_status=409,
            code="VNC_TRANSFER_NATIVE_AVAILABLE",
            message="native file transfer is available for this session",
            details={"session_id": session_id},
        )

    target = _resolve_target(str(session.get("target_id") or ""))
    fallback = target.transfer_fallback or {}
    if not fallback.get("method"):
        raise VncSessionError(
            http_status=404,
            code="VNC_TRANSFER_FALLBACK_UNAVAILABLE",
            message="no fallback transfer method is configured for this target",
            details={"target_id": target.target_id},
        )

    expires_at = _now() + 900
    return {
        "session_id": session_id,
        "method": str(fallback.get("method") or ""),
        "label": str(fallback.get("label") or "Fallback transfer"),
        "instructions": str(fallback.get("instructions") or "Use the configured fallback transfer method."),
        "url": str(fallback.get("url") or ""),
        "expires_at": expires_at,
    }


def teardown_session(*, user_sub: str, session_id: str) -> dict[str, Any]:
    _cleanup_expired_sessions()
    session = STORE.get(session_id)
    if not session:
        raise VncSessionError(
            http_status=404,
            code="VNC_SESSION_NOT_FOUND",
            message="VNC session not found",
            details={"session_id": session_id},
        )
    if session.get("user_sub") != user_sub:
        raise VncSessionError(
            http_status=403,
            code="VNC_AUTH_UNAUTHORIZED",
            message="user is not authorized for this VNC session",
            details={"session_id": session_id},
        )

    bridge_state = BRIDGE.get(session_id)
    if bridge_state and bridge_state.get("state") not in {"closed", "failed"}:
        BRIDGE.close(session_id=session_id, reason="user_disconnect")

    if session.get("state") != "active":
        return session

    closed = STORE.close(session_id)
    final = closed or session
    target_id = str(final.get("target_id") or "unknown")
    created_at = int(final.get("created_at") or _now())
    elapsed = max(0, _now() - created_at)
    record_vnc_session_event(action="stop", outcome="success", target_id=target_id)
    record_vnc_session_duration(target_id=target_id, outcome="closed", elapsed_seconds=float(elapsed))
    log_vnc_event("session_stopped", session_id=session_id, target_id=target_id, user_sub=user_sub, duration_seconds=elapsed)
    return final


def get_bridge_state(*, session_id: str) -> dict[str, Any] | None:
    return BRIDGE.get(session_id)


def cleanup_bridge_crash(*, session_id: str) -> dict[str, Any] | None:
    closed = BRIDGE.handle_bridge_crash(session_id=session_id)
    if closed:
        STORE.close(session_id, reason="process_crash")
    return closed
