from __future__ import annotations

import io
import json
import logging
import os
import socket
import threading
import time
import uuid
from collections import deque
from types import SimpleNamespace
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.auth.deps import get_authenticated_user
from app.auth.roles import normalize_role
from app.core.settings import S
from app.metrics import (
    record_browser_ssh_connect_denied,
    record_browser_ssh_connect_throttled,
    record_browser_ssh_session_duration,
    record_browser_ssh_session_lifecycle,
    set_browser_ssh_active_sessions,
)
from app.services import terminal_monitor
from app.services.alerts import audit_event
from app.services.host_inventory import _should_record, record_connection
from app.services.sessions import require_ui_session
from app.services.ssh_key_manager import get_decrypted_private_key, get_key_metadata

router = APIRouter(prefix="/api/browser-ssh", tags=["browser-ssh-terminal"])
logger = logging.getLogger(__name__)


_ACTIVE_SSH_SESSIONS_BY_USER: dict[str, int] = {}
_CONNECT_ATTEMPTS_BY_USER: dict[str, deque[float]] = {}
_BROWSER_SSH_STATE_LOCK = threading.Lock()


# WebSocket Session Protocol v1
# Envelope: {"type": <message-type>, "payload": {...}}
#
# Client -> server:
# - connect: payload={host, port, username, authType, password?, privateKey?, passphrase?}
# - input:   payload={data}
# - resize:  payload={cols, rows}
#
# Server -> client:
# - status: payload={phase, connected, message, cols?, rows?}
# - output: payload={data}
# - error:  payload={code, message, request_type, details?}


class BrowserSshError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class ParamikoSshBridge:
    def __init__(
        self,
        *,
        host: str,
        port: int,
        username: str,
        auth_type: str,
        password: str | None,
        private_key: str | None,
        passphrase: str | None,
        cols: int,
        rows: int,
    ) -> None:
        self._host = host
        self._port = port
        self._username = username
        self._auth_type = auth_type
        self._password = password
        self._private_key = private_key
        self._passphrase = passphrase
        self._cols = cols
        self._rows = rows
        self._client: Any | None = None
        self._channel: Any | None = None
        self._closed = False
        self._output_chunks: list[str] = []
        self._lock = threading.Lock()
        self._reader_thread: threading.Thread | None = None

    def _load_private_key(self, paramiko: Any) -> Any:
        if not self._private_key:
            raise BrowserSshError("invalid_private_key", "Private key is required for private key auth.")
        key_text = self._private_key.strip()
        key_loaders = [
            paramiko.RSAKey.from_private_key,
            paramiko.Ed25519Key.from_private_key,
            paramiko.ECDSAKey.from_private_key,
            paramiko.DSSKey.from_private_key,
        ]
        last_exc: Exception | None = None
        for loader in key_loaders:
            try:
                return loader(io.StringIO(key_text), password=self._passphrase or None)
            except Exception as exc:  # pragma: no cover - parsed through aggregate error
                last_exc = exc
        raise BrowserSshError(
            "invalid_private_key_format",
            "Unsupported private key format or invalid passphrase.",
        ) from last_exc

    def connect(self) -> None:
        try:
            import paramiko
        except ImportError as exc:  # pragma: no cover - dependency protection
            raise BrowserSshError("ssh_unavailable", "SSH support is unavailable on this server.") from exc

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            connect_kwargs: dict[str, Any] = {
                "hostname": self._host,
                "port": self._port,
                "username": self._username,
                "look_for_keys": False,
                "allow_agent": False,
                "timeout": 10,
                "banner_timeout": 10,
                "auth_timeout": 10,
            }
            if self._auth_type == "private_key":
                connect_kwargs["pkey"] = self._load_private_key(paramiko)
            else:
                connect_kwargs["password"] = self._password
            client.connect(**connect_kwargs)
            channel = client.invoke_shell(term="xterm-256color", width=self._cols, height=self._rows)
            channel.settimeout(0.0)
            self._client = client
            self._channel = channel
            self._reader_thread = threading.Thread(target=self._reader_loop, daemon=True)
            self._reader_thread.start()
        except paramiko.AuthenticationException as exc:
            self.close()
            raise BrowserSshError("auth_failed", "Authentication failed. Check your username or password.") from exc
        except (paramiko.SSHException, TimeoutError, socket.error, OSError) as exc:
            self.close()
            raise BrowserSshError("connect_failed", "Unable to connect to the SSH host.") from exc

    def _reader_loop(self) -> None:
        while not self._closed:
            try:
                if not self._channel:
                    return
                if self._channel.recv_ready():
                    chunk = self._channel.recv(4096)
                    if not chunk:
                        return
                    with self._lock:
                        self._output_chunks.append(chunk.decode("utf-8", errors="replace"))
                    continue
            except Exception:
                return
            time.sleep(0.01)

    def poll_output(self) -> str:
        with self._lock:
            if not self._output_chunks:
                return ""
            output = "".join(self._output_chunks)
            self._output_chunks.clear()
            return output

    def send_input(self, data: str) -> None:
        if not self._channel:
            raise BrowserSshError("not_connected", "SSH session is not connected.")
        try:
            self._channel.send(data)
        except Exception as exc:
            raise BrowserSshError("io_error", "SSH channel is unavailable.") from exc

    def resize(self, cols: int, rows: int) -> None:
        if not self._channel:
            raise BrowserSshError("not_connected", "SSH session is not connected.")
        try:
            self._channel.resize_pty(width=cols, height=rows)
        except Exception as exc:
            raise BrowserSshError("resize_failed", "Failed to resize terminal session.") from exc

    def close(self) -> None:
        self._closed = True
        try:
            if self._channel:
                self._channel.close()
        finally:
            self._channel = None
        try:
            if self._client:
                self._client.close()
        finally:
            self._client = None


def _create_ssh_bridge(connect_info: dict[str, Any], cols: int, rows: int) -> ParamikoSshBridge:
    return ParamikoSshBridge(
        host=connect_info["host"],
        port=connect_info["port"],
        username=connect_info["username"],
        auth_type=connect_info["authType"],
        password=connect_info.get("password"),
        private_key=connect_info.get("privateKey"),
        passphrase=connect_info.get("passphrase"),
        cols=max(cols, 80),
        rows=max(rows, 24),
    )


def browser_ssh_terminal_enabled() -> bool:
    raw = os.environ.get("BROWSER_SSH_TERMINAL_ENABLED")
    if raw is None:
        return bool(getattr(S, "browser_ssh_terminal_enabled", False))
    return raw.strip().lower() not in ("0", "false", "no", "off")


def _terminal_allowed_roles() -> set[str]:
    raw = os.environ.get("BROWSER_SSH_TERMINAL_ALLOWED_ROLES")
    if raw is None:
        raw = getattr(S, "browser_ssh_terminal_allowed_roles", "admin,root")
    return {item.strip().lower() for item in (raw or "").split(",") if item.strip()}


async def _authorize_terminal_access(websocket: WebSocket) -> tuple[dict[str, str] | None, dict[str, Any] | None]:
    req = SimpleNamespace(
        cookies=dict(getattr(websocket, "cookies", {}) or {}),
        headers=websocket.headers,
        method="GET",
        state=SimpleNamespace(),
        client=getattr(websocket, "client", None),
    )
    user_sub = "anonymous"
    try:
        auth_user = await get_authenticated_user(req)
        role = normalize_role(getattr(auth_user, "role", None)).value
        user_sub = str(getattr(auth_user, "sub", "") or "anonymous")
        ctx = await require_ui_session(req, auth_user=auth_user)
        allowed_roles = _terminal_allowed_roles()
        if allowed_roles and role not in allowed_roles:
            audit_event(
                "browser_ssh_connect_access_denied",
                user_sub,
                req,
                outcome="denied",
                reason="missing_terminal_connect_role",
                required_role_hint="terminal.connect",
                role=role,
            )
            record_browser_ssh_connect_denied(reason="forbidden")
            return None, _error_payload(
                code="forbidden",
                message="Not authorized for terminal.connect",
                request_type="connect",
            )
        audit_event("browser_ssh_connect_access_granted", user_sub, req, outcome="success", role=role)
        return {"user_sub": ctx.get("user_sub", user_sub), "role": role}, None
    except Exception:
        audit_event(
            "browser_ssh_connect_access_denied",
            user_sub,
            req,
            outcome="denied",
            reason="unauthenticated",
            required_role_hint="terminal.connect",
        )
        record_browser_ssh_connect_denied(reason="unauthorized")
        return None, _error_payload(
            code="unauthorized",
            message="Authentication required to open terminal session",
            request_type="connect",
        )


def _max_sessions_per_user() -> int:
    raw = os.environ.get("BROWSER_SSH_MAX_SESSIONS_PER_USER")
    if raw is None:
        raw = str(getattr(S, "browser_ssh_max_sessions_per_user", 2))
    try:
        return max(0, int(raw))
    except ValueError:
        return 2


def _idle_timeout_seconds() -> int:
    raw = os.environ.get("BROWSER_SSH_IDLE_TIMEOUT_SECONDS")
    if raw is None:
        raw = str(getattr(S, "browser_ssh_idle_timeout_seconds", 900))
    try:
        return max(1, int(raw))
    except ValueError:
        return 900


def _max_session_duration_seconds() -> int:
    raw = os.environ.get("BROWSER_SSH_MAX_SESSION_DURATION_SECONDS")
    if raw is None:
        raw = str(getattr(S, "browser_ssh_max_session_duration_seconds", 3600))
    try:
        return max(1, int(raw))
    except ValueError:
        return 3600


def _connect_rate_limit_count() -> int:
    raw = os.environ.get("BROWSER_SSH_CONNECT_RATE_LIMIT_COUNT")
    if raw is None:
        raw = str(getattr(S, "browser_ssh_connect_rate_limit_count", 10))
    try:
        return max(1, int(raw))
    except ValueError:
        return 10


def _connect_rate_limit_window_seconds() -> int:
    raw = os.environ.get("BROWSER_SSH_CONNECT_RATE_LIMIT_WINDOW_SECONDS")
    if raw is None:
        raw = str(getattr(S, "browser_ssh_connect_rate_limit_window_seconds", 60))
    try:
        return max(1, int(raw))
    except ValueError:
        return 60


def _try_acquire_user_session_slot(user_sub: str) -> bool:
    limit = _max_sessions_per_user()
    with _BROWSER_SSH_STATE_LOCK:
        current = int(_ACTIVE_SSH_SESSIONS_BY_USER.get(user_sub, 0))
        if current >= limit:
            return False
        current += 1
        _ACTIVE_SSH_SESSIONS_BY_USER[user_sub] = current
        set_browser_ssh_active_sessions(user_sub=user_sub, count=current)
        return True


def _release_user_session_slot(user_sub: str | None) -> None:
    if not user_sub:
        return
    with _BROWSER_SSH_STATE_LOCK:
        current = int(_ACTIVE_SSH_SESSIONS_BY_USER.get(user_sub, 0))
        if current <= 1:
            _ACTIVE_SSH_SESSIONS_BY_USER.pop(user_sub, None)
            set_browser_ssh_active_sessions(user_sub=user_sub, count=0)
            return
        current -= 1
        _ACTIVE_SSH_SESSIONS_BY_USER[user_sub] = current
        set_browser_ssh_active_sessions(user_sub=user_sub, count=current)


def _consume_connect_rate_limit(user_sub: str, now: float) -> bool:
    cap = _connect_rate_limit_count()
    window = float(_connect_rate_limit_window_seconds())
    with _BROWSER_SSH_STATE_LOCK:
        dq = _CONNECT_ATTEMPTS_BY_USER.get(user_sub)
        if dq is None:
            dq = deque()
            _CONNECT_ATTEMPTS_BY_USER[user_sub] = dq
        threshold = now - window
        while dq and dq[0] < threshold:
            dq.popleft()
        if len(dq) >= cap:
            return False
        dq.append(now)
        return True


def _session_timeout_error(*, started_at: float, last_activity_at: float, now: float) -> dict[str, Any] | None:
    if now - last_activity_at > float(_idle_timeout_seconds()):
        return _error_payload(
            code="idle_timeout",
            message="SSH session closed due to inactivity timeout.",
            request_type="session",
        )
    if now - started_at > float(_max_session_duration_seconds()):
        return _error_payload(
            code="session_expired",
            message="SSH session closed due to max session duration.",
            request_type="session",
        )
    return None


def _csv_items(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [item.strip().lower() for item in raw.split(",") if item.strip()]


def _host_matches(pattern: str, host: str) -> bool:
    p = pattern.strip().lower()
    h = host.strip().lower()
    if not p:
        return False
    if p == "*":
        return True
    if p.startswith("*."):
        suffix = p[1:]
        return h.endswith(suffix)
    return h == p


def _policy_hosts_allowed() -> list[str]:
    raw = os.environ.get("BROWSER_SSH_ALLOWED_HOSTS")
    if raw is None:
        raw = getattr(S, "browser_ssh_allowed_hosts", "")
    return _csv_items(raw)


def _policy_hosts_denied() -> list[str]:
    raw = os.environ.get("BROWSER_SSH_DENIED_HOSTS")
    if raw is None:
        raw = getattr(S, "browser_ssh_denied_hosts", "")
    return _csv_items(raw)


def _policy_ports_allowed() -> set[int]:
    raw = os.environ.get("BROWSER_SSH_ALLOWED_PORTS")
    if raw is None:
        raw = getattr(S, "browser_ssh_allowed_ports", "")
    values: set[int] = set()
    for item in _csv_items(raw):
        try:
            port = int(item)
        except ValueError:
            continue
        if 1 <= port <= 65535:
            values.add(port)
    return values


def _policy_ports_denied() -> set[int]:
    raw = os.environ.get("BROWSER_SSH_DENIED_PORTS")
    if raw is None:
        raw = getattr(S, "browser_ssh_denied_ports", "")
    values: set[int] = set()
    for item in _csv_items(raw):
        try:
            port = int(item)
        except ValueError:
            continue
        if 1 <= port <= 65535:
            values.add(port)
    return values


def _enforce_destination_policy(connect_info: dict[str, Any]) -> dict[str, Any] | None:
    host = str(connect_info.get("host") or "").strip().lower()
    port = int(connect_info.get("port") or 0)

    denied_hosts = _policy_hosts_denied()
    if any(_host_matches(pattern, host) for pattern in denied_hosts):
        return _error_payload(
            code="policy_denied_host",
            message="Connection denied by destination policy: host is blocked.",
            request_type="connect",
        )

    allowed_hosts = _policy_hosts_allowed()
    if allowed_hosts and not any(_host_matches(pattern, host) for pattern in allowed_hosts):
        return _error_payload(
            code="policy_denied_host",
            message="Connection denied by destination policy: host is not allowlisted.",
            request_type="connect",
        )

    denied_ports = _policy_ports_denied()
    if port in denied_ports:
        return _error_payload(
            code="policy_denied_port",
            message="Connection denied by destination policy: port is blocked.",
            request_type="connect",
        )

    allowed_ports = _policy_ports_allowed()
    if allowed_ports and port not in allowed_ports:
        return _error_payload(
            code="policy_denied_port",
            message="Connection denied by destination policy: port is not allowlisted.",
            request_type="connect",
        )

    return None


@router.get("/config")
def browser_ssh_terminal_config() -> dict[str, object]:
    return {
        "enabled": browser_ssh_terminal_enabled(),
        "route": "/browser-ssh",
        "ws_path": "/api/browser-ssh/ws",
        "protocol_version": "v1",
        "policy": {
            "allowed_hosts_configured": bool(_policy_hosts_allowed()),
            "denied_hosts_configured": bool(_policy_hosts_denied()),
            "allowed_ports_configured": bool(_policy_ports_allowed()),
            "denied_ports_configured": bool(_policy_ports_denied()),
        },
        "limits": {
            "idle_timeout_seconds": _idle_timeout_seconds(),
            "max_session_duration_seconds": _max_session_duration_seconds(),
            "max_sessions_per_user": _max_sessions_per_user(),
            "connect_rate_limit_count": _connect_rate_limit_count(),
            "connect_rate_limit_window_seconds": _connect_rate_limit_window_seconds(),
        },
    }


@router.get("/protocol")
def browser_ssh_terminal_protocol() -> dict[str, object]:
    """Protocol documentation endpoint for Browser SSH websocket v1."""
    return {
        "version": "v1",
        "envelope": {"type": "string", "payload": "object"},
        "client_messages": {
            "connect": {
                "required": ["host", "port", "username", "authType"],
                "authType": ["password", "private_key", "stored_key"],
                "example": {
                    "type": "connect",
                    "payload": {
                        "host": "example.internal",
                        "port": 22,
                        "username": "alice",
                        "authType": "password",
                        "password": "***",
                    },
                },
                "example_stored_key": {
                    "type": "connect",
                    "payload": {
                        "host": "example.internal",
                        "port": 22,
                        "username": "alice",
                        "authType": "stored_key",
                        "keyId": "key_abc123",
                    },
                },
            },
            "input": {
                "required": ["data"],
                "example": {"type": "input", "payload": {"data": "ls -la\n"}},
            },
            "resize": {
                "required": ["cols", "rows"],
                "example": {"type": "resize", "payload": {"cols": 120, "rows": 36}},
            },
        },
        "server_messages": {
            "status": {"payload": ["phase", "connected", "message", "cols", "rows"]},
            "output": {"payload": ["data"]},
            "error": {"payload": ["code", "message", "request_type", "details"]},
        },
    }


@router.get("/health")
def browser_ssh_terminal_health() -> dict[str, object]:
    return {
        "service": "browser-ssh-gateway",
        "status": "ok",
        "websocket_placeholder": False,
        "protocol_version": "v1",
    }


def _looks_like_private_key(raw: str) -> bool:
    text = raw.strip()
    if not (text.startswith("-----BEGIN ") and "PRIVATE KEY-----" in text):
        return False
    return any(
        text.endswith(suffix)
        for suffix in (
            "-----END OPENSSH PRIVATE KEY-----",
            "-----END RSA PRIVATE KEY-----",
            "-----END PRIVATE KEY-----",
            "-----END EC PRIVATE KEY-----",
            "-----END DSA PRIVATE KEY-----",
        )
    )


def _redact_connect_payload(payload: dict[str, Any]) -> dict[str, Any]:
    redacted = dict(payload)
    if "password" in redacted:
        redacted["password"] = "***REDACTED***"
    if "privateKey" in redacted:
        key_text = str(redacted.get("privateKey") or "")
        redacted["privateKey"] = f"***REDACTED***({len(key_text)} chars)"
    if "passphrase" in redacted:
        redacted["passphrase"] = "***REDACTED***"
    if "keyId" in redacted and redacted.get("keyId"):
        key_id = str(redacted.get("keyId") or "")
        redacted["keyId"] = f"***REDACTED***({len(key_id)} chars)"
    return redacted


def _session_log_context(*, session_id: str, user_sub: str, host: str | None = None, port: int | None = None) -> dict[str, Any]:
    ctx: dict[str, Any] = {"session_id": session_id, "user_sub": user_sub}
    if host:
        ctx["host"] = host
    if port is not None:
        ctx["port"] = int(port)
    return ctx


def _audit_session_event(
    *,
    event: str,
    user_sub: str,
    host: str | None,
    port: int | None,
    session_id: str,
    started_at: float,
    outcome: str,
    reason: str = "",
) -> None:
    fields: dict[str, Any] = {
        "outcome": outcome,
        "session_id": session_id,
        "started_at": int(started_at),
    }
    if host:
        fields["host"] = host
    if port is not None:
        fields["port"] = int(port)
    if reason:
        fields["reason"] = reason
    audit_event(event, user_sub, None, **fields)


def _error_payload(*, code: str, message: str, request_type: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "code": code,
        "message": message,
        "request_type": request_type,
    }
    if details:
        payload["details"] = details
    return payload


def _validate_connect_payload(payload: Any) -> tuple[bool, dict[str, Any] | None, dict[str, Any] | None]:
    if not isinstance(payload, dict):
        return False, None, _error_payload(
            code="invalid_payload",
            message="connect payload must be an object",
            request_type="connect",
        )

    host = payload.get("host")
    port = payload.get("port")
    username = payload.get("username")
    auth_type = payload.get("authType")

    if not isinstance(host, str) or not host.strip():
        return False, None, _error_payload(
            code="invalid_host",
            message="host is required",
            request_type="connect",
        )
    if not isinstance(port, int) or port < 1 or port > 65535:
        return False, None, _error_payload(
            code="invalid_port",
            message="port must be an integer between 1 and 65535",
            request_type="connect",
        )
    if not isinstance(username, str) or not username.strip():
        return False, None, _error_payload(
            code="invalid_username",
            message="username is required",
            request_type="connect",
        )
    if auth_type not in {"password", "private_key", "stored_key"}:
        return False, None, _error_payload(
            code="invalid_auth_type",
            message="authType must be one of: password, private_key, stored_key",
            request_type="connect",
        )

    if auth_type == "password":
        password = payload.get("password")
        if not isinstance(password, str) or not password:
            return False, None, _error_payload(
                code="invalid_password",
                message="password is required for password auth",
                request_type="connect",
            )
    elif auth_type == "stored_key":
        # The browser sends only an opaque keyId; the private key never leaves
        # the server. The PEM is resolved server-side in the connect handler via
        # ssh_key_manager.get_decrypted_private_key.
        key_id = payload.get("keyId")
        if not isinstance(key_id, str) or not key_id.strip():
            return False, None, _error_payload(
                code="invalid_key_id",
                message="keyId is required for stored_key auth",
                request_type="connect",
            )
    else:
        key = payload.get("privateKey")
        if not isinstance(key, str) or not key.strip():
            return False, None, _error_payload(
                code="invalid_private_key",
                message="privateKey is required for private_key auth",
                request_type="connect",
            )
        if not _looks_like_private_key(key):
            return False, None, _error_payload(
                code="invalid_private_key_format",
                message="Unsupported private key format. Use PEM/OpenSSH private key text.",
                request_type="connect",
            )

    passphrase = payload.get("passphrase")
    if passphrase is not None and not isinstance(passphrase, str):
        return False, None, _error_payload(
            code="invalid_passphrase",
            message="passphrase must be a string",
            request_type="connect",
        )

    return True, {
        "host": host.strip(),
        "port": port,
        "username": username.strip(),
        "authType": auth_type,
        "password": payload.get("password"),
        "privateKey": payload.get("privateKey"),
        "keyId": payload.get("keyId"),
        "passphrase": passphrase,
        # Optional registered host reference (host inventory). Used post-connect
        # to resolve the per-host record_sessions flag (INFRA-010 / GAP-0234).
        "host_id": str(payload.get("host_id") or "").strip(),
    }, None


async def _dispatch_terminal_signal(
    *,
    signal: dict[str, Any],
    worker_id: str,
    user_id: str | None,
    websocket: WebSocket,
) -> None:
    """Dispatch an agent terminal signal detected in the SSH output stream.

    Creates a feedback request on ``feedback_needed`` and notifies the browser
    for completion/error signals. Best-effort: any failure is logged and
    swallowed so terminal forwarding is never interrupted.
    """
    category = signal.get("signal")
    match_text = signal.get("match", "")
    detected_pattern = signal.get("pattern", "")
    buf = terminal_monitor.get_or_create_buffer(worker_id)
    context = buf.get_recent(2000)

    if category == "feedback_needed":
        try:
            req = terminal_monitor.create_feedback_request(
                user_id=user_id or "",
                worker_id=worker_id,
                ticket_id="",
                question=match_text,
                terminal_context=context,
                detected_pattern=detected_pattern,
            )
            await websocket.send_json(
                {
                    "type": "feedback_request",
                    "payload": {"request_id": req["request_id"], "question": match_text},
                }
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.error(
                "Failed to create feedback request for worker %s: %s",
                worker_id, exc,
            )
    elif category == "completion":
        try:
            await websocket.send_json({"type": "agent_complete", "payload": {}})
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("Failed to send agent_complete for worker %s: %s", worker_id, exc)
    elif category == "error":
        try:
            await websocket.send_json(
                {"type": "agent_error", "payload": {"match": match_text}}
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("Failed to send agent_error for worker %s: %s", worker_id, exc)


@router.websocket("/ws")
async def browser_ssh_terminal_ws(websocket: WebSocket) -> None:
    import asyncio

    ws_session_id = uuid.uuid4().hex[:12]
    await websocket.accept()
    auth_ctx, auth_err = await _authorize_terminal_access(websocket)
    if auth_err:
        logger.warning(
            "browser_ssh websocket unauthorized",
            extra={"session_id": ws_session_id, "code": auth_err.get("code")},
        )
        await websocket.send_json({"type": "error", "payload": auth_err})
        await websocket.close(code=4403)
        return

    session_connected = False
    session_size = {"cols": 0, "rows": 0}
    ssh_bridge: ParamikoSshBridge | None = None
    session_user_sub = auth_ctx.get("user_sub")
    session_slot_acquired = False
    session_started_at = time.time()
    session_last_activity_at = session_started_at
    connected_started_at: float | None = None
    session_host: str | None = None
    session_port: int | None = None
    session_worker_id: str | None = None
    # INFRA-010 (GAP-0233/GAP-0234): server-side SSH session recording state.
    recording_id: str | None = None
    recording_start_time: float | None = None
    end_outcome = "disconnected"
    end_reason = "websocket_closed"

    logger.info("browser_ssh websocket accepted", extra=_session_log_context(session_id=ws_session_id, user_sub=session_user_sub))
    record_browser_ssh_session_lifecycle(event="ws", outcome="accepted")

    await websocket.send_json(
        {
            "type": "status",
            "payload": {
                "phase": "ready",
                "connected": False,
                "message": f"Browser SSH gateway is ready (protocol v1) for {auth_ctx['user_sub']}.",
            },
        }
    )

    try:
        while True:
            now = time.time()
            if session_connected:
                timeout_err = _session_timeout_error(
                    started_at=session_started_at,
                    last_activity_at=session_last_activity_at,
                    now=now,
                )
                if timeout_err:
                    end_outcome = "timeout"
                    end_reason = str(timeout_err.get("code") or "session_timeout")
                    await websocket.send_json({"type": "error", "payload": timeout_err})
                    await websocket.close(code=4000)
                    break

            if ssh_bridge:
                output = ssh_bridge.poll_output()
                if output:
                    session_last_activity_at = now
                    await websocket.send_json({"type": "output", "payload": {"data": output}})
                    # INFRA-010 (GAP-0233): server-side recording capture. Append
                    # each output chunk in asciicast [elapsed, "o", data] form.
                    # Best-effort: a recording failure must NEVER interrupt the
                    # live terminal stream.
                    if recording_id is not None and recording_start_time is not None:
                        elapsed = round(time.time() - recording_start_time, 6)
                        try:
                            from app.services.ssh_session_recording import append_events

                            append_events(
                                session_user_sub,
                                recording_id,
                                [[elapsed, "o", output]],
                            )
                        except Exception:
                            logger.exception(
                                "browser_ssh recording_append_failed recording_id=%s",
                                recording_id,
                            )
                    # Tap into the monitoring pipeline only for agent-tracked
                    # sessions (worker_id present in the connect payload). Normal
                    # interactive terminals leave session_worker_id None and are
                    # entirely unaffected.
                    if session_worker_id:
                        signal = terminal_monitor.process_terminal_output(
                            session_worker_id, output
                        )
                        if signal:
                            await _dispatch_terminal_signal(
                                signal=signal,
                                worker_id=session_worker_id,
                                user_id=session_user_sub,
                                websocket=websocket,
                            )

            try:
                raw_message = await asyncio.wait_for(websocket.receive_text(), timeout=0.05)
            except asyncio.TimeoutError:
                continue

            try:
                envelope = json.loads(raw_message)
            except json.JSONDecodeError:
                await websocket.send_json(
                    {
                        "type": "error",
                        "payload": _error_payload(
                            code="invalid_json",
                            message="message must be valid JSON",
                            request_type="unknown",
                        ),
                    }
                )
                continue

            if not isinstance(envelope, dict):
                await websocket.send_json(
                    {
                        "type": "error",
                        "payload": _error_payload(
                            code="invalid_envelope",
                            message="message must be a JSON object",
                            request_type="unknown",
                        ),
                    }
                )
                continue

            msg_type = envelope.get("type")
            payload = envelope.get("payload")
            if not isinstance(msg_type, str) or not msg_type:
                await websocket.send_json(
                    {
                        "type": "error",
                        "payload": _error_payload(
                            code="missing_type",
                            message="message type is required",
                            request_type="unknown",
                        ),
                    }
                )
                continue

            if msg_type == "connect":
                valid, normalized, err = _validate_connect_payload(payload)
                if not valid:
                    await websocket.send_json({"type": "error", "payload": err})
                    continue

                session_host = str(normalized["host"])
                session_port = int(normalized["port"])
                # Optional agent linkage: when the Worker Fleet UI launches an
                # agent terminal it includes a worker_id so output flows into
                # the monitoring pipeline. Absent for normal terminals.
                wid = payload.get("worker_id") if isinstance(payload, dict) else None
                session_worker_id = wid.strip() if isinstance(wid, str) and wid.strip() else None
                now = time.time()
                if not _consume_connect_rate_limit(session_user_sub, now):
                    record_browser_ssh_connect_throttled(reason="connect_rate_limit")
                    record_browser_ssh_session_lifecycle(event="connect", outcome="failure")
                    await websocket.send_json(
                        {
                            "type": "error",
                            "payload": _error_payload(
                                code="rate_limited",
                                message="Too many connect attempts. Please retry later.",
                                request_type="connect",
                            ),
                        }
                    )
                    continue

                if not session_slot_acquired and not _try_acquire_user_session_slot(session_user_sub):
                    record_browser_ssh_connect_denied(reason="session_limit")
                    record_browser_ssh_session_lifecycle(event="connect", outcome="failure")
                    await websocket.send_json(
                        {
                            "type": "error",
                            "payload": _error_payload(
                                code="session_limit_exceeded",
                                message="Maximum concurrent terminal sessions reached for this user.",
                                request_type="connect",
                            ),
                        }
                    )
                    continue
                session_slot_acquired = True

                policy_err = _enforce_destination_policy(normalized)
                if policy_err:
                    record_browser_ssh_connect_denied(reason=str(policy_err.get("code") or "policy_denied"))
                    record_browser_ssh_session_lifecycle(event="connect", outcome="failure")
                    await websocket.send_json({"type": "error", "payload": policy_err})
                    if session_slot_acquired:
                        _release_user_session_slot(session_user_sub)
                        session_slot_acquired = False
                    continue

                # stored_key auth: the browser only sent an opaque keyId. Resolve
                # the KMS-encrypted private key server-side so the PEM never
                # reaches the browser. We preserve the original auth type + keyId
                # for post-connect host bookkeeping, then normalise to the
                # existing private_key bridge path.
                session_stored_key_auth = normalized["authType"] == "stored_key"
                session_stored_key_id = ""
                if session_stored_key_auth:
                    session_stored_key_id = str(normalized.get("keyId") or "")
                    pem = get_decrypted_private_key(session_user_sub, session_stored_key_id)
                    if pem is None:
                        record_browser_ssh_connect_denied(reason="key_not_found")
                        record_browser_ssh_session_lifecycle(event="connect", outcome="failure")
                        await websocket.send_json(
                            {
                                "type": "error",
                                "payload": _error_payload(
                                    code="key_not_found",
                                    message="SSH key not found or access denied.",
                                    request_type="connect",
                                ),
                            }
                        )
                        if session_slot_acquired:
                            _release_user_session_slot(session_user_sub)
                            session_slot_acquired = False
                        continue
                    normalized["privateKey"] = pem
                    normalized["authType"] = "private_key"

                if ssh_bridge:
                    ssh_bridge.close()
                    ssh_bridge = None

                logger.info(
                    "browser_ssh connect request",
                    extra={
                        **_session_log_context(
                            session_id=ws_session_id,
                            user_sub=session_user_sub,
                            host=session_host,
                            port=session_port,
                        ),
                        "connect": _redact_connect_payload(normalized),
                    },
                )
                try:
                    ssh_bridge = _create_ssh_bridge(normalized, session_size["cols"], session_size["rows"])
                    ssh_bridge.connect()
                except BrowserSshError as exc:
                    session_connected = False
                    end_outcome = "connect_failed"
                    end_reason = exc.code
                    record_browser_ssh_session_lifecycle(event="connect", outcome="failure")
                    logger.warning(
                        "browser_ssh connect failed",
                        extra={
                            **_session_log_context(
                                session_id=ws_session_id,
                                user_sub=session_user_sub,
                                host=session_host,
                                port=session_port,
                            ),
                            "code": exc.code,
                            "connect": _redact_connect_payload(normalized),
                        },
                    )
                    await websocket.send_json(
                        {
                            "type": "error",
                            "payload": _error_payload(
                                code=exc.code,
                                message=exc.message,
                                request_type="connect",
                            ),
                        }
                    )
                    if session_slot_acquired:
                        _release_user_session_slot(session_user_sub)
                        session_slot_acquired = False
                    continue

                session_connected = True
                session_started_at = now
                connected_started_at = now
                session_last_activity_at = now
                record_browser_ssh_session_lifecycle(event="connect", outcome="success")
                _audit_session_event(
                    event="browser_ssh_session_start",
                    user_sub=session_user_sub,
                    host=session_host,
                    port=session_port,
                    session_id=ws_session_id,
                    started_at=session_started_at,
                    outcome="success",
                )
                # For stored_key connections against managed hosts, record the
                # connection so the host inventory's last_connected_at / history
                # audit trail stays accurate. Best-effort: never break the session.
                if session_stored_key_auth and session_stored_key_id:
                    try:
                        key_meta = get_key_metadata(session_user_sub, session_stored_key_id)
                        for associated_host_id in (key_meta or {}).get("associated_hosts", []) or []:
                            record_connection(session_user_sub, associated_host_id)
                    except Exception:
                        logger.warning(
                            "browser_ssh stored_key record_connection failed",
                            extra=_session_log_context(
                                session_id=ws_session_id,
                                user_sub=session_user_sub,
                                host=session_host,
                                port=session_port,
                            ),
                        )
                # INFRA-010 (GAP-0233/GAP-0234): start server-side session
                # recording when the global flag is on AND either the per-host
                # record_sessions flag is set or the always-record override is
                # enabled. Best-effort: recording failures never abort the
                # session (recording_id stays None → output loop skips capture).
                connect_host_id = str(normalized.get("host_id") or "").strip()
                auto_record = (
                    _should_record(session_user_sub, connect_host_id)
                    or S.ssh_session_recording_always_record
                )
                logger.info(
                    "browser_ssh auto_record_decision auto_record=%s host_id=%s",
                    auto_record, connect_host_id or "(none)",
                )
                if auto_record and S.ssh_session_recording_enabled:
                    try:
                        from app.services.ssh_session_recording import start_recording

                        rec = start_recording(
                            session_user_sub,
                            hostname=str(session_host or ""),
                            port=int(session_port or 0),
                            username=str(normalized.get("username") or ""),
                            terminal_cols=int(session_size.get("cols") or 80),
                            terminal_rows=int(session_size.get("rows") or 24),
                            host_id=connect_host_id,
                            session_id=ws_session_id,
                        )
                        recording_id = rec["recording_id"]
                        recording_start_time = time.time()
                        logger.info(
                            "browser_ssh recording_started recording_id=%s",
                            recording_id,
                            extra=_session_log_context(
                                session_id=ws_session_id,
                                user_sub=session_user_sub,
                                host=session_host,
                                port=session_port,
                            ),
                        )
                    except Exception:
                        logger.exception(
                            "browser_ssh recording_start_failed session_id=%s",
                            ws_session_id,
                        )
                        recording_id = None
                logger.info(
                    "browser_ssh connect success",
                    extra=_session_log_context(
                        session_id=ws_session_id,
                        user_sub=session_user_sub,
                        host=session_host,
                        port=session_port,
                    ),
                )
                await websocket.send_json(
                    {
                        "type": "status",
                        "payload": {
                            "phase": "connected",
                            "connected": True,
                            "message": f"Connected to {normalized['host']}:{normalized['port']} as {normalized['username']}",
                            "cols": session_size["cols"],
                            "rows": session_size["rows"],
                        },
                    }
                )
                continue

            if msg_type == "input":
                if not session_connected:
                    await websocket.send_json(
                        {
                            "type": "error",
                            "payload": _error_payload(
                                code="not_connected",
                                message="connect must be completed before input",
                                request_type="input",
                            ),
                        }
                    )
                    continue
                if not isinstance(payload, dict) or not isinstance(payload.get("data"), str):
                    await websocket.send_json(
                        {
                            "type": "error",
                            "payload": _error_payload(
                                code="invalid_payload",
                                message="input payload must include string field data",
                                request_type="input",
                            ),
                        }
                    )
                    continue

                if ssh_bridge:
                    try:
                        ssh_bridge.send_input(payload["data"])
                    except BrowserSshError as exc:
                        await websocket.send_json(
                            {
                                "type": "error",
                                "payload": _error_payload(
                                    code=exc.code,
                                    message=exc.message,
                                    request_type="input",
                                ),
                            }
                        )
                session_last_activity_at = time.time()
                continue

            if msg_type == "resize":
                if not session_connected:
                    await websocket.send_json(
                        {
                            "type": "error",
                            "payload": _error_payload(
                                code="not_connected",
                                message="connect must be completed before resize",
                                request_type="resize",
                            ),
                        }
                    )
                    continue
                if not isinstance(payload, dict):
                    await websocket.send_json(
                        {
                            "type": "error",
                            "payload": _error_payload(
                                code="invalid_payload",
                                message="resize payload must be an object",
                                request_type="resize",
                            ),
                        }
                    )
                    continue

                cols = payload.get("cols")
                rows = payload.get("rows")
                if not isinstance(cols, int) or not isinstance(rows, int) or cols <= 0 or rows <= 0:
                    await websocket.send_json(
                        {
                            "type": "error",
                            "payload": _error_payload(
                                code="invalid_resize",
                                message="resize payload must include positive integer cols and rows",
                                request_type="resize",
                            ),
                        }
                    )
                    continue

                session_size = {"cols": cols, "rows": rows}
                session_last_activity_at = time.time()
                if ssh_bridge:
                    try:
                        ssh_bridge.resize(cols, rows)
                    except BrowserSshError as exc:
                        await websocket.send_json(
                            {
                                "type": "error",
                                "payload": _error_payload(
                                    code=exc.code,
                                    message=exc.message,
                                    request_type="resize",
                                ),
                            }
                        )
                await websocket.send_json(
                    {
                        "type": "status",
                        "payload": {
                            "phase": "resized",
                            "connected": True,
                            "message": f"Terminal resized to {cols}x{rows}",
                            "cols": cols,
                            "rows": rows,
                        },
                    }
                )
                continue

            await websocket.send_json(
                {
                    "type": "error",
                    "payload": _error_payload(
                        code="unsupported_type",
                        message="unsupported message type",
                        request_type=msg_type,
                    ),
                }
            )
    except WebSocketDisconnect:
        end_reason = "websocket_disconnect"
    finally:
        if ssh_bridge:
            ssh_bridge.close()
        # INFRA-010 (GAP-0233): finalize the server-side recording. Best-effort.
        if recording_id is not None:
            try:
                from app.services.ssh_session_recording import stop_recording

                stop_recording(session_user_sub, recording_id)
                logger.info(
                    "browser_ssh recording_finished recording_id=%s", recording_id
                )
            except Exception:
                logger.exception(
                    "browser_ssh recording_finish_failed recording_id=%s",
                    recording_id,
                )
        if connected_started_at is not None:
            elapsed = time.time() - connected_started_at
            record_browser_ssh_session_duration(outcome=end_outcome, elapsed_seconds=elapsed)
            record_browser_ssh_session_lifecycle(event="session_end", outcome=end_outcome)
            _audit_session_event(
                event="browser_ssh_session_end",
                user_sub=session_user_sub,
                host=session_host,
                port=session_port,
                session_id=ws_session_id,
                started_at=session_started_at,
                outcome=end_outcome,
                reason=end_reason,
            )
            logger.info(
                "browser_ssh session ended",
                extra={
                    **_session_log_context(
                        session_id=ws_session_id,
                        user_sub=session_user_sub,
                        host=session_host,
                        port=session_port,
                    ),
                    "outcome": end_outcome,
                    "reason": end_reason,
                    "duration_seconds": round(elapsed, 3),
                },
            )
        if session_slot_acquired:
            _release_user_session_slot(session_user_sub)
