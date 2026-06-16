"""RDP browser transport — Phase 1 (Option C fallback) per ADR-004.

This module implements the *fallback* RDP transport decided in
`docs/adr/ADR-004-rdp-transport.md`:

- There is NO native in-browser RDP rendering yet. The native Guacamole
  gateway path (Option A) is a separately-budgeted future milestone.
- The master gate `RDP_REMOTE_DESKTOP_ENABLED` defaults **off**. With it off,
  the reserved native session endpoint returns ``503 RDP_FEATURE_DISABLED``
  and the FE shows a clear "RDP not available — use VNC/SSH" surface — never a
  broken connect attempt.
- The session/token *contract* mirrors the VNC scheme
  (`app/services/vnc_sessions.py`) so the future native build is additive: the
  endpoint shape, ownership scoping (`user:{host_id}`), and connect_params
  envelope are locked in now.

Security invariants inherited from VNC (see ADR §"Security & dev/prod-parity"):
server-side, owner-scoped host resolution only (client never supplies
host/port); flag-gated fail-safe; no `dev_mode` fork in the resolution logic.

NOTE: settings are read via module-level ``os.environ`` exactly like
`app/services/vnc_sessions.py` (VNC does NOT route these through the ``S``
settings dataclass), keeping the two subsystems byte-for-byte parallel.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("app.rdp.sessions")


@dataclass(frozen=True)
class RdpFallbackTarget:
    """Owner-scoped host metadata surfaced to the FE fallback page.

    Contains NO secrets — only the connection coordinates a user would type
    into a native RDP client (mstsc / Microsoft Remote Desktop / FreeRDP).
    """

    host_id: str
    hostname: str
    port: int
    username: str
    label: str


class RdpSessionError(Exception):
    """Structured error mirroring `VncSessionError` so the router maps it the
    same way (http_status + machine-readable code)."""

    def __init__(self, *, http_status: int, code: str, message: str, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.http_status = http_status
        self.code = code
        self.message = message
        self.details = details or {}


def _env_flag(name: str, *, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def rdp_feature_enabled() -> bool:
    """Master gate. Defaults OFF per ADR-004.

    When off: only the fallback/instructions UX is available and the native
    session endpoint returns 503.
    """
    return _env_flag("RDP_REMOTE_DESKTOP_ENABLED", default=False)


def _ensure_rdp_feature_enabled() -> None:
    """Mirror `_ensure_vnc_feature_enabled`: raise 503 when the master gate is
    off. In Phase 1 the gate is off by default, so the native session endpoint
    is dormant and the FE uses the fallback surface."""
    if rdp_feature_enabled():
        return
    raise RdpSessionError(
        http_status=503,
        code="RDP_FEATURE_DISABLED",
        message="native RDP remote desktop is not available; use VNC/SSH or a native RDP client",
    )


def _resolve_fallback_target(*, user_sub: str, host_id: str) -> RdpFallbackTarget:
    """Resolve an owner-scoped RDP host into copy-ready connection metadata.

    Ownership is enforced by the host_inventory ``Key={user_sub, sk}`` access
    pattern (same as VNC `_resolve_target` and CTI-001/CTI-002): a host_id not
    owned by the caller simply doesn't resolve → RDP_TARGET_NOT_FOUND.
    """
    host_id = (host_id or "").strip()
    if not host_id:
        raise RdpSessionError(
            http_status=404,
            code="RDP_TARGET_NOT_FOUND",
            message="host_id is required",
        )

    host = None
    try:
        from app.services.host_inventory import get_host

        host = get_host(user_sub, host_id)
    except Exception:  # pragma: no cover - lookup failure is treated as not-found
        host = None

    if not host or not host.get("hostname"):
        raise RdpSessionError(
            http_status=404,
            code="RDP_TARGET_NOT_FOUND",
            message="requested RDP host is not registered",
            details={"host_id": host_id},
        )

    port = int(host.get("port") or 0) or 3389
    return RdpFallbackTarget(
        host_id=host_id,
        hostname=str(host.get("hostname") or ""),
        port=port,
        username=str(host.get("username") or ""),
        label=str(host.get("label") or host.get("hostname") or host_id),
    )


def get_fallback_details(*, user_sub: str, host_id: str) -> dict[str, Any]:
    """Return the Phase-1 fallback payload for a Windows/RDP host.

    No session/token is minted (there is no live bridge in Phase 1). The
    payload is pure, secret-free metadata + native-client guidance. This path
    is identical in dev and prod (SECOPS-007 parity).
    """
    target = _resolve_fallback_target(user_sub=user_sub, host_id=host_id)
    address = f"{target.hostname}:{target.port}"
    instructions = (
        "Native in-browser RDP is not available yet. Connect using a native RDP "
        "client (Windows Remote Desktop / mstsc, Microsoft Remote Desktop on macOS, "
        f"or FreeRDP) to {address}"
        + (f" with username '{target.username}'." if target.username else ".")
        + " If this host also exposes a VNC endpoint, you can connect in-browser via VNC instead."
    )
    return {
        "available": False,
        "host_id": target.host_id,
        "label": target.label,
        "hostname": target.hostname,
        "port": target.port,
        "username": target.username,
        "address": address,
        "instructions": instructions,
        "native_clients": ["mstsc", "Microsoft Remote Desktop", "FreeRDP"],
    }


def create_session(*, user_sub: str, target_id: str, user_role: str = "user") -> dict[str, Any]:
    """Reserved native-phase session bootstrap (mirrors `vnc_sessions.create_session`).

    In Phase 1 the master gate is off by default, so this raises 503
    RDP_FEATURE_DISABLED before any work. The body is intentionally a thin
    stub: when Option A (Guacamole gateway) lands, the resolution + token mint
    drops in here behind the same gate, and the FE/contract stays unchanged.
    """
    _ensure_rdp_feature_enabled()
    # Even with the flag on, Phase 1 ships no native bridge. Resolve the target
    # owner-scoped (so the contract + ownership check are exercised) and report
    # that the native gateway is not yet wired. The future Option-A build
    # replaces this with a real token mint + gateway ws_url.
    _resolve_fallback_target(user_sub=user_sub, host_id=_host_id_from_target(target_id))
    raise RdpSessionError(
        http_status=501,
        code="RDP_NATIVE_NOT_IMPLEMENTED",
        message="native RDP gateway is not yet implemented; use the fallback connection details",
        details={"target_id": target_id},
    )


def _host_id_from_target(target_id: str) -> str:
    target_id = (target_id or "").strip()
    if target_id.startswith("user:"):
        return target_id.split(":", 1)[1].strip()
    return target_id
