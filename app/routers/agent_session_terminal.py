"""Interactive Claude Code agent-session WebSocket terminal (ACS-004..008).

A dedicated WebSocket endpoint, peer to (and SEPARATE from) the raw Browser SSH
``/api/browser-ssh/ws`` endpoint, so agent sessions are never conflated with raw
SSH connect payloads. The raw SSH handler is left byte-for-byte unchanged; this
router only *reuses* its security-relevant helpers (auth, rate-limit, session
slots, redaction) and the terminal_monitor tap.

The whole feature is gated behind ``S.agent_claude_code_session_enabled``
(default OFF). With the flag off the endpoint refuses every connect before any
bridge is built.

Protocol v1 envelope ``{type, payload}`` is reused, but the connect payload is
``{worker_id, session_id?, cols, rows}`` — NO host/port/auth/key fields. A
raw-SSH-shaped payload (host/port/authType) is rejected with a structured error.

Key differences from raw SSH (ADR-002 drivers #4/#5):
  * The PTY bridge is held in a process-local registry keyed by ``session_id``;
    detaching (WS close) does NOT close the bridge, so a user can reattach.
  * Reattach re-binds the live bridge and replays a bounded scrollback from the
    monitor ring buffer.
  * Browser ``input`` drives the live ``claude`` PTY (the one-way → two-way
    change) AND output is still tapped into ``terminal_monitor`` so signal
    detection / feedback creation works with or without a viewer.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
import uuid
from typing import Any, Dict, Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.core.settings import S
from app.services import agent_session_manager as sessions_mgr
from app.services import terminal_monitor
from app.services.agent_worker_provisioner import get_worker_raw
from app.services.alerts import audit_event
from app.services.claude_code_pty_bridge import (
    ClaudeBridgeError,
    build_claude_code_bridge,
)

# Reuse the SSH terminal's audited security helpers verbatim — shared abuse
# limits and the same authorization path. Importing (not copying) keeps a single
# source of truth and avoids drift.
from app.routers.browser_ssh_terminal import (
    _authorize_terminal_access,
    _consume_connect_rate_limit,
    _error_payload,
    _release_user_session_slot,
    _try_acquire_user_session_slot,
)

router = APIRouter(prefix="/api/agent-session", tags=["agent-session-terminal"])
logger = logging.getLogger(__name__)


# Process-local registry of live PTY bridges, keyed by session_id. Analogous to
# browser_ssh_terminal._ACTIVE_SSH_SESSIONS_BY_USER — single-worker uvicorn only
# (CLAUDE.md: --workers 1). A backend restart drops live PTYs; reattach restarts
# the CLI, which is acceptable per the ADR.
_LIVE_BRIDGES: Dict[str, Any] = {}
# Parallel metadata (session_id -> {user_id, worker_id}) so the idle reaper can
# resolve a live bridge's owning session record (PK is USER#{user_id}) without
# changing the _LIVE_BRIDGES value shape that the WS handler + tests rely on.
_BRIDGE_META: Dict[str, Dict[str, str]] = {}
_REGISTRY_LOCK = threading.Lock()


def agent_claude_code_session_enabled() -> bool:
    return bool(getattr(S, "agent_claude_code_session_enabled", False))


def _replay_bytes() -> int:
    try:
        return max(0, int(getattr(S, "agent_claude_code_session_replay_bytes", 65536)))
    except (TypeError, ValueError):
        return 65536


def _register_bridge(
    session_id: str,
    bridge: Any,
    *,
    user_id: str = "",
    worker_id: str = "",
) -> None:
    with _REGISTRY_LOCK:
        _LIVE_BRIDGES[session_id] = bridge
        _BRIDGE_META[session_id] = {"user_id": user_id, "worker_id": worker_id}


def _get_bridge(session_id: str) -> Optional[Any]:
    with _REGISTRY_LOCK:
        return _LIVE_BRIDGES.get(session_id)


def _drop_bridge(session_id: str) -> Optional[Any]:
    with _REGISTRY_LOCK:
        _BRIDGE_META.pop(session_id, None)
        return _LIVE_BRIDGES.pop(session_id, None)


def stop_session_bridge(session_id: str) -> bool:
    """Close + drop a live bridge for a session (explicit stop / worker reap).

    Best-effort; returns True if a bridge was present. Used by the REST stop
    route and by worker stop/terminate hooks.
    """
    bridge = _drop_bridge(session_id)
    if bridge is None:
        return False
    try:
        bridge.close()
    except Exception:  # pragma: no cover - defensive
        logger.exception("agent_session bridge close failed session_id=%s", session_id)
    return True


def _idle_timeout_seconds() -> int:
    try:
        return max(0, int(getattr(S, "agent_claude_code_session_idle_timeout_seconds", 1800)))
    except (TypeError, ValueError):
        return 1800


def reap_idle_sessions(*, now: Optional[float] = None) -> int:
    """Close + end any live PTY bridge whose session has been idle/abandoned
    longer than ``AGENT_CLAUDE_CODE_SESSION_IDLE_TIMEOUT_SECONDS``.

    A *detached* session (the browser closed the WS) keeps its bridge alive in
    the process-local registry so the user can reattach (ADR-002 driver #4) —
    but a bridge with no viewer still consumes a PTY and LLM tokens. This reaper
    is the safety valve called out in the ADR "Consequences": it walks the live
    bridge registry, and for each bridge whose owning session record has not had
    activity within the idle window (or whose record is already terminal /
    missing), it closes the PTY (``stop_session_bridge``) and transitions the
    session to ``ended`` (``error``-tolerant). Returns the number of sessions
    reaped.

    Best-effort and never raises: a per-session failure is logged and skipped.
    A timeout of 0 disables reaping (treated as "never idle out").
    """
    timeout = _idle_timeout_seconds()
    if timeout <= 0:
        return 0
    now_s = float(now) if now is not None else time.time()
    with _REGISTRY_LOCK:
        snapshot = dict(_BRIDGE_META)
    reaped = 0
    for session_id, meta in snapshot.items():
        if session_id not in _LIVE_BRIDGES:
            continue
        user_id = meta.get("user_id", "")
        worker_id = meta.get("worker_id", "")
        try:
            sess = sessions_mgr.get_session(user_id, session_id) if user_id else None
        except Exception:  # pragma: no cover - defensive
            logger.exception("reap_idle_sessions lookup failed session_id=%s", session_id)
            continue
        # Orphaned bridge (record gone or already terminal): drop the PTY.
        if not sess or sess.get("state") in sessions_mgr.TERMINAL_STATES:
            stop_session_bridge(session_id)
            reaped += 1
            continue
        last_activity = int(sess.get("last_activity_at", 0) or 0)
        if last_activity and (now_s - last_activity) < timeout:
            continue
        # Idle/abandoned past the window — close the PTY and end the session.
        stop_session_bridge(session_id)
        try:
            sessions_mgr.end_session(user_id, session_id)
        except Exception:  # pragma: no cover - defensive
            logger.exception("reap_idle_sessions end failed session_id=%s", session_id)
        _audit(
            "agent_session_reaped",
            user_id,
            outcome="idle_timeout",
            session_id=session_id,
            worker_id=worker_id,
            idle_timeout_seconds=timeout,
        )
        logger.info(
            "agent_session reaped idle session_id=%s worker_id=%s (idle>%ds)",
            session_id, worker_id, timeout,
        )
        reaped += 1
    return reaped


async def run_idle_session_reaper(*, poll_interval: Optional[int] = None) -> None:
    """Background task: periodically reap idle/abandoned agent sessions.

    Gated by the master flag at registration time. The poll interval defaults to
    a fraction of the idle timeout (so a session is reaped within roughly one
    extra interval of going idle), bounded to a sane floor/ceiling.
    """
    if poll_interval is not None:
        interval = poll_interval
    else:
        interval = min(300, max(30, _idle_timeout_seconds() // 4 or 60))
    while True:
        try:
            reap_idle_sessions()
        except Exception:  # pragma: no cover - defensive
            logger.exception("agent_session idle reaper error")
        await asyncio.sleep(interval)


def start_agent_session_reaper_task() -> None:
    """Register the idle-session reaper at app startup (flag-gated)."""
    if agent_claude_code_session_enabled():
        asyncio.ensure_future(run_idle_session_reaper())
        logger.info(
            "Agent Claude Code session idle reaper started (idle_timeout=%ds)",
            _idle_timeout_seconds(),
        )


async def _dispatch_signal(
    *,
    signal: Dict[str, Any],
    worker_id: str,
    user_id: str,
    session_id: str,
    websocket: WebSocket,
) -> Optional[str]:
    """Map a monitor signal to a browser message AND a session-state transition.

    Mirrors browser_ssh_terminal._dispatch_terminal_signal for the browser
    surface, but additionally drives the session state machine (ACS-008):
    ``feedback_needed`` → ``awaiting_input``; ``completion`` → ``ended``;
    ``error`` → ``error``. Best-effort — never interrupts the stream.

    Returns the ``request_id`` of a newly created feedback request when the
    signal was ``feedback_needed`` (so the WS loop can later mark it responded
    when the user answers), else ``None``.
    """
    category = signal.get("signal")
    match_text = signal.get("match", "")
    detected_pattern = signal.get("pattern", "")
    buf = terminal_monitor.get_or_create_buffer(worker_id)
    context = buf.get_recent(2000)

    if category == "feedback_needed":
        request_id: Optional[str] = None
        try:
            req = terminal_monitor.create_feedback_request(
                user_id=user_id or "",
                worker_id=worker_id,
                ticket_id="",
                question=match_text,
                terminal_context=context,
                detected_pattern=detected_pattern,
            )
            request_id = req.get("request_id")
            await websocket.send_json(
                {
                    "type": "feedback_request",
                    "payload": {"request_id": request_id, "question": match_text},
                }
            )
        except Exception:  # pragma: no cover - defensive
            logger.exception("agent_session feedback dispatch failed worker_id=%s", worker_id)
        _safe_transition(user_id, session_id, sessions_mgr.STATE_AWAITING_INPUT)
        return request_id
    elif category == "completion":
        try:
            await websocket.send_json({"type": "agent_complete", "payload": {}})
        except Exception:  # pragma: no cover - defensive
            logger.exception("agent_session agent_complete failed worker_id=%s", worker_id)
        _safe_transition(user_id, session_id, sessions_mgr.STATE_ENDED)
    elif category == "error":
        try:
            await websocket.send_json({"type": "agent_error", "payload": {"match": match_text}})
        except Exception:  # pragma: no cover - defensive
            logger.exception("agent_session agent_error failed worker_id=%s", worker_id)
        _safe_transition(user_id, session_id, sessions_mgr.STATE_ERROR, error_message=match_text)
    return None


def _safe_transition(
    user_id: str,
    session_id: str,
    new_state: str,
    *,
    error_message: str = "",
) -> None:
    """Transition without ever raising — illegal/terminal transitions are a
    no-op so a state nudge from the loop never crashes the live terminal.
    """
    try:
        sessions_mgr.transition_state(
            user_id, session_id, new_state, error_message=error_message
        )
    except ValueError:
        pass
    except Exception:  # pragma: no cover - defensive
        logger.exception("agent_session transition failed session_id=%s", session_id)


def _audit(event: str, user_sub: str, **fields: Any) -> None:
    try:
        audit_event(event, user_sub, None, **fields)
    except Exception:  # pragma: no cover - defensive
        logger.exception("agent_session audit failed event=%s", event)


@router.get("/config")
def agent_session_config() -> Dict[str, Any]:
    return {
        "enabled": agent_claude_code_session_enabled(),
        "ws_path": "/api/agent-session/ws",
        "protocol_version": "v1",
        "connect_payload": ["worker_id", "session_id?", "cols", "rows"],
    }


@router.websocket("/ws")
async def agent_session_ws(websocket: WebSocket) -> None:
    ws_id = uuid.uuid4().hex[:12]
    await websocket.accept()

    if not agent_claude_code_session_enabled():
        await websocket.send_json(
            {
                "type": "error",
                "payload": _error_payload(
                    code="feature_disabled",
                    message="Agent Claude Code sessions are not enabled.",
                    request_type="connect",
                ),
            }
        )
        await websocket.close(code=4404)
        return

    auth_ctx, auth_err = await _authorize_terminal_access(websocket)
    if auth_err:
        await websocket.send_json({"type": "error", "payload": auth_err})
        await websocket.close(code=4403)
        return

    user_sub = str(auth_ctx.get("user_sub") or "")
    bridge: Any | None = None
    session_id: str | None = None
    worker_id: str | None = None
    slot_acquired = False
    attached_existing = False  # reattach to an already-live bridge (no new slot)
    started_at = time.time()
    # Most-recent pending feedback request_id for this session (ACS-005). When
    # the user's next input answers it we mark it responded via the monitor's
    # no-buffer-reinject helper so the feedback CRUD view stays consistent
    # without double-injecting the answer into the ring buffer.
    pending_feedback_id: str | None = None

    await websocket.send_json(
        {
            "type": "status",
            "payload": {
                "phase": "ready",
                "connected": False,
                "message": f"Agent session gateway ready (protocol v1) for {user_sub}.",
            },
        }
    )

    try:
        while True:
            # Pump bridge output -> browser + monitor tap (the two-way wiring).
            if bridge is not None and session_id and worker_id:
                output = bridge.poll_output()
                if output:
                    await websocket.send_json({"type": "output", "payload": {"data": output}})
                    # Tap the SAME output into terminal_monitor BEFORE/independent
                    # of any signal so detection works whether or not a human is
                    # watching (preserves the existing monitor pipeline).
                    try:
                        signal = terminal_monitor.process_terminal_output(worker_id, output)
                    except Exception:  # pragma: no cover - defensive
                        signal = None
                    # Only ACT on a signal whose match is in THIS fresh chunk.
                    # process_terminal_output matches against the whole ring
                    # buffer (shared with the SSH path), so a stale feedback line
                    # buffered from earlier output would otherwise re-fire on
                    # every poll and clobber the state the user just advanced.
                    # The monitor tap above still sees the full output regardless.
                    if signal and str(signal.get("match", "")) and str(signal["match"]) in output:
                        new_fb = await _dispatch_signal(
                            signal=signal,
                            worker_id=worker_id,
                            user_id=user_sub,
                            session_id=session_id,
                            websocket=websocket,
                        )
                        if new_fb:
                            pending_feedback_id = new_fb

            try:
                raw = await asyncio.wait_for(websocket.receive_text(), timeout=0.05)
            except asyncio.TimeoutError:
                continue

            try:
                envelope = json.loads(raw)
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
                if bridge is not None:
                    # Already connected on this WS — ignore re-connect.
                    continue
                if not isinstance(payload, dict):
                    await websocket.send_json(
                        {
                            "type": "error",
                            "payload": _error_payload(
                                code="invalid_payload",
                                message="connect payload must be an object",
                                request_type="connect",
                            ),
                        }
                    )
                    continue
                # Reject raw-SSH-shaped payloads explicitly — agent sessions
                # carry worker_id only, never host/port/auth.
                if any(k in payload for k in ("host", "port", "authType", "privateKey", "password")):
                    await websocket.send_json(
                        {
                            "type": "error",
                            "payload": _error_payload(
                                code="invalid_payload",
                                message="agent session connect takes worker_id only (no host/port/auth)",
                                request_type="connect",
                            ),
                        }
                    )
                    continue

                req_worker_id = payload.get("worker_id")
                if not isinstance(req_worker_id, str) or not req_worker_id.strip():
                    await websocket.send_json(
                        {
                            "type": "error",
                            "payload": _error_payload(
                                code="invalid_worker_id",
                                message="worker_id is required",
                                request_type="connect",
                            ),
                        }
                    )
                    continue
                req_worker_id = req_worker_id.strip()
                req_session_id = payload.get("session_id")
                req_session_id = req_session_id.strip() if isinstance(req_session_id, str) else None
                cols = payload.get("cols") if isinstance(payload.get("cols"), int) else 80
                rows = payload.get("rows") if isinstance(payload.get("rows"), int) else 24

                # Ownership: the worker PK is USER#{user_sub}; an unknown/foreign
                # worker yields not_found before any bridge is built.
                worker = get_worker_raw(user_sub, req_worker_id)
                if not worker:
                    await websocket.send_json(
                        {
                            "type": "error",
                            "payload": _error_payload(
                                code="worker_not_found",
                                message="Worker not found or access denied.",
                                request_type="connect",
                            ),
                        }
                    )
                    continue

                now = time.time()
                if not _consume_connect_rate_limit(user_sub, now):
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

                # Reattach path: an existing session_id with a live bridge in the
                # registry re-binds without consuming a new session slot, and
                # replays a bounded scrollback so the terminal repaints.
                if req_session_id:
                    existing = sessions_mgr.get_session(user_sub, req_session_id)
                    if not existing or existing.get("worker_id") != req_worker_id:
                        await websocket.send_json(
                            {
                                "type": "error",
                                "payload": _error_payload(
                                    code="session_not_found",
                                    message="Session not found or access denied.",
                                    request_type="connect",
                                ),
                            }
                        )
                        continue
                    if existing.get("state") in sessions_mgr.TERMINAL_STATES:
                        await websocket.send_json(
                            {
                                "type": "error",
                                "payload": _error_payload(
                                    code="session_ended",
                                    message="Session has already ended.",
                                    request_type="connect",
                                ),
                            }
                        )
                        continue
                    live = _get_bridge(req_session_id)
                    if live is not None:
                        bridge = live
                        session_id = req_session_id
                        worker_id = req_worker_id
                        attached_existing = True
                        _audit(
                            "agent_session_attach",
                            user_sub,
                            outcome="success",
                            session_id=session_id,
                            worker_id=worker_id,
                        )
                        # Replay bounded scrollback from the monitor ring buffer.
                        replay = terminal_monitor.get_or_create_buffer(worker_id).get_recent(
                            _replay_bytes()
                        )
                        if replay:
                            await websocket.send_json(
                                {"type": "output", "payload": {"data": replay}}
                            )
                        await websocket.send_json(
                            {
                                "type": "status",
                                "payload": {
                                    "phase": "connected",
                                    "connected": True,
                                    "message": f"Reattached to session {session_id}.",
                                    "session_id": session_id,
                                    "state": existing.get("state"),
                                },
                            }
                        )
                        continue
                    # No live bridge (e.g. after restart) — fall through and start
                    # a fresh bridge bound to the existing session record.
                    session_id = req_session_id

                # Fresh start: acquire a per-user session slot.
                if not _try_acquire_user_session_slot(user_sub):
                    await websocket.send_json(
                        {
                            "type": "error",
                            "payload": _error_payload(
                                code="session_limit_exceeded",
                                message="Maximum concurrent agent sessions reached.",
                                request_type="connect",
                            ),
                        }
                    )
                    continue
                slot_acquired = True

                # Create the session record if this isn't a restart-rebind.
                if session_id is None:
                    try:
                        sess = sessions_mgr.create_session(
                            user_id=user_sub,
                            worker_id=req_worker_id,
                            cols=cols,
                            rows=rows,
                        )
                    except sessions_mgr.SessionError as exc:
                        if slot_acquired:
                            _release_user_session_slot(user_sub)
                            slot_acquired = False
                        await websocket.send_json(
                            {
                                "type": "error",
                                "payload": _error_payload(
                                    code="session_create_failed",
                                    message=str(exc),
                                    request_type="connect",
                                ),
                            }
                        )
                        continue
                    session_id = sess["session_id"]
                worker_id = req_worker_id

                # Build + connect the PTY bridge (the single dev/prod fork point).
                try:
                    bridge = build_claude_code_bridge(
                        user_id=user_sub, worker=worker, cols=cols, rows=rows
                    )
                    bridge.connect()
                except ClaudeBridgeError as exc:
                    _safe_transition(
                        user_sub, session_id, sessions_mgr.STATE_ERROR, error_message=exc.code
                    )
                    if slot_acquired:
                        _release_user_session_slot(user_sub)
                        slot_acquired = False
                    await websocket.send_json(
                        {
                            "type": "error",
                            "payload": _error_payload(
                                code=exc.code, message=exc.message, request_type="connect"
                            ),
                        }
                    )
                    bridge = None
                    continue

                _register_bridge(
                    session_id, bridge, user_id=user_sub, worker_id=worker_id
                )
                _safe_transition(user_sub, session_id, sessions_mgr.STATE_READY)
                _audit(
                    "agent_session_start",
                    user_sub,
                    outcome="success",
                    session_id=session_id,
                    worker_id=worker_id,
                )
                await websocket.send_json(
                    {
                        "type": "status",
                        "payload": {
                            "phase": "connected",
                            "connected": True,
                            "message": f"Claude Code session {session_id} is ready.",
                            "session_id": session_id,
                            "state": sessions_mgr.STATE_READY,
                        },
                    }
                )
                continue

            if msg_type == "input":
                if bridge is None or not session_id or not worker_id:
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
                # The one-way -> two-way change: browser input drives the live
                # Claude PTY (the same send_input call the raw SSH path makes).
                try:
                    bridge.send_input(payload["data"])
                except ClaudeBridgeError as exc:
                    await websocket.send_json(
                        {
                            "type": "error",
                            "payload": _error_payload(
                                code=exc.code, message=exc.message, request_type="input"
                            ),
                        }
                    )
                    continue
                # If this input answers a pending feedback request, flip that
                # request to "responded" via the monitor's no-buffer-reinject
                # helper. The answer is ALREADY tapped into the ring buffer via
                # the PTY echo on the next poll, so we must NOT call the
                # buffer-appending respond_to_feedback here (that would
                # double-inject the same answer and skew pattern matching).
                if pending_feedback_id:
                    try:
                        terminal_monitor.mark_feedback_responded(
                            worker_id, pending_feedback_id, payload["data"]
                        )
                    except Exception:  # pragma: no cover - defensive
                        logger.exception(
                            "agent_session mark_feedback_responded failed session_id=%s",
                            session_id,
                        )
                    pending_feedback_id = None
                # Submitting input clears awaiting_input back to running so the UI
                # badge updates promptly (ACS-008).
                _safe_transition(user_sub, session_id, sessions_mgr.STATE_RUNNING)
                continue

            if msg_type == "resize":
                if bridge is None:
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
                try:
                    bridge.resize(cols, rows)
                except ClaudeBridgeError:
                    pass
                continue

            if msg_type == "stop":
                # Explicit stop terminates the CLI + bridge -> ended.
                if session_id:
                    stop_session_bridge(session_id)
                    _safe_transition(user_sub, session_id, sessions_mgr.STATE_ENDED)
                    _audit(
                        "agent_session_stop",
                        user_sub,
                        outcome="success",
                        session_id=session_id,
                        worker_id=worker_id or "",
                    )
                    await websocket.send_json(
                        {
                            "type": "status",
                            "payload": {
                                "phase": "ended",
                                "connected": False,
                                "message": "Session stopped.",
                                "session_id": session_id,
                                "state": sessions_mgr.STATE_ENDED,
                            },
                        }
                    )
                bridge = None
                break

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
        pass
    finally:
        # DETACH semantics (ADR-002 driver #4): closing the WS must NOT kill the
        # live bridge — leave it in the registry so the user can reattach. We
        # only release the per-user session slot. The bridge is closed by an
        # explicit stop, a worker reap, or the idle reaper.
        if slot_acquired:
            _release_user_session_slot(user_sub)
        if session_id and not attached_existing:
            _audit(
                "agent_session_detach",
                user_sub,
                outcome="disconnected",
                session_id=session_id,
                worker_id=worker_id or "",
                duration_seconds=round(time.time() - started_at, 3),
            )
