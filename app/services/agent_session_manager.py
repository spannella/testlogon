"""Interactive Claude Code Session manager (ACS-002 / ADR-002).

A "Claude Code session" is one interactive ``claude`` PTY attached to an agent
worker (AGENT-002). A worker is durable compute + an installed CLI tool + an LLM
key; a session is a single live, human-drivable terminal process on top of it.

This module owns the session *record* and its *state machine*; the live PTY
bridge (ACS-003) and the WebSocket loop (ACS-004/005/006) live elsewhere. The
DDB layout mirrors the worker table so ownership is structural:

    PK  pk = USER#{user_id}
    SK  sk = SESSION#{session_id}
    GSI ByWorker (worker_id, created_at)   # list_sessions_for_worker

State machine (ADR-002):

    starting -> ready -> awaiting_input <-> running -> ended
                                       (any) -> error

``ended`` and ``error`` are terminal. Illegal transitions raise ``ValueError``
the same way ``agent_worker_provisioner.stop_worker`` rejects bad states.
"""

from __future__ import annotations

import logging
from decimal import Decimal
from typing import Any, Dict, List, Optional
from uuid import uuid4

from app.core.tables import T
from app.core.time import now_ts
from app.services.agent_worker_provisioner import get_worker_raw

logger = logging.getLogger(__name__)


# --- State machine ---------------------------------------------------------

STATE_STARTING = "starting"
STATE_READY = "ready"
STATE_AWAITING_INPUT = "awaiting_input"
STATE_RUNNING = "running"
STATE_ENDED = "ended"
STATE_ERROR = "error"

VALID_STATES = {
    STATE_STARTING,
    STATE_READY,
    STATE_AWAITING_INPUT,
    STATE_RUNNING,
    STATE_ENDED,
    STATE_ERROR,
}

TERMINAL_STATES = {STATE_ENDED, STATE_ERROR}

# Every non-terminal state can transition to ended/error (stop / failure).
_ALLOWED_TRANSITIONS: Dict[str, set] = {
    STATE_STARTING: {STATE_READY, STATE_ENDED, STATE_ERROR},
    STATE_READY: {STATE_RUNNING, STATE_AWAITING_INPUT, STATE_ENDED, STATE_ERROR},
    STATE_RUNNING: {STATE_AWAITING_INPUT, STATE_READY, STATE_ENDED, STATE_ERROR},
    STATE_AWAITING_INPUT: {STATE_RUNNING, STATE_READY, STATE_ENDED, STATE_ERROR},
    STATE_ENDED: set(),
    STATE_ERROR: set(),
}

# Worker states that may host a new interactive session.
_WORKER_SESSIONABLE_STATES = {"ready", "running"}


class SessionError(Exception):
    """Typed error for session lifecycle problems (worker missing / bad state)."""


# --- Helpers ---------------------------------------------------------------


def _item_to_session(item: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a DDB item to a clean session dict, coercing Decimals.

    Mirrors ``agent_worker_provisioner._item_to_worker``.
    """
    out: Dict[str, Any] = {}
    for k, v in item.items():
        if k in ("pk", "sk"):
            continue
        if isinstance(v, Decimal):
            out[k] = int(v)
        else:
            out[k] = v
    return out


def _pk(user_id: str) -> str:
    return f"USER#{user_id}"


def _sk(session_id: str) -> str:
    return f"SESSION#{session_id}"


# --- CRUD + lifecycle ------------------------------------------------------


def create_session(
    *,
    user_id: str,
    worker_id: str,
    cols: int = 80,
    rows: int = 24,
) -> Dict[str, Any]:
    """Create a new interactive session record for ``worker_id``.

    The worker must exist (owned by ``user_id`` — PK is ``USER#{user_id}``) and
    be in a sessionable state (``ready``/``running``). A foreign or unknown
    worker raises ``SessionError`` (the caller maps this to 404/403).

    The session starts in ``starting``; the WS connect handler transitions it to
    ``ready`` once the PTY bridge is live.
    """
    worker = get_worker_raw(user_id, worker_id)
    if not worker:
        raise SessionError("Worker not found")
    status = worker.get("worker_status")
    if status not in _WORKER_SESSIONABLE_STATES:
        raise SessionError(
            f"Cannot open a session against worker in state: {status}"
        )

    session_id = f"acs_{uuid4().hex}"
    ts = now_ts()
    item: Dict[str, Any] = {
        "pk": _pk(user_id),
        "sk": _sk(session_id),
        "session_id": session_id,
        "worker_id": worker_id,
        "user_id": user_id,
        "state": STATE_STARTING,
        "created_at": ts,
        "started_at": 0,
        "ended_at": 0,
        "last_activity_at": ts,
        "cols": int(cols) if cols else 80,
        "rows": int(rows) if rows else 24,
        "claude_pid": 0,
        "error_message": "",
    }
    T.agent_sessions.put_item(Item=item)
    logger.info(
        "agent_session.created session_id=%s worker_id=%s user_id=%s",
        session_id, worker_id, user_id,
    )
    return _item_to_session(item)


def get_session(user_id: str, session_id: str) -> Optional[Dict[str, Any]]:
    """Get a single session by ID (cleaned), scoped to its owner."""
    resp = T.agent_sessions.get_item(
        Key={"pk": _pk(user_id), "sk": _sk(session_id)}
    )
    item = resp.get("Item")
    return _item_to_session(item) if item else None


def list_sessions_for_worker(user_id: str, worker_id: str) -> List[Dict[str, Any]]:
    """List a worker's sessions newest-first via the ByWorker GSI.

    The GSI is partitioned by ``worker_id`` with a numeric ``created_at`` sort
    key; ``ScanIndexForward=False`` yields newest-first. Results are filtered to
    the requesting owner defensively (the GSI projects the owner ``user_id``).
    """
    resp = T.agent_sessions.query(
        IndexName="ByWorker",
        KeyConditionExpression="worker_id = :wid",
        ExpressionAttributeValues={":wid": worker_id},
        ScanIndexForward=False,
    )
    out: List[Dict[str, Any]] = []
    for item in resp.get("Items", []):
        if item.get("user_id") and item.get("user_id") != user_id:
            continue
        out.append(_item_to_session(item))
    return out


def transition_state(
    user_id: str,
    session_id: str,
    new_state: str,
    *,
    error_message: str = "",
    claude_pid: Optional[int] = None,
) -> Dict[str, Any]:
    """Transition a session to ``new_state``, enforcing the state machine.

    Illegal transitions raise ``ValueError`` (mirrors
    ``agent_worker_provisioner.stop_worker``). A no-op transition to the current
    state is allowed and idempotent. Touches ``last_activity_at`` and stamps
    ``started_at``/``ended_at`` on the relevant edges.
    """
    if new_state not in VALID_STATES:
        raise ValueError(f"Unknown session state: {new_state}")

    resp = T.agent_sessions.get_item(
        Key={"pk": _pk(user_id), "sk": _sk(session_id)}
    )
    item = resp.get("Item")
    if not item:
        raise SessionError("Session not found")
    current = item.get("state")

    if current == new_state:
        # Idempotent: still refresh activity (e.g. running -> running on input).
        ts = now_ts()
        T.agent_sessions.update_item(
            Key={"pk": _pk(user_id), "sk": _sk(session_id)},
            UpdateExpression="SET last_activity_at = :ts",
            ExpressionAttributeValues={":ts": ts},
        )
        return get_session(user_id, session_id)  # type: ignore[return-value]

    allowed = _ALLOWED_TRANSITIONS.get(current, set())
    if new_state not in allowed:
        raise ValueError(
            f"Cannot transition session from {current} to {new_state}"
        )

    ts = now_ts()
    set_parts = ["#st = :st", "last_activity_at = :ts"]
    values: Dict[str, Any] = {":st": new_state, ":ts": ts}
    names = {"#st": "state"}

    if new_state == STATE_READY and not int(item.get("started_at", 0) or 0):
        set_parts.append("started_at = :sa")
        values[":sa"] = ts
    if new_state in TERMINAL_STATES:
        set_parts.append("ended_at = :ea")
        values[":ea"] = ts
    if error_message:
        set_parts.append("error_message = :em")
        values[":em"] = error_message
    if claude_pid is not None:
        set_parts.append("claude_pid = :pid")
        values[":pid"] = int(claude_pid)

    T.agent_sessions.update_item(
        Key={"pk": _pk(user_id), "sk": _sk(session_id)},
        UpdateExpression="SET " + ", ".join(set_parts),
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
    )
    logger.info(
        "agent_session.transition session_id=%s %s -> %s",
        session_id, current, new_state,
    )
    return get_session(user_id, session_id)  # type: ignore[return-value]


def end_session(
    user_id: str,
    session_id: str,
    *,
    error: str = "",
) -> Optional[Dict[str, Any]]:
    """End a session (stop). Idempotent on an already-terminal session.

    Transitions to ``error`` when ``error`` is supplied, else ``ended``.
    Returns the session dict, or ``None`` if it doesn't exist.
    """
    existing = get_session(user_id, session_id)
    if not existing:
        return None
    if existing.get("state") in TERMINAL_STATES:
        return existing
    target = STATE_ERROR if error else STATE_ENDED
    return transition_state(user_id, session_id, target, error_message=error)


def end_sessions_for_worker(user_id: str, worker_id: str) -> int:
    """End all live sessions for a worker (called when a worker is stopped or
    terminated). Returns the count of sessions ended. Best-effort per session.
    """
    ended = 0
    for sess in list_sessions_for_worker(user_id, worker_id):
        if sess.get("state") in TERMINAL_STATES:
            continue
        try:
            end_session(user_id, sess["session_id"])
            ended += 1
        except Exception:  # pragma: no cover - defensive
            logger.exception(
                "agent_session.end_for_worker failed session_id=%s",
                sess.get("session_id"),
            )
    return ended
