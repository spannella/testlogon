from __future__ import annotations

import logging
import threading
import time
from typing import Any

logger = logging.getLogger("app.vnc.bridge")

class BridgeLifecycleError(Exception):
    def __init__(self, *, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class BridgeLifecycleManager:
    def __init__(self, *, idle_timeout_seconds: int = 300, max_duration_seconds: int = 3600) -> None:
        self._lock = threading.Lock()
        self._idle_timeout_seconds = max(30, idle_timeout_seconds)
        self._max_duration_seconds = max(60, max_duration_seconds)
        self._states: dict[str, dict[str, Any]] = {}

    def _log(self, event: str, **fields: Any) -> None:
        logger.info("vnc_bridge_lifecycle", extra={"event": event, **fields})

    def start_creating(self, *, session_id: str, user_sub: str, target_id: str) -> None:
        now = int(time.time())
        with self._lock:
            self._states[session_id] = {
                "session_id": session_id,
                "user_sub": user_sub,
                "target_id": target_id,
                "state": "creating",
                "created_at": now,
                "last_activity_at": now,
                "closed_at": None,
                "failure_code": None,
            }
        self._log("state_transition", session_id=session_id, from_state=None, to_state="creating", target_id=target_id)

    def mark_active(self, *, session_id: str) -> None:
        with self._lock:
            current = self._states.get(session_id)
            if not current:
                return
            from_state = current.get("state")
            current["state"] = "active"
            current["last_activity_at"] = int(time.time())
        self._log("state_transition", session_id=session_id, from_state=from_state, to_state="active")

    def mark_failed(self, *, session_id: str, failure_code: str) -> None:
        with self._lock:
            current = self._states.get(session_id)
            if not current:
                return
            from_state = current.get("state")
            now = int(time.time())
            current["state"] = "failed"
            current["failure_code"] = failure_code
            current["closed_at"] = now
            current["last_activity_at"] = now
        self._log("state_transition", session_id=session_id, from_state=from_state, to_state="failed", failure_code=failure_code)

    def close(self, *, session_id: str, reason: str) -> dict[str, Any] | None:
        with self._lock:
            current = self._states.get(session_id)
            if not current:
                return None
            from_state = current.get("state")
            now = int(time.time())
            if from_state in {"closed", "failed"}:
                return dict(current)
            current["state"] = "closing"
            current["last_activity_at"] = now
            closing_snapshot = dict(current)
            current["state"] = "closed"
            current["closed_at"] = now
            current["close_reason"] = reason
            current["last_activity_at"] = now
            closed_snapshot = dict(current)
        self._log("state_transition", session_id=session_id, from_state=from_state, to_state="closing", reason=reason)
        self._log("state_transition", session_id=session_id, from_state="closing", to_state="closed", reason=reason)
        return closed_snapshot | {"_closing": closing_snapshot}

    def touch(self, *, session_id: str) -> None:
        with self._lock:
            current = self._states.get(session_id)
            if not current:
                return
            current["last_activity_at"] = int(time.time())

    def get(self, session_id: str) -> dict[str, Any] | None:
        with self._lock:
            current = self._states.get(session_id)
            return dict(current) if current else None

    def cleanup_expired(self) -> list[str]:
        now = int(time.time())
        expired_ids: list[str] = []
        with self._lock:
            for session_id, session in list(self._states.items()):
                state = session.get("state")
                if state not in {"creating", "active", "closing"}:
                    continue
                created_at = int(session.get("created_at") or now)
                last_activity_at = int(session.get("last_activity_at") or now)
                timed_out = (now - last_activity_at) >= self._idle_timeout_seconds
                maxed = (now - created_at) >= self._max_duration_seconds
                if timed_out or maxed:
                    session["state"] = "closed"
                    session["closed_at"] = now
                    session["close_reason"] = "idle_timeout" if timed_out else "max_duration"
                    session["last_activity_at"] = now
                    expired_ids.append(session_id)
        for sid in expired_ids:
            self._log("cleanup", session_id=sid, action="close", reason="timeout_or_max_duration")
        return expired_ids

    def handle_bridge_crash(self, *, session_id: str) -> dict[str, Any] | None:
        closed = self.close(session_id=session_id, reason="process_crash")
        if closed:
            self._log("cleanup", session_id=session_id, action="close", reason="process_crash")
        return closed

    def validate_target_ws_url(self, *, ws_url: str) -> None:
        if not ws_url or not (ws_url.startswith("ws://") or ws_url.startswith("wss://")):
            raise BridgeLifecycleError(code="VNC_TARGET_UNREACHABLE", message="bridge cannot reach target endpoint")

