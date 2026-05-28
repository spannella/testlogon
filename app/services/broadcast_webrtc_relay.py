"""WebRTC-to-RTMP relay for browser-based broadcast guests (BCAST-016).

In dev mode: returns mock SDP answers and tracks relay state in memory.
In production: would start FFmpeg processes (not implemented yet).
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from app.core.settings import S

logger = logging.getLogger("broadcast.webrtc_relay")

_ACTIVE_RELAYS: Dict[tuple[str, str], Any] = {}


def start_relay(
    *,
    session_id: str,
    input_id: str,
    rtmp_target_url: str,
    sdp_offer: str,
) -> dict:
    """Start a WebRTC-to-RTMP relay. Returns mock SDP answer in dev mode."""
    key = (session_id, input_id)
    if key in _ACTIVE_RELAYS:
        return {"status": "already_running", "session_id": session_id, "input_id": input_id}

    _ACTIVE_RELAYS[key] = {"mock": True, "session_id": session_id, "input_id": input_id}
    return {
        "status": "started",
        "sdp_answer": "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=mock\r\nt=0 0\r\n",
        "session_id": session_id,
        "input_id": input_id,
    }


def stop_relay(session_id: str, input_id: str) -> dict:
    key = (session_id, input_id)
    relay = _ACTIVE_RELAYS.pop(key, None)
    if not relay:
        return {"status": "not_found"}
    return {"status": "stopped", "session_id": session_id, "input_id": input_id}


def stop_all_relays_for_session(session_id: str) -> int:
    keys_to_stop = [k for k in _ACTIVE_RELAYS if k[0] == session_id]
    for key in keys_to_stop:
        stop_relay(key[0], key[1])
    return len(keys_to_stop)


def get_relay_status(session_id: str, input_id: str) -> dict | None:
    key = (session_id, input_id)
    relay = _ACTIVE_RELAYS.get(key)
    if not relay:
        return None
    return {"status": "running", "session_id": session_id, "input_id": input_id}
