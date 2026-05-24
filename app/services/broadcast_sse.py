"""In-memory pub/sub for broadcast session real-time events."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, Set

_BROADCAST_SUBSCRIBERS: Dict[str, Set[asyncio.Queue]] = {}


def broadcast_sse_subscribe(session_id: str) -> asyncio.Queue:
    """Subscribe to real-time events for a broadcast session."""
    q: asyncio.Queue = asyncio.Queue(maxsize=100)
    subs = _BROADCAST_SUBSCRIBERS.setdefault(session_id, set())
    subs.add(q)
    return q


def broadcast_sse_unsubscribe(session_id: str, q: asyncio.Queue) -> None:
    """Unsubscribe from a broadcast session's event stream."""
    subs = _BROADCAST_SUBSCRIBERS.get(session_id)
    if not subs:
        return
    subs.discard(q)
    if not subs:
        _BROADCAST_SUBSCRIBERS.pop(session_id, None)


def broadcast_sse_publish(session_id: str, event: Dict[str, Any]) -> None:
    """Publish an event to all subscribers of a broadcast session."""
    subs = _BROADCAST_SUBSCRIBERS.get(session_id)
    if not subs:
        return
    dead = []
    for q in list(subs):
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            dead.append(q)
    for q in dead:
        subs.discard(q)
        if not subs:
            _BROADCAST_SUBSCRIBERS.pop(session_id, None)


def broadcast_sse_subscriber_count(session_id: str) -> int:
    """Return number of active SSE subscribers for a session."""
    subs = _BROADCAST_SUBSCRIBERS.get(session_id)
    return len(subs) if subs else 0
