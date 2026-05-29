"""In-memory pub/sub for creator dashboard real-time events."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, Set

_DASHBOARD_SUBSCRIBERS: Dict[str, Set[asyncio.Queue]] = {}


def dashboard_sse_subscribe(user_id: str) -> asyncio.Queue:
    """Subscribe to real-time events for a user's dashboard.

    Max 1 connection per user: new subscribe replaces the old queue.
    """
    q: asyncio.Queue = asyncio.Queue(maxsize=100)
    subs = _DASHBOARD_SUBSCRIBERS.setdefault(user_id, set())
    # Evict old queues to enforce max-1 policy
    for old_q in list(subs):
        try:
            old_q.put_nowait({"type": "replaced"})
        except asyncio.QueueFull:
            pass
    subs.clear()
    subs.add(q)
    return q


def dashboard_sse_unsubscribe(user_id: str, q: asyncio.Queue) -> None:
    """Unsubscribe from a user's dashboard event stream."""
    subs = _DASHBOARD_SUBSCRIBERS.get(user_id)
    if not subs:
        return
    subs.discard(q)
    if not subs:
        _DASHBOARD_SUBSCRIBERS.pop(user_id, None)


def dashboard_sse_publish(user_id: str, event: Dict[str, Any]) -> None:
    """Publish an event to all subscribers of a user's dashboard stream."""
    subs = _DASHBOARD_SUBSCRIBERS.get(user_id)
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
            _DASHBOARD_SUBSCRIBERS.pop(user_id, None)
