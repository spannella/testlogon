"""Watch-party SSE wrappers — namespaced over broadcast_sse (GAP-0166).

Watch parties previously published/subscribed against the shared
``_BROADCAST_SUBSCRIBERS`` dict in ``broadcast_sse`` using the raw ``party_id``,
which shares a flat namespace with broadcast ``session_id`` keys. These thin
wrappers prefix every key with ``"wp:"`` so watch-party events can never bleed
into broadcast-session SSE streams (and vice versa).
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict

from app.services.broadcast_sse import (
    broadcast_sse_publish,
    broadcast_sse_subscribe,
    broadcast_sse_unsubscribe,
)

_WP_PREFIX = "wp:"


def wp_sse_subscribe(party_id: str) -> asyncio.Queue:
    """Subscribe to real-time events for a watch party."""
    return broadcast_sse_subscribe(f"{_WP_PREFIX}{party_id}")


def wp_sse_unsubscribe(party_id: str, q: asyncio.Queue) -> None:
    """Unsubscribe from a watch party's event stream."""
    broadcast_sse_unsubscribe(f"{_WP_PREFIX}{party_id}", q)


def wp_sse_publish(party_id: str, event: Dict[str, Any]) -> None:
    """Publish an event to all subscribers of a watch party."""
    broadcast_sse_publish(f"{_WP_PREFIX}{party_id}", event)
