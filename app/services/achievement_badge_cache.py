"""In-memory TTL cache for display badges.

ENGAGE-001: Achievements & Gamification System.
"""
from __future__ import annotations

import threading
import time
from typing import Any, Dict, List

_BADGE_CACHE: Dict[str, Dict[str, Any]] = {}
_BADGE_CACHE_LOCK = threading.Lock()
_BADGE_CACHE_TTL = 300  # 5 minutes


def get_cached_badges(user_sub: str) -> List[Dict[str, Any]]:
    """Get display badges from cache, falling back to DDB on miss."""
    with _BADGE_CACHE_LOCK:
        entry = _BADGE_CACHE.get(user_sub)
        if entry and entry["expires_at"] > int(time.time()):
            return entry["badges"]

    from app.services.achievement_badges import get_display_badges
    badges = get_display_badges(user_sub)

    with _BADGE_CACHE_LOCK:
        _BADGE_CACHE[user_sub] = {
            "badges": badges,
            "expires_at": int(time.time()) + _BADGE_CACHE_TTL,
        }

    return badges


def _invalidate_badge_cache(user_sub: str) -> None:
    """Invalidate cache when user changes their display badges."""
    with _BADGE_CACHE_LOCK:
        _BADGE_CACHE.pop(user_sub, None)
