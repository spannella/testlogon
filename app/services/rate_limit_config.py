"""
Rate limit endpoint group definitions and DDB override cache (PLATFORM-001).
"""
from __future__ import annotations

import copy
import fnmatch
import logging
import time
from typing import Any, Dict, Optional

from app.core.settings import S
from app.core.tables import T

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default endpoint group configuration
# ---------------------------------------------------------------------------

ENDPOINT_GROUPS: Dict[str, Dict[str, Any]] = {
    "global_ip": {
        "description": "Global per-IP rate limit applied to all requests",
        "window_seconds": 60,
        "max_requests": 300,
        "applies_to": "ip",
        "bypass_roles": ["root"],
    },
    "auth": {
        "description": "Authentication endpoints (login, register, password reset)",
        "paths": ["/ui/login", "/ui/register", "/ui/password-recovery/*"],
        "window_seconds": 900,
        "max_requests_per_user": 10,
        "max_requests_per_ip": 20,
        "bypass_roles": [],
    },
    "messaging": {
        "description": "Messaging send/read endpoints",
        "paths": ["/messaging/*"],
        "window_seconds": 60,
        "max_requests_per_user": 120,
        "max_requests_per_ip": 200,
        "bypass_roles": ["root", "admin"],
    },
    "file_upload": {
        "description": "File upload endpoints",
        "paths": ["/ui/files/upload", "/ui/files/*/content"],
        "window_seconds": 300,
        "max_requests_per_user": 50,
        "max_requests_per_ip": 100,
        "bypass_roles": ["root", "admin"],
    },
    "billing": {
        "description": "Billing and payment endpoints",
        "paths": ["/ui/billing/*", "/ui/wallet/*"],
        "window_seconds": 60,
        "max_requests_per_user": 30,
        "max_requests_per_ip": 60,
        "bypass_roles": ["root"],
    },
    "admin": {
        "description": "Admin and root endpoints",
        "paths": ["/ui/admin/*", "/internal/*"],
        "window_seconds": 60,
        "max_requests_per_user": 200,
        "max_requests_per_ip": 300,
        "bypass_roles": ["root"],
    },
    "newsfeed": {
        "description": "Newsfeed read/write endpoints",
        "paths": ["/ui/feed/*", "/ui/posts/*"],
        "window_seconds": 60,
        "max_requests_per_user": 180,
        "max_requests_per_ip": 300,
        "bypass_roles": ["root", "admin"],
    },
    "search": {
        "description": "Search endpoints",
        "paths": ["/ui/discover/*", "/messaging/contacts/search", "/messaging/conversations/*/messages/search", "/messaging/messages/search"],
        "window_seconds": 60,
        "max_requests_per_user": 60,
        "max_requests_per_ip": 100,
        "bypass_roles": ["root", "admin"],
    },
    "api_public": {
        "description": "Public API endpoints accessed via API keys",
        "paths": ["/api/*"],
        "window_seconds": 60,
        "max_requests_per_user": 60,
        "max_requests_per_ip": 120,
        "bypass_roles": ["root"],
    },
}


# ---------------------------------------------------------------------------
# In-memory config override cache (60 s TTL)
# ---------------------------------------------------------------------------

_CONFIG_CACHE: Dict[str, Dict[str, Any]] = {}
_CONFIG_CACHE_TS: Dict[str, float] = {}
_CACHE_TTL_SECONDS = 60.0


def _load_override(group: str) -> Optional[Dict[str, Any]]:
    """Load a config override from DDB, returning None if not found."""
    try:
        resp = T.rate_limits.get_item(
            Key={"pk": "CONFIG#global", "sk": f"GROUP#{group}"},
        )
        item = resp.get("Item")
        if not item:
            return None
        return {
            "window_seconds": int(item.get("window_seconds", 0)) or None,
            "max_requests_per_user": int(item.get("max_requests_per_user", 0)) or None,
            "max_requests_per_ip": int(item.get("max_requests_per_ip", 0)) or None,
            "bypass_roles": item.get("bypass_roles") or None,
            "max_requests": int(item.get("max_requests", 0)) or None,
        }
    except Exception:
        logger.warning("rate_limit_config: failed to load override for group=%s", group, exc_info=True)
        return None


def get_group_config(group: str) -> Dict[str, Any]:
    """
    Return effective config for an endpoint group.

    Merges DDB overrides (cached 60 s) over the in-code defaults.
    """
    default = ENDPOINT_GROUPS.get(group)
    if default is None:
        return {
            "window_seconds": 60,
            "max_requests_per_user": 120,
            "max_requests_per_ip": 200,
            "bypass_roles": ["root"],
        }

    config = copy.deepcopy(default)

    now = time.time()
    cached_ts = _CONFIG_CACHE_TS.get(group, 0.0)
    if (now - cached_ts) >= _CACHE_TTL_SECONDS:
        override = _load_override(group)
        _CONFIG_CACHE[group] = override or {}
        _CONFIG_CACHE_TS[group] = now
    else:
        override = _CONFIG_CACHE.get(group, {})

    if override:
        config["is_override"] = True
        for key in ("window_seconds", "max_requests_per_user", "max_requests_per_ip", "bypass_roles", "max_requests"):
            val = override.get(key)
            if val is not None:
                config[key] = val
    else:
        config["is_override"] = False

    return config


def save_group_override(
    group: str,
    *,
    window_seconds: Optional[int] = None,
    max_requests_per_user: Optional[int] = None,
    max_requests_per_ip: Optional[int] = None,
    bypass_roles: Optional[list] = None,
    updated_by: str = "",
) -> Dict[str, Any]:
    """Persist a config override to DDB and bust the cache."""
    from app.core.time import now_ts as _now_ts

    item: Dict[str, Any] = {
        "pk": "CONFIG#global",
        "sk": f"GROUP#{group}",
        "updated_by": updated_by,
        "updated_at": _now_ts(),
    }
    if window_seconds is not None:
        item["window_seconds"] = window_seconds
    if max_requests_per_user is not None:
        item["max_requests_per_user"] = max_requests_per_user
    if max_requests_per_ip is not None:
        item["max_requests_per_ip"] = max_requests_per_ip
    if bypass_roles is not None:
        item["bypass_roles"] = bypass_roles
    T.rate_limits.put_item(Item=item)

    # Bust cache
    _CONFIG_CACHE.pop(group, None)
    _CONFIG_CACHE_TS.pop(group, None)

    return item


def get_all_configs() -> Dict[str, Any]:
    """Return the full configuration (defaults + overrides) for all groups."""
    result: Dict[str, Any] = {}
    for group_name in ENDPOINT_GROUPS:
        cfg = get_group_config(group_name)
        result[group_name] = cfg
    return result


# ---------------------------------------------------------------------------
# Path matching
# ---------------------------------------------------------------------------

def match_path_to_group(path: str) -> Optional[str]:
    """
    Match a request path to an endpoint group name.
    Returns None if no group matched.
    """
    for group_name, group_cfg in ENDPOINT_GROUPS.items():
        if group_name == "global_ip":
            continue
        patterns = group_cfg.get("paths", [])
        for pattern in patterns:
            if fnmatch.fnmatch(path, pattern):
                return group_name
    return None
