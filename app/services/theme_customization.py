"""Per-user theme customization persistence (PLATFORM-013).

Stores a single theme-config record per user in the dedicated `user_themes`
DynamoDB table:

    PK: user_sub (string)   -- simple primary key, no sort key

The record holds the user's UI theme preferences (mode, accent color,
custom hex, font scale, density, preset, high-contrast flag). This is a
self-contained store distinct from the legacy UX-001 `ui_preferences`
profile attribute, so it can evolve independently.

All validation of enum/hex/scale values happens at the Pydantic model layer
(`ThemeConfigPatchReq` in app.models); this service only persists and reads
the validated values and supplies deterministic defaults when no record
exists.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# Allowed enum values mirror the Pydantic Literal definitions. Kept here so
# the service can sanitize a stored record (defensive against manual writes).
THEME_MODES = ("light", "dark", "system")
ACCENT_COLORS = ("blue", "purple", "green", "orange", "pink", "red", "teal", "custom")
FONT_SCALES = ("small", "default", "large", "xlarge")
DENSITIES = ("compact", "comfortable", "spacious")
PRESETS = ("default", "midnight", "sunrise", "forest", "ocean")

# Deterministic defaults returned when a user has no saved theme config.
DEFAULT_THEME_CONFIG: Dict[str, Any] = {
    "mode": "system",
    "accent_color": "blue",
    "custom_accent_hex": None,
    "font_scale": "default",
    "density": "comfortable",
    "preset": "default",
    "high_contrast": False,
}

# Fields persisted in the record (in addition to user_sub + updated_at).
_CONFIG_FIELDS = tuple(DEFAULT_THEME_CONFIG.keys())


def _normalize(item: Dict[str, Any]) -> Dict[str, Any]:
    """Project a raw DynamoDB item into a clean config dict with defaults."""
    out = dict(DEFAULT_THEME_CONFIG)
    for field in _CONFIG_FIELDS:
        if field in item and item[field] is not None:
            out[field] = item[field]
    # high_contrast may come back as a Decimal/0/1 in some stores; coerce.
    out["high_contrast"] = bool(out["high_contrast"])
    return out


def get_theme_config(user_sub: str) -> Dict[str, Any]:
    """Return the user's saved theme config, or deterministic defaults.

    Always returns a fully-populated dict (every field present).
    """
    try:
        resp = T.user_themes.get_item(Key={"user_sub": user_sub})
    except Exception:  # pragma: no cover - defensive
        logger.exception("Failed to read theme config for %s", user_sub)
        return dict(DEFAULT_THEME_CONFIG)
    item = resp.get("Item")
    if not item:
        return dict(DEFAULT_THEME_CONFIG)
    return _normalize(item)


def save_theme_config(user_sub: str, patch: Dict[str, Any]) -> Dict[str, Any]:
    """Merge-update the user's theme config and return the full config.

    `patch` should contain only validated, non-None values (callers pass
    `model.model_dump(exclude_none=True)`). Unknown keys are ignored. The
    record is upserted so partial updates merge with the existing config.
    """
    current = get_theme_config(user_sub)
    merged = dict(current)
    for key, value in patch.items():
        if key in _CONFIG_FIELDS:
            merged[key] = value

    item: Dict[str, Any] = {"user_sub": user_sub, "updated_at": now_ts()}
    for field in _CONFIG_FIELDS:
        value = merged[field]
        # DynamoDB cannot store None as an attribute value; skip it so the
        # attribute is simply absent (treated as default on read).
        if value is None:
            continue
        item[field] = value

    T.user_themes.put_item(Item=item)
    return merged


def reset_theme_config(user_sub: str) -> Dict[str, Any]:
    """Delete the user's saved theme config; subsequent reads return defaults."""
    try:
        T.user_themes.delete_item(Key={"user_sub": user_sub})
    except Exception:  # pragma: no cover - defensive
        logger.exception("Failed to reset theme config for %s", user_sub)
    return dict(DEFAULT_THEME_CONFIG)
