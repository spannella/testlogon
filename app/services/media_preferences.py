"""
Media Preferences service — persist user camera/mic/speaker device
preferences and default mute states in DynamoDB.

Table: media_preferences
  PK = user_sub  (string)
  SK = "PREFS"   (constant)
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

_SK = "PREFS"


def get_preferences(user_sub: str) -> Optional[Dict[str, Any]]:
    """Return the saved media preferences for *user_sub*, or None."""
    resp = T.media_preferences.get_item(
        Key={"user_sub": user_sub, "sk": _SK},
    )
    item = resp.get("Item")
    if not item:
        return None
    return _item_to_out(item)


def save_preferences(user_sub: str, prefs: Dict[str, Any]) -> Dict[str, Any]:
    """Upsert media preferences for *user_sub*."""
    now = now_ts()
    item: Dict[str, Any] = {
        "user_sub": user_sub,
        "sk": _SK,
        "preferred_audio_input_id": prefs.get("preferred_audio_input_id") or None,
        "preferred_video_input_id": prefs.get("preferred_video_input_id") or None,
        "preferred_audio_output_id": prefs.get("preferred_audio_output_id") or None,
        "default_audio_muted": bool(prefs.get("default_audio_muted", False)),
        "default_video_off": bool(prefs.get("default_video_off", False)),
        "video_resolution": prefs.get("video_resolution", "720"),
        "updated_at": now,
    }
    # DynamoDB cannot store None values in top-level attributes — remove them.
    cleaned = {k: v for k, v in item.items() if v is not None}
    T.media_preferences.put_item(Item=cleaned)
    return _item_to_out(cleaned)


def _item_to_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "user_sub": item["user_sub"],
        "preferred_audio_input_id": item.get("preferred_audio_input_id"),
        "preferred_video_input_id": item.get("preferred_video_input_id"),
        "preferred_audio_output_id": item.get("preferred_audio_output_id"),
        "default_audio_muted": bool(item.get("default_audio_muted", False)),
        "default_video_off": bool(item.get("default_video_off", False)),
        "video_resolution": str(item.get("video_resolution", "720")),
        "updated_at": int(item.get("updated_at", 0)),
    }
