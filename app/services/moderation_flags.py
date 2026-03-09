from __future__ import annotations

from typing import Any, Literal

from fastapi import HTTPException

from app.auth.deps import AuthenticatedUser
from app.auth.roles import AdminScope, admin_profile_has_scope, normalize_admin_profile
from app.core.tables import T

FLAGS_PK = "__moderation_flags__"

DEFAULT_FLAGS: dict[str, Any] = {
    "enabled": True,
    "report_feed_enabled": True,
    "report_messages_enabled": True,
    "report_profile_enabled": True,
    "admin_board_enabled": True,
    "admin_actions_enabled": True,
    "enforcement_enabled": True,
    "min_scope_for_board": "content_moderation",
    "min_scope_for_actions": "content_moderation",
    "min_scope_for_permanent_ban": "content_moderation_senior",
}


FlagScope = Literal["content_moderation", "content_moderation_senior"]


def _normalize_scope(raw: Any, *, default: FlagScope) -> FlagScope:
    val = str(raw or "").strip().lower()
    if val in {"content_moderation", "content_moderation_senior"}:
        return val  # type: ignore[return-value]
    return default


def get_moderation_feature_flags() -> dict[str, Any]:
    try:
        row = T.alert_prefs.get_item(Key={"user_sub": FLAGS_PK}).get("Item") or {}
    except Exception:
        row = {}
    persisted = row.get("moderation_feature_flags") if isinstance(row.get("moderation_feature_flags"), dict) else {}
    flags = {**DEFAULT_FLAGS, **persisted}
    flags["min_scope_for_board"] = _normalize_scope(flags.get("min_scope_for_board"), default="content_moderation")
    flags["min_scope_for_actions"] = _normalize_scope(flags.get("min_scope_for_actions"), default="content_moderation")
    flags["min_scope_for_permanent_ban"] = _normalize_scope(flags.get("min_scope_for_permanent_ban"), default="content_moderation_senior")
    return flags


def set_moderation_feature_flags(updates: dict[str, Any]) -> dict[str, Any]:
    cur = get_moderation_feature_flags()
    merged = {**cur, **(updates or {})}
    try:
        T.alert_prefs.put_item(Item={"user_sub": FLAGS_PK, "moderation_feature_flags": merged})
    except Exception:
        return merged
    return get_moderation_feature_flags()


def _has_scope(admin: AuthenticatedUser, required_scope: str) -> bool:
    if getattr(admin.role, "name", "") == "ROOT":
        return True
    profile = normalize_admin_profile(getattr(admin, "admin_profile", None))
    if required_scope == "content_moderation_senior":
        return admin_profile_has_scope(profile, AdminScope.CONTENT_MODERATION_SENIOR)
    return admin_profile_has_scope(profile, AdminScope.CONTENT_MODERATION)


def ensure_admin_board_enabled(admin: AuthenticatedUser) -> None:
    flags = get_moderation_feature_flags()
    if not bool(flags.get("enabled", True)) or not bool(flags.get("admin_board_enabled", True)):
        raise HTTPException(status_code=403, detail="moderation board is disabled")
    if not _has_scope(admin, str(flags.get("min_scope_for_board") or "content_moderation")):
        raise HTTPException(status_code=403, detail="moderation board rollout scope not enabled for role")


def ensure_admin_actions_enabled(admin: AuthenticatedUser) -> None:
    flags = get_moderation_feature_flags()
    if not bool(flags.get("enabled", True)) or not bool(flags.get("admin_actions_enabled", True)):
        raise HTTPException(status_code=403, detail="moderation actions are disabled")
    if not _has_scope(admin, str(flags.get("min_scope_for_actions") or "content_moderation")):
        raise HTTPException(status_code=403, detail="moderation actions rollout scope not enabled for role")


def ensure_reporting_surface_enabled(content_type: str) -> None:
    flags = get_moderation_feature_flags()
    if not bool(flags.get("enabled", True)):
        raise HTTPException(status_code=403, detail="moderation reporting is disabled")
    ctype = str(content_type or "")
    if ctype.startswith("feed_") and not bool(flags.get("report_feed_enabled", True)):
        raise HTTPException(status_code=403, detail="feed reporting is disabled")
    if ctype.startswith("message") and not bool(flags.get("report_messages_enabled", True)):
        raise HTTPException(status_code=403, detail="message reporting is disabled")
    if ctype == "profile_photo" and not bool(flags.get("report_profile_enabled", True)):
        raise HTTPException(status_code=403, detail="profile reporting is disabled")


def ensure_permanent_ban_scope_rollout(admin: AuthenticatedUser) -> None:
    flags = get_moderation_feature_flags()
    required = str(flags.get("min_scope_for_permanent_ban") or "content_moderation_senior")
    if not _has_scope(admin, required):
        raise HTTPException(status_code=403, detail="permanent ban rollout scope not enabled for role")
