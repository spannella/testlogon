from __future__ import annotations

import hashlib
from fastapi import HTTPException

from app.core.settings import S


def rollout_mode() -> str:
    mode = str(getattr(S, "google_calendar_sync_rollout_mode", "all") or "all").strip().lower()
    if mode in {"all", "cohort", "off"}:
        return mode
    return "all"


def _cohort_users() -> set[str]:
    raw = str(getattr(S, "google_calendar_sync_rollout_cohort_user_subs", "") or "")
    return {part.strip() for part in raw.split(",") if part.strip()}


def rollout_percent() -> int:
    raw = getattr(S, "google_calendar_sync_rollout_percent", 100)
    try:
        value = int(raw)
    except Exception:
        return 100
    return max(0, min(100, value))


def _in_rollout_percent(user_sub: str) -> bool:
    pct = rollout_percent()
    if pct >= 100:
        return True
    if pct <= 0:
        return False
    bucket = int(hashlib.sha256(user_sub.encode("utf-8")).hexdigest()[:8], 16) % 100
    return bucket < pct


def is_google_calendar_sync_enabled() -> bool:
    return bool(getattr(S, "google_calendar_sync_enabled", False))


def is_google_calendar_sync_enabled_for_user(user_sub: str | None) -> bool:
    if not is_google_calendar_sync_enabled():
        return False
    mode = rollout_mode()
    if mode == "off":
        return False
    if mode == "all":
        return True
    if not user_sub:
        return False
    allowed = _cohort_users()
    if user_sub in allowed:
        return True
    return _in_rollout_percent(user_sub)


def is_google_calendar_writeback_enabled() -> bool:
    return is_google_calendar_sync_enabled() and bool(
        getattr(S, "google_calendar_writeback_enabled", False)
    )


def is_google_calendar_writeback_enabled_for_user(user_sub: str | None) -> bool:
    return is_google_calendar_writeback_enabled() and is_google_calendar_sync_enabled_for_user(user_sub)


def require_google_calendar_sync_enabled() -> None:
    if is_google_calendar_sync_enabled():
        return
    raise HTTPException(
        status_code=403,
        detail={"code": "feature_disabled", "feature": "google_calendar_sync"},
    )


def require_google_calendar_sync_enabled_for_user(user_sub: str | None) -> None:
    if is_google_calendar_sync_enabled_for_user(user_sub):
        return
    raise HTTPException(
        status_code=403,
        detail={"code": "feature_disabled", "feature": "google_calendar_sync"},
    )


def require_google_calendar_writeback_enabled() -> None:
    if is_google_calendar_writeback_enabled():
        return
    raise HTTPException(
        status_code=403,
        detail={"code": "feature_disabled", "feature": "google_calendar_writeback"},
    )


def require_google_calendar_writeback_enabled_for_user(user_sub: str | None) -> None:
    if is_google_calendar_writeback_enabled_for_user(user_sub):
        return
    raise HTTPException(
        status_code=403,
        detail={"code": "feature_disabled", "feature": "google_calendar_writeback"},
    )
