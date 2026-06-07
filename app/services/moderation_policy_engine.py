from __future__ import annotations

from typing import Any

from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import write_alert


BAN_STATUS = "banned"


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return default


def issue_warning_notification(*, offender_user_id: str, ticket_id: str, note: str, policy_category: str = "unspecified", enforcement_id: str | None = None) -> None:
    if not offender_user_id:
        return
    write_alert(
        offender_user_id,
        event="moderation_warning",
        outcome="warning",
        title="Account warning issued",
        details={
            "ticket_id": ticket_id,
            "action": "warn",
            "policy_category": str(policy_category or "unspecified"),
            "note": (note or "")[:500],
            **({"enforcement_id": enforcement_id} if enforcement_id else {}),
        },
    )


def _ban_duration_label(duration_days: int) -> str:
    return f"{duration_days} day{'s' if duration_days != 1 else ''}" if duration_days > 0 else "permanent"


def notify_content_removal(*, offender_user_id: str, ticket_id: str, content_type: str, policy_category: str, note: str) -> None:
    if not offender_user_id:
        return
    write_alert(
        offender_user_id,
        event="moderation_content_removed",
        outcome="warning",
        title="Content removed",
        details={
            "ticket_id": ticket_id,
            "action": "content_removed",
            "content_type": str(content_type or ""),
            "policy_category": str(policy_category or "unspecified"),
            "note": (note or "")[:500],
        },
    )


def apply_ban(
    *,
    offender_user_id: str,
    ticket_id: str,
    admin_user_id: str,
    note: str,
    duration_days: int | None,
    policy_category: str = "unspecified",
    enforcement_id: str | None = None,
) -> dict[str, Any]:
    if not offender_user_id:
        return {"status": "skipped"}

    ts = now_ts()
    duration = _coerce_int(duration_days, 0)
    banned_until = ts + duration * 86400 if duration > 0 else 0

    T.account_state.put_item(
        Item={
            "user_sub": offender_user_id,
            "status": BAN_STATUS,
            "updated_at": ts,
            "reason": "moderation_ban",
            "requested_by": admin_user_id,
            "source_ticket_id": ticket_id,
            "ban_duration_days": duration,
            "ban_started_at": ts,
            "ban_until": banned_until,
            "ban_note": (note or "")[:500],
        }
    )

    write_alert(
        offender_user_id,
        event="moderation_ban",
        outcome="warning",
        title="Account restricted",
        details={
            "ticket_id": ticket_id,
            "action": "ban",
            "policy_category": str(policy_category or "unspecified"),
            "ban_duration_days": duration,
            "effective_duration": _ban_duration_label(duration),
            "ban_until": banned_until,
            "note": (note or "")[:500],
            **({"enforcement_id": enforcement_id} if enforcement_id else {}),
        },
    )

    return {
        "status": BAN_STATUS,
        "ban_duration_days": duration,
        "ban_until": banned_until,
    }


def is_user_currently_banned(user_sub: str) -> bool:
    if not user_sub:
        return False
    try:
        item = T.account_state.get_item(Key={"user_sub": user_sub}).get("Item") or {}
    except Exception:
        return False
    if str(item.get("status") or "") != BAN_STATUS:
        return False

    ban_until = _coerce_int(item.get("ban_until"), 0)
    if ban_until > 0 and now_ts() >= ban_until:
        return False
    return True
