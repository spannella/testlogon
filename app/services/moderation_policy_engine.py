from __future__ import annotations

import logging
import time
from typing import Any

from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import write_alert

logger = logging.getLogger(__name__)


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

    # MODX-6: link the offender's device/email/IP fingerprints (backfilled from
    # signup signals on account_state) so a new account created on the same
    # device/email/IP can be flagged as likely ban-evasion at registration.
    try:
        from app.services.moderation_ban_fingerprint import record_ban_fingerprints
        record_ban_fingerprints(user_sub=offender_user_id, source_ticket_id=ticket_id, now_ts=ts)
    except Exception:
        logger.exception("apply_ban: ban-fingerprint capture failed for %s", offender_user_id)

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


# MOD-F1: statuses that gate the authenticated request path. ``banned`` is the
# ban model; ``suspended`` is an admin-imposed hold. Both are enforced; timed
# entries auto-expire via ``ban_until``.
ENFORCED_BLOCK_STATUSES = {BAN_STATUS, "suspended"}


def _load_account_state_or_fail_closed(user_sub: str) -> dict[str, Any]:
    # MOD-F1 (fail-CLOSED): a transient DDB read error must NOT admit a possibly
    # -banned user. Retry briefly, then DENY the request with a 503 rather than
    # silently returning "not banned" (the previous fail-OPEN behavior).
    last_exc: Exception | None = None
    for attempt in range(3):
        try:
            return T.account_state.get_item(Key={"user_sub": user_sub}).get("Item") or {}
        except Exception as exc:  # noqa: BLE001 - transient DDB error
            last_exc = exc
            time.sleep(0.05 * (attempt + 1))
    logger.error("account_state read failed for %s; failing CLOSED", user_sub, exc_info=last_exc)
    raise HTTPException(status_code=503, detail="account state temporarily unavailable")


def is_user_currently_banned(user_sub: str) -> bool:
    if not user_sub:
        return False
    item = _load_account_state_or_fail_closed(user_sub)
    if str(item.get("status") or "") not in ENFORCED_BLOCK_STATUSES:
        return False

    ban_until = _coerce_int(item.get("ban_until"), 0)
    if ban_until > 0 and now_ts() >= ban_until:
        return False
    return True
