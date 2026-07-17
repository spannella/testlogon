"""TIPX-E1/E3 — single choke-point tip notification helper.

`notify_tip` is invoked from the ONE tip choke point (`charge_tip`, after a
successful atomic charge) and from `reverse_tip` (on the first reversal). It is
the single place that:

  * emits a RECIPIENT alert ("you received a tip") into the alerts store the app
    actually reads (`emit_social_alert` -> `T.alerts`), with amount + a real
    `action_url` deep-link derived from `content_type` + `meta`;
  * emits a TIPPER receipt ("tip sent") into the same store, so the tipper has a
    durable proof-of-tip (N6);
  * on reversal, emits `tip_reversed` (creator) + `tip_refunded` (tipper) (N8).

Every branch is best-effort and NEVER raises into the money path: a notification
failure must not break or roll back a real charge/credit that already committed.

Deep-link derivation (N1/N2 dead-link fix) — a single `_action_url_for` maps the
tip's `content_type`+`meta` to a relative in-app path the client's TIP resolver
(AlertsScreen `isTipAlert`) parses:

    post / post_react       -> /feed/posts/{post_id}
    comment                 -> /feed/posts/{post_id}      (meta.post_id)
    message / message_react -> /messaging/thread/{conversation_id} (meta.conversation_id)
    video / video_comment   -> /videos/{video_id}         (meta.video_id)
    broadcast               -> /broadcast/{content_id}
    profile                 -> /profile/{content_id}

N4/N5 (message-react / attached-tip silent) and N2 (video dead-link) are fixed
simply by routing EVERY surface through this one helper — there are no per-surface
notification call-sites left to forget.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Recipient alert type per surface. post/message keep their established social
# types (already default-ON push + already parsed by older clients); every other
# surface uses the unified `tip_received` type. All are `tip_*`/`*_tip`, so the
# client normalizes them to the TIP notification bucket.
_RECIPIENT_ALERT_TYPE: Dict[str, str] = {
    "post": "post_tip",
    "post_react": "post_tip",
    "comment": "tip_received",
    "message": "message_tip",
    "message_react": "message_tip",
    "broadcast": "tip_received",
    "video": "tip_received",
    "video_comment": "tip_received",
    "profile": "tip_received",
}

# Human label per surface for the alert title / receipt copy.
_SURFACE_LABEL: Dict[str, str] = {
    "post": "post",
    "post_react": "post",
    "comment": "comment",
    "message": "message",
    "message_react": "message",
    "broadcast": "live broadcast",
    "video": "video",
    "video_comment": "video comment",
    "profile": "profile",
}


def _display_name(user_id: str) -> str:
    try:
        from app.services.profile import get_profile_identity

        return (get_profile_identity(user_id) or {}).get("display_name") or user_id
    except Exception:
        return user_id


def _action_url_for(content_type: str, content_id: str, meta: Dict[str, Any]) -> str:
    """Relative in-app deep-link to the tipped content (open-redirect-safe)."""
    m = meta or {}
    if content_type in ("post", "post_react"):
        return f"/feed/posts/{content_id}"
    if content_type == "comment":
        pid = m.get("post_id") or content_id
        return f"/feed/posts/{pid}"
    if content_type in ("message", "message_react"):
        cid = m.get("conversation_id") or ""
        return f"/messaging/thread/{cid}" if cid else "/messaging"
    if content_type in ("video", "video_comment"):
        vid = m.get("video_id") or (content_id if content_type == "video" else "")
        return f"/videos/{vid}" if vid else "/videos"
    if content_type == "broadcast":
        return f"/broadcast/{content_id}"
    if content_type == "profile":
        return f"/profile/{content_id}"
    return "/wallet/tips"


def _dollars(amount_cents: int, currency: str) -> str:
    sym = "$" if (currency or "USD").upper() == "USD" else ""
    return f"{sym}{amount_cents / 100:.2f}"


def notify_tip(
    *,
    tipper_id: str,
    recipient_id: str,
    amount_cents: int,
    net_cents: int,
    fee_cents: int,
    currency: str,
    content_type: str,
    content_id: str,
    tip_payment_id: str,
    meta: Optional[Dict[str, Any]] = None,
) -> None:
    """Emit the recipient tip alert + tipper receipt for ONE successful tip.

    Best-effort: never raises into the money path.
    """
    meta = dict(meta or {})
    label = _SURFACE_LABEL.get(content_type, "content")
    action_url = _action_url_for(content_type, content_id, meta)
    amount_str = _dollars(amount_cents, currency)

    # --- recipient: "you received a tip" (into the store the app reads) ---
    try:
        from app.services.social_alerts import emit_social_alert

        actor_name = _display_name(tipper_id)
        alert_type = _RECIPIENT_ALERT_TYPE.get(content_type, "tip_received")
        # N9: keep distinct tips on the same post from collapsing — key on the txn.
        batch_key = None
        if content_type in ("post", "post_react"):
            batch_key = f"tip:{content_id}:{tip_payment_id}"
        emit_social_alert(
            recipient_user_id=recipient_id,
            alert_type=alert_type,
            actor_user_id=tipper_id,
            actor_display_name=actor_name,
            batch_key=batch_key,
            title=f"{actor_name} tipped you {amount_str}",
            details={
                "tip_payment_id": tip_payment_id,
                "content_type": content_type,
                "content_id": content_id,
                "amount_cents": int(amount_cents),
                "net_cents": int(net_cents),
                "currency": currency,
                "surface": label,
                "kind": "tip_received",
            },
            action_url=action_url,
        )
    except Exception:
        logger.warning("tip recipient alert failed tip=%s", tip_payment_id, exc_info=True)

    # --- tipper: durable "tip sent" receipt (N6) ---
    try:
        from app.services.alerts import write_alert

        recipient_name = _display_name(recipient_id)
        write_alert(
            tipper_id,
            event="tip_sent",
            outcome="success",
            title=f"You tipped {recipient_name} {amount_str}",
            details={
                "tip_payment_id": tip_payment_id,
                "content_type": content_type,
                "content_id": content_id,
                "amount_cents": int(amount_cents),
                "fee_cents": int(fee_cents),
                "net_cents": int(net_cents),
                "currency": currency,
                "recipient_user_id": recipient_id,
                "surface": label,
                "kind": "tip_sent",
            },
            action_url=action_url,
        )
    except Exception:
        logger.warning("tip sender receipt failed tip=%s", tip_payment_id, exc_info=True)


def notify_tip_reversed(
    *,
    tipper_id: str,
    recipient_id: str,
    gross_cents: int,
    net_cents: int,
    currency: str,
    content_type: str,
    content_id: str,
    tip_payment_id: str,
    reason: str = "admin_reversal",
) -> None:
    """TIPX-E3 (N8): notify BOTH parties when a tip is reversed/refunded.

    Recipient sees `tip_reversed` (earnings clawed back, explained); tipper sees
    `tip_refunded` (money returned). Best-effort, never raises.
    """
    gross_str = _dollars(gross_cents, currency)
    net_str = _dollars(net_cents, currency)

    # Creator: earnings reversed — explain the drop.
    try:
        from app.services.alerts import write_alert

        write_alert(
            recipient_id,
            event="tip_reversed",
            outcome="success",
            title=f"A {net_str} tip was reversed",
            details={
                "tip_payment_id": tip_payment_id,
                "content_type": content_type,
                "content_id": content_id,
                "amount_cents": int(net_cents),
                "gross_cents": int(gross_cents),
                "currency": currency,
                "reason": reason,
                "kind": "tip_reversed",
            },
            action_url="/wallet/tips",
        )
    except Exception:
        logger.warning("tip reversal (creator) alert failed tip=%s", tip_payment_id, exc_info=True)

    # Tipper: refund landed.
    try:
        from app.services.alerts import write_alert

        write_alert(
            tipper_id,
            event="tip_refunded",
            outcome="success",
            title=f"Your {gross_str} tip was refunded",
            details={
                "tip_payment_id": tip_payment_id,
                "content_type": content_type,
                "content_id": content_id,
                "amount_cents": int(gross_cents),
                "currency": currency,
                "reason": reason,
                "kind": "tip_refunded",
            },
            action_url="/wallet/tips",
        )
    except Exception:
        logger.warning("tip refund (tipper) alert failed tip=%s", tip_payment_id, exc_info=True)
