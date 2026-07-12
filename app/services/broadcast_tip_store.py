"""Broadcast live tip service -- tip chat messages, session totals, and goal tracking (BCAST-013)."""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Dict, List
from uuid import uuid4

from boto3.dynamodb.conditions import Attr, Key
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.broadcast_sse import broadcast_sse_publish
from app.services.tip_ledger import TipLedgerEntry, write_tip_ledger

logger = logging.getLogger(__name__)

# --- Rate Limiting (in-memory, separate bucket for tips) ---

_TIP_RATE_LOCK = threading.Lock()
_TIP_RATE_BUCKETS: Dict[str, int] = {}  # "{session_id}#{user_id}" -> last_tip_ts_ms


def _enforce_tip_rate_limit(session_id: str, user_id: str) -> None:
    """Raise 429 if user is sending tips faster than allowed.

    Only checks — does NOT record the timestamp. Call ``_record_tip_rate_limit``
    after all validations pass to avoid penalising failed tip attempts.
    """
    key = f"{session_id}#{user_id}"
    now_ms = int(time.time() * 1000)
    limit_ms = S.broadcast_tip_rate_limit_ms
    with _TIP_RATE_LOCK:
        last = _TIP_RATE_BUCKETS.get(key, 0)
        if now_ms - last < limit_ms:
            raise HTTPException(
                status_code=429,
                detail={
                    "code": "BROADCAST_TIP_RATE_LIMITED",
                    "message": "You can send one tip every 3 seconds.",
                    "retry_after_ms": limit_ms - (now_ms - last),
                },
            )


def _record_tip_rate_limit(session_id: str, user_id: str) -> None:
    """Record a successful tip so the next tip is rate-limited from now."""
    key = f"{session_id}#{user_id}"
    now_ms = int(time.time() * 1000)
    with _TIP_RATE_LOCK:
        _TIP_RATE_BUCKETS[key] = now_ms


def reset_tip_rate_limits() -> None:
    """Clear all tip rate limit state (for tests)."""
    with _TIP_RATE_LOCK:
        _TIP_RATE_BUCKETS.clear()


# --- Payment Method Validation ---

def _validate_payment_method(user_id: str, payment_method_id: str) -> None:
    """Validate that the given payment method belongs to the user."""
    billing_pk = f"USER#{user_id}"
    resp = T.billing.query(
        KeyConditionExpression=Key("pk").eq(billing_pk),
    )
    items = resp.get("Items", [])
    pm_ids = {
        it["payment_method_id"]
        for it in items
        if it.get("sk", "").startswith("PM#") and "payment_method_id" in it
    }
    if payment_method_id not in pm_ids:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "PAYMENT_METHOD_NOT_FOUND",
                "message": "Payment method not found. Add a payment method in Billing.",
            },
        )


# --- Tip Chat Message ---

def send_tip_message(
    *,
    session_id: str,
    user_id: str,
    display_name: str,
    amount_cents: int,
    currency: str = "USD",
    payment_method_id: str,
    text: str = "",
    broadcaster_id: str,
) -> Dict[str, Any]:
    """Send a tip as a chat message. Validates PM, writes ledger, updates session total."""
    from app.services.broadcast_chat_store import _enforce_chat_mute

    # 1. Mute check
    _enforce_chat_mute(session_id, user_id)

    # 2. Validate PM
    _validate_payment_method(user_id, payment_method_id)

    # 3. Validate amount bounds
    if amount_cents < S.broadcast_tip_min_cents:
        raise HTTPException(400, {"code": "TIP_TOO_SMALL", "message": f"Minimum tip is ${S.broadcast_tip_min_cents / 100:.2f}."})
    if amount_cents > S.broadcast_tip_max_cents:
        raise HTTPException(400, {"code": "TIP_TOO_LARGE", "message": f"Maximum tip is ${S.broadcast_tip_max_cents / 100:.2f}."})

    # 4. Prevent self-tip
    if user_id == broadcaster_id:
        raise HTTPException(400, {"code": "CANNOT_TIP_SELF", "message": "You cannot tip your own broadcast."})

    # 5. Rate limit — checked and recorded only after all validations pass,
    #    so invalid attempts (wrong PM, self-tip, etc.) don't consume the
    #    rate-limit window.
    _enforce_tip_rate_limit(session_id, user_id)
    _record_tip_rate_limit(session_id, user_id)

    # 6. Generate IDs
    tip_payment_id = f"bctip_{uuid4().hex}"
    ts = now_ts()
    ts_ms = int(time.time() * 1000)
    msg_id = "cm_" + uuid4().hex
    sort_key = f"{ts_ms:016d}#{msg_id}"

    # 7. Charge + write billing ledger via the centralized charge_tip seam.
    #    PM ownership, amount bounds and self-tip were validated above; charge_tip
    #    re-validates PM + self-tip and writes the same net-credit ledger. The
    #    minted tip id is threaded through so the chat row and ledger stay linked.
    from app.services.tips import charge_tip
    charge_tip(
        tipper_id=user_id,
        recipient_id=broadcaster_id,
        amount_cents=amount_cents,
        currency=currency,
        payment_method_id=payment_method_id,
        content_type="broadcast",
        content_id=f"{session_id}#{msg_id}",
        meta={
            "session_id": session_id,
            "message_id": msg_id,
            "display_name": display_name,
        },
        idempotency_key=f"bctip:{msg_id}",
        tip_payment_id=tip_payment_id,
    )

    # 8. Write tip chat message to DDB
    tip_text = text.strip() if text else ""
    item: Dict[str, Any] = {
        "session_id": session_id,
        "sort_key": sort_key,
        "message_id": msg_id,
        "sender_id": user_id,
        "sender_display_name": display_name,
        "text": tip_text,
        "kind": "tip",
        "tip_amount_cents": amount_cents,
        "tip_currency": currency,
        "tip_payment_id": tip_payment_id,
        "created_at": ts,
        "deleted": False,
        "ttl": ts + 7 * 24 * 3600,
    }
    T.broadcast_chat_messages.put_item(Item=item)

    # 9. Atomically increment session tip totals
    new_totals = _increment_session_tip_totals(session_id, amount_cents)

    # 10. Publish SSE events
    out = _tip_msg_out(item)
    broadcast_sse_publish(session_id, {"_type": "chat:tip", **out})
    broadcast_sse_publish(session_id, {
        "_type": "tip:total_update",
        "session_id": session_id,
        "tip_total_cents": new_totals["tip_total_cents"],
        "tip_count": new_totals["tip_count"],
        "latest_tip": {
            "sender_id": user_id,
            "sender_display_name": display_name,
            "amount_cents": amount_cents,
            "message_id": msg_id,
        },
    })

    # 11. Update goal progress
    _update_goals_for_tip(session_id, amount_cents)

    return {**out, "session_tip_total_cents": new_totals["tip_total_cents"]}


def _increment_session_tip_totals(session_id: str, amount_cents: int) -> Dict[str, int]:
    """Atomically increment tip_total_cents and tip_count on the session record."""
    from datetime import datetime, timezone
    resp = T.broadcast_sessions.update_item(
        Key={"session_id": session_id},
        UpdateExpression=(
            "ADD tip_total_cents :amt, tip_count :one "
            "SET updated_at = :now"
        ),
        ExpressionAttributeValues={
            ":amt": amount_cents,
            ":one": 1,
            ":now": datetime.now(timezone.utc).isoformat(),
        },
        ReturnValues="UPDATED_NEW",
    )
    attrs = resp.get("Attributes", {})
    return {
        "tip_total_cents": int(attrs.get("tip_total_cents", 0)),
        "tip_count": int(attrs.get("tip_count", 0)),
    }


def _tip_msg_out(item: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a tip DDB item to output dict."""
    return {
        "message_id": item["message_id"],
        "session_id": item["session_id"],
        "sender_id": item["sender_id"],
        "sender_display_name": item.get("sender_display_name", ""),
        "text": item.get("text", ""),
        "kind": "tip",
        "tip_amount_cents": int(item.get("tip_amount_cents", 0)),
        "tip_currency": item.get("tip_currency", "USD"),
        "tip_payment_id": item.get("tip_payment_id", ""),
        "created_at": int(item.get("created_at", 0)),
        "deleted": bool(item.get("deleted", False)),
    }


def _update_goals_for_tip(session_id: str, amount_cents: int) -> None:
    """Update tip goals with the new tip amount. Silent on errors."""
    try:
        from app.services.broadcast_tip_goals import advance_goal_progress
        advance_goal_progress(session_id, amount_cents)
    except Exception:
        logger.warning(
            "broadcast_tip_goal_update_failed",
            extra={"session_id": session_id, "amount": amount_cents},
        )


# --- Tip Summary ---

def get_tip_summary(session_id: str, *, limit: int = 10) -> Dict[str, Any]:
    """Get tip summary for a broadcast session."""
    from app.services.broadcast_store import get_session

    session = get_session(session_id)
    total_cents = int(getattr(session, "tip_total_cents", 0) or 0)
    tip_count_val = int(getattr(session, "tip_count", 0) or 0)

    # Query tip messages from chat table
    tip_messages = _query_tip_messages(session_id, limit=200)

    # Aggregate top tippers
    tipper_agg: Dict[str, Dict[str, Any]] = {}
    for msg in tip_messages:
        uid = msg["sender_id"]
        if uid not in tipper_agg:
            tipper_agg[uid] = {
                "user_id": uid,
                "display_name": msg.get("sender_display_name", uid),
                "total_cents": 0,
                "tip_count": 0,
            }
        tipper_agg[uid]["total_cents"] += int(msg.get("tip_amount_cents", 0))
        tipper_agg[uid]["tip_count"] += 1

    top_tippers = sorted(tipper_agg.values(), key=lambda x: x["total_cents"], reverse=True)[:limit]

    # Recent tips (newest first)
    recent = sorted(tip_messages, key=lambda m: m.get("created_at", 0), reverse=True)[:limit]
    recent_tips = [
        {
            "message_id": m["message_id"],
            "sender_id": m["sender_id"],
            "sender_display_name": m.get("sender_display_name", ""),
            "amount_cents": int(m.get("tip_amount_cents", 0)),
            "text": m.get("text", ""),
            "created_at": int(m.get("created_at", 0)),
        }
        for m in recent
    ]

    return {
        "session_id": session_id,
        "total_cents": total_cents,
        "tip_count": tip_count_val,
        "currency": "USD",
        "top_tippers": top_tippers,
        "recent_tips": recent_tips,
    }


def _query_tip_messages(session_id: str, *, limit: int = 200) -> List[Dict[str, Any]]:
    """Query all tip messages for a session from the chat table."""
    all_tips: List[Dict[str, Any]] = []
    last_key = None
    pages = 0
    while pages < 10:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("session_id").eq(session_id),
            "FilterExpression": Attr("kind").eq("tip") & Attr("deleted").ne(True),
            "Limit": 500,
            "ScanIndexForward": False,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.broadcast_chat_messages.query(**kwargs)
        all_tips.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key or len(all_tips) >= limit:
            break
        pages += 1
    return all_tips[:limit]
