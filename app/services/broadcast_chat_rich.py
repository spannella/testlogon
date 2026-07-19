"""Broadcast chat rich messaging features — reactions, replies, expiry,
locking, and tipping for broadcast chat messages (BCAST-015)."""

from __future__ import annotations

import logging
import threading
import time
import uuid
from typing import Any, Dict, List, Optional, Set

from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts
from app.services.broadcast_sse import broadcast_sse_publish

logger = logging.getLogger("broadcast.chat.rich")

# ─── Allowed Reactions ────────────────────────────────────────────

ALLOWED_REACTIONS: Set[str] = {"\U0001f44d", "❤️", "\U0001f602", "\U0001f525", "\U0001f62e", "\U0001f44f"}

# ─── Rate Limiting (separate buckets from text messages) ──────────

_REACTION_RATE_LOCK = threading.Lock()
_REACTION_RATE_BUCKETS: Dict[str, int] = {}
_REACTION_RATE_MS = 500  # 1 reaction per 500ms

_UNLOCK_RATE_LOCK = threading.Lock()
_UNLOCK_RATE_BUCKETS: Dict[str, int] = {}
_UNLOCK_RATE_MS = 2000  # 1 unlock per 2s

_TIP_RATE_LOCK = threading.Lock()
_TIP_RATE_BUCKETS: Dict[str, int] = {}
_TIP_RATE_MS = 5000  # 1 tip per 5s


def _enforce_rate_limit(
    buckets: Dict[str, int],
    lock: threading.Lock,
    key: str,
    limit_ms: int,
    code: str,
    message: str,
) -> None:
    """Generic in-memory rate limiter."""
    now_ms = int(time.time() * 1000)
    with lock:
        last = buckets.get(key, 0)
        if now_ms - last < limit_ms:
            raise HTTPException(
                status_code=429,
                detail={
                    "code": code,
                    "message": message,
                    "retry_after_ms": limit_ms - (now_ms - last),
                },
            )
        buckets[key] = now_ms


# ─── Phase A: Reactions ──────────────────────────────────────────

def react_to_chat_message(
    session_id: str,
    message_id: str,
    user_id: str,
    emoji: str,
    action: str = "add",
) -> Dict[str, Any]:
    """Add or remove a reaction on a broadcast chat message.

    Uses DDB atomic ADD/DELETE on the reactions map.
    Publishes chat:reaction SSE event with updated counts.
    """
    if emoji not in ALLOWED_REACTIONS:
        raise HTTPException(400, "Emoji not allowed")

    _enforce_rate_limit(
        _REACTION_RATE_BUCKETS, _REACTION_RATE_LOCK,
        f"{session_id}#{user_id}", _REACTION_RATE_MS,
        "BROADCAST_REACTION_RATE_LIMITED",
        "Too many reactions. Try again shortly.",
    )

    sort_key = _find_sort_key(session_id, message_id)
    if not sort_key:
        raise HTTPException(400, "Message not found")

    expr_names = {"#e": emoji}

    try:
        if action == "add":
            # First ensure reactions map exists, then add to the emoji set
            try:
                T.broadcast_chat_messages.update_item(
                    Key={"session_id": session_id, "sort_key": sort_key},
                    UpdateExpression="ADD reactions.#e :u",
                    ExpressionAttributeNames=expr_names,
                    ExpressionAttributeValues={":u": {user_id}},
                )
            except Exception:
                # reactions map might not exist yet - create it
                T.broadcast_chat_messages.update_item(
                    Key={"session_id": session_id, "sort_key": sort_key},
                    UpdateExpression="SET reactions = if_not_exists(reactions, :empty)",
                    ExpressionAttributeValues={":empty": {}},
                )
                T.broadcast_chat_messages.update_item(
                    Key={"session_id": session_id, "sort_key": sort_key},
                    UpdateExpression="ADD reactions.#e :u",
                    ExpressionAttributeNames=expr_names,
                    ExpressionAttributeValues={":u": {user_id}},
                )
        else:
            try:
                T.broadcast_chat_messages.update_item(
                    Key={"session_id": session_id, "sort_key": sort_key},
                    UpdateExpression="DELETE reactions.#e :u",
                    ExpressionAttributeNames=expr_names,
                    ExpressionAttributeValues={":u": {user_id}},
                )
            except Exception:
                pass  # Removing from non-existent set is fine
    except Exception as e:
        logger.warning("broadcast.chat.react_failed: %s", str(e))
        raise HTTPException(400, f"Reaction update failed: {str(e)}")

    # Re-fetch to compute updated counts
    item = T.broadcast_chat_messages.get_item(
        Key={"session_id": session_id, "sort_key": sort_key}
    ).get("Item", {})
    counts = _build_reaction_counts(item)

    broadcast_sse_publish(session_id, {
        "_type": "chat:reaction",
        "message_id": message_id,
        "emoji": emoji,
        "action": action,
        "user_id": user_id,
        "counts": counts,
    })

    return {"ok": True, "reactions_counts": counts}


# ─── Phase D: Unlock ─────────────────────────────────────────────

def unlock_chat_message(
    session_id: str,
    message_id: str,
    user_id: str,
    payment_method_id: str,
    broadcaster_id: str,
) -> Dict[str, Any]:
    """Unlock a locked broadcast chat message by paying the lock price."""
    _enforce_rate_limit(
        _UNLOCK_RATE_BUCKETS, _UNLOCK_RATE_LOCK,
        f"{session_id}#{user_id}", _UNLOCK_RATE_MS,
        "BROADCAST_UNLOCK_RATE_LIMITED",
        "Unlock rate limited. Try again shortly.",
    )

    sort_key = _find_sort_key(session_id, message_id)
    if not sort_key:
        raise HTTPException(400, "Message not found")

    item = T.broadcast_chat_messages.get_item(
        Key={"session_id": session_id, "sort_key": sort_key}
    ).get("Item")
    if not item:
        raise HTTPException(400, "Message not found")
    if not item.get("lock_price_cents"):
        raise HTTPException(400, "Message is not locked")
    if item.get("sender_id") == user_id:
        raise HTTPException(400, "Sender cannot unlock their own message")
    if user_id in (item.get("unlocked_by") or {}):
        raise HTTPException(400, "Already unlocked")

    # Validate payment method
    pm_item = T.billing.get_item(
        Key={"pk": f"USER#{user_id}", "sk": f"PM#{payment_method_id}"}
    ).get("Item")
    if not pm_item:
        raise HTTPException(400, "Payment method not found")

    amount_cents = int(item["lock_price_cents"])
    unlock_payment_id = "bcunlock_" + uuid.uuid4().hex

    # Write billing
    _write_chat_billing(
        payer_id=user_id,
        recipient_id=broadcaster_id,
        amount_cents=amount_cents,
        reason="Broadcast chat message unlock",
        content_type="broadcast_chat_unlock",
        content_id=message_id,
        session_id=session_id,
        payment_method_id=payment_method_id,
    )

    # Update DDB
    T.broadcast_chat_messages.update_item(
        Key={"session_id": session_id, "sort_key": sort_key},
        UpdateExpression="SET unlocked_by.#uid = :pid",
        ExpressionAttributeNames={"#uid": user_id},
        ExpressionAttributeValues={":pid": unlock_payment_id},
    )

    broadcast_sse_publish(session_id, {
        "_type": "chat:unlock",
        "message_id": message_id,
        "user_id": user_id,
        "text": item.get("text", ""),
    })

    return {
        "ok": True,
        "message_id": message_id,
        "text": item.get("text", ""),
        "unlock_payment_id": unlock_payment_id,
        "amount_cents": amount_cents,
    }


# ─── Helpers ─────────────────────────────────────────────────────

def _find_sort_key(session_id: str, message_id: str) -> Optional[str]:
    """Find sort_key by message_id. Delegates to broadcast_chat_store."""
    from app.services.broadcast_chat_store import _find_sort_key as _find
    return _find(session_id, message_id)


def _build_reaction_counts(item: Dict[str, Any]) -> Dict[str, int]:
    """Compute reaction emoji counts from the reactions DDB map."""
    reactions = item.get("reactions") or {}
    counts: Dict[str, int] = {}
    for emoji, user_set in reactions.items():
        if isinstance(user_set, set):
            counts[emoji] = len(user_set)
        elif isinstance(user_set, dict):
            counts[emoji] = len(user_set)
    return counts


def _write_chat_billing(
    payer_id: str,
    recipient_id: str,
    amount_cents: int,
    reason: str,
    content_type: str,
    content_id: str,
    session_id: str,
    payment_method_id: str,
) -> tuple:
    """Write paired debit/credit billing ledger entries.

    The payer debit and recipient credit are committed atomically via DynamoDB
    ``TransactWriteItems`` so that either both ledger rows are written or neither
    is. On failure a ``RuntimeError`` is raised so the caller does not silently
    treat a half-completed (or failed) billing write as success — preventing a
    payer debit with no matching recipient credit, and preventing content from
    being unlocked when no debit was collected (GAP-0129).

    Returns (debit_entry_id, credit_entry_id).
    """
    # Imported at function scope to keep module-level imports minimal. The
    # low-level DynamoDB client is built using the SAME endpoint / region /
    # credential resolution as the table handles, so dev (DynamoDB Local) and
    # prod (AWS) behave identically (SECOPS-007 parity). TransactWriteItems is
    # only available on the low-level client, not on the resource Table API.
    import boto3
    from boto3.dynamodb.types import TypeSerializer
    from botocore.exceptions import ClientError

    from app.core.aws_clients import ddb_transact_client
    from app.core.settings import S

    ts = now_ts()
    debit_id = uuid.uuid4().hex
    credit_id = uuid.uuid4().hex
    platform_fee_pct = 20
    creator_amount = int(amount_cents * (100 - platform_fee_pct) / 100)

    meta = {
        "content_type": content_type,
        "content_id": content_id,
        "session_id": session_id,
        "payer_id": payer_id,
        "recipient_id": recipient_id,
        "payment_method_id": payment_method_id,
    }

    debit_row: Dict[str, Any] = {
        "pk": f"USER#{payer_id}",
        "sk": f"LEDGER#{ts}#{debit_id}",
        "entry_id": debit_id,
        "ts": ts,
        "type": "debit",
        "amount_cents": amount_cents,
        "currency": "USD",
        "state": "settled",
        "reason": reason,
        "meta": meta,
    }
    credit_row: Dict[str, Any] = {
        "pk": f"USER#{recipient_id}",
        "sk": f"LEDGER#{ts}#{credit_id}",
        "entry_id": credit_id,
        "ts": ts,
        "type": "credit",
        "amount_cents": creator_amount,
        "currency": "USD",
        "state": "settled",
        "reason": reason,
        "meta": meta,
    }

    # SECOPS/parity fix: use the shared transact client, which inherits the
    # SAME endpoint/region/creds as the app dynamodb resource (where the
    # billing table lives). Building a client off _ddb_endpoint_url() pointed
    # writes at DDB_ENDPOINT_URL, which in the dev split-brain setup (main
    # tables on AWS_ENDPOINT_URL) has no billing table -> ResourceNotFound 500.
    client = ddb_transact_client()
    serializer = TypeSerializer()
    table_name = S.billing_table_name

    def _serialize(row: Dict[str, Any]) -> Dict[str, Any]:
        return {k: serializer.serialize(v) for k, v in row.items()}

    try:
        client.transact_write_items(
            TransactItems=[
                {"Put": {"TableName": table_name, "Item": _serialize(debit_row)}},
                {"Put": {"TableName": table_name, "Item": _serialize(credit_row)}},
            ]
        )
    except ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code", "Unknown")
        logger.error(
            "broadcast_chat_billing_transact_failed payer=%s recipient=%s amount=%d error=%s",
            payer_id, recipient_id, amount_cents, error_code,
        )
        raise RuntimeError(
            f"Broadcast chat billing transaction failed ({error_code}): "
            f"payer={payer_id} recipient={recipient_id} amount={amount_cents}"
        ) from exc

    return debit_id, credit_id


def reset_rich_rate_limits() -> None:
    """Clear all rich-feature rate limit state (for tests)."""
    with _REACTION_RATE_LOCK:
        _REACTION_RATE_BUCKETS.clear()
    with _UNLOCK_RATE_LOCK:
        _UNLOCK_RATE_BUCKETS.clear()
    with _TIP_RATE_LOCK:
        _TIP_RATE_BUCKETS.clear()
