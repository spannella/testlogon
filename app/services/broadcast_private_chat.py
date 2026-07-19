"""Broadcast private chat service -- manages paid 1-on-1 text chat with voyeur mode (BCAST-012).

Handles:
  - Tier 1 (participant) and tier 2 (voyeur) purchases
  - Private chat message send/history
  - Chat extension, ending, and expiry
  - Chat settings on the broadcast session
  - Billing ledger writes (prepaid model)
"""

from __future__ import annotations

import logging
import time as _time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Attr, Key
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts
from app.services.broadcast_sse import broadcast_sse_publish
from app.services.content_filter import filter_message

logger = logging.getLogger("broadcast.private_chat")

DEFAULT_RATE_CENTS = 500          # $5.00/min default for tier 1
DEFAULT_VOYEUR_RATE_CENTS = 100   # $1.00/min default for tier 2
DEFAULT_PLATFORM_FEE_PCT = 20     # 20% platform fee
MAX_CONCURRENT_CHATS = 5


# ─── Purchase ─────────────────────────────────────────────────────


def purchase_private_chat(
    session_id: str,
    viewer_id: str,
    viewer_display_name: str,
    tier: int,
    duration_minutes: int,
    payment_method_id: str,
    rate_per_minute_cents: int,
    platform_fee_pct: int = DEFAULT_PLATFORM_FEE_PCT,
    *,
    chat_id: Optional[str] = None,
    creator_id: str,
    max_concurrent: int = MAX_CONCURRENT_CHATS,
) -> Dict[str, Any]:
    """Purchase a private chat session (tier 1) or voyeur access (tier 2).

    For tier 1: creates a new private chat item and starts the timer.
    For tier 2: creates a voyeur tracking item linked to an existing chat.
    Billing (debit/credit) is written immediately (prepaid model).

    Returns dict with purchase details suitable for API response.
    """
    ts = now_ts()
    total_cents = rate_per_minute_cents * duration_minutes
    platform_fee_cents = int(total_cents * platform_fee_pct / 100)
    creator_earnings_cents = total_cents - platform_fee_cents

    if tier == 1:
        active_count = _count_active_chats(session_id)
        if active_count >= max_concurrent:
            raise HTTPException(
                status_code=409,
                detail="Maximum number of concurrent private chats reached.",
            )

        new_chat_id = f"pchat_{uuid.uuid4().hex}"
        expires_at = ts + duration_minutes * 60

        item: Dict[str, Any] = {
            "pk": f"BCAST_PCHAT#{session_id}",
            "sk": f"CHAT#{new_chat_id}",
            "chat_id": new_chat_id,
            "session_id": session_id,
            "viewer_id": viewer_id,
            "viewer_display_name": viewer_display_name,
            "tier": 1,
            "rate_per_minute_cents": rate_per_minute_cents,
            "purchased_minutes": duration_minutes,
            "remaining_seconds": duration_minutes * 60,
            "total_paid_cents": total_cents,
            "platform_fee_cents": platform_fee_cents,
            "creator_earnings_cents": creator_earnings_cents,
            "status": "active",
            "payment_method_id": payment_method_id,
            "started_at": ts,
            "expires_at": expires_at,
            "ttl": ts + 90 * 24 * 3600,
        }
        T.broadcast_private_sessions.put_item(Item=item)

        debit_id, credit_id = _write_private_chat_billing(
            viewer_id=viewer_id,
            creator_id=creator_id,
            total_cents=total_cents,
            creator_earnings_cents=creator_earnings_cents,
            chat_id=new_chat_id,
            session_id=session_id,
            tier=1,
            duration_minutes=duration_minutes,
            payment_method_id=payment_method_id,
        )

        T.broadcast_private_sessions.update_item(
            Key={"pk": f"BCAST_PCHAT#{session_id}", "sk": f"CHAT#{new_chat_id}"},
            UpdateExpression="SET billing_debit_entry_id = :did, billing_credit_entry_id = :cid",
            ExpressionAttributeValues={":did": debit_id, ":cid": credit_id},
        )

        broadcast_sse_publish(session_id, {
            "_type": "private_chat:started",
            "chat_id": new_chat_id,
            "viewer_id": viewer_id,
            "viewer_display_name": viewer_display_name,
            "duration_minutes": duration_minutes,
            "expires_at": expires_at,
        })

        logger.info(
            "broadcast.private_chat.purchased session=%s viewer=%s tier=1 duration=%d total=%d",
            session_id, viewer_id, duration_minutes, total_cents,
        )

        return {
            "chat_id": new_chat_id,
            "session_id": session_id,
            "tier": 1,
            "duration_minutes": duration_minutes,
            "total_paid_cents": total_cents,
            "rate_per_minute_cents": rate_per_minute_cents,
            "expires_at": expires_at,
            "status": "active",
        }

    # ── Tier 2 (voyeur) ──────────────────────────────────────────

    target_chat = _get_private_chat(session_id, chat_id)  # type: ignore[arg-type]
    if not target_chat or target_chat.get("status") not in ("active", "expiring"):
        raise HTTPException(status_code=404, detail="Private chat not found or not active.")

    chat_expires = int(target_chat.get("expires_at", 0))
    voyeur_expires = min(ts + duration_minutes * 60, chat_expires)

    voyeur_item: Dict[str, Any] = {
        "pk": f"BCAST_PCHAT#{session_id}",
        "sk": f"VOYEUR#{chat_id}#{viewer_id}",
        "chat_id": chat_id,
        "session_id": session_id,
        "viewer_id": viewer_id,
        "viewer_display_name": viewer_display_name,
        "tier": 2,
        "rate_per_minute_cents": rate_per_minute_cents,
        "purchased_minutes": duration_minutes,
        "total_paid_cents": total_cents,
        "status": "active",
        "payment_method_id": payment_method_id,
        "started_at": ts,
        "expires_at": voyeur_expires,
        "ttl": ts + 90 * 24 * 3600,
    }
    T.broadcast_private_sessions.put_item(Item=voyeur_item)

    _write_private_chat_billing(
        viewer_id=viewer_id,
        creator_id=creator_id,
        total_cents=total_cents,
        creator_earnings_cents=creator_earnings_cents,
        chat_id=chat_id,  # type: ignore[arg-type]
        session_id=session_id,
        tier=2,
        duration_minutes=duration_minutes,
        payment_method_id=payment_method_id,
    )

    broadcast_sse_publish(session_id, {
        "_type": "private_chat:voyeur_joined",
        "chat_id": chat_id,
        "viewer_id": viewer_id,
        "viewer_display_name": viewer_display_name,
    })

    logger.info(
        "broadcast.private_chat.voyeur_joined session=%s chat=%s voyeur=%s",
        session_id, chat_id, viewer_id,
    )

    return {
        "chat_id": chat_id,  # type: ignore[dict-item]
        "session_id": session_id,
        "tier": 2,
        "duration_minutes": duration_minutes,
        "total_paid_cents": total_cents,
        "rate_per_minute_cents": rate_per_minute_cents,
        "expires_at": voyeur_expires,
        "status": "active",
    }


# ─── Messaging ────────────────────────────────────────────────────


def send_private_chat_message(
    session_id: str,
    chat_id: str,
    sender_id: str,
    sender_display_name: str,
    text: str,
) -> Dict[str, Any]:
    """Send a message in a private chat.

    Only the tier-1 viewer and the session creator may call this.
    Messages are stored in the existing broadcast_chat_messages table
    with a ``private_chat_id`` field for scoping.

    The message text is passed through the content filter; blocked words
    are replaced with asterisks.
    """
    # Content filter
    filtered_text, was_filtered = filter_message(text.strip())

    ts = now_ts()
    ts_ms = int(_time.time() * 1000)
    msg_id = "pcm_" + uuid.uuid4().hex
    sort_key = f"{ts_ms:016d}#{msg_id}"

    item: Dict[str, Any] = {
        "session_id": session_id,
        "sort_key": sort_key,
        "message_id": msg_id,
        "sender_id": sender_id,
        "sender_display_name": sender_display_name,
        "text": filtered_text,
        "kind": "private_chat",
        "private_chat_id": chat_id,
        "created_at": ts,
        "deleted": False,
        "filtered": was_filtered,
        "ttl": ts + 7 * 24 * 3600,
    }
    T.broadcast_chat_messages.put_item(Item=item)

    out = _private_chat_msg_out(item)
    broadcast_sse_publish(session_id, {"_type": "private_chat:message", **out})

    return out


def get_private_chat_history(
    session_id: str,
    chat_id: str,
    limit: int = 100,
    before_sort_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Get message history for a private chat, filtered by private_chat_id."""
    kce = Key("session_id").eq(session_id)
    if before_sort_key:
        kce = kce & Key("sort_key").lt(before_sort_key)

    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": kce,
        "FilterExpression": Attr("private_chat_id").eq(chat_id) & Attr("deleted").ne(True),
        "Limit": limit * 3,  # over-fetch to compensate for filter
        "ScanIndexForward": False,
    }

    resp = T.broadcast_chat_messages.query(**kwargs)
    items = resp.get("Items", [])
    items = items[:limit]
    items.reverse()  # chronological order

    messages = [_private_chat_msg_out(item) for item in items]
    return {
        "messages": messages,
        "has_more": len(resp.get("Items", [])) > limit or bool(resp.get("LastEvaluatedKey")),
        "oldest_sort_key": items[0]["sort_key"] if items else None,
    }


# ─── End / Extend ────────────────────────────────────────────────


def end_private_chat(
    session_id: str,
    chat_id: str,
    ended_reason: str,
) -> bool:
    """End a private chat and all associated voyeur sessions.

    Returns True if found and ended, False if not found.
    """
    chat = _get_private_chat(session_id, chat_id)
    if not chat:
        return False

    ts = now_ts()
    T.broadcast_private_sessions.update_item(
        Key={"pk": f"BCAST_PCHAT#{session_id}", "sk": f"CHAT#{chat_id}"},
        UpdateExpression="SET #st = :status, ended_at = :ea, ended_reason = :er",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":status": "ended", ":ea": ts, ":er": ended_reason},
    )

    _end_voyeurs_for_chat(session_id, chat_id, ts)

    broadcast_sse_publish(session_id, {
        "_type": "private_chat:ended",
        "chat_id": chat_id,
        "ended_reason": ended_reason,
    })

    logger.info(
        "broadcast.private_chat.ended session=%s chat=%s reason=%s",
        session_id, chat_id, ended_reason,
    )
    return True


def extend_private_chat(
    session_id: str,
    chat_id: str,
    viewer_id: str,
    additional_minutes: int,
    payment_method_id: str,
    rate_per_minute_cents: int,
    platform_fee_pct: int,
    creator_id: str,
    *,
    is_voyeur: bool = False,
) -> Dict[str, Any]:
    """Extend a private chat or voyeur session by purchasing more time."""
    ts = now_ts()
    additional_cents = rate_per_minute_cents * additional_minutes
    platform_fee_cents = int(additional_cents * platform_fee_pct / 100)
    creator_earnings_cents = additional_cents - platform_fee_cents

    sk = f"VOYEUR#{chat_id}#{viewer_id}" if is_voyeur else f"CHAT#{chat_id}"

    item = T.broadcast_private_sessions.get_item(
        Key={"pk": f"BCAST_PCHAT#{session_id}", "sk": sk}
    ).get("Item")
    if not item or item.get("status") not in ("active", "expiring"):
        raise HTTPException(status_code=409, detail="Chat session is not active.")

    current_expires = int(item.get("expires_at", ts))
    new_expires = max(current_expires, ts) + additional_minutes * 60
    new_purchased = int(item.get("purchased_minutes", 0)) + additional_minutes
    new_total = int(item.get("total_paid_cents", 0)) + additional_cents

    T.broadcast_private_sessions.update_item(
        Key={"pk": f"BCAST_PCHAT#{session_id}", "sk": sk},
        UpdateExpression=(
            "SET expires_at = :exp, purchased_minutes = :pm, "
            "total_paid_cents = :tp, #st = :status"
        ),
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={
            ":exp": new_expires,
            ":pm": new_purchased,
            ":tp": new_total,
            ":status": "active",
        },
    )

    _write_private_chat_billing(
        viewer_id=viewer_id,
        creator_id=creator_id,
        total_cents=additional_cents,
        creator_earnings_cents=creator_earnings_cents,
        chat_id=chat_id,
        session_id=session_id,
        tier=2 if is_voyeur else 1,
        duration_minutes=additional_minutes,
        payment_method_id=payment_method_id,
    )

    return {
        "chat_id": chat_id,
        "session_id": session_id,
        "expires_at": new_expires,
        "purchased_minutes": new_purchased,
        "total_paid_cents": new_total,
        "status": "active",
    }


# ─── Queries ──────────────────────────────────────────────────────


def get_chat_status(session_id: str, chat_id: str) -> Optional[Dict[str, Any]]:
    """Return status of a private chat including time remaining and voyeur count."""
    chat = _get_private_chat(session_id, chat_id)
    if not chat:
        return None

    ts = now_ts()
    remaining = max(0, int(chat.get("expires_at", 0)) - ts)
    voyeur_count = _count_voyeurs(session_id, chat_id)

    return {
        "chat_id": chat_id,
        "session_id": session_id,
        "viewer_id": chat.get("viewer_id", ""),
        "viewer_display_name": chat.get("viewer_display_name", ""),
        "status": chat.get("status", ""),
        "tier": int(chat.get("tier", 1)),
        "rate_per_minute_cents": int(chat.get("rate_per_minute_cents", 0)),
        "purchased_minutes": int(chat.get("purchased_minutes", 0)),
        "remaining_seconds": remaining,
        "started_at": int(chat.get("started_at", 0)),
        "expires_at": int(chat.get("expires_at", 0)),
        "voyeur_count": voyeur_count,
    }


def list_active_chats(session_id: str) -> List[Dict[str, Any]]:
    """List all active private chats for a broadcast (creator view)."""
    resp = T.broadcast_private_sessions.query(
        KeyConditionExpression=(
            Key("pk").eq(f"BCAST_PCHAT#{session_id}")
            & Key("sk").begins_with("CHAT#")
        ),
        FilterExpression=Attr("status").is_in(["active", "expiring"]),
    )
    chats = resp.get("Items", [])
    ts = now_ts()
    out: List[Dict[str, Any]] = []
    for chat in chats:
        voyeur_count = _count_voyeurs(session_id, chat["chat_id"])
        remaining = max(0, int(chat.get("expires_at", 0)) - ts)
        out.append({
            "chat_id": chat["chat_id"],
            "viewer_id": chat["viewer_id"],
            "viewer_display_name": chat.get("viewer_display_name", ""),
            "tier": int(chat.get("tier", 1)),
            "rate_per_minute_cents": int(chat.get("rate_per_minute_cents", 0)),
            "purchased_minutes": int(chat.get("purchased_minutes", 0)),
            "remaining_seconds": remaining,
            "status": chat["status"],
            "started_at": int(chat.get("started_at", 0)),
            "expires_at": int(chat.get("expires_at", 0)),
            "voyeur_count": voyeur_count,
            "total_revenue_cents": int(chat.get("total_paid_cents", 0)),
        })
    out.sort(key=lambda x: x["started_at"])
    return out


# ─── Settings ─────────────────────────────────────────────────────


def update_chat_settings(
    session_id: str,
    settings: Dict[str, Any],
) -> Dict[str, Any]:
    """Update private chat pricing settings on a broadcast session."""
    update_parts: List[str] = []
    expr_values: Dict[str, Any] = {}

    field_map = {
        "private_chat_enabled": ":pce",
        "private_chat_rate_per_minute_cents": ":pcr",
        "voyeur_rate_per_minute_cents": ":vrr",
        "private_chat_time_blocks": ":pctb",
        "private_chat_max_concurrent": ":pcmc",
    }

    for field, placeholder in field_map.items():
        if field in settings and settings[field] is not None:
            update_parts.append(f"{field} = {placeholder}")
            expr_values[placeholder] = settings[field]

    if not update_parts:
        return settings

    T.broadcast_sessions.update_item(
        Key={"session_id": session_id},
        UpdateExpression="SET " + ", ".join(update_parts),
        ExpressionAttributeValues=expr_values,
    )

    return settings


# ─── Expiry Background Task ──────────────────────────────────────


def check_and_expire_chats() -> int:
    """Check all active private chats and expire those past their expires_at.

    For dev/MVP we scan the table — acceptable at low scale.
    Returns the number of chats expired.
    """
    expired_count = 0
    ts = now_ts()

    # Scan for active chats (CHAT# items)
    try:
        resp = T.broadcast_private_sessions.scan(
            FilterExpression=Attr("status").is_in(["active", "expiring"])
            & Attr("sk").begins_with("CHAT#"),
            Limit=200,
        )
    except Exception:
        logger.exception("check_and_expire_chats scan failed")
        return 0

    for item in resp.get("Items", []):
        expires_at = int(item.get("expires_at", 0))
        session_id = item.get("session_id", "")
        chat_id = item.get("chat_id", "")

        if expires_at <= ts:
            end_private_chat(session_id, chat_id, "expired")
            expired_count += 1
        elif expires_at - ts <= 60 and item.get("status") == "active":
            # Transition to expiring
            T.broadcast_private_sessions.update_item(
                Key={"pk": item["pk"], "sk": item["sk"]},
                UpdateExpression="SET #st = :status",
                ExpressionAttributeNames={"#st": "status"},
                ExpressionAttributeValues={":status": "expiring"},
            )
            broadcast_sse_publish(session_id, {
                "_type": "private_chat:expiring",
                "chat_id": chat_id,
                "remaining_seconds": max(0, expires_at - ts),
            })

    return expired_count


# ─── Internal Helpers ─────────────────────────────────────────────


def _get_private_chat(session_id: str, chat_id: str) -> Optional[Dict[str, Any]]:
    """Fetch a private chat item from DDB."""
    return T.broadcast_private_sessions.get_item(
        Key={"pk": f"BCAST_PCHAT#{session_id}", "sk": f"CHAT#{chat_id}"}
    ).get("Item")


def get_private_chat(session_id: str, chat_id: str) -> Optional[Dict[str, Any]]:
    """Public accessor for _get_private_chat."""
    return _get_private_chat(session_id, chat_id)


def _count_active_chats(session_id: str) -> int:
    """Count active private chats for a session."""
    resp = T.broadcast_private_sessions.query(
        KeyConditionExpression=(
            Key("pk").eq(f"BCAST_PCHAT#{session_id}")
            & Key("sk").begins_with("CHAT#")
        ),
        FilterExpression=Attr("status").is_in(["active", "expiring"]),
        Select="COUNT",
    )
    return resp.get("Count", 0)


def _count_voyeurs(session_id: str, chat_id: str) -> int:
    """Count active voyeurs for a specific private chat."""
    resp = T.broadcast_private_sessions.query(
        KeyConditionExpression=(
            Key("pk").eq(f"BCAST_PCHAT#{session_id}")
            & Key("sk").begins_with(f"VOYEUR#{chat_id}#")
        ),
        FilterExpression=Attr("status").eq("active"),
        Select="COUNT",
    )
    return resp.get("Count", 0)


def get_voyeur_item(session_id: str, chat_id: str, viewer_id: str) -> Optional[Dict[str, Any]]:
    """Fetch a voyeur tracking item."""
    return T.broadcast_private_sessions.get_item(
        Key={"pk": f"BCAST_PCHAT#{session_id}", "sk": f"VOYEUR#{chat_id}#{viewer_id}"}
    ).get("Item")


def _end_voyeurs_for_chat(session_id: str, chat_id: str, ts: int) -> None:
    """End all active voyeur sessions for a chat."""
    resp = T.broadcast_private_sessions.query(
        KeyConditionExpression=(
            Key("pk").eq(f"BCAST_PCHAT#{session_id}")
            & Key("sk").begins_with(f"VOYEUR#{chat_id}#")
        ),
        FilterExpression=Attr("status").eq("active"),
    )
    for item in resp.get("Items", []):
        T.broadcast_private_sessions.update_item(
            Key={"pk": item["pk"], "sk": item["sk"]},
            UpdateExpression="SET #st = :status, ended_at = :ea, ended_reason = :er",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={":status": "ended", ":ea": ts, ":er": "parent_chat_ended"},
        )


def _write_private_chat_billing(
    viewer_id: str,
    creator_id: str,
    total_cents: int,
    creator_earnings_cents: int,
    chat_id: str,
    session_id: str,
    tier: int,
    duration_minutes: int,
    payment_method_id: str,
) -> Tuple[str, str]:
    """Write paired debit/credit billing ledger entries.

    The viewer debit and creator credit are committed atomically via DynamoDB
    ``TransactWriteItems`` so that either both ledger rows are written or neither
    is. On failure a ``RuntimeError`` is raised so the caller does not silently
    treat a half-completed (or failed) billing write as success — preventing a
    viewer debit with no matching creator credit (GAP-0126).

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

    # SECOPS/parity fix: use the shared transact client, which inherits the
    # SAME endpoint/region/creds as the app dynamodb resource (where the
    # billing table lives). Building a client off _ddb_endpoint_url() pointed
    # writes at DDB_ENDPOINT_URL, which in the dev split-brain setup (main
    # tables on AWS_ENDPOINT_URL) has no billing table -> ResourceNotFound 500.
    client = ddb_transact_client()

    ts = now_ts()
    debit_id = uuid.uuid4().hex
    credit_id = uuid.uuid4().hex
    reason = f"Private chat: tier {tier}"
    meta: Dict[str, Any] = {
        "content_type": "private_chat",
        "chat_id": chat_id,
        "session_id": session_id,
        "tier": tier,
        "duration_minutes": duration_minutes,
        "viewer_id": viewer_id,
        "creator_id": creator_id,
        "payment_method_id": payment_method_id,
    }

    debit_row: Dict[str, Any] = {
        "pk": f"USER#{viewer_id}",
        "sk": f"LEDGER#{ts}#{debit_id}",
        "entry_id": debit_id,
        "ts": ts,
        "type": "debit",
        "amount_cents": total_cents,
        "currency": "USD",
        "state": "settled",
        "reason": reason,
        "meta": meta,
    }
    credit_row: Dict[str, Any] = {
        "pk": f"USER#{creator_id}",
        "sk": f"LEDGER#{ts}#{credit_id}",
        "entry_id": credit_id,
        "ts": ts,
        "type": "credit",
        "amount_cents": creator_earnings_cents,
        "currency": "USD",
        "state": "settled",
        "reason": reason,
        "meta": meta,
    }

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
            "private_chat_billing_transact_failed viewer=%s creator=%s total=%d error=%s",
            viewer_id, creator_id, total_cents, error_code,
        )
        raise RuntimeError(
            f"Private chat billing transaction failed ({error_code}): "
            f"viewer={viewer_id} creator={creator_id} total={total_cents}"
        ) from exc

    return debit_id, credit_id


def _private_chat_msg_out(item: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a private chat message DDB item to output dict."""
    return {
        "message_id": item["message_id"],
        "session_id": item["session_id"],
        "sender_id": item["sender_id"],
        "sender_display_name": item.get("sender_display_name", ""),
        "text": item.get("text", ""),
        "kind": item.get("kind", "private_chat"),
        "private_chat_id": item.get("private_chat_id"),
        "created_at": int(item.get("created_at", 0)),
        "deleted": bool(item.get("deleted", False)),
        "filtered": bool(item.get("filtered", False)),
    }
