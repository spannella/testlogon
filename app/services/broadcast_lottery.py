"""Broadcast chat lottery service -- create, enter, close, draw (BCAST-014)."""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Dict, List, Optional, Sequence, Mapping
from uuid import uuid4

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.broadcast_sse import broadcast_sse_publish
from app.services.messaging_lottery_store import _normalized_outcomes, LotteryConfigValidationError
from app.services.messaging_lottery_rng import choose_weighted_outcome

logger = logging.getLogger(__name__)

# --- Lottery States --------------------------------------------------------

LOTTERY_STATES = {"open", "entries_closed", "drawn"}
LOTTERY_TRANSITIONS = {
    "open": {"entries_closed", "drawn"},
    "entries_closed": {"drawn"},
    "drawn": set(),
}

# --- Rate Limiting (in-memory) --------------------------------------------

_LOTTERY_RATE_LOCK = threading.Lock()
_LOTTERY_CREATE_BUCKETS: Dict[str, int] = {}
_LOTTERY_ENTRY_BUCKETS: Dict[str, int] = {}

LOTTERY_CREATE_COOLDOWN_MS = 30_000
LOTTERY_ENTRY_COOLDOWN_MS = 2_000


def _enforce_lottery_create_rate_limit(session_id: str, user_id: str) -> None:
    key = f"{session_id}#{user_id}"
    now_ms = int(time.time() * 1000)
    with _LOTTERY_RATE_LOCK:
        last = _LOTTERY_CREATE_BUCKETS.get(key, 0)
        if now_ms - last < LOTTERY_CREATE_COOLDOWN_MS:
            from fastapi import HTTPException
            raise HTTPException(
                status_code=429,
                detail={
                    "code": "BROADCAST_LOTTERY_CREATE_RATE_LIMITED",
                    "message": f"You can create one lottery every {LOTTERY_CREATE_COOLDOWN_MS // 1000} seconds.",
                    "retry_after_ms": LOTTERY_CREATE_COOLDOWN_MS - (now_ms - last),
                },
            )
        _LOTTERY_CREATE_BUCKETS[key] = now_ms


def _enforce_lottery_entry_rate_limit(session_id: str, user_id: str) -> None:
    key = f"{session_id}#{user_id}"
    now_ms = int(time.time() * 1000)
    with _LOTTERY_RATE_LOCK:
        last = _LOTTERY_ENTRY_BUCKETS.get(key, 0)
        if now_ms - last < LOTTERY_ENTRY_COOLDOWN_MS:
            from fastapi import HTTPException
            raise HTTPException(
                status_code=429,
                detail={
                    "code": "BROADCAST_LOTTERY_ENTRY_RATE_LIMITED",
                    "message": "You can enter one lottery every 2 seconds.",
                    "retry_after_ms": LOTTERY_ENTRY_COOLDOWN_MS - (now_ms - last),
                },
            )
        _LOTTERY_ENTRY_BUCKETS[key] = now_ms


def reset_lottery_rate_limits() -> None:
    """Clear all lottery rate limit state (for tests)."""
    with _LOTTERY_RATE_LOCK:
        _LOTTERY_CREATE_BUCKETS.clear()
        _LOTTERY_ENTRY_BUCKETS.clear()


# --- Create Lottery -------------------------------------------------------

def create_lottery(
    *,
    session_id: str,
    broadcaster_id: str,
    display_name: str,
    title: str,
    outcomes: Sequence[Mapping[str, Any]],
    max_entries: Optional[int] = None,
    entry_fee_cents: int = 0,
    duration_seconds: Optional[int] = None,
) -> Dict[str, Any]:
    """Create a lottery in a broadcast chat session."""
    _enforce_lottery_create_rate_limit(session_id, broadcaster_id)

    normalized = _normalized_outcomes(outcomes)

    ts = now_ts()
    ts_ms = int(time.time() * 1000)
    lottery_id = "lot_" + uuid4().hex
    msg_id = "cm_" + uuid4().hex
    sort_key = f"{ts_ms:016d}#{msg_id}"

    closes_at = (ts + duration_seconds) if duration_seconds else None

    # Item 1: Chat message (appears in chat history)
    chat_item: Dict[str, Any] = {
        "session_id": session_id,
        "sort_key": sort_key,
        "message_id": msg_id,
        "sender_id": broadcaster_id,
        "sender_display_name": display_name,
        "text": title,
        "kind": "lottery",
        "lottery_id": lottery_id,
        "created_at": ts,
        "deleted": False,
        "ttl": ts + 7 * 24 * 3600,
    }
    T.broadcast_chat_messages.put_item(Item=chat_item)

    # Item 2: Lottery config (mutable state)
    config_item: Dict[str, Any] = {
        "session_id": session_id,
        "sort_key": f"LOTTERY#{lottery_id}",
        "lottery_id": lottery_id,
        "message_id": msg_id,
        "broadcaster_id": broadcaster_id,
        "title": title,
        "outcomes": normalized,
        "total_weight_bps": 10_000,
        "max_entries": max_entries,
        "entry_fee_cents": entry_fee_cents,
        "currency": "USD",
        "duration_seconds": duration_seconds,
        "closes_at": closes_at,
        "status": "open",
        "entry_count": 0,
        "created_at": ts,
        "updated_at": ts,
        "drawn_at": None,
    }
    T.broadcast_chat_messages.put_item(Item=config_item)

    broadcast_sse_publish(session_id, {
        "_type": "lottery:created",
        "lottery_id": lottery_id,
        "message_id": msg_id,
        "title": title,
        "broadcaster_id": broadcaster_id,
        "entry_fee_cents": entry_fee_cents,
        "max_entries": max_entries,
        "closes_at": closes_at,
        "outcome_count": len(normalized),
    })

    return config_item


# --- Enter Lottery --------------------------------------------------------

def enter_lottery(
    *,
    session_id: str,
    lottery_id: str,
    user_id: str,
    display_name: str,
    payment_method_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Register a viewer's entry into a broadcast lottery."""
    from botocore.exceptions import ClientError

    # Check for existing entry first (before rate limit) for idempotent returns
    existing_entry = get_lottery_entry(session_id, lottery_id, user_id)
    if existing_entry:
        return {"entry": existing_entry, "already_entered": True}

    _enforce_lottery_entry_rate_limit(session_id, user_id)

    # Enforce mute check
    from app.services.broadcast_chat_store import _enforce_chat_mute
    _enforce_chat_mute(session_id, user_id)

    config = get_lottery_config(session_id, lottery_id)
    if not config:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail={"code": "LOTTERY_NOT_FOUND", "message": "Lottery not found"})

    # Broadcaster cannot enter own lottery
    if user_id == config["broadcaster_id"]:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=403,
            detail={"code": "BROADCASTER_CANNOT_ENTER", "message": "Broadcaster cannot enter their own lottery"},
        )

    if config["status"] != "open":
        from fastapi import HTTPException
        raise HTTPException(
            status_code=409,
            detail={"code": "LOTTERY_NOT_OPEN", "message": "Lottery is no longer accepting entries"},
        )

    # Check max entries
    if config.get("max_entries") and int(config["entry_count"]) >= int(config["max_entries"]):
        from fastapi import HTTPException
        raise HTTPException(
            status_code=409,
            detail={"code": "LOTTERY_FULL", "message": "Lottery has reached maximum entries"},
        )

    # Check closes_at
    ts = now_ts()
    closes_at = config.get("closes_at")
    if closes_at is not None and ts >= int(closes_at):
        _transition_lottery_status(session_id, lottery_id, "entries_closed", ts)
        from fastapi import HTTPException
        raise HTTPException(
            status_code=409,
            detail={"code": "LOTTERY_CLOSED", "message": "Lottery entry period has ended"},
        )

    # Validate and charge entry fee if required
    entry_fee_cents = int(config.get("entry_fee_cents", 0) or 0)
    fee_payment_id = None
    if entry_fee_cents > 0:
        fee_payment_id = _charge_entry_fee(
            user_id=user_id,
            broadcaster_id=config["broadcaster_id"],
            entry_fee_cents=entry_fee_cents,
            lottery_id=lottery_id,
            session_id=session_id,
            payment_method_id=payment_method_id,
        )

    # Write entry item (idempotent)
    entry_item: Dict[str, Any] = {
        "session_id": session_id,
        "sort_key": f"LENTRY#{lottery_id}#{user_id}",
        "lottery_id": lottery_id,
        "user_id": user_id,
        "display_name": display_name,
        "entered_at": ts,
        "entry_fee_cents": entry_fee_cents,
        "fee_payment_id": fee_payment_id,
        "outcome_id": None,
        "rng_roll": None,
    }
    try:
        T.broadcast_chat_messages.put_item(
            Item=entry_item,
            ConditionExpression="attribute_not_exists(sort_key)",
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            existing = T.broadcast_chat_messages.get_item(
                Key={"session_id": session_id, "sort_key": f"LENTRY#{lottery_id}#{user_id}"},
            ).get("Item", entry_item)
            return {"entry": existing, "already_entered": True}
        raise

    # Atomically increment entry count
    T.broadcast_chat_messages.update_item(
        Key={"session_id": session_id, "sort_key": f"LOTTERY#{lottery_id}"},
        UpdateExpression="SET entry_count = entry_count + :one, updated_at = :ts",
        ExpressionAttributeValues={":one": 1, ":ts": ts},
    )

    new_count = int(config["entry_count"]) + 1
    broadcast_sse_publish(session_id, {
        "_type": "lottery:entry",
        "lottery_id": lottery_id,
        "entry_count": new_count,
        "user_id": user_id,
        "display_name": display_name,
    })

    return {"entry": entry_item, "already_entered": False}


# --- Close Entries --------------------------------------------------------

def close_lottery_entries(
    *,
    session_id: str,
    lottery_id: str,
    actor_id: str,
) -> Dict[str, Any]:
    """Close entries for a lottery (broadcaster only)."""
    config = get_lottery_config(session_id, lottery_id)
    if not config:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail={"code": "LOTTERY_NOT_FOUND", "message": "Lottery not found"})

    if config["broadcaster_id"] != actor_id:
        from fastapi import HTTPException
        raise HTTPException(status_code=403, detail={"code": "NOT_BROADCASTER", "message": "Only the broadcaster can close entries"})

    if config["status"] != "open":
        from fastapi import HTTPException
        raise HTTPException(
            status_code=409,
            detail={"code": "LOTTERY_NOT_OPEN", "message": f"Lottery is already {config['status']}"},
        )

    ts = now_ts()
    _transition_lottery_status(session_id, lottery_id, "entries_closed", ts)

    broadcast_sse_publish(session_id, {
        "_type": "lottery:closed",
        "lottery_id": lottery_id,
        "entry_count": int(config.get("entry_count", 0)),
    })

    config["status"] = "entries_closed"
    config["updated_at"] = ts
    return config


# --- Draw -----------------------------------------------------------------

def draw_lottery(
    *,
    session_id: str,
    lottery_id: str,
    actor_id: str,
) -> Dict[str, Any]:
    """Execute the lottery draw."""
    config = get_lottery_config(session_id, lottery_id)
    if not config:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail={"code": "LOTTERY_NOT_FOUND", "message": "Lottery not found"})

    if config["broadcaster_id"] != actor_id:
        from fastapi import HTTPException
        raise HTTPException(status_code=403, detail={"code": "NOT_BROADCASTER", "message": "Only the broadcaster can draw"})

    if config["status"] == "drawn":
        results = _get_draw_results(session_id, lottery_id)
        return {"lottery_id": lottery_id, "status": "drawn", "results": results, "idempotent": True}

    if config["status"] not in ("open", "entries_closed"):
        from fastapi import HTTPException
        raise HTTPException(
            status_code=409,
            detail={"code": "LOTTERY_INVALID_STATE", "message": f"Cannot draw from state {config['status']}"},
        )

    ts = now_ts()
    outcomes = config["outcomes"]

    entries = _list_entries(session_id, lottery_id)
    if not entries:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=409,
            detail={"code": "LOTTERY_NO_ENTRIES", "message": "Cannot draw with zero entries"},
        )

    results: List[Dict[str, Any]] = []
    for entry in entries:
        selected, rng_roll = choose_weighted_outcome(outcomes)

        T.broadcast_chat_messages.update_item(
            Key={"session_id": session_id, "sort_key": entry["sort_key"]},
            UpdateExpression="SET outcome_id = :oid, rng_roll = :roll, drawn_at = :ts",
            ExpressionAttributeValues={
                ":oid": selected["outcome_id"],
                ":roll": rng_roll,
                ":ts": ts,
            },
        )

        results.append({
            "user_id": entry["user_id"],
            "display_name": entry.get("display_name", ""),
            "outcome_id": selected["outcome_id"],
            "display_label": selected.get("display_label"),
            "payload_type": selected["payload_type"],
            "text_content": selected.get("text_content"),
            "media_asset_id": selected.get("media_asset_id"),
            "rng_roll": rng_roll,
        })

    _transition_lottery_status(session_id, lottery_id, "drawn", ts)

    T.broadcast_chat_messages.update_item(
        Key={"session_id": session_id, "sort_key": f"LOTTERY#{lottery_id}"},
        UpdateExpression="SET drawn_at = :ts",
        ExpressionAttributeValues={":ts": ts},
    )

    broadcast_sse_publish(session_id, {
        "_type": "lottery:result",
        "lottery_id": lottery_id,
        "results": results,
        "drawn_at": ts,
    })

    return {"lottery_id": lottery_id, "status": "drawn", "results": results, "idempotent": False}


# --- Helpers --------------------------------------------------------------

def get_lottery_config(session_id: str, lottery_id: str) -> Optional[Dict[str, Any]]:
    """Fetch the mutable lottery config item."""
    resp = T.broadcast_chat_messages.get_item(
        Key={"session_id": session_id, "sort_key": f"LOTTERY#{lottery_id}"},
    )
    return resp.get("Item")


def get_lottery_entry(session_id: str, lottery_id: str, user_id: str) -> Optional[Dict[str, Any]]:
    """Check if a user has entered a specific lottery."""
    resp = T.broadcast_chat_messages.get_item(
        Key={"session_id": session_id, "sort_key": f"LENTRY#{lottery_id}#{user_id}"},
    )
    return resp.get("Item")


def _list_entries(session_id: str, lottery_id: str, limit: int = 1000) -> List[Dict[str, Any]]:
    """Fetch all entry items for a lottery."""
    entries: List[Dict[str, Any]] = []
    last_key = None
    prefix = f"LENTRY#{lottery_id}#"

    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("session_id").eq(session_id) & Key("sort_key").begins_with(prefix),
            "Limit": min(limit - len(entries), 500),
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.broadcast_chat_messages.query(**kwargs)
        entries.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key or len(entries) >= limit:
            break

    return entries


def _get_draw_results(session_id: str, lottery_id: str) -> List[Dict[str, Any]]:
    """Fetch stored draw results from entry items."""
    entries = _list_entries(session_id, lottery_id)
    config = get_lottery_config(session_id, lottery_id)
    outcomes_by_id: Dict[str, Dict[str, Any]] = {}
    if config:
        outcomes_by_id = {o["outcome_id"]: o for o in (config.get("outcomes") or [])}

    results: List[Dict[str, Any]] = []
    for entry in entries:
        oid = entry.get("outcome_id")
        if not oid:
            continue
        outcome = outcomes_by_id.get(oid, {})
        results.append({
            "user_id": entry["user_id"],
            "display_name": entry.get("display_name", ""),
            "outcome_id": oid,
            "display_label": outcome.get("display_label"),
            "payload_type": outcome.get("payload_type"),
            "text_content": outcome.get("text_content"),
            "media_asset_id": outcome.get("media_asset_id"),
            "rng_roll": int(entry.get("rng_roll", 0)),
        })
    return results


def _transition_lottery_status(session_id: str, lottery_id: str, new_status: str, ts: int) -> None:
    """Update the status field on the lottery config item."""
    T.broadcast_chat_messages.update_item(
        Key={"session_id": session_id, "sort_key": f"LOTTERY#{lottery_id}"},
        UpdateExpression="SET #st = :s, updated_at = :ts",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":s": new_status, ":ts": ts},
    )


def _charge_entry_fee(
    *,
    user_id: str,
    broadcaster_id: str,
    entry_fee_cents: int,
    lottery_id: str,
    session_id: str,
    payment_method_id: Optional[str] = None,
) -> str:
    """Charge the entry fee and write billing ledger entries."""
    import uuid
    from app.core.aws import ddb

    ts = now_ts()
    fee_payment_id = "lotfee_" + uuid.uuid4().hex

    billing_tbl = ddb.Table(S.billing_table_name)
    if payment_method_id:
        pm_resp = billing_tbl.get_item(Key={"pk": f"USER#{user_id}", "sk": f"PM#{payment_method_id}"})
        if not pm_resp.get("Item"):
            from fastapi import HTTPException
            raise HTTPException(status_code=400, detail="Payment method not found")
    else:
        billing_resp = billing_tbl.get_item(Key={"pk": f"USER#{user_id}", "sk": "BILLING"})
        billing_item = billing_resp.get("Item")
        if not billing_item or not billing_item.get("default_payment_method_id"):
            from fastapi import HTTPException
            raise HTTPException(
                status_code=400,
                detail={"code": "NO_PAYMENT_METHOD", "message": "Add a payment method in Billing to enter paid lotteries"},
            )
        payment_method_id = billing_item["default_payment_method_id"]

    try:
        debit_entry_id = uuid.uuid4().hex
        billing_tbl.put_item(Item={
            "pk": f"USER#{user_id}",
            "sk": f"LEDGER#{ts}#{debit_entry_id}",
            "entry_id": debit_entry_id,
            "ts": ts,
            "type": "debit",
            "amount_cents": entry_fee_cents,
            "currency": "USD",
            "state": "settled",
            "reason": "Lottery entry fee",
            "meta": {
                "lottery_id": lottery_id,
                "session_id": session_id,
                "fee_payment_id": fee_payment_id,
                "payment_method_id": payment_method_id,
            },
        })
    except Exception:
        logger.exception("Failed to write lottery entry fee debit user=%s lottery=%s", user_id, lottery_id)

    try:
        credit_entry_id = uuid.uuid4().hex
        billing_tbl.put_item(Item={
            "pk": f"USER#{broadcaster_id}",
            "sk": f"LEDGER#{ts}#{credit_entry_id}",
            "entry_id": credit_entry_id,
            "ts": ts,
            "type": "credit",
            "amount_cents": entry_fee_cents,
            "currency": "USD",
            "state": "settled",
            "reason": "Lottery entry fee received",
            "meta": {
                "lottery_id": lottery_id,
                "session_id": session_id,
                "fee_payment_id": fee_payment_id,
                "from_user_id": user_id,
            },
        })
    except Exception:
        logger.exception("Failed to write lottery entry fee credit broadcaster=%s lottery=%s", broadcaster_id, lottery_id)

    return fee_payment_id


def get_lottery_status_for_viewer(
    session_id: str,
    lottery_id: str,
    viewer_id: str,
) -> Optional[Dict[str, Any]]:
    """Get lottery state from a specific viewer's perspective."""
    config = get_lottery_config(session_id, lottery_id)
    if not config:
        return None

    entry = get_lottery_entry(session_id, lottery_id, viewer_id)
    viewer_outcome = None
    if entry and entry.get("outcome_id"):
        outcomes_by_id = {o["outcome_id"]: o for o in (config.get("outcomes") or [])}
        oc = outcomes_by_id.get(entry["outcome_id"], {})
        viewer_outcome = {
            "outcome_id": entry["outcome_id"],
            "display_label": oc.get("display_label"),
            "payload_type": oc.get("payload_type", "text"),
            "text_content": oc.get("text_content"),
            "media_asset_id": oc.get("media_asset_id"),
            "rng_roll": int(entry.get("rng_roll", 0)),
        }

    return {
        "lottery_id": config["lottery_id"],
        "title": config["title"],
        "status": config["status"],
        "entry_count": int(config.get("entry_count", 0)),
        "max_entries": int(config["max_entries"]) if config.get("max_entries") is not None else None,
        "entry_fee_cents": int(config.get("entry_fee_cents", 0)),
        "closes_at": int(config["closes_at"]) if config.get("closes_at") is not None else None,
        "created_at": int(config.get("created_at", 0)),
        "drawn_at": int(config["drawn_at"]) if config.get("drawn_at") is not None else None,
        "has_entered": entry is not None,
        "viewer_outcome": viewer_outcome,
    }
