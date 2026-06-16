"""Chat delegation service (DELEGATE-002).

Enables delegates with chat_read/chat_respond permissions to view
and respond to a creator's conversations on their behalf.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.aws import ddb
from app.core.time import now_ts
from app.services.delegates import (
    get_creator_settings,
    get_delegate,
    require_delegate_permission,
    _write_audit,
)
from app.services.profile import get_profile

logger = logging.getLogger(__name__)

DDB_CONVERSATIONS = os.getenv("DDB_CONVERSATIONS", "Conversations")
DDB_PARTICIPANTS = os.getenv("DDB_PARTICIPANTS", "Participants")
DDB_MESSAGES = os.getenv("DDB_MESSAGES", "Messages")

tbl_convos = ddb.Table(DDB_CONVERSATIONS)
tbl_parts = ddb.Table(DDB_PARTICIPANTS)
tbl_msgs = ddb.Table(DDB_MESSAGES)


def list_creator_conversations(
    *,
    creator_id: str,
    delegate_id: str,
) -> List[Dict[str, Any]]:
    """List creator's conversations for a delegate.

    Requires chat_read permission. Returns conversation items enriched
    with participant status for the creator.
    """
    require_delegate_permission(
        creator_id=creator_id,
        delegate_id=delegate_id,
        required_permission="chat_read",
    )

    # Fetch creator's participant records
    parts: List[dict] = []
    last_key = None
    while True:
        kwargs: dict = {
            "KeyConditionExpression": Key("user_id").eq(creator_id),
            "Limit": 500,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = tbl_parts.query(**kwargs)
        parts.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key or len(parts) >= 2000:
            break

    if not parts:
        return []

    parts_by_cid = {p["conversation_id"]: p for p in parts}
    cids = list(parts_by_cid.keys())

    # Batch-fetch conversation records
    convo_map: Dict[str, dict] = {}
    for i in range(0, len(cids), 100):
        batch_keys = [{"conversation_id": cid} for cid in cids[i : i + 100]]
        try:
            batch_resp = ddb.batch_get_item(
                RequestItems={DDB_CONVERSATIONS: {"Keys": batch_keys}}
            )
            for item in batch_resp.get("Responses", {}).get(DDB_CONVERSATIONS, []):
                convo_map[item["conversation_id"]] = item
        except Exception:
            pass

    # Sort by recency, cap at 200
    def _sort_key(cid: str) -> tuple:
        convo = convo_map.get(cid, {})
        return (
            int(convo.get("last_message_at", 0) or 0),
            int(convo.get("created_at", 0) or 0),
        )

    sorted_cids = sorted(cids, key=_sort_key, reverse=True)[:200]

    result = []
    for cid in sorted_cids:
        p = parts_by_cid[cid]
        convo = convo_map.get(cid)
        if not convo:
            convo = tbl_convos.get_item(Key={"conversation_id": cid}).get("Item")
        if not convo:
            continue

        # Fetch participants for this conversation
        part_items = tbl_parts.query(
            IndexName="GSI1",
            KeyConditionExpression=Key("GSI1PK").eq(cid),
            Limit=50,
        ).get("Items", [])
        participant_list = [
            {
                "user_id": pi.get("user_id", ""),
                "status": pi.get("status", "pending"),
                "role": pi.get("role", "member"),
            }
            for pi in part_items
            if pi.get("status") != "left"
        ]

        result.append({
            "conversation_id": cid,
            "type": convo.get("type", "dm"),
            "title": convo.get("title"),
            "created_at": int(convo.get("created_at", 0)),
            "last_message_at": int(convo.get("last_message_at", 0) or 0),
            "last_message_preview": convo.get("last_message_preview"),
            "participant_count": int(convo.get("participant_count", 0)),
            "status": p.get("status", "pending"),
            "unread_count": int(p.get("unread_count", 0) or 0),
            "participants": participant_list,
        })

    result.sort(
        key=lambda x: (x.get("last_message_at", 0), x.get("created_at", 0)),
        reverse=True,
    )
    return result


def get_creator_conversation_messages(
    *,
    creator_id: str,
    delegate_id: str,
    conversation_id: str,
    limit: int = 50,
    before: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Get messages in a creator's conversation for a delegate.

    Requires chat_read. Encrypted messages are redacted.
    """
    require_delegate_permission(
        creator_id=creator_id,
        delegate_id=delegate_id,
        required_permission="chat_read",
    )
    _require_creator_participant(creator_id, conversation_id)

    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("conversation_id").eq(conversation_id),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if before:
        kwargs["ExclusiveStartKey"] = {
            "conversation_id": conversation_id,
            "message_id": before,
        }

    resp = tbl_msgs.query(**kwargs)
    items = resp.get("Items", [])

    # Convert to output dicts with delegate redaction
    result = []
    for m in items:
        msg = _message_to_dict(m)
        msg = _redact_encrypted_for_delegate(msg)
        result.append(msg)

    result.sort(key=lambda m: int(m.get("created_at", 0)), reverse=True)
    return result


def send_message_as_creator(
    *,
    creator_id: str,
    delegate_id: str,
    conversation_id: str,
    text: str,
    reply_to_message_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Send a message as the creator via delegation.

    Requires chat_respond. Message is attributed to the creator
    but carries delegate metadata.
    """
    delegate_item = require_delegate_permission(
        creator_id=creator_id,
        delegate_id=delegate_id,
        required_permission="chat_respond",
    )

    _require_creator_participant(creator_id, conversation_id)

    delegate_profile = get_profile(delegate_id)
    delegate_display_name = delegate_profile.get("display_name") or delegate_id

    # Build delegate tag if enabled
    delegate_tag = None
    if delegate_item.get("show_delegate_tag"):
        fmt = delegate_item.get(
            "delegate_tag_format", "[via @{delegate_name}]"
        )
        delegate_tag = fmt.replace("{delegate_name}", delegate_display_name)

    # When the creator opts to hide the delegate from recipients, the "via @…"
    # attribution must NOT be baked into the shared message text (which the
    # recipient and the sidebar preview both read) — it stays only in the
    # structured fields + audit log, which only the creator/delegate can see.
    # (DLP-003) Read live so toggling the setting affects existing delegates.
    hide_from_recipients = bool(
        get_creator_settings(creator_id).get("hide_delegate_from_recipients")
    )

    # Append tag to message text only when attribution is visible to everyone.
    final_text = text
    if delegate_tag and not hide_from_recipients:
        final_text = f"{text} {delegate_tag}"

    ts = now_ts()
    mid = f"m_{uuid4().hex}"

    item: Dict[str, Any] = {
        "conversation_id": conversation_id,
        "message_id": mid,
        "sender_id": creator_id,
        "created_at": ts,
        "kind": "text",
        "text": final_text,
        "is_encrypted": False,
        "reactions": {},
        # Delegate metadata
        "sent_by_delegate": delegate_id,
        "delegate_display_name": delegate_display_name,
    }
    if delegate_tag:
        item["delegate_tag"] = delegate_tag
    if reply_to_message_id:
        item["reply_to_message_id"] = reply_to_message_id

    tbl_msgs.put_item(Item=item)

    # Update conversation last_message
    tbl_convos.update_item(
        Key={"conversation_id": conversation_id},
        UpdateExpression="SET last_message_at = :ts, last_message_preview = :p, last_message_id = :mid",
        ExpressionAttributeValues={
            ":ts": ts,
            ":p": final_text[:140],
            ":mid": mid,
        },
    )

    # Bump unread for other participants
    try:
        parts_resp = tbl_parts.query(
            IndexName="GSI1",
            KeyConditionExpression=Key("GSI1PK").eq(conversation_id),
        )
        for p in parts_resp.get("Items", []):
            pid = p.get("user_id")
            if pid and pid != creator_id:
                tbl_parts.update_item(
                    Key={
                        "user_id": pid,
                        "conversation_id": conversation_id,
                    },
                    UpdateExpression="SET unread_count = if_not_exists(unread_count, :zero) + :one",
                    ExpressionAttributeValues={":zero": 0, ":one": 1},
                )
    except Exception:
        logger.warning("Failed to bump unread counts for delegated message")

    # Write audit entry
    _write_audit(
        creator_id,
        delegate_id,
        "delegate",
        "chat_message_sent",
        conversation_id,
        {
            "message_id": mid,
            "text_preview": text[:100],
        },
    )

    return {
        "conversation_id": conversation_id,
        "message_id": mid,
        "sender_id": creator_id,
        "created_at": ts,
        "kind": "text",
        "text": final_text,
        "sent_by_delegate": delegate_id,
        "delegate_display_name": delegate_display_name,
        "delegate_tag": delegate_tag,
    }


def get_delegated_messages_audit(
    *,
    creator_id: str,
    requester_id: str,
    conversation_id: Optional[str] = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """Get messages sent by delegates (creator-only audit view).

    Only the creator can access this endpoint.
    """
    if requester_id != creator_id:
        raise HTTPException(403, "Only the creator can view delegation audit")

    from app.core.tables import T

    resp = T.delegates.query(
        KeyConditionExpression=Key("pk").eq(f"CREATOR#{creator_id}")
        & Key("sk").begins_with("AUDIT#"),
        ScanIndexForward=False,
        Limit=limit * 2,  # over-fetch since we filter
    )

    items = resp.get("Items", [])
    audit_entries = []
    for item in items:
        if item.get("action") != "chat_message_sent":
            continue
        details = item.get("details", {})
        entry = {
            "event_id": item.get("event_id", ""),
            "delegate_id": item.get("actor_id", ""),
            "conversation_id": item.get("target_id", ""),
            "message_id": details.get("message_id", ""),
            "text_preview": details.get("text_preview", ""),
            "delegate_display_name": "",
            "created_at": int(item.get("ts", 0)),
        }
        if conversation_id and entry["conversation_id"] != conversation_id:
            continue
        audit_entries.append(entry)
        if len(audit_entries) >= limit:
            break

    return audit_entries


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _require_creator_participant(creator_id: str, conversation_id: str) -> None:
    """Verify the creator is a participant in the conversation."""
    resp = tbl_parts.get_item(
        Key={"user_id": creator_id, "conversation_id": conversation_id}
    )
    if not resp.get("Item"):
        raise HTTPException(404, "Conversation not found")
    if resp["Item"].get("status") not in ("active", "pending"):
        raise HTTPException(404, "Conversation not found")


def _message_to_dict(m: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a raw DDB message item to a response dict."""
    return {
        "conversation_id": str(m.get("conversation_id", "")),
        "message_id": str(m.get("message_id", "")),
        "sender_id": str(m.get("sender_id", "")),
        "created_at": int(m.get("created_at", 0)),
        "kind": str(m.get("kind", "text")),
        "text": m.get("text"),
        "is_encrypted": bool(m.get("is_encrypted", False)),
        "encryption": m.get("encryption"),
        "sent_by_delegate": m.get("sent_by_delegate"),
        "delegate_display_name": m.get("delegate_display_name"),
        "delegate_tag": m.get("delegate_tag"),
        "reply_to_message_id": m.get("reply_to_message_id"),
        "reactions": m.get("reactions", {}),
    }


def _redact_encrypted_for_delegate(message: Dict[str, Any]) -> Dict[str, Any]:
    """Replace encrypted message content with placeholder for delegates."""
    if message.get("is_encrypted") or message.get("encryption"):
        message = dict(message)
        message["text"] = None
        message["delegate_cannot_decrypt"] = True
    return message
