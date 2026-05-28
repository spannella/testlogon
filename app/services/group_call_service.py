"""Group Video Call service (CALL-012).

Manages group call sessions with DynamoDB single-table design:
  PK=CALL#{call_id}, SK=META        — call metadata
  PK=CALL#{call_id}, SK=PART#{uid}  — per-participant record

State machine: created -> active -> ended
"""
from __future__ import annotations

import os
import uuid
import logging
from typing import Optional

from boto3.dynamodb.conditions import Key
from app.core.time import now_ts

logger = logging.getLogger(__name__)


def _table():
    from app.core.tables import T
    return T.group_call_sessions


def _participants_table():
    from app.core.aws import ddb
    return ddb.Table(os.getenv("DDB_PARTICIPANTS", "Participants"))


def _conversations_table():
    from app.core.aws import ddb
    return ddb.Table(os.getenv("DDB_CONVERSATIONS", "Conversations"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

TERMINAL_STATES = {"ended"}
ACTIVE_STATES = {"created", "active"}


def generate_call_id() -> str:
    return f"gc_{uuid.uuid4().hex[:12]}"


def _get_conversation_participant_ids(conversation_id: str) -> set[str]:
    """Return set of active participant user_ids for a conversation."""
    tbl_parts = _participants_table()
    resp = tbl_parts.query(
        IndexName="GSI1",
        KeyConditionExpression=Key("GSI1PK").eq(conversation_id),
    )
    items = resp.get("Items") or []
    return {
        str(item.get("user_id") or item.get("participant_id") or "").strip()
        for item in items
        if str(item.get("status") or "").strip() in ("active", "")
    }


def _get_conversation_or_none(conversation_id: str) -> Optional[dict]:
    tbl = _conversations_table()
    return tbl.get_item(Key={"conversation_id": conversation_id}).get("Item")


# ---------------------------------------------------------------------------
# CRUD — META row
# ---------------------------------------------------------------------------


def create_group_call(
    *,
    conversation_id: str,
    creator_user_id: str,
    mode: str = "video",
    max_participants: int = 8,
) -> dict:
    """Create a new group call. Returns the META item dict."""
    from app.core.settings import S

    if not S.group_calls_enabled:
        raise GroupCallError(403, "Group calls are not enabled")

    # Clamp max_participants
    cap = S.group_call_max_participants
    max_participants = max(2, min(max_participants, cap))

    # Validate conversation exists and has 3+ members
    participant_ids = _get_conversation_participant_ids(conversation_id)
    if creator_user_id not in participant_ids:
        raise GroupCallError(403, "Not a member of this conversation")
    if len(participant_ids) < 3:
        raise GroupCallError(400, "Conversation is not a group conversation")

    # Check no active call in this conversation
    existing = get_active_call_for_conversation(conversation_id)
    if existing:
        raise GroupCallError(409, "An active call already exists in this conversation")

    call_id = generate_call_id()
    ts = int(now_ts())

    item = {
        "pk": f"CALL#{call_id}",
        "sk": "META",
        "call_id": call_id,
        "conversation_id": conversation_id,
        "creator_user_id": creator_user_id,
        "state": "created",
        "mode": mode,
        "max_participants": max_participants,
        "current_participant_count": 0,
        "start_ts": 0,
        "end_ts": 0,
        "end_reason": "",
        "created_at": ts,
        "updated_at": ts,
    }
    _table().put_item(Item=item)
    return item


def get_call(call_id: str) -> Optional[dict]:
    """Get call META row."""
    item = _table().get_item(Key={"pk": f"CALL#{call_id}", "sk": "META"}).get("Item")
    return item


def get_active_call_for_conversation(conversation_id: str) -> Optional[dict]:
    """Find active (non-ended) call for a conversation."""
    resp = _table().query(
        IndexName="ByConversationCreatedAt",
        KeyConditionExpression=Key("conversation_id").eq(conversation_id),
        ScanIndexForward=False,
        Limit=10,
    )
    for item in resp.get("Items") or []:
        if item.get("sk") == "META" and item.get("state") in ACTIVE_STATES:
            return item
    return None


def list_call_history(conversation_id: str, *, limit: int = 20) -> list[dict]:
    """List recent calls for a conversation (most recent first)."""
    resp = _table().query(
        IndexName="ByConversationCreatedAt",
        KeyConditionExpression=Key("conversation_id").eq(conversation_id),
        ScanIndexForward=False,
        Limit=max(1, min(limit, 100)),
    )
    return [item for item in (resp.get("Items") or []) if item.get("sk") == "META"]


# ---------------------------------------------------------------------------
# CRUD — PARTICIPANT rows
# ---------------------------------------------------------------------------


def join_call(call_id: str, user_id: str, display_name: str = "") -> dict:
    """Add participant to a call. Returns updated META item."""
    from app.core.settings import S

    meta = get_call(call_id)
    if not meta:
        raise GroupCallError(404, "Call not found")
    if meta.get("state") in TERMINAL_STATES:
        raise GroupCallError(410, "Call has ended")

    conversation_id = meta["conversation_id"]
    participant_ids = _get_conversation_participant_ids(conversation_id)
    if user_id not in participant_ids:
        raise GroupCallError(403, "Not a member of this conversation")

    max_p = int(meta.get("max_participants") or S.group_call_max_participants)
    current = int(meta.get("current_participant_count") or 0)

    # Check if already joined (rejoin)
    existing_part = _table().get_item(
        Key={"pk": f"CALL#{call_id}", "sk": f"PART#{user_id}"}
    ).get("Item")
    if existing_part and existing_part.get("state") == "active":
        # Already in the call — return current state
        meta = get_call(call_id) or meta
        return meta

    if current >= max_p and not (existing_part and existing_part.get("state") == "left"):
        raise GroupCallError(409, "Call is at maximum capacity")

    ts = int(now_ts())

    # Write participant row
    part_item = {
        "pk": f"CALL#{call_id}",
        "sk": f"PART#{user_id}",
        "user_id": user_id,
        "display_name": display_name or user_id,
        "joined_at": ts,
        "left_at": 0,
        "media_status": {"audio": True, "video": meta.get("mode") == "video", "screen": False},
        "connection_quality": "good",
        "state": "active",
        # GSI fields carried from meta for indexing
        "conversation_id": conversation_id,
        "created_at": int(meta.get("created_at", ts)),
    }
    _table().put_item(Item=part_item)

    # Increment participant count & transition state if first join
    new_count = current + 1
    new_state = "active" if meta.get("state") == "created" or meta.get("state") == "active" else meta.get("state")
    update_expr = "SET current_participant_count = :cnt, #st = :state, updated_at = :ts"
    expr_values = {":cnt": new_count, ":state": new_state, ":ts": ts}
    expr_names = {"#st": "state"}

    if new_state == "active" and int(meta.get("start_ts") or 0) == 0:
        update_expr += ", start_ts = :start"
        expr_values[":start"] = ts

    _table().update_item(
        Key={"pk": f"CALL#{call_id}", "sk": "META"},
        UpdateExpression=update_expr,
        ExpressionAttributeValues=expr_values,
        ExpressionAttributeNames=expr_names,
    )

    # Emit timeline event
    _emit_timeline("group_call.join", call_id=call_id, conversation_id=conversation_id, actor_user_id=user_id, call_state=new_state)

    return get_call(call_id) or meta


def leave_call(call_id: str, user_id: str) -> dict:
    """Remove participant from a call. Returns leave summary."""
    meta = get_call(call_id)
    if not meta:
        raise GroupCallError(404, "Call not found")
    if meta.get("state") in TERMINAL_STATES:
        raise GroupCallError(410, "Call has ended")

    # Check participant is in the call
    part = _table().get_item(
        Key={"pk": f"CALL#{call_id}", "sk": f"PART#{user_id}"}
    ).get("Item")
    if not part or part.get("state") != "active":
        raise GroupCallError(400, "Not in this call")

    ts = int(now_ts())

    # Update participant row
    _table().update_item(
        Key={"pk": f"CALL#{call_id}", "sk": f"PART#{user_id}"},
        UpdateExpression="SET left_at = :ts, #st = :state",
        ExpressionAttributeValues={":ts": ts, ":state": "left"},
        ExpressionAttributeNames={"#st": "state"},
    )

    # Decrement count
    current = max(0, int(meta.get("current_participant_count") or 1) - 1)
    _table().update_item(
        Key={"pk": f"CALL#{call_id}", "sk": "META"},
        UpdateExpression="SET current_participant_count = :cnt, updated_at = :ts",
        ExpressionAttributeValues={":cnt": current, ":ts": ts},
    )

    conversation_id = meta["conversation_id"]
    _emit_timeline("group_call.leave", call_id=call_id, conversation_id=conversation_id, actor_user_id=user_id, call_state="active")

    # Auto-end if no active participants remain
    call_ended = False
    if current <= 0:
        _end_call_internal(call_id, meta, reason="all_left", actor_user_id=user_id)
        call_ended = True

    return {"ok": True, "call_ended": call_ended, "remaining_participants": max(0, current)}


def end_call(call_id: str, user_id: str, *, role: str = "USER") -> dict:
    """End a call for all participants. Only creator or admin/root can do this."""
    meta = get_call(call_id)
    if not meta:
        raise GroupCallError(404, "Call not found")
    if meta.get("state") in TERMINAL_STATES:
        raise GroupCallError(410, "Call has already ended")

    # Authorization: must be creator or admin/root
    if user_id != meta.get("creator_user_id") and role not in ("ADMIN", "ROOT"):
        raise GroupCallError(403, "Only the call creator or an admin can end the call")

    participants = list_participants(call_id)
    _end_call_internal(call_id, meta, reason="creator_ended", actor_user_id=user_id)

    start_ts = int(meta.get("start_ts") or meta.get("created_at") or 0)
    end_ts = int(now_ts())
    duration = max(0, end_ts - start_ts) if start_ts > 0 else 0

    total_participants = len([p for p in participants if int(p.get("joined_at") or 0) > 0])

    return {
        "ok": True,
        "call_id": call_id,
        "duration_seconds": duration,
        "total_participants": total_participants,
    }


def _end_call_internal(call_id: str, meta: dict, *, reason: str, actor_user_id: str) -> None:
    """Transition call to ended state and mark all active participants as left."""
    ts = int(now_ts())

    _table().update_item(
        Key={"pk": f"CALL#{call_id}", "sk": "META"},
        UpdateExpression="SET #st = :state, end_ts = :ts, end_reason = :reason, updated_at = :ts, current_participant_count = :zero",
        ExpressionAttributeValues={":state": "ended", ":ts": ts, ":reason": reason, ":zero": 0},
        ExpressionAttributeNames={"#st": "state"},
    )

    # Mark all active participants as left
    participants = list_participants(call_id)
    for p in participants:
        if p.get("state") == "active":
            _table().update_item(
                Key={"pk": f"CALL#{call_id}", "sk": f"PART#{p['user_id']}"},
                UpdateExpression="SET left_at = :ts, #st = :state",
                ExpressionAttributeValues={":ts": ts, ":state": "left"},
                ExpressionAttributeNames={"#st": "state"},
            )

    conversation_id = meta.get("conversation_id", "")
    _emit_timeline(
        "group_call.end",
        call_id=call_id,
        conversation_id=conversation_id,
        actor_user_id=actor_user_id,
        call_state="ended",
        reason=reason,
    )


def list_participants(call_id: str) -> list[dict]:
    """List all participant rows for a call."""
    resp = _table().query(
        KeyConditionExpression=Key("pk").eq(f"CALL#{call_id}") & Key("sk").begins_with("PART#"),
    )
    return resp.get("Items") or []


def get_participant(call_id: str, user_id: str) -> Optional[dict]:
    """Get a single participant row."""
    return _table().get_item(
        Key={"pk": f"CALL#{call_id}", "sk": f"PART#{user_id}"}
    ).get("Item")


def _check_screen_share_conflict(call_id: str, requesting_user_id: str) -> str | None:
    """Check if another active participant is already screen sharing.

    Returns the conflicting user_id, or None if no conflict.
    """
    participants = list_participants(call_id)
    for p in participants:
        if p.get("state") != "active":
            continue
        if p.get("user_id") == requesting_user_id:
            continue
        media = p.get("media_status") or {}
        if media.get("screen"):
            return str(p.get("user_id") or p.get("sk", "").replace("PART#", ""))
    return None


def update_media_state(
    call_id: str,
    user_id: str,
    *,
    audio: Optional[bool] = None,
    video: Optional[bool] = None,
    screen: Optional[bool] = None,
) -> dict:
    """Update a participant's media state (mute toggles)."""
    part = get_participant(call_id, user_id)
    if not part or part.get("state") != "active":
        raise GroupCallError(400, "Not an active participant in this call")

    # Prevent simultaneous screen shares
    if screen is True:
        conflict = _check_screen_share_conflict(call_id, user_id)
        if conflict:
            raise GroupCallError(409, f"Another participant ({conflict}) is already sharing their screen")

    media = dict(part.get("media_status") or {"audio": True, "video": True, "screen": False})
    if audio is not None:
        media["audio"] = bool(audio)
    if video is not None:
        media["video"] = bool(video)
    if screen is not None:
        media["screen"] = bool(screen)

    _table().update_item(
        Key={"pk": f"CALL#{call_id}", "sk": f"PART#{user_id}"},
        UpdateExpression="SET media_status = :ms",
        ExpressionAttributeValues={":ms": media},
    )
    return media


# ---------------------------------------------------------------------------
# Signal relay (dev mesh mode)
# ---------------------------------------------------------------------------

# In-memory signal relay for dev mode (not persistent)
_signal_queues: dict[str, list[dict]] = {}


def relay_signal(call_id: str, sender_user_id: str, target_user_id: str, signal_type: str, payload: dict) -> dict:
    """Relay a signaling message from one participant to another."""
    meta = get_call(call_id)
    if not meta:
        raise GroupCallError(404, "Call not found")
    if meta.get("state") in TERMINAL_STATES:
        raise GroupCallError(410, "Call has ended")

    sender_part = get_participant(call_id, sender_user_id)
    if not sender_part or sender_part.get("state") != "active":
        raise GroupCallError(403, "Sender is not an active participant")

    target_part = get_participant(call_id, target_user_id)
    if not target_part or target_part.get("state") != "active":
        raise GroupCallError(400, "Target is not an active participant")

    # In dev mode, store signal in memory queue
    queue_key = f"{call_id}:{target_user_id}"
    if queue_key not in _signal_queues:
        _signal_queues[queue_key] = []
    _signal_queues[queue_key].append({
        "from_user_id": sender_user_id,
        "type": signal_type,
        "payload": payload,
        "ts": int(now_ts()),
    })

    return {"ok": True, "relayed_to": target_user_id}


# ---------------------------------------------------------------------------
# Timeline integration
# ---------------------------------------------------------------------------

def _emit_timeline(
    event_type: str,
    *,
    call_id: str,
    conversation_id: str,
    actor_user_id: str,
    call_state: str,
    reason: Optional[str] = None,
) -> None:
    """Emit a timeline event reusing the existing call timeline infrastructure."""
    try:
        from app.services.messaging_call_timeline import emit_call_timeline_event
        emit_call_timeline_event(
            call_id=call_id,
            conversation_id=conversation_id,
            actor_user_id=actor_user_id,
            event_type=event_type,
            call_state=call_state,
            reason=reason,
        )
    except Exception:
        logger.warning("Failed to emit group call timeline event", exc_info=True)


# ---------------------------------------------------------------------------
# Error class
# ---------------------------------------------------------------------------

class GroupCallError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


__all__ = [
    "GroupCallError",
    "create_group_call",
    "get_call",
    "get_active_call_for_conversation",
    "list_call_history",
    "join_call",
    "leave_call",
    "end_call",
    "list_participants",
    "get_participant",
    "update_media_state",
    "relay_signal",
    "generate_call_id",
]
