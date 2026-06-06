"""Watch Party service (ENGAGE-004).

Synchronized VOD watch parties with playback control, co-host, invite codes,
and linked group chat conversations.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts
from app.services.watch_party_sse import wp_sse_publish as broadcast_sse_publish


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _new_party_id() -> str:
    return f"wp_{uuid4().hex}"


def _new_invite_code() -> str:
    return uuid4().hex[:8]


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------

def create_party(
    *,
    host_user_sub: str,
    video_id: str,
    video_title: str,
    video_duration_seconds: float,
    max_participants: int = 50,
    title: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a new watch party in 'waiting' state."""
    ts = now_ts()
    party_id = _new_party_id()
    invite_code = _new_invite_code()

    item: Dict[str, Any] = {
        "party_id": party_id,
        "host_user_sub": host_user_sub,
        "video_id": video_id,
        "video_title": video_title,
        "video_duration_seconds": int(video_duration_seconds),
        "title": title or video_title,
        "invite_code": invite_code,
        "status": "waiting",
        "max_participants": max_participants,
        "participant_count": 1,
        "position": 0,
        "position_updated_at": ts,
        "created_at": ts,
        "updated_at": ts,
        # GSI: ByHost  PK=HOST#{sub}  SK=created_at (N)
        "GSI1PK": f"HOST#{host_user_sub}",
        "GSI1SK": ts,
        # GSI: ByInvite  PK=INVITE#{code}
        "GSI2PK": f"INVITE#{invite_code}",
        "GSI2SK": party_id,
    }

    T.watch_parties.put_item(Item=item)

    # Add host as first participant
    T.watch_party_participants.put_item(Item={
        "party_id": party_id,
        "user_sub": host_user_sub,
        "role": "host",
        "status": "active",
        "joined_at": ts,
    })

    return item


# ---------------------------------------------------------------------------
# Read
# ---------------------------------------------------------------------------

def get_party(party_id: str) -> Dict[str, Any]:
    """Get party by ID. Raises 404 if not found."""
    resp = T.watch_parties.get_item(Key={"party_id": party_id})
    item = resp.get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="watch party not found")
    return item


def resolve_invite(invite_code: str) -> Dict[str, Any]:
    """Look up a party by invite code. Raises 404 if not found."""
    resp = T.watch_parties.query(
        IndexName="ByInvite",
        KeyConditionExpression=Key("GSI2PK").eq(f"INVITE#{invite_code}"),
        Limit=1,
    )
    items = resp.get("Items", [])
    if not items:
        raise HTTPException(status_code=404, detail="invalid invite code")
    return items[0]


def list_host_parties(host_user_sub: str, limit: int = 50) -> List[Dict[str, Any]]:
    """List parties created by a host, newest first."""
    resp = T.watch_parties.query(
        IndexName="ByHost",
        KeyConditionExpression=Key("GSI1PK").eq(f"HOST#{host_user_sub}"),
        ScanIndexForward=False,
        Limit=min(limit, 200),
    )
    return resp.get("Items", [])


# ---------------------------------------------------------------------------
# Join / Leave
# ---------------------------------------------------------------------------

def join_party(party_id: str, user_sub: str) -> Dict[str, Any]:
    """Add a user to a watch party."""
    party = get_party(party_id)

    if party["status"] == "ended":
        raise HTTPException(status_code=410, detail="party has ended")

    # Check if kicked
    existing = _get_participant(party_id, user_sub)
    if existing and existing.get("status") == "kicked":
        raise HTTPException(status_code=403, detail="you have been kicked from this party")

    # Check max participants
    current_count = int(party.get("participant_count", 0))
    max_p = int(party.get("max_participants", 50))
    if current_count >= max_p and not existing:
        raise HTTPException(status_code=409, detail="party is full")

    ts = now_ts()

    if existing and existing.get("status") == "active":
        # Already in the party
        return existing

    if existing:
        # Re-joining (was "left")
        T.watch_party_participants.update_item(
            Key={"party_id": party_id, "user_sub": user_sub},
            UpdateExpression="SET #s = :s, joined_at = :j",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":s": "active", ":j": ts},
        )
    else:
        T.watch_party_participants.put_item(Item={
            "party_id": party_id,
            "user_sub": user_sub,
            "role": "member",
            "status": "active",
            "joined_at": ts,
        })

    # Increment participant count
    _update_participant_count(party_id, 1)

    broadcast_sse_publish(party_id, {
        "_type": "participant_joined",
        "user_sub": user_sub,
        "joined_at": ts,
    })

    return _get_participant(party_id, user_sub) or {}


def leave_party(party_id: str, user_sub: str) -> None:
    """Remove a user from a watch party."""
    existing = _get_participant(party_id, user_sub)
    if not existing or existing.get("status") != "active":
        return

    T.watch_party_participants.update_item(
        Key={"party_id": party_id, "user_sub": user_sub},
        UpdateExpression="SET #s = :s",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "left"},
    )
    _update_participant_count(party_id, -1)

    broadcast_sse_publish(party_id, {
        "_type": "participant_left",
        "user_sub": user_sub,
    })


# ---------------------------------------------------------------------------
# End
# ---------------------------------------------------------------------------

def end_party(party_id: str, user_sub: str) -> Dict[str, Any]:
    """End a watch party (host only)."""
    party = get_party(party_id)
    if party["host_user_sub"] != user_sub:
        raise HTTPException(status_code=403, detail="only the host can end the party")

    ts = now_ts()
    T.watch_parties.update_item(
        Key={"party_id": party_id},
        UpdateExpression="SET #s = :s, ended_at = :e, updated_at = :u",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "ended", ":e": ts, ":u": ts},
    )

    broadcast_sse_publish(party_id, {"_type": "party_ended", "ended_at": ts})

    party["status"] = "ended"
    party["ended_at"] = ts
    party["updated_at"] = ts
    return party


# ---------------------------------------------------------------------------
# Playback Control
# ---------------------------------------------------------------------------

def control_playback(
    party_id: str,
    user_sub: str,
    *,
    action: str,
    position: Optional[float] = None,
) -> Dict[str, Any]:
    """Control playback: play, pause, seek. Host or co-host only."""
    party = get_party(party_id)

    if party["status"] == "ended":
        raise HTTPException(status_code=410, detail="party has ended")

    # Check permissions
    participant = _get_participant(party_id, user_sub)
    if not participant or participant.get("status") != "active":
        raise HTTPException(status_code=403, detail="not a participant")
    if participant.get("role") not in ("host", "co-host"):
        raise HTTPException(status_code=403, detail="only host or co-host can control playback")

    ts = now_ts()
    duration = int(party.get("video_duration_seconds", 0))

    if action == "play":
        new_pos = max(0, min(float(position if position is not None else party.get("position", 0)), duration))
        new_status = "playing"
    elif action == "pause":
        new_pos = max(0, min(float(position if position is not None else party.get("position", 0)), duration))
        new_status = "paused"
    elif action == "seek":
        if position is None:
            raise HTTPException(status_code=400, detail="position required for seek")
        new_pos = max(0, min(float(position), duration))
        new_status = str(party.get("status", "paused"))
    else:
        raise HTTPException(status_code=400, detail=f"unknown action: {action}")

    from decimal import Decimal
    T.watch_parties.update_item(
        Key={"party_id": party_id},
        UpdateExpression="SET #s = :s, #p = :p, position_updated_at = :t, updated_at = :u",
        ExpressionAttributeNames={"#s": "status", "#p": "position"},
        ExpressionAttributeValues={
            ":s": new_status,
            ":p": Decimal(str(new_pos)),
            ":t": ts,
            ":u": ts,
        },
    )

    broadcast_sse_publish(party_id, {
        "_type": "playback_control",
        "action": action,
        "status": new_status,
        "position": new_pos,
        "position_updated_at": ts,
        "controlled_by": user_sub,
    })

    party["status"] = new_status
    party["position"] = new_pos
    party["position_updated_at"] = ts
    party["updated_at"] = ts
    return party


# ---------------------------------------------------------------------------
# Co-host
# ---------------------------------------------------------------------------

def grant_co_host(party_id: str, host_user_sub: str, target_user_sub: str) -> None:
    """Grant co-host to a participant. Host only."""
    party = get_party(party_id)
    if party["host_user_sub"] != host_user_sub:
        raise HTTPException(status_code=403, detail="only the host can grant co-host")

    participant = _get_participant(party_id, target_user_sub)
    if not participant or participant.get("status") != "active":
        raise HTTPException(status_code=404, detail="participant not found or not active")

    T.watch_party_participants.update_item(
        Key={"party_id": party_id, "user_sub": target_user_sub},
        UpdateExpression="SET #r = :r",
        ExpressionAttributeNames={"#r": "role"},
        ExpressionAttributeValues={":r": "co-host"},
    )

    broadcast_sse_publish(party_id, {
        "_type": "co_host_granted",
        "user_sub": target_user_sub,
    })


# ---------------------------------------------------------------------------
# Kick
# ---------------------------------------------------------------------------

def kick_participant(party_id: str, host_user_sub: str, target_user_sub: str) -> None:
    """Kick a participant. Host only."""
    party = get_party(party_id)
    if party["host_user_sub"] != host_user_sub:
        raise HTTPException(status_code=403, detail="only the host can kick participants")

    if target_user_sub == host_user_sub:
        raise HTTPException(status_code=400, detail="cannot kick yourself")

    participant = _get_participant(party_id, target_user_sub)
    if not participant:
        raise HTTPException(status_code=404, detail="participant not found")

    T.watch_party_participants.update_item(
        Key={"party_id": party_id, "user_sub": target_user_sub},
        UpdateExpression="SET #s = :s",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "kicked"},
    )

    if participant.get("status") == "active":
        _update_participant_count(party_id, -1)

    broadcast_sse_publish(party_id, {
        "_type": "participant_kicked",
        "user_sub": target_user_sub,
    })


# ---------------------------------------------------------------------------
# Heartbeat
# ---------------------------------------------------------------------------

def heartbeat(party_id: str, user_sub: str) -> Dict[str, Any]:
    """Update last_seen for a participant. Returns current party state."""
    ts = now_ts()
    try:
        T.watch_party_participants.update_item(
            Key={"party_id": party_id, "user_sub": user_sub},
            UpdateExpression="SET last_seen = :t",
            ExpressionAttributeValues={":t": ts},
            ConditionExpression="attribute_exists(party_id)",
        )
    except Exception:
        pass
    return get_party(party_id)


# ---------------------------------------------------------------------------
# Participants
# ---------------------------------------------------------------------------

def list_participants(party_id: str) -> List[Dict[str, Any]]:
    """List all participants for a party."""
    resp = T.watch_party_participants.query(
        KeyConditionExpression=Key("party_id").eq(party_id),
    )
    return resp.get("Items", [])


# ---------------------------------------------------------------------------
# Playback URL
# ---------------------------------------------------------------------------

def get_playback_url(party_id: str, user_sub: str) -> Dict[str, str]:
    """Get a playback URL for a party's video. Participant must be active."""
    party = get_party(party_id)
    participant = _get_participant(party_id, user_sub)
    if not participant or participant.get("status") != "active":
        raise HTTPException(status_code=403, detail="not an active participant")

    video_id = party["video_id"]

    # Try to use VOD playback URL generation
    try:
        from app.services.vod_playback_url import mint_vod_playback_url
        vod_url = mint_vod_playback_url(video_id=video_id, tenant_id=party.get("host_user_sub", "default"))
        return {"url": vod_url.url, "video_id": video_id}
    except Exception:
        # Fallback: return a mock URL in dev mode
        from app.core.settings import S
        if S.dev_mode:
            return {
                "url": f"http://localhost:8000/mock/s3/vod-output/tenants/{party.get('host_user_sub', 'default')}/assets/{video_id}/hls/master.m3u8",
                "video_id": video_id,
            }
        raise HTTPException(status_code=500, detail="unable to generate playback URL")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_participant(party_id: str, user_sub: str) -> Optional[Dict[str, Any]]:
    resp = T.watch_party_participants.get_item(
        Key={"party_id": party_id, "user_sub": user_sub}
    )
    return resp.get("Item")


def _update_participant_count(party_id: str, delta: int) -> None:
    """Atomically update participant count, clamping to a floor of 0 (GAP-0167).

    Decrements use a ``ConditionExpression`` so the counter can never go
    negative when a spurious double-decrement occurs (concurrent leave/kick,
    retries). A rejected decrement (count already at 0) is a no-op.
    """
    if delta < 0:
        from botocore.exceptions import ClientError

        try:
            T.watch_parties.update_item(
                Key={"party_id": party_id},
                UpdateExpression="SET participant_count = participant_count + :d, updated_at = :u",
                ConditionExpression="participant_count > :zero",
                ExpressionAttributeValues={":d": delta, ":u": now_ts(), ":zero": 0},
            )
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                # Count already at (or below) the floor — spurious decrement, no-op.
                return
            raise
    else:
        T.watch_parties.update_item(
            Key={"party_id": party_id},
            UpdateExpression="SET participant_count = participant_count + :d, updated_at = :u",
            ExpressionAttributeValues={":d": delta, ":u": now_ts()},
        )
