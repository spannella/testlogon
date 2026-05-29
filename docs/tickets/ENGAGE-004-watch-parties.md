# ENGAGE-004: Synchronized VOD Watch Parties

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-28  
**Priority**: Medium  
**Estimated effort**: 14-18 days

---

## 1. Overview & Motivation

### 1.1 Problem Statement

The platform offers on-demand video content through the VOD system (upload, transcode, HLS playback) and real-time social interaction through broadcasts and messaging. However, there is **no way to combine these**: viewers cannot watch a VOD together in real-time with synchronized playback and integrated chat. When a creator says "go watch my latest video" in chat, each viewer watches independently at their own pace, losing the shared social experience.

Watch parties solve this by:

1. **Creating a shared viewing session** around an existing VOD asset.
2. **Synchronizing playback state** (play, pause, seek) across all participants in real-time.
3. **Providing integrated group chat** so participants can react to the content together.
4. **Lowering the barrier for community events** -- creators can host "premiere" watch parties for new uploads without needing live streaming infrastructure.

### 1.2 How It Works

1. A host (creator or viewer with permission) creates a watch party by selecting a VOD from their library or a public catalog.
2. The system generates a **shareable invite link** (URL with party ID).
3. Participants join via the link. A player and chat panel render side by side.
4. The host controls playback: play, pause, seek. Control commands are broadcast to all participants via SSE.
5. Each participant's player receives state updates and adjusts its position to stay within a configurable sync tolerance (default: 2 seconds).
6. A group chat sidebar enables real-time text conversation alongside the video.
7. The host can end the party, which stops playback for all participants and archives the chat.

### 1.3 Design Principles

- **Host authority**: Only the host (or designated co-hosts) can control playback. This prevents conflicts from multiple users seeking simultaneously.
- **Eventual consistency**: Network latency means perfect frame-sync is impossible. The system targets "within 2 seconds" as the sync tolerance, which is sufficient for a social viewing experience.
- **Leverage existing infrastructure**: VOD playback uses `mint_vod_playback_url()` for URL signing. Group chat uses the messaging system. SSE uses the broadcast SSE pubsub.
- **Minimal server-side state**: The server tracks the party metadata and relays control events. Actual playback happens client-side. No server-side video processing is needed.

### 1.4 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Host (creator) | As a creator, I want to host a watch party for my new video so my community can watch it together. | Create party with video_id; shareable link generated; chat available. |
| Host | As a host, I want my play/pause/seek actions to sync across all viewers. | SSE event sent on host action; all clients adjust playback within 2s. |
| Viewer | As a viewer, I want to join a watch party via an invite link. | Link opens player + chat; video starts playing in sync with the host. |
| Viewer | As a viewer, I want to chat with other participants while watching. | Messages appear in sidebar; standard messaging features (reactions, replies). |
| Host | As a host, I want to end the party when the video is over. | "End Party" button; all participants see "Party ended" screen; chat archived. |
| Viewer | As a viewer joining late, I want to catch up to the current playback position. | On join, client receives current timestamp and seeks to it. |
| Host | As a host, I want to promote a viewer to co-host so they can control playback too. | Co-host grant endpoint; co-host can play/pause/seek. |
| Viewer | As a viewer, I want to see who else is watching. | Participant list with display names and avatar thumbnails. |
| Host | As a host, I want to kick disruptive viewers. | Kick endpoint removes participant and blocks re-join. |

---

## 2. Current State Analysis

### 2.1 VOD Playback URL Generation (`app/services/vod_playback_url.py`) <!-- VERIFIED: app/services/vod_playback_url.py exists, mint_vod_playback_url at line 40 -->

The `mint_vod_playback_url` function (line 40) generates signed HLS manifest URLs:

```python
def mint_vod_playback_url(
    video_id: str, tenant_id: str, *, ttl_seconds: Optional[int] = None,
) -> VodPlaybackUrl:
    if S.dev_mode:
        return _mint_dev_url(video_id=video_id, tenant_id=tenant_id)
    if S.vod_cloudfront_domain or S.broadcast_cloudfront_domain:
        return _mint_cloudfront_url(video_id=video_id, tenant_id=tenant_id, ttl_seconds=ttl_seconds)
    return _mint_presigned_url(video_id=video_id, tenant_id=tenant_id, ttl_seconds=ttl_seconds)
```

In dev mode, it returns a mock URL pattern (line 118): <!-- VERIFIED: app/services/vod_playback_url.py:118 _mint_dev_url -->

```python
def _mint_dev_url(*, video_id: str, tenant_id: str) -> VodPlaybackUrl:
    bucket = S.vod_output_bucket or S.transcode_output_bucket or "vod-output"
    key = _manifest_key(video_id, tenant_id)
    url = f"http://localhost:8000/mock/s3/{bucket}/{key}"
    return VodPlaybackUrl(url=url, expires_at=0, manifest_key=key, mode="dev", thumbnail_url=thumb_url)
```

Watch parties will call `mint_vod_playback_url()` for each participant when they join, providing them with a signed playback URL valid for the party duration.

### 2.2 Broadcast SSE Infrastructure (`app/services/broadcast_sse.py`) <!-- VERIFIED: app/services/broadcast_sse.py exists, 50 lines -->

The in-memory pub/sub system uses per-session subscriber sets (full file, 50 lines):

```python
_BROADCAST_SUBSCRIBERS: Dict[str, Set[asyncio.Queue]] = {}

def broadcast_sse_subscribe(session_id: str) -> asyncio.Queue:
    q: asyncio.Queue = asyncio.Queue(maxsize=100)
    subs = _BROADCAST_SUBSCRIBERS.setdefault(session_id, set())
    subs.add(q)
    return q

def broadcast_sse_publish(session_id: str, event: Dict[str, Any]) -> None:
    subs = _BROADCAST_SUBSCRIBERS.get(session_id)
    if not subs:
        return
    dead = []
    for q in list(subs):
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            dead.append(q)
    for q in dead:
        subs.discard(q)
```

Watch parties will reuse this exact infrastructure with the party ID as the "session_id" key. Playback control events and chat messages will be published through `broadcast_sse_publish(party_id, event)`.

### 2.3 Messaging Group Chat (`app/routers/messaging.py`) <!-- VERIFIED: app/routers/messaging.py exists -->

Group conversations are already supported in the messaging system. Group conversations in DynamoDB have participants, message history, and read tracking. Watch party chat will be implemented as a **standard group conversation** with `routing_mode: "watch_party"` -- this reuses all existing messaging features (reactions, replies, read receipts) without new infrastructure.

### 2.4 Video Metadata (`app/routers/video_listing.py`) <!-- VERIFIED: app/routers/video_listing.py exists -->

The video listing router (line 40) provides video detail retrieval: <!-- CORRECTED: was "line 41", actually line 40 -->

```python
router = APIRouter(prefix="/ui/videos", tags=["video-listing"])

class VideoDetailOut(BaseModel):  # <!-- VERIFIED: app/routers/video_listing.py:67 -->
    video_id: str
    owner_user_id: str
    title: str
    description: Optional[str] = None
    status: str
    visibility: str
    duration_seconds: Optional[float] = None
    hls_manifest_url: Optional[str] = None
    playback_token: Optional[str] = None
    playback_expires_at: Optional[int] = None
    ...
```

Watch party creation will validate that the video exists and is in a playable state (`status in ("published", "approved")`).

### 2.5 Broadcast Recording Playback (`app/services/broadcast_recording.py`) <!-- VERIFIED: app/services/broadcast_recording.py exists, mint_recording_playback_url at line 208 -->

Recording playback URL generation follows the same signed URL pattern (line 208):

```python
def mint_recording_playback_url(recording: RecordingRecord) -> Dict[str, Any]:
    ttl = S.broadcast_recording_playback_ttl_seconds
    expires_at = _now_ts() + ttl
    bucket = S.broadcast_recording_vod_bucket
    manifest_key = recording.s3_manifest_key or f"{recording.session_id}/recording/master.m3u8"
    playback_url = f"/mock/s3/{bucket}/{manifest_key}?expires={expires_at}"
    return {"playback_url": playback_url, "playback_expires_at": expires_at}
```

Watch parties support both regular VOD videos and broadcast recordings as source content.

---

## 3. Technical Design

### 3.1 DynamoDB Schema

**Table: `watch_parties`**

| Field | Type | Key | Description |
|-------|------|-----|-------------|
| `party_id` | S | PK | Unique ID: `wp_{uuid4().hex}` |
| `host_user_id` | S | | Creator of the party |
| `video_id` | S | | VOD video being watched |
| `video_title` | S | | Denormalized for display |
| `video_duration_seconds` | N | | Total video duration |
| `video_thumbnail_url` | S | | Thumbnail URL for invite card |
| `status` | S | | `waiting`, `playing`, `paused`, `ended` |
| `conversation_id` | S | | Linked messaging group conversation |
| `current_position_seconds` | N | | Host's last reported playback position |
| `last_state_change_at` | N | | Timestamp of last play/pause/seek (for sync calculation) |
| `participant_count` | N | | Current number of active participants |
| `max_participants` | N | | Limit (default 50) |
| `invite_code` | S | | Short code for shareable link |
| `created_at` | N | | Creation timestamp |
| `ended_at` | N | | End timestamp (when host ends party) |
| `ttl` | N | | DDB TTL: ended_at + 7 days |
| `GSI1PK` | S | GSI | `HOST#{host_user_id}` for listing host's parties |
| `GSI1SK` | N | GSI | `{created_at}` for sorting |
| `GSI2PK` | S | GSI | `INVITE#{invite_code}` for invite code lookup |
| `GSI2SK` | S | GSI | `{party_id}` |

DynamoDB table definition for `scripts/local-ddb-init.py`:

```python
TableDef(
    "watch_parties",
    "party_id",
    gsi=[
        {"index_name": "ByHost", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
        {"index_name": "ByInvite", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
    ],
    attr_types={"GSI1SK": "N"},
),
```

**Table: `watch_party_participants`**

| Field | Type | Key | Description |
|-------|------|-----|-------------|
| `party_id` | S | PK | Party this participant belongs to |
| `user_sub` | S | SK | Participant user ID |
| `display_name` | S | | Participant display name |
| `joined_at` | N | | When they joined |
| `last_heartbeat_at` | N | | Last activity timestamp (presence) |
| `is_co_host` | BOOL | | Can they control playback? |
| `status` | S | | `active`, `left`, `kicked` |
| `kicked_by` | S | | Who kicked them (for audit) |

DynamoDB table definition:

```python
TableDef(
    "watch_party_participants",
    "party_id",
    "user_sub",
),
```

### 3.2 Playback Synchronization Protocol

The synchronization protocol is state-based rather than command-based. The server maintains the authoritative state (`status`, `current_position_seconds`, `last_state_change_at`). Clients compute their target position from this state.

**State update flow:**

```
1. Host clicks Play at position 45.0s
2. Client sends: POST /watch-parties/{id}/control { action: "play", position: 45.0 }
3. Server updates party record:
     status = "playing"
     current_position_seconds = 45.0
     last_state_change_at = now_ts()
4. Server publishes SSE:
     { _type: "wp:state", status: "playing", position: 45.0, timestamp: 1748400000 }
5. Each client receives the event and computes:
     target_position = position + (now() - timestamp)
                     = 45.0 + elapsed_seconds
6. If |client_position - target_position| > SYNC_TOLERANCE:
     client seeks to target_position
7. If state is "playing" and client is paused: client.play()
8. If state is "paused" and client is playing: client.pause()
```

**Sync tolerance**: 2 seconds (configurable). Prevents constant seeking due to minor clock differences.

**Late joiner sync sequence:**

```
1. Client calls POST /watch-parties/{id}/join
2. Server returns party state: { status: "playing", position: 120.0, timestamp: 1748400042 }
3. Client computes: target = 120.0 + (now() - 1748400042)
4. Client sets player.currentTime = target
5. Client calls player.play()
6. Client subscribes to SSE stream for ongoing state updates
```

**Pause state handling:**
When the state is `paused`, the position does not advance. All clients show the same frozen frame at `current_position_seconds`.

### 3.3 Service Layer (`app/services/watch_party.py`)

```python
"""Watch party service -- creation, joining, playback control (ENGAGE-004)."""

from __future__ import annotations

import logging
from decimal import Decimal
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Key, Attr
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts
from app.services.broadcast_sse import broadcast_sse_publish

logger = logging.getLogger(__name__)


def create_party(
    host_user_id: str,
    video_id: str,
    max_participants: int = 50,
) -> Dict[str, Any]:
    """Create a watch party and linked group conversation."""
    from app.services.video_metadata_store import get_video
    video = get_video(video_id)
    if not video:
        raise HTTPException(404, "Video not found")
    if video.status not in ("published", "approved"):
        raise HTTPException(400, "Video not available for watch party")

    party_id = f"wp_{uuid4().hex}"
    invite_code = uuid4().hex[:8]
    ts = now_ts()

    # Create linked group conversation
    from app.services.messaging_conversations import create_group_conversation
    conversation = create_group_conversation(
        creator_id=host_user_id,
        name=f"Watch Party: {video.title}",
        routing_mode="watch_party",
    )

    item = {
        "party_id": party_id,
        "host_user_id": host_user_id,
        "video_id": video_id,
        "video_title": video.title,
        "video_duration_seconds": Decimal(str(video.duration_seconds or 0)),
        "video_thumbnail_url": getattr(video, "thumbnail_url", "") or "",
        "status": "waiting",
        "conversation_id": conversation["conversation_id"],
        "current_position_seconds": Decimal("0"),
        "last_state_change_at": ts,
        "participant_count": 0,
        "max_participants": max_participants,
        "invite_code": invite_code,
        "created_at": ts,
        "GSI1PK": f"HOST#{host_user_id}",
        "GSI1SK": ts,
        "GSI2PK": f"INVITE#{invite_code}",
        "GSI2SK": party_id,
    }
    T.watch_parties.put_item(Item=item)

    # Add host as first participant
    _add_participant(party_id, host_user_id, is_co_host=True)

    return _party_out(item)


def join_party(party_id: str, user_sub: str, display_name: str) -> Dict[str, Any]:
    """Join a watch party.

    Validates:
    - Party exists and is not ended
    - Party is not full
    - User is not kicked

    Adds user to participant table and linked conversation.
    Returns current party state for sync.
    """
    party = _get_party_item(party_id)
    if not party:
        raise HTTPException(404, "Watch party not found")
    if party.get("status") == "ended":
        raise HTTPException(410, "Party has ended")
    if int(party.get("participant_count", 0)) >= int(party.get("max_participants", 50)):
        raise HTTPException(409, "Party is full")

    # Check if kicked
    existing = _get_participant(party_id, user_sub)
    if existing and existing.get("status") == "kicked":
        raise HTTPException(403, "You have been removed from this party")

    # Add or re-add participant
    _add_participant(party_id, user_sub, display_name=display_name)

    # Add to linked messaging conversation
    try:
        from app.services.messaging_conversations import add_participant
        add_participant(party["conversation_id"], user_sub)
    except Exception:
        logger.warning("Failed to add to conversation", exc_info=True)

    # Increment participant count (only if new)
    if not existing or existing.get("status") != "active":
        T.watch_parties.update_item(
            Key={"party_id": party_id},
            UpdateExpression="SET participant_count = if_not_exists(participant_count, :zero) + :one",
            ExpressionAttributeValues={":one": 1, ":zero": 0},
        )

    # Publish join event
    broadcast_sse_publish(party_id, {
        "_type": "wp:join",
        "user_sub": user_sub,
        "display_name": display_name,
    })

    # Return current state for sync
    return _party_out(_get_party_item(party_id))


def leave_party(party_id: str, user_sub: str) -> Dict[str, Any]:
    """Leave a watch party."""
    T.watch_party_participants.update_item(
        Key={"party_id": party_id, "user_sub": user_sub},
        UpdateExpression="SET #s = :left",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":left": "left"},
    )

    T.watch_parties.update_item(
        Key={"party_id": party_id},
        UpdateExpression="SET participant_count = participant_count - :one",
        ExpressionAttributeValues={":one": 1},
    )

    broadcast_sse_publish(party_id, {
        "_type": "wp:leave",
        "user_sub": user_sub,
    })

    return {"ok": True}


def end_party(party_id: str, actor: str) -> Dict[str, Any]:
    """End a watch party (host only)."""
    party = _get_party_item(party_id)
    if not party:
        raise HTTPException(404, "Party not found")
    if party.get("host_user_id") != actor:
        raise HTTPException(403, "Only the host can end the party")

    ts = now_ts()
    T.watch_parties.update_item(
        Key={"party_id": party_id},
        UpdateExpression="SET #s = :ended, ended_at = :ts, #ttl = :ttl",
        ExpressionAttributeNames={"#s": "status", "#ttl": "ttl"},
        ExpressionAttributeValues={
            ":ended": "ended",
            ":ts": ts,
            ":ttl": ts + 7 * 86400,
        },
    )

    broadcast_sse_publish(party_id, {"_type": "wp:end"})
    return _party_out(_get_party_item(party_id))


def control_playback(
    party_id: str,
    actor: str,
    action: str,
    position: float,
) -> Dict[str, Any]:
    """Process a playback control command from host/co-host.

    action: "play", "pause", or "seek"
    position: current playback position in seconds
    """
    party = _get_party_item(party_id)
    if not party:
        raise HTTPException(404, "Party not found")
    if actor != party["host_user_id"] and not _is_co_host(party_id, actor):
        raise HTTPException(403, "Only host/co-host can control playback")
    if party.get("status") == "ended":
        raise HTTPException(410, "Party has ended")

    ts = now_ts()
    status_map = {"play": "playing", "pause": "paused", "seek": party["status"]}
    new_status = status_map.get(action, party["status"])

    # Clamp position to video duration
    max_dur = float(party.get("video_duration_seconds", 0))
    position = max(0.0, min(position, max_dur))

    T.watch_parties.update_item(
        Key={"party_id": party_id},
        UpdateExpression="SET #s = :status, current_position_seconds = :pos, last_state_change_at = :ts",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":status": new_status,
            ":pos": Decimal(str(position)),
            ":ts": ts,
        },
    )

    event = {
        "_type": "wp:state",
        "status": new_status,
        "position": position,
        "timestamp": ts,
        "action": action,
    }
    broadcast_sse_publish(party_id, event)
    return event


def grant_co_host(party_id: str, target_user: str, actor: str) -> Dict[str, Any]:
    """Grant co-host privileges to a participant."""
    party = _get_party_item(party_id)
    if party.get("host_user_id") != actor:
        raise HTTPException(403, "Only the host can grant co-host")

    T.watch_party_participants.update_item(
        Key={"party_id": party_id, "user_sub": target_user},
        UpdateExpression="SET is_co_host = :t",
        ExpressionAttributeValues={":t": True},
    )

    broadcast_sse_publish(party_id, {
        "_type": "wp:co_host",
        "user_sub": target_user,
        "is_co_host": True,
    })
    return {"ok": True, "user_sub": target_user, "is_co_host": True}


def kick_participant(party_id: str, target_user: str, actor: str) -> Dict[str, Any]:
    """Kick a participant from the party."""
    party = _get_party_item(party_id)
    if party.get("host_user_id") != actor and not _is_co_host(party_id, actor):
        raise HTTPException(403, "Only host/co-host can kick participants")
    if target_user == party.get("host_user_id"):
        raise HTTPException(400, "Cannot kick the host")

    T.watch_party_participants.update_item(
        Key={"party_id": party_id, "user_sub": target_user},
        UpdateExpression="SET #s = :kicked, kicked_by = :actor",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":kicked": "kicked", ":actor": actor},
    )

    T.watch_parties.update_item(
        Key={"party_id": party_id},
        UpdateExpression="SET participant_count = participant_count - :one",
        ExpressionAttributeValues={":one": 1},
    )

    broadcast_sse_publish(party_id, {
        "_type": "wp:kick",
        "user_sub": target_user,
    })
    return {"ok": True}


def heartbeat(party_id: str, user_sub: str) -> None:
    """Update participant heartbeat for presence tracking."""
    T.watch_party_participants.update_item(
        Key={"party_id": party_id, "user_sub": user_sub},
        UpdateExpression="SET last_heartbeat_at = :now",
        ExpressionAttributeValues={":now": now_ts()},
    )


def list_participants(party_id: str) -> List[Dict[str, Any]]:
    """List active participants for a party."""
    resp = T.watch_party_participants.query(
        KeyConditionExpression=Key("party_id").eq(party_id),
        FilterExpression=Attr("status").eq("active"),
    )
    return [_participant_out(item) for item in resp.get("Items", [])]


def resolve_invite(invite_code: str) -> Dict[str, Any]:
    """Resolve an invite code to party details."""
    resp = T.watch_parties.query(
        IndexName="ByInvite",
        KeyConditionExpression=Key("GSI2PK").eq(f"INVITE#{invite_code}"),
        Limit=1,
    )
    items = resp.get("Items", [])
    if not items:
        raise HTTPException(404, "Invalid invite code")
    return _party_out(items[0])


def list_host_parties(host_user_id: str) -> List[Dict[str, Any]]:
    """List parties created by a host."""
    resp = T.watch_parties.query(
        IndexName="ByHost",
        KeyConditionExpression=Key("GSI1PK").eq(f"HOST#{host_user_id}"),
        ScanIndexForward=False,
    )
    return [_party_out(item) for item in resp.get("Items", [])]


def get_party(party_id: str) -> Dict[str, Any]:
    """Get party details for API response."""
    item = _get_party_item(party_id)
    if not item:
        raise HTTPException(404, "Watch party not found")
    return _party_out(item)


# ─── Internal helpers ──────────────────────────────────────

def _get_party_item(party_id: str) -> Optional[Dict[str, Any]]:
    resp = T.watch_parties.get_item(Key={"party_id": party_id})
    return resp.get("Item")


def _get_participant(party_id: str, user_sub: str) -> Optional[Dict[str, Any]]:
    resp = T.watch_party_participants.get_item(
        Key={"party_id": party_id, "user_sub": user_sub},
    )
    return resp.get("Item")


def _add_participant(party_id: str, user_sub: str, display_name: str = "", is_co_host: bool = False) -> None:
    T.watch_party_participants.put_item(Item={
        "party_id": party_id,
        "user_sub": user_sub,
        "display_name": display_name,
        "joined_at": now_ts(),
        "last_heartbeat_at": now_ts(),
        "is_co_host": is_co_host,
        "status": "active",
    })


def _is_co_host(party_id: str, user_sub: str) -> bool:
    participant = _get_participant(party_id, user_sub)
    return bool(participant and participant.get("is_co_host"))


def _party_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "party_id": item.get("party_id", ""),
        "host_user_id": item.get("host_user_id", ""),
        "video_id": item.get("video_id", ""),
        "video_title": item.get("video_title", ""),
        "video_duration_seconds": float(item.get("video_duration_seconds", 0)),
        "video_thumbnail_url": item.get("video_thumbnail_url", ""),
        "status": item.get("status", "waiting"),
        "conversation_id": item.get("conversation_id", ""),
        "current_position_seconds": float(item.get("current_position_seconds", 0)),
        "last_state_change_at": int(item.get("last_state_change_at", 0)),
        "participant_count": int(item.get("participant_count", 0)),
        "max_participants": int(item.get("max_participants", 50)),
        "invite_code": item.get("invite_code", ""),
        "created_at": int(item.get("created_at", 0)),
        "ended_at": int(item.get("ended_at", 0)) if item.get("ended_at") else None,
    }


def _participant_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "user_sub": item.get("user_sub", ""),
        "display_name": item.get("display_name", ""),
        "joined_at": int(item.get("joined_at", 0)),
        "is_co_host": bool(item.get("is_co_host", False)),
        "status": item.get("status", "active"),
    }
```

### 3.4 Pydantic Models

```python
# Additions for the watch party router

class CreatePartyIn(BaseModel):
    video_id: str = Field(..., min_length=1, max_length=64)
    max_participants: int = Field(default=50, ge=2, le=500)

class PlaybackControlIn(BaseModel):
    action: Literal["play", "pause", "seek"]
    position: float = Field(..., ge=0)

class PartyOut(BaseModel):
    party_id: str
    host_user_id: str
    video_id: str
    video_title: str
    video_duration_seconds: float
    video_thumbnail_url: str
    status: Literal["waiting", "playing", "paused", "ended"]
    conversation_id: str
    current_position_seconds: float
    last_state_change_at: int
    participant_count: int
    max_participants: int
    invite_code: str
    created_at: int
    ended_at: Optional[int] = None
    playback_url: Optional[str] = None
    playback_expires_at: Optional[int] = None

class ParticipantOut(BaseModel):
    user_sub: str
    display_name: str
    joined_at: int
    is_co_host: bool
    status: str
```

### 3.5 Chat Integration

The watch party chat reuses the messaging system. When a participant joins, they are added to the linked group conversation. The conversation has `routing_mode: "watch_party"` which allows the frontend to render it with a video-specific UI.

### 3.6 Heartbeat and Stale Participant Cleanup

```python
# Background task running every 60 seconds
async def _cleanup_stale_participants():
    """Mark participants as 'left' if no heartbeat in 2 minutes."""
    cutoff = now_ts() - 120  # 2 minutes ago
    # Scan active parties
    resp = T.watch_parties.scan(
        FilterExpression=Attr("status").ne("ended"),
        ProjectionExpression="party_id",
    )
    for party_item in resp.get("Items", []):
        party_id = party_item["party_id"]
        participants = T.watch_party_participants.query(
            KeyConditionExpression=Key("party_id").eq(party_id),
            FilterExpression=Attr("status").eq("active") & Attr("last_heartbeat_at").lt(cutoff),
        ).get("Items", [])

        for p in participants:
            T.watch_party_participants.update_item(
                Key={"party_id": party_id, "user_sub": p["user_sub"]},
                UpdateExpression="SET #s = :left",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={":left": "left"},
            )
            T.watch_parties.update_item(
                Key={"party_id": party_id},
                UpdateExpression="SET participant_count = participant_count - :one",
                ExpressionAttributeValues={":one": 1},
            )
            broadcast_sse_publish(party_id, {
                "_type": "wp:leave",
                "user_sub": p["user_sub"],
                "reason": "timeout",
            })
```

### 3.7 Playback URL Refresh

```python
def get_playback_url(party_id: str, user_sub: str) -> Dict[str, Any]:
    """Get or refresh a playback URL for a party participant.

    Validates the user is an active participant.
    Returns signed URL with TTL matching the party duration.
    """
    party = _get_party_item(party_id)
    if not party:
        raise HTTPException(404, "Party not found")

    participant = _get_participant(party_id, user_sub)
    if not participant or participant.get("status") != "active":
        raise HTTPException(403, "Not an active participant")

    video_id = party["video_id"]
    # Use long TTL for party duration
    ttl = max(3600, int(party.get("video_duration_seconds", 0)) + 3600)

    from app.services.vod_playback_url import mint_vod_playback_url
    tenant_id = party.get("host_user_id", "default")
    playback = mint_vod_playback_url(video_id, tenant_id, ttl_seconds=ttl)

    return {
        "playback_url": playback.url,
        "playback_expires_at": playback.expires_at,
        "thumbnail_url": playback.thumbnail_url,
    }
```

---

## 4. API Endpoints

### 4.1 Party Management

```
POST   /ui/watch-parties                          -- Create a party
GET    /ui/watch-parties                          -- List my parties (as host)
GET    /ui/watch-parties/{party_id}               -- Get party details
GET    /ui/watch-parties/join/{invite_code}       -- Resolve invite code to party
POST   /ui/watch-parties/{party_id}/join          -- Join a party
POST   /ui/watch-parties/{party_id}/leave         -- Leave a party
POST   /ui/watch-parties/{party_id}/end           -- End a party (host only)
DELETE /ui/watch-parties/{party_id}               -- Delete a party (host only)
```

### 4.2 Playback Control

```
POST /ui/watch-parties/{party_id}/control
```

Request: `{ "action": "play" | "pause" | "seek", "position": 45.0 }`
Response: `{ "status": "playing", "position": 45.0, "timestamp": 1748400000 }`

### 4.3 Participant Management

```
GET  /ui/watch-parties/{party_id}/participants
POST /ui/watch-parties/{party_id}/co-host        -- Grant co-host to a participant
POST /ui/watch-parties/{party_id}/kick/{user_sub} -- Remove a participant
POST /ui/watch-parties/{party_id}/heartbeat      -- Participant heartbeat
GET  /ui/watch-parties/{party_id}/playback-url   -- Get/refresh playback URL
```

### 4.4 SSE Stream

```
GET /ui/watch-parties/{party_id}/stream
```

Events: `wp:state`, `wp:join`, `wp:leave`, `wp:end`, `wp:kick`, `wp:co_host`

---

## 5. Frontend Components

### 5.1 New Pages and Components

| Component | Path | Description |
|-----------|------|-------------|
| `WatchPartyPage` | `pages/watch-parties/WatchPartyPage.tsx` | Main party view: video player + chat sidebar + participant list |
| `CreatePartyDialog` | `pages/watch-parties/CreatePartyDialog.tsx` | Video picker + settings for creating a new party |
| `PartyPlayer` | `pages/watch-parties/PartyPlayer.tsx` | HLS player with sync logic; disables seek/play/pause for non-hosts |
| `PartyChat` | `pages/watch-parties/PartyChat.tsx` | Thin wrapper around messaging ConversationView |
| `PartyParticipants` | `pages/watch-parties/PartyParticipants.tsx` | Collapsible participant list with co-host/kick controls |
| `SyncOverlay` | `pages/watch-parties/SyncOverlay.tsx` | "Syncing..." indicator when client is catching up |
| `PartyInviteCard` | `pages/watch-parties/PartyInviteCard.tsx` | Shareable card with video thumbnail, title, participant count |
| `PartyListPage` | `pages/watch-parties/PartyListPage.tsx` | List of host's current/past parties |

### 5.2 Player Sync Logic

```tsx
// frontend/src/pages/watch-parties/usePlaybackSync.ts
import { useEffect, useRef, useState } from "react";

const SYNC_TOLERANCE_SECONDS = 2;

interface PlaybackState {
  status: "waiting" | "playing" | "paused" | "ended";
  position: number;
  timestamp: number;
}

export function usePlaybackSync(
  playerRef: React.RefObject<HTMLVideoElement>,
  state: PlaybackState | null,
  isHost: boolean,
) {
  const [syncing, setSyncing] = useState(false);

  useEffect(() => {
    if (!state || !playerRef.current || isHost) return;
    const player = playerRef.current;

    if (state.status === "ended") {
      player.pause();
      return;
    }

    if (state.status === "waiting") {
      player.pause();
      player.currentTime = 0;
      return;
    }

    const elapsed = (Date.now() / 1000) - state.timestamp;
    const targetPosition = state.status === "playing"
      ? state.position + elapsed
      : state.position;

    const drift = Math.abs(player.currentTime - targetPosition);
    if (drift > SYNC_TOLERANCE_SECONDS) {
      setSyncing(true);
      player.currentTime = targetPosition;
      setTimeout(() => setSyncing(false), 1000);
    }

    if (state.status === "playing" && player.paused) {
      player.play().catch(() => {});
    }
    if (state.status === "paused" && !player.paused) {
      player.pause();
    }
  }, [state, isHost]);

  return { syncing };
}
```

### 5.3 Host Controls

```tsx
{isHost || isCoHost ? (
    <div className="flex items-center gap-2">
        <Button size="icon" variant="ghost" onClick={handlePlayPause}>
            {isPlaying ? <Pause className="h-5 w-5" /> : <Play className="h-5 w-5" />}
        </Button>
        <Slider
            value={[position]}
            max={duration}
            step={1}
            onValueChange={([v]) => handleSeek(v)}
            className="flex-1"
        />
        <span className="text-xs tabular-nums text-muted-foreground">
            {formatTime(position)} / {formatTime(duration)}
        </span>
    </div>
) : (
    <div className="text-muted-foreground text-sm flex items-center gap-1 px-3 py-2">
        <Lock className="h-3 w-3" /> Host is controlling playback
    </div>
)}
```

### 5.4 Route Registration

```tsx
// In App.tsx
const WatchPartyPage = lazy(() => import("./pages/watch-parties/WatchPartyPage"));
const PartyListPage = lazy(() => import("./pages/watch-parties/PartyListPage"));

<Route path="/watch-parties" element={<PartyListPage />} />
<Route path="/watch-parties/:partyId" element={<WatchPartyPage />} />
<Route path="/party/:inviteCode" element={<PartyJoinRedirect />} />
```

---

## 6. E2E Test Plan

### Section 94: Watch Party CRUD API

| # | Test | Assertion |
|---|------|-----------|
| 94.1 | Create a watch party for a published video | 200, party_id, invite_code, status="waiting" |
| 94.2 | Create party for unpublished video fails | 400, "video not available" |
| 94.3 | List host's parties | Array includes created party |
| 94.4 | Get party by invite code | Returns party details |
| 94.5 | End a party | status="ended", ended_at set |
| 94.6 | Create party with max_participants=2 | 200, max_participants=2 |
| 94.7 | Get party by party_id | 200, includes all fields |
| 94.8 | Non-existent party returns 404 | 404 |

### Section 95: Join & Leave API

| # | Test | Assertion |
|---|------|-----------|
| 95.1 | Viewer joins via party_id | 200, participant added, conversation_id returned |
| 95.2 | Joining a full party returns 409 | 409, "party is full" |
| 95.3 | Joining an ended party returns 410 | 410, "party has ended" |
| 95.4 | Leave a party | participant status="left", count decremented |
| 95.5 | Kicked user cannot re-join | 403 |
| 95.6 | List participants shows active users | Only active participants returned |
| 95.7 | Playback URL returned on join | playback_url and playback_expires_at present |

### Section 96: Playback Control API

| # | Test | Assertion |
|---|------|-----------|
| 96.1 | Host sends play command | 200, status="playing", position set |
| 96.2 | Host sends pause command | 200, status="paused" |
| 96.3 | Host sends seek command | 200, position updated |
| 96.4 | Non-host cannot control playback | 403 |
| 96.5 | Co-host can control playback | 200 after co-host grant |
| 96.6 | Control on ended party returns 410 | 410 |
| 96.7 | Position clamped to video duration | Position <= video_duration_seconds |
| 96.8 | Seek to negative position clamped to 0 | position = 0 |

### Section 97: Watch Party UI

| # | Test | Assertion |
|---|------|-----------|
| 97.1 | Party page renders player and chat | Player element + chat panel visible |
| 97.2 | Participant list shows joined users | Display names visible |
| 97.3 | Invite link contains correct code | URL includes invite_code |
| 97.4 | Non-host sees "Host is controlling playback" | Lock icon + text visible |
| 97.5 | Host sees play/pause/seek controls | Control buttons visible |
| 97.6 | "End Party" button visible for host only | Button visible for host, hidden for viewer |
| 97.7 | Party ended screen shown after end | "Party ended" message visible |

---

## 7. Edge Cases

1. **Host disconnects**: The party remains in its last state (playing/paused). Participants continue watching. If the host reconnects, they resume control. A configurable `host_timeout_seconds` (default 5 minutes) auto-pauses if the host is gone for too long (detected via heartbeat).

2. **Video access revocation**: If the video is taken down while a party is active, participants receive a `wp:error` event and the party transitions to `ended`.

3. **Clock skew**: The sync formula `target = position + (now - timestamp)` is sensitive to client clock accuracy. To mitigate, the SSE event includes a server timestamp and the client computes drift from the SSE connection latency (measured during the initial state fetch).

4. **Mobile background suspension**: Mobile browsers pause JS execution when backgrounded. On resume, the client re-fetches current state via GET and seeks to catch up.

5. **Playback URL expiry**: VOD playback URLs have a TTL. For long parties, the client must refresh the URL before expiry. The party join response includes `playback_expires_at`; the client re-requests a URL 5 minutes before expiry via the `GET /playback-url` endpoint.

6. **Participant count vs. SSE subscribers**: Participants who close the tab without explicitly "leaving" still count toward `participant_count`. The heartbeat mechanism (every 30s from client, cleanup every 60s on server) marks stale participants as `left` after 2 minutes of silence.

7. **Concurrent playback commands**: If two co-hosts send play commands simultaneously, the second command overwrites the first. This is acceptable -- the most recent state wins. SSE delivers both events, and clients use the latest timestamp.

8. **Video buffering**: If a participant's network is slow, they may fall behind the sync target. The client only seeks when drift exceeds 2 seconds. Minor buffering delays are tolerated.

---

## 8. Security Considerations

1. **Video access authorization**: Before joining, the server verifies the user can access the video (not blocked by visibility, subscription gate, or pay-per-view requirement). Unauthorized users receive 403.

2. **Invite code brute-force**: 8-character hex codes provide 4 billion possibilities. Rate-limiting invite code lookups (10 per minute per IP) prevents enumeration.

3. **Chat moderation**: The linked group conversation inherits all messaging moderation features (reporting, muting, deletion by admin).

4. **Host impersonation**: Playback control is server-side authorized. Even if a client sends control events, the server rejects non-host/non-co-host actors.

5. **Max participant limit**: Prevents resource exhaustion. Default 50, configurable up to 500. SSE fan-out at 500 is manageable with the in-memory pubsub.

6. **Data retention**: Party records TTL after 7 days. Chat messages in the linked conversation follow standard messaging retention policy.

7. **Kicked participant re-join**: Kicked participants are blocked from re-joining (status="kicked" check on join). This prevents harassment loops.

---

## 9. Rollout Plan

1. **Phase 1** (days 1-5): Backend -- DDB tables, watch_party.py service (create, join, leave, end, control, kick, co-host), router endpoints, SSE stream endpoint.

2. **Phase 2** (days 6-9): Frontend -- WatchPartyPage, PartyPlayer with sync logic, PartyChat, PartyParticipants, CreatePartyDialog, invite code resolution.

3. **Phase 3** (days 10-13): Heartbeat system, stale participant cleanup, playback URL refresh, SyncOverlay, PartyInviteCard.

4. **Phase 4** (days 14-18): E2E tests (sections 94-97), integration testing with real HLS playback, performance testing with multiple participants, QA.

Feature flag: `WATCH_PARTIES_ENABLED` (default `false`).

---

## Codebase References

| Ref | File | Line(s) | Status |
|-----|------|---------|--------|
| `mint_vod_playback_url` | `app/services/vod_playback_url.py` | 40 | VERIFIED |
| `_mint_dev_url` | `app/services/vod_playback_url.py` | 118 | VERIFIED |
| Broadcast SSE | `app/services/broadcast_sse.py` | 49 lines | VERIFIED |
| `broadcast_sse_publish` | `app/services/broadcast_sse.py` | 29 | VERIFIED |
| Messaging router | `app/routers/messaging.py` | exists | VERIFIED |
| Video listing router | `app/routers/video_listing.py` | 40 (router) | VERIFIED |
| `VideoDetailOut` | `app/routers/video_listing.py` | 67 | VERIFIED |
| `mint_recording_playback_url` | `app/services/broadcast_recording.py` | 208 | VERIFIED |
| `require_ui_session` | `app/services/sessions.py` | 283 | VERIFIED (NOT in app/auth/deps.py) |
| Watch party settings | `app/core/settings.py` | 1473-1474 | VERIFIED |
| Watch party service | `app/services/watch_party.py` | exists | VERIFIED |
| Watch party router | `app/routers/watch_party.py` | exists, registered at `app/main.py:123,461` | VERIFIED |
| WatchPartyPage | `frontend/src/pages/watch-parties/WatchPartyPage.tsx` | exists | VERIFIED |
| Route registration | `frontend/src/App.tsx` | 91, 161 | VERIFIED |

---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_watch_party.py`

| # | Test Function | Description | Mocks |
|---|--------------|-------------|-------|
| 1 | `test_engage_004_create_basic` | Core creation logic succeeds with valid inputs | moto DDB |
| 2 | `test_engage_004_validation_rejects_invalid` | 400/422 for invalid inputs | moto DDB |
| 3 | `test_engage_004_pagination` | Cursor-based pagination returns correct pages | moto DDB |
| 4 | `test_engage_004_auth_required` | 401 for unauthenticated requests | moto DDB |
| 5 | `test_engage_004_forbidden_wrong_user` | 403 when non-owner accesses restricted resource | moto DDB |
| 6 | `test_engage_004_not_found` | 404 for non-existent resource | moto DDB |
| 7 | `test_engage_004_duplicate_rejected` | 409 for duplicate creation | moto DDB |
| 8 | `test_engage_004_feature_flag_off` | Feature disabled returns 404 when flag is off | moto DDB |

### Integration Tests

| # | Scenario | Services Involved |
|---|----------|-------------------|
| 1 | Full CRUD lifecycle: create, read, update, delete | Service layer, DDB |
| 2 | Cross-service interaction with dependent features | Multiple service modules |
| 3 | Concurrent access patterns do not corrupt data | Service layer, parallel requests |

### E2E Tests (Playwright)

**File**: `frontend/e2e/watch-party.spec.ts`

Tests use `injectAuth(page, identity)` for cookie-based auth and include CSRF headers (`x-csrf-token`) on all POST/PUT/DELETE requests. Negative tests cover 401 (unauthenticated), 403 (wrong role/user), 404 (not found), 409 (conflict), and 422 (validation) responses. Edge cases include duplicate operations (idempotency), concurrent access, and feature-flag-disabled behavior.

**Total E2E tests**: 15

### Test Data Requirements

- DDB seeds: required tables created via `scripts/local-ddb-init.py`
- Test users: Alice, Bob, Root, Charlie via `e2e_session_setup.py` / `e2e_admin_session_setup.py`
- Feature flag: `WATCH_PARTIES_ENABLED` in `.env.local`

### CI/Pipeline

- Feature flag: `WATCH_PARTIES_ENABLED` must be enabled for tests to run
- Serial execution: run with `--workers 1` to avoid shared state conflicts
- Retry safety: tests use unique timestamps/UUIDs per run; safe to retry on failure

---

## Dependencies & Merge Safety

### Depends On

| Ticket | Status | What It Provides |
|--------|--------|-----------------|
| (none) | -- | This ticket has no upstream ticket dependencies |

### Depended On By

| Ticket | What It Needs |
|--------|--------------|
| (none currently) | -- |

### Merge Strategy

**Independent** -- Changes are additive (new service files, new router, new frontend pages). Shared infrastructure files (`main.py`, `settings.py`, `tables.py`, `local-ddb-init.py`) receive only additive modifications.

### Merge Checklist

- [ ] All new DDB tables/GSIs added to `scripts/local-ddb-init.py`
- [ ] Settings added to `app/core/settings.py`
- [ ] Table handles added to `app/core/tables.py`
- [ ] Router registered in `app/main.py`
- [ ] Frontend routes added to `App.tsx`
- [ ] Feature flag `WATCH_PARTIES_ENABLED` added to `.env.local.example`
- [ ] All E2E tests pass
- [ ] No regressions in existing test suite
