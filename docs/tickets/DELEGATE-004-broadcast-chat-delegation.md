# DELEGATE-004: Broadcast Chat Delegation

**Ticket**: DELEGATE-004
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 7-9 days

---

## 1. Overview & Motivation

### 1.1 Purpose

DELEGATE-004 enables delegates to moderate live broadcast chat and control broadcast sessions on behalf of a creator. Delegates with `broadcast_moderate` can pin messages, delete messages, mute/ban users, and post announcements in broadcast chat. Delegates with `broadcast_control` can start, stop, and schedule broadcasts. Multiple moderators can be active simultaneously on the same broadcast, and all moderator actions are visibly attributed in the chat (e.g., "[Moderator @name] pinned a message").

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Delegate | As a moderator, I want to pin a message in broadcast chat so that important content stays visible. | POST pin; message shows pin indicator; chat displays "[Moderator @name] pinned a message". |
| Delegate | As a moderator, I want to delete offensive messages from broadcast chat so that the stream stays clean. | DELETE message; message removed from chat; system message "[Moderator @name] removed a message". |
| Delegate | As a moderator, I want to mute a disruptive viewer so that they cannot send messages temporarily. | POST mute with duration; viewer's messages blocked; system message shows mute. |
| Delegate | As a moderator, I want to ban a viewer from broadcast chat so that they cannot return. | POST ban; viewer's messages blocked permanently for this session; ban logged. |
| Delegate | As a moderator, I want to post announcements in broadcast chat so that viewers see important notices. | POST announcement; styled differently from regular chat (highlighted, bold); attributed to moderator. |
| Delegate | As a broadcast controller, I want to start a broadcast on behalf of the creator so that scheduled shows go live on time. | POST start; broadcast transitions to live; attributed to delegate in audit. |
| Delegate | As a broadcast controller, I want to stop a broadcast so that the stream ends cleanly. | POST stop; broadcast transitions to ended; delegate action logged. |
| Delegate | As a broadcast controller, I want to schedule a broadcast so that the creator's content calendar stays full. | POST schedule; broadcast appears in scheduled queue; creator notified. |
| Creator | As a creator, I want to see which moderators are active during a broadcast so that I know who's helping. | Active moderator list displayed in broadcast dashboard; shows online/offline status. |
| Creator | As a creator, I want multiple moderators active simultaneously so that large audiences are well-managed. | Multiple delegates connected to same broadcast; all can moderate independently; no conflicts. |

### 1.3 Why This Is Needed

Live broadcasts with large audiences generate hundreds of chat messages per minute. Creators cannot both perform on camera and moderate chat simultaneously. Professional broadcasters rely on moderator teams to keep chat civil, highlight interesting messages, and manage audience interactions. Without broadcast delegation, creators must either ignore chat moderation (leading to toxic environments) or recruit unofficial moderators who cannot be properly controlled or audited.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

| Component | Location | Relevance |
|-----------|----------|-----------|
| Broadcast chat store | `app/services/broadcast_chat_store.py` (~423 lines) | Chat CRUD, muting, rate limiting, message deletion; needs moderator authorization |
<!-- NOTE: broadcast_chat_store.py is ~423 lines, not ~350 lines -->
| Broadcast chat rich | `app/services/broadcast_chat_rich.py` | Rich chat features (emotes, badges); moderator badges needed |
| Broadcast store | `app/services/broadcast_store.py` (~480 lines) | Session lifecycle (create, start, stop, schedule); needs delegate authorization |
| Broadcast orchestrator | `app/services/broadcast_orchestrator.py` | Broadcast state transitions; needs to accept delegate-initiated transitions |
| Broadcast state machine | `app/services/broadcast_state_machine.py` | State transition validation; delegate transitions use same state machine |
| Broadcast SSE | `app/services/broadcast_sse.py` | SSE event streaming for broadcast chat; needs moderator event types |
| Broadcast viewers | `app/services/broadcast_viewers.py` | Viewer tracking; moderators tracked separately from viewers |
| Broadcast scheduler | `app/services/broadcast_scheduler.py` | Scheduled broadcast promotion; delegate-created schedules use same mechanism |
| Broadcast audit | `app/services/broadcast_audit.py` | Broadcast audit logging; needs delegate attribution |
| Delegates service | `app/services/delegates.py` (DELEGATE-001) | `require_delegate_permission`, audit logging |
<!-- NOTE: app/services/delegates.py does not exist yet — depends on DELEGATE-001 completion -->

### 2.2 Gaps

1. **No moderator role in broadcast chat** -- `broadcast_chat_store.py` has `set_mute` and `delete_chat_message` but they require the `actor` to be the session creator. No moderator authorization check.
2. **No moderator system messages** -- when a message is pinned or deleted, no system message is generated to inform viewers.
3. **No announcement message type** -- broadcast chat only has regular messages and product links; no styled "announcement" type.
4. **No moderator presence tracking** -- `broadcast_viewers.py` tracks viewer count but does not distinguish moderators from viewers.
5. **No delegate-authorized state transitions** -- `broadcast_orchestrator.py` checks that the caller is the session creator; no delegation support.
6. **No ban mechanism** -- `set_mute` is time-limited; there is no permanent ban for the session duration.
7. **No moderator badge** -- `broadcast_chat_rich.py` renders badges (subscriber, etc.) but has no moderator badge type.

---

## 3. Technical Design

### 3.1 DynamoDB Schema Changes

#### 3.1.1 Broadcast Chat Moderation Extensions

Add fields to broadcast chat items in the `broadcast_chat` table:

| Field | Type | Purpose |
|-------|------|---------|
| `pinned` | BOOL | Whether the message is pinned |
| `pinned_by` | S | Moderator user ID who pinned the message |
| `pinned_at` | N | Timestamp when pinned |
| `is_announcement` | BOOL | Whether this is a moderator announcement |
| `announcement_by` | S | Moderator user ID who posted the announcement |

#### 3.1.2 Broadcast Session Moderator Tracking

Add a new item pattern to the `broadcasts` table:

| PK Pattern | SK Pattern | Purpose | Key Fields |
|------------|------------|---------|------------|
| `SESSION#{session_id}` | `MOD#{delegate_id}` | Active moderator for broadcast | `delegate_id`, `display_name`, `connected_at`, `status` (online/offline), `actions_count` |
| `SESSION#{session_id}` | `BAN#{user_id}` | Banned user for broadcast session | `user_id`, `banned_by`, `banned_at`, `reason` |

#### 3.1.3 Moderation Audit Extensions

Add fields to broadcast audit items:

| Field | Type | Purpose |
|-------|------|---------|
| `moderator_id` | S | Delegate who performed the moderation action |
| `moderator_display_name` | S | Display name at time of action |
| `moderation_type` | S | `pin` / `unpin` / `delete` / `mute` / `ban` / `announcement` / `start` / `stop` |

### 3.2 Backend Service

**New file**: `app/services/delegate_broadcast.py` (~350 lines)

```python
"""Broadcast chat delegation service (DELEGATE-004)."""

from __future__ import annotations
import logging
from typing import Any, Dict, List, Optional
from uuid import uuid4
from app.core.tables import T
from app.core.time import now_ts
from app.services.delegates import require_delegate_permission, get_delegate
from app.services.broadcast_chat_store import (
    send_chat_message,
    delete_chat_message,
    get_mute_status,
    set_mute,
)
from app.services.broadcast_store import (
    get_session,
    transition_session_status,
    create_session,
)
from app.services.broadcast_sse import broadcast_event
from app.services.profile import get_profile

logger = logging.getLogger(__name__)

MAX_MUTE_DURATION_SECONDS = 86400  # 24 hours
MAX_ACTIVE_MODERATORS = 20


def pin_chat_message(
    *,
    session_id: str,
    message_id: str,
    moderator_id: str,
    creator_id: str,
) -> Dict[str, Any]:
    """Pin a message in broadcast chat.
    
    Requires broadcast_moderate permission. Unpins any previously
    pinned message (only one pinned message at a time).
    """
    _require_broadcast_moderator(session_id, moderator_id, creator_id)
    
    mod_profile = get_profile(moderator_id) or {}
    mod_name = mod_profile.get("display_name", moderator_id)
    
    # Find current pinned message and unpin it
    # Update target message: pinned=True, pinned_by, pinned_at
    # Send system message: "[Moderator @{mod_name}] pinned a message"
    # Broadcast SSE event: type="pin", message_id, moderator
    # Write moderation audit entry


def unpin_chat_message(
    *,
    session_id: str,
    message_id: str,
    moderator_id: str,
    creator_id: str,
) -> Dict[str, Any]:
    """Unpin a previously pinned message."""
    _require_broadcast_moderator(session_id, moderator_id, creator_id)
    # Remove pinned flag
    # Send system message
    # Broadcast SSE event


def delete_moderated_message(
    *,
    session_id: str,
    message_id: str,
    moderator_id: str,
    creator_id: str,
) -> Dict[str, Any]:
    """Delete a message from broadcast chat as a moderator."""
    _require_broadcast_moderator(session_id, moderator_id, creator_id)
    
    mod_profile = get_profile(moderator_id) or {}
    mod_name = mod_profile.get("display_name", moderator_id)
    
    # Delete the message
    delete_chat_message(session_id, message_id, moderator_id)
    # Send system message: "[Moderator @{mod_name}] removed a message"
    # Broadcast SSE event
    # Write audit entry


def mute_viewer(
    *,
    session_id: str,
    user_id: str,
    moderator_id: str,
    creator_id: str,
    duration_seconds: int,
) -> Dict[str, Any]:
    """Mute a viewer in broadcast chat for a specified duration."""
    _require_broadcast_moderator(session_id, moderator_id, creator_id)
    
    if duration_seconds > MAX_MUTE_DURATION_SECONDS:
        raise ValueError(f"Mute duration cannot exceed {MAX_MUTE_DURATION_SECONDS} seconds")
    
    mod_profile = get_profile(moderator_id) or {}
    mod_name = mod_profile.get("display_name", moderator_id)
    
    result = set_mute(session_id, user_id, duration_seconds, moderator_id)
    # Send system message: "[Moderator @{mod_name}] muted @{user} for {duration}"
    # Broadcast SSE event
    # Write audit entry
    return result


def ban_viewer(
    *,
    session_id: str,
    user_id: str,
    moderator_id: str,
    creator_id: str,
    reason: str = "",
) -> Dict[str, Any]:
    """Ban a viewer from broadcast chat for the session duration."""
    _require_broadcast_moderator(session_id, moderator_id, creator_id)
    
    ts = now_ts()
    mod_profile = get_profile(moderator_id) or {}
    mod_name = mod_profile.get("display_name", moderator_id)
    
    ban_item = {
        "pk": f"SESSION#{session_id}",
        "sk": f"BAN#{user_id}",
        "user_id": user_id,
        "banned_by": moderator_id,
        "banned_at": ts,
        "reason": reason,
    }
    T.broadcasts.put_item(Item=ban_item)
    # Send system message: "[Moderator @{mod_name}] banned @{user} from chat"
    # Broadcast SSE event
    # Write audit entry
    return ban_item


def unban_viewer(
    *,
    session_id: str,
    user_id: str,
    moderator_id: str,
    creator_id: str,
) -> None:
    """Unban a viewer from broadcast chat."""
    _require_broadcast_moderator(session_id, moderator_id, creator_id)
    # Delete BAN#{user_id} item
    # Broadcast SSE event
    # Write audit entry


def post_announcement(
    *,
    session_id: str,
    moderator_id: str,
    creator_id: str,
    text: str,
) -> Dict[str, Any]:
    """Post a highlighted announcement in broadcast chat."""
    _require_broadcast_moderator(session_id, moderator_id, creator_id)
    
    mod_profile = get_profile(moderator_id) or {}
    mod_name = mod_profile.get("display_name", moderator_id)
    
    # Create chat message with is_announcement=True
    # Display name includes "[Moderator]" prefix
    # Broadcast SSE event: type="announcement"
    # Write audit entry


def start_broadcast_as_delegate(
    *,
    session_id: str,
    delegate_id: str,
    creator_id: str,
) -> Dict[str, Any]:
    """Start a broadcast on behalf of the creator."""
    require_delegate_permission(
        creator_id=creator_id,
        delegate_id=delegate_id,
        required_permission="broadcast_control",
    )
    # Transition session to "live" using broadcast_orchestrator
    # Write delegation audit entry


def stop_broadcast_as_delegate(
    *,
    session_id: str,
    delegate_id: str,
    creator_id: str,
) -> Dict[str, Any]:
    """Stop a broadcast on behalf of the creator."""
    require_delegate_permission(
        creator_id=creator_id,
        delegate_id=delegate_id,
        required_permission="broadcast_control",
    )
    # Transition session to "ended"
    # Write delegation audit entry


def schedule_broadcast_as_delegate(
    *,
    delegate_id: str,
    creator_id: str,
    title: str,
    scheduled_at: int,
    profile_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Schedule a broadcast on behalf of the creator."""
    require_delegate_permission(
        creator_id=creator_id,
        delegate_id=delegate_id,
        required_permission="broadcast_control",
    )
    # Create session with status="scheduled", created_by=creator_id
    # Add delegate attribution
    # Write delegation audit entry


def register_moderator(
    *,
    session_id: str,
    moderator_id: str,
    creator_id: str,
) -> Dict[str, Any]:
    """Register a moderator as active for a broadcast session."""
    _require_broadcast_moderator(session_id, moderator_id, creator_id)
    
    ts = now_ts()
    mod_profile = get_profile(moderator_id) or {}
    
    mod_item = {
        "pk": f"SESSION#{session_id}",
        "sk": f"MOD#{moderator_id}",
        "delegate_id": moderator_id,
        "display_name": mod_profile.get("display_name", moderator_id),
        "connected_at": ts,
        "status": "online",
        "actions_count": 0,
    }
    T.broadcasts.put_item(Item=mod_item)
    return mod_item


def list_active_moderators(session_id: str) -> List[Dict[str, Any]]:
    """List all moderators currently active in a broadcast session."""
    # Query SESSION#{session_id} with sk begins_with "MOD#"


def list_banned_viewers(session_id: str) -> List[Dict[str, Any]]:
    """List all viewers banned from broadcast chat."""
    # Query SESSION#{session_id} with sk begins_with "BAN#"


def is_viewer_banned(session_id: str, user_id: str) -> bool:
    """Check if a viewer is banned from broadcast chat."""
    # get_item pk=SESSION#{session_id}, sk=BAN#{user_id}


def get_broadcast_moderation_log(
    session_id: str,
    *,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Get moderation actions for a broadcast session."""
    # Query broadcast audit entries filtered to moderation actions


# --- Internal helpers ---

def _require_broadcast_moderator(session_id: str, moderator_id: str, creator_id: str) -> None:
    """Verify the caller has broadcast_moderate permission for the creator."""
    session = get_session(session_id)
    if session.created_by != creator_id:
        raise HTTPException(403, "Session does not belong to specified creator")
    require_delegate_permission(
        creator_id=creator_id,
        delegate_id=moderator_id,
        required_permission="broadcast_moderate",
    )
```

### 3.3 Backend Router

**New file**: `app/routers/delegate_broadcast.py` (~250 lines)

```python
"""Broadcast delegation router (DELEGATE-004)."""

from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, Query
from app.services.sessions import require_ui_session  # actual location of require_ui_session
from app.services import delegate_broadcast as svc

router = APIRouter(prefix="/ui/broadcast/delegate", tags=["broadcast-delegation"])
```

### 3.4 Router Endpoints

| Method | Path | Auth | Permission | Description |
|--------|------|------|------------|-------------|
| `POST` | `/ui/broadcast/delegate/{creator_id}/sessions/{sid}/chat/{mid}/pin` | `require_ui_session` | `broadcast_moderate` | Pin a chat message |
| `DELETE` | `/ui/broadcast/delegate/{creator_id}/sessions/{sid}/chat/{mid}/pin` | `require_ui_session` | `broadcast_moderate` | Unpin a chat message |
| `DELETE` | `/ui/broadcast/delegate/{creator_id}/sessions/{sid}/chat/{mid}` | `require_ui_session` | `broadcast_moderate` | Delete a chat message |
| `POST` | `/ui/broadcast/delegate/{creator_id}/sessions/{sid}/mute` | `require_ui_session` | `broadcast_moderate` | Mute a viewer |
| `POST` | `/ui/broadcast/delegate/{creator_id}/sessions/{sid}/ban` | `require_ui_session` | `broadcast_moderate` | Ban a viewer |
| `DELETE` | `/ui/broadcast/delegate/{creator_id}/sessions/{sid}/ban/{uid}` | `require_ui_session` | `broadcast_moderate` | Unban a viewer |
| `POST` | `/ui/broadcast/delegate/{creator_id}/sessions/{sid}/announcement` | `require_ui_session` | `broadcast_moderate` | Post announcement |
| `POST` | `/ui/broadcast/delegate/{creator_id}/sessions/{sid}/start` | `require_ui_session` | `broadcast_control` | Start broadcast |
| `POST` | `/ui/broadcast/delegate/{creator_id}/sessions/{sid}/stop` | `require_ui_session` | `broadcast_control` | Stop broadcast |
| `POST` | `/ui/broadcast/delegate/{creator_id}/sessions/schedule` | `require_ui_session` | `broadcast_control` | Schedule broadcast |
| `POST` | `/ui/broadcast/delegate/{creator_id}/sessions/{sid}/moderator/register` | `require_ui_session` | `broadcast_moderate` | Register as active moderator |
| `GET` | `/ui/broadcast/delegate/{creator_id}/sessions/{sid}/moderators` | `require_ui_session` | `broadcast_moderate` | List active moderators |
| `GET` | `/ui/broadcast/delegate/{creator_id}/sessions/{sid}/bans` | `require_ui_session` | `broadcast_moderate` | List banned viewers |
| `GET` | `/ui/broadcast/delegate/{creator_id}/sessions/{sid}/moderation-log` | `require_ui_session` | `broadcast_moderate` | Get moderation action log |

### 3.5 Request/Response Models

**Add to `app/models.py`**:

```python
# -- Broadcast Delegation (DELEGATE-004) --

class BroadcastMuteIn(BaseModel):
    user_id: str
    duration_seconds: int = Field(ge=30, le=86400, description="Mute duration in seconds (30s to 24h)")

class BroadcastBanIn(BaseModel):
    user_id: str
    reason: str = Field(default="", max_length=500)

class BroadcastAnnouncementIn(BaseModel):
    text: str = Field(min_length=1, max_length=500)

class BroadcastScheduleIn(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    scheduled_at: int = Field(description="Unix timestamp, must be in the future")
    profile_id: Optional[str] = None

class BroadcastModeratorOut(BaseModel):
    delegate_id: str
    display_name: str = ""
    connected_at: int = 0
    status: str  # "online" | "offline"
    actions_count: int = 0

class BroadcastBanOut(BaseModel):
    user_id: str
    display_name: str = ""
    banned_by: str
    banned_by_display_name: str = ""
    banned_at: int = 0
    reason: str = ""

class BroadcastModerationLogEntry(BaseModel):
    event_id: str
    moderator_id: str
    moderator_display_name: str = ""
    moderation_type: str  # "pin" | "unpin" | "delete" | "mute" | "ban" | "unban" | "announcement"
    target_user_id: Optional[str] = None
    target_message_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    ts: int = 0

class BroadcastChatSystemMessage(BaseModel):
    """System message injected into chat for moderator actions."""
    message_id: str
    kind: str = "system"
    text: str  # e.g., "[Moderator @Bob] pinned a message"
    moderator_id: str
    moderator_display_name: str = ""
    moderation_type: str
    created_at: int = 0
```

### 3.6 Frontend Components

**New files**:

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `frontend/src/pages/broadcast/ModeratorPanel.tsx` | Moderator control panel overlay for broadcast chat | ~250 |
| `frontend/src/pages/broadcast/ModeratorActionBar.tsx` | Action buttons for each chat message (pin, delete) | ~80 |
| `frontend/src/pages/broadcast/ModeratorUserMenu.tsx` | Context menu for viewer actions (mute, ban) | ~100 |
| `frontend/src/pages/broadcast/AnnouncementComposer.tsx` | Announcement input with styled preview | ~60 |
| `frontend/src/pages/broadcast/ActiveModerators.tsx` | List of active moderators in broadcast | ~60 |
| `frontend/src/pages/broadcast/BroadcastControlPanel.tsx` | Start/stop/schedule controls for delegates | ~120 |
| `frontend/src/pages/broadcast/ModerationLog.tsx` | Moderation action history | ~100 |
| `frontend/src/api/endpoints/delegate-broadcast.ts` | API client wrappers | ~120 |

**Component tree**:

```
BroadcastPage (modified)
├── BroadcastPlayer (existing)
├── BroadcastChat (existing, modified)
│   ├── ChatMessage (existing, modified)
│   │   ├── ModeratorActionBar (visible to moderators)
│   │   │   ├── Pin/Unpin button
│   │   │   └── Delete button
│   │   ├── Pinned indicator (📌 for pinned messages)
│   │   ├── "[Moderator]" badge on moderator names
│   │   └── ModeratorUserMenu (right-click on viewer name)
│   │       ├── "Mute (5m / 30m / 1h)" options
│   │       ├── "Ban from chat" option
│   │       └── Viewer info (join time, message count)
│   ├── AnnouncementComposer (moderator input, styled differently)
│   ├── System messages ("[Moderator @name] pinned/deleted/muted")
│   └── Pinned message banner (top of chat)
├── ModeratorPanel (sidebar overlay)
│   ├── ActiveModerators list
│   ├── Banned viewers list with "Unban" buttons
│   ├── ModerationLog
│   └── Quick actions (clear all pins, slow mode toggle)
└── BroadcastControlPanel (broadcast_control delegates)
    ├── "Start Broadcast" button
    ├── "Stop Broadcast" button
    └── "Schedule Broadcast" form
```

### 3.7 SSE Event Types for Moderation

New SSE event types broadcast to all viewers and moderators:

| Event Type | Payload | When |
|------------|---------|------|
| `mod:pin` | `{message_id, moderator_name}` | Message pinned |
| `mod:unpin` | `{message_id, moderator_name}` | Message unpinned |
| `mod:delete` | `{message_id, moderator_name}` | Message deleted |
| `mod:mute` | `{user_id, moderator_name, duration}` | Viewer muted |
| `mod:ban` | `{user_id, moderator_name}` | Viewer banned |
| `mod:unban` | `{user_id, moderator_name}` | Viewer unbanned |
| `mod:announcement` | `{text, moderator_name}` | Announcement posted |
| `mod:join` | `{moderator_name}` | Moderator connected |
| `mod:leave` | `{moderator_name}` | Moderator disconnected |

### 3.8 Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `app/services/delegate_broadcast.py` | Broadcast delegation service | ~350 |
| `app/routers/delegate_broadcast.py` | REST API endpoints | ~250 |
| `frontend/src/pages/broadcast/ModeratorPanel.tsx` | Moderator control panel | ~250 |
| `frontend/src/pages/broadcast/ModeratorActionBar.tsx` | Per-message action buttons | ~80 |
| `frontend/src/pages/broadcast/ModeratorUserMenu.tsx` | Viewer context menu | ~100 |
| `frontend/src/pages/broadcast/AnnouncementComposer.tsx` | Announcement input | ~60 |
| `frontend/src/pages/broadcast/ActiveModerators.tsx` | Active moderators list | ~60 |
| `frontend/src/pages/broadcast/BroadcastControlPanel.tsx` | Start/stop/schedule controls | ~120 |
| `frontend/src/pages/broadcast/ModerationLog.tsx` | Moderation history | ~100 |
| `frontend/src/api/endpoints/delegate-broadcast.ts` | API wrappers | ~120 |
| `frontend/e2e/delegates-broadcast.spec.ts` | E2E tests | ~500 |

### 3.9 Files to Modify

| File | Change |
|------|--------|
| `app/main.py` | Register `delegate_broadcast_router` |
| `app/models.py` | Add BroadcastMute*, BroadcastBan*, BroadcastAnnouncement*, BroadcastModerator* models |
| `app/services/broadcast_chat_store.py` | Add `pinned`, `is_announcement` fields; check ban list in `_enforce_chat_mute`; add `_chat_msg_out` moderator badge |
| `app/services/broadcast_sse.py` | Add `mod:*` event types |
| `app/services/broadcast_audit.py` | Add moderator attribution fields |
| `scripts/local-ddb-init.py` | No new table needed (reuses `broadcasts` table) |
| `frontend/src/api/types.ts` | Add BroadcastModerator, BroadcastBan, BroadcastModeration types |
| `frontend/src/pages/broadcast/BroadcastChat.tsx` | Add moderator action bar, system messages, pinned message banner |

---

## 4. Concurrent Moderator Design

### 4.1 Multi-Moderator Coordination

Multiple moderators can be active simultaneously. Coordination rules:

1. **Pin conflicts**: Only one message can be pinned at a time. If moderator A pins message X and moderator B pins message Y, message X is unpinned and message Y becomes pinned. No lock needed -- last pin wins.
2. **Delete conflicts**: If two moderators delete the same message simultaneously, the second delete is a no-op (idempotent).
3. **Mute/ban overlap**: If moderator A mutes a user for 5 minutes and moderator B bans the same user, the ban takes precedence (more restrictive).
4. **Announcement ordering**: Announcements from multiple moderators appear in chronological order. No deduplication.

### 4.2 Moderator Presence

Moderator presence is tracked via periodic heartbeats:

1. On SSE connection: `register_moderator` creates/updates the `MOD#` item with `status=online`.
2. Every 30 seconds: moderator sends heartbeat; `connected_at` is updated.
3. On SSE disconnect: `status` set to `offline`.
4. Cleanup: moderators with `status=offline` for > 5 minutes are removed from the active list.

### 4.3 Ban Enforcement

Bans are session-scoped:
1. When a viewer is banned, a `BAN#{user_id}` item is created under the session.
2. `broadcast_chat_store.send_chat_message` checks `is_viewer_banned` before allowing a message.
3. Banned viewers can still watch the stream but cannot send messages.
4. Bans do not persist across sessions -- each broadcast starts fresh.

---

## 5. E2E Test Plan

**File**: `frontend/e2e/delegates-broadcast.spec.ts`

### Section 499: Broadcast Chat Moderation API (5 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 499.1 | Moderator pins a chat message | POST pin; 200; message has `pinned=true`, `pinned_by=bob` |
| 499.2 | Moderator deletes a chat message | DELETE message; 200; message no longer in chat history |
| 499.3 | Moderator mutes a viewer | POST mute with `duration_seconds=300`; 200; viewer cannot send messages |
| 499.4 | Moderator bans a viewer from chat | POST ban; 200; viewer in banned list; cannot send messages |
| 499.5 | Moderator posts an announcement | POST announcement; 200; message `is_announcement=true`, styled as system message |

### Section 500: Broadcast Control Delegation API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 500.1 | Delegate starts broadcast on behalf of creator | POST start; 200; session status transitions to `live` |
| 500.2 | Delegate stops broadcast on behalf of creator | POST stop; 200; session status transitions to `ended` |
| 500.3 | Delegate schedules broadcast on behalf of creator | POST schedule; 200; session created with `status=scheduled`, `created_by=creator` |
| 500.4 | Delegate without broadcast_control gets 403 | Delegate with only broadcast_moderate; POST start returns 403 |

### Section 501: Multi-Moderator & Ban API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 501.1 | Multiple moderators register for same session | Bob and Charlie both register; GET moderators returns both with `status=online` |
| 501.2 | Second pin replaces first pin | Bob pins message A; Charlie pins message B; only message B is pinned |
| 501.3 | Unban restores viewer chat access | Moderator bans viewer; unbans viewer; viewer can send message again |
| 501.4 | Banned viewers list returned correctly | Ban 2 viewers; GET bans; both appear with `banned_by` and `reason` |

### Section 502: Moderation Audit & System Messages API (3 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 502.1 | System message generated for pin action | After pin; chat history includes system message "[Moderator @Bob] pinned a message" |
| 502.2 | System message generated for mute action | After mute; chat history includes "[Moderator @Bob] muted @viewer for 5 minutes" |
| 502.3 | Moderation log records all actions | GET moderation-log; entries include pin, delete, mute, ban actions with correct moderator attribution |

**Total E2E tests: 16**

---

## 6. Security Considerations

### 6.1 Auth Requirements

| Endpoint | Auth | Permission Required |
|----------|------|---------------------|
| All moderation actions (pin, delete, mute, ban, announcement) | `require_ui_session` | `broadcast_moderate` |
| Broadcast control (start, stop, schedule) | `require_ui_session` | `broadcast_control` |
| Moderator list, ban list, moderation log | `require_ui_session` | `broadcast_moderate` |

### 6.2 Authorization Enforcement

- Session ownership is verified: the `created_by` field on the broadcast session must match the `creator_id` in the delegation.
- Moderators cannot mute/ban other moderators or the creator.
- Moderators cannot start/stop broadcasts without `broadcast_control` permission (even if they have `broadcast_moderate`).
- Ban enforcement is checked at the `send_chat_message` level, not at the API gateway, ensuring no bypass.

### 6.3 Rate Limiting

- Moderation actions (pin, delete, mute, ban): max 60 per moderator per minute.
- Announcements: max 10 per moderator per minute (prevent spam).
- Broadcast control (start/stop): max 5 per delegate per hour.

### 6.4 Abuse Prevention

- Moderators cannot ban the session creator.
- Mute duration capped at 24 hours.
- Ban reason is stored for audit purposes.
- All moderation actions are visible to viewers via system messages -- moderators cannot act invisibly.

---

## 7. Dependencies

| Dependency | Status | Required For |
|------------|--------|-------------|
| DELEGATE-001 | Required (must complete first) | `require_delegate_permission`, delegation infrastructure |
| `app/services/broadcast_chat_store.py` | Exists (modify) | Ban enforcement in `send_chat_message`, pin fields |
| `app/services/broadcast_store.py` | Exists | Session lifecycle for delegate-initiated transitions |
| `app/services/broadcast_sse.py` | Exists (modify) | New `mod:*` event types |
| `app/services/broadcast_audit.py` | Exists (modify) | Moderator attribution fields |
| `app/services/broadcast_orchestrator.py` | Exists | State transitions for delegate-started broadcasts |
| DELEGATE-005 | Not started | Will extend broadcast delegation to API clients |

---

## 8. Acceptance Criteria

1. Moderators can pin, unpin, and delete messages in broadcast chat.
2. Moderators can mute viewers for configurable durations.
3. Moderators can ban and unban viewers from broadcast chat.
4. Moderators can post styled announcements in broadcast chat.
5. All moderation actions generate visible system messages in chat.
6. Multiple moderators can be active simultaneously without conflicts.
7. Delegates with `broadcast_control` can start, stop, and schedule broadcasts.
8. Banned viewers cannot send messages but can still watch the stream.
9. All moderation actions are recorded in the moderation log.
10. Active moderator list shows online/offline status.
11. All 16 E2E tests pass.

---

## Codebase References

| File | Line(s) | What | Status |
|------|---------|------|--------|
| `app/services/delegates.py` | — | Delegate management (DELEGATE-001 dependency) | NOT YET CREATED |
| `app/services/broadcast_chat_store.py` | all (423 lines) | Broadcast chat CRUD, muting, rate limiting | EXISTS (modify) |
| `app/services/broadcast_store.py` | all (480 lines) | Broadcast session lifecycle | EXISTS |
| `app/services/broadcast_chat_rich.py` | all | Rich chat features (emotes, badges) | EXISTS (modify) |
| `app/services/broadcast_orchestrator.py` | all | Broadcast state transitions | EXISTS |
| `app/services/broadcast_state_machine.py` | all | State transition validation | EXISTS |
| `app/services/broadcast_sse.py` | all (49 lines) | SSE event streaming | EXISTS (modify) |
| `app/services/broadcast_viewers.py` | all | Viewer tracking | EXISTS (modify) |
| `app/services/broadcast_scheduler.py` | all | Scheduled broadcast promotion | EXISTS |
| `app/services/broadcast_audit.py` | all | Broadcast audit logging | EXISTS (modify) |
| `app/services/sessions.py` | 283 | `require_ui_session` (NOT in app/auth/deps.py) | EXISTS |

---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_delegate_broadcast.py`

| # | Test Function | Description | Mocks |
|---|--------------|-------------|-------|
| 1 | `test_pin_chat_message` | Message pinned and system message generated | moto DDB |
| 2 | `test_delete_moderated_message` | Message deleted and audit entry written | moto DDB |
| 3 | `test_mute_viewer_duration_cap` | Mute duration capped at 24 hours | moto DDB |
| 4 | `test_ban_viewer_creates_item` | BAN# item created under session PK | moto DDB |
| 5 | `test_banned_viewer_cannot_chat` | send_chat_message rejected for banned user | moto DDB |
| 6 | `test_start_broadcast_requires_control` | 403 without broadcast_control permission | moto DDB |
| 7 | `test_moderator_cannot_ban_creator` | Ban rejected for session creator | moto DDB |

### Integration Tests

| # | Scenario | Services Involved |
|---|----------|-------------------|
| 1 | Multi-moderator: both pin/delete independently without conflicts | delegate_broadcast, broadcast_chat_store |
| 2 | Ban enforcement: banned viewer blocked from chat | delegate_broadcast, broadcast_chat_store |
| 3 | Broadcast control: delegate starts, stops, schedules broadcasts | delegate_broadcast, broadcast_store |

### E2E Tests (Playwright)

**File**: `frontend/e2e/delegates-broadcast.spec.ts`

Tests use `injectAuth(page, identity)` for cookie-based auth and include CSRF headers (`x-csrf-token`) on all POST/PUT/DELETE requests. Negative tests cover 401 (unauthenticated), 403 (wrong role/user), 404 (not found), 409 (conflict), and 422 (validation) responses. Edge cases include duplicate operations (idempotency), concurrent access, and feature-flag-disabled behavior.

**Total E2E tests**: 16

### Test Data Requirements

- DDB seeds: required tables created via `scripts/local-ddb-init.py`
- Test users: Alice, Bob, Root, Charlie via `e2e_session_setup.py` / `e2e_admin_session_setup.py`
- Feature flag: `BROADCAST_DELEGATION_ENABLED` in `.env.local`

### CI/Pipeline

- Feature flag: `BROADCAST_DELEGATION_ENABLED` must be enabled for tests to run
- Serial execution: run with `--workers 1` to avoid shared state conflicts
- Retry safety: tests use unique timestamps/UUIDs per run; safe to retry on failure

---

## Dependencies & Merge Safety

### Depends On

| Ticket | Status | What It Provides |
|--------|--------|-----------------|
| DELEGATE-001 | Required | `require_delegate_permission`, delegation infrastructure |

### Depended On By

| Ticket | What It Needs |
|--------|--------------|
| DELEGATE-005 | Wraps broadcast delegation for API key access |

### Merge Strategy

**Sequential (after DELEGATE-001)** -- Changes are additive (new service files, new router, new frontend pages). Shared infrastructure files (`main.py`, `settings.py`, `tables.py`, `local-ddb-init.py`) receive only additive modifications.

### Merge Checklist

- [ ] `app/services/delegate_broadcast.py` created
- [ ] `app/routers/delegate_broadcast.py` registered in `main.py`
- [ ] `mod:*` SSE event types added to `broadcast_sse.py`
- [ ] Ban check added to `broadcast_chat_store.py`
- [ ] All 16 E2E tests pass
- [ ] Feature flag `BROADCAST_DELEGATION_ENABLED` added to `.env.local.example`
- [ ] All E2E tests pass
- [ ] No regressions in existing test suite
