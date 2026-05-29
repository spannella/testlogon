# DELEGATE-002: Chat Delegation

**Ticket**: DELEGATE-002
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 8-10 days

---

## 1. Overview & Motivation

### 1.1 Purpose

DELEGATE-002 enables delegates with `chat_read` and `chat_respond` permissions to view and respond to a creator's direct messages and group chats on their behalf. This is the core chat delegation feature that allows creators to scale their audience interactions by having assistants handle routine conversations. Delegates see a "Managing @creator" mode in the messaging UI, and creators retain full visibility into which messages were sent by delegates through an internal audit view.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Delegate | As a delegate with `chat_read`, I want to view the creator's conversation list so that I can monitor incoming messages. | GET conversations returns creator's conversations; delegate sees them in "Managing" mode UI. |
| Delegate | As a delegate with `chat_respond`, I want to send messages as the creator so that fans receive timely responses. | POST message with `on_behalf_of` header; message appears as from creator; optional delegate tag appended. |
| Creator | As a creator, I want to see which messages were sent by delegates so that I can review their work. | Messages sent by delegates include `sent_by_delegate` metadata; creator audit view highlights delegated messages. |
| Creator | As a creator, I want to configure whether delegate names are shown to recipients so that I control my brand. | Setting `show_delegate_tag` on delegate record; tag format configurable (e.g., "[via @assistant]"). |
| Delegate | As a delegate, I want to switch between managing multiple creators from one interface. | Creator selector dropdown in messaging header; switching loads the selected creator's conversations. |
| Delegate | As a delegate, I want to receive real-time notifications of new messages in creator's conversations. | SSE stream for creator's conversations delivered to delegate connections. |
| Creator | As a creator, I want delegates to be unable to read my E2E encrypted messages so that my private conversations stay private. | Encrypted messages return `encryption_envelope` but delegate cannot decrypt; UI shows "[Encrypted message]" placeholder. |
| Delegate | As a delegate, I want to see which conversations I've already responded to so that I don't duplicate effort. | Delegated messages carry `delegate_id` metadata; UI shows "Responded by you" indicator. |

### 1.3 Why This Is Needed

Creators with thousands of subscribers receive hundreds of DMs daily. Without chat delegation, creators must either ignore messages (hurting engagement and revenue) or spend all their time in the inbox. Chat delegation lets trusted team members handle routine interactions -- answering FAQs, processing tip requests, and managing conversation flow -- while the creator focuses on content creation. The delegate tag feature ensures transparency with fans who want to know if they're talking to the creator directly.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

| Component | Location | Relevance |
|-----------|----------|-----------|
| Messaging router | `app/routers/messaging.py` (~1200 lines) | All conversation/message endpoints; needs `on_behalf_of` parameter support |
| Messaging drafts | `app/services/messaging_drafts.py` | Draft message service; delegates may use drafts |
| Messaging routing | `app/services/messaging_routing.py` | Message routing logic; needs delegate-aware routing |
| Messaging SSE | Messaging SSE stream in router | Real-time message delivery; needs delegate subscription |
| Broadcast SSE | `app/services/broadcast_sse.py` | SSE pattern reference for multi-subscriber streams |
| Delegates service | `app/services/delegates.py` (DELEGATE-001) | `require_delegate_permission`, `DelegationContext`, audit logging |
| ConversationView | `frontend/src/pages/messages/ConversationView.tsx` | Message UI; needs "Managing" mode and delegate tag rendering |
| ConversationList | `frontend/src/pages/messages/ConversationList.tsx` | Conversation sidebar; needs creator-context switching |
| useMessagingStream | `frontend/src/pages/messages/useMessagingStream.ts` | SSE hook; needs creator-scoped subscription |

### 2.2 Gaps

1. **No `on_behalf_of` parameter** -- all messaging endpoints assume `user_sub` from session is the message sender. No mechanism to specify an alternate sender identity.
2. **No delegate metadata on messages** -- `MessageOut` does not carry `sent_by_delegate` or `delegate_id` fields.
3. **No delegate SSE subscription** -- SSE streams are keyed by the authenticated user's conversations, not by a creator's conversations on behalf of a delegate.
4. **No "Managing" UI mode** -- the messaging frontend has no concept of acting on behalf of another user.
5. **No creator selector** -- no UI component for switching between managed creators.
6. **No delegate audit for chat actions** -- the delegation audit infrastructure from DELEGATE-001 needs to be wired into every messaging endpoint.
7. **No encrypted message handling for delegates** -- encrypted messages are delivered with full envelope; delegates would see ciphertext if not handled.

---

## 3. Technical Design

### 3.1 DynamoDB Schema Changes

No new table required. Changes to existing messaging patterns:

#### 3.1.1 Message Item Extensions

Add fields to message items in the `messages` table:

| Field | Type | Purpose |
|-------|------|---------|
| `sent_by_delegate` | S | Delegate user ID who sent the message (absent if sent by creator directly) |
| `delegate_display_name` | S | Display name of the delegate at the time of sending |
| `delegate_tag` | S | Formatted tag string (e.g., "[via @Bob]") if creator enabled delegate tags |

These fields are stored on the message item and returned in `MessageOut` so both the creator's audit view and the recipient can see delegate attribution.

#### 3.1.2 Delegate Conversation Access Index

To enable delegates to efficiently list a creator's conversations without scanning:

Add a new DDB item pattern to the delegates table:

| PK Pattern | SK Pattern | Purpose |
|------------|------------|---------|
| `CREATOR#{creator_id}` | `CHAT_ACCESS#{delegate_id}` | Tracks which delegate has active chat access (materialized from permission checks) |

This is a lightweight cache to avoid per-request permission lookups on the hot conversation list path.

### 3.2 Backend Service

**New file**: `app/services/delegate_chat.py` (~300 lines)

```python
"""Chat delegation service (DELEGATE-002)."""

from __future__ import annotations
import logging
from typing import Any, Dict, List, Optional
from app.core.tables import T
from app.core.time import now_ts
from app.services.delegates import (
    require_delegate_permission,
    get_delegate,
    DelegationContext,
)
from app.services.profile import get_profile

logger = logging.getLogger(__name__)


def list_creator_conversations(
    *,
    creator_id: str,
    delegate_id: str,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List creator's conversations for a delegate.
    
    Requires chat_read permission. Returns the same shape as
    the standard list_conversations but scoped to the creator.
    """
    require_delegate_permission(
        creator_id=creator_id,
        delegate_id=delegate_id,
        required_permission="chat_read",
    )
    # Reuse existing list_conversations logic with creator_id as the user


def get_creator_conversation_messages(
    *,
    creator_id: str,
    delegate_id: str,
    conversation_id: str,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Get messages in a creator's conversation for a delegate.
    
    Requires chat_read permission. Encrypted messages return
    envelope but delegate cannot decrypt.
    """
    require_delegate_permission(
        creator_id=creator_id,
        delegate_id=delegate_id,
        required_permission="chat_read",
    )
    # Reuse existing list_messages logic with creator_id as the user
    # Mark encrypted messages with delegate_cannot_decrypt=True


def send_message_as_creator(
    *,
    creator_id: str,
    delegate_id: str,
    conversation_id: str,
    text: str,
    tip_amount_cents: int = 0,
    lock_price_cents: int = 0,
    reply_to_message_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Send a message as the creator via delegation.
    
    Requires chat_respond permission. Message is attributed to
    the creator but carries delegate metadata.
    """
    require_delegate_permission(
        creator_id=creator_id,
        delegate_id=delegate_id,
        required_permission="chat_respond",
    )
    
    delegate_item = get_delegate(creator_id, delegate_id)
    delegate_profile = get_profile(delegate_id) or {}
    
    # Build delegate tag if enabled
    delegate_tag = None
    if delegate_item.get("show_delegate_tag"):
        fmt = delegate_item.get("delegate_tag_format", "[via @{delegate_name}]")
        delegate_tag = fmt.replace("{delegate_name}", delegate_profile.get("display_name", delegate_id))
    
    # Append tag to message text if configured
    final_text = text
    if delegate_tag:
        final_text = f"{text} {delegate_tag}"
    
    # Call existing send_text_message with creator_id as sender
    # Add delegate metadata fields to the message item
    # Write delegation audit entry


def get_delegated_messages(
    *,
    creator_id: str,
    conversation_id: Optional[str] = None,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Get messages sent by delegates in creator's conversations.
    
    Creator-only audit view. Filters messages where
    sent_by_delegate is non-empty.
    """
    # Query messages with FilterExpression for sent_by_delegate


def _redact_encrypted_for_delegate(message: Dict[str, Any]) -> Dict[str, Any]:
    """Replace encrypted message content with placeholder for delegates."""
    if message.get("encryption_envelope"):
        message["text"] = None
        message["delegate_cannot_decrypt"] = True
    return message
```

### 3.3 Backend Router Changes

**Modify**: `app/routers/messaging.py` -- add delegation support to existing endpoints.

**New router section**: Add delegate-specific endpoints alongside existing messaging endpoints.

```python
# --- Delegation endpoints (DELEGATE-002) ---

@router.get("/ui/messaging/delegate/{creator_id}/conversations")
async def list_delegated_conversations(
    creator_id: str,
    ctx: dict = Depends(require_ui_session),
    limit: int = Query(50, ge=1, le=200),
    cursor: Optional[str] = None,
):
    """List creator's conversations as a delegate."""

@router.get("/ui/messaging/delegate/{creator_id}/conversations/{conversation_id}/messages")
async def list_delegated_messages(
    creator_id: str,
    conversation_id: str,
    ctx: dict = Depends(require_ui_session),
    limit: int = Query(50, ge=1, le=200),
    cursor: Optional[str] = None,
):
    """List messages in creator's conversation as a delegate."""

@router.post("/ui/messaging/delegate/{creator_id}/conversations/{conversation_id}/messages")
async def send_delegated_message(
    creator_id: str,
    conversation_id: str,
    body: SendMessageIn,
    ctx: dict = Depends(require_ui_session),
):
    """Send a message as the creator via delegation."""

@router.get("/ui/messaging/delegate/{creator_id}/audit")
async def list_delegated_chat_audit(
    creator_id: str,
    ctx: dict = Depends(require_ui_session),
    conversation_id: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
):
    """List messages sent by delegates in creator's conversations (creator only)."""

@router.get("/ui/messaging/delegate/{creator_id}/sse")
async def delegate_sse_stream(
    creator_id: str,
    ctx: dict = Depends(require_ui_session),
):
    """SSE stream for creator's conversations, delivered to delegate."""
```

### 3.4 Router Endpoints (Complete)

| Method | Path | Auth | Permission | Description |
|--------|------|------|------------|-------------|
| `GET` | `/ui/messaging/delegate/{creator_id}/conversations` | `require_ui_session` | `chat_read` | List creator's conversations |
| `GET` | `/ui/messaging/delegate/{creator_id}/conversations/{cid}/messages` | `require_ui_session` | `chat_read` | List messages in creator's conversation |
| `POST` | `/ui/messaging/delegate/{creator_id}/conversations/{cid}/messages` | `require_ui_session` | `chat_respond` | Send message as creator |
| `GET` | `/ui/messaging/delegate/{creator_id}/audit` | `require_ui_session` | creator only | List delegated messages (audit) |
| `GET` | `/ui/messaging/delegate/{creator_id}/sse` | `require_ui_session` | `chat_read` | SSE stream for creator's conversations |

### 3.5 Request/Response Models

**Add to `app/models.py`**:

```python
# -- Chat Delegation (DELEGATE-002) --

class DelegatedSendMessageIn(BaseModel):
    text: str = Field(min_length=1, max_length=5000)
    tip_amount_cents: int = Field(default=0, ge=0)
    lock_price_cents: int = Field(default=0, ge=0)
    reply_to_message_id: Optional[str] = None

class DelegatedMessageOut(BaseModel):
    """Extends MessageOut with delegate metadata."""
    message_id: str
    conversation_id: str
    sender_id: str  # Always the creator's ID
    text: Optional[str] = None
    kind: str = "text"
    created_at: int = 0
    sent_by_delegate: Optional[str] = None
    delegate_display_name: Optional[str] = None
    delegate_tag: Optional[str] = None
    delegate_cannot_decrypt: bool = False
    encryption_envelope: Optional[Dict[str, Any]] = None
    # ... other standard MessageOut fields

class DelegatedConversationOut(BaseModel):
    """Conversation with delegate-specific context."""
    conversation_id: str
    kind: str  # "dm" | "group"
    participants: List[Dict[str, Any]]
    last_message: Optional[Dict[str, Any]] = None
    last_message_at: int = 0
    unread_count: int = 0
    has_encrypted: bool = False  # True if any messages are encrypted (delegate can't read them)
    delegate_message_count: int = 0  # How many messages delegate has sent in this conversation

class ChatDelegateAuditEntry(BaseModel):
    message_id: str
    conversation_id: str
    delegate_id: str
    delegate_display_name: str = ""
    text_preview: str = ""  # First 100 chars of message text
    created_at: int = 0
```

### 3.6 Frontend Components

**New files**:

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `frontend/src/pages/messages/DelegateConversationView.tsx` | Conversation view in "Managing" mode | ~300 |
| `frontend/src/pages/messages/CreatorSelector.tsx` | Dropdown for switching between managed creators | ~80 |
| `frontend/src/pages/messages/DelegateMessageBubble.tsx` | Message bubble with delegate attribution | ~60 |
| `frontend/src/pages/messages/DelegateBanner.tsx` | "Managing @creator" banner in messaging header | ~40 |
| `frontend/src/pages/messages/DelegateAuditView.tsx` | Creator audit view of delegated messages | ~120 |

**Component tree**:

```
MessagesPage (modified)
├── DelegateBanner (when in managing mode)
│   ├── "Managing @{creator_name}" label
│   ├── CreatorSelector dropdown
│   └── "Exit Managing" button
├── ConversationList (reused, scoped to creator's conversations)
│   └── For each conversation:
│       ├── Standard conversation preview
│       ├── "[Encrypted]" badge if has_encrypted
│       └── "Responded" badge if delegate has sent messages
├── DelegateConversationView (replaces ConversationView in managing mode)
│   ├── DelegateMessageBubble for each message
│   │   ├── Standard message content
│   │   ├── "[via @delegate]" tag (if shown)
│   │   ├── "[Encrypted message]" placeholder (if encrypted)
│   │   └── "Sent by you" indicator (for delegate's own delegated messages)
│   ├── ComposeBar (sends via delegate endpoint)
│   │   └── Encrypted message compose disabled (greyed out E2E encrypt toggle)
│   └── "[Encrypted - cannot decrypt]" banner for encrypted messages
└── DelegateAuditView (creator-only tab)
    └── Filtered list of messages with delegate attribution
```

### 3.7 SSE Architecture for Delegates

Delegates need real-time message updates for the creator's conversations. The approach:

1. **New SSE endpoint**: `/ui/messaging/delegate/{creator_id}/sse` -- subscribes the delegate to the creator's message events.
2. **Server-side fan-out**: When a new message arrives for the creator, the SSE dispatcher checks if any active delegates with `chat_read` have open SSE connections and fans out the event.
3. **Event filtering**: Delegates receive message events but NOT account events (settings changes, billing, security).
4. **Connection lifecycle**: SSE connections are validated on each heartbeat (every 30s) against the delegate's current permission status. If revoked, the connection closes.
5. **Encrypted message events**: Delivered with `type: "encrypted_message"` and no decrypted content -- delegate sees the event notification but cannot read the content.

### 3.8 Encrypted Message Handling

Delegates CANNOT access encrypted messages. The system enforces this at multiple levels:

1. **Backend**: `_redact_encrypted_for_delegate` replaces `text` with `null` and sets `delegate_cannot_decrypt=True` when serving messages to delegates.
2. **Frontend**: `DelegateMessageBubble` renders "[Encrypted message - creator only]" placeholder when `delegate_cannot_decrypt` is true.
3. **Compose**: The E2E encryption toggle is disabled in delegate mode. Delegates can only send plaintext messages.
4. **SSE**: Encrypted message events to delegates include the message metadata (sender, timestamp) but not the decrypted text.

### 3.9 Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `app/services/delegate_chat.py` | Chat delegation service | ~300 |
| `frontend/src/pages/messages/DelegateConversationView.tsx` | Delegate conversation view | ~300 |
| `frontend/src/pages/messages/CreatorSelector.tsx` | Creator selector dropdown | ~80 |
| `frontend/src/pages/messages/DelegateMessageBubble.tsx` | Delegate message bubble | ~60 |
| `frontend/src/pages/messages/DelegateBanner.tsx` | Managing banner | ~40 |
| `frontend/src/pages/messages/DelegateAuditView.tsx` | Delegated message audit view | ~120 |
| `frontend/e2e/delegates-chat.spec.ts` | E2E tests | ~500 |

### 3.10 Files to Modify

| File | Change |
|------|--------|
| `app/routers/messaging.py` | Add delegation endpoints; add `sent_by_delegate` field to message creation |
| `app/models.py` | Add DelegatedSendMessageIn, DelegatedMessageOut, DelegatedConversationOut, ChatDelegateAuditEntry |
| `frontend/src/pages/messages/ConversationList.tsx` | Add delegate mode rendering; creator-scoped queries |
| `frontend/src/pages/messages/ConversationView.tsx` | Delegate mode awareness; disable E2E encrypt for delegates |
| `frontend/src/pages/messages/useMessagingStream.ts` | Add delegate SSE subscription mode |
| `frontend/src/api/endpoints/messaging.ts` | Add delegate conversation/message API wrappers |
| `frontend/src/api/types.ts` | Add DelegatedMessage, DelegatedConversation types |
| `frontend/src/stores/authStore.ts` | Add `managingCreatorId` state for delegate mode |

---

## 4. Delegate Mode State Management

### 4.1 Auth Store Extension

Add `managingCreatorId` to `authStore` (Zustand):

```typescript
interface AuthState {
  // ... existing fields
  managingCreatorId: string | null;
  managingCreatorName: string | null;
  setManagingCreator: (creatorId: string | null, name?: string) => void;
  isManagingMode: () => boolean;
}
```

### 4.2 API Client Header Injection

When `managingCreatorId` is set, the axios instance in `api/client.ts` automatically adds:
- `X-On-Behalf-Of: {managingCreatorId}` header to all requests
- Routes API calls to the delegate-specific endpoints

### 4.3 React Query Key Scoping

All messaging React Query keys include the `managingCreatorId` when in delegate mode:

```typescript
// Normal mode
["conversations", userId]
// Delegate mode
["delegate", "conversations", creatorId, delegateId]
```

This ensures cache isolation between the delegate's own conversations and the managed creator's conversations.

### 4.4 Edge Cases

- **Delegate switches creators**: Clear React Query cache for the previous creator; load fresh data for the new creator.
- **Permission revoked while managing**: Next API call returns 403; delegate mode auto-exits; toast notification shown.
- **Creator sends while delegate is typing**: Standard optimistic update conflict -- delegate sees creator's message appear in real-time via SSE.
- **Multiple delegates managing simultaneously**: Each delegate has their own SSE connection; messages from any delegate appear to all delegates in real-time.
- **Delegate tag overlap with message content**: Tag is appended as a separate suffix, not parsed from message content. No injection risk.

---

## 5. E2E Test Plan

**File**: `frontend/e2e/delegates-chat.spec.ts`

### Section 491: Chat Read Delegation API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 491.1 | Delegate lists creator's conversations | Alice adds Bob as delegate (chat_read); Bob GET `/ui/messaging/delegate/alice/conversations`; 200; returns Alice's conversations |
| 491.2 | Delegate reads messages in creator's conversation | Bob GET `.../conversations/{cid}/messages`; 200; returns message list |
| 491.3 | Delegate without chat_read gets 403 | Charlie added with feed_post only; GET delegate conversations returns 403 |
| 491.4 | Encrypted messages redacted for delegate | Alice sends encrypted message; Bob reads via delegate endpoint; `delegate_cannot_decrypt=true`, `text=null` |

### Section 492: Chat Respond Delegation API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 492.1 | Delegate sends message as creator | Bob POST `.../delegate/alice/conversations/{cid}/messages`; 200; message `sender_id=alice`, `sent_by_delegate=bob` |
| 492.2 | Delegate tag appended when enabled | Creator settings `show_delegate_tag=true`; message text ends with "[via @Bob]" |
| 492.3 | Delegate tag omitted when disabled | Creator settings `show_delegate_tag=false`; message text has no tag suffix |
| 492.4 | Delegate without chat_respond gets 403 on send | Delegate with only chat_read; POST message returns 403 |

### Section 493: Chat Delegate Audit API (3 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 493.1 | Creator sees delegated messages in audit | Alice GET `.../delegate/alice/audit`; response includes Bob's delegated messages with `delegate_id`, `text_preview` |
| 493.2 | Audit filters by conversation | GET audit with `conversation_id` param; only messages from that conversation returned |
| 493.3 | Delegate cannot access creator's audit endpoint | Bob GET `.../delegate/alice/audit`; 403 (creator-only) |

### Section 494: Chat Delegation SSE & E2E (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 494.1 | Delegate receives SSE for new message in creator's conversation | Bob opens SSE; third party sends message to Alice; Bob receives message event |
| 494.2 | Revoked delegate SSE closes | Alice revokes Bob; Bob's SSE connection closes on next heartbeat |
| 494.3 | Multiple delegates see each other's messages | Bob and Charlie both delegates; Bob sends; Charlie sees Bob's delegated message in real-time |
| 494.4 | Delegate mode exit clears managed state | Bob exits managing mode; conversations reload with Bob's own conversations |

**Total E2E tests: 15**

---

## 6. Security Considerations

### 6.1 Auth Requirements

| Endpoint | Auth | Permission Required |
|----------|------|---------------------|
| GET delegate conversations | `require_ui_session` | `chat_read` |
| GET delegate messages | `require_ui_session` | `chat_read` |
| POST delegate messages | `require_ui_session` | `chat_respond` |
| GET delegate audit | `require_ui_session` | Creator only (not delegate) |
| GET delegate SSE | `require_ui_session` | `chat_read` |

### 6.2 Authorization Enforcement

- Every delegate endpoint calls `require_delegate_permission` before accessing creator data.
- The `creator_id` in the URL path is validated against the delegation record -- delegates cannot guess a creator ID.
- `chat_respond` implies `chat_read` (you must be able to read to respond meaningfully), but the permissions are tracked independently for audit granularity.
- Encrypted messages are redacted at the service layer, not the router layer, so no code path can accidentally expose plaintext to delegates.

### 6.3 Rate Limiting

- Delegate message sending: max 60 messages per minute per delegate per creator (more generous than direct user rate limit because delegates handle multiple conversations).
- Delegate conversation listing: max 120 requests per minute.
- SSE connections: max 3 concurrent per delegate per creator.

### 6.4 Data Privacy

- Delegates see the creator's conversations but NOT the creator's account settings, billing, security, or contact list.
- Message content sent by delegates is fully visible to the creator in the audit view.
- Encrypted messages are architecturally protected -- the creator's private key never leaves the creator's device, and the delegation system has no key escrow.

---

## 7. Dependencies

| Dependency | Status | Required For |
|------------|--------|-------------|
| DELEGATE-001 | Required (must complete first) | `require_delegate_permission`, `DelegationContext`, audit logging infrastructure |
| `app/routers/messaging.py` | Exists (modify) | Add delegation endpoints and delegate metadata fields |
| `app/services/delegates.py` | From DELEGATE-001 | Permission checks and audit trail |
| `app/services/profile.py` | Exists | Delegate display names for tags |
| `frontend/src/stores/authStore.ts` | Exists (modify) | `managingCreatorId` state |
| `frontend/src/pages/messages/*` | Exists (modify) | Delegate mode awareness |
| DELEGATE-005 | Not started | Will extend chat delegation to API clients |

---

## 8. Acceptance Criteria

1. Delegates with `chat_read` can list and read the creator's conversations and messages.
2. Delegates with `chat_respond` can send messages that appear as from the creator.
3. Delegate tag is appended to messages when enabled by the creator.
4. Encrypted messages are inaccessible to delegates -- they see "[Encrypted message]" placeholder.
5. Creator can view all delegated messages in the audit view with delegate attribution.
6. Delegates receive real-time SSE events for the creator's conversations.
7. Permission revocation immediately terminates delegate access and SSE connections.
8. Multiple delegates can manage the same creator's chat simultaneously.
9. Delegate mode UI shows "Managing @creator" banner with creator selector.
10. All 15 E2E tests pass.

---

## 9. Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                   Chat Delegation Architecture                      │
└─────────────────────────────────────────────────────────────────────┘

  Delegate User                      Creator Account
       │                                  │
       │  "Managing @creator" mode        │  Owner of conversations
       │                                  │
       ▼                                  │
  ┌──────────────────────────────────┐    │
  │ Frontend (delegate mode)         │    │
  │                                  │    │
  │ authStore.managingCreatorId set  │    │
  │ API calls pass creator_id header │    │
  │ Delegate banner shown            │    │
  └──────────┬───────────────────────┘    │
             │                            │
             ▼                            │
  ┌──────────────────────────────────┐    │
  │ Backend (messaging.py)           │    │
  │                                  │    │
  │ require_delegate_permission()    │    │
  │ ├── chat_read → list, read      │    │
  │ ├── chat_respond → send         │    │
  │ └── append delegate_tag         │    │
  │                                  │    │
  │ Encrypted msgs → "[Encrypted]"  │    │
  │ Audit → delegate_sub logged     │    │
  └──────────┬───────────────────────┘    │
             │                            │
             ▼                            │
  ┌──────────────────────────────────┐    │
  │ SSE Stream                       │    │
  │                                  │    │
  │ Delegate subscribes to creator's │    │
  │ conversation events              │    │
  │ Revocation → close connection    │    │
  └──────────────────────────────────┘    │
```

---

## 10. DynamoDB Access Patterns

| Access Pattern | Table | PK | SK | Notes |
|----------------|-------|----|----|-------|
| Check delegate permission | `delegates` | `CREATOR#{creator_id}` | `DELEGATE#{delegate_id}` | Verify permission set |
| List creator's conversations | `conversations` | `USER#{creator_id}` | begins_with `CONV#` | Delegate reads as creator |
| Send delegated message | `messages` | `CONV#{conv_id}` | `MSG#{msg_id}` | Added: delegate_sub, delegate_tag |
| Audit delegated messages | `messages` | `CONV#{conv_id}` | begins_with `MSG#` | Filter: delegate_sub is not null |
| Revoke delegate access | `delegates` | `CREATOR#{creator_id}` | `DELEGATE#{delegate_id}` | DELETE item |

---

## 11. API Request/Response Examples

```bash
# --- GET /ui/messaging/conversations (as delegate for creator) ---
curl http://localhost:8000/ui/messaging/conversations \
  -H "Cookie: ui_session=delegate_sess; ui_access_token=eyJ..." \
  -H "X-Managing-Creator: creator-sub-001"

# Response 200:
{
  "conversations": [
    {
      "conversation_id": "conv-abc",
      "participants": ["creator-sub-001", "fan-001"],
      "last_message_at": 1748534400,
      "last_message": {"text": "Hey creator!", "sender": "fan-001"}
    }
  ]
}

# --- POST /ui/messaging/conversations/{conv_id}/messages (as delegate) ---
curl -X POST http://localhost:8000/ui/messaging/conversations/conv-abc/messages \
  -H "Cookie: ui_session=delegate_sess; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_tok_123" \
  -H "X-Managing-Creator: creator-sub-001" \
  -H "Content-Type: application/json" \
  -d '{"text": "Thanks for reaching out! -- sent by team"}'

# Response 201:
{
  "message_id": "m_abc123",
  "sender": "creator-sub-001",
  "text": "Thanks for reaching out! -- sent by team",
  "delegate_tag": "TeamMember",
  "delegate_sub": "delegate-sub-001",
  "created_at": 1748534500
}
```

---

## 12. Error Handling Matrix

| Error Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|----------------|-------------|------------|---------------------|-----------------|
| No delegation permission | 403 | `NO_DELEGATE_PERMISSION` | "You don't have permission to manage this creator's chat." | Request permission from creator |
| chat_read only, tried to send | 403 | `CHAT_RESPOND_REQUIRED` | "You only have read access to this chat." | Request chat_respond permission |
| Creator not found | 404 | `CREATOR_NOT_FOUND` | "Creator account not found." | Verify creator ID |
| Permission revoked mid-session | 403 | `PERMISSION_REVOKED` | "Your delegation access has been revoked." | SSE closes; redirect to own account |
| Encrypted message access | 200 | (placeholder shown) | "[Encrypted message]" | Cannot decrypt; intended behavior |
| Conversation not found | 404 | `CONVERSATION_NOT_FOUND` | "Conversation not found." | Verify conversation ID |

---

## 13. Pydantic Models

```python
from pydantic import BaseModel, Field
from typing import Optional

class DelegatedMessageIn(BaseModel):
    text: str = Field(..., min_length=1, max_length=5000)
    delegate_tag: Optional[str] = Field(default=None, max_length=50)

class DelegatedMessageOut(BaseModel):
    message_id: str
    sender: str
    text: str
    delegate_tag: Optional[str] = None
    delegate_sub: str
    created_at: int

class DelegateChatAuditOut(BaseModel):
    messages: list[DelegatedMessageOut]
    total_count: int
    delegate_name: str
```

---

## 14. Observability & Monitoring

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `delegate_chat_reads_total` | Counter | `creator_id` | Conversations read by delegates |
| `delegate_chat_sends_total` | Counter | `creator_id`, `delegate_id` | Messages sent by delegates |
| `delegate_sse_connections_gauge` | Gauge | -- | Active delegate SSE streams |
| `delegate_permission_denied_total` | Counter | `reason` | Rejected delegate attempts |

### Alerts

| Alert | Condition | Severity |
|-------|-----------|----------|
| High delegate send rate | > 100 sends/min per delegate | P3 |
| Permission denied spike | > 20 denials in 10min | P2 |

---

## 15. Rollout Plan

| Flag | Default | Description |
|------|---------|-------------|
| `CHAT_DELEGATION_ENABLED` | `false` | Master kill switch |
| `DELEGATE_TAG_ENABLED` | `true` | Show delegate attribution on messages |
| `DELEGATE_SSE_ENABLED` | `true` | Real-time events for delegates |

### Canary

1. **Week 1**: Enable for 5 test creators. Verify read/send/audit flow.
2. **Week 2**: Enable for all creators. Monitor SSE connection count.
3. **Week 3**: Full rollout.

---

## 16. Performance Considerations

| Concern | Mitigation |
|---------|-----------|
| Delegate SSE connections scale | Each delegate opens 1 SSE stream; reuse creator's event bus |
| Permission check on every request | Cache delegate permissions (30s TTL) in backend |
| Audit query on large conversation | Paginated query; filter delegate_sub != null |
| Multiple delegates same creator | Each gets own SSE; no broadcast needed (SSE is per-user) |

---

## 17. Expanded E2E Test Details

### Additional Edge Cases (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| E1 | Delegate sees new message in real-time | SSE delivers message; conversation list updates |
| E2 | Permission revoked while viewing | SSE closes; next API call returns 403 |
| E3 | Delegate sends to encrypted conversation | Message rejected or sent as plaintext with warning |
| E4 | Multiple delegates send simultaneously | Both messages appear with correct delegate_tags |

### Negative Tests (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| N1 | Send without X-Managing-Creator header | 400 or treated as own account |
| N2 | Delegate tries to delete creator's message | 403 |
| N3 | Expired delegation tries to read | 403 after expiry |
