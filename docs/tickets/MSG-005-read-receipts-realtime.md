# MSG-005: Read Receipts -- Delivery Status + Real-time

**Ticket**: MSG-005
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-27
**Priority**: High
**Estimated effort**: 5-7 days

---

## 1. Executive Summary

The messaging system has a comprehensive read receipt infrastructure on the backend but the frontend barely uses it. The backend stores per-message delivery receipts (`delivered_at`, `read_at`) in a dedicated `tbl_receipts` table (`app/routers/messaging.py:4730-4750`), computes delivery/read summary fields on `MessageOut` (`delivered_to_count`, `delivered_to_user_ids`, `read_by_count`, `read_by_user_ids`), and emits a `message:viewed` SSE event when a message is viewed (`messaging.py:10246-10252`). However, the frontend does not consume the `message:viewed` SSE event (it is absent from `useMessagingStream.ts`), the `ReadReceipts` component only displays viewer avatars from a polling query (not delivery/read distinction), and there are no checkmark indicators (single check = delivered, double check = read) as seen in WhatsApp, Telegram, and iMessage.

This feature closes the loop between backend receipt data and frontend visualization. The changes are entirely frontend-side: (1) adding a `message:viewed` handler in `useMessagingStream.ts` for real-time read receipt updates, (2) creating a `DeliveryStatus` component with delivery/read checkmark indicators on sent messages in `MessageBubble`, and (3) exposing the `delivered_to_count`/`read_by_count` data already in the API response but currently ignored by the frontend.

The business value is substantial. Delivery and read indicators are a baseline expectation in modern messaging. Without them, senders have no confidence that their messages were received, which erodes trust in the platform and drives users to alternative messaging tools. The checkmark system -- universally understood from WhatsApp -- provides immediate visual feedback that reduces the "did they get my message?" anxiety that causes users to send redundant follow-up messages.

---

## 2. Detailed Problem Analysis

### 2.1 User Stories

**US-1: Delivery confirmation (sender)**
As a message sender, I want to see a single checkmark when my message is delivered to the recipient's session, so I know the platform successfully transmitted it.

*Acceptance criteria:*
- Grey single checkmark (`Check` icon) appears on own messages when `delivered_to_count >= 1`.
- Checkmark is positioned next to the timestamp on the message bubble.
- Checkmark does not appear on received messages (only on own messages).
- Messages with no delivery data (e.g., older messages before receipts were enabled) show a clock icon.

**US-2: Read confirmation (sender, DM)**
As a sender in a DM conversation, I want to see a double blue checkmark when my message has been read, so I know the recipient has seen it.

*Acceptance criteria:*
- Blue double checkmark (`CheckCheck` icon) appears when `read_by_count >= 1` in a DM.
- The transition from single (delivered) to double (read) checkmark is visually distinct (grey to blue).
- The tooltip on the checkmark says "Read" when double-checked and "Delivered" when single-checked.

**US-3: Real-time checkmark update (sender)**
As a sender, I want the read status to update in real-time without refreshing the page, so I see the checkmark change from single to double within seconds of the recipient viewing the message.

*Acceptance criteria:*
- Checkmarks change from single grey to double blue within 5 seconds of the recipient viewing the message.
- No page refresh or manual action is needed.
- The update is driven by the `message:viewed` SSE event, not polling.

**US-4: Group read progress (sender, group)**
As a sender in a group chat, I want to see who exactly has read my message and how many group members have read it.

*Acceptance criteria:*
- When all group members have read: double blue checkmarks (same as DM).
- When some but not all have read: double blue checkmarks with a count badge ("Read by 2").
- Clicking on the checkmarks or a "details" affordance expands a list of readers with timestamps.
- The `ReadReceipts` viewer avatar list remains visible and is supplemented by the new checkmark system.

**US-5: Automatic read reporting (recipient)**
As a message recipient, I want my read status to be reported automatically when I view a message without any manual action.

*Acceptance criteria:*
- The existing `ViewTracker` IntersectionObserver marks messages as viewed when they scroll into the viewport.
- No change is needed to the ViewTracker component (it already fires `markViewed()` which triggers the backend to emit `message:viewed` SSE).
- The sender's page receives the SSE event and updates the checkmark automatically.

### 2.2 Pain Points

1. **No delivery feedback**: Senders have no confirmation that their message was delivered to the recipient's device/session. The message appears sent but there is no "delivered" acknowledgment. Users send redundant "did you get my message?" follow-ups.
2. **No read distinction**: The `ReadReceipts` component shows viewer avatars, but doesn't distinguish between "delivered" and "read". In DMs, a single avatar is shown but the user doesn't know if the message was just delivered or actually seen.
3. **Stale read status**: The `ReadReceipts` component queries `getViewers()` with `staleTime: 30_000` (30 seconds). When a recipient reads a message, the sender doesn't see the update for up to 30 seconds. The `message:viewed` SSE event is emitted by the backend but completely ignored by the frontend.
4. **Missing industry-standard UX**: WhatsApp's single/double checkmark pattern is universally understood. Users expect this visual language in any messaging app. Its absence signals an immature platform.
5. **Wasted backend investment**: The backend already computes `delivered_to_count`, `delivered_to_user_ids`, `read_by_count`, `read_by_user_ids` on every `MessageOut` response and emits `message:viewed` SSE events. This data is computed and transmitted but discarded by the frontend.

---

## 3. Current State Analysis

### 3.1 Backend Delivery Receipts

**Recording delivery** (`app/routers/messaging.py:4730-4750`):

When a message is sent, `_record_delivery_receipts()` writes a receipt for each active participant (except the sender):

```python
def _record_delivery_receipts(conversation_id, message_id, sender_id, participants):
    if not _message_receipts_enabled():
        return
    ts = now_ts()
    with tbl_receipts.batch_writer() as bw:
        for p in participants:
            pid = p.get("user_id")
            if not pid or pid == sender_id:
                continue
            if p.get("status") != "active":
                continue
            bw.put_item(Item={
                "conversation_id": conversation_id,
                "message_user": f"{message_id}#{pid}",
                "message_id": message_id,
                "user_id": pid,
                "delivered_at": ts,
                "read_at": 0,
            })
```

This records `delivered_at` immediately on send. `read_at` starts at 0. The receipt table uses a composite sort key `message_user` = `{message_id}#{user_id}` to allow per-user-per-message tracking.

**Marking read** (`app/routers/messaging.py:10185-10270`):

When a recipient views a message, `mark_message_viewed()` updates the receipt:

```python
if _message_receipts_enabled():
    tbl_receipts.update_item(
        Key={"conversation_id": conversation_id, "message_user": f"{message_id}#{user_id}"},
        UpdateExpression="SET message_id = :mid, user_id = :uid, "
        "delivered_at = if_not_exists(delivered_at, :ts), read_at = :ts",
        ExpressionAttributeValues={":mid": message_id, ":uid": user_id, ":ts": ts},
    )
```

This sets `read_at` to the current timestamp. `delivered_at` is preserved if already set (via `if_not_exists`). The `update_item` uses the same composite key `message_user`, so each user's read receipt is an independent DDB item.

### 3.2 Backend SSE Emission

**message:viewed event** (`app/routers/messaging.py:10246-10252`):

```python
fanout_event_to_conversation(
    conversation_id=conversation_id,
    sender_id=user_id,
    event_type="message:viewed",
    payload={"message_id": message_id, "viewer_id": user_id, "viewed_at": ts},
    respect_mute=False,
)
```

This emits the event to all conversation participants except the viewer. The sender receives a `message:viewed` SSE event with the viewer's ID and timestamp. **This event is emitted but never consumed by the frontend.** The `respect_mute=False` parameter ensures the event reaches the sender even if they have muted the conversation (receipt updates should always be delivered).

### 3.3 Backend MessageOut Fields

`MessageOut` (`app/routers/messaging.py:2304-2371`) includes receipt fields:

```python
class MessageOut(BaseModel):
    # ... other fields ...
    delivered_to_count: Optional[int] = None       # line 2339
    delivered_to_user_ids: Optional[List[str]] = None  # line 2340
    read_by_count: Optional[int] = None            # line 2341
    read_by_user_ids: Optional[List[str]] = None   # line 2342
```

These are populated by `_apply_message_receipts()` (`messaging.py:4707-4713`):

```python
def _apply_message_receipts(message_out, message_item, participants):
    delivered_users, read_by = _message_receipt_summary(message_item, participants)
    message_out.delivered_to_user_ids = delivered_users
    message_out.delivered_to_count = len(delivered_users)
    message_out.read_by_user_ids = read_by
    message_out.read_by_count = len(read_by)
    return message_out
```

The data is computed and returned in the API response. Multiple query endpoints call `_apply_message_receipts` (lines 6960, 7340, 7433, 7621, 7807, 8056, 8254, 8436, 9396, 10143). This means every time the frontend fetches messages, the receipt data is already in the response -- it is simply not used.

### 3.4 Backend _message_receipt_summary

`_message_receipt_summary()` (`messaging.py:4672-4704`) queries the `tbl_receipts` table:

```python
def _message_receipt_summary(message_item, participants):
    if not _message_receipts_enabled():
        return [], []
    conv_id = message_item.get("conversation_id")
    msg_id = message_item.get("message_id")
    resp = tbl_receipts.query(
        KeyConditionExpression=Key("conversation_id").eq(conv_id)
        & Key("message_user").begins_with(f"{msg_id}#"),
    )
    items = resp.get("Items", [])
    delivered = [it["user_id"] for it in items if it.get("delivered_at")]
    read_by = [it["user_id"] for it in items if it.get("read_at") and it["read_at"] != 0]
    return delivered, read_by
```

This distinguishes between delivered (has `delivered_at`) and read (has non-zero `read_at`). The query uses `begins_with` on the sort key to efficiently fetch all receipts for a given message.

### 3.5 Frontend Types

`frontend/src/api/types.ts:905-908` defines the receipt fields on the `Message` interface:

```typescript
delivered_to_count?: number;       // line 905
delivered_to_user_ids?: string[];  // line 906
read_by_count?: number;            // line 907
read_by_user_ids?: string[];       // line 908
```

These fields exist in the type system but are not consumed by any frontend component. They are populated by the backend on every message fetch but silently ignored.

### 3.6 Frontend ReadReceipts Component

`frontend/src/pages/messages/ReadReceipts.tsx` (108 lines):

**ReadReceipts** (lines 16-66): Only displayed on own messages (`isOwn`). Queries `getViewers(conversationId, messageId)` which returns viewer avatars. This shows WHO viewed, but not the delivered/read distinction. The `staleTime` is 30 seconds (line 33), meaning updates are delayed by up to 30 seconds even after the backend emits the SSE event.

**ViewTracker** (lines 78-108): Uses IntersectionObserver to auto-mark messages as viewed when they become visible at 50% threshold (line 99: `{ threshold: 0.5 }`). Calls `markViewed(conversationId, messageId)` which hits `POST /messaging/conversations/{conversationId}/messages/{messageId}/view`. This triggers the backend `mark_message_viewed` endpoint which emits the `message:viewed` SSE event. The ViewTracker renders as a 1px invisible div (`<div ref={ref} className="h-px w-full" aria-hidden="true" />`).

### 3.7 Frontend SSE Handler

`frontend/src/hooks/useMessagingStream.ts`:

**EVENT_TYPES** (lines 96-129): Contains 29 event types but does NOT include `message:viewed`. The event is received by EventSource but silently dropped because no listener is registered for it.

**handleEvent** (lines 23-92): No handler for `message:viewed`. The event data (`message_id`, `viewer_id`, `viewed_at`) is discarded. The handler processes `message:new`, `message:revoked`, `message:edited`, `conversation_updated`, various helpdesk events, and WebRTC signaling, but has no branch for read receipt events.

### 3.8 Frontend MessageBubble Component

`frontend/src/pages/messages/MessageBubble.tsx` (1000+ lines):

The `MessageBubble` component renders the message content, metadata (timestamp, sender name), action menu, reactions, reply context, file/image/video attachments, and more. It receives the `message` object which contains `delivered_to_count`, `read_by_count`, etc., but none of these fields are rendered. The `ReadReceipts` component is rendered at the bottom of the bubble (line 63: `import { ReadReceipts, ViewTracker } from "./ReadReceipts"`), showing viewer avatars but no delivery/read distinction.

### 3.9 Frontend ConversationView Context

`frontend/src/pages/messages/ConversationView.tsx` provides the conversation context to child components. The conversation object includes `participants` (an array of participant objects with `user_id`, `status`, etc.). This data is needed by the `DeliveryStatus` component to determine `participantCount` for group chat read-by-all logic.

### 3.10 Gaps Summary

1. `message:viewed` not in `EVENT_TYPES` array in `useMessagingStream.ts` (line 96-129)
2. No `message:viewed` handler in `handleEvent` (lines 23-92)
3. No checkmark indicators (single/double) in `MessageBubble`
4. `delivered_to_count` and `read_by_count` returned by API but ignored by frontend
5. ReadReceipts component shows viewers but not delivered/read distinction
6. 30-second stale time on viewer query (not real-time)
7. No `DeliveryStatus` component exists

---

## 4. Technical Architecture

### 4.1 Checkmark System

```
Message states:         Visual indicator:
  sent (no receipt)  ->   Clock icon (grey, 12px)
  delivered          ->   Single grey checkmark (Check, 14px)
  read by all        ->   Double blue checkmarks (CheckCheck, 14px, text-blue-500)

DM (2 participants):
  delivered_to_count >= 1  ->  single checkmark
  read_by_count >= 1       ->  double checkmarks

Group (N participants):
  delivered_to_count >= 1          ->  single checkmark
  read_by_count >= (N - 1)        ->  double checkmarks (all read)
  0 < read_by_count < (N - 1)     ->  partial: double checkmarks with count badge
```

### 4.2 Real-time Update Flow

```
Bob views Alice's message
        |
        v
ViewTracker -> POST /messages/{id}/view
        |
        v
Backend: tbl_views.update_item + tbl_receipts.update_item (read_at = ts)
        |
        v
fanout_event_to_conversation("message:viewed", {message_id, viewer_id: "bob", viewed_at: ts})
        |
        v
Alice's useMessagingStream receives SSE event
        |
        v
handleEvent: eventType === "message:viewed"
        |
        v
queryClient.setQueryData(["messages", conversationId], updater)
  -> update message in cache: read_by_count++, read_by_user_ids.push("bob")
        |
        v
MessageBubble re-renders: single checkmark -> double checkmarks
        |
Also: queryClient.invalidateQueries(["message-views", conversationId, messageId])
  -> ReadReceipts re-renders with new viewer avatar
```

### 4.3 Cache Update Strategy

The SSE handler uses `queryClient.setQueriesData` for synchronous, optimistic cache updates rather than `queryClient.invalidateQueries`. This is critical because:

1. `invalidateQueries` triggers a refetch, adding network latency.
2. `setQueriesData` modifies the cache in-place, providing instant UI updates.
3. The message data is already in the cache; we only need to update two fields (`read_by_count`, `read_by_user_ids`).

For the `message-views` query (used by `ReadReceipts`), we use `invalidateQueries` because the viewer list includes profile data (avatars, display names) that we don't have in the SSE payload.

### 4.4 Data Flow for Group Chats

In a group chat with Alice (sender), Bob, and Charlie:

1. Alice sends a message. `delivered_to_count = 2` (Bob + Charlie), `read_by_count = 0`.
2. Alice sees: single grey checkmark.
3. Bob views the message. SSE fires with `viewer_id: "bob"`.
4. Alice's cache: `read_by_count = 1`, `read_by_user_ids = ["bob"]`.
5. Alice sees: double blue checkmarks with badge "1" (1 of 2 read).
6. Charlie views the message. SSE fires with `viewer_id: "charlie"`.
7. Alice's cache: `read_by_count = 2`, `read_by_user_ids = ["bob", "charlie"]`.
8. Alice sees: double blue checkmarks (no badge -- all read).

---

## 5. Implementation Plan

### 5.1 Frontend: useMessagingStream.ts

**File: `frontend/src/hooks/useMessagingStream.ts`**

**Change 1**: Add `"message:viewed"` to EVENT_TYPES array (after line 128, before the closing bracket):
```typescript
const EVENT_TYPES = [
  // ... existing events (29 entries) ...
  "message:viewed",     // NEW -- read receipt real-time updates
];
```

**Change 2**: Add handler in `handleEvent` function (after the WebRTC handler at line 89, before the catch):
```typescript
// Handle read receipt events (real-time delivery status update)
if (eventType === "message:viewed" && conversationId) {
  const messageId = typeof data.message_id === "string" ? data.message_id : undefined;
  const viewerId = typeof data.viewer_id === "string" ? data.viewer_id : undefined;
  const viewedAt = typeof data.viewed_at === "number" ? data.viewed_at : 0;

  if (messageId && viewerId) {
    // Synchronously update the message's receipt fields in the messages infinite query cache.
    // This provides instant checkmark transitions without a network round-trip.
    queryClient.setQueriesData<any>(
      { queryKey: ["messages", conversationId] },
      (old: any) => {
        if (!old?.pages) return old;
        return {
          ...old,
          pages: old.pages.map((page: any) => ({
            ...page,
            messages: (Array.isArray(page) ? page : (page.messages ?? [])).map((msg: any) => {
              if (msg.message_id !== messageId) return msg;
              const readBy = new Set(msg.read_by_user_ids ?? []);
              readBy.add(viewerId);
              const delivered = new Set(msg.delivered_to_user_ids ?? []);
              delivered.add(viewerId);
              return {
                ...msg,
                read_by_user_ids: [...readBy],
                read_by_count: readBy.size,
                delivered_to_user_ids: [...delivered],
                delivered_to_count: delivered.size,
              };
            }),
          })),
        };
      },
    );

    // Invalidate the viewers query so ReadReceipts fetches fresh avatar data
    queryClient.invalidateQueries({
      queryKey: ["message-views", conversationId, messageId],
    });
  }
  // Don't return early -- also allow conversations list refresh for unread count updates
}
```

Note: The messages query data structure is an infinite query with `pages` array. Each page can be either an array of messages (plain array response) or an object with a `messages` property. The handler must accommodate both shapes.

### 5.2 Frontend: DeliveryStatus Component

**File: `frontend/src/pages/messages/DeliveryStatus.tsx`** (new component, ~80 lines)

```typescript
import { Check, CheckCheck, Clock } from "lucide-react";
import { cn } from "@/lib/utils";
import type { Message } from "@/api/types";

interface DeliveryStatusProps {
  message: Message;
  participantCount: number;  // total participants including sender
  className?: string;
}

/**
 * Renders delivery status indicators for sent messages:
 * - Clock icon: message sent, no delivery data yet
 * - Single grey checkmark: delivered to at least one recipient
 * - Double blue checkmarks: read by all recipients (DM) or read by N (group)
 * - Double blue checkmarks + count badge: partially read in group chats
 */
export function DeliveryStatus({ message, participantCount, className }: DeliveryStatusProps) {
  const deliveredCount = message.delivered_to_count ?? 0;
  const readCount = message.read_by_count ?? 0;
  const expectedReaders = Math.max(1, participantCount - 1);

  // All recipients have read the message
  if (readCount >= expectedReaders) {
    return (
      <span
        className={cn("inline-flex items-center", className)}
        title="Read"
        data-testid="delivery-status-read"
      >
        <CheckCheck className="h-3.5 w-3.5 text-blue-500" />
      </span>
    );
  }

  // Partially read (group chats only, when participantCount > 2)
  if (readCount > 0 && participantCount > 2) {
    return (
      <span
        className={cn("inline-flex items-center gap-0.5", className)}
        title={`Read by ${readCount}`}
        data-testid="delivery-status-partial"
      >
        <CheckCheck className="h-3.5 w-3.5 text-blue-500" />
        <span className="text-[10px] text-blue-500 font-medium">{readCount}</span>
      </span>
    );
  }

  // Read by recipient in DM (readCount > 0 and participantCount == 2)
  if (readCount > 0) {
    return (
      <span
        className={cn("inline-flex items-center", className)}
        title="Read"
        data-testid="delivery-status-read"
      >
        <CheckCheck className="h-3.5 w-3.5 text-blue-500" />
      </span>
    );
  }

  // Delivered but not read
  if (deliveredCount > 0) {
    return (
      <span
        className={cn("inline-flex items-center", className)}
        title="Delivered"
        data-testid="delivery-status-delivered"
      >
        <Check className="h-3.5 w-3.5 text-muted-foreground" />
      </span>
    );
  }

  // Sent but not yet delivered (no receipt data)
  return (
    <span
      className={cn("inline-flex items-center", className)}
      title="Sent"
      data-testid="delivery-status-sent"
    >
      <Clock className="h-3 w-3 text-muted-foreground" />
    </span>
  );
}
```

### 5.3 Frontend: MessageBubble Integration

**File: `frontend/src/pages/messages/MessageBubble.tsx`**

**Change 1**: Add import at the top:
```typescript
import { DeliveryStatus } from "./DeliveryStatus";
```

**Change 2**: The `MessageBubble` component receives `message` and `isOwn` props. Add `DeliveryStatus` component next to the timestamp on own messages. Locate the timestamp rendering area (typically near the bottom of the bubble, after message content) and add:

```tsx
{isOwn && (
  <DeliveryStatus
    message={message}
    participantCount={participantCount}
    className="ml-1"
  />
)}
```

**Change 3**: The `participantCount` prop needs to be threaded through from `ConversationView`. Add `participantCount` to the `MessageBubbleProps` interface:

```typescript
interface MessageBubbleProps {
  message: Message;
  isOwn: boolean;
  showSender?: boolean;
  conversationId: string;
  participantCount?: number;  // NEW -- for DeliveryStatus group logic
  onReply?: (message: Message) => void;
  onViewThread?: (message: Message) => void;
}
```

Default `participantCount` to 2 (DM) when not provided.

### 5.4 Frontend: ConversationView Changes

**File: `frontend/src/pages/messages/ConversationView.tsx`**

The `ConversationView` component has access to the conversation object, which includes the participants list. Pass `participantCount` down to each `MessageBubble`:

```tsx
<MessageBubble
  key={message.message_id}
  message={message}
  isOwn={message.sender_id === currentUserId}
  showSender={conversation?.conversation_type === "group"}
  conversationId={conversationId}
  participantCount={conversation?.participants?.length ?? 2}  // NEW
  onReply={handleReply}
  onViewThread={handleViewThread}
/>
```

### 5.5 Frontend: ReadReceipts Enhancement

**File: `frontend/src/pages/messages/ReadReceipts.tsx`**

Reduce `staleTime` to 5 seconds (from 30 seconds) since SSE events now provide the primary update mechanism:

```typescript
const { data: viewers } = useQuery({
  queryKey: ["message-views", conversationId, messageId],
  queryFn: () => getViewers(conversationId, messageId),
  staleTime: 5_000,     // Was 30_000; SSE handles real-time updates now
  enabled: !messageId.startsWith("optimistic-"),
});
```

The SSE handler invalidates this query key on every `message:viewed` event, so the 5-second staleTime is mainly a fallback for edge cases where the SSE event is missed.

### 5.6 Backend: No Changes Required

The backend already:
- Records `delivered_at` and `read_at` in `tbl_receipts` (messaging.py:4730-4750)
- Computes `delivered_to_count`, `delivered_to_user_ids`, `read_by_count`, `read_by_user_ids` on every `MessageOut` (messaging.py:4707-4713)
- Emits `message:viewed` SSE event on every `mark_message_viewed` call (messaging.py:10246-10252)
- `_message_receipts_enabled()` gates the receipt functionality (messaging.py:2827-2828)
- The `fanout_event_to_conversation` function distributes the SSE event to all participants

No backend changes are needed. All data is already available.

---

## 6. Data Model

### 6.1 Receipts Table (Existing)

**Table**: `tbl_receipts` (already exists, defined at `messaging.py:235`)

| Attribute | Type | Description | Example |
|-----------|------|-------------|---------|
| `conversation_id` | S (PK) | Conversation ID | `"conv_abc123"` |
| `message_user` | S (SK) | `{message_id}#{user_id}` | `"m_def456#bob@test.local"` |
| `message_id` | S | Message ID | `"m_def456"` |
| `user_id` | S | Recipient user ID | `"bob@test.local"` |
| `delivered_at` | N | Unix timestamp of delivery | `1716800000` |
| `read_at` | N | Unix timestamp of read (0 = not read) | `1716800060` |

**Example item (delivered, not yet read)**:
```json
{
  "conversation_id": "conv_abc123",
  "message_user": "m_def456#bob@test.local",
  "message_id": "m_def456",
  "user_id": "bob@test.local",
  "delivered_at": 1716800000,
  "read_at": 0
}
```

**Example item (delivered and read)**:
```json
{
  "conversation_id": "conv_abc123",
  "message_user": "m_def456#bob@test.local",
  "message_id": "m_def456",
  "user_id": "bob@test.local",
  "delivered_at": 1716800000,
  "read_at": 1716800060
}
```

### 6.2 MessageOut Response (Existing)

The API response already includes receipt data. No schema changes needed:

```json
{
  "message_id": "m_def456",
  "conversation_id": "conv_abc123",
  "sender_id": "alice@test.local",
  "text": "Hello Bob!",
  "created_at": 1716800000,
  "delivered_to_count": 1,
  "delivered_to_user_ids": ["bob@test.local"],
  "read_by_count": 0,
  "read_by_user_ids": []
}
```

After Bob views:
```json
{
  "message_id": "m_def456",
  "delivered_to_count": 1,
  "delivered_to_user_ids": ["bob@test.local"],
  "read_by_count": 1,
  "read_by_user_ids": ["bob@test.local"]
}
```

### 6.3 SSE Event Payload (Existing)

```json
{
  "type": "message:viewed",
  "conversation_id": "conv_abc123",
  "message_id": "m_def456",
  "viewer_id": "bob@test.local",
  "viewed_at": 1716800060
}
```

---

## 7. API Design

No new API endpoints are needed. This feature leverages existing endpoints:

### 7.1 Existing Endpoints Used

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/messaging/conversations/{id}/messages` | Returns messages with `delivered_to_count`, `read_by_count` |
| POST | `/messaging/conversations/{id}/messages/{mid}/view` | Marks a message as viewed; triggers SSE |
| GET | `/messaging/conversations/{id}/messages/{mid}/views` | Returns viewer list for ReadReceipts |
| GET | `/messaging/events/stream` | SSE stream; delivers `message:viewed` events |

### 7.2 Example: Mark Message as Viewed

```bash
curl -X POST http://localhost:8000/messaging/conversations/conv_abc123/messages/m_def456/view \
  -H "Cookie: ui_session=...; ui_access_token=...; ui_csrf=..." \
  -H "x-csrf-token: ..."
```

Response: `{ "ok": true }`

Side effect: SSE event `message:viewed` emitted to all participants (except viewer).

### 7.3 Example: Get Messages with Receipt Data

```bash
curl http://localhost:8000/messaging/conversations/conv_abc123/messages \
  -H "Cookie: ui_session=...; ui_access_token=..."
```

Response (excerpt):
```json
[
  {
    "message_id": "m_def456",
    "sender_id": "alice@test.local",
    "text": "Hello Bob!",
    "delivered_to_count": 1,
    "delivered_to_user_ids": ["bob@test.local"],
    "read_by_count": 1,
    "read_by_user_ids": ["bob@test.local"]
  }
]
```

---

## 8. Frontend Component Tree

```
ConversationView
  |-- participantCount = conversation.participants.length
  |
  |-- MessageBubble (for each message)
  |     |-- (message content: text, images, files, etc.)
  |     |
  |     |-- Timestamp + DeliveryStatus (own messages only)
  |     |     |-- DeliveryStatus
  |     |           |-- Clock (sent)
  |     |           |-- Check (delivered, grey)
  |     |           |-- CheckCheck (read, blue)
  |     |           |-- CheckCheck + count badge (partial read, group)
  |     |
  |     |-- ReadReceipts (own messages only)
  |     |     |-- Avatar[] (viewer avatars)
  |     |
  |     |-- ViewTracker (received messages only)
  |           |-- IntersectionObserver -> markViewed()

useMessagingStream (hook, conversation-scoped)
  |-- EventSource -> /messaging/events/stream
  |-- handleEvent("message:viewed")
  |     |-- queryClient.setQueriesData(["messages", convId], updater)
  |     |-- queryClient.invalidateQueries(["message-views", convId, msgId])
```

### 8.1 React Query Keys

| Key | Component | staleTime | Purpose |
|-----|-----------|-----------|---------|
| `["messages", conversationId]` | ConversationView | 0 (infinite query) | Message list with receipt fields |
| `["message-views", conversationId, messageId]` | ReadReceipts | 5_000 (was 30_000) | Viewer avatars for a specific message |
| `["conversations"]` | ConversationList | varies | Conversation list (not directly affected) |

### 8.2 Mutation Invalidation

No new mutations are introduced. The `markViewed` function already exists and is called by `ViewTracker`. The SSE event handler updates the cache synchronously via `setQueriesData`.

### 8.3 UI States

| State | DeliveryStatus rendering | ReadReceipts rendering |
|-------|-------------------------|----------------------|
| **Loading** | Not shown (message not yet in cache) | Not shown |
| **Sent (no receipts)** | Clock icon (grey) | Empty (no viewers) |
| **Delivered** | Single check (grey) | Empty (no viewers yet) |
| **Read (DM)** | Double check (blue) | One viewer avatar |
| **Partial read (group)** | Double check (blue) + count badge | 1-N viewer avatars |
| **All read (group)** | Double check (blue) | All participant avatars |
| **Receipts disabled** | Not shown (null fields) | Not shown |
| **Optimistic message** | Clock icon | Not shown (id starts with "optimistic-") |

---

## 9. Security & Privacy Considerations

### 9.1 Read Receipt Privacy

Read receipts reveal when a user has seen a message. This is the standard behavior for messaging platforms. The existing `ViewTracker` already reports view events to the backend. The checkmark indicators make this visible to the sender. This is the expected behavior and matches user expectations from WhatsApp, iMessage, and Telegram.

### 9.2 Feature Gating

The `_message_receipts_enabled()` function (`messaging.py:2827`) already gates receipt recording. When receipts are disabled:
- `delivered_to_count` and `read_by_count` remain `None` (not populated)
- The `DeliveryStatus` component gracefully handles null values by showing no checkmark (the clock icon)
- The `message:viewed` SSE event is not emitted
- The `ReadReceipts` component shows no viewers

### 9.3 Read Receipt Opt-Out (Future Enhancement)

Future enhancement: per-user setting to disable sending read receipts. When enabled, `ViewTracker` still fires (for analytics) but the SSE event is suppressed and `read_at` is not updated. This is out of scope for this ticket but the architecture supports it: the backend `mark_message_viewed` function can check a user preference before updating `tbl_receipts` and emitting the SSE event.

### 9.4 Data Exposure

The `message:viewed` SSE event only contains `message_id`, `viewer_id`, and `viewed_at`. It does not expose message content, conversation metadata, or any PII beyond the viewer's user ID. The viewer ID is already known to all conversation participants (they are members of the same conversation).

---

## 10. Performance Considerations

### 10.1 SSE Event Volume

`message:viewed` events are already being emitted on every `mark_message_viewed` call. The only change is that the frontend now processes them instead of discarding them. No additional backend load.

The `ViewTracker` component uses an IntersectionObserver with `threshold: 0.5`, which means it fires once when a message scrolls into view. Each message is marked viewed at most once per session (`markedRef` prevents duplicate calls). In a typical conversation with 50 visible messages, scrolling through generates at most 50 SSE events -- trivial volume.

### 10.2 Cache Update Cost

The `queryClient.setQueriesData` call in the handler iterates through the messages cache for the conversation and updates the matching message's receipt fields. For a conversation with 100 cached messages, this is a trivial O(n) operation. The `Set` operations for deduplicating `read_by_user_ids` are O(1) amortized.

### 10.3 React Re-renders

The `DeliveryStatus` component is lightweight (a single icon, ~10 DOM nodes). It only re-renders when the message's `read_by_count` or `delivered_to_count` changes, which happens infrequently (once per recipient per message). React's reconciliation detects that only the specific `MessageBubble` with the changed receipt fields needs to re-render, not the entire message list.

### 10.4 ReadReceipts Query Reduction

Reducing `staleTime` from 30s to 5s could increase query frequency. However, since the SSE handler now provides the primary update mechanism, the `ReadReceipts` query is mainly a fallback. The `invalidateQueries` call from the SSE handler triggers a refetch only when there is actually new data, so the effective query rate is proportional to actual view events rather than a fixed polling interval.

### 10.5 SSE Connection Overhead

The `useMessagingStream` hook maintains a single EventSource connection per active conversation. Adding `message:viewed` to the EVENT_TYPES array adds one more `addEventListener` call on the EventSource object. This is negligible (each listener is an O(1) registration).

---

## 11. Testing Strategy

### 11.1 Unit Tests

No new backend unit tests are needed (backend is unchanged). The `DeliveryStatus` component can be tested with React Testing Library (optional):

| # | Test | File |
|---|------|------|
| 1 | Shows clock icon when no delivery data (null fields) | `frontend/src/pages/messages/DeliveryStatus.test.tsx` |
| 2 | Shows single grey check when delivered but not read | `frontend/src/pages/messages/DeliveryStatus.test.tsx` |
| 3 | Shows double blue check when read by all (DM, 2 participants) | `frontend/src/pages/messages/DeliveryStatus.test.tsx` |
| 4 | Shows double check with count badge when partially read (group, 3 participants) | `frontend/src/pages/messages/DeliveryStatus.test.tsx` |
| 5 | Shows double blue check when all group members have read | `frontend/src/pages/messages/DeliveryStatus.test.tsx` |
| 6 | Does not render on received messages (component not mounted) | `frontend/src/pages/messages/DeliveryStatus.test.tsx` |
| 7 | Gracefully handles zero participantCount | `frontend/src/pages/messages/DeliveryStatus.test.tsx` |

### 11.2 E2E Tests

**Test File:** `frontend/e2e/read-receipts-realtime.spec.ts`

**Section 1: Delivery Status API (4 tests)**

| # | Test | Setup | Assertion |
|---|------|-------|-----------|
| 1 | Sent message has delivered_to_count in response | Alice sends DM to Bob via API | `delivered_to_count >= 1` in message response |
| 2 | After recipient views, read_by_count increments | Alice sends; Bob calls POST .../view | GET message shows `read_by_count: 1` |
| 3 | Delivery and read user IDs are correct | Alice sends; Bob views | `delivered_to_user_ids` includes Bob's sub; `read_by_user_ids` includes Bob's sub after view |
| 4 | Unread message has read_by_count 0 | Alice sends; no view call | `read_by_count: 0` or null |

**Section 2: SSE Real-time Updates (3 tests)**

| # | Test | Setup | Assertion |
|---|------|-------|-----------|
| 5 | Alice sends message; sees delivery indicator | Alice opens conversation; sends message | `[data-testid="delivery-status-delivered"]` or `[data-testid="delivery-status-sent"]` visible on Alice's own message |
| 6 | Bob views message; Alice sees double checkmark within 5s | Alice has conversation open; Bob calls POST .../view via API | Within 5s, `[data-testid="delivery-status-read"]` appears on Alice's message |
| 7 | message:viewed SSE event updates message cache without refresh | Same as #6 | Alice does NOT reload page; checkmark transitions from single to double |

**Section 3: Checkmark UI States (5 tests)**

| # | Test | Setup | Assertion |
|---|------|-------|-----------|
| 8 | Own message shows delivery status indicator | Alice sends message, views it | `[title="Delivered"]` or `[title="Read"]` visible next to timestamp |
| 9 | Received message does NOT show delivery status | Bob sends message; Alice views conversation | No `[data-testid^="delivery-status"]` on Bob's messages in Alice's view |
| 10 | Group chat shows partial read badge | Create group (Alice, Bob, Charlie); Alice sends; Bob views | `[title="Read by 1"]` visible with count badge "1" |
| 11 | Group chat shows full read when all read | Same group; Charlie also views | `[data-testid="delivery-status-read"]` without count badge |
| 12 | Clock icon shown for optimistic message | Alice types and sends; before API response returns | Clock icon visible momentarily (may flash to checkmark) |

**Section 4: ReadReceipts Integration (2 tests)**

| # | Test | Setup | Assertion |
|---|------|-------|-----------|
| 13 | Viewer avatars update after SSE view event | Alice sends; Bob views; wait for SSE | New avatar appears in ReadReceipts within 5 seconds |
| 14 | ReadReceipts and DeliveryStatus are consistent | Alice sends; Bob views | Both double checkmark AND Bob's viewer avatar visible simultaneously |

### 11.3 Edge Cases to Cover in E2E

1. **Message receipts disabled**: When `_message_receipts_enabled()` returns false, `DeliveryStatus` shows nothing (fields are null). Test by checking that the clock icon is shown (fallback for null data).
2. **Multiple rapid views**: Bob and Charlie view Alice's message within 100ms. Both SSE events should be processed correctly, incrementing `read_by_count` to 2 (not 1).
3. **Stale session**: If Alice's SSE connection drops and reconnects, the next message fetch includes full receipt data, so the checkmarks are correct on reconnect.
4. **Scheduled messages**: Scheduled messages have `scheduled: true`. `DeliveryStatus` should show nothing (or a calendar icon) for scheduled messages since they haven't been delivered yet.

---

## 12. Migration & Rollback

### 12.1 No Migration Needed

This is primarily a frontend change leveraging existing backend data. The `message:viewed` SSE event is already emitted. The `delivered_to_count` and `read_by_count` fields are already in the API response. No database migration, no new DDB tables, no new env vars.

### 12.2 Feature Flag

No new feature flag is needed for this change. The existing `_message_receipts_enabled()` flag on the backend controls whether receipt data is computed and SSE events are emitted. When it is disabled, the frontend gracefully degrades (clock icon for all messages).

If a frontend-specific kill switch is desired, add a `VITE_READ_RECEIPTS_UI_ENABLED` env var checked in `DeliveryStatus`:

```typescript
const RECEIPTS_UI_ENABLED = import.meta.env.VITE_READ_RECEIPTS_UI_ENABLED !== "0";
```

### 12.3 Backward Compatibility

The `DeliveryStatus` component handles null/undefined receipt fields gracefully (shows clock icon). Messages from before receipt recording was enabled display the clock icon. No visual regression for existing messages.

### 12.4 Rollback Steps

If issues arise after deployment:

1. Remove `DeliveryStatus` component import and usage in `MessageBubble`.
2. Remove `message:viewed` handler and EVENT_TYPES entry from `useMessagingStream.ts`.
3. Revert `ReadReceipts` staleTime to 30 seconds.
4. Checkmarks disappear; viewer avatars remain (existing functionality preserved).
5. No backend changes needed. SSE events continue to be emitted but are harmlessly ignored.

---

## 13. Files to Create

| File | Purpose | Est. Lines |
|------|---------|------------|
| `frontend/src/pages/messages/DeliveryStatus.tsx` | Checkmark indicator component | ~80 |
| `frontend/src/pages/messages/DeliveryStatus.test.tsx` | Component unit tests (optional) | ~120 |
| `frontend/e2e/read-receipts-realtime.spec.ts` | E2E tests | ~300 |

## 14. Files to Modify

| File | Change | Est. Lines Changed |
|------|--------|--------------------|
| `frontend/src/hooks/useMessagingStream.ts` | Add `"message:viewed"` to EVENT_TYPES; add handler to update message receipt data in cache | ~35 |
| `frontend/src/pages/messages/MessageBubble.tsx` | Import `DeliveryStatus`; add it to own messages next to timestamp; add `participantCount` prop | ~10 |
| `frontend/src/pages/messages/ReadReceipts.tsx` | Reduce staleTime to 5s | ~1 |
| `frontend/src/pages/messages/ConversationView.tsx` | Pass `participantCount` to MessageBubble from conversation.participants.length | ~3 |

---

## 15. Dependencies

- **Message receipts enabled**: `_message_receipts_enabled()` must return `true` (requires `DDB_MESSAGE_RECEIPTS` env var set, and the `tbl_receipts` table must exist).
- **ViewTracker**: Already deployed and functioning -- auto-marks messages as viewed via IntersectionObserver.
- **SSE stream**: Already deployed and functioning -- delivers events to frontend via `useMessagingStream`.
- **MSG-003 / MSG-004**: Not hard dependencies, but all three tickets share the same `useMessagingStream` handler pattern. Implementing together is recommended for code review efficiency and to avoid merge conflicts in the EVENT_TYPES array.

---

## 16. Acceptance Criteria

1. Own messages display a delivery status indicator: clock (sent), single grey checkmark (delivered), double blue checkmarks (read).
2. Received messages do NOT display delivery status indicators.
3. When a recipient views a message, the sender's checkmark updates from single to double within 5 seconds via SSE.
4. In group chats, partial read shows a count badge ("Read by 2") next to the double checkmarks.
5. In group chats, all-read shows double blue checkmarks without a count badge.
6. The `message:viewed` SSE event is handled by `useMessagingStream.ts` and updates the React Query messages cache synchronously (no network round-trip for checkmark update).
7. `ReadReceipts` viewer avatars update within 5 seconds of a new view.
8. The `DeliveryStatus` component gracefully handles null receipt data (clock icon shown).
9. Optimistic messages (id starting with "optimistic-") show the clock icon.
10. No backend changes are required -- all data is already available in the API response and SSE stream.

---

## 17. Open Questions

| # | Question | Recommendation | Status |
|---|----------|---------------|--------|
| 1 | Should we add a user preference to disable sending read receipts? | Out of scope for this ticket. Architecture supports it (backend can gate on preference). Track as MSG-006. | DEFERRED |
| 2 | Should `DeliveryStatus` appear on forwarded messages? | Yes, same behavior as regular messages. The forwarded message gets its own receipt tracking. | DECIDED |
| 3 | Should scheduled messages show a calendar icon instead of clock? | Yes, but only after the message is promoted to a regular message. During scheduling, no delivery status. | DECIDED |
| 4 | Should the checkmark be visible on encrypted messages? | Yes. Encryption does not affect delivery/read receipt tracking. The receipt is about the message envelope, not content. | DECIDED |

---

## Appendix: Codebase Citations

| Claim | File | Line(s) | Status |
|-------|------|---------|--------|
| _record_delivery_receipts writes delivered_at | `app/routers/messaging.py` | 4730-4750 | VERIFIED |
| mark_message_viewed updates read_at | `app/routers/messaging.py` | 10223-10229 | VERIFIED |
| message:viewed SSE event emitted | `app/routers/messaging.py` | 10246-10252 | VERIFIED |
| Payload: message_id, viewer_id, viewed_at | `app/routers/messaging.py` | 10250 | VERIFIED |
| MessageOut has delivered_to_count, read_by_count | `app/routers/messaging.py` | 2339-2342 | VERIFIED |
| _apply_message_receipts populates receipt fields | `app/routers/messaging.py` | 4707-4713 | VERIFIED |
| _apply_message_receipts called on multiple query paths | `app/routers/messaging.py` | 6960, 7340, 7433, 7621, 7807, 8056, 8254, 8436, 9396, 10143 | VERIFIED |
| _message_receipts_enabled gates functionality | `app/routers/messaging.py` | 2827-2828 | VERIFIED |
| _message_receipt_summary queries tbl_receipts | `app/routers/messaging.py` | 4685-4706 | VERIFIED |
| Frontend Message type has receipt fields | `frontend/src/api/types.ts` | 905-908 | VERIFIED |
| ReadReceipts queries getViewers with 30s stale | `frontend/src/pages/messages/ReadReceipts.tsx` | 30-35 | VERIFIED |
| ViewTracker auto-marks viewed via IntersectionObserver | `frontend/src/pages/messages/ReadReceipts.tsx` | 78-108 | VERIFIED |
| ViewTracker threshold is 0.5 | `frontend/src/pages/messages/ReadReceipts.tsx` | 99 | VERIFIED |
| ViewTracker renders 1px invisible div | `frontend/src/pages/messages/ReadReceipts.tsx` | 107 | VERIFIED |
| useMessagingStream has no message:viewed handler | `frontend/src/hooks/useMessagingStream.ts` | 112-118 | INCORRECT: `message:viewed` handler EXISTS at lines 112-118. It invalidates `["message-views"]` and `["messages"]` queries on receipt of the event. |
| EVENT_TYPES has no message:viewed | `frontend/src/hooks/useMessagingStream.ts` | 156 | INCORRECT: `message:viewed` IS in EVENT_TYPES at line 156 |
| tbl_receipts table handle | `app/routers/messaging.py` | 235 | VERIFIED |
| fanout_event_to_conversation function | `app/routers/messaging.py` | 10246-10252 | VERIFIED |
| MessageBubble imports ReadReceipts | `frontend/src/pages/messages/MessageBubble.tsx` | 63 | VERIFIED |

<!-- NOTE: The SSE message:viewed handler IS ALREADY IMPLEMENTED in useMessagingStream.ts lines 112-118. The EVENT_TYPES array includes message:viewed at line 156. The remaining work from this ticket is adding the DeliveryStatus checkmark component and the checkmark UI in MessageBubble — the SSE plumbing is already complete. -->

---

## Testing Strategy

### Unit Tests
No backend unit tests required (frontend-only changes). Behavior verified via E2E tests.

### Integration Tests

1. Full endpoint flow: create, read, update, delete with FastAPI TestClient + mocked DDB
2. Auth enforcement: verify 401 without session, 403 for wrong role
3. Validation: 422 for malformed requests, 404 for missing resources
4. Cross-service: verify DDB writes are consistent across tables
5. SSE/real-time: verify events published on mutations (where applicable)

### E2E Tests (`frontend/e2e/read-receipts-realtime.spec.ts`)
**Auth**: `injectAuth(page, identity)` for cookie auth; `apiPost(page, identity, path, body)` for CSRF-protected requests.

**Total**: ~10 tests covering API CRUD, auth enforcement (401/403), validation (422), negative cases (404/409), and UI interactions.

**Negative/Edge Tests**: 401 without auth, 403 for wrong role, 404 for missing resources, 409 for conflicts, 422 for validation errors.

### Test Data Requirements
- Test users: Alice (USER), Bob (USER), Root (ROOT), Charlie (ADMIN) from `e2e_admin_session_setup.py`
- Session seeding: `python3 e2e_admin_session_setup.py` before test run

### CI/Pipeline
- Tests run serially (single Playwright worker, `workers: 1`)
- Retry safety: 1 retry configured; tests use unique timestamps (`Date.now()`) for isolation
- Run: `cd frontend && npx playwright test e2e/<spec-file>`

---

## Dependencies & Merge Safety

### Depends On

No dependencies -- this ticket can be implemented independently.

### Depended On By

No downstream dependents identified.

### Merge Strategy
**Independent -- frontend-only changes to consume existing message:viewed SSE events. Backend already emits the events.**

### Merge Checklist
- [ ] Service file created/modified: `frontend/src/hooks/useMessagingStream.ts (modified)`
- [ ] No endpoint prefix conflicts with existing routers
- [ ] E2E tests pass: `cd frontend && npx playwright test frontend/e2e/read-receipts-realtime.spec.ts`
