# MSG-010: Countdown Messages

**Ticket**: MSG-010
**Author**: Engineering
**Status**: Implemented
**Date**: 2026-05-29
**Priority**: Low
**Estimated effort**: 4-5 days

---

## 1. Overview & Motivation

### 1.1 Purpose

MSG-010 adds a countdown message kind to the messaging system. A countdown message displays a live ticking countdown timer to a target datetime, rendered as a card in the conversation with a title and real-time days/hours/minutes/seconds display. Countdowns can optionally be linked to platform events (broadcasts, calls, calendar events) and display a contextual action button when the countdown reaches zero.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Sender | As a sender, I want to create a countdown to an event and share it in a conversation. | POST creates countdown message; card shows title + ticking timer. |
| Sender | As a sender, I want to link a countdown to a scheduled broadcast so participants see a "Join" button when it starts. | `associated_event_type=broadcast`, `associated_event_id` set; "Watch Live" button appears at zero. |
| Sender | As a sender, I want to create a custom countdown (no linked event) for things like birthdays or deadlines. | `associated_event_type=custom`; card shows "Time's up!" at zero. |
| Recipient | As a recipient, I want to see the countdown ticking in real time without refreshing. | `useEffect` interval updates display every second. |
| Recipient | As a recipient, I want to see a clear state change when the countdown reaches zero. | Timer text changes to "Time's up!" or "Event started!"; card style changes. |

### 1.3 Why This Is Needed Now

Countdowns create anticipation and engagement around upcoming events. With the broadcast and call scheduling features already built, linking countdowns to those events creates a seamless experience where users can anticipate, count down to, and immediately join events from within their conversations.

---

## 2. Architecture & Data Flow

### 2.1 Countdown Message Creation Flow

```
  User (ComposeBar)              Backend (messaging.py)            DynamoDB
  ─────────────────              ──────────────────────            ────────
       │                                │                            │
       │  Click Timer icon              │                            │
       │  Fill CountdownComposerDialog  │                            │
       │   - title                      │                            │
       │   - date/time picker           │                            │
       │   - event type selector        │                            │
       │                                │                            │
       │  POST /conversations/{id}/     │                            │
       │    messages/countdown          │                            │
       │  { title, target_datetime,     │                            │
       │    associated_event_type,      │                            │
       │    associated_event_id }       │                            │
       │ ────────────────────────────>  │                            │
       │                                │  1. Validate target > now  │
       │                                │  2. Verify conv access     │
       │                                │  3. Generate msg_id        │
       │                                │                            │
       │                                │  PutItem to Messages       │
       │                                │  table with kind=countdown │
       │                                │ ────────────────────────>  │
       │                                │                            │
       │                                │  4. Update conversation    │
       │                                │     last_message           │
       │                                │ ────────────────────────>  │
       │                                │                            │
       │                                │  5. Emit SSE event         │
       │                                │                            │
       │  <── 201 Created               │                            │
       │  { message with countdown }    │                            │
```

### 2.2 Live Countdown Rendering Flow

```
  MessageBubble                   CountdownCard                 Browser Timer
  ─────────────                   ─────────────                 ─────────────
       │                               │                             │
       │  kind === "countdown"?        │                             │
       │ ──────────────────────────>   │                             │
       │                               │  useEffect(() => {          │
       │                               │    setInterval(1000)        │
       │                               │ ──────────────────────────> │
       │                               │                             │
       │                               │  Every 1 second:            │
       │                               │  <── remaining = calc()     │
       │                               │                             │
       │                               │  if remaining.total <= 0:   │
       │                               │    Show "Time's up!" or     │
       │                               │    "Event started!" + CTA   │
       │                               │    clearInterval            │
       │                               │                             │
       │  <── Rendered card             │                             │
       │      with live timer           │                             │
```

### 2.3 Associated Event Action Mapping

```
  Countdown reaches zero
       │
       ├── associated_event_type === "broadcast"
       │   └── Show "Watch Live" → /broadcasts/{associated_event_id}
       │
       ├── associated_event_type === "call"
       │   └── Show "Join Call" → /calls/{associated_event_id}
       │
       ├── associated_event_type === "calendar"
       │   └── Show "View Event" → /calendar/events/{associated_event_id}
       │
       └── associated_event_type === "custom"
           └── Show "Time's up!" (no CTA button)
```

---

## 3. Current State Analysis

### 3.1 Message Kinds

Current kinds (see `app/routers/messaging.py:2330`): `text`, `image`, `file`, `audio`, `video`, `gallery`, `file_share`, `calendar_share`, `calendar_event`, `meeting_poll`, `video_share`, `voice_message`, `voicemail`. Adding `countdown` follows the established pattern.

<!-- NOTE: "find_datetime" does not exist in the codebase — the original list was incorrect. The actual Literal is at messaging.py:2330. -->

### 3.2 Message Send Infrastructure

`send_text_message()` in `app/routers/messaging.py` (line 7684) is the core send function. New message kinds are added by:
1. Defining a new endpoint in `app/routers/messaging.py`
2. Storing kind-specific fields on the message DDB item via `tbl_msgs.put_item()` (see line 7828)
3. Including the fields in `MessageOut` (line 2325) and `_message_out_from_item()` (line 3766)
4. Adding rendering in `MessageBubble.tsx`

<!-- NOTE: app/services/messaging.py does not exist — all messaging logic lives in app/routers/messaging.py (a single ~9000-line file). -->

### 3.3 Frontend Timer Patterns

React's `useEffect` with `setInterval` is the standard pattern for live timers. The frontend already uses similar patterns in scheduled message indicators. The countdown component will follow the same approach with a 1-second interval.

### 3.4 Gaps

1. **No `countdown` message kind** -- no backend support.
2. **No countdown fields on messages** -- no `target_datetime`, `associated_event_type`.
3. **No CountdownCard component** -- no live timer rendering.
4. **No "Join" button integration** -- no link to broadcast/call when timer expires.

---

## 4. Technical Design

### 4.1 Message Schema

Add to message item when `kind = "countdown"`:

| Field | Type | Description |
|-------|------|-------------|
| `countdown_title` | String | Display title (e.g., "Team meeting starts in...") |
| `target_datetime` | Number | UTC Unix timestamp of target event |
| `associated_event_type` | String | `"broadcast"`, `"call"`, `"calendar"`, `"custom"` |
| `associated_event_id` | String (optional) | ID of linked event (broadcast_id, call_id, calendar_event_id) |

### 4.2 Detailed DynamoDB Access Patterns

| # | Access Pattern | Table | PK | SK | Operation | Notes |
|---|---------------|-------|----|----|-----------|-------|
| 1 | Create countdown message | Messages (`DDB_MESSAGES`, see `messaging.py:160`) | `conversation_id` | `message_id` (m_{uuid}) | PutItem | Standard message write pattern (see `tbl_msgs.put_item()` at line 7828) |
| 2 | Get countdown message | Messages | `conversation_id` | `message_id` | GetItem | Standard message read (see line 4163) |
| 3 | List messages in conversation | Messages | `conversation_id` | begins_with("m_") | Query | Includes countdown messages in regular list (see line 4079) |
| 4 | Update conversation last_message | Conversations (`DDB_CONVERSATIONS`, see `messaging.py:158`) | `conversation_id` | — | UpdateItem | Sets last_message_id, last_message_at, last_message_preview (see line 4842) |

<!-- NOTE: Conversations table SK for the update is not "META" — the update uses Key={"conversation_id": conversation_id} directly (single-item table, no SK). See messaging.py:4842. -->
| 5 | Get associated event details | Varies | Event-specific PK | Event-specific SK | GetItem | Optional: validate event exists at creation |

### 4.3 Pydantic Model Definitions

```python
# app/routers/messaging.py additions (NOT app/models.py — all messaging models
# are defined inline in the router file, e.g. SendTextMessageIn at line 1844)

from pydantic import BaseModel, Field, model_validator
from typing import Optional
from app.core.time import now_ts


class SendCountdownMessageIn(BaseModel):
    """Request model for sending a countdown message."""
    title: str = Field(..., min_length=1, max_length=200,
                       description="Display title for the countdown")
    target_datetime: int = Field(...,
                                 description="UTC Unix timestamp of target event")
    associated_event_type: str = Field(
        default="custom",
        pattern=r"^(broadcast|call|calendar|custom)$",
        description="Type of associated event"
    )
    associated_event_id: Optional[str] = Field(
        default=None, max_length=128,
        description="ID of linked event (required for non-custom types)"
    )
    reply_to_message_id: Optional[str] = Field(
        default=None,
        description="ID of message being replied to"
    )

    @model_validator(mode="after")
    def validate_target(self):
        if self.target_datetime <= now_ts():
            raise ValueError("target_datetime must be in the future")
        if self.associated_event_type != "custom" and not self.associated_event_id:
            raise ValueError("associated_event_id required for non-custom events")
        return self


class CountdownMessageOut(BaseModel):
    """Countdown-specific fields in MessageOut."""
    countdown_title: Optional[str] = None
    target_datetime: Optional[int] = None
    associated_event_type: Optional[str] = None
    associated_event_id: Optional[str] = None
```

### 4.4 Backend Endpoint

**File**: `app/routers/messaging.py`

```python
# Pattern follows send_text_message (see messaging.py:7684)
@router.post("/conversations/{conv_id}/messages/countdown", status_code=201)
def send_countdown_message(conv_id: str, body: SendCountdownMessageIn, user_id: str = Depends(get_messaging_user_id)):
    """Send a countdown message to a conversation."""
    require_participant_active(user_id, conv_id)  # see existing pattern at line 7695
    conv = _get_conversation_or_404(conv_id)  # takes only conversation_id (see messaging.py:4296)

    msg_id = f"m_{new_id()}"  # uses new_id() helper, not uuid4().hex directly
    ts = now_ts()

    message_item = {
        "conversation_id": conv_id,
        "message_id": msg_id,
        "sender_id": user_id,
        "kind": "countdown",
        "text": body.title,  # Also stored as text for search/preview
        "countdown_title": body.title,
        "target_datetime": body.target_datetime,
        "associated_event_type": body.associated_event_type,
        "associated_event_id": body.associated_event_id,
        "reactions": {},
        "created_at": ts,
    }

    tbl_msgs.put_item(Item=message_item)  # uses tbl_msgs, not T.messages (see messaging.py:224)

    # Follow _send_single_destination_message pattern (see line 4806)
    # which handles conversation last_message update + search indexing + SSE fanout

    return _message_out_from_item(message_item, user_id)  # requires viewer_user_id (see messaging.py:3766)
```

<!-- NOTE: _get_conversation_or_404() takes only conversation_id, not user_sub (see messaging.py:4296). Participant access check is done separately via require_participant_active(). -->
<!-- NOTE: _message_out_from_item() takes (message_item, viewer_user_id) — the viewer_user_id param is required (see messaging.py:3766). -->
<!-- NOTE: T.messages does not exist — messaging.py uses module-level tbl_msgs = ddb.Table(DDB_MESSAGES) (see line 224). -->
<!-- NOTE: _update_conversation_last_message() and _emit_message_sse() do not exist as named functions. Use _send_single_destination_message() (line 4806) which handles last_message update (line 4842) + SSE fanout via fanout_event_to_conversation() (line 5297). -->

### 4.5 API Request/Response Examples

**POST /ui/messaging/conversations/{conv_id}/messages/countdown**

Request:
```json
{
  "title": "Team standup starts in...",
  "target_datetime": 1748527200,
  "associated_event_type": "call",
  "associated_event_id": "call_abc123def456"
}
```

Response (201):
```json
{
  "message_id": "m_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
  "conversation_id": "conv_x1y2z3",
  "sender_id": "e2e_alice@test.local",
  "kind": "countdown",
  "text": "Team standup starts in...",
  "countdown_title": "Team standup starts in...",
  "target_datetime": 1748527200,
  "associated_event_type": "call",
  "associated_event_id": "call_abc123def456",
  "reply_to_message_id": null,
  "created_at": 1748523600,
  "reactions": {},
  "tip_amount_cents": 0
}
```

**POST (custom countdown, no event link)**

Request:
```json
{
  "title": "Birthday countdown!",
  "target_datetime": 1751241600,
  "associated_event_type": "custom"
}
```

Response (201):
```json
{
  "message_id": "m_f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6",
  "conversation_id": "conv_x1y2z3",
  "sender_id": "e2e_alice@test.local",
  "kind": "countdown",
  "text": "Birthday countdown!",
  "countdown_title": "Birthday countdown!",
  "target_datetime": 1751241600,
  "associated_event_type": "custom",
  "associated_event_id": null,
  "created_at": 1748523601
}
```

**POST (broadcast link)**

Request:
```json
{
  "title": "Live stream starting soon!",
  "target_datetime": 1748530800,
  "associated_event_type": "broadcast",
  "associated_event_id": "bcast_789xyz"
}
```

Response (201):
```json
{
  "message_id": "m_1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d",
  "kind": "countdown",
  "countdown_title": "Live stream starting soon!",
  "target_datetime": 1748530800,
  "associated_event_type": "broadcast",
  "associated_event_id": "bcast_789xyz",
  "created_at": 1748523602
}
```

### 4.6 Error Handling Matrix

| Scenario | HTTP Status | Error Code | Error Message | Recovery Action |
|----------|-------------|------------|---------------|-----------------|
| target_datetime in the past | 422 | `validation_error` | "target_datetime must be in the future" | Set target_datetime to a future timestamp |
| Non-custom event without associated_event_id | 422 | `validation_error` | "associated_event_id required for non-custom events" | Provide an event ID or use "custom" type |
| Invalid associated_event_type | 422 | `validation_error` | "String should match pattern '^(broadcast\|call\|calendar\|custom)$'" | Use one of: broadcast, call, calendar, custom |
| Title too long (>200 chars) | 422 | `validation_error` | "ensure this value has at most 200 characters" | Shorten the title |
| Title empty | 422 | `validation_error` | "ensure this value has at least 1 character" | Provide a non-empty title |
| Conversation not found | 404 | `not_found` | "Conversation not found" | Verify the conversation ID |
| User not a participant | 403 | `forbidden` | "Not a participant in this conversation" | User must be in the conversation |
| associated_event_id too long (>128 chars) | 422 | `validation_error` | "ensure this value has at most 128 characters" | Use a valid event ID |
| Non-integer target_datetime | 422 | `validation_error` | "value is not a valid integer" | Provide Unix timestamp as integer |

### 4.7 MessageOut Extension

Add to `MessageOut` model (see `app/routers/messaging.py:2325`) and `_message_out_from_item()` (line 3766). Also add `"countdown"` to the `kind` Literal at line 2330:

```python
countdown_title: Optional[str] = None
target_datetime: Optional[int] = None
associated_event_type: Optional[str] = None
associated_event_id: Optional[str] = None
```

### 4.8 Frontend Types

**File**: `frontend/src/api/types.ts` (existing file — add countdown fields to `MessageOut` interface)

```typescript
export interface MessageOut {
  // ... existing fields ...
  countdown_title?: string | null;
  target_datetime?: number | null;
  associated_event_type?: "broadcast" | "call" | "calendar" | "custom" | null;
  associated_event_id?: string | null;
}
```

### 4.9 Frontend API

**File**: `frontend/src/api/endpoints/messaging.ts` (existing file — add new function)

```typescript
export const sendCountdownMessage = (
  conversationId: string,
  data: {
    title: string;
    target_datetime: number;
    associated_event_type?: string;
    associated_event_id?: string;
  }
) => api.post(`/ui/messaging/conversations/${conversationId}/messages/countdown`, data);
```

### 4.10 CountdownCard Component

**File**: `frontend/src/pages/messages/CountdownCard.tsx`

```typescript
interface CountdownCardProps {
  title: string;
  targetDatetime: number;  // UTC Unix timestamp
  associatedEventType: string;
  associatedEventId?: string | null;
}

export function CountdownCard({ title, targetDatetime, associatedEventType, associatedEventId }: CountdownCardProps) {
  const [remaining, setRemaining] = useState(calculateRemaining(targetDatetime));

  useEffect(() => {
    const interval = setInterval(() => {
      setRemaining(calculateRemaining(targetDatetime));
    }, 1000);
    return () => clearInterval(interval);
  }, [targetDatetime]);

  const isExpired = remaining.total <= 0;

  return (
    <Card className="w-72" data-testid="countdown-card">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm flex items-center gap-2">
          <Timer className="h-4 w-4" />
          {title}
        </CardTitle>
      </CardHeader>
      <CardContent>
        {!isExpired ? (
          <div className="text-center text-2xl font-mono font-bold tracking-wider">
            {remaining.days > 0 && <span>{remaining.days}d </span>}
            <span>{pad(remaining.hours)}:{pad(remaining.minutes)}:{pad(remaining.seconds)}</span>
          </div>
        ) : (
          <div className="text-center">
            <p className="text-lg font-semibold text-green-600">
              {associatedEventType === "custom" ? "Time's up!" : "Event started!"}
            </p>
            {associatedEventType === "broadcast" && associatedEventId && (
              <Button size="sm" className="mt-2" asChild>
                <a href={`/broadcasts/${associatedEventId}`}>Watch Live</a>
              </Button>
            )}
            {associatedEventType === "call" && associatedEventId && (
              <Button size="sm" className="mt-2" asChild>
                <a href={`/calls/${associatedEventId}`}>Join Call</a>
              </Button>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function calculateRemaining(targetTs: number) {
  const diff = targetTs - Math.floor(Date.now() / 1000);
  if (diff <= 0) return { total: 0, days: 0, hours: 0, minutes: 0, seconds: 0 };
  return {
    total: diff,
    days: Math.floor(diff / 86400),
    hours: Math.floor((diff % 86400) / 3600),
    minutes: Math.floor((diff % 3600) / 60),
    seconds: diff % 60,
  };
}

function pad(n: number) { return n.toString().padStart(2, "0"); }
```

### 4.11 Frontend Component Tree

```
ComposeBar
├── ... existing buttons ...
├── CountdownButton (Timer icon)
│   └── onClick → setCountdownDialogOpen(true)
└── CountdownComposerDialog
    ├── DialogHeader: "Create Countdown"
    ├── TitleInput (text field, max 200 chars)
    ├── DateTimePicker (target date + time)
    ├── EventTypeSelector
    │   ├── RadioGroup
    │   │   ├── "Custom" (default)
    │   │   ├── "Broadcast"
    │   │   ├── "Call"
    │   │   └── "Calendar Event"
    │   └── EventIdInput (conditional, shown for non-custom types)
    │       └── Or: EventPicker (browse existing events)
    ├── PreviewSection
    │   └── CountdownCard (preview with live timer)
    └── DialogFooter
        ├── CancelButton
        └── CreateButton (disabled if title empty or target in past)

MessageBubble
├── ... existing kind checks ...
└── kind === "countdown"
    └── CountdownCard
        ├── CardHeader
        │   ├── Timer icon
        │   └── countdown_title
        └── CardContent
            ├── (active) TimerDisplay: DD:HH:MM:SS
            └── (expired) CompletionMessage
                ├── "Time's up!" or "Event started!"
                └── CTAButton (Watch Live / Join Call / View Event)
```

**Props interfaces**:

```typescript
interface CountdownComposerDialogProps {
  open: boolean;
  onClose: () => void;
  onSubmit: (data: {
    title: string;
    target_datetime: number;
    associated_event_type: string;
    associated_event_id?: string;
  }) => void;
}

interface CountdownCardProps {
  title: string;
  targetDatetime: number;
  associatedEventType: string;
  associatedEventId?: string | null;
}

interface TimerDisplayProps {
  remaining: {
    total: number;
    days: number;
    hours: number;
    minutes: number;
    seconds: number;
  };
}

interface CompletionMessageProps {
  eventType: string;
  eventId?: string | null;
}
```

### 4.12 ComposeBar Integration

Add a countdown button to ComposeBar toolbar:

```tsx
<Button variant="ghost" size="icon" onClick={() => setCountdownDialogOpen(true)}>
  <Timer className="h-4 w-4" />
</Button>

<CountdownComposerDialog
  open={countdownDialogOpen}
  onClose={() => setCountdownDialogOpen(false)}
  onSubmit={handleCountdownSubmit}
/>
```

**CountdownComposerDialog** fields:
- Title input
- Date + time picker for target datetime
- Event type selector (Custom / Broadcast / Call / Calendar)
- Event ID input (if not Custom) -- or picker from existing events

### 4.13 MessageBubble Integration

```tsx
{message.kind === "countdown" && message.countdown_title && message.target_datetime && (
  <CountdownCard
    title={message.countdown_title}
    targetDatetime={message.target_datetime}
    associatedEventType={message.associated_event_type || "custom"}
    associatedEventId={message.associated_event_id}
  />
)}
```

---

## 5. Observability

### 5.1 Metrics

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `msg_countdown_created_total` | Counter | `event_type=(broadcast\|call\|calendar\|custom)` | Countdown messages created by event type |
| `msg_countdown_expired_views_total` | Counter | `event_type`, `had_cta=(true\|false)` | Views of expired countdown cards (measures CTA visibility) |
| `msg_countdown_cta_clicks_total` | Counter | `event_type` | Clicks on "Watch Live" / "Join Call" buttons |

### 5.2 Logging

| Log Event | Level | Fields | Trigger |
|-----------|-------|--------|---------|
| `countdown.created` | INFO | `conversation_id`, `message_id`, `event_type`, `target_datetime` | Countdown message sent |
| `countdown.validation_failed` | WARNING | `reason`, `target_datetime`, `event_type` | Validation error on creation |
| `countdown.event_not_found` | WARNING | `event_type`, `event_id` | Associated event does not exist (optional validation) |

### 5.3 Alerting

No specific alerting needed for countdown messages. Standard messaging error rate alerts apply.

---

## 6. Rollout Plan

### 6.1 Feature Flags

| Flag | Environment Variable | Default | Description |
|------|---------------------|---------|-------------|
| `COUNTDOWN_MESSAGES_ENABLED` | `COUNTDOWN_MESSAGES_ENABLED` | `true` | Enable countdown message kind |

### 6.2 Phased Rollout

**Phase 1: Backend (Day 1)**
- Add countdown endpoint and validation
- Extend MessageOut with countdown fields
- Wire _message_out_from_item() for countdown fields

**Phase 2: Frontend components (Days 2-3)**
- Build CountdownCard component with live timer
- Build CountdownComposerDialog
- Integrate into ComposeBar and MessageBubble

**Phase 3: Polish and testing (Days 4-5)**
- Add event type validation (optional: verify linked event exists)
- Write E2E tests
- Handle edge cases (timezone display, very long countdowns)

---

## 7. Performance Considerations

### 7.1 Latency Targets

| Operation | Target | Strategy |
|-----------|--------|----------|
| Create countdown message | < 50ms | Single DDB PutItem + UpdateItem |
| Render countdown card | < 1ms | Pure frontend calculation, no API call |
| Timer tick (1s interval) | < 0.1ms | Simple arithmetic on cached target timestamp |

### 7.2 Timer Performance

| Concern | Mitigation |
|---------|-----------|
| Many countdown cards ticking simultaneously | Each card runs its own `setInterval(1000)`; typically only 1-2 visible at once. For conversations with many countdowns, the interval only runs for visible messages (IntersectionObserver, future optimization). |
| Client clock drift | Timer is cosmetic -- display only. No server roundtrip for each tick. Server stores the authoritative `target_datetime`. |
| Memory leak from intervals | `useEffect` cleanup function calls `clearInterval` on unmount. Expired countdowns also clear their interval. |
| Countdown cards in message list (scrolled offscreen) | React only renders visible messages in virtualized lists. Offscreen cards are unmounted, stopping their intervals. |

### 7.3 Caching Strategy

- No caching needed for countdown data -- it is part of the standard message object.
- The `target_datetime` is immutable after creation -- no stale data concern.
- CountdownCard performs all calculations client-side with `Date.now()`.

---

## 8. E2E Test Plan

### 8.1 Test File

`frontend/e2e/countdown-messages.spec.ts` -- 24 tests across 6 sections.

### 8.2 Test Setup

```typescript
const TS = Date.now();
const FUTURE_TS = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
const PAST_TS = Math.floor(Date.now() / 1000) - 60; // 1 minute ago
const NEAR_FUTURE_TS = Math.floor(Date.now() / 1000) + 10; // 10 seconds from now
let dmConvoId: string;

test.beforeAll(async ({ browser }) => {
  // Set up Alice and Bob sessions
  // Create/get DM conversation
});
```

### 8.3 Section 306: Countdown Message API (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 306.1 | Create countdown message with valid future target | POST; 201; `kind=countdown`, `countdown_title` and `target_datetime` set |
| 306.2 | Countdown message with custom event type | POST `associated_event_type=custom`; 201; no `associated_event_id` required |
| 306.3 | Countdown message with broadcast link | POST `associated_event_type=broadcast`, `associated_event_id=bcast_123`; 201 |
| 306.4 | Reject countdown with past target_datetime | POST with `target_datetime` in past; 422; "target_datetime must be in the future" |
| 306.5 | Reject broadcast countdown without event ID | POST `associated_event_type=broadcast` without `associated_event_id`; 422 |

### 8.4 Section 307: Countdown Message in Conversation (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 307.1 | Countdown message appears in message list | GET messages; find message with `kind=countdown`; `countdown_title` matches |
| 307.2 | Bob receives countdown message | Bob GET messages; countdown message visible with `target_datetime` |
| 307.3 | Countdown message supports replies | POST text message with `reply_to_message_id` of countdown; 201 |
| 307.4 | Countdown appears in last_message preview | GET conversations; conversation has `last_message` with `kind=countdown` |

### 8.5 Section 308: Countdown Rendering (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 308.1 | Active countdown shows timer display | Navigate to conversation; `[data-testid="countdown-card"]` visible; contains colon-separated time |
| 308.2 | Countdown card shows title | Card contains the countdown title text |
| 308.3 | Expired countdown shows completion state | Create countdown with near-future target; wait; card shows "Time's up!" or "Event started!" |

### 8.6 Section 309: Countdown Validation Edge Cases (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 309.1 | Reject countdown with title > 200 characters | POST with 201-char title; 422 |
| 309.2 | Reject countdown with invalid event type | POST with `associated_event_type=invalid`; 422 |
| 309.3 | Countdown with calendar event type and event ID | POST `associated_event_type=calendar`, `associated_event_id=evt_123`; 201 |
| 309.4 | Countdown with call event type and event ID | POST `associated_event_type=call`, `associated_event_id=call_456`; 201 |

### 8.7 Section 310: Countdown in Group Chats (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 310.1 | Create countdown in group conversation | Create group; POST countdown; 201; all participants receive message |
| 310.2 | Multiple countdowns in same conversation | Create 3 countdown messages; GET messages; all 3 present with distinct IDs |
| 310.3 | Countdown with reply_to in group | Create text message; create countdown as reply; reply_to_message_id set correctly |
| 310.4 | Non-participant cannot send countdown | Non-member POST countdown to group; 403 |

### 8.8 Section 311: Countdown CTA Buttons (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 311.1 | Broadcast countdown shows "Watch Live" when expired | Create broadcast countdown with near-future target; wait; verify "Watch Live" button appears |
| 311.2 | Call countdown shows "Join Call" when expired | Create call countdown with near-future target; wait; verify "Join Call" button appears |
| 311.3 | Custom countdown shows "Time's up!" without CTA | Create custom countdown with near-future target; wait; verify "Time's up!" text, no button |
| 311.4 | CTA button has correct href | Verify "Watch Live" button links to `/broadcasts/{event_id}` |

---

## 9. Security Considerations

- `target_datetime` validated server-side (must be future)
- `associated_event_id` is display-only in countdown card -- the linked event's own access control governs whether the "Join" button works
- No sensitive data in countdown fields
- Only conversation participants can create countdown messages
- CTA buttons use standard navigation -- clicking "Watch Live" still requires broadcast access

---

## 10. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| None | -- | Standalone feature |

### 10.1 Downstream Dependents

| Ticket | Depends On |
|--------|-----------|
| FEED-005 (Countdown Newsfeed Posts) | CountdownCard component |

---

## 11. File Change Summary

| File | Change Type | Description |
|------|-------------|-------------|
| `frontend/src/pages/messages/CountdownCard.tsx` | **New** | Live countdown timer card component |
| `frontend/src/pages/messages/CountdownComposerDialog.tsx` | **New** | Dialog for creating countdown messages |
| `app/routers/messaging.py` | Modify | Add countdown endpoint, `SendCountdownMessageIn` model, extend `MessageOut` kind Literal (line 2330), add countdown fields to `_message_out_from_item()` (line 3766) |
| `frontend/src/api/types.ts` | Modify | Add countdown fields to `MessageOut` interface |
| `frontend/src/api/endpoints/messaging.ts` | Modify | Add `sendCountdownMessage` function |
| `frontend/src/pages/messages/ComposeBar.tsx` | Modify | Add countdown button + dialog |
| `frontend/src/pages/messages/MessageBubble.tsx` | Modify | Render CountdownCard for `kind === "countdown"` |
| `frontend/e2e/countdown-messages.spec.ts` | **New** | 24 E2E tests across sections 306-311 |

<!-- NOTE: app/models.py is NOT the correct location for SendCountdownMessageIn — all messaging Pydantic models are defined inline in app/routers/messaging.py (e.g., SendTextMessageIn at line 1844, CreateImageMessageIn at line 1911). Define SendCountdownMessageIn in messaging.py alongside the other models. -->

---

## Codebase References

### Backend — `app/routers/messaging.py`
| Reference | Line | Notes |
|-----------|------|-------|
| `MessageOut` class | 2325 | Add `countdown_title`, `target_datetime`, `associated_event_type`, `associated_event_id` fields |
| `kind` Literal | 2330 | Add `"countdown"` to the union; current kinds: text, image, file, audio, video, gallery, file_share, calendar_share, calendar_event, meeting_poll, video_share, voice_message, voicemail |
| `SendTextMessageIn` | 1844 | Pattern reference for `SendCountdownMessageIn` model definition |
| `CreateImageMessageIn` | 1911 | Another pattern reference for new message kind input models |
| `_message_out_from_item(message_item, viewer_user_id)` | 3766 | Extend to populate countdown fields; signature takes `(dict, str)` |
| `_serialize_message_event_payload(message_item, viewer_user_id)` | 4065 | May need to include countdown fields in SSE payloads |
| `_get_conversation_or_404(conversation_id)` | 4296 | Takes only `conversation_id` (not `user_sub`) |
| `_send_single_destination_message(...)` | 4806 | Handles last_message update + search indexing + SSE fanout |
| `tbl_convos.update_item(...)` (last_message update) | 4842 | Sets `last_message_at`, `last_message_preview`, `last_message_id` |
| `fanout_event_to_conversation(...)` | 5297 | SSE event fanout to participants |
| `send_text_message(...)` | 7684 | Primary pattern reference for new message endpoints |
| `tbl_msgs` (Messages table handle) | 224 | `ddb.Table(DDB_MESSAGES)` — use this, not `T.messages` |
| `DDB_MESSAGES` constant | 160 | `os.getenv("DDB_MESSAGES", "Messages")` |
| `DDB_CONVERSATIONS` constant | 158 | `os.getenv("DDB_CONVERSATIONS", "Conversations")` |

### Backend — DynamoDB Tables (`scripts/local-ddb-init.py`)
| Table | Notes |
|-------|-------|
| `Messages` | PK: `conversation_id`, SK: `message_id` — stores all message kinds including countdown |
| `Conversations` | PK: `conversation_id` — stores conversation metadata, last_message fields |
| `Participants` | PK: `conversation_id#user_id`, GSI1PK: `conversation_id` — participant membership |

### Frontend — Existing Files to Modify
| File | Notes |
|------|-------|
| `frontend/src/pages/messages/MessageBubble.tsx` | Add countdown card rendering branch (existing expiry countdown logic at line 417 is unrelated — it handles message expiry timers) |
| `frontend/src/pages/messages/ComposeBar.tsx` | Add Timer icon button + CountdownComposerDialog trigger (existing `autosaveTimerRef` at line 177 is unrelated) |
| `frontend/src/pages/messages/ConversationView.tsx` | Wire countdown mutation to ComposeBar `onCountdownSubmit` prop |
| `frontend/src/api/types.ts` | Add countdown fields to `MessageOut` TypeScript interface |
| `frontend/src/api/endpoints/messaging.ts` | Add `sendCountdownMessage()` API function |

### Frontend — New Files
| File | Notes |
|------|-------|
| `frontend/src/pages/messages/CountdownCard.tsx` | New component — live ticking countdown card |
| `frontend/src/pages/messages/CountdownComposerDialog.tsx` | New component — dialog for creating countdown messages |

### Frontend — UI Components (verified present)
| Component | Path |
|-----------|------|
| `Card`, `CardHeader`, `CardContent`, `CardTitle` | `frontend/src/components/ui/card.tsx` |
| `Button` | `frontend/src/components/ui/button.tsx` |
| `Dialog` | `frontend/src/components/ui/dialog.tsx` |

### Corrections Applied
| Original Claim | Correction |
|----------------|------------|
| `find_datetime` listed as existing message kind | Does not exist anywhere in codebase |
| `app/services/messaging.py` referenced as location of `send_text_message` | File does not exist; all messaging logic is in `app/routers/messaging.py` |
| `_get_conversation_or_404(conv_id, user_sub)` | Function takes only `conversation_id` (see line 4296) |
| `_message_out_from_item(message_item)` | Function takes `(message_item, viewer_user_id)` — two arguments required (see line 3766) |
| `T.messages.put_item(...)` | Should be `tbl_msgs.put_item(...)` — messaging.py uses module-level table handles, not `T.*` |
| `_update_conversation_last_message()` and `_emit_message_sse()` | These named functions do not exist; use `_send_single_destination_message()` (line 4806) or call `tbl_convos.update_item()` + `fanout_event_to_conversation()` directly |
| `app/models.py` for `SendCountdownMessageIn` | All messaging Pydantic models are defined in `app/routers/messaging.py`, not `app/models.py` |


---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_countdown_messages.py`

| # | Test Function | Description |
|---|--------------|-------------|
| 1 | `test_create_countdown_valid` | POST with valid future target; 201; kind=countdown, title/target set |
| 2 | `test_countdown_past_target_rejected` | target_datetime in past; 422 |
| 3 | `test_countdown_broadcast_without_event_id` | broadcast type without event_id; 422 |
| 4 | `test_countdown_custom_no_event_id` | custom type without event_id; 201 |
| 5 | `test_countdown_title_too_long` | 201-char title; 422 |
| 6 | `test_countdown_invalid_event_type` | invalid event type; 422 |
| 7 | `test_countdown_in_message_list` | Create countdown; GET messages; present with correct fields |
| 8 | `test_countdown_non_participant` | Non-member POST; 403 |

All tests use moto-mocked DynamoDB. Messages/Conversations/Participants tables seeded in conftest fixtures.

### Integration Tests

| # | Scenario | Services Involved |
|---|----------|-------------------|
| 1 | Countdown updates conversation last_message | messaging router + conversations table |
| 2 | Countdown triggers SSE fanout to participants | messaging router + SSE publish |
| 3 | Countdown in group visible to all members | messaging router + participants table |

### E2E Tests (Playwright)

**File**: `frontend/e2e/countdown-messages.spec.ts` -- 24 tests, sections 306-311

**Auth**: `injectAuth(page, identity)` for cookie auth; `sessions[identity].csrf_token` for CSRF header on POST.

| Section | Tests | Key Assertions |
|---------|-------|----------------|
| 306 | 5 | Countdown API CRUD: create valid, custom type, broadcast link, reject past, reject missing event_id |
| 307 | 4 | Conversation: appears in list, Bob receives, supports replies, last_message preview |
| 308 | 3 | Rendering: timer display visible, title shown, expired shows completion |
| 309 | 4 | Validation: title >200 (422), invalid type (422), calendar type (201), call type (201) |
| 310 | 4 | Group chats: create in group, multiple countdowns, reply, non-participant 403 |
| 311 | 4 | CTA buttons: broadcast Watch Live, call Join Call, custom Time's up, correct href |

**Negative tests**: 422 for past target, missing event_id, title too long, invalid type. 403 for non-participant.

### Test Data Requirements

- DDB seeds: Messages, Conversations, Participants via `e2e_session_setup.py`
- Test users: Alice (sender), Bob (recipient)
- DM conversation + group conversation created in `beforeAll`

### CI/Pipeline

- Feature flag: `COUNTDOWN_MESSAGES_ENABLED=true`
- Serial execution (1 worker), 1 retry per `playwright.config.ts`
- Retry-safe: unique `Date.now()` timestamps in countdown titles


---

## Dependencies & Merge Safety

### Depends On

| Ticket | Type | Detail |
|--------|------|--------|
| (none) | -- | Standalone; uses existing message infrastructure |

### Depended On By

| Ticket | Type | Detail |
|--------|------|--------|
| FEED-005 | Component | CountdownCard reused for newsfeed countdown posts |

### Merge Strategy

**Independent** -- No prerequisite tickets. Can merge at any time.

### Merge Checklist

- [ ] `"countdown"` added to `kind` Literal in MessageOut (messaging.py:2330)
- [ ] `_message_out_from_item()` populates countdown fields
- [ ] CountdownCard.tsx and CountdownComposerDialog.tsx created
- [ ] ComposeBar and MessageBubble integrate countdown components
- [ ] E2E pass: `npx playwright test e2e/countdown-messages.spec.ts`
- [ ] No regressions: `npx playwright test e2e/messaging-features.spec.ts`
