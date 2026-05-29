# MSG-010: Countdown Messages

**Ticket**: MSG-010
**Author**: Engineering
**Status**: Design
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

## 2. Current State Analysis

### 2.1 Message Kinds

Current kinds: `text`, `image`, `file_share`, `calendar_share`, `calendar_event`, `meeting_poll`, `find_datetime`. Adding `countdown` follows the established pattern.

### 2.2 Message Send Infrastructure

`send_text_message()` in `app/services/messaging.py` is the core send function. New message kinds are added by:
1. Defining a new endpoint in `app/routers/messaging.py`
2. Storing kind-specific fields on the message DDB item
3. Including the fields in `MessageOut` and `_message_out_from_item()`
4. Adding rendering in `MessageBubble.tsx`

### 2.3 Frontend Timer Patterns

React's `useEffect` with `setInterval` is the standard pattern for live timers. The frontend already uses similar patterns in scheduled message indicators. The countdown component will follow the same approach with a 1-second interval.

### 2.4 Gaps

1. **No `countdown` message kind** — no backend support.
2. **No countdown fields on messages** — no `target_datetime`, `associated_event_type`.
3. **No CountdownCard component** — no live timer rendering.
4. **No "Join" button integration** — no link to broadcast/call when timer expires.

---

## 3. Technical Design

### 3.1 Message Schema

Add to message item when `kind = "countdown"`:

| Field | Type | Description |
|-------|------|-------------|
| `countdown_title` | String | Display title (e.g., "Team meeting starts in...") |
| `target_datetime` | Number | UTC Unix timestamp of target event |
| `associated_event_type` | String | `"broadcast"`, `"call"`, `"calendar"`, `"custom"` |
| `associated_event_id` | String (optional) | ID of linked event (broadcast_id, call_id, calendar_event_id) |

### 3.2 Backend Endpoint

**File**: `app/routers/messaging.py`

```python
class SendCountdownMessageIn(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    target_datetime: int = Field(..., description="UTC Unix timestamp")
    associated_event_type: str = Field(
        default="custom",
        pattern=r"^(broadcast|call|calendar|custom)$",
    )
    associated_event_id: Optional[str] = Field(default=None, max_length=128)
    reply_to_message_id: Optional[str] = None

    @model_validator(mode="after")
    def validate_target(self):
        if self.target_datetime <= now_ts():
            raise ValueError("target_datetime must be in the future")
        if self.associated_event_type != "custom" and not self.associated_event_id:
            raise ValueError("associated_event_id required for non-custom events")
        return self

@router.post("/conversations/{conv_id}/messages/countdown", status_code=201)
def send_countdown_message(conv_id: str, body: SendCountdownMessageIn, ctx=Depends(require_ui_session)):
    """Send a countdown message to a conversation."""
    user_sub = ctx["user_sub"]

    # Verify conversation access (existing pattern)
    conv = _get_conversation_or_404(conv_id, user_sub)

    msg_id = f"m_{uuid4().hex}"
    ts = now_ts()

    message_item = {
        "conversation_id": conv_id,
        "message_id": msg_id,
        "sender_id": user_sub,
        "kind": "countdown",
        "text": body.title,  # Also stored as text for search/preview
        "countdown_title": body.title,
        "target_datetime": body.target_datetime,
        "associated_event_type": body.associated_event_type,
        "associated_event_id": body.associated_event_id,
        "reply_to_message_id": body.reply_to_message_id,
        "created_at": ts,
    }

    T.messages.put_item(Item=message_item)
    _update_conversation_last_message(conv_id, msg_id, ts)
    _emit_message_sse(conv_id, message_item)

    return _message_out_from_item(message_item)
```

### 3.3 MessageOut Extension

Add to `MessageOut` model and `_message_out_from_item()`:

```python
countdown_title: Optional[str] = None
target_datetime: Optional[int] = None
associated_event_type: Optional[str] = None
associated_event_id: Optional[str] = None
```

### 3.4 Frontend Types

**File**: `frontend/src/api/types.ts`

```typescript
export interface MessageOut {
  // ... existing fields ...
  countdown_title?: string | null;
  target_datetime?: number | null;
  associated_event_type?: "broadcast" | "call" | "calendar" | "custom" | null;
  associated_event_id?: string | null;
}
```

### 3.5 Frontend API

**File**: `frontend/src/api/endpoints/messaging.ts`

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

### 3.6 CountdownCard Component

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

### 3.7 ComposeBar Integration

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
- Event ID input (if not Custom) — or picker from existing events

### 3.8 MessageBubble Integration

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

## 4. Implementation Plan

### 4.1 Files to Create

| File | Purpose |
|------|---------|
| `frontend/src/pages/messages/CountdownCard.tsx` | Live countdown timer card component |
| `frontend/src/pages/messages/CountdownComposerDialog.tsx` | Dialog for creating countdown messages |

### 4.2 Files to Modify

| File | Changes |
|------|---------|
| `app/routers/messaging.py` | Add countdown endpoint and model |
| `app/models.py` | Add countdown fields to MessageOut |
| `frontend/src/api/types.ts` | Add countdown fields to MessageOut |
| `frontend/src/api/endpoints/messaging.ts` | Add `sendCountdownMessage` |
| `frontend/src/pages/messages/ComposeBar.tsx` | Add countdown button + dialog |
| `frontend/src/pages/messages/MessageBubble.tsx` | Render CountdownCard |

### 4.3 Step-by-Step Order

1. Add countdown endpoint and model to backend
2. Extend MessageOut with countdown fields
3. Add frontend types and API
4. Build CountdownCard component
5. Build CountdownComposerDialog
6. Integrate into ComposeBar and MessageBubble
7. Write E2E tests

---

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/countdown-messages.spec.ts` — 12 tests across 3 sections.

### 5.2 Test Setup

```typescript
const TS = Date.now();
const FUTURE_TS = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
const PAST_TS = Math.floor(Date.now() / 1000) - 60; // 1 minute ago
let dmConvoId: string;

test.beforeAll(async ({ browser }) => {
  // Set up Alice and Bob sessions
  // Create/get DM conversation
});
```

### 5.3 Section 306: Countdown Message API (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 306.1 | Create countdown message with valid future target | POST; 201; `kind=countdown`, `countdown_title` and `target_datetime` set |
| 306.2 | Countdown message with custom event type | POST `associated_event_type=custom`; 201; no `associated_event_id` required |
| 306.3 | Countdown message with broadcast link | POST `associated_event_type=broadcast`, `associated_event_id=bcast_123`; 201 |
| 306.4 | Reject countdown with past target_datetime | POST with `target_datetime` in past; 422; "target_datetime must be in the future" |
| 306.5 | Reject broadcast countdown without event ID | POST `associated_event_type=broadcast` without `associated_event_id`; 422 |

### 5.4 Section 307: Countdown Message in Conversation (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 307.1 | Countdown message appears in message list | GET messages; find message with `kind=countdown`; `countdown_title` matches |
| 307.2 | Bob receives countdown message | Bob GET messages; countdown message visible with `target_datetime` |
| 307.3 | Countdown message supports replies | POST text message with `reply_to_message_id` of countdown; 201 |
| 307.4 | Countdown appears in last_message preview | GET conversations; conversation has `last_message` with `kind=countdown` |

### 5.5 Section 308: Countdown Rendering (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 308.1 | Active countdown shows timer display | Navigate to conversation; `[data-testid="countdown-card"]` visible; contains colon-separated time |
| 308.2 | Countdown card shows title | Card contains the countdown title text |
| 308.3 | Expired countdown shows completion state | Create countdown with near-future target; wait; card shows "Time's up!" or "Event started!" |

---

## 6. Error Handling

| Scenario | Status | Detail |
|----------|--------|--------|
| target_datetime in the past | 422 | "target_datetime must be in the future" |
| Non-custom event without ID | 422 | "associated_event_id required for non-custom events" |
| Invalid event type | 422 | Pydantic pattern validation |
| Title too long (> 200 chars) | 422 | Pydantic max_length validation |

---

## 7. Performance Considerations

| Concern | Mitigation |
|---------|-----------|
| Many countdown cards ticking simultaneously | Each card runs its own `setInterval(1000)`; typically only 1-2 visible at once. For conversations with many countdowns, the interval only runs for visible messages (IntersectionObserver, future optimization). |
| Client clock drift | Timer is cosmetic — display only. No server roundtrip for each tick. Server stores the authoritative `target_datetime`. |

---

## 8. Security Considerations

- `target_datetime` validated server-side (must be future)
- `associated_event_id` is display-only in countdown card — the linked event's own access control governs whether the "Join" button works
- No sensitive data in countdown fields

---

## 9. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| None | — | Standalone feature |

### 9.1 Downstream Dependents

| Ticket | Depends On |
|--------|-----------|
| FEED-005 (Countdown Newsfeed Posts) | CountdownCard component |
