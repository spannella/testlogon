# CALL-007: Add Call Ringing Timeout and Missed-Call Handling

## 1. Overview & Motivation

When a user initiates a WebRTC direct call, the callee receives an invite that places the call into the `invited` state. If the callee never responds (e.g., they are away from the device, the app is backgrounded, or they simply ignore the incoming ring), the call remains in the `invited` state indefinitely. This creates several problems:

- **Caller UX degradation**: The caller sees the "outgoing ringing" UI forever with no resolution. The only escape is manually canceling the call.
- **Resource leak**: The `CallSessionRecord` in DynamoDB stays in a non-terminal state, which means subsequent calls to the same callee may be blocked by the `callee_busy` check in `create_invite()` (line 157 of `messaging_call_lifecycle.py`), since the function scans recent sessions in `active_states = {"invited", "accepted", "connected"}`.
- **Missing notification**: The callee never receives a "missed call" indicator in their conversation timeline, so they have no record that someone tried to reach them.
- **Inaccurate metrics**: The `record_webrtc_call_setup` metric only records `outcome="attempt"` at invite time; without a timeout transition, there is no corresponding failure metric for unanswered calls.

The `missed` state already exists in the type system (`CallState = Literal["invited", "accepted", "connected", "ended", "missed", "declined", "busy", "failed", "canceled"]` in `messaging_call_sessions.py`, line 9) and in the `TERMINAL_STATES` set (`messaging_call_lifecycle.py`, line 23), but no code path currently transitions a call into this state. This ticket adds a dual-layer timeout mechanism (client-driven primary, server-driven backstop) that transitions unanswered calls to `missed` after 30 seconds, emits a timeline event, sends an SSE notification, and updates the frontend state machine.

---

## 2. Current State Analysis

### 2.1 Call State Machine (Backend)

The backend lifecycle is defined in `app/services/messaging_call_lifecycle.py`. The allowed transitions are:

```python
TERMINAL_STATES = {"declined", "busy", "missed", "ended", "failed", "canceled"}
ALLOWED_TRANSITIONS = {
    "invited": {"accepted", "declined", "busy", "canceled", "failed"},
    "accepted": {"connected", "ended", "failed", "canceled"},
    "connected": {"ended", "failed"},
}
```

Key observation: `"missed"` is a terminal state but is NOT listed as a valid target in `ALLOWED_TRANSITIONS["invited"]`. This means no existing function can transition a call to `missed` without first updating the allowed transitions map.

### 2.2 Call Session Storage

Call sessions are stored in the `MessageCallSessions` DynamoDB table (`app/services/messaging_call_sessions.py`):
- **Primary key**: `call_id` (string)
- **GSIs**: `ByConversationStartedAt` (partition: `conversation_id`, sort: `start_ts_sort` numeric), `ByCallerStartedAt`, `ByCalleeStartedAt`
- **Fields**: `state`, `start_ts`, `connect_ts`, `end_ts`, `end_reason`, `lifecycle_events[]`, `idempotency_records{}`

The `start_ts` field is set at invite creation time (`now_ts()`). This gives us the precise timestamp to compute elapsed ringing duration for timeout detection.

### 2.3 Timeline Events

`app/services/messaging_call_timeline.py` emits system messages into the conversation's Messages table. The `emit_call_timeline_event` function:
1. Writes a system message (sender_id="system", subtype="call_lifecycle") with a deterministic `message_id` format: `sys_call_{call_id}_{event_type}_{ts}`
2. Updates the conversation's `last_message_at` and `last_message_preview`
3. Writes an archive event via `messaging_archive_writer`

The `_preview_for_event` function currently handles `call.invite`, `call.accept`, `call.decline`, and `call.end` but has no case for a `call.missed` or `call.timeout` event type.

### 2.4 Frontend State Machine

The frontend state machine (`frontend/src/pages/messages/callStateMachine.ts`) defines `CallUiState` including `"timeout"` as a valid UI state. The `REMOTE_DECLINE` event with `reason: "timeout"` transitions the machine to the `timeout` phase (line 96):

```typescript
if (event.reason === "timeout") return withPhase(state, "timeout", {
  reasonMessage: event.message ?? "Call timed out with no answer."
});
```

The `CallSessionOverlay.tsx` renders outcome copy for `timeout`: `"Call timed out with no answer."` (line 49).

### 2.5 Existing Client-Side Timer (Partial Implementation)

In `ConversationView.tsx` (line 533), there is already a 30-second `setTimeout` that fires after a successful invite creation:

```typescript
callTimeoutRef.current = window.setTimeout(() => {
  dispatchCall({ type: "REMOTE_DECLINE", reason: "timeout" });
}, 30_000);
```

However, this timer:
- Only updates the local UI state; it does NOT call the backend to transition the call to `missed`
- Is cleared if the caller navigates away or the component unmounts (line 487-490)
- Does not emit an SSE event to notify the callee
- Does not write a timeline event or update the DDB record

There is also a problematic auto-accept at line 530-532: `window.setTimeout(() => { dispatchCall({ type: "REMOTE_ACCEPT" }); }, 700)` which simulates acceptance after 700ms (likely a dev placeholder that should be removed or gated).

### 2.6 SSE Event Delivery

The `useMessagingStream.ts` hook listens for `call.*` event types and dispatches them to `window` as `CustomEvent("messaging:call-event")`. The `ConversationView.tsx` listener (line 558-591) handles `call.invite`, `call.accept`, `call.decline`, and `call.end`. There is no handler for a `call.missed` or `call.timeout` event type.

### 2.7 Background Task Pattern

The existing `_messaging_background_loop()` in `messaging.py` (line 11730) runs every 30 seconds and performs DynamoDB scans for scheduled message delivery and message expiry. The `broadcast_reconciler.py` provides a more sophisticated pattern with:
- Configurable interval via settings (`S.broadcast_reconciler_interval_seconds`)
- Enable/disable via feature flag (`S.broadcast_reconciler_enabled`)
- Drift detection with SLA-based escalation

---

## 3. Technical Design

### 3.1 Architecture Decision: Dual-Layer Timeout

We implement a **client-driven primary timeout** with a **server-driven backstop**:

| Layer | Mechanism | Latency | Purpose |
|-------|-----------|---------|---------|
| Client (caller) | `setTimeout` in ConversationView | Exact 30s | Fast UX feedback + API call to transition state |
| Server (background) | Periodic scan of `invited` sessions | 30s + up to 15s scan lag | Catches cases where client timer fails (page closed, network loss, crash) |

### 3.2 Default Timeout Duration

- **Default**: 30 seconds (matching existing client timer and industry norms: WhatsApp uses 30s, Signal uses 30s, FaceTime uses ~60s)
- **Configurable**: New setting `MESSAGING_WEBRTC_CALL_RINGING_TIMEOUT_SECONDS` (default 30, min 10, max 120)
- **Per-call override**: Future extension point in `CallInviteIn` model (not implemented in v1)

### 3.3 Backend Changes

#### 3.3.1 Allow `invited -> missed` Transition

In `app/services/messaging_call_lifecycle.py`, add `"missed"` to the allowed transitions from `invited`:

```python
ALLOWED_TRANSITIONS = {
    "invited": {"accepted", "declined", "busy", "canceled", "failed", "missed"},
    "accepted": {"connected", "ended", "failed", "canceled"},
    "connected": {"ended", "failed"},
}
```

#### 3.3.2 New `timeout_call()` Function

Add a new lifecycle function in `messaging_call_lifecycle.py`:

```python
def timeout_call(
    *,
    call_id: str,
    actor_user_id: str,
    reason: str = "no_answer",
    idempotency_key: Optional[str] = None,
    client_platform: str = "unknown",
    client_browser: str = "unknown",
    timeline_emitter: Callable[..., dict[str, object]] = emit_call_timeline_event,
) -> tuple[CallSessionRecord, LifecycleEvent]:
```

This function:
1. Loads the call session
2. Checks idempotency (same pattern as `end_call`)
3. Validates the actor is the caller (only the caller can declare a timeout; the server backstop uses `actor_user_id = "system"`)
4. Checks transition validity (`invited -> missed`)
5. Updates state to `missed` with `end_ts` and `end_reason="no_answer"`
6. Emits a `call.missed` timeline event
7. Records `record_webrtc_call_setup(outcome="failure", reason="timeout_no_answer")`

#### 3.3.3 New API Endpoint

Add to `app/routers/messaging.py`:

```python
@router.post("/messages/calls/{call_id}/timeout", response_model=CallActionOut)
async def timeout_call_endpoint(
    call_id: str,
    body: CallEndIn = CallEndIn(reason="no_answer"),
    user_id: str = Depends(get_messaging_user_id),
):
```

This endpoint allows the caller's client to explicitly transition the call to `missed` when the ringing timer expires.

#### 3.3.4 Timeline Preview Text

Add to `_preview_for_event` in `messaging_call_timeline.py`:

```python
if event_type == "call.missed":
    return "Missed call"
```

This produces the timeline system message "Missed call" visible to both parties in the conversation.

#### 3.3.5 Server-Side Background Timeout (Backstop)

Add a new function `_expire_stale_invites()` called from `_messaging_background_loop()`:

```python
async def _expire_stale_invites():
    """Transition calls stuck in 'invited' state past the ringing timeout to 'missed'."""
    timeout_seconds = S.messaging_webrtc_call_ringing_timeout_seconds
    cutoff_ts = now_ts() - timeout_seconds
    
    # Query the ByConversationStartedAt GSI is not suitable (partitioned by conversation_id).
    # Instead, scan the table filtering for state="invited" AND start_ts <= cutoff.
    # In production, this would use a dedicated GSI: ByStateStartedAt.
    resp = _call_sessions_table().scan(
        FilterExpression=(
            Attr("state").eq("invited") & Attr("start_ts").lte(cutoff_ts)
        )
    )
    for item in resp.get("Items", []):
        try:
            timeout_call(
                call_id=item["call_id"],
                actor_user_id="system",
                reason="server_timeout",
                idempotency_key=f"server_timeout_{item['call_id']}",
            )
        except CallLifecycleError:
            pass  # Already transitioned (race with client timeout)
```

This runs inside the existing `_messaging_background_loop()` on every 30-second tick, immediately after the scheduled message delivery step. The scan is lightweight because active `invited` calls are rare (most calls transition within seconds).

#### 3.3.6 New Settings

In `app/core/settings.py`:

```python
messaging_webrtc_call_ringing_timeout_seconds: int = int(
    os.environ.get("MESSAGING_WEBRTC_CALL_RINGING_TIMEOUT_SECONDS", "30")
)
```

#### 3.3.7 SSE Event Emission

After `timeout_call()` transitions the state, the existing `fanout_event_to_conversation` should be called with `event_type="call.missed"` to notify the callee via SSE. This happens implicitly through the `timeline_emitter` (which writes the system message), but we also need an explicit SSE fanout for real-time notification:

```python
fanout_event_to_conversation(
    conversation_id=record.conversation_id,
    sender_id=record.caller_user_id,
    event_type="call.missed",
    payload={
        "call_id": record.call_id,
        "conversation_id": record.conversation_id,
        "caller_user_id": record.caller_user_id,
        "callee_user_id": record.callee_user_id,
        "initial_mode": record.initial_mode,
        "event_ts": now_ts(),
    },
    respect_mute=False,  # Missed calls should always notify
)
```

### 3.4 Frontend Changes

#### 3.4.1 Client Timeout Calls Backend

Replace the fire-and-forget UI-only timer in `ConversationView.tsx` (line 533-535) with a version that calls the new `/timeout` endpoint:

```typescript
callTimeoutRef.current = window.setTimeout(async () => {
  dispatchCall({ type: "REMOTE_DECLINE", reason: "timeout" });
  if (callMachine.callId) {
    try {
      await timeoutCall(callMachine.callId, {
        reason: "no_answer",
        idempotency_key: `ui-timeout-${Date.now()}`,
      });
    } catch {
      // Best-effort; server backstop will catch it
    }
  }
}, RINGING_TIMEOUT_MS);
```

#### 3.4.2 Remove Auto-Accept Placeholder

Remove the 700ms auto-accept timer at line 530-532 which conflicts with the timeout mechanism:

```typescript
// REMOVE:
window.setTimeout(() => {
  dispatchCall({ type: "REMOTE_ACCEPT" });
}, 700);
```

#### 3.4.3 Handle `call.missed` SSE Event

In the `onCallEvent` handler (ConversationView.tsx, line 575-588), add a case for `call.missed`:

```typescript
} else if (eventType === "call.missed") {
  if (isCurrentUserCaller) {
    dispatchCall({ type: "REMOTE_DECLINE", reason: "timeout" });
  } else if (isCurrentUserCallee) {
    // Callee was on a different page or component was unmounted during ring
    // Invalidate conversations to show "Missed call" in sidebar
    queryClient.invalidateQueries({ queryKey: ["conversations"] });
  }
}
```

#### 3.4.4 Register `call.missed` in SSE Event Types

In `useMessagingStream.ts`, add `"call.missed"` to the `EVENT_TYPES` array (after `"call.end"` at line 105):

```typescript
"call.missed",
```

#### 3.4.5 Callee Ringing Timeout (Incoming Ring Auto-Dismiss)

The callee's `incoming_ringing` state should also timeout if they don't interact. Add a useEffect in `ConversationView.tsx`:

```typescript
React.useEffect(() => {
  if (callMachine.phase !== "incoming_ringing") return;
  const timer = window.setTimeout(() => {
    dispatchCall({ type: "END_REMOTE", message: "Call timed out." });
  }, RINGING_TIMEOUT_MS + 2000); // 2s grace for network latency
  return () => window.clearTimeout(timer);
}, [callMachine.phase]);
```

### 3.5 State Machine Update

Add `"missed"` handling to `callStateMachine.ts`. The existing `REMOTE_DECLINE` with `reason: "timeout"` already transitions to the `timeout` phase, which is the correct UX for the caller. For the callee receiving a `call.missed` SSE event while still showing `incoming_ringing`, the `END_REMOTE` event transitions to `ended`.

No changes needed to the state machine reducer itself; the existing events cover both sides.

### 3.6 Sequence Diagrams

**Happy path (client-driven timeout):**

```
Caller                    Backend                     Callee
  |                         |                           |
  |--POST /calls/invite---->|                           |
  |<---200 {call_id}--------|----SSE call.invite------->|
  |                         |                           |
  | [30s timer starts]      |                           |
  |                         |                           |
  | [30s elapsed]           |                           |
  |--POST /calls/{id}/timeout-->|                       |
  |<---200 {state:missed}---|----SSE call.missed------->|
  |                         |                           |
  | [UI: "Call timed out"]  | [Timeline: "Missed call"] |
```

**Backstop path (server-driven timeout):**

```
Caller                    Backend                     Callee
  |                         |                           |
  |--POST /calls/invite---->|                           |
  |<---200 {call_id}--------|----SSE call.invite------->|
  |                         |                           |
  | [caller closes tab]     |                           |
  |                         |                           |
  |                    [background loop tick, finds     |
  |                     start_ts > 30s ago, state=invited]
  |                         |                           |
  |                         |----SSE call.missed------->|
  |                         | [Timeline: "Missed call"] |
```

---

## 4. Implementation Plan

### Phase 1: Backend Core (Priority: P0)

| Step | File | Change |
|------|------|--------|
| 1.1 | `app/services/messaging_call_lifecycle.py` | Add `"missed"` to `ALLOWED_TRANSITIONS["invited"]` |
| 1.2 | `app/services/messaging_call_lifecycle.py` | Add `timeout_call()` function |
| 1.3 | `app/services/messaging_call_timeline.py` | Add `call.missed` case to `_preview_for_event` |
| 1.4 | `app/core/settings.py` | Add `messaging_webrtc_call_ringing_timeout_seconds` setting |
| 1.5 | `app/routers/messaging.py` | Add `POST /messages/calls/{call_id}/timeout` endpoint |
| 1.6 | `app/routers/messaging.py` | Add `_expire_stale_invites()` to `_messaging_background_loop()` |
| 1.7 | `app/routers/messaging.py` | Add SSE fanout in timeout endpoint (call `fanout_event_to_conversation`) |

### Phase 2: Frontend Integration (Priority: P0)

| Step | File | Change |
|------|------|--------|
| 2.1 | `frontend/src/api/endpoints/messaging.ts` | Add `timeoutCall(callId, opts)` API function |
| 2.2 | `frontend/src/pages/messages/ConversationView.tsx` | Replace UI-only timer with backend call |
| 2.3 | `frontend/src/pages/messages/ConversationView.tsx` | Remove 700ms auto-accept dev placeholder |
| 2.4 | `frontend/src/pages/messages/ConversationView.tsx` | Add `call.missed` to SSE event handler |
| 2.5 | `frontend/src/pages/messages/ConversationView.tsx` | Add callee incoming_ringing timeout effect |
| 2.6 | `frontend/src/hooks/useMessagingStream.ts` | Add `"call.missed"` to `EVENT_TYPES` array |

### Phase 3: Observability (Priority: P1)

| Step | File | Change |
|------|------|--------|
| 3.1 | `app/metrics.py` | Add `record_webrtc_call_timeout(source: "client" | "server")` metric |
| 3.2 | `app/services/messaging_call_lifecycle.py` | Emit timeout metric in `timeout_call()` |
| 3.3 | `app/routers/messaging.py` | Log server-side timeout transitions at INFO level |

### Phase 4: Production Hardening (Priority: P1)

| Step | File | Change |
|------|------|--------|
| 4.1 | `scripts/local-ddb-init.py` | Add `ByStateStartedAt` GSI to `MessageCallSessions` (partition: `state`, sort: `start_ts_sort`) for efficient server-side scans at scale |
| 4.2 | `app/services/messaging_call_sessions.py` | Add `list_call_sessions_by_state(state, start_ts_before)` query function using new GSI |
| 4.3 | `app/core/settings.py` | Add `messaging_webrtc_call_timeout_backstop_enabled` feature flag (default True) |

### Phase 5: Edge Cases & Polish (Priority: P2)

| Step | Description |
|------|-------------|
| 5.1 | Handle race condition: callee accepts at t=29.9s, client fires timeout at t=30s. The `_check_transition` will reject `invited -> missed` because the state is already `accepted`. The client timeout handler must catch `409 Conflict` and update local state to `connected` (not `timeout`). |
| 5.2 | Handle multiple devices: if callee has two active sessions, one might accept while the other shows ringing. The SSE `call.accept` event dismisses all callee ringing UIs. No special timeout handling needed. |
| 5.3 | Handle caller disconnect during ringing: if caller's network drops and the timer never fires, the server backstop catches it at next tick. The caller reconnects and sees `missed` state via GET `/calls/{id}`. |

---

## 5. Testing Strategy

### 5.1 Unit Tests (`tests/`)

#### 5.1.1 Lifecycle Tests

```python
# tests/test_messaging_call_lifecycle.py

def test_timeout_call_transitions_invited_to_missed():
    """timeout_call() on an invited call sets state=missed, end_reason=no_answer."""
    record, event = create_invite(...)
    updated, timeout_event = timeout_call(call_id=record.call_id, actor_user_id=caller_id)
    assert updated.state == "missed"
    assert updated.end_reason == "no_answer"
    assert updated.end_ts is not None
    assert timeout_event.event_type == "call.missed"
    assert timeout_event.to_state == "missed"

def test_timeout_call_rejected_if_already_accepted():
    """timeout_call() returns 409 if call is already accepted."""
    record, _ = create_invite(...)
    accept_invite(call_id=record.call_id, actor_user_id=callee_id)
    with pytest.raises(CallLifecycleError) as exc_info:
        timeout_call(call_id=record.call_id, actor_user_id=caller_id)
    assert exc_info.value.code == "invalid_state_transition"

def test_timeout_call_idempotent():
    """Second timeout_call() with same idempotency_key returns same result."""
    record, _ = create_invite(...)
    r1, e1 = timeout_call(call_id=record.call_id, actor_user_id=caller_id, idempotency_key="key1")
    r2, e2 = timeout_call(call_id=record.call_id, actor_user_id=caller_id, idempotency_key="key1")
    assert r1.state == r2.state == "missed"

def test_timeout_call_by_non_caller_forbidden():
    """Only the caller (or system) can timeout a call."""
    record, _ = create_invite(...)
    with pytest.raises(CallLifecycleError) as exc_info:
        timeout_call(call_id=record.call_id, actor_user_id=callee_id)
    assert exc_info.value.code == "forbidden"

def test_timeout_call_system_actor_allowed():
    """Server backstop uses actor_user_id='system' which should be allowed."""
    record, _ = create_invite(...)
    updated, event = timeout_call(call_id=record.call_id, actor_user_id="system")
    assert updated.state == "missed"
```

#### 5.1.2 Timeline Tests

```python
def test_missed_call_timeline_preview():
    """emit_call_timeline_event with call.missed produces 'Missed call' preview."""
    result = emit_call_timeline_event(
        call_id="c1", conversation_id="conv1", actor_user_id="u1",
        event_type="call.missed", call_state="missed", reason="no_answer",
    )
    assert result["text"] == "Missed call"
```

#### 5.1.3 Background Loop Tests

```python
def test_expire_stale_invites_transitions_old_calls():
    """Calls in 'invited' state older than timeout are transitioned to 'missed'."""
    # Create a call with start_ts 60 seconds ago
    record = create_call_session(
        call_id="c1", conversation_id="conv1",
        caller_user_id="caller", callee_user_id="callee",
        initial_mode="audio", state="invited",
        start_ts=now_ts() - 60,
    )
    _expire_stale_invites()
    updated = get_call_session("c1")
    assert updated.state == "missed"

def test_expire_stale_invites_skips_recent_calls():
    """Calls in 'invited' state within timeout window are not touched."""
    record = create_call_session(
        call_id="c2", conversation_id="conv1",
        caller_user_id="caller", callee_user_id="callee",
        initial_mode="audio", state="invited",
        start_ts=now_ts() - 5,  # Only 5 seconds old
    )
    _expire_stale_invites()
    updated = get_call_session("c2")
    assert updated.state == "invited"
```

### 5.2 API Integration Tests

```python
def test_timeout_endpoint_returns_missed_state(client, alice_session, bob_session):
    """POST /messages/calls/{id}/timeout transitions to missed."""
    # Alice creates invite to Bob
    resp = client.post("/ui/messages/calls/invite", json={...}, cookies=alice_session)
    call_id = resp.json()["call_id"]
    # Alice times out the call
    resp = client.post(f"/ui/messages/calls/{call_id}/timeout",
                       json={"reason": "no_answer"}, cookies=alice_session)
    assert resp.status_code == 200
    assert resp.json()["state"] == "missed"

def test_timeout_after_accept_returns_409(client, alice_session, bob_session):
    """POST /timeout after callee accepted returns 409 Conflict."""
    resp = client.post("/ui/messages/calls/invite", json={...}, cookies=alice_session)
    call_id = resp.json()["call_id"]
    client.post(f"/ui/messages/calls/{call_id}/accept", cookies=bob_session)
    resp = client.post(f"/ui/messages/calls/{call_id}/timeout", cookies=alice_session)
    assert resp.status_code == 409
```

### 5.3 E2E Tests (`frontend/e2e/`)

New file: `frontend/e2e/call-timeout.spec.ts`

```typescript
test.describe("Section 80: Call ringing timeout", () => {
  test("80.1 Outgoing call shows timeout UI after 30s with no answer", async ({ page }) => {
    // Inject Alice auth, navigate to DM with Bob
    // Initiate call (mock Bob never answering)
    // Fast-forward or use a short timeout override
    // Assert CallSessionOverlay shows "Call timed out with no answer."
  });

  test("80.2 Timeout call creates 'Missed call' timeline message", async ({ page, request }) => {
    // Create invite via API
    // Call timeout endpoint
    // Fetch messages for conversation
    // Assert system message with text "Missed call" exists
  });

  test("80.3 Callee receives missed call SSE and sees timeline event", async ({ page }) => {
    // Alice calls Bob, timeout fires
    // Bob's page receives call.missed SSE
    // Bob's conversation shows "Missed call" system message
  });

  test("80.4 Timeout is rejected if callee already accepted (race condition)", async ({ request }) => {
    // Create invite, accept, then try timeout
    // Assert 409 response
  });

  test("80.5 Server backstop catches calls where client timer failed", async ({ request }) => {
    // Create invite with start_ts in the past (> 30s ago)
    // Wait for background loop tick (or call internal endpoint)
    // Assert call state is now "missed"
  });

  test("80.6 Missed call does not block subsequent calls to same callee", async ({ request }) => {
    // Create invite, timeout it
    // Create a new invite to same callee
    // Assert success (no callee_busy error)
  });
});
```

### 5.4 State Machine Unit Tests (Frontend)

```typescript
// In a jest/vitest test file for callStateMachine.ts
describe("callStateReducer timeout handling", () => {
  it("transitions outgoing_ringing to timeout on REMOTE_DECLINE with reason=timeout", () => {
    const state = { ...createInitialCallMachineState(), phase: "outgoing_ringing" as const };
    const next = callStateReducer(state, { type: "REMOTE_DECLINE", reason: "timeout" });
    expect(next.phase).toBe("timeout");
    expect(next.reasonMessage).toBe("Call timed out with no answer.");
  });

  it("allows RESET from timeout phase", () => {
    const state = { ...createInitialCallMachineState(), phase: "timeout" as const };
    const next = callStateReducer(state, { type: "RESET" });
    expect(next.phase).toBe("idle");
  });
});
```

### 5.5 Metrics Verification

After implementation, verify via the `/metrics` endpoint:
- `webrtc_call_setup_total{outcome="failure", reason="timeout_no_answer"}` increments on timeout
- `webrtc_call_timeout_total{source="client"}` and `{source="server"}` distinguish timeout origin

### 5.6 Manual QA Checklist

1. Start a call, do not answer on callee device, verify timeout at 30s
2. Start a call, answer at 29s, verify call connects (no timeout)
3. Start a call, caller closes browser tab, verify server backstop triggers within 45s
4. Verify "Missed call" appears in both caller and callee conversation timelines
5. Verify callee receives push notification (if push is enabled) for missed call
6. Verify caller can immediately re-call after a missed call (no busy lock)
7. Verify `callTimeoutRef` is cleared on component unmount (no memory leak)
8. Test with configurable timeout (set env var to 10s, verify faster timeout)

---

## 6. Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│               Ringing Timeout & Missed Call Flow                    │
└─────────────────────────────────────────────────────────────────────┘

  Caller                        Server (SSE)                   Callee
    │                              │                              │
    │  POST /calls/initiate        │                              │
    │─────────────────────────────▶│                              │
    │                              │  SSE: call:incoming          │
    │  Start client timer (30s)    │──────────────────────────────▶│
    │                              │                              │
    │                              │  Start server timer (45s)    │
    │                              │                              │
    │  ... 30s elapses ...         │                              │
    │                              │                              │
    │  Client timer fires          │                              │
    │  POST /calls/{id}/cancel     │                              │
    │  reason="timeout_no_answer"  │                              │
    │─────────────────────────────▶│                              │
    │                              │  SSE: call:cancelled         │
    │                              │──────────────────────────────▶│
    │                              │  Cancel server timer         │
    │                              │  Write missed_call record    │
    │                              │  SSE: call:missed            │
    │                              │──────────────────────────────▶│
    │                              │                              │
    │  Show "No answer" UI         │              Show "Missed call"
    │                              │                              │

  Server Backstop (if client fails to cancel):
    │                              │
    │  ... 45s elapses ...         │
    │                              │  Server timer fires
    │                              │  Force-cancel call
    │  SSE: call:cancelled         │  Write missed_call
    │◀──────────────────────────── │──────────────────────────────▶│
```

---

## 7. DynamoDB Access Patterns

| Access Pattern | Table | PK | SK | Notes |
|----------------|-------|----|----|-------|
| Create active call | `calls` | `CALL#{call_id}` | `META` | status=ringing, created_at=now |
| Timeout call | `calls` | `CALL#{call_id}` | `META` | Conditional: status=ringing; SET status=missed |
| Write missed call record | `call_events` | `USER#{callee_id}` | `MISSED#{ts}` | caller_id, call_id, duration=0 |
| List missed calls | `call_events` | `USER#{user_id}` | begins_with `MISSED#` | Newest first |
| Cancel server timer | `call_timers` | `CALL#{call_id}` | `TIMEOUT` | Delete on answer/cancel |

---

## 8. Error Handling Matrix

| Error Scenario | Behavior | User-Facing Message | Recovery Action |
|----------------|----------|---------------------|-----------------|
| Client timer fires but server already answered | Client cancel returns 409; ignore | No message (call connected) | Auto-resolve; call continues |
| Server timer fires but client already cancelled | Server cancel is idempotent | No extra message | No action needed |
| Both timers fire simultaneously | Conditional update on call status; first write wins | "No answer" shown once | Idempotent; no conflict |
| Network failure during timeout | Client-side timer still fires; offline cancel queued | "Call timed out" (optimistic) | Sync on reconnect |
| Callee answers at exactly 30s | Answer POST races with cancel POST; answer wins if first | Call connects | Server resolves race |
| Call cancelled before timeout | Clear client timer; clear server timer | "Call cancelled" | Normal flow |

---

## 9. Performance Considerations

| Concern | Mitigation |
|---------|-----------|
| Timer accuracy (30s client) | `setTimeout` with drift check; re-fire if < 29s elapsed |
| Server timer resource leak | DDB TTL on call_timers (60s); cron cleanup for orphans |
| Missed call notification fan-out | Single SSE event per callee; no fan-out needed |
| Concurrent calls to same callee | Each call has independent timers; no interference |
| Memory leak from unmounted timers | Clear `callTimeoutRef` in `useEffect` cleanup |

---

## 10. Rollout Plan

| Flag | Default | Description |
|------|---------|-------------|
| `CALL_RINGING_TIMEOUT_ENABLED` | `true` | Enable client-side timeout |
| `CALL_SERVER_BACKSTOP_ENABLED` | `true` | Enable server-side timeout backup |
| `CALL_TIMEOUT_SECONDS` | `30` | Configurable timeout duration |
| `CALL_SERVER_BACKSTOP_SECONDS` | `45` | Server backup timeout |

### Canary

1. **Week 1**: Deploy with defaults (30s/45s). Monitor timeout vs answer rates.
2. **Week 2**: Adjust timeout if miss rate is too high (increase to 45s/60s).
3. **Week 3**: Verify missed call notifications and UI in all clients.

---

## 11. Expanded E2E Test Details

### Additional Edge Cases (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| E1 | Answer at 29.9 seconds | Call connects; no timeout; no missed call |
| E2 | Caller disconnects during ringing | Server backstop fires; callee sees missed call |
| E3 | Multiple rapid call/timeout cycles | Each creates independent missed call records |
| E4 | Timeout with push notification enabled | Push notification sent with "Missed call from {name}" |

### Negative Tests (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| N1 | Cancel non-existent call | POST cancel with bad call_id; 404 |
| N2 | Timeout already-answered call | Server timeout on answered call; no-op; call continues |
| N3 | Invalid timeout configuration | Set CALL_TIMEOUT_SECONDS=0; 422 on config update |
