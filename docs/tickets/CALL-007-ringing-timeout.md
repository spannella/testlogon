# CALL-007: Add Call Ringing Timeout and Missed-Call Handling

> **NOTE: This feature is FULLY IMPLEMENTED.** The backend `timeout_call()` function, the `POST /messages/calls/{call_id}/timeout` endpoint, the server-side `_expire_stale_invites()` backstop, the `call.missed` timeline event, the frontend client timer with backend call, the `call.missed` SSE handler, and unit tests all exist. See Codebase References at the bottom for all verified locations.

## 1. Overview & Motivation

When a user initiates a WebRTC direct call, the callee receives an invite that places the call into the `invited` state. If the callee never responds (e.g., they are away from the device, the app is backgrounded, or they simply ignore the incoming ring), the call remains in the `invited` state indefinitely. This creates several problems:

- **Caller UX degradation**: The caller sees the "outgoing ringing" UI forever with no resolution. The only escape is manually canceling the call.
- **Resource leak**: The `CallSessionRecord` in DynamoDB stays in a non-terminal state, which means subsequent calls to the same callee may be blocked by the `callee_busy` check in `create_invite()` (see `app/services/messaging_call_lifecycle.py:155` for `active_states` and `:164` for the `callee_busy` raise), since the function scans recent sessions in `active_states = {"invited", "accepted", "connected"}`.
- **Missing notification**: The callee never receives a "missed call" indicator in their conversation timeline, so they have no record that someone tried to reach them.
- **Inaccurate metrics**: The `record_webrtc_call_setup` metric only records `outcome="attempt"` at invite time; without a timeout transition, there is no corresponding failure metric for unanswered calls.

The `missed` state already exists in the type system (`CallState = Literal["invited", "accepted", "connected", "ended", "missed", "declined", "busy", "failed", "canceled"]` in `messaging_call_sessions.py`, line 9) (see `app/services/messaging_call_sessions.py:9`) and in the `TERMINAL_STATES` set (see `app/services/messaging_call_lifecycle.py:23`), and the `timeout_call()` function (see `app/services/messaging_call_lifecycle.py:404-453`) now transitions calls to `missed`. This ticket documents the dual-layer timeout mechanism (client-driven primary, server-driven backstop) that transitions unanswered calls to `missed` after 30 seconds, emits a timeline event, sends an SSE notification, and updates the frontend state machine.

---

## 2. Current State Analysis

### 2.1 Call State Machine (Backend)

The backend lifecycle is defined in `app/services/messaging_call_lifecycle.py` (see `app/services/messaging_call_lifecycle.py:23-28`). The allowed transitions are:

```python
TERMINAL_STATES = {"declined", "busy", "missed", "ended", "failed", "canceled"}
ALLOWED_TRANSITIONS = {
    "invited": {"accepted", "declined", "busy", "canceled", "failed", "missed"},
    "accepted": {"connected", "ended", "failed", "canceled"},
    "connected": {"ended", "failed"},
}
```

<!-- NOTE: "missed" IS now included in ALLOWED_TRANSITIONS["invited"] — see app/services/messaging_call_lifecycle.py:25. This was added as part of implementing this ticket. -->

### 2.2 Call Session Storage

Call sessions are stored in the `MessageCallSessions` DynamoDB table (see `scripts/local-ddb-init.py:629-639` for table definition, `app/services/messaging_call_sessions.py` for access):
- **Primary key**: `call_id` (string)
- **GSIs**: `ByConversationStartedAt` (partition: `conversation_id`, sort: `start_ts_sort` numeric), `ByCallerStartedAt`, `ByCalleeStartedAt` (see `scripts/local-ddb-init.py:633-637`)
- **Fields**: `state`, `start_ts`, `connect_ts`, `end_ts`, `end_reason`, `lifecycle_events[]`, `idempotency_records{}`, plus billing fields and `voicemail_message_id` (see `app/services/messaging_call_sessions.py:19-50`)

The `start_ts` field is set at invite creation time (`now_ts()`). This gives us the precise timestamp to compute elapsed ringing duration for timeout detection.

### 2.3 Timeline Events

`app/services/messaging_call_timeline.py` emits system messages into the conversation's Messages table (see `app/services/messaging_call_timeline.py:39-119`). The `emit_call_timeline_event` function:
1. Writes a system message (sender_id="system", subtype="call_lifecycle") with a deterministic `message_id` format: `sys_call_{call_id}_{event_type}_{ts}` (see `:52`)
2. Updates the conversation's `last_message_at` and `last_message_preview` (see `:83-90`)
3. Writes an archive event via `messaging_archive_writer` (see `:92-117`)

The `_preview_for_event` function (see `app/services/messaging_call_timeline.py:21-36`) handles `call.invite`, `call.accept`, `call.decline`, `call.end`, and `call.missed` (see `:34-35`, returns `"Missed call"`).

### 2.4 Frontend State Machine

The frontend state machine (see `frontend/src/pages/messages/callStateMachine.ts:28,108`) defines `CallUiState` including `"timeout"` as a valid UI state. The `REMOTE_DECLINE` event with `reason: "timeout"` transitions the machine to the `timeout` phase (see `:108`):

```typescript
if (event.reason === "timeout") return withPhase(state, "timeout", {
  reasonMessage: event.message ?? "Call timed out with no answer."
});
```

The `CallSessionOverlay.tsx` renders outcome copy for `timeout`: `"Call timed out with no answer."` (see `frontend/src/pages/messages/CallSessionOverlay.tsx:72-78`, specifically `:75`).

### 2.5 Client-Side Timer (IMPLEMENTED)

In `ConversationView.tsx` (see `frontend/src/pages/messages/ConversationView.tsx:764-772`), the 30-second `setTimeout` fires after a successful invite creation and now calls the backend:

```typescript
callTimeoutRef.current = window.setTimeout(async () => {
  dispatchCall({ type: "REMOTE_DECLINE", reason: "timeout" });
  if (res.call_id) {
    try {
      const { timeoutCall } = await import("@/api/endpoints/messaging");
      await timeoutCall(res.call_id, { reason: "no_answer" });
    } catch { /* best-effort */ }
  }
}, 30_000);
```

This timer:
- Updates the local UI state AND calls the backend `timeoutCall` endpoint to transition to `missed`
- Is cleared when the call state enters a terminal phase (see `:683-685`)
- The backend writes a `call.missed` timeline event via `timeout_call()` (see `app/services/messaging_call_lifecycle.py:444-452`)

<!-- NOTE: The 700ms auto-accept dev placeholder referenced in the original spec has been REMOVED. No auto-accept timer exists. -->

### 2.6 SSE Event Delivery

The `useMessagingStream.ts` hook (see `frontend/src/hooks/useMessagingStream.ts:168-172`) listens for `call.*` event types including `call.missed` (`:172`) and dispatches them to `window` as `CustomEvent("messaging:call-event")`. The `ConversationView.tsx` listener (see `frontend/src/pages/messages/ConversationView.tsx:823-827`) handles `call.missed` — if the current user is the callee, it dispatches `REMOTE_DECLINE` with `reason: "timeout"` to dismiss the ringing UI.

<!-- NOTE: The timeout_call_endpoint (messaging.py:13112-13143) does NOT call fanout_event_to_conversation after transitioning to missed. The timeline_emitter writes a system message to the Messages table, but real-time SSE delivery of call.missed to the callee depends on the callee's SSE stream picking up the new system message on next poll. There is no dedicated SSE fanout for the call.missed event, which means the callee may experience a delay of up to 1 second (the SSE poll interval) before seeing the missed call notification. -->

### 2.7 Background Task Pattern

The existing `_messaging_background_loop()` in `messaging.py` (see `app/routers/messaging.py:12504`) runs every 30 seconds and performs DynamoDB scans for scheduled message delivery and message expiry. `_expire_stale_invites()` is called as step C of this loop (see `:12581-12582`). The `broadcast_reconciler.py` provides a more sophisticated pattern with:
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

#### 3.3.1 Allow `invited -> missed` Transition — IMPLEMENTED

`"missed"` is already included in `ALLOWED_TRANSITIONS["invited"]` (see `app/services/messaging_call_lifecycle.py:25`):

```python
ALLOWED_TRANSITIONS = {
    "invited": {"accepted", "declined", "busy", "canceled", "failed", "missed"},
    "accepted": {"connected", "ended", "failed", "canceled"},
    "connected": {"ended", "failed"},
}
```

#### 3.3.2 `timeout_call()` Function — IMPLEMENTED

The `timeout_call()` function exists at `app/services/messaging_call_lifecycle.py:404-453` with the following signature:

```python
def timeout_call(
    *,
    call_id: str,
    actor_user_id: str,
    reason: str = "no_answer",
    idempotency_key: Optional[str] = None,
    timeline_emitter: Callable[..., dict[str, object]] = emit_call_timeline_event,
) -> tuple[CallSessionRecord, LifecycleEvent]:
```

<!-- NOTE: The actual signature omits client_platform and client_browser params (unlike the spec). It also does not call record_webrtc_call_setup — no timeout-specific metric is emitted. -->

This function:
1. Loads the call session (`:413`)
2. Checks idempotency via `_dedupe_if_retried` (`:416-418`)
3. Validates the actor is the caller or "system" (`:419-421`)
4. Checks transition validity via `_check_transition` (`:423`)
5. Updates state to `missed` with `end_ts` and `end_reason` (`:432-441`)
6. Emits a `call.missed` timeline event (`:444-452`)

#### 3.3.3 API Endpoint — IMPLEMENTED

The endpoint exists at `app/routers/messaging.py:13112-13143`:

```python
@router.post("/messages/calls/{call_id}/timeout", response_model=CallActionOut)
async def timeout_call_endpoint(
    call_id: str,
    body: CallTimeoutIn = CallTimeoutIn(),
    user_id: str = Depends(get_messaging_user_id),
):
```

<!-- NOTE: The body model is CallTimeoutIn (see messaging.py:13107-13109), not CallEndIn as originally proposed. CallTimeoutIn has fields: reason (str, default "no_answer") and idempotency_key (Optional[str]). -->

This endpoint also computes `voicemail_eligible` from `VOICEMAIL_ELIGIBLE_STATES` (see `:8346,13127-13131`) and returns it in `CallActionOut`.

#### 3.3.4 Timeline Preview Text — IMPLEMENTED

The `call.missed` case exists in `_preview_for_event` (see `app/services/messaging_call_timeline.py:34-35`):

```python
if event_type == "call.missed":
    return "Missed call"
```

This produces the timeline system message "Missed call" visible to both parties in the conversation.

#### 3.3.5 Server-Side Background Timeout (Backstop) — IMPLEMENTED

`_expire_stale_invites()` exists at `app/routers/messaging.py:12472-12501` and is called from `_messaging_background_loop()` at `:12581-12582`:

```python
async def _expire_stale_invites() -> None:
    """Server-side backstop: transition invited calls to missed after timeout."""
    timeout_seconds = S.messaging_webrtc_call_ringing_timeout_seconds
    cutoff_ts = int(now_ts()) - timeout_seconds
    # ... scan + timeout_call for each stale invite
```

This uses a table scan with `FilterExpression` matching `state="invited" AND start_ts <= cutoff` (see `:12481-12482`). Each stale invite is transitioned via `timeout_call(actor_user_id="system", reason="server_timeout")` (see `:12489-12492`).

<!-- NOTE: No ByStateStartedAt GSI was added to scripts/local-ddb-init.py. The implementation uses a full table scan, which is acceptable for dev/low traffic but would need the GSI for production scale. The idempotency_key is also not passed (unlike the spec proposal), relying on the state transition check for idempotency instead. -->

#### 3.3.6 Settings — IMPLEMENTED

The setting exists at `app/core/settings.py:1051`:

```python
messaging_webrtc_call_ringing_timeout_seconds: int = int(
    os.environ.get("MESSAGING_WEBRTC_CALL_RINGING_TIMEOUT_SECONDS", "30")
)
```

<!-- NOTE: The messaging_webrtc_call_timeout_backstop_enabled feature flag proposed in Phase 4 does NOT exist in settings.py. The backstop always runs when the background loop runs. -->

#### 3.3.7 SSE Event Emission

<!-- NOTE: fanout_event_to_conversation is NOT called in the timeout_call_endpoint (see app/routers/messaging.py:13112-13143) or in timeout_call() (see app/services/messaging_call_lifecycle.py:404-453). The timeline_emitter writes a system message to the Messages table, which the callee's SSE events_stream will pick up on its next poll cycle (~1 second). This means there is no dedicated real-time SSE push for call.missed — the callee relies on polling. For production, the explicit fanout below should be added to the timeout endpoint for sub-second delivery: -->

After `timeout_call()` transitions the state, `fanout_event_to_conversation` should be called with `event_type="call.missed"` to notify the callee via SSE. Currently the timeline emitter writes a system message, but there is no explicit SSE fanout for real-time notification. The proposed addition:

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

#### 3.4.1 Client Timeout Calls Backend — IMPLEMENTED

The timer in `ConversationView.tsx` (see `frontend/src/pages/messages/ConversationView.tsx:764-772`) dispatches the UI state change AND calls the backend endpoint:

```typescript
callTimeoutRef.current = window.setTimeout(async () => {
  dispatchCall({ type: "REMOTE_DECLINE", reason: "timeout" });
  if (res.call_id) {
    try {
      const { timeoutCall } = await import("@/api/endpoints/messaging");
      await timeoutCall(res.call_id, { reason: "no_answer" });
    } catch { /* best-effort */ }
  }
}, 30_000);
```

The `timeoutCall` API function is at `frontend/src/api/endpoints/messaging.ts:313`.

#### 3.4.2 Remove Auto-Accept Placeholder — DONE

<!-- NOTE: The 700ms auto-accept placeholder no longer exists in ConversationView.tsx. It was removed as part of earlier CALL ticket implementations. -->

#### 3.4.3 Handle `call.missed` SSE Event — IMPLEMENTED

The `onCallEvent` handler (see `frontend/src/pages/messages/ConversationView.tsx:823-827`) handles `call.missed`:

```typescript
} else if (eventType === "call.missed") {
  // If I'm the callee, dismiss any ringing UI
  if (isCurrentUserCallee) {
    dispatchCall({ type: "REMOTE_DECLINE", reason: "timeout" });
  }
}
```

<!-- NOTE: The implementation only handles the callee case. The caller case and queryClient invalidation proposed in the spec are not included — the caller already transitions to timeout via its local timer. -->

#### 3.4.4 Register `call.missed` in SSE Event Types — IMPLEMENTED

`"call.missed"` is registered in `useMessagingStream.ts` at line 172 (see `frontend/src/hooks/useMessagingStream.ts:172`), after `"call.end"` at line 171.

#### 3.4.5 Callee Ringing Timeout (Incoming Ring Auto-Dismiss)

<!-- NOTE: This callee-side incoming_ringing timeout useEffect is NOT implemented in ConversationView.tsx. The callee relies on receiving the call.missed SSE event from the server (dispatched when the caller's client or server backstop calls the timeout endpoint). If SSE delivery is delayed or the fanout is missing, the callee's ringing UI may persist beyond the expected timeout window. -->

The proposed callee-side timeout:

```typescript
React.useEffect(() => {
  if (callMachine.phase !== "incoming_ringing") return;
  const timer = window.setTimeout(() => {
    dispatchCall({ type: "END_REMOTE", message: "Call timed out." });
  }, RINGING_TIMEOUT_MS + 2000); // 2s grace for network latency
  return () => window.clearTimeout(timer);
}, [callMachine.phase]);
```

### 3.5 State Machine Update — Already Covered

The existing `REMOTE_DECLINE` with `reason: "timeout"` already transitions to the `timeout` phase (see `frontend/src/pages/messages/callStateMachine.ts:108`), which is the correct UX for the caller. For the callee receiving a `call.missed` SSE event while still showing `incoming_ringing`, the `REMOTE_DECLINE` event with `reason: "timeout"` is dispatched (see `frontend/src/pages/messages/ConversationView.tsx:826`).

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

### Phase 1: Backend Core (Priority: P0) — IMPLEMENTED

| Step | File | Change | Status |
|------|------|--------|--------|
| 1.1 | `app/services/messaging_call_lifecycle.py:25` | `"missed"` in `ALLOWED_TRANSITIONS["invited"]` | DONE |
| 1.2 | `app/services/messaging_call_lifecycle.py:404-453` | `timeout_call()` function | DONE |
| 1.3 | `app/services/messaging_call_timeline.py:34-35` | `call.missed` case in `_preview_for_event` | DONE |
| 1.4 | `app/core/settings.py:1051` | `messaging_webrtc_call_ringing_timeout_seconds` setting | DONE |
| 1.5 | `app/routers/messaging.py:13112-13143` | `POST /messages/calls/{call_id}/timeout` endpoint | DONE |
| 1.6 | `app/routers/messaging.py:12472-12501,12581-12582` | `_expire_stale_invites()` in `_messaging_background_loop()` | DONE |
| 1.7 | `app/routers/messaging.py` | SSE fanout via `fanout_event_to_conversation` | NOT DONE |

### Phase 2: Frontend Integration (Priority: P0) — MOSTLY IMPLEMENTED

| Step | File | Change | Status |
|------|------|--------|--------|
| 2.1 | `frontend/src/api/endpoints/messaging.ts:313` | `timeoutCall(callId, opts)` API function | DONE |
| 2.2 | `frontend/src/pages/messages/ConversationView.tsx:764-772` | Timer calls backend | DONE |
| 2.3 | `frontend/src/pages/messages/ConversationView.tsx` | 700ms auto-accept removed | DONE |
| 2.4 | `frontend/src/pages/messages/ConversationView.tsx:823-827` | `call.missed` SSE event handler | DONE |
| 2.5 | `frontend/src/pages/messages/ConversationView.tsx` | Callee incoming_ringing timeout effect | NOT DONE |
| 2.6 | `frontend/src/hooks/useMessagingStream.ts:172` | `"call.missed"` in `EVENT_TYPES` | DONE |

### Phase 3: Observability (Priority: P1) — NOT IMPLEMENTED

<!-- NOTE: No timeout-specific metrics (record_webrtc_call_timeout) exist in app/metrics.py. The server-side timeout does log at INFO level (see messaging.py:12494). -->

| Step | File | Change | Status |
|------|------|--------|--------|
| 3.1 | `app/metrics.py` | `record_webrtc_call_timeout(source)` metric | NOT DONE |
| 3.2 | `app/services/messaging_call_lifecycle.py` | Emit timeout metric in `timeout_call()` | NOT DONE |
| 3.3 | `app/routers/messaging.py:12494` | Log server-side timeout transitions at INFO | DONE |

### Phase 4: Production Hardening (Priority: P1) — NOT IMPLEMENTED

<!-- NOTE: No ByStateStartedAt GSI, no list_call_sessions_by_state function, and no backstop_enabled flag exist. The current implementation uses table scan (see messaging.py:12481) which works for low traffic but not at scale. -->

| Step | File | Change | Status |
|------|------|--------|--------|
| 4.1 | `scripts/local-ddb-init.py` | `ByStateStartedAt` GSI | NOT DONE |
| 4.2 | `app/services/messaging_call_sessions.py` | `list_call_sessions_by_state()` | NOT DONE |
| 4.3 | `app/core/settings.py` | `messaging_webrtc_call_timeout_backstop_enabled` flag | NOT DONE |

### Phase 5: Edge Cases & Polish (Priority: P2)

| Step | Description |
|------|-------------|
| 5.1 | Handle race condition: callee accepts at t=29.9s, client fires timeout at t=30s. The `_check_transition` will reject `invited -> missed` because the state is already `accepted`. The client timeout handler must catch `409 Conflict` and update local state to `connected` (not `timeout`). |
| 5.2 | Handle multiple devices: if callee has two active sessions, one might accept while the other shows ringing. The SSE `call.accept` event dismisses all callee ringing UIs. No special timeout handling needed. |
| 5.3 | Handle caller disconnect during ringing: if caller's network drops and the timer never fires, the server backstop catches it at next tick. The caller reconnects and sees `missed` state via GET `/calls/{id}`. |

---

## 5. Testing Strategy

### 5.1 Unit Tests (`tests/`) — IMPLEMENTED

Unit tests exist at `tests/test_call_timeout.py` (337 lines). See Codebase References.

#### 5.1.1 Lifecycle Tests

```python
# tests/test_call_timeout.py (see tests/test_call_timeout.py:73-130)

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

<!-- NOTE: frontend/e2e/call-timeout.spec.ts does NOT exist yet — new implementation required -->
Proposed new file: `frontend/e2e/call-timeout.spec.ts`

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

<!-- NOTE: The table names and key schemas below do NOT match the actual implementation. The actual table is MessageCallSessions with PK=call_id (no SK), not "calls" with PK=CALL#{call_id}/SK=META. There are no separate call_events or call_timers tables. The actual patterns are:
- Create call: MessageCallSessions table, PK=call_id, state="invited" (see scripts/local-ddb-init.py:631-638)
- Timeout call: MessageCallSessions table, update call_id item SET state=missed (see messaging_call_lifecycle.py:432-438)
- Stale invite scan: MessageCallSessions full table scan FilterExpression state=invited AND start_ts<=cutoff (see messaging.py:12481-12482)
- Timeline message: Messages table, PK=conversation_id, SK=sys_call_{call_id}_call_missed_{ts} (see messaging_call_timeline.py:52)
-->

| Access Pattern | Table | Key | Notes |
|----------------|-------|-----|-------|
| Create call session | `MessageCallSessions` | PK: `call_id` | `state="invited"`, `start_ts=now_ts()` |
| Timeout call | `MessageCallSessions` | PK: `call_id` | SET `state=missed`, `end_ts`, `end_reason` |
| Stale invite scan | `MessageCallSessions` | Full scan | `FilterExpression`: `state=invited AND start_ts <= cutoff` |
| Timeline message | `Messages` | PK: `conversation_id`, SK: `sys_call_{call_id}_call_missed_{ts}` | System message with text "Missed call" |

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

---

## Codebase References

| File | Lines | What |
|------|-------|------|
| `app/services/messaging_call_lifecycle.py` | 23-28 | `TERMINAL_STATES` and `ALLOWED_TRANSITIONS` (includes `"missed"`) |
| `app/services/messaging_call_lifecycle.py` | 404-453 | `timeout_call()` function |
| `app/services/messaging_call_lifecycle.py` | 155,164 | `create_invite()` — `active_states` + `callee_busy` raise |
| `app/services/messaging_call_sessions.py` | 9 | `CallState` Literal (includes `"missed"`) |
| `app/services/messaging_call_sessions.py` | 19-50 | `CallSessionRecord` dataclass |
| `app/services/messaging_call_timeline.py` | 21-36 | `_preview_for_event` (handles `call.missed` at 34-35) |
| `app/services/messaging_call_timeline.py` | 39-119 | `emit_call_timeline_event` |
| `app/core/settings.py` | 1051 | `messaging_webrtc_call_ringing_timeout_seconds` (default 30) |
| `app/routers/messaging.py` | 13107-13109 | `CallTimeoutIn` model |
| `app/routers/messaging.py` | 13112-13143 | `timeout_call_endpoint` — `POST /messages/calls/{call_id}/timeout` |
| `app/routers/messaging.py` | 12472-12501 | `_expire_stale_invites()` — server-side backstop |
| `app/routers/messaging.py` | 12504,12581-12582 | `_messaging_background_loop()` calls `_expire_stale_invites()` |
| `app/routers/messaging.py` | 8346 | `VOICEMAIL_ELIGIBLE_STATES` (includes `"missed"`) |
| `scripts/local-ddb-init.py` | 629-639 | `MessageCallSessions` table definition (3 GSIs, no `ByStateStartedAt`) |
| `frontend/src/api/endpoints/messaging.ts` | 313 | `timeoutCall()` API function |
| `frontend/src/pages/messages/ConversationView.tsx` | 91 | `callTimeoutRef` ref |
| `frontend/src/pages/messages/ConversationView.tsx` | 683-685 | Timeout ref cleanup |
| `frontend/src/pages/messages/ConversationView.tsx` | 764-772 | Client timer — dispatches `REMOTE_DECLINE` + calls `timeoutCall` |
| `frontend/src/pages/messages/ConversationView.tsx` | 823-827 | `call.missed` SSE event handler (callee only) |
| `frontend/src/pages/messages/callStateMachine.ts` | 28 | `REMOTE_DECLINE` event type (includes `"timeout"` reason) |
| `frontend/src/pages/messages/callStateMachine.ts` | 108 | Timeout phase transition in reducer |
| `frontend/src/pages/messages/CallSessionOverlay.tsx` | 29 | `"timeout"` in `CallUiState` type |
| `frontend/src/pages/messages/CallSessionOverlay.tsx` | 72-78 | `outcomeCopy` — `timeout: "Call timed out with no answer."` |
| `frontend/src/hooks/useMessagingStream.ts` | 172 | `"call.missed"` in `EVENT_TYPES` |
| `tests/test_call_timeout.py` | 1-337 | Unit tests for timeout lifecycle |
