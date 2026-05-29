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

## Testing Strategy

### Unit Tests (pytest)

**Test file**: `tests/test_call_7.py`

**Mock setup**: moto mock for DynamoDB (call session tables). Mock RTCPeerConnection for frontend unit tests. Chromium fake media devices for E2E.

| Test Function | Description |
|---|---|
| `test_create_resource` | Create primary resource; verify stored correctly |
| `test_lifecycle_transitions` | Verify allowed state transitions succeed |
| `test_invalid_transition_rejected` | Invalid transition returns 409 |
| `test_authorization_check` | Non-participant returns 403 |
| `test_idempotent_operation` | Repeated call returns same result |
| `test_cleanup_on_end` | Resources cleaned up after call ends |

### Integration Tests

Cross-service tests with real DynamoDB Local:

1. Full call lifecycle through real DDB (invite -> accept -> connect -> end)
2. Signaling relay: offer/answer/ICE exchange between two sessions
3. State machine transitions verified end-to-end

### E2E Tests (Playwright)

**Test file**: `frontend/e2e/call-7.spec.ts`

**Auth pattern**: `injectAuth(page, "alice")` for caller; `injectAuth(page, "bob")` for callee; separate browser contexts for two-peer tests

| # | Test Name | Assertion |
|---|---|---|
| 1 | Call invite creates session | POST invite -> 200 with call_id |
| 2 | Call accept transitions state | POST accept -> state = accepted |
| 3 | Signaling relay delivers events | POST signal -> SSE event received by peer |
| 4 | Connected state shows overlay | Both peers reach connected; overlay visible |
| 5 | End call cleans up resources | POST end -> state = ended; tracks stopped |
| 6 | Call overlay shows correct UI | Ringing/connected/ended states render correctly |
| 7 | Feature flag gates functionality | Disabled flag -> call button hidden |
| 8 | Unauthenticated returns 401 | No session -> 401 |
| 9 | Non-participant returns 403 | Third party -> 403 |
| 10 | Non-existent call returns 404 | Invalid call_id -> 404 |
| 11 | Invalid transition returns 409 | End already-ended call -> 409 |

**Negative tests**: 401 unauthenticated, 403 non-participant, 404 non-existent call, 409 invalid transition, 422 invalid payload

**Edge cases**: Concurrent accept/decline, call timeout (30s), ICE restart during connected state, tab backgrounding, network offline

### Test Data Requirements

Create DM conversation between Alice and Bob in `beforeAll`. Use `--use-fake-device-for-media-stream` Chromium flag for media tests.

**Test users**: Alice (USER, caller), Bob (USER, callee), Root (ROOT, admin for feature flags)

### CI/Pipeline

Serial execution (WebRTC requires sequential peer setup). `VITE_MESSAGING_WEBRTC_DIRECT_CALL_ENABLED=true`. Retry-safe.

---

## Dependencies & Merge Safety

### Depends On

| Ticket | What's Needed | Status | Can Overlap? |
|---|---|---|---|
| CALL-001 | Call lifecycle endpoints (invite/accept/decline/end) | Implemented | Yes |

### Depended On By

No downstream dependents identified.

### Merge Strategy

Independent. Backend timeout function + frontend timer. Parallel-safe with CALL-002 through CALL-006.

### Merge Checklist

- [ ] Backend endpoint/service changes registered in `app/main.py`
- [ ] Frontend hooks and components created/modified
- [ ] Settings and feature flags configured
- [ ] DDB tables added if needed (`scripts/local-ddb-init.py`)
- [ ] E2E tests pass in CI
- [ ] No breaking changes to existing call endpoints

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
