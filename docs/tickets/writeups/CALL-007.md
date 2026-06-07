# CALL-007: Add Call Ringing Timeout and Missed-Call Handling — Investigation & Implementation Write-up

## 1. Summary & Classification

When a WebRTC call invite is created, the callee's device is placed in the `invited` state. Without a timeout mechanism, a callee who never answers leaves the call session permanently non-terminal: the caller sees a ringing UI that never resolves, the `CallSessionRecord` in DynamoDB blocks subsequent `callee_busy` checks (which scan `active_states = {"invited", "accepted", "connected"}`), and no "Missed call" entry appears in the conversation timeline. This ticket implements a dual-layer timeout — a client-driven 30-second timer that calls a backend endpoint, backed by a server-side scan-and-expire loop — to transition unanswered calls to `missed`, emit a timeline event, and dispatch SSE notifications to both parties.

**Type**: Feature / UX hardening
**Priority**: P0 (blocks all call feature work; resource-leak and bad-UX)
**Status**: Substantially implemented; two gaps remain (SSE fanout for `call.missed`, callee-side incoming timer)
**Owning area**: Messaging / WebRTC calls
**Cross-references**: CALL-001 (base lifecycle), CALL-002 (RTCPeerConnection), CALL-008 (depends on ICE restart for reconnect flows), SECOPS-007 (dev/prod parity — feature-flag-selected paths, no `dev_mode`-only code)

---

## 2. Current-State Investigation

### 2.1 State Machine and Transition Table

`app/services/messaging_call_lifecycle.py:23-28` defines `TERMINAL_STATES` and `ALLOWED_TRANSITIONS`. The `"missed"` state is present in both `TERMINAL_STATES` (`:23`) and `ALLOWED_TRANSITIONS["invited"]` (`:25`), so the transition `invited → missed` is already legal and guarded by `_check_transition`. The `CallState` Literal type in `app/services/messaging_call_sessions.py:9` includes `"missed"`.

### 2.2 `timeout_call()` Service Function

`app/services/messaging_call_lifecycle.py:404-453` implements `timeout_call()`. Its steps:
1. Loads the session via `get_call_session(call_id)` (`:413`).
2. Deduplicates retried requests with `_dedupe_if_retried` (`:416-418`).
3. Enforces authorization: actor must be the `caller_user_id` or the literal string `"system"` (`:419-421`).
4. Validates the `invited → missed` transition via `_check_transition(record.state, "missed")` (`:423`).
5. Calls `update_call_session_state` with `state="missed"`, `end_reason`, and `end_ts` (`:432-441`).
6. Emits a `call.missed` timeline event via `emit_call_timeline_event` (`:444-452`).

The function does **not** call `fanout_event_to_conversation` — there is no dedicated SSE push for `call.missed`. The callee only learns of the transition when the SSE poll cycle (approximately 1 second) picks up the new system message written to the Messages table.

### 2.3 Timeline Preview Text

`app/services/messaging_call_timeline.py:34-35` handles `call.missed` in `_preview_for_event`, returning the string `"Missed call"`. This is written as a system message into the conversation timeline by `emit_call_timeline_event` (`:45-119`), which sets a deterministic `message_id` of the form `sys_call_{call_id}_{event_type}_{ts}` (`:52`) and updates `last_message_at` / `last_message_preview` on the conversation record (`:83-90`).

### 2.4 API Endpoint

`app/routers/messaging.py:14028-14059` defines `POST /messages/calls/{call_id}/timeout`. The model `CallTimeoutIn` (`:14023-14025`) carries `reason` (default `"no_answer"`) and optional `idempotency_key`. The handler calls `timeout_call()`, checks `VOICEMAIL_ELIGIBLE_STATES` for the post-miss voicemail gate (`:14043-14048`), and returns a `CallActionOut`. No `fanout_event_to_conversation` call is present in this handler.

### 2.5 Server-Side Backstop

`app/routers/messaging.py:13318-13347` implements `_expire_stale_invites()`. It performs a full table scan of `T.message_call_sessions` filtered on `state="invited" AND start_ts <= cutoff_ts` (`:13327-13329`), then calls `timeout_call(actor_user_id="system", reason="server_timeout")` for each hit (`:13335-13342`). The function is invoked from `_messaging_background_loop()` (`:13428`), which runs on a 30-second cycle.

The scan approach is functional at dev/low-traffic scale but does not scale to production without a GSI. No `ByStateStartedAt` GSI exists in `scripts/local-ddb-init.py:629-639`; the table has only three GSIs (`ByConversationStartedAt`, `ByCallerStartedAt`, `ByCalleeStartedAt`).

### 2.6 Settings

`app/core/settings.py:1149` defines `messaging_webrtc_call_ringing_timeout_seconds` (default 30, configurable via `MESSAGING_WEBRTC_CALL_RINGING_TIMEOUT_SECONDS`). No enable/disable flag for the backstop exists; it always runs with the background loop.

### 2.7 Client-Side Timer

`frontend/src/pages/messages/ConversationView.tsx:764-772` sets a 30-second `setTimeout` after a successful invite. On expiry it dispatches `REMOTE_DECLINE` with `reason: "timeout"` to the local state machine and calls the backend `timeoutCall(res.call_id, { reason: "no_answer" })` endpoint. The API wrapper is at `frontend/src/api/endpoints/messaging.ts:313`. The ref (`callTimeoutRef` at `:91`) is cleared on terminal phase entry (`:683-685`).

### 2.8 SSE Handling on the Callee Side

`frontend/src/hooks/useMessagingStream.ts:172` registers `"call.missed"` in `EVENT_TYPES`. When the callee's SSE stream delivers the event, `ConversationView.tsx:823-827` dispatches `REMOTE_DECLINE` with `reason: "timeout"` — dismissing the incoming ringing UI. Only the callee case is handled; there is no queryClient invalidation call.

The callee has **no local timer** to auto-dismiss the ringing UI. If SSE delivery is delayed (e.g., the fanout push is missing and the 1-second poll is slow), the callee sees a ringing overlay past the intended 30-second window.

### 2.9 State Machine (Frontend)

`frontend/src/pages/messages/callStateMachine.ts:108` handles `REMOTE_DECLINE` with `reason: "timeout"`:
```typescript
if (event.reason === "timeout") return withPhase(state, "timeout", {
  reasonMessage: event.message ?? "Call timed out with no answer."
});
```
`frontend/src/pages/messages/CallSessionOverlay.tsx:72-78` renders `"Call timed out with no answer."` for the `timeout` phase.

---

## 3. Gap / Threat Analysis

### 3.1 Missing SSE Fanout for `call.missed`

The `timeout_call_endpoint` (`:14028-14059`) and `timeout_call()` service function (`:404-453`) do not call `fanout_event_to_conversation`. The callee learns of the timeout only via the SSE poll picking up the new system message — a delay of up to 1 second. In production with SSE connection pooling, this may be 2-3 seconds. The callee's ringing UI may ring visibly longer than the configured timeout.

**Impact**: User-visible: callee UI rings 1-3 seconds past the intended timeout. Low severity but clearly wrong.

### 3.2 No Callee-Side Local Timer

The callee has no local `setTimeout` to auto-dismiss the incoming ringing overlay if the `call.missed` SSE event is lost or delayed. The only mitigation is the SSE-delivered event.

**Impact**: If the SSE stream connection drops and the callee's browser does not reconnect within the grace period, the ringing overlay stays up indefinitely until a page reload.

### 3.3 Backstop Table Scan Does Not Scale

`_expire_stale_invites()` uses a full table scan of `MessageCallSessions`. On a table with millions of call records (each stored for 90 days), this scan will consume substantial read capacity units and slow the background loop.

**Impact**: Production scaling issue; no acute risk in dev with small datasets.

### 3.4 Race Condition: Accept at t=29.9s

If the callee accepts at t=29.9 s and the caller's 30-second timer fires at t=30 s, `timeout_call()` will call `_check_transition(record.state, "missed")` on a session already in `accepted` state. This raises a `CallLifecycleError` with code `"invalid_transition"`, which the endpoint converts to HTTP 409. The client-side `catch { /* best-effort */ }` in `ConversationView.tsx:776-778` silently swallows the 409, leaving the local state machine in `timeout` phase even though the call is actually `accepted`. The caller UI will show "Call timed out" while the call is actually connected on the callee side.

**Impact**: Confusing caller UX; the caller does not see the accepted state.

---

## 4. Proposed Design / Fix

### 4.1 Add SSE Fanout to `timeout_call_endpoint`

In `app/routers/messaging.py:14028-14059`, after `timeout_call()` returns successfully, add:

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
        "event_ts": event.event_ts,
    },
    respect_mute=False,
)
```

`fanout_event_to_conversation` is defined at `app/routers/messaging.py:5465`. This must happen before the `return CallActionOut(...)` statement. The same call should be added to `_expire_stale_invites()` for the backstop path.

### 4.2 Add Callee-Side Local Timer

In `ConversationView.tsx`, add a `useEffect` that fires `REMOTE_DECLINE` with `reason: "timeout"` after `RINGING_TIMEOUT_MS + 2000` ms (2-second grace for network latency) if the machine is still in `incoming_ringing` phase:

```typescript
React.useEffect(() => {
  if (callMachine.phase !== "incoming_ringing") return;
  const timer = window.setTimeout(() => {
    dispatchCall({ type: "END_REMOTE", message: "Call timed out." });
  }, S.messaging_webrtc_call_ringing_timeout_seconds * 1000 + 2000);
  return () => window.clearTimeout(timer);
}, [callMachine.phase]);
```

The frontend constant can be imported from a shared constants file or from the existing feature-flags module. The 2-second grace prevents the timer from firing before the `call.missed` SSE event arrives under normal conditions.

### 4.3 Fix Race Condition: 409 Should Update State

In `ConversationView.tsx:764-772`, change the `catch` block to handle `409 Conflict` specifically:

```typescript
} catch (err: unknown) {
  if (err && typeof err === "object" && "status" in err && (err as {status: number}).status === 409) {
    // Call already transitioned (e.g., callee accepted at last moment) — fetch current state
    queryClient.invalidateQueries({ queryKey: ["call", res.call_id] });
  }
  // Other errors: best-effort, suppress
}
```

The `REMOTE_DECLINE` dispatch should be deferred until after the 409 check, and the state should be updated from the fetched call state if a 409 is received.

### 4.4 Production GSI for Backstop (P1 Hardening)

Add `ByStateStartedAt` GSI to `scripts/local-ddb-init.py` `MessageCallSessions` table definition:

```python
{"index_name": "ByStateStartedAt", "partition_key": "state", "sort_key": "start_ts_sort"},
```

with `attr_types={"start_ts_sort": "N"}`. Implement `list_call_sessions_by_state(state, max_age_ts)` in `app/services/messaging_call_sessions.py` using a GSI query instead of a scan.

### 4.5 Dev/Prod Parity (SECOPS-007)

All timeout paths are gated by `S.messaging_webrtc_call_ringing_timeout_seconds` (`:1149`), which is read from an env var in both dev and prod. The mock stack (DynamoDB Local, moto) is used by default; the same code path runs in prod. No `dev_mode`-only branching exists in the timeout path, which is correct SECOPS-007 behavior. The backstop always runs; a feature flag `messaging_webrtc_call_timeout_backstop_enabled` should be added to `app/core/settings.py` for prod kill-switch capability without code changes.

---

## 5. Testing, Verification & Rollout

### 5.1 Pytest Unit Tests

**File**: `tests/test_call_timeout.py` (337 lines, exists)

Key cases to add/verify:
- `test_timeout_call_transitions_invited_to_missed`: POST `/messages/calls/{id}/timeout` with caller auth → `state=missed`, `end_reason="no_answer"`.
- `test_timeout_call_forbidden_non_caller`: Third party returns 403.
- `test_timeout_call_idempotent`: Repeated request with same `idempotency_key` returns the same result.
- `test_timeout_call_409_on_accepted_state`: Attempting timeout on an `accepted` call returns HTTP 409 (`invalid_transition`).
- `test_expire_stale_invites_transitions_old_sessions`: Seed a session with `state="invited"` and `start_ts` > 30 s ago; run `_expire_stale_invites()`; verify session state is `missed`.
- `test_expire_stale_invites_skips_young_sessions`: Session started 10 s ago is not transitioned.

**Mock setup**: moto `DynamoDB` for all DDB calls; no AWS credentials required. Tests are offline-runnable.

### 5.2 Playwright E2E Tests

**File**: `frontend/e2e/call-7.spec.ts` (verify existence) — run with `--use-fake-device-for-media-stream`.

Key scenarios:
- Alice initiates a call to Bob; Bob ignores it; after 30 s the caller's overlay shows "Call timed out with no answer."
- Backend call session is in `missed` state after timeout.
- Bob's incoming ringing overlay auto-dismisses (after adding the callee-side local timer).
- Conversation timeline shows a "Missed call" system message visible to both Alice and Bob.
- Initiating a second call after timeout succeeds (no `callee_busy` block from the stale `invited` session).
- Feature flag `MESSAGING_WEBRTC_CALL_RINGING_TIMEOUT_SECONDS=5` used to accelerate the test.

**Auth pattern**: `injectAuth(alicePage, "alice")` for caller; `injectAuth(bobPage, "bob")` for callee; separate browser contexts.

### 5.3 Observability

Add `record_webrtc_call_timeout(source: str)` to `app/metrics.py` — `source` is `"client"` (from the HTTP endpoint) or `"server"` (from the backstop). Call it in `timeout_call_endpoint` and in `_expire_stale_invites()`. This metric feeds the SECOPS-001 operational dashboard for call health.

### 5.4 Rollback

The feature flag `messaging_webrtc_call_ringing_timeout_seconds` can be set to a very large value (e.g., `9999999`) to effectively disable timeouts without disabling the endpoint. The `messaging_webrtc_call_timeout_backstop_enabled` flag (once added) provides a clean off switch for the background scan. Neither change is destructive to existing data.

### 5.5 Effort and Order

- **S (1-2 days)**: Add SSE fanout to timeout endpoint + backstop path (gap 3.1).
- **S (0.5 day)**: Add callee-side local timer in ConversationView (gap 3.2).
- **S (0.5 day)**: Fix 409 handling in client timer catch block (gap 3.4).
- **M (2-3 days)**: Add `ByStateStartedAt` GSI + `list_call_sessions_by_state()` function + backstop feature flag (gap 3.3).

Implement in that order. The SSE fanout and callee timer are P0 for correct UX; the GSI is P1 hardening before production rollout.
