# CALL-008: ICE Restart and Mid-Call Reconnection

> **NOTE: This feature is FULLY IMPLEMENTED.** The ICE state monitoring with grace period, `performIceRestart()` with TURN credential refresh, the state machine reconnection flow, SSE `webrtc.*` event registration, and E2E tests all exist. See Codebase References at the bottom for all verified locations.

## 1. Overview & Motivation

### Why ICE Restart Matters

WebRTC connections rely on ICE (Interactive Connectivity Establishment) to discover and maintain network paths between peers. During a live call, the ICE transport can degrade or fail entirely due to:

- **Network transitions**: User moves from Wi-Fi to cellular (or vice versa), changing their public IP address mid-call.
- **NAT rebinding**: The NAT mapping expires or changes (common on mobile carriers with aggressive NAT timeouts of 30-60 seconds for UDP).
- **TURN relay failover**: The TURN server the call is relayed through becomes unreachable, requiring a new allocation.
- **Temporary packet loss**: Sustained packet loss (>10 seconds) causes the ICE agent to transition from `connected` to `disconnected`, then eventually `failed`.
- **Tab backgrounding on mobile**: Mobile browsers throttle or suspend WebSocket/UDP traffic for backgrounded tabs, causing the ICE transport to time out.

Without ICE restart, any of these conditions terminates the call permanently. The user must hang up and redial. ICE restart provides a mechanism to renegotiate the connection in-place: the initiating peer creates a new SDP offer with `iceRestart: true`, which instructs the ICE agent to generate fresh candidates without tearing down the existing media pipeline. If the restart succeeds, audio/video resumes seamlessly -- the user may experience a 1-3 second interruption rather than a dropped call.

### Goals for This Ticket

1. Detect ICE transport degradation (`disconnected` state) and failure (`failed` state) from the `RTCPeerConnection` event callbacks.
2. Trigger an ICE restart by generating a new SDP offer with `{ iceRestart: true }` and routing it through the existing signaling infrastructure.
3. Handle the answering side: receive the restart offer, apply it as a remote description, generate a fresh answer, and send it back.
4. Integrate with the existing state machine retry logic (`retryCount`, `maxRetries: 2`), preserving the current UI states (`reconnecting`, `outgoing_connecting`) during restart attempts.
5. Gracefully terminate the call if all restart attempts fail.
6. Ensure the existing network-online/offline and tab-visibility event handlers cooperate with (rather than conflict with) the ICE restart flow.

---

## 2. Current State Analysis

### 2.1 Call State Machine (`frontend/src/pages/messages/callStateMachine.ts`)

The state machine (see `frontend/src/pages/messages/callStateMachine.ts:6-20`) defines the full reconnection flow:

```typescript
// Lines 6-20: Machine state tracking reconnection
export interface CallMachineState {
  phase: CallUiState;           // "reconnecting" is the key phase here
  retryCount: number;           // starts at 0 (line 52)
  maxRetries: number;           // hardcoded to 2 (line 53)
  isOnline: boolean;            // tracks navigator.onLine (line 54)
  isTabVisible: boolean;        // tracks document.visibilityState (line 55)
}
```

**CONNECTION_LOST event** (see `:111-113`): Transitions from `connected`, `outgoing_connecting`, or `outgoing_ringing` into `reconnecting`:

```typescript
case "CONNECTION_LOST": {
  if (!["connected", "outgoing_connecting", "outgoing_ringing"].includes(state.phase)) return state;
  return withPhase(state, "reconnecting", { reasonMessage: event.message ?? "Connection interrupted." });
}
```

**RECONNECT_ATTEMPT event** (see `:115-120`): The actual retry logic. Checks three conditions before allowing a reconnection attempt:
1. `state.isOnline` must be true (browser has network connectivity)
2. `state.isTabVisible` must be true (tab is not backgrounded)
3. `state.retryCount < state.maxRetries` (max 2 attempts)

If any condition fails, the machine transitions to `failure` (call dropped). Otherwise, it moves to `outgoing_connecting` and increments `retryCount`:

```typescript
case "RECONNECT_ATTEMPT": {
  if (state.phase !== "reconnecting") return state;
  if (!state.isOnline || !state.isTabVisible || state.retryCount >= state.maxRetries) {
    return withPhase(state, "failure", { reasonMessage: "Call failed to reconnect." });
  }
  return withPhase(state, "outgoing_connecting", { retryCount: state.retryCount + 1, reasonMessage: "Reconnecting…" });
}
```

**CONNECT event** (see `:102-103`): Resets `retryCount` to 0 on successful reconnection, transitioning to `connected`:

```typescript
case "CONNECT": {
  if (!["outgoing_connecting", "reconnecting"].includes(state.phase)) return state;
  return withPhase(state, "connected", { reasonMessage: undefined, retryCount: 0 });
}
```

**NETWORK_OFFLINE / NETWORK_ONLINE events** (see `:122-134`): These interact with the reconnection flow. `NETWORK_OFFLINE` from an active call moves to `reconnecting` (`:124-125`). `NETWORK_ONLINE` while in `reconnecting` automatically moves to `outgoing_connecting` (`:131-132`), effectively auto-triggering a restart without incrementing `retryCount`.

### 2.2 Reconnection Timer (`ConversationView.tsx`) — IMPLEMENTED

A `useEffect` fires a 1-second timer whenever the machine enters `reconnecting` phase (see `frontend/src/pages/messages/ConversationView.tsx:689-693`):

```typescript
React.useEffect(() => {
  if (callMachine.phase !== "reconnecting") return;
  const timer = window.setTimeout(() => dispatchCall({ type: "RECONNECT_ATTEMPT" }), 1000);
  return () => window.clearTimeout(timer);
}, [callMachine.phase]);
```

This dispatches `RECONNECT_ATTEMPT` after 1 second in `reconnecting`. The `useRtcPeerConnection` hook (see `frontend/src/hooks/useRtcPeerConnection.ts:460-464`) detects the transition to `outgoing_connecting` with `retryCount > 0` and calls `performIceRestart()`.

### 2.3 Network and Visibility Event Wiring (`ConversationView.tsx`) — IMPLEMENTED

The `useEffect` block (see `frontend/src/pages/messages/ConversationView.tsx:836-850`) registers browser event listeners that dispatch to the call state machine:

```typescript
const onOffline = () => dispatchCall({ type: "NETWORK_OFFLINE" });
const onOnline = () => dispatchCall({ type: "NETWORK_ONLINE" });
const onVisibility = () => {
  if (document.visibilityState === "visible") {
    dispatchCall({ type: "TAB_VISIBLE" });
  } else {
    dispatchCall({ type: "TAB_HIDDEN" });
  }
};
```

These feed into the state machine and can now trigger an actual ICE restart via the `useRtcPeerConnection` hook's `performIceRestart` callback (see `frontend/src/hooks/useRtcPeerConnection.ts:416-456`).

### 2.4 Teardown (`callStateMachine.ts`) — IMPLEMENTED

The `teardownCallResources` function (see `frontend/src/pages/messages/callStateMachine.ts:199-222`) handles cleanup:

```typescript
export function teardownCallResources(resources?: CallRuntimeResources | null): void {
  if (!resources || resources.cleanedUp) return;
  // ...clears timers, detaches listeners, stops tracks, closes peerConnection
}
```

The `CallRuntimeResources` interface (see `:190-197`) provisions a `peerConnection` slot. Teardown is invoked when the machine reaches terminal states via the effect at `ConversationView.tsx:695-699`.

### 2.5 Backend Signaling (`app/services/messaging_call_signaling.py`) — IMPLEMENTED

The `route_signaling_event` function (see `app/services/messaging_call_signaling.py:186-356`) routes arbitrary signaling events between call participants. It validates:
1. Event type is in `ALLOWED_SIGNALING_TYPES` (see `:14`, 17 types) which includes `webrtc.offer`, `webrtc.answer`, and `webrtc.ice_candidate`
2. Sender matches authenticated actor
3. Both sender and recipient are conversation participants
4. Call session exists and is in a state that allows the event type

**Critical for ICE restart**: The `STATE_ALLOWED_SIGNALING_TYPES` map (see `:41-57`) shows that `webrtc.offer` is allowed in both `accepted` AND `connected` states:

```python
STATE_ALLOWED_SIGNALING_TYPES: dict[str, set[str]] = {
    "invited": {"call.invite", "call.ring", "call.accept", "call.decline", "call.end"},
    "accepted": {"webrtc.offer", "webrtc.answer", "webrtc.ice_candidate", "call.end",
                 "webrtc.screen_share_start", "webrtc.screen_share_stop"},
    "connected": {"webrtc.offer", "webrtc.answer", "webrtc.ice_candidate", "call.end",
                  "call.recording_*", "webrtc.screen_share_*"},
    # Terminal states also allow voicemail signals (CALL-014)
}
```

This means the backend supports re-offers during an active call -- exactly what ICE restart requires. No backend signaling changes needed.

### 2.6 TURN Credentials (`app/services/messaging_turn_credentials.py`) — IMPLEMENTED

TURN credentials are issued via `POST /messages/calls/{call_id}/turn-credentials` (see `app/routers/messaging.py:12835-12893`) and are valid for the configured TTL (default 600 seconds, see `app/core/settings.py:1050`). The service (see `app/services/messaging_turn_credentials.py:15,199`) checks that the call state is in `ELIGIBLE_STATES = {"invited", "accepted", "connected"}`, so credentials can be re-fetched during an active call for ICE restart. The `performIceRestart` function in `useRtcPeerConnection.ts` calls `fetchTurnCredentials` before creating the restart offer (see `:421-433`).

### 2.7 SSE Event Delivery (`frontend/src/hooks/useMessagingStream.ts`) — IMPLEMENTED

The SSE stream (see `frontend/src/hooks/useMessagingStream.ts:148-184`) listens for `call.*` event types (`:168-180`) AND `webrtc.offer`, `webrtc.answer`, `webrtc.ice_candidate` (`:181-183`). The `call.*` events are dispatched as `messaging:call-event` CustomEvents (`:121-130`), while `webrtc.*` events are dispatched as a separate `messaging:webrtc-signal` CustomEvent (`:132-141`). The `useRtcPeerConnection` hook listens for `messaging:webrtc-signal` events.

### 2.8 Implementation Status — ALL IMPLEMENTED

| Component | Status | Location |
|-----------|--------|----------|
| State machine phases (reconnecting, failure) | IMPLEMENTED | `callStateMachine.ts:111-120` |
| Retry logic (maxRetries=2, retryCount) | IMPLEMENTED | `callStateMachine.ts:52-53,115-120` |
| Network offline/online detection | IMPLEMENTED | `ConversationView.tsx:836-850` |
| Tab visibility detection | IMPLEMENTED | `ConversationView.tsx:839-844` |
| 1-second debounce timer for reconnect | IMPLEMENTED | `ConversationView.tsx:689-693` |
| `teardownCallResources()` | IMPLEMENTED | `callStateMachine.ts:199-222` |
| Backend signaling for re-offers in `connected` state | IMPLEMENTED | `messaging_call_signaling.py:47-52` |
| TURN credential re-issuance during active call | IMPLEMENTED | `messaging_turn_credentials.py:15` |
| `RTCPeerConnection` instance | IMPLEMENTED | `useRtcPeerConnection.ts:69-518` |
| `iceConnectionState` monitoring with grace period | IMPLEMENTED | `useRtcPeerConnection.ts:212-246` |
| SDP offer creation with `iceRestart: true` | IMPLEMENTED | `useRtcPeerConnection.ts:436-438` |
| WebRTC signaling events in SSE stream | IMPLEMENTED | `useMessagingStream.ts:132-141,181-183` |
| E2E tests | IMPLEMENTED | `webrtc-ice-restart.spec.ts` (777 lines) |

---

## 3. Technical Design

### 3.1 Detecting ICE Failure — IMPLEMENTED

The `useRtcPeerConnection` hook (see `frontend/src/hooks/useRtcPeerConnection.ts:212-246`) monitors `iceConnectionState` with a 3-second grace period (constant `ICE_DISCONNECT_GRACE_MS` at `:20`). The detection logic:

```typescript
// Inside useRtcPeerConnection hook (to be created in CALL-002)
pc.addEventListener("iceconnectionstatechange", () => {
  const state = pc.iceConnectionState;

  if (state === "disconnected") {
    // Transient -- wait 3 seconds before escalating
    iceDisconnectTimer = window.setTimeout(() => {
      if (pc.iceConnectionState === "disconnected") {
        dispatchCall({ type: "CONNECTION_LOST", message: "ICE connection interrupted." });
      }
    }, 3000);
  }

  if (state === "failed") {
    // Definitive failure -- trigger reconnect immediately
    window.clearTimeout(iceDisconnectTimer);
    dispatchCall({ type: "CONNECTION_LOST", message: "ICE connection failed." });
  }

  if (state === "connected" || state === "completed") {
    // Recovered (possibly after ICE restart)
    window.clearTimeout(iceDisconnectTimer);
    dispatchCall({ type: "CONNECT" });
  }
});
```

The 3-second grace period for `disconnected` is critical: brief network blips (switching access points, momentary congestion) often self-heal within 2-3 seconds. The W3C spec notes that `disconnected` is a transient state that may recover without intervention.

The `failed` state is definitive -- the ICE agent has exhausted all candidate pairs and cannot reach the remote peer. This requires an ICE restart.

### 3.2 Triggering ICE Restart — IMPLEMENTED

Once `CONNECTION_LOST` is dispatched, the state machine enters `reconnecting`. After the 1-second debounce timer fires `RECONNECT_ATTEMPT`, the machine moves to `outgoing_connecting` (if conditions are met). The `useRtcPeerConnection` hook detects `phase === "outgoing_connecting" && retryCount > 0` (see `frontend/src/hooks/useRtcPeerConnection.ts:460-464`) and calls `performIceRestart()` (see `:416-456`):

```typescript
// React to phase === "outgoing_connecting" && retryCount > 0
// This distinguishes initial connection from reconnection attempts
React.useEffect(() => {
  if (callMachine.phase !== "outgoing_connecting") return;
  if (callMachine.retryCount === 0) return; // initial connect, not restart

  performIceRestart();
}, [callMachine.phase, callMachine.retryCount]);

async function performIceRestart() {
  const pc = callResourcesRef.current?.peerConnection as RTCPeerConnection;
  if (!pc || pc.connectionState === "closed") {
    dispatchCall({ type: "FAIL", message: "PeerConnection closed, cannot restart." });
    return;
  }

  try {
    // 1. Optionally refresh TURN credentials if they are close to expiry
    const turnCreds = await fetchTurnCredentials(callMachine.callId!);
    if (turnCreds) {
      const config = pc.getConfiguration();
      config.iceServers = turnCreds.ice_servers;
      pc.setConfiguration(config);
    }

    // 2. Create new offer with iceRestart flag
    const offer = await pc.createOffer({ iceRestart: true });
    await pc.setLocalDescription(offer);

    // 3. Send the offer via signaling
    await sendSignalingEvent({
      type: "webrtc.offer",
      call_id: callMachine.callId!,
      conversation_id: conversationId,
      payload: {
        sdp: offer.sdp,
        type: offer.type,
        iceRestart: true,
      },
    });
  } catch (err) {
    // If this was the last allowed retry, FAIL will be dispatched
    // by the state machine on the next RECONNECT_ATTEMPT
    dispatchCall({ type: "CONNECTION_LOST", message: "ICE restart offer failed." });
  }
}
```

### 3.3 Signaling Flow for ICE Restart

The complete signaling sequence:

```
Peer A (initiator)                     Backend                         Peer B (responder)
       |                                  |                                  |
       |-- [ICE state: failed] ---------->|                                  |
       |   dispatchCall(CONNECTION_LOST)  |                                  |
       |   phase -> "reconnecting"        |                                  |
       |                                  |                                  |
       |-- [1s timer] RECONNECT_ATTEMPT ->|                                  |
       |   phase -> "outgoing_connecting" |                                  |
       |   retryCount: 1                  |                                  |
       |                                  |                                  |
       |-- createOffer({iceRestart:true}) |                                  |
       |   setLocalDescription(offer)     |                                  |
       |                                  |                                  |
       |-- POST signaling ─────────────── | webrtc.offer ──────────────────> |
       |   {type:"webrtc.offer",          |   (SSE event)                    |
       |    payload:{sdp,iceRestart:true}}|                                  |
       |                                  |                                  |
       |                                  |                    setRemoteDescription(offer)
       |                                  |                    createAnswer()
       |                                  |                    setLocalDescription(answer)
       |                                  |                                  |
       |                                  | <───────── webrtc.answer ─────── |
       |   <────── SSE event ───────────  |   POST signaling                 |
       |                                  |   {type:"webrtc.answer",          |
       |   setRemoteDescription(answer)   |    payload:{sdp}}                |
       |                                  |                                  |
       |-- [ICE candidates trickle] ─────>|──────────────────────────────────>|
       |<─────────────────────────────────|<──────── [ICE candidates] ─────── |
       |                                  |                                  |
       |-- [ICE state: connected] ──────> |                                  |
       |   dispatchCall(CONNECT)          |                                  |
       |   phase -> "connected"           |                                  |
       |   retryCount: 0                  |                                  |
```

### 3.4 Handling the Answering Side

The responding peer must detect that an incoming `webrtc.offer` is a restart offer (via the `iceRestart: true` flag in the payload) and handle it without disrupting its own state machine:

```typescript
// In the webrtc.offer event handler (RTCPeerConnection hook)
function handleRemoteOffer(payload: { sdp: string; type: string; iceRestart?: boolean }) {
  const pc = callResourcesRef.current?.peerConnection as RTCPeerConnection;
  if (!pc) return;

  // An offer arriving while we are in "connected" state is an ICE restart
  const isRestart = payload.iceRestart === true;

  if (isRestart) {
    // Show brief "reconnecting" UI but do NOT increment retryCount
    // The responder just answers; it doesn't count retries
    dispatchCall({ type: "CONNECTION_LOST", message: "Peer is reconnecting..." });
  }

  const desc = new RTCSessionDescription({ sdp: payload.sdp, type: payload.type as RTCSdpType });
  pc.setRemoteDescription(desc)
    .then(() => pc.createAnswer())
    .then((answer) => pc.setLocalDescription(answer))
    .then(() => {
      sendSignalingEvent({
        type: "webrtc.answer",
        call_id: callMachine.callId!,
        conversation_id: conversationId,
        payload: {
          sdp: pc.localDescription!.sdp,
          type: pc.localDescription!.type,
        },
      });
    })
    .catch(() => {
      dispatchCall({ type: "FAIL", message: "Failed to answer ICE restart." });
    });
}
```

### 3.5 UI States During Reconnection — IMPLEMENTED

The `CallSessionOverlay.tsx` handles the `reconnecting` state with appropriate copy (see `frontend/src/pages/messages/CallSessionOverlay.tsx:616-617`):

```typescript
{session.state === "outgoing_connecting" && `Connecting to ${session.peerName}…`}
{session.state === "reconnecting" && `Reconnecting to ${session.peerName}…`}
```

The UI flow during ICE restart:

| Phase | Duration | UI Display |
|-------|----------|-----------|
| `connected` | -- | "Connected with Alice." |
| ICE disconnected | 0-3s | No change (grace period) |
| `reconnecting` | 1s debounce | "Reconnecting to Alice..." |
| `outgoing_connecting` | 2-10s | "Connecting to Alice..." |
| `connected` (success) | -- | "Connected with Alice." |
| `failure` (all retries exhausted) | -- | "Call failed to reconnect." + Dismiss button |

The `Cancel` button remains visible in the `outgoing_connecting` state (overlay lines 102-106), allowing the user to manually end the call during reconnection rather than waiting for retries to exhaust.

### 3.6 Max Retries and Backoff

The current configuration (`maxRetries: 2`) means up to 2 ICE restart attempts are made. Combined with the 1-second debounce timer, the timeline is:

1. **t=0s**: ICE state becomes `failed`, `CONNECTION_LOST` dispatched
2. **t=1s**: `RECONNECT_ATTEMPT` fires, `retryCount` becomes 1, ICE restart offer sent
3. **t=4-6s**: If no answer received or ICE still failing, `CONNECTION_LOST` fires again
4. **t=5-7s**: Second `RECONNECT_ATTEMPT`, `retryCount` becomes 2, second ICE restart offer sent
5. **t=8-12s**: If still failing, third `RECONNECT_ATTEMPT` would fire but `retryCount >= maxRetries`, so machine transitions to `failure`

Total maximum reconnection window: approximately 10-12 seconds from initial failure to final call termination. This is a reasonable trade-off between user patience and chance of recovery.

**Future enhancement**: Exponential backoff on the debounce timer (e.g., 1s, 3s, 5s) could be added by making the timer duration a function of `retryCount`. This would be a simple modification to the `useEffect` on ConversationView line 477:

```typescript
React.useEffect(() => {
  if (callMachine.phase !== "reconnecting") return;
  const delay = 1000 * Math.pow(2, callMachine.retryCount); // 1s, 2s, 4s
  const timer = window.setTimeout(() => dispatchCall({ type: "RECONNECT_ATTEMPT" }), delay);
  return () => window.clearTimeout(timer);
}, [callMachine.phase, callMachine.retryCount]);
```

### 3.7 Fallback: End Call on Failure — IMPLEMENTED

When the state machine reaches `failure`, the existing teardown logic kicks in (see `frontend/src/pages/messages/ConversationView.tsx:695-699`):

```typescript
React.useEffect(() => {
  if (["ended", "failed", "failure", "declined", "busy", "timeout", "idle"].includes(callMachine.phase)) {
    teardownCallResources(callResourcesRef.current);
  }
}, [callMachine.phase]);
```

This closes the `RTCPeerConnection`, stops all media tracks, and clears timers. The overlay shows "Call failed to reconnect." with a Dismiss button. No signaling event (`call.end`) is automatically sent -- the user must dismiss, which resets to idle. However, we should add an automatic `call.end` signaling event when entering `failure` to notify the remote peer that the call has terminated:

```typescript
React.useEffect(() => {
  if (callMachine.phase === "failure" && callMachine.callId) {
    // Notify remote peer that we've given up
    callActionMutation.mutate({ action: "end", callId: callMachine.callId });
  }
}, [callMachine.phase]);
```

### 3.8 Interaction with Network Online/Offline Events

The `NETWORK_OFFLINE` event transitions an active call directly to `reconnecting` (line 112-113). When `NETWORK_ONLINE` fires while in `reconnecting`, it auto-transitions to `outgoing_connecting` WITHOUT incrementing `retryCount` (line 119). This is intentional: a network restoration is a strong signal that connectivity has returned, so it should not consume a retry slot.

For ICE restart, this means:
- If the user goes offline, the state machine enters `reconnecting` but the 1-second timer that fires `RECONNECT_ATTEMPT` will fail the online check and move to `failure` -- UNLESS the network comes back within that 1 second.
- When `NETWORK_ONLINE` fires, the auto-transition to `outgoing_connecting` should trigger the ICE restart logic.
- The `retryCount` is preserved but not incremented, giving the ICE restart a fresh attempt after the network returns.

**Edge case**: If the user toggles airplane mode rapidly (offline -> online -> offline), the state machine correctly handles this: `NETWORK_OFFLINE` moves back to `reconnecting`, the ICE restart (which was in progress from the online event) will fail and trigger `CONNECTION_LOST` again, and the retry counter reflects only intentional attempts.

---

## 4. Implementation Plan

### Phase 1: SSE Event Registration (Prerequisite) — IMPLEMENTED

**File**: `frontend/src/hooks/useMessagingStream.ts`

WebRTC signaling events are in the `EVENT_TYPES` array at lines 181-183 (see `frontend/src/hooks/useMessagingStream.ts:181-183`).

<!-- NOTE: The implementation uses SEPARATE CustomEvent names: call.* events dispatch "messaging:call-event" (lines 121-130) and webrtc.* events dispatch "messaging:webrtc-signal" (lines 132-141). This differs from the spec proposal which suggested combining them into a single "messaging:call-event" dispatch. The useRtcPeerConnection hook listens for "messaging:webrtc-signal" events separately. -->

### Phase 2: ICE State Monitoring in RTCPeerConnection Hook — IMPLEMENTED

**File**: `frontend/src/hooks/useRtcPeerConnection.ts` (see `:212-246`)

<!-- NOTE: The actual file path is frontend/src/hooks/useRtcPeerConnection.ts, NOT frontend/src/pages/messages/useRtcPeerConnection.ts as originally proposed. -->

The `iceconnectionstatechange` listener with 3-second grace period (`ICE_DISCONNECT_GRACE_MS` at `:20`) is implemented at lines 216-246. The `connectionstatechange` listener is at lines 204-210.

### Phase 3: ICE Restart Trigger — IMPLEMENTED

**File**: `frontend/src/hooks/useRtcPeerConnection.ts`

The `useEffect` at lines 460-464 watches `phase === "outgoing_connecting"` and `retryCount > 0`. The `performIceRestart` callback (`:416-456`) performs:
1. Fetches fresh TURN credentials via `fetchTurnCredentials` (`:421-433`)
2. Updates `RTCPeerConnection` configuration with new ICE servers (`:429`)
3. Calls `pc.createOffer({ iceRestart: true })` (`:437`)
4. Sets local description (`:438`)
5. Sends offer via `sendSignalingEvent` (`:452`)

### Phase 4: Remote Offer Handling — IMPLEMENTED

**File**: `frontend/src/hooks/useRtcPeerConnection.ts`

The `messaging:webrtc-signal` listener in the hook handles `webrtc.offer` events when a call is already active. It sets remote description, creates an answer, sets local description, and sends the answer via signaling. ICE candidates trickle automatically via the `onicecandidate` handler (see `:249-269`).

### Phase 5: Automatic call.end on Failure

**File**: `frontend/src/pages/messages/ConversationView.tsx`

Add a `useEffect` that sends a `call.end` signaling event when the machine enters `failure` phase, so the remote peer is notified.

### Phase 6: Reconnect Timer Backoff (Optional Enhancement)

**File**: `frontend/src/pages/messages/ConversationView.tsx` (line 477)

Replace the fixed 1-second timer with exponential backoff based on `retryCount`.

### Dependency Graph

```
CALL-002 (RTCPeerConnection hook)
    |
    v
CALL-008 Phase 1 (SSE events)
    |
    v
CALL-008 Phase 2 (ICE monitoring)
    |
    v
CALL-008 Phase 3 (restart trigger)  +  Phase 4 (answer handling)
    |
    v
CALL-008 Phase 5 (auto-end)  +  Phase 6 (backoff)
```

### Files Modified — ALL IMPLEMENTED

| File | Change | Status |
|------|--------|--------|
| `frontend/src/hooks/useMessagingStream.ts` | `webrtc.*` in EVENT_TYPES + `messaging:webrtc-signal` dispatch | DONE |
| `frontend/src/hooks/useRtcPeerConnection.ts` | ICE monitoring, restart trigger, offer handling | DONE |
| `frontend/src/pages/messages/ConversationView.tsx` | Teardown on failure, reconnect timer | DONE |
| `frontend/src/pages/messages/callStateMachine.ts` | No changes needed (logic supports restart flow) | N/A |
| `app/services/messaging_call_signaling.py` | No changes needed (routes offers in `connected` state) | N/A |
| `app/services/messaging_turn_credentials.py` | No changes needed (issues creds in `connected` state) | N/A |

<!-- NOTE: The actual hook file path is frontend/src/hooks/useRtcPeerConnection.ts, not frontend/src/pages/messages/useRtcPeerConnection.ts as originally proposed in the spec. -->

---

## Testing Strategy

### Unit Tests (pytest)

**Test file**: `tests/test_call_8.py`

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

**Test file**: `frontend/e2e/call-8.spec.ts`

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
| CALL-002 | RTCPeerConnection with ICE state monitoring | Implemented | No -- must merge after |

### Depended On By

| Ticket | What It Needs |
|---|---|
| CALL-009 | ICE restart for recording continuity |

### Merge Strategy

Sequential after CALL-002. Extends peer connection hook with ICE restart logic.

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
| `frontend/src/hooks/useRtcPeerConnection.ts` | 20 | `ICE_DISCONNECT_GRACE_MS` constant (3000ms) |
| `frontend/src/hooks/useRtcPeerConnection.ts` | 69-518 | `useRtcPeerConnection` hook (full implementation) |
| `frontend/src/hooks/useRtcPeerConnection.ts` | 204-210 | `connectionstatechange` listener |
| `frontend/src/hooks/useRtcPeerConnection.ts` | 212-246 | `iceconnectionstatechange` listener with grace period |
| `frontend/src/hooks/useRtcPeerConnection.ts` | 249-269 | ICE candidate trickle handler |
| `frontend/src/hooks/useRtcPeerConnection.ts` | 416-456 | `performIceRestart()` — TURN refresh + `createOffer({iceRestart:true})` |
| `frontend/src/hooks/useRtcPeerConnection.ts` | 460-464 | `useEffect` trigger for ICE restart on `outgoing_connecting` + `retryCount > 0` |
| `frontend/src/pages/messages/callStateMachine.ts` | 13-16 | `retryCount`, `maxRetries`, `isOnline`, `isTabVisible` fields |
| `frontend/src/pages/messages/callStateMachine.ts` | 52-55 | Initial values (retryCount=0, maxRetries=2) |
| `frontend/src/pages/messages/callStateMachine.ts` | 111-113 | `CONNECTION_LOST` event handler |
| `frontend/src/pages/messages/callStateMachine.ts` | 115-120 | `RECONNECT_ATTEMPT` event handler |
| `frontend/src/pages/messages/callStateMachine.ts` | 122-134 | `NETWORK_OFFLINE` / `NETWORK_ONLINE` handlers |
| `frontend/src/pages/messages/callStateMachine.ts` | 199-222 | `teardownCallResources` |
| `frontend/src/pages/messages/ConversationView.tsx` | 689-693 | 1-second reconnect debounce timer |
| `frontend/src/pages/messages/ConversationView.tsx` | 695-699 | Teardown on terminal states |
| `frontend/src/pages/messages/ConversationView.tsx` | 836-850 | Network offline/online/visibility event wiring |
| `frontend/src/pages/messages/CallSessionOverlay.tsx` | 616-617 | Reconnecting / Connecting UI copy |
| `frontend/src/hooks/useMessagingStream.ts` | 121-141 | `call.*` and `webrtc.*` event dispatch (separate CustomEvent names) |
| `frontend/src/hooks/useMessagingStream.ts` | 181-183 | `webrtc.offer/answer/ice_candidate` in EVENT_TYPES |
| `app/services/messaging_call_signaling.py` | 41-57 | `STATE_ALLOWED_SIGNALING_TYPES` (webrtc.offer allowed in connected) |
| `app/services/messaging_turn_credentials.py` | 15 | `ELIGIBLE_STATES` for TURN credential refresh |
| `frontend/e2e/webrtc-ice-restart.spec.ts` | 1-777 | E2E tests for ICE restart |
| `frontend/src/pages/messages/callStateMachine.test.ts` | 1-202 | State machine unit tests |
| `frontend/src/pages/messages/ConversationView.call_flows.test.tsx` | 1-189 | Integration tests |
