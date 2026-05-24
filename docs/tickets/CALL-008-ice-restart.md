# CALL-008: ICE Restart and Mid-Call Reconnection

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

The state machine defines the full reconnection flow in terms of events and phase transitions:

```typescript
// Lines 6-17: Machine state tracking reconnection
export interface CallMachineState {
  phase: CallUiState;           // "reconnecting" is the key phase here
  retryCount: number;           // starts at 0, incremented on each RECONNECT_ATTEMPT
  maxRetries: number;           // hardcoded to 2
  isOnline: boolean;            // tracks navigator.onLine
  isTabVisible: boolean;        // tracks document.visibilityState
}
```

**CONNECTION_LOST event** (lines 99-101): Transitions from `connected`, `outgoing_connecting`, or `outgoing_ringing` into `reconnecting`. This is the trigger point where ICE restart should initiate.

```typescript
case "CONNECTION_LOST": {
  if (!["connected", "outgoing_connecting", "outgoing_ringing"].includes(state.phase)) return state;
  return withPhase(state, "reconnecting", { reasonMessage: event.message ?? "Connection interrupted." });
}
```

**RECONNECT_ATTEMPT event** (lines 103-108): The actual retry logic. Checks three conditions before allowing a reconnection attempt:
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

**CONNECT event** (lines 89-91): Resets `retryCount` to 0 on successful reconnection, transitioning to `connected`:

```typescript
case "CONNECT": {
  if (!["outgoing_connecting", "reconnecting"].includes(state.phase)) return state;
  return withPhase(state, "connected", { reasonMessage: undefined, retryCount: 0 });
}
```

**NETWORK_OFFLINE / NETWORK_ONLINE events** (lines 110-123): These interact with the reconnection flow. `NETWORK_OFFLINE` from an active call moves to `reconnecting`. `NETWORK_ONLINE` while in `reconnecting` automatically moves to `outgoing_connecting`, effectively auto-triggering a restart without incrementing `retryCount`.

### 2.2 Reconnection Timer (`ConversationView.tsx`, lines 475-479)

A `useEffect` fires a 1-second timer whenever the machine enters `reconnecting` phase:

```typescript
React.useEffect(() => {
  if (callMachine.phase !== "reconnecting") return;
  const timer = window.setTimeout(() => dispatchCall({ type: "RECONNECT_ATTEMPT" }), 1000);
  return () => window.clearTimeout(timer);
}, [callMachine.phase]);
```

This is currently theoretical -- it dispatches `RECONNECT_ATTEMPT` after 1 second in `reconnecting`, but since there is no real `RTCPeerConnection`, nothing actually performs the ICE restart. The timer acts as a "debounce" to avoid reacting to transient disconnects.

### 2.3 Network and Visibility Event Wiring (`ConversationView.tsx`, lines 594-612)

The `useEffect` block registers browser event listeners that dispatch to the call state machine:

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
window.addEventListener("offline", onOffline);
window.addEventListener("online", onOnline);
document.addEventListener("visibilitychange", onVisibility);
```

These correctly feed into the state machine, but they currently cannot trigger an actual ICE restart because no `RTCPeerConnection` exists.

### 2.4 Teardown (`callStateMachine.ts`, lines 163-186)

The `teardownCallResources` function handles cleanup:

```typescript
export function teardownCallResources(resources?: CallRuntimeResources | null): void {
  if (!resources || resources.cleanedUp) return;
  for (const timerId of resources.teardownTimers ?? []) window.clearTimeout(timerId);
  for (const detach of resources.detachListeners ?? []) { try { detach(); } catch {} }
  for (const stream of [resources.localStream, resources.remoteStream]) {
    for (const track of stream?.getTracks() ?? []) track.stop();
  }
  resources.peerConnection?.close();
  resources.cleanedUp = true;
}
```

The `CallRuntimeResources` interface (lines 154-161) already provisions a `peerConnection` slot. Teardown is invoked when the machine reaches terminal states (`ended`, `failed`, `failure`, `declined`, `busy`, `timeout`, `idle`) via the effect on lines 481-485.

### 2.5 Backend Signaling (`app/services/messaging_call_signaling.py`)

The `route_signaling_event` function (lines 162-333) routes arbitrary signaling events between call participants. It validates:
1. Event type is in `ALLOWED_SIGNALING_TYPES` (line 14) which includes `webrtc.offer`, `webrtc.answer`, and `webrtc.ice_candidate`
2. Sender matches authenticated actor
3. Both sender and recipient are conversation participants
4. Call session exists and is in a state that allows the event type

**Critical for ICE restart**: The `STATE_ALLOWED_SIGNALING_TYPES` map (lines 29-33) shows that `webrtc.offer` is allowed in both `accepted` AND `connected` states:

```python
STATE_ALLOWED_SIGNALING_TYPES: dict[str, set[str]] = {
    "invited": {"call.invite", "call.ring", "call.accept", "call.decline", "call.end"},
    "accepted": {"webrtc.offer", "webrtc.answer", "webrtc.ice_candidate", "call.end"},
    "connected": {"webrtc.offer", "webrtc.answer", "webrtc.ice_candidate", "call.end"},
}
```

This means the backend already supports re-offers during an active call -- which is exactly what ICE restart requires. No backend signaling changes are needed. A new `webrtc.offer` with `iceRestart: true` in the payload can be routed while the call session state is `connected`.

### 2.6 TURN Credentials (`app/services/messaging_turn_credentials.py`)

TURN credentials are issued via `POST /messages/calls/{call_id}/turn-credentials` and are valid for the configured TTL (default 600 seconds). During ICE restart, fresh TURN credentials may be needed if the original allocation has expired. The endpoint checks that the call state is in `ELIGIBLE_STATES = {"invited", "accepted", "connected"}`, so credentials can be re-fetched during an active call.

### 2.7 SSE Event Delivery (`frontend/src/hooks/useMessagingStream.ts`)

The SSE stream listens for `call.invite`, `call.accept`, `call.decline`, and `call.end` event types (lines 102-106). However, it does NOT currently listen for `webrtc.offer`, `webrtc.answer`, or `webrtc.ice_candidate`. These WebRTC signaling events will need to be added to the `EVENT_TYPES` array and dispatched as `messaging:call-event` CustomEvents for the `RTCPeerConnection` hook to consume.

### 2.8 What Is Theoretical vs Real

| Component | Status |
|-----------|--------|
| State machine phases (reconnecting, failure) | Fully implemented, tested |
| Retry logic (maxRetries=2, retryCount) | Fully implemented |
| Network offline/online detection | Fully wired to state machine |
| Tab visibility detection | Fully wired to state machine |
| 1-second debounce timer for reconnect | Implemented |
| `teardownCallResources()` | Implemented |
| Backend signaling for re-offers in `connected` state | Supported by existing code |
| TURN credential re-issuance during active call | Supported |
| Actual `RTCPeerConnection` instance | Does NOT exist yet (CALL-002) |
| `iceConnectionState` monitoring | Does NOT exist yet |
| SDP offer creation with `iceRestart: true` | Does NOT exist yet |
| WebRTC signaling events in SSE stream | Not registered in `EVENT_TYPES` |

---

## 3. Technical Design

### 3.1 Detecting ICE Failure

When the `RTCPeerConnection` is instantiated (per CALL-002), its `iceConnectionState` and `connectionState` must be monitored. The detection logic:

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

### 3.2 Triggering ICE Restart

Once `CONNECTION_LOST` is dispatched, the state machine enters `reconnecting`. After the 1-second debounce timer fires `RECONNECT_ATTEMPT`, the machine moves to `outgoing_connecting` (if conditions are met). At this point, the RTCPeerConnection hook should perform the ICE restart:

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

### 3.5 UI States During Reconnection

The `CallSessionOverlay.tsx` already handles the `reconnecting` state with appropriate copy:

```typescript
// Line 83: Already shows "Reconnecting to {peerName}..."
{session.state === "reconnecting" && `Reconnecting to ${session.peerName}…`}
```

And `outgoing_connecting` (used during the actual restart attempt):
```typescript
// Line 82
{session.state === "outgoing_connecting" && `Connecting to ${session.peerName}…`}
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

### 3.7 Fallback: End Call on Failure

When the state machine reaches `failure`, the existing teardown logic kicks in:

```typescript
// ConversationView.tsx lines 481-485
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

### Phase 1: SSE Event Registration (Prerequisite)

**File**: `frontend/src/hooks/useMessagingStream.ts`

Add WebRTC signaling events to the `EVENT_TYPES` array (line 85-106):

```typescript
const EVENT_TYPES = [
  // ... existing types ...
  "call.invite",
  "call.accept",
  "call.decline",
  "call.end",
  // Add these:
  "webrtc.offer",
  "webrtc.answer",
  "webrtc.ice_candidate",
];
```

These events are already dispatched to `window` as `messaging:call-event` CustomEvents (lines 69-77) when `eventType.startsWith("call.")`. Expand the condition to also match `eventType.startsWith("webrtc.")`:

```typescript
if (eventType.startsWith("call.") || eventType.startsWith("webrtc.")) {
  window.dispatchEvent(
    new CustomEvent("messaging:call-event", {
      detail: { ...data, event_type: eventType },
    }),
  );
}
```

### Phase 2: ICE State Monitoring in RTCPeerConnection Hook

**File**: `frontend/src/pages/messages/useRtcPeerConnection.ts` (new file from CALL-002)

Add `iceconnectionstatechange` listener with 3-second grace period for `disconnected` and immediate escalation for `failed`. Wire up `connectionstatechange` as a secondary signal. Store the grace period timer in `CallRuntimeResources.teardownTimers` for cleanup.

### Phase 3: ICE Restart Trigger

**File**: `frontend/src/pages/messages/useRtcPeerConnection.ts`

Add a `useEffect` that watches `callMachine.phase === "outgoing_connecting"` and `callMachine.retryCount > 0`. When triggered:
1. Fetch fresh TURN credentials via `POST /messages/calls/{call_id}/turn-credentials`
2. Update `RTCPeerConnection` configuration with new ICE servers
3. Call `pc.createOffer({ iceRestart: true })`
4. Set local description
5. Send offer via signaling endpoint

### Phase 4: Remote Offer Handling

**File**: `frontend/src/pages/messages/useRtcPeerConnection.ts`

In the `messaging:call-event` listener, handle `webrtc.offer` events when a call is already active:
1. Check if `payload.iceRestart === true`
2. Set remote description from the offer
3. Create and set local answer
4. Send answer via signaling
5. Let ICE agent re-gather candidates (they trickle automatically)

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

### Files Modified

| File | Change |
|------|--------|
| `frontend/src/hooks/useMessagingStream.ts` | Add `webrtc.*` to EVENT_TYPES, expand dispatch condition |
| `frontend/src/pages/messages/useRtcPeerConnection.ts` | ICE state monitoring, restart trigger, offer handling |
| `frontend/src/pages/messages/ConversationView.tsx` | Auto-end on failure, optional timer backoff |
| `frontend/src/pages/messages/callStateMachine.ts` | No changes needed (logic already supports restart flow) |
| `app/services/messaging_call_signaling.py` | No changes needed (already routes offers in `connected` state) |
| `app/services/messaging_turn_credentials.py` | No changes needed (already issues creds in `connected` state) |

---

## 5. Testing Strategy

### 5.1 Unit Tests: State Machine Reconnection Logic

**File**: `frontend/src/pages/messages/callStateMachine.test.ts` (existing or new)

These tests validate the state machine in isolation (no `RTCPeerConnection` needed):

1. **CONNECTION_LOST from connected -> reconnecting**: Verify phase transition and retry count preserved.
2. **RECONNECT_ATTEMPT within budget**: `retryCount < maxRetries` -> transitions to `outgoing_connecting`, increments retryCount.
3. **RECONNECT_ATTEMPT exhausted**: `retryCount >= maxRetries` -> transitions to `failure`.
4. **RECONNECT_ATTEMPT when offline**: `isOnline: false` -> transitions to `failure`.
5. **RECONNECT_ATTEMPT when tab hidden**: `isTabVisible: false` -> transitions to `failure`.
6. **CONNECT after reconnect**: Resets `retryCount` to 0.
7. **NETWORK_OFFLINE during connected**: Moves to `reconnecting`.
8. **NETWORK_ONLINE during reconnecting**: Moves to `outgoing_connecting` without incrementing retryCount.
9. **Rapid NETWORK_OFFLINE/ONLINE cycling**: Verify state remains consistent.
10. **CONNECTION_LOST while already reconnecting**: Stays in `reconnecting` (no-op, since reconnecting is not in the allowed source phases).

### 5.2 Unit Tests: ICE Restart Hook Logic

**File**: `frontend/src/pages/messages/useRtcPeerConnection.test.ts`

Using mocked `RTCPeerConnection`:

1. **ICE disconnected -> 3s grace period -> CONNECTION_LOST**: Mock `iceConnectionState` change to `disconnected`, verify no dispatch for 3 seconds, then verify `CONNECTION_LOST` dispatched.
2. **ICE disconnected -> connected within grace period**: No `CONNECTION_LOST` dispatched, timer cleared.
3. **ICE failed -> immediate CONNECTION_LOST**: No grace period for `failed` state.
4. **performIceRestart called**: Verify `createOffer({ iceRestart: true })` called, `setLocalDescription` called, signaling event sent.
5. **TURN credentials refreshed before restart**: Verify `fetchTurnCredentials` called and `setConfiguration` updated.
6. **Restart offer fails**: Verify `CONNECTION_LOST` re-dispatched (will trigger next retry).
7. **Remote restart offer received**: Verify `setRemoteDescription`, `createAnswer`, `setLocalDescription`, signaling answer sent.
8. **Remote restart offer when no PeerConnection**: Verify `FAIL` dispatched.

### 5.3 Integration Tests: ConversationView Call Flows

**File**: `frontend/src/pages/messages/ConversationView.call_flows.test.tsx` (existing)

Extend the existing test suite:

1. **Full ICE restart cycle via CustomEvents**: Dispatch `messaging:call-event` with `event_type: "webrtc.offer"` and `payload.iceRestart: true` while in `connected` state. Verify overlay shows "Reconnecting" then "Connected" after answer exchange.
2. **Auto-end on failure**: Verify `endCall` mutation is called when machine reaches `failure`.
3. **Network restore triggers restart**: Simulate `offline` event -> verify "Reconnecting", then `online` event -> verify restart initiated.

### 5.4 E2E Tests

**File**: `frontend/e2e/webrtc-ice-restart.spec.ts` (new)

Since E2E tests cannot create real WebRTC connections (no second browser with media), these tests focus on the signaling and state machine integration:

1. **Section: ICE restart signaling route validation**
   - Create a call session in `connected` state via DDB seeding
   - Send a `webrtc.offer` signaling event via the backend signaling route
   - Verify it is delivered (event appears in recipient's Events table)
   - Send a `webrtc.answer` back, verify delivery

2. **Section: TURN credential refresh during active call**
   - Create a call in `connected` state
   - Issue TURN credentials (should succeed since state is `connected`)
   - Verify credentials contain valid `ice_servers` array

3. **Section: Signaling rejected in terminal state**
   - End a call (state becomes `ended`)
   - Attempt to route `webrtc.offer` -> verify 400/409 rejection with `invalid_state` code

4. **Section: UI state machine via call events**
   - Use `page.evaluate` to dispatch `messaging:call-event` CustomEvents
   - Verify overlay transitions: `connected` -> `reconnecting` -> `connected` (via simulated offer/answer)
   - Verify overlay shows "Call failed to reconnect." after exhausting retries

### 5.5 Manual QA Scenarios

For full validation once CALL-002 provides a real `RTCPeerConnection`:

| Scenario | Steps | Expected |
|----------|-------|----------|
| Wi-Fi to cellular | Start call on Wi-Fi, disable Wi-Fi adapter | Overlay shows "Reconnecting...", call resumes within 5-10s on cellular |
| Brief packet loss | Simulate 5s network throttle via DevTools | No visible interruption (grace period absorbs it) |
| Sustained loss | Simulate 30s network block | Call shows "Reconnecting...", fails after 2 retries, shows "Call failed to reconnect." |
| Tab background (desktop) | Switch to another tab for 30s | Call continues (ICE keep-alive maintains connection) |
| Tab background (mobile) | Background the browser app for 60s | On foreground: "Reconnecting..." -> auto-restart -> "Connected" |
| TURN server failure | Kill TURN server mid-call | Restart attempts fetch new TURN creds, connection re-established via alternate path |
| Both peers lose network | Both go offline simultaneously | Both enter `reconnecting`, whichever comes online first sends restart offer |

### 5.6 Metrics Validation

The existing metrics infrastructure in `app/metrics.py` records signaling events via `_record_signaling_metric`. After ICE restart implementation, verify:

- `webrtc_signaling_event_total{outcome="success", event_type="webrtc.offer"}` increments during restart
- `webrtc_call_duration` metric reflects the total call time (including reconnection periods)
- A new metric `webrtc_ice_restart_total{outcome="success|failure"}` should be added to track restart success rate across the fleet

### 5.7 Regression Concerns

1. **Existing `CONNECT` event handling**: Ensure that `CONNECT` dispatched from ICE `connected` state does not conflict with the initial connection `CONNECT` (it doesn't -- both are accepted from `outgoing_connecting`).
2. **Retry count reset**: After a successful restart (`CONNECT`), `retryCount` resets to 0. Verify that a subsequent failure gets the full retry budget again.
3. **Teardown during restart**: If user clicks "Cancel" while in `outgoing_connecting` (during restart), verify `teardownCallResources` is called and `call.end` is sent.
4. **Concurrent restart attempts**: If both peers detect failure simultaneously and both send restart offers, the "glare" scenario must be handled (per WebRTC spec: the peer with the lower session ID should roll back their offer and accept the other's).
