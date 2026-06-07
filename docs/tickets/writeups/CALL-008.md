# CALL-008: ICE Restart and Mid-Call Reconnection — Investigation & Implementation Write-up

## 1. Summary & Classification

WebRTC `RTCPeerConnection` ICE transport state can degrade from `connected` to `disconnected` or `failed` mid-call due to network transitions (Wi-Fi ↔ cellular), NAT rebinding, TURN relay failover, sustained packet loss, or mobile tab backgrounding. Without a recovery mechanism, any such degradation permanently terminates the call — the user must hang up and redial. ICE restart allows the initiating peer to generate a new SDP offer with `{ iceRestart: true }`, causing the ICE agent to discover fresh candidates without tearing down the media pipeline. A successful restart means the user experiences a 1-3 second audio interruption rather than a dropped call.

This ticket implements the full ICE restart stack: browser-side `iceconnectionstatechange` monitoring with a 3-second grace period for transient `disconnected` states, a `performIceRestart()` callback that refreshes TURN credentials and sends a restart offer through the existing signaling relay, the responder-side offer-handling path, and frontend state machine `reconnecting`/`outgoing_connecting` phases with a 1-second debounce timer and `maxRetries: 2`.

**Type**: Feature / resilience hardening
**Priority**: P0 for production quality; P1 for initial launch
**Status**: Fully implemented (all phases); two gaps remain (automatic `call.end` fanout on `failure` phase, optional exponential backoff)
**Owning area**: Messaging / WebRTC calls
**Cross-references**: CALL-002 (RTCPeerConnection hook), CALL-009 (recording continuity during ICE restart), SECOPS-007 (dev/prod parity — same code path; no `dev_mode`-only branching in ICE logic)
**Dependencies**: Merged after CALL-002; CALL-009 depends on this being present.

---

## 2. Current-State Investigation

### 2.1 State Machine Reconnection Fields

`frontend/src/pages/messages/callStateMachine.ts:13-16` adds `retryCount: number`, `maxRetries: number`, `isOnline: boolean`, and `isTabVisible: boolean` to `CallMachineState`. Initial values (`:52-55`): `retryCount: 0`, `maxRetries: 2`, `isOnline: true`, `isTabVisible: true`.

The `CONNECTION_LOST` event handler (`:111-113`) transitions `connected | outgoing_connecting | outgoing_ringing` → `reconnecting` with an optional `reasonMessage`.

`RECONNECT_ATTEMPT` (`:115-120`) guards on three conditions: `isOnline`, `isTabVisible`, and `retryCount < maxRetries`. If any guard fails the machine transitions to `failure`; otherwise it moves to `outgoing_connecting` and increments `retryCount`.

`CONNECT` (`:102-103`) transitions `outgoing_connecting | reconnecting` → `connected` and resets `retryCount` to 0.

`NETWORK_OFFLINE` (`:122-125`) from an active call moves directly to `reconnecting`. `NETWORK_ONLINE` (`:131-132`) while in `reconnecting` moves to `outgoing_connecting` without consuming a retry slot — a network restoration is a strong liveness signal.

### 2.2 ICE Monitoring in `useRtcPeerConnection.ts`

`frontend/src/hooks/useRtcPeerConnection.ts:21` defines `const ICE_DISCONNECT_GRACE_MS = 3000`. The `oniceconnectionstatechange` handler (`:216-246`) implements:

- **`disconnected`**: Starts a 3-second timer (`:224-230`). If still `disconnected` at timer expiry, calls `onConnectionLostRef.current?.()` → dispatches `CONNECTION_LOST` to the state machine.
- **`failed`**: Immediately calls `onConnectionLostRef.current?.()` with no grace period (`:231-237`).
- **`connected` / `completed`**: Cancels the grace timer and calls `onConnectRef.current?.()` → dispatches `CONNECT` (`:238-244`).

The `connectionstatechange` handler (`:204-210`) is also present for `RTCPeerConnection.connectionState` tracking (distinct from `iceConnectionState`).

### 2.3 `performIceRestart()` Callback

`frontend/src/hooks/useRtcPeerConnection.ts:416-456` implements `performIceRestart()`:
1. Fetches fresh TURN credentials via `fetchTurnCredentials(callMachine.callId)` (`:421-433`).
2. Calls `pc.setConfiguration(config)` with updated `iceServers` from the new credentials (`:429`).
3. Calls `pc.createOffer({ iceRestart: true })` (`:437`) and `pc.setLocalDescription(offer)` (`:438`).
4. Sends a `webrtc.offer` signaling event with `payload.iceRestart: true` via `sendSignalingEvent` (`:452`).

The trigger `useEffect` (`:460-464`) watches `phase === "outgoing_connecting"` and `retryCount > 0`. `retryCount === 0` is the initial connection; `retryCount > 0` distinguishes a reconnect attempt.

### 2.4 Reconnect Debounce Timer

`frontend/src/pages/messages/ConversationView.tsx:689-693` fires a 1-second `setTimeout` when `callMachine.phase === "reconnecting"`, dispatching `RECONNECT_ATTEMPT`. This 1-second delay is a fixed debounce.

### 2.5 Network and Visibility Event Wiring

`ConversationView.tsx:836-850` registers `window.addEventListener("offline", onOffline)`, `window.addEventListener("online", onOnline)`, and `document.addEventListener("visibilitychange", onVisibility)`. These dispatch `NETWORK_OFFLINE`, `NETWORK_ONLINE`, `TAB_HIDDEN`, and `TAB_VISIBLE` to the state machine.

### 2.6 Backend Signaling Support for Re-Offers

`app/services/messaging_call_signaling.py:41-57` defines `STATE_ALLOWED_SIGNALING_TYPES`. The `"connected"` entry (`:47-52`) includes `"webrtc.offer"`, `"webrtc.answer"`, and `"webrtc.ice_candidate"`. This means the signaling relay already accepts re-offers during an active call — no backend changes are needed to support ICE restart offers.

### 2.7 TURN Credential Re-Issuance

`app/services/messaging_turn_credentials.py:15` defines `ELIGIBLE_STATES = {"invited", "accepted", "connected"}`. The `POST /messages/calls/{call_id}/turn-credentials` endpoint (`:12835-12893`) checks this set, so credentials can be re-fetched during an active `connected` call. TURN settings: `messaging_webrtc_turn_enabled` (`app/core/settings.py:1145`), TTL at `:1148` (default 600 s).

### 2.8 SSE Event Registration

`frontend/src/hooks/useMessagingStream.ts:181-183` registers `webrtc.offer`, `webrtc.answer`, and `webrtc.ice_candidate` in `EVENT_TYPES`. These are dispatched as a separate `"messaging:webrtc-signal"` CustomEvent (`:132-141`), distinct from the `"messaging:call-event"` CustomEvent used for `call.*` events (`:121-130`). The `useRtcPeerConnection` hook listens for `"messaging:webrtc-signal"`.

### 2.9 Teardown on Terminal States

`ConversationView.tsx:695-699` calls `teardownCallResources(callResourcesRef.current)` when the machine enters any terminal phase including `"failure"`. `teardownCallResources` (`:199-222` of `callStateMachine.ts`) closes the `RTCPeerConnection`, stops tracks, clears timers, and marks `cleanedUp: true`.

### 2.10 E2E and Unit Tests

`frontend/e2e/webrtc-ice-restart.spec.ts` (777 lines) covers the ICE restart flow end-to-end. `frontend/src/pages/messages/callStateMachine.test.ts` (202 lines) unit-tests the state machine reducer. `frontend/src/pages/messages/ConversationView.call_flows.test.tsx` (189 lines) covers integration flows.

---

## 3. Gap / Threat Analysis

### 3.1 No Automatic `call.end` Signal on `failure` Phase

When all retries are exhausted and the machine enters `failure`, `teardownCallResources()` is called locally but no `call.end` signaling event is sent to the remote peer. The remote peer does not know the call has terminated and its state machine remains in whatever phase it was in when the last ICE failure occurred. The remote peer's call overlay will remain visible until the user manually dismisses it or a page reload occurs.

**Impact**: Remote user confusion; the call session in DynamoDB remains non-terminal (`connected` or `accepted`) until the heartbeat timeout (for paid calls) or a server-side scan identifies it as stale.

### 3.2 Fixed 1-Second Debounce Has No Backoff

The `CONNECTION_LOST → RECONNECT_ATTEMPT` debounce is hardcoded at 1 second for all attempts. With `maxRetries: 2`, two restart attempts are made at approximately t=1s and t=5-7s from failure. There is no exponential backoff. If the network disruption is longer than 10-12 seconds total, the call is dropped without trying further.

**Impact**: Minor; for most transient failures 1-2 attempts within 10 s is sufficient. For longer outages (e.g., parking garage dead zones) exponential backoff would give the call a better chance of recovery.

### 3.3 Responder-Side State Machine Behavior

When the responder receives a `webrtc.offer` ICE restart signal while in `connected` phase, the hook correctly calls `setRemoteDescription` / `createAnswer` / `setLocalDescription`. However, the `handleRemoteOffer` path also dispatches `CONNECTION_LOST` to show a brief "reconnecting" UI. This transitions the responder to `reconnecting` and starts a 1-second timer, which fires `RECONNECT_ATTEMPT`. The responder's `retryCount` then increments. If the initiator sends two consecutive restart offers (e.g., due to a first offer timing out), the responder may exhaust its `maxRetries: 2` and enter `failure` before the ICE restart succeeds — even though it is only answering, not initiating.

**Impact**: Edge case; the responder's `maxRetries` counter being consumed by the act of answering restart offers is not the intended behavior. The responder should not increment its retry count when merely answering a remote restart offer.

### 3.4 TURN Credentials May Expire Before Restart

The TURN credential TTL is 600 seconds (`:1148`). If a call has been running for more than 10 minutes and the ICE failure occurs, `performIceRestart()` re-fetches TURN credentials before creating the offer (`:421-433`). However, if the re-fetch itself fails (network is down), the function catches the error and dispatches `CONNECTION_LOST` again — consuming a retry. The caller's browser may have no TURN server to route through during the fetch.

**Impact**: Low probability; the re-fetch uses the existing session auth (cookies), which works independently of the WebRTC data path.

---

## 4. Proposed Design / Fix

### 4.1 Auto-Send `call.end` on `failure` Phase

In `ConversationView.tsx`, add a `useEffect` that fires when `callMachine.phase === "failure"`:

```typescript
React.useEffect(() => {
  if (callMachine.phase === "failure" && callMachine.callId) {
    callActionMutation.mutate(
      { action: "end", callId: callMachine.callId, reason: "reconnect_failed" },
      { onSettled: () => { /* ignore errors — best-effort */ } },
    );
  }
}, [callMachine.phase]);
```

This sends `POST /messaging/messages/calls/{call_id}/end` with `reason: "reconnect_failed"` to notify the remote peer via SSE `call.end`, transition the backend session to `ended`, and trigger `teardownCallResources` on the remote side.

### 4.2 Optional Exponential Backoff

Replace the fixed 1-second debounce in `ConversationView.tsx:689-693` with:

```typescript
React.useEffect(() => {
  if (callMachine.phase !== "reconnecting") return;
  const delay = 1000 * Math.pow(2, callMachine.retryCount); // 1s, 2s, 4s
  const timer = window.setTimeout(() => dispatchCall({ type: "RECONNECT_ATTEMPT" }), delay);
  return () => window.clearTimeout(timer);
}, [callMachine.phase, callMachine.retryCount]);
```

With `maxRetries: 2` the total retry window becomes approximately 7 seconds — a better match for typical mobile network recovery.

### 4.3 Fix Responder Retry Counter

When the responder receives a `webrtc.offer` ICE restart (identified by `payload.iceRestart === true`), it should call `setRemoteDescription` and reply without dispatching `CONNECTION_LOST`. A brief "reconnecting" UI is still appropriate, but the dispatch should use a new event `PEER_RESTARTING` that transitions to `reconnecting` but does **not** increment `retryCount`. Add `PEER_RESTARTING` to `callStateMachine.ts` event union and reducer, distinct from `CONNECTION_LOST`.

### 4.4 Dev/Prod Parity (SECOPS-007)

All ICE restart logic is entirely client-side JavaScript — no backend paths differ between dev and prod. The TURN credential endpoint uses `S.messaging_webrtc_turn_enabled` (`:1145`), which is `false` by default in dev (no TURN server), so `performIceRestart()` in dev receives `null` from `fetchTurnCredentials` and skips the `setConfiguration` call (`:421-433`). The offer creation and signaling still proceed. This is correct SECOPS-007 behavior: same code path, feature-flag-selected behavior. No `dev_mode`-only branching exists in the ICE restart path.

### 4.5 Backward Compatibility

The `webrtc.offer` signaling event is already supported in `connected` state by `STATE_ALLOWED_SIGNALING_TYPES` (`:47-52`). No backend schema changes are required. The frontend state machine changes (`PEER_RESTARTING` event) are additive. Rollback is safe — removing the `PEER_RESTARTING` dispatch reverts to the current behavior.

---

## 5. Testing, Verification & Rollout

### 5.1 Pytest Unit Tests

No backend changes for this ticket. Existing `tests/test_call_signaling.py` (verify file exists) covers `STATE_ALLOWED_SIGNALING_TYPES` validation. Add:

- `test_webrtc_offer_allowed_in_connected_state`: Signal relay accepts `webrtc.offer` when `state=connected`.
- `test_turn_credentials_eligible_during_connected`: `GET /messages/calls/{id}/turn-credentials` returns 200 when `state=connected`.

**Mock setup**: moto DynamoDB; no real TURN server required.

### 5.2 Playwright E2E Tests

**File**: `frontend/e2e/webrtc-ice-restart.spec.ts` (777 lines, exists)

Scenarios to verify are present:
1. Simulate ICE `disconnected` state via `page.evaluate(() => window.__rtcPeerConnection.dispatchEvent(new Event("iceconnectionstatechange")))` with mocked `iceConnectionState = "disconnected"`. Overlay should remain in `connected` for 3 seconds (grace period), then transition to `reconnecting`.
2. ICE `failed` state triggers immediate `reconnecting` transition (no grace period).
3. Two successive failed restarts exhaust `maxRetries` and show "Call failed to reconnect." overlay.
4. Successful restart (ICE `connected` after `failed`) resets `retryCount` to 0 and shows `connected` overlay.
5. `NETWORK_OFFLINE` → `NETWORK_ONLINE` sequence does not consume a retry slot.
6. `TAB_HIDDEN` while in `reconnecting` transitions to `failure` on next `RECONNECT_ATTEMPT`.

**Additional E2E test needed**: After entering `failure`, verify that the remote peer receives a `call.end` SSE event and its overlay auto-dismisses (gap 4.1).

### 5.3 State Machine Unit Tests

`frontend/src/pages/messages/callStateMachine.test.ts` (202 lines) covers existing events. Add:
- `test_failure_after_max_retries`: Dispatch `CONNECTION_LOST`, then three `RECONNECT_ATTEMPT` events; verify machine reaches `failure`.
- `test_network_online_does_not_increment_retry`: Dispatch `NETWORK_OFFLINE`, then `NETWORK_ONLINE`; verify `retryCount` unchanged.

### 5.4 Manual QA Steps

1. Start a call between two browser windows on the same machine.
2. Open DevTools Network tab; throttle to "Offline" for 2 seconds.
3. Observe: overlay transitions to `reconnecting`, then `outgoing_connecting`, then back to `connected`.
4. Throttle to "Offline" for 15 seconds; observe both retries exhausted and "Call failed to reconnect." UI.
5. On mobile: initiate a call over Wi-Fi, then disable Wi-Fi mid-call to force cellular failover. Verify ICE restart succeeds within 10 seconds.

### 5.5 Metrics and Observability

Add `record_webrtc_ice_restart_attempt(outcome: str)` to `app/metrics.py` — `outcome` is `"success"`, `"exhausted"`, or `"aborted"`. Emit from `useRtcPeerConnection.ts` via a callback prop (same pattern as `onConnectionLost`). This feeds SECOPS-001 call quality dashboards.

### 5.6 Rollout and Rollback

ICE restart is feature-gated by `VITE_MESSAGING_WEBRTC_DIRECT_CALL_ENABLED`. The restart logic is activated only when a call is active. No DynamoDB schema changes required. Rollback by reverting `useRtcPeerConnection.ts` changes; the signaling backend is unaffected.

**Effort**: Gap 4.1 (auto-send `call.end` on failure): **S** (0.5 day). Gap 4.2 (exponential backoff): **S** (0.5 day). Gap 4.3 (responder retry counter): **M** (1.5 days, includes state machine changes and tests).
