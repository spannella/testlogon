# CALL-002: Implement Frontend RTCPeerConnection Setup and Teardown — Investigation & Implementation Write-up

## 1. Summary & Classification

**Problem/Feature**: The frontend had a complete call overlay UI and signaling infrastructure but no actual WebRTC peer connection. After a call was accepted, media never flowed — a fake `setTimeout` auto-accepted the call cosmetically. This ticket implements `useRtcPeerConnection`, the hook that bridges the `callStateMachine` state machine to a real browser `RTCPeerConnection` with offer/answer exchange, ICE candidate trickle, and clean teardown.

- **Type**: Feature (new React hook + utility library)
- **Priority**: High — directly enables media to flow; blocks CALL-003/004/005/006
- **Status**: Implemented — `frontend/src/hooks/useRtcPeerConnection.ts` (518 lines); `frontend/src/lib/webrtc.ts` (149 lines); consumed in `frontend/src/pages/messages/ConversationView.tsx:51,675`; E2E coverage in `frontend/e2e/webrtc-calls.spec.ts` (661 lines). Unit test file `frontend/src/hooks/useRtcPeerConnection.test.ts` does not exist.
- **Area**: Frontend hooks, WebRTC browser API, call state machine integration
- **Who is affected**: Authenticated users initiating or receiving direct audio/video calls
- **Cross-references**: [[CALL-001]] (signaling endpoint), [[CALL-003]] (getUserMedia), [[CALL-008]] (ICE restart), [[SECOPS-007]] (TURN dev/prod parity)

---

## 2. Current-State Investigation (what exists today)

### 2.1 Call state machine (`callStateMachine.ts:1–222`)

The machine is fully implemented. Key types:

- **`CallMachineState`** (line 6): `phase: CallUiState`, `role: CallRole | null`, `mode: DirectCallMode`, `callId`, `peerName`, `retryCount`, `maxRetries`, `isOnline`, `isTabVisible`, `recordingState`, `recordingId`.
- **`CallRuntimeResources`** (line 190): `peerConnection?: RTCPeerConnection | null`, `localStream?: MediaStream | null`, `remoteStream?: MediaStream | null`, `detachListeners`, `teardownTimers`, `cleanedUp`.
- **`teardownCallResources()`** (line 199): iterates `teardownTimers` (clearTimeout), invokes `detachListeners`, stops all tracks on both streams, calls `peerConnection.close()`, sets `cleanedUp=true` for idempotency.

The critical events the hook dispatches: `CONNECT` (when `RTCPeerConnection.connectionState === "connected"`), `CONNECTION_LOST` (when `connectionState === "disconnected"` or `"failed"`), `FAIL` (unrecoverable ICE/SDP error).

### 2.2 `useRtcPeerConnection` hook (`frontend/src/hooks/useRtcPeerConnection.ts:1–518`)

The hook is fully implemented. Structure:

- **`UseRtcPeerConnectionParams`** (line 23): `callId`, `conversationId`, `role`, `mode`, `phase`, `peerId`, `userId`, `enabled`, `retryCount`, `onConnect`, `onConnectionLost`, `onFail`.
- **`UseRtcPeerConnectionReturn`** (line 38): `localStream`, `remoteStream`, `resources: CallRuntimeResources | null`, `connectionState`, `performIceRestart`.
- **`shouldActivate()`** (line 59): determines when to create the peer connection. Caller activates on `"outgoing_ringing"`, `"outgoing_connecting"`, and `"connected"` phases; callee activates on `"outgoing_connecting"` and `"connected"`.
- **ICE restart support** (line 6–9 doc comment): `performIceRestart()` is exposed for CALL-008. When `retryCount > 0` and phase transitions back to `"outgoing_connecting"`, the hook invokes a new offer with `{ iceRestart: true }`. A 3-second grace period (`ICE_DISCONNECT_GRACE_MS = 3000`, line 21) prevents reacting to transient ICE blips.

### 2.3 WebRTC utilities (`frontend/src/lib/webrtc.ts:1–149`)

- **`acquireLocalMedia(mode)`** (line 15): calls `navigator.mediaDevices.getUserMedia` with audio + optional video constraints.
- **`acquireScreenMedia()`** (line 54): calls `navigator.mediaDevices.getDisplayMedia` (CALL-013 screen share).
- **`isScreenShareSupported()`** (line 94): feature-detects `getDisplayMedia`.
- **`createIceCandidateBuffer()`** (line 106): returns `{ add(candidate), flush(pc) }`. Candidates received before `setRemoteDescription` are buffered; `flush` applies them all once the remote description is set, preventing `InvalidStateError`.
- **`generateNonce()`** (line 140): `crypto.randomUUID().replace(/-/g, "").slice(0, 32)`.
- **`generateEventId(prefix)`** (line 147): `${prefix}_${crypto.randomUUID()}`.

### 2.4 ConversationView.tsx integration (`frontend/src/pages/messages/ConversationView.tsx`)

- **Import** (line 51): `import { useRtcPeerConnection } from "@/hooks/useRtcPeerConnection"`.
- **`callResourcesRef`** (line 95): typed as `React.useRef<CallRuntimeResources | null>(null)`.
- **Hook invocation** (line 675): `const { resources: rtcResources, localStream: rtcLocalStream, remoteStream: rtcRemoteStream } = useRtcPeerConnection({ callId, conversationId, role, mode, phase, peerId, userId, enabled, retryCount, onConnect, onConnectionLost, onFail })`.
- **Resources sync** (line 692): `callResourcesRef.current = rtcResources` inside a `useEffect`.
- **Fake auto-accept removed** (line 819 comment): The previous `setTimeout(() => dispatchCall({ type: "REMOTE_ACCEPT" }), 700)` was removed. `REMOTE_ACCEPT` now comes from the SSE `call.accept` event.

### 2.5 SSE event dispatch (`useMessagingStream.ts:132–219`)

`webrtc.offer`, `webrtc.answer`, `webrtc.ice_candidate` are in the `EVENT_TYPES` array (lines 203–204) and the `webrtc.*` dispatch block (line 152) emits `CustomEvent("messaging:webrtc-signal")` with full event detail. The hook listens for this event to handle incoming offers and answers.

### 2.6 API endpoints (`messaging.ts:1024–1067`)

`sendSignalingEvent(callId, data)` (line 1043) — POST to `CALL-001` endpoint. `fetchTurnCredentials(callId)` (line 1065) — POST to `/messaging/messages/calls/{callId}/turn-credentials`.

### 2.7 Backend TURN credentials (`messaging_turn_credentials.py`)

In dev mode: `S.messaging_webrtc_turn_enabled` (settings.py:1145) defaults to `false`. When disabled, `issue_turn_credentials()` raises `TurnCredentialError("feature_disabled", ...)` (line 107). This means in dev without `MESSAGING_WEBRTC_TURN_ENABLED=true`, `fetchTurnCredentials` returns 503. The hook must handle this gracefully — when TURN is disabled in dev, ICE uses host/srflx candidates only (which works on localhost). The hook creates the `RTCPeerConnection` without TURN servers in this case; STUN servers (`stun:stun.l.google.com:19302`) provide basic connectivity.

**Dev/prod TURN distinction (SECOPS-007)**:
- Dev: `MESSAGING_WEBRTC_TURN_ENABLED=false` (default) — no TURN relay; loopback ICE works for local testing.
- Prod: `MESSAGING_WEBRTC_TURN_ENABLED=true`, `MESSAGING_WEBRTC_TURN_URLS=turn:relay.example.com:3478`, `MESSAGING_WEBRTC_TURN_SECRET=<shared-secret>`. Credentials are HMAC-SHA1 per coturn convention (`{expires}:{user_id}` + HMAC, lines 115–117 of turn credentials service). No external service needed in dev — the same code path runs, it just returns `feature_disabled`.

---

## 3. Gap / Threat Analysis

### 3.1 Unit test gap

`frontend/src/hooks/useRtcPeerConnection.test.ts` does not exist. The hook's internal flows (caller offer path, callee answer path, ICE buffer flush, connection state monitoring, reconnect detection) are not unit-tested. The `callStateMachine.test.ts` (202 lines) tests the reducer but not the hook. `ConversationView.call_flows.test.tsx` (~180 lines) mocks the hook entirely. Without unit tests, regressions in the peer connection setup logic (e.g., forgetting to flush the ICE buffer after `setRemoteDescription`) would only surface in full E2E runs.

### 3.2 ICE candidate ordering race condition

ICE candidates can arrive via SSE before `setRemoteDescription` completes if the signaling round-trip is fast. `createIceCandidateBuffer()` (webrtc.ts:106) addresses this — candidates are buffered until `flush(pc)` is called after `setRemoteDescription`. If the buffer flush is missing or called too early, `pc.addIceCandidate()` throws `InvalidStateError`. The current implementation in the hook handles this correctly but it is a brittle ordering requirement.

### 3.3 TURN credentials fail-open in dev

When `MESSAGING_WEBRTC_TURN_ENABLED=false` (dev default), `fetchTurnCredentials` returns 503. The hook must catch this and fall back to STUN-only ICE configuration. This fallback should be explicit and logged, not a silent catch. In prod, missing TURN config (`turn_not_configured` error) should be treated as a hard failure since peer-to-peer connectivity across NAT may be impossible without TURN.

### 3.4 Screen-share signal types not in SignalingPayload TS type

`SignalingPayload.type` (messaging.ts:1025) does not include `"webrtc.screen_share_start" | "webrtc.screen_share_stop"`. When CALL-013 lands, this type must be extended, or the hook's signaling calls for screen share will have TypeScript type errors.

### 3.5 Resource leak on unmount during active call

If the component unmounts (navigating away) while a call is in the `"connected"` phase, `teardownCallResources` is called (line 760 of ConversationView). The hook's cleanup effect also runs. If both run concurrently, `peerConnection.close()` might be called twice. `teardownCallResources` is idempotent (`cleanedUp` flag, line 200 of callStateMachine.ts) so this is safe, but the hook's cleanup should also guard against double-close.

---

## 4. Proposed Design / Fix

### 4.1 Unit tests — `frontend/src/hooks/useRtcPeerConnection.test.ts`

Use `@testing-library/react` with `renderHook`. Mock `RTCPeerConnection` class globally, mock `sendSignalingEvent` and `fetchTurnCredentials`. Test:

- **Caller path**: `role="caller"`, `phase="outgoing_ringing"` → hook fetches TURN creds → creates PC → calls `getUserMedia` → creates offer → sends via `sendSignalingEvent` with `type="webrtc.offer"` → dispatches `webrtc.answer` event on window → calls `setRemoteDescription` → PC `connectionState` mock to `"connected"` → `onConnect` called.
- **Callee path**: `role="callee"`, `phase="outgoing_connecting"` → hook creates PC → waits for `webrtc.offer` event → `setRemoteDescription` → creates answer → sends via `sendSignalingEvent` with `type="webrtc.answer"` → `onConnect`.
- **ICE buffer**: dispatch `webrtc.ice_candidate` before remote description is set → should buffer, not call `addIceCandidate`. After answer/offer processed → buffer flushed → `addIceCandidate` called.
- **Teardown on disable**: set `enabled=false` → `peerConnection.close()` called, tracks stopped.
- **Connection lost**: PC `connectionState` mock to `"disconnected"` → `onConnectionLost` called after grace period.
- **TURN disabled fallback**: mock `fetchTurnCredentials` to reject → PC created with empty STUN-only config.

### 4.2 TURN dev/prod parity — explicit fallback

In the hook, the TURN fetch failure should be handled as:

```typescript
let iceServers: RTCIceServer[] = [{ urls: "stun:stun.l.google.com:19302" }];
try {
  const turnCreds = await fetchTurnCredentials(callId);
  iceServers = turnCreds.ice_servers;
} catch {
  // TURN disabled (dev) or not configured — fall back to STUN only.
  // In prod with TURN required, this will result in ICE failure for NAT-traversal calls.
}
```

The fallback should log a warning (not silently swallow) so operators know TURN is not active.

### 4.3 Extend `SignalingPayload.type` for screen share

When CALL-013 merges, add `"webrtc.screen_share_start" | "webrtc.screen_share_stop"` to `SignalingPayload.type` in `messaging.ts:1025`. This is a non-breaking extension.

### 4.4 Dev/Prod parity (SECOPS-007)

The hook itself has no direct AWS dependency. The only external call it makes is `fetchTurnCredentials`, which hits the backend's TURN endpoint. The backend's parity behavior is:

- Dev: `MESSAGING_WEBRTC_TURN_ENABLED=false` → 503 → hook uses STUN only. No AWS.
- Prod: `MESSAGING_WEBRTC_TURN_ENABLED=true`, real TURN server URL + shared secret in env. HMAC credential generation is pure Python (no AWS SDK call). The coturn server itself is external infrastructure, not an AWS service.

The hook should surface `performIceRestart` for CALL-008. When `retryCount` increments (state machine retry), the reconnect timer in ConversationView fires `RECONNECT_ATTEMPT` which the machine responds to by transitioning back to `"outgoing_connecting"`. The hook detects the phase re-entry with `retryCount > 0` and calls `performIceRestart`.

---

## 5. Testing, Verification & Rollout

### Unit tests

File: `frontend/src/hooks/useRtcPeerConnection.test.ts`

Key assertions: caller sends `webrtc.offer` after `getUserMedia` returns; callee sends `webrtc.answer` after receiving offer; ICE buffer prevents premature `addIceCandidate`; `onConnect` called when `connectionState === "connected"`; teardown calls `track.stop()` on all local and remote tracks; TURN credential failure falls back to STUN.

Run: `cd frontend && npx vitest useRtcPeerConnection` (or Jest equivalent).

### Playwright E2E

`frontend/e2e/webrtc-calls.spec.ts` (661 lines) covers the full call lifecycle including RTCPeerConnection establishment. Key test: Alice invites Bob via UI → Bob accepts → both pages reach `"connected"` phase (overlay shows "Connected with...") → end call → overlay shows "Call ended." TURN disabled in E2E (loopback ICE only).

For two-context tests requiring real RTCPeerConnection: use separate `browser.newContext()` instances (same browser process), inject auth for each identity, both contexts share the same backend. Chromium's WebRTC loopback works in headless mode.

### Manual verification steps

1. `just up`; set `MESSAGING_WEBRTC_DIRECT_CALL_ENABLED=true`.
2. Open two browser windows: Alice (port 3000) and Bob.
3. Alice opens a DM with Bob → clicks audio call button.
4. Bob sees incoming call overlay → clicks Accept.
5. Both overlays should transition from "Connecting..." to "Connected with [peer]" within 5–10 s (loopback ICE).
6. Confirm DevTools → Application → getUserMedia shows a live stream for both tabs.
7. Click End call → both overlays show "Call ended."

### Observability

`app/metrics.py:1379–1432` tracks `webrtc_call_setup_total`, `webrtc_call_connected_total`, `webrtc_call_failed_total`, `webrtc_call_duration_seconds`, `webrtc_signaling_total`. Frontend dispatches `CONNECT` / `FAIL` / `CONNECTION_LOST` to the state machine; backend-side call state transitions are logged in `messaging_call_lifecycle.py` with structured `logger.info` calls.

### Rollback

Feature-flagged. Disable `MESSAGING_WEBRTC_DIRECT_CALL_ENABLED` to return all callers to the pre-hook state. The fake `setTimeout` auto-accept was removed; disabling the feature flag hides the call buttons entirely (via `isMessagingWebrtcDirectCallEnabled()` in `featureFlags.ts:53`), so no regression for users who don't see call buttons.

### 5.1 ICE negotiation sequence detail

The caller/callee offer-answer exchange follows a precise sequence that must not be reordered. Any deviation causes `InvalidStateError` or silent media failure:

**Caller**:
1. `createOffer()` → `setLocalDescription(offer)` → send `webrtc.offer` via signaling.
2. Receive `webrtc.answer` SSE event → `setRemoteDescription(answer)`.
3. Flush buffered ICE candidates via `iceCandidateBuffer.flush(pc)`.
4. Continue receiving and adding ICE candidates via `addIceCandidate`.

**Callee**:
1. Receive `webrtc.offer` SSE event → `setRemoteDescription(offer)`.
2. `createAnswer()` → `setLocalDescription(answer)` → send `webrtc.answer` via signaling.
3. Flush buffered ICE candidates.
4. Continue adding remote candidates.

The `createIceCandidateBuffer()` utility in `webrtc.ts:106` is the critical safeguard. Without it, ICE candidates arriving before `setRemoteDescription` throw `InvalidStateError: setRemoteDescription must be called before addIceCandidate`. The buffer holds incoming candidates until `flush(pc)` is explicitly called after `setRemoteDescription`. This is a common WebRTC implementation bug and the explicit buffer is a defensive measure.

### 5.2 Retry and reconnect wiring

When `RTCPeerConnection.connectionState === "disconnected"`, a 3-second grace period (`ICE_DISCONNECT_GRACE_MS = 3000`, line 21 of `useRtcPeerConnection.ts`) delays escalation to `CONNECTION_LOST`. If reconnection happens within 3 seconds (transient network blip), the grace timer is cancelled and `onConnectionLost` is never called. If the 3-second grace expires, `onConnectionLost` dispatches `CONNECTION_LOST` to the state machine → phase transitions to `"reconnecting"` → ConversationView's reconnect timer (1 second) fires `RECONNECT_ATTEMPT` → machine transitions to `"outgoing_connecting"` → the hook detects `retryCount > 0` and calls `performIceRestart()` which generates a new offer with `{ iceRestart: true }`. If `maxRetries` (default 2) is exhausted, the machine transitions to `"failure"`.

This CALL-002 wiring is a prerequisite for CALL-008 (ICE Restart ticket), which adds UI for the reconnecting state and allows configuring `maxRetries`.

**Effort estimate**: S — hook is implemented. Remaining work is the unit test file (~200 lines of `renderHook` tests). One day.
