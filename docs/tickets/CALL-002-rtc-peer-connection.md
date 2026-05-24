# CALL-002: Implement Frontend RTCPeerConnection Setup and Teardown

## 1. Overview & Motivation

### Purpose

This ticket covers implementing a React hook (`useRtcPeerConnection`) that bridges the existing call state machine (`callStateMachine.ts`) to a real browser `RTCPeerConnection`. Today the frontend has complete signaling infrastructure, call lifecycle management, and UI -- but the actual peer-to-peer media connection is simulated with a hardcoded `window.setTimeout(() => dispatchCall({ type: "REMOTE_ACCEPT" }), 700)` in `ConversationView.tsx` (line 530-531). This hook will replace that simulation with genuine WebRTC offer/answer exchange, ICE candidate trickle, TURN credential fetching, and media stream attachment.

### What the Hook Does

The hook encapsulates the full `RTCPeerConnection` lifecycle:

1. **Creates** an `RTCPeerConnection` with ICE servers obtained from `POST /messages/calls/{call_id}/turn-credentials`
2. **Generates** an SDP offer (caller) or answer (callee) and sends it via the signaling service
3. **Trickles** ICE candidates to the remote peer via `webrtc.ice_candidate` signaling events
4. **Receives** remote SDP and ICE candidates from the SSE stream (dispatched as `messaging:call-event` CustomEvents)
5. **Manages** local and remote `MediaStream` objects, attaching them to the `CallRuntimeResources` ref
6. **Monitors** `RTCPeerConnection.connectionState` and `iceConnectionState` to dispatch `CONNECT`, `CONNECTION_LOST`, and `FAIL` events to the state machine
7. **Tears down** cleanly on unmount or call end, delegating to the existing `teardownCallResources()` function

### Integration Scope

The hook will be consumed by `ConversationView.tsx` and will:
- Replace the fake `setTimeout` auto-accept on line 530-531
- Populate `callResourcesRef.current` with real `peerConnection`, `localStream`, and `remoteStream`
- Listen for incoming `webrtc.offer`, `webrtc.answer`, and `webrtc.ice_candidate` events already dispatched by `useMessagingStream.ts` (lines 69-77)
- Call the existing `teardownCallResources()` (line 163 of `callStateMachine.ts`) for cleanup

---

## 2. Current State Analysis

### What Exists

#### State Machine (`frontend/src/pages/messages/callStateMachine.ts`)

The state machine is fully implemented with 16 event types and 12 phases. Key types:

```typescript
// Line 4: Role discriminator
export type CallRole = "caller" | "callee";

// Lines 6-17: Full machine state
export interface CallMachineState {
  phase: CallUiState;
  role: CallRole | null;
  mode: DirectCallMode;        // "audio" | "video"
  callId?: string;
  peerName: string;
  retryCount: number;          // for reconnect attempts
  maxRetries: number;          // default 2
  isOnline: boolean;
  isTabVisible: boolean;
}
```

Critical events the RTCPeerConnection hook must dispatch:
- `CONNECT` -- when `RTCPeerConnection.connectionState === "connected"`
- `CONNECTION_LOST` -- when `connectionState === "disconnected"` or `"failed"`
- `FAIL` -- when ICE gathering or offer/answer exchange fails unrecoverably
- `RECONNECT_ATTEMPT` -- already triggered by a 1-second timer in `ConversationView.tsx` (line 477) when phase is `"reconnecting"`

#### Resource Interface (`callStateMachine.ts`, lines 154-161)

```typescript
export interface CallRuntimeResources {
  peerConnection?: { close: () => void } | null;
  localStream?: MediaStream | null;
  remoteStream?: MediaStream | null;
  detachListeners?: Array<() => void>;
  teardownTimers?: Array<number>;
  cleanedUp?: boolean;
}
```

This is the contract the hook must fulfill. The `teardownCallResources()` function (lines 163-186) already handles:
- Clearing timers via `window.clearTimeout`
- Invoking `detachListeners` callbacks
- Stopping all tracks on both streams
- Calling `peerConnection.close()`
- Setting `cleanedUp = true` for idempotency

#### Call UI (`frontend/src/pages/messages/CallSessionOverlay.tsx`)

A Dialog-based overlay rendering different states. It does not need modification for CALL-002 -- it already handles all phases. The `onAccept`, `onDecline`, `onEnd`, `onDismiss` callbacks wire through to the state machine dispatch in `ConversationView.tsx` (lines 969-1011).

#### SSE Event Dispatch (`frontend/src/hooks/useMessagingStream.ts`, lines 69-77)

All `call.*` events (including `webrtc.offer`, `webrtc.answer`, `webrtc.ice_candidate` per the backend `ALLOWED_SIGNALING_TYPES` set) are re-dispatched as `window` CustomEvents:

```typescript
if (eventType.startsWith("call.")) {
  window.dispatchEvent(
    new CustomEvent("messaging:call-event", {
      detail: { ...data, event_type: eventType },
    }),
  );
}
```

The `ConversationView.tsx` already listens to these (lines 558-591) and handles `call.invite`, `call.accept`, `call.decline`, `call.end`. The hook will add handling for `webrtc.offer`, `webrtc.answer`, and `webrtc.ice_candidate`.

#### API Endpoints (`frontend/src/api/endpoints/messaging.ts`, lines 253-284)

Existing call API functions:
- `createCallInvite(conversationId, body)` -- POST `/messages/calls/invite`
- `acceptCallInvite(callId, idempotency_key)` -- POST `/messages/calls/{callId}/accept`
- `declineCallInvite(callId, body)` -- POST `/messages/calls/{callId}/decline`
- `endCall(callId, body)` -- POST `/messages/calls/{callId}/end`

**Missing**: No frontend function for `POST /messages/calls/{call_id}/turn-credentials` or signaling relay.

#### Backend Signaling Service (`app/services/messaging_call_signaling.py`)

Fully implemented. Validates, rate-limits (nonce-based replay guard), and routes signaling events between participants. Allowed types (line 14-23):
- `call.invite`, `call.ring`, `call.accept`, `call.decline`, `call.end`
- `webrtc.offer`, `webrtc.answer`, `webrtc.ice_candidate`

State-gated signaling (lines 29-33):
- In `"accepted"` or `"connected"` states: `webrtc.offer`, `webrtc.answer`, `webrtc.ice_candidate`, `call.end` are allowed
- In `"invited"` state: only `call.*` lifecycle events

#### Backend TURN Credentials (`app/services/messaging_turn_credentials.py`)

Issues time-limited HMAC credentials per RFC 5766 / coturn convention:
- Username format: `{expires_at}:{actor_user_id}` (line 203)
- Credential: HMAC-SHA1 of username with shared secret (line 204)
- Validates: call exists, actor is participant, call state in `{"invited", "accepted", "connected"}` (line 15)
- Returns: `TurnCredentials(ttl_seconds, expires_at, ice_servers=[{urls, username, credential}])`

#### Backend TURN Endpoint (`app/routers/messaging.py`, line 12079-12101)

```
POST /messages/calls/{call_id}/turn-credentials
Response: { ttl_seconds, expires_at, ice_servers: [{ urls: string[], username, credential }] }
```

### What's Simulated (the Gap)

In `ConversationView.tsx` lines 528-535, after a successful `createCallInvite`:

```typescript
onSuccess: (res) => {
  dispatchCall({ type: "OUTGOING_RINGING", callId: res.call_id });
  window.setTimeout(() => {
    dispatchCall({ type: "REMOTE_ACCEPT" });   // <-- FAKE: auto-accepts after 700ms
  }, 700);
  callTimeoutRef.current = window.setTimeout(() => {
    dispatchCall({ type: "REMOTE_DECLINE", reason: "timeout" });
  }, 30_000);
},
```

This bypasses:
1. Fetching TURN credentials
2. Creating an `RTCPeerConnection`
3. Acquiring local media via `getUserMedia`
4. Creating/setting SDP offer
5. Sending offer via signaling
6. Receiving answer via SSE
7. Trickling ICE candidates
8. Monitoring connection state

On the **callee** side (lines 972-981), `onAccept` just calls the accept API and dispatches `CONNECT` on success -- no SDP answer creation occurs.

---

## 3. Technical Design

### 3.1 Hook API

```typescript
// frontend/src/hooks/useRtcPeerConnection.ts

interface UseRtcPeerConnectionParams {
  callId: string | undefined;
  conversationId: string;
  role: "caller" | "callee" | null;
  mode: "audio" | "video";
  phase: CallUiState;
  peerId: string;             // remote user_id for signaling
  userId: string;             // local user_id
  enabled: boolean;           // false when phase is idle/terminal
  onConnect: () => void;      // dispatch CONNECT
  onConnectionLost: (msg?: string) => void;  // dispatch CONNECTION_LOST
  onFail: (msg?: string) => void;            // dispatch FAIL
}

interface UseRtcPeerConnectionReturn {
  localStream: MediaStream | null;
  remoteStream: MediaStream | null;
  resources: CallRuntimeResources;
  iceGatheringState: RTCIceGatheringState | null;
  connectionState: RTCPeerConnectionState | null;
}
```

### 3.2 RTCPeerConnection Lifecycle

#### Caller Flow

```
1. phase transitions to "outgoing_ringing" (callId available)
2. Hook activates (enabled = true, role = "caller")
3. Fetch TURN credentials: POST /messages/calls/{callId}/turn-credentials
4. Create RTCPeerConnection with iceServers from TURN response
5. getUserMedia({ audio: true, video: mode === "video" })
6. Add local tracks to peerConnection
7. Create SDP offer → setLocalDescription
8. Send offer via signaling: POST /messages/calls/signaling
     { type: "webrtc.offer", call_id, conversation_id, sender_user_id, recipient_user_id,
       payload: { sdp: offer.sdp, type: offer.type }, nonce, sent_at, event_id, version: 1 }
9. Listen for "webrtc.answer" via messaging:call-event → setRemoteDescription
10. Trickle ICE: onicecandidate → send via signaling
11. Receive remote ICE candidates → addIceCandidate
12. connectionState === "connected" → onConnect()
```

#### Callee Flow

```
1. phase transitions to "incoming_ringing" (after user clicks Accept → "outgoing_connecting")
2. Hook activates (enabled = true, role = "callee")
3. Fetch TURN credentials
4. Create RTCPeerConnection with iceServers
5. getUserMedia
6. Listen for "webrtc.offer" via messaging:call-event → setRemoteDescription
7. Create SDP answer → setLocalDescription
8. Send answer via signaling: { type: "webrtc.answer", ... payload: { sdp, type } }
9. Trickle ICE (same as caller)
10. connectionState === "connected" → onConnect()
```

### 3.3 ICE Handling

```typescript
// onicecandidate handler
pc.onicecandidate = (event) => {
  if (event.candidate) {
    sendSignalingEvent({
      type: "webrtc.ice_candidate",
      call_id: callId,
      conversation_id: conversationId,
      sender_user_id: userId,
      recipient_user_id: peerId,
      payload: {
        candidate: event.candidate.candidate,
        sdpMid: event.candidate.sdpMid,
        sdpMLineIndex: event.candidate.sdpMLineIndex,
        usernameFragment: event.candidate.usernameFragment,
      },
      nonce: crypto.randomUUID(),
      sent_at: Math.floor(Date.now() / 1000),
      event_id: `ice_${crypto.randomUUID()}`,
      version: 1,
    });
  }
};

// Receiving remote ICE candidates
window.addEventListener("messaging:call-event", (event) => {
  const detail = event.detail;
  if (detail.event_type === "webrtc.ice_candidate" && detail.call_id === callId) {
    const candidate = new RTCIceCandidate(detail.payload);
    pc.addIceCandidate(candidate);
  }
});
```

ICE candidates received before `setRemoteDescription` must be queued in a buffer and applied once the remote description is set. This avoids `InvalidStateError`.

### 3.4 Connection State Monitoring

```typescript
pc.onconnectionstatechange = () => {
  switch (pc.connectionState) {
    case "connected":
      onConnect();
      break;
    case "disconnected":
      onConnectionLost("Peer connection interrupted.");
      break;
    case "failed":
      onConnectionLost("Peer connection failed.");
      break;
    case "closed":
      // No-op; teardown handles this
      break;
  }
};

pc.oniceconnectionstatechange = () => {
  if (pc.iceConnectionState === "failed") {
    // ICE restart attempt
    if (phase === "reconnecting" || phase === "outgoing_connecting") {
      pc.restartIce();
    }
  }
};
```

### 3.5 Reconnection Strategy

When `CONNECTION_LOST` fires, the state machine moves to `"reconnecting"`. The existing reconnect timer (ConversationView.tsx line 475-479) fires `RECONNECT_ATTEMPT` after 1 second. The hook responds to the phase changing back to `"outgoing_connecting"` (from reconnecting) by:

1. Calling `pc.restartIce()` (triggers new ICE gathering on existing connection)
2. Creating a new offer with `iceRestart: true`
3. Sending new offer via signaling
4. If this fails after `maxRetries` (2), state machine transitions to `"failure"`

### 3.6 New API Function (to add to `messaging.ts`)

```typescript
// frontend/src/api/endpoints/messaging.ts

export interface TurnIceServer {
  urls: string[];
  username: string;
  credential: string;
}

export interface TurnCredentialsResp {
  ttl_seconds: number;
  expires_at: number;
  ice_servers: TurnIceServer[];
}

export const fetchTurnCredentials = (callId: string) =>
  api.post<TurnCredentialsResp>(`/messages/calls/${callId}/turn-credentials`, {});
```

### 3.7 Signaling Relay Function

A new function to post signaling events (offer/answer/ICE) to the backend. The backend routing service (`messaging_call_signaling.py`) writes these to the Events table, and the SSE stream delivers them to the recipient.

```typescript
// frontend/src/api/endpoints/messaging.ts

export interface SignalingEnvelope {
  type: string;
  version: number;
  event_id: string;
  call_id: string;
  conversation_id: string;
  sender_user_id: string;
  recipient_user_id: string;
  nonce: string;
  sent_at: number;
  payload: Record<string, unknown>;
}

export const sendSignalingEvent = (envelope: SignalingEnvelope) =>
  api.post<{ event_id: string; status: string }>(
    `/messages/calls/${envelope.call_id}/signaling`,
    envelope
  );
```

Note: The backend signaling endpoint needs to be registered in `app/routers/messaging.py`. The service layer (`route_signaling_event`) exists but no HTTP endpoint currently exposes it. This is a prerequisite dependency (likely CALL-001 or a sub-task).

### 3.8 Media Stream Management

```typescript
async function acquireLocalMedia(mode: "audio" | "video"): Promise<MediaStream> {
  const constraints: MediaStreamConstraints = {
    audio: true,
    video: mode === "video" ? { facingMode: "user", width: { ideal: 1280 }, height: { ideal: 720 } } : false,
  };
  return navigator.mediaDevices.getUserMedia(constraints);
}
```

The remote stream is assembled from incoming tracks:

```typescript
const remoteStream = new MediaStream();
pc.ontrack = (event) => {
  for (const track of event.streams[0]?.getTracks() ?? event.tracks ?? []) {
    remoteStream.addTrack(track);
  }
  // Update ref so UI can render <video>/<audio> element
};
```

### 3.9 Integration Points with CallRuntimeResources

The hook populates the `callResourcesRef` in `ConversationView.tsx`:

```typescript
callResourcesRef.current = {
  peerConnection: pc,
  localStream,
  remoteStream,
  detachListeners: [
    () => window.removeEventListener("messaging:call-event", signalingHandler),
    () => { pc.onicecandidate = null; },
    () => { pc.ontrack = null; },
    () => { pc.onconnectionstatechange = null; },
    () => { pc.oniceconnectionstatechange = null; },
  ],
  teardownTimers: [],
  cleanedUp: false,
};
```

---

## 4. Implementation Plan

### 4.1 File Structure

```
frontend/src/
├── hooks/
│   └── useRtcPeerConnection.ts          # NEW: main hook
├── api/endpoints/
│   └── messaging.ts                      # MODIFIED: add fetchTurnCredentials, sendSignalingEvent
├── pages/messages/
│   ├── callStateMachine.ts              # MODIFIED: expand CallRuntimeResources type
│   ├── CallSessionOverlay.tsx           # UNCHANGED
│   └── ConversationView.tsx             # MODIFIED: consume hook, remove fake setTimeout
└── lib/
    └── webrtc.ts                         # NEW: utility functions (acquireMedia, ICE buffer)
```

### 4.2 Step-by-Step Implementation

#### Step 1: Add API Functions

**File**: `frontend/src/api/endpoints/messaging.ts`

Add after line 284 (after `endCall`):

```typescript
export interface TurnIceServer {
  urls: string[];
  username: string;
  credential: string;
}

export interface TurnCredentialsResp {
  ttl_seconds: number;
  expires_at: number;
  ice_servers: TurnIceServer[];
}

export const fetchTurnCredentials = (callId: string) =>
  api.post<TurnCredentialsResp>(`/messages/calls/${callId}/turn-credentials`, {});

export interface SignalingEnvelope {
  type: string;
  version: number;
  event_id: string;
  call_id: string;
  conversation_id: string;
  sender_user_id: string;
  recipient_user_id: string;
  nonce: string;
  sent_at: number;
  payload: Record<string, unknown>;
}

export interface SignalingAckResp {
  event_id: string;
  call_id: string;
  status: string;
}

export const sendSignalingEvent = (envelope: SignalingEnvelope) =>
  api.post<SignalingAckResp>(`/messages/calls/${envelope.call_id}/signaling`, envelope);
```

#### Step 2: Create WebRTC Utilities

**File**: `frontend/src/lib/webrtc.ts` (NEW)

```typescript
export async function acquireLocalMedia(mode: "audio" | "video"): Promise<MediaStream> {
  return navigator.mediaDevices.getUserMedia({
    audio: true,
    video: mode === "video" ? { facingMode: "user", width: { ideal: 1280 }, height: { ideal: 720 } } : false,
  });
}

export function createIceCandidateBuffer() {
  let buffer: RTCIceCandidateInit[] = [];
  let flushed = false;

  return {
    add(candidate: RTCIceCandidateInit) {
      if (flushed) return null; // Signal: apply immediately
      buffer.push(candidate);
      return candidate;
    },
    flush(pc: RTCPeerConnection) {
      flushed = true;
      const pending = buffer;
      buffer = [];
      return Promise.all(pending.map((c) => pc.addIceCandidate(new RTCIceCandidate(c))));
    },
  };
}

export function generateNonce(): string {
  return crypto.randomUUID().replace(/-/g, "").slice(0, 32);
}

export function generateEventId(prefix: string): string {
  return `${prefix}_${crypto.randomUUID()}`;
}
```

#### Step 3: Implement the Hook

**File**: `frontend/src/hooks/useRtcPeerConnection.ts` (NEW)

The hook is structured as a `useEffect` that activates when:
- `enabled === true` (i.e., phase is `"outgoing_ringing"` for caller, `"outgoing_connecting"` for callee)
- `callId` is defined
- `role` is non-null

Internal state machine within the effect:
1. Fetch TURN credentials
2. Create `RTCPeerConnection`
3. Acquire local media
4. Add tracks
5. (Caller) create offer, set local description, send via signaling
6. Listen for remote SDP and ICE via `messaging:call-event`
7. (Callee) on receiving offer: set remote description, create answer, send
8. Monitor connection state

Cleanup returns teardown of listeners, timers, and streams.

#### Step 4: Modify ConversationView.tsx

**File**: `frontend/src/pages/messages/ConversationView.tsx`

Changes:

1. **Import the hook** (after line 46):
   ```typescript
   import { useRtcPeerConnection } from "@/hooks/useRtcPeerConnection";
   ```

2. **Invoke the hook** (after line 86, near other call-related refs):
   ```typescript
   const rtcEnabled = callMachine.phase !== "idle" &&
     !["declined", "busy", "timeout", "ended", "failure"].includes(callMachine.phase);

   const { resources: rtcResources } = useRtcPeerConnection({
     callId: callMachine.callId,
     conversationId: convoId,
     role: callMachine.role,
     mode: callMachine.mode,
     phase: callMachine.phase,
     peerId: dmPartner?.user_id ?? "",
     userId: userId ?? "",
     enabled: rtcEnabled && !!callMachine.callId,
     onConnect: () => dispatchCall({ type: "CONNECT" }),
     onConnectionLost: (msg) => dispatchCall({ type: "CONNECTION_LOST", message: msg }),
     onFail: (msg) => dispatchCall({ type: "FAIL", message: msg }),
   });
   ```

3. **Wire resources ref** (after the hook call):
   ```typescript
   React.useEffect(() => {
     if (rtcResources) {
       callResourcesRef.current = rtcResources;
     }
   }, [rtcResources]);
   ```

4. **Remove fake auto-accept** (lines 530-532):
   Delete:
   ```typescript
   window.setTimeout(() => {
     dispatchCall({ type: "REMOTE_ACCEPT" });
   }, 700);
   ```
   The `REMOTE_ACCEPT` will now come from the SSE stream when the callee actually accepts (already handled at line 583).

5. **Remove auto-CONNECT on accept** (line 978):
   Change:
   ```typescript
   onSuccess: () => dispatchCall({ type: "CONNECT" }),
   ```
   to:
   ```typescript
   onSuccess: () => {
     // CONNECT will be dispatched by useRtcPeerConnection when
     // RTCPeerConnection.connectionState === "connected"
   },
   ```

#### Step 5: Update SSE Event Types

**File**: `frontend/src/hooks/useMessagingStream.ts`

Add to the `EVENT_TYPES` array (after line 105):
```typescript
"webrtc.offer",
"webrtc.answer",
"webrtc.ice_candidate",
```

These events are already handled by the generic `call.*` startsWith check (line 41 and 69), but explicitly listing them ensures `EventSource.addEventListener` is called for each type (line 119-121). Without explicit registration, typed SSE events with `event: webrtc.offer` would not fire `handleEvent`.

#### Step 6: Register Backend Signaling Endpoint

**File**: `app/routers/messaging.py` (add after line 12101)

```python
class SignalingEventIn(BaseModel):
    type: str
    version: int = 1
    event_id: str
    call_id: str
    conversation_id: str
    sender_user_id: str
    recipient_user_id: str
    nonce: str
    sent_at: int
    payload: dict = Field(default_factory=dict)

class SignalingAckOut(BaseModel):
    event_id: str
    call_id: str
    status: str

@router.post("/messages/calls/{call_id}/signaling", response_model=SignalingAckOut)
async def post_signaling_event(
    call_id: str,
    body: SignalingEventIn,
    user_id: str = Depends(get_messaging_user_id),
):
    from app.services.messaging_call_signaling import SignalingValidationError, route_signaling_event
    try:
        ack = route_signaling_event(envelope=body.model_dump(), actor_user_id=user_id)
        return SignalingAckOut(event_id=ack.event_id, call_id=ack.call_id, status=ack.status)
    except SignalingValidationError as exc:
        raise HTTPException(status_code=400, detail={"code": exc.code, "message": str(exc)})
```

### 4.3 Sequence Diagram (Caller Initiates)

```
Caller Browser          Backend SSE          Callee Browser
     |                      |                      |
     |--createCallInvite--->|---call.invite SSE--->|
     |<---call_id-----------|                      |
     |                      |<--acceptCallInvite---|
     |<--call.accept SSE----|                      |
     |                      |                      |
     |--fetchTurnCreds----->|                      |
     |<--iceServers---------|                      |
     |                      |   fetchTurnCreds---->|
     |                      |   <--iceServers------|
     |                      |                      |
     |  createOffer()       |                      |
     |--webrtc.offer------->|---webrtc.offer SSE-->|
     |                      |                      |  setRemoteDesc()
     |                      |                      |  createAnswer()
     |<--webrtc.answer SSE--|<---webrtc.answer-----|
     |  setRemoteDesc()     |                      |
     |                      |                      |
     |--ice_candidate------>|---ice_candidate SSE->|  addIceCandidate()
     |<--ice_candidate SSE--|<---ice_candidate-----|  addIceCandidate()
     |                      |                      |
     |  connectionState="connected"                |  connectionState="connected"
     |  dispatch(CONNECT)   |                      |  dispatch(CONNECT)
```

---

## 5. Testing Strategy

### 5.1 Unit Tests with Mocked RTCPeerConnection

**File**: `frontend/src/hooks/useRtcPeerConnection.test.ts`

Use Vitest + `@testing-library/react-hooks` (or `renderHook` from `@testing-library/react`). Mock `RTCPeerConnection` globally:

```typescript
class MockRTCPeerConnection {
  localDescription: RTCSessionDescription | null = null;
  remoteDescription: RTCSessionDescription | null = null;
  connectionState: RTCPeerConnectionState = "new";
  iceConnectionState: RTCIceConnectionState = "new";
  iceGatheringState: RTCIceGatheringState = "new";

  onicecandidate: ((event: RTCPeerConnectionIceEvent) => void) | null = null;
  ontrack: ((event: RTCTrackEvent) => void) | null = null;
  onconnectionstatechange: (() => void) | null = null;

  createOffer = vi.fn().mockResolvedValue({ type: "offer", sdp: "v=0\r\n..." });
  createAnswer = vi.fn().mockResolvedValue({ type: "answer", sdp: "v=0\r\n..." });
  setLocalDescription = vi.fn().mockResolvedValue(undefined);
  setRemoteDescription = vi.fn().mockResolvedValue(undefined);
  addIceCandidate = vi.fn().mockResolvedValue(undefined);
  addTrack = vi.fn();
  close = vi.fn();
  restartIce = vi.fn();

  // Helper to simulate state changes in tests
  simulateConnectionState(state: RTCPeerConnectionState) {
    this.connectionState = state;
    this.onconnectionstatechange?.();
  }
}
```

**Test cases**:

1. **Caller creates offer and sends via signaling**
   - Verify `createOffer()` called when role=caller and phase=outgoing_ringing
   - Verify `setLocalDescription()` called with the offer
   - Verify `sendSignalingEvent` called with type `"webrtc.offer"`

2. **Callee receives offer and sends answer**
   - Dispatch `messaging:call-event` with `event_type: "webrtc.offer"`
   - Verify `setRemoteDescription()` called with offer SDP
   - Verify `createAnswer()` called
   - Verify `sendSignalingEvent` called with type `"webrtc.answer"`

3. **ICE candidates trickled bidirectionally**
   - Trigger `onicecandidate` on mock PC → verify signaling POST
   - Dispatch `messaging:call-event` with `event_type: "webrtc.ice_candidate"` → verify `addIceCandidate` called

4. **ICE candidate buffering before remote description**
   - Send ICE candidate events before offer/answer exchange completes
   - Verify candidates are buffered (not applied)
   - After remote description set, verify buffered candidates are flushed

5. **Connection state monitoring**
   - Simulate `connectionState = "connected"` → verify `onConnect` callback fired
   - Simulate `connectionState = "disconnected"` → verify `onConnectionLost` callback fired
   - Simulate `connectionState = "failed"` → verify `onFail` callback fired

6. **TURN credential fetch failure**
   - Mock `fetchTurnCredentials` to reject → verify `onFail` dispatched

7. **getUserMedia permission denied**
   - Mock `navigator.mediaDevices.getUserMedia` to reject with `NotAllowedError`
   - Verify `onFail` dispatched with meaningful message

8. **Cleanup on unmount**
   - Render hook, then unmount → verify `pc.close()` called, tracks stopped

9. **ICE restart on reconnect**
   - Transition phase from `"connected"` to `"reconnecting"` back to `"outgoing_connecting"`
   - Verify `pc.restartIce()` called and new offer created with `iceRestart: true`

10. **Idempotent teardown**
    - Call teardown multiple times → verify no double-close errors

### 5.2 E2E Tests with Fake Media

**File**: `frontend/e2e/webrtc-calls.spec.ts`

Playwright supports granting media permissions and using fake media devices:

```typescript
const context = await browser.newContext({
  permissions: ["microphone", "camera"],
  // Chromium flag for fake media
  args: ["--use-fake-device-for-media-stream", "--use-fake-ui-for-media-stream"],
});
```

However, true peer-to-peer WebRTC in Playwright requires two browser contexts on the same machine -- which works because both connect to `localhost`. The backend signaling relay (via DynamoDB Events table + SSE) connects them.

**E2E test scenarios**:

1. **Audio call connects end-to-end** (caller + callee)
   - Alice starts audio call with Bob
   - Bob accepts
   - Both see "Connected" state
   - Alice ends call
   - Both see "Call ended" state

2. **Video call connects**
   - Same as above with mode=video
   - Verify video tracks present in remote stream

3. **Call declined by callee**
   - Alice starts call, Bob declines
   - Alice sees "Call declined" state

4. **Call timeout** (no answer within 30s)
   - Alice starts call, Bob does not accept
   - After 30s timeout, Alice sees "Call timed out"

5. **Network interruption simulated**
   - After connection established, simulate offline event on Alice's browser
   - Verify reconnecting state
   - Simulate online event
   - Verify reconnection attempt

6. **ICE restart after disconnection**
   - After connection, close the `RTCPeerConnection` on one side via `page.evaluate`
   - Verify the other side enters reconnecting state and attempts ICE restart

**Note on E2E limitations**: Full WebRTC E2E tests require the signaling endpoint (`POST /messages/calls/{call_id}/signaling`) to be implemented. Until then, E2E tests can verify the UI flow up to the "Connecting..." state using mocked API responses via `page.route()`.

### 5.3 Edge Cases to Test

| Edge Case | Expected Behavior |
|-----------|-------------------|
| `getUserMedia` not available (HTTP, no camera) | `onFail` with "Media devices unavailable" |
| TURN credentials expired mid-call | ICE restart fetches fresh credentials |
| Offer received before local media acquired | Buffer offer, apply after media ready |
| Browser tab backgrounded during ICE gathering | Continue gathering (browsers throttle but don't stop) |
| Peer sends offer but callee hasn't accepted via API yet | Buffer offer until phase is `outgoing_connecting` |
| Multiple rapid offer/answer exchanges (glare) | Use `signalingState` to detect and handle rollback |
| `RTCPeerConnection` constructor throws (CSP blocks) | Catch, dispatch FAIL |
| TURN server unreachable | `iceConnectionState = "failed"` after timeout, dispatch FAIL |
| Call ended while ICE still gathering | `teardownCallResources` stops everything cleanly |
| Component unmounts during `getUserMedia` prompt | AbortController cancels; cleanup fires |

### 5.4 SDP Offer/Answer Glare Handling

If both peers simultaneously create an offer (e.g., during ICE restart), the "polite peer" pattern should be implemented:

```typescript
// Caller is always the "impolite" peer (their offer wins)
// Callee is always the "polite" peer (rolls back own offer if collision)
const isPolite = role === "callee";

// On receiving an offer when we have a pending local offer:
if (pc.signalingState === "have-local-offer" && isPolite) {
  await pc.setLocalDescription({ type: "rollback" });
  await pc.setRemoteDescription(remoteOffer);
  const answer = await pc.createAnswer();
  await pc.setLocalDescription(answer);
  // Send answer
}
```

### 5.5 Performance Metrics (Future)

The hook should emit timing metrics for observability:
- Time from hook activation to `connectionState === "connected"` (ICE + DTLS total)
- TURN credential fetch latency
- Number of ICE candidates exchanged
- Whether final connection is relay (TURN) or direct (STUN/host)

These can be sent to the existing metrics endpoint or logged to console in dev mode. The backend already has `TURN_CREDENTIAL_ISSUE_LATENCY` and `messaging_webrtc_signaling_latency_seconds` histograms (defined in `app/metrics.py` lines 706-751), so frontend timing complements server-side observability.

---

## Appendix: Key File References

| File | Lines | What |
|------|-------|------|
| `frontend/src/pages/messages/callStateMachine.ts` | 1-186 | State machine, events, reducer, `CallRuntimeResources`, `teardownCallResources` |
| `frontend/src/pages/messages/CallSessionOverlay.tsx` | 1-124 | Call UI overlay (Dialog) |
| `frontend/src/pages/messages/ConversationView.tsx` | 83-86, 466-612, 636-647, 717-738, 969-1011 | Call integration, fake setTimeout (530-531), SSE listener, UI buttons, overlay wiring |
| `frontend/src/hooks/useMessagingStream.ts` | 41, 69-77, 102-105 | SSE call event dispatch |
| `frontend/src/api/endpoints/messaging.ts` | 242-284 | Call API types and functions |
| `frontend/src/lib/featureFlags.ts` | 35-79 | WebRTC feature flag gating |
| `app/services/messaging_call_signaling.py` | 1-335 | Backend signaling validation and routing |
| `app/services/messaging_call_sessions.py` | 1-159 | Call session DDB CRUD |
| `app/services/messaging_turn_credentials.py` | 1-222 | TURN credential issuance (HMAC-SHA1) |
| `app/routers/messaging.py` | 12036-12101 | TURN credential HTTP endpoint |
| `app/routers/messaging.py` | 12104-12218 | Call lifecycle HTTP endpoints (invite/accept/decline/end) |
| `frontend/src/pages/messages/callStateMachine.test.ts` | 1-83 | Existing unit tests for state machine |
