# CALL-003: Implement getUserMedia Capture with Permission Handling

**Status**: Implemented

## 1. Overview & Motivation

### Problem Statement

The WebRTC direct call system currently has a complete signaling layer (invite/accept/decline/end lifecycle via `app/services/messaging_call_lifecycle.py`), a frontend state machine (`frontend/src/pages/messages/callStateMachine.ts`), and a call overlay UI (`frontend/src/pages/messages/CallSessionOverlay.tsx`). <!-- NOTE: The useMediaCapture hook is now IMPLEMENTED at frontend/src/hooks/useMediaCapture.ts (315 lines). The useMediaDevices hook exists at frontend/src/hooks/useMediaDevices.ts (107 lines). getUserMedia is called via acquireLocalMedia() in frontend/src/lib/webrtc.ts:15. ConversationView.tsx imports and uses useMediaCapture at lines 50 and 94. The E2E test file exists at frontend/e2e/webrtc-media.spec.ts (1375 lines). Unit test files for the hooks do NOT exist yet. -->

The `localStream` and `remoteStream` fields on `CallRuntimeResources` (lines 191-193 of `callStateMachine.ts`, see `frontend/src/pages/messages/callStateMachine.ts:190`) are now populated by the `useRtcPeerConnection` hook and `useMediaCapture` hook.

### Audio vs Video Modes

The backend defines two call modes via `CallMode = Literal["audio", "video"]` in `app/services/messaging_call_sessions.py` (line 8) (see `app/services/messaging_call_sessions.py:8`). The frontend mirrors this as `DirectCallMode = "audio" | "video"` in `frontend/src/api/endpoints/messaging.ts`. The mode is set at invite creation time via the `initial_mode` parameter and persists on `CallSessionRecord.initial_mode`.

The frontend state machine carries this as `CallMachineState.mode` (line 9 of `callStateMachine.ts`, see `frontend/src/pages/messages/callStateMachine.ts:9`), set during `START_OUTGOING` or `INCOMING_INVITE` events. The `CallSessionOverlay` (see `frontend/src/pages/messages/CallSessionOverlay.tsx`) reads this to display mode-appropriate UI copy and icons.

Media capture constraints differ by mode:
- **Audio mode**: `{ audio: true, video: false }` -- microphone only.
- **Video mode**: `{ audio: true, video: true }` -- microphone + camera.

### Why This Matters

Without `getUserMedia`, the entire call flow is purely cosmetic. The state machine progresses through visual states (ringing, connecting, connected) but no real-time communication occurs. CALL-003 bridges this gap by acquiring local media tracks that CALL-002 (RTCPeerConnection) will attach to the peer connection for transmission.

---

## 2. Current State Analysis

### Existing Media Infrastructure

<!-- NOTE: MediaStream usage is now widespread. Key locations:
- callStateMachine.ts:191-193 — CallRuntimeResources type
- useRtcPeerConnection.ts:85-86 — localStream/remoteStream state
- useMediaCapture.ts:125 — stream state
- lib/webrtc.ts:15 — acquireLocalMedia() calls getUserMedia
- ConversationView.tsx:94 — mediaCapture hook usage
-->

`CallRuntimeResources` (see `frontend/src/pages/messages/callStateMachine.ts:190`):
```ts
export interface CallRuntimeResources {
  peerConnection?: RTCPeerConnection | null;
  localStream?: MediaStream | null;
  remoteStream?: MediaStream | null;
  detachListeners?: Array<() => void>;
  teardownTimers?: Array<number>;
  cleanedUp?: boolean;
}
```

`getUserMedia()` is called via `acquireLocalMedia()` in `frontend/src/lib/webrtc.ts:15`. The `useMediaCapture` hook (see `frontend/src/hooks/useMediaCapture.ts:124`) wraps this with permission handling and error categorization.

### Existing Permission Patterns (Reference Implementation)

The closest permission-request pattern in the codebase is in `frontend/src/pages/alerts/PushDevices.tsx` (lines 51-62) (see `frontend/src/pages/alerts/PushDevices.tsx:51`), which handles `Notification.requestPermission()`:

```ts
const handleEnable = async () => {
  if (!("Notification" in window)) {
    toast.error("Push notifications are not supported in this browser");
    return;
  }
  setEnabling(true);
  try {
    let permission = Notification.permission;
    if (permission === "default") {
      permission = await Notification.requestPermission();
    }
    if (permission !== "granted") {
      toast.error("Notification permission denied");
      return;
    }
    // ... proceed with registration
  } catch {
    toast.error("Failed to enable push notifications");
  } finally {
    setEnabling(false);
  }
};
```

This pattern (check API availability -> check existing permission state -> request if "default" -> handle denial gracefully -> show toast on error) should be adapted for `getUserMedia`.

### Call Flow Integration Points

The `ConversationView.tsx` (see `frontend/src/pages/messages/ConversationView.tsx`) creates the call state machine:
```ts
const [callMachine, dispatchCall] = React.useReducer(callStateReducer, undefined, createInitialCallMachineState);
```

Media capture should be triggered at specific state transitions:
- **Outgoing call (caller)**: After `START_OUTGOING` dispatches, `mediaCapture.acquire(mode)` is called at line 737 of `ConversationView.tsx` before `callMutation.mutate()`. The caller needs local media ready before signaling.
- **Incoming call (callee)**: After user clicks Accept, `mediaCapture.acquire(callMachine.mode)` is called at line 1294 of `ConversationView.tsx`.

The `startOutgoingCall` function (see `frontend/src/pages/messages/ConversationView.tsx:737`) is the caller-side entry point. The `onAccept` prop at line 1290 is the callee-side entry point.

### Feature Flag Gating

WebRTC calls are gated by `isMessagingWebrtcDirectCallEnabled()` from `frontend/src/lib/featureFlags.ts` (line 53) (see `frontend/src/lib/featureFlags.ts:53`). This function checks:
- `VITE_MESSAGING_WEBRTC_DIRECT_CALL_ENABLED` (master toggle)
- `VITE_MESSAGING_WEBRTC_DIRECT_CALL_KILL_SWITCH` (emergency off)
- `VITE_MESSAGING_WEBRTC_DIRECT_CALL_MODE` (rollout mode: enabled/disabled/selective/internal)
- Tenant and cohort allow-lists for gradual rollout

The `callsEnabled` computed value in `ConversationView.tsx` determines whether call buttons render.

### Teardown Path

The `teardownCallResources` function (lines 199-222 of `callStateMachine.ts`, see `frontend/src/pages/messages/callStateMachine.ts:199`) already handles stopping tracks:
```ts
for (const stream of [resources.localStream, resources.remoteStream]) {
  for (const track of stream?.getTracks() ?? []) {
    track.stop();
  }
}
```

This ensures that once media is acquired, it will be properly released on call end, failure, or component unmount. Teardown is triggered when the machine reaches terminal states.

---

## 3. Technical Design

### 3.1 Media Capture Hook: `useMediaCapture`

<!-- NOTE: IMPLEMENTED at frontend/src/hooks/useMediaCapture.ts (315 lines), not at the proposed path. -->
The hook at `frontend/src/hooks/useMediaCapture.ts` (see line 124) encapsulates all `getUserMedia` logic:

```ts
export interface MediaCaptureState {
  status: "idle" | "requesting" | "active" | "denied" | "not_found" | "error";
  localStream: MediaStream | null;
  error: MediaCaptureError | null;
  audioTrack: MediaStreamTrack | null;
  videoTrack: MediaStreamTrack | null;
}

export interface MediaCaptureError {
  type: "NotAllowedError" | "NotFoundError" | "NotReadableError" | "OverconstrainedError" | "AbortError" | "unknown";
  message: string;
  originalError?: unknown;
}

export interface MediaCaptureActions {
  acquire: (mode: DirectCallMode) => Promise<MediaStream | null>;
  release: () => void;
  toggleMute: () => boolean; // returns new muted state
  toggleCamera: () => boolean; // returns new camera-off state
  switchAudioDevice: (deviceId: string) => Promise<void>;
  switchVideoDevice: (deviceId: string) => Promise<void>;
}
```

### 3.2 Permission Request Flow

The capture flow must handle multiple failure modes from the getUserMedia API:

```
acquire(mode) called
    |
    v
[Check navigator.mediaDevices exists]
    |-- No --> status: "error", type: "unknown", message: "Media devices API not available"
    |
    v
[Build constraints from mode]
    |-- audio: { audio: true, video: false }
    |-- video: { audio: true, video: { width: { ideal: 1280 }, height: { ideal: 720 } } }
    |
    v
[Call getUserMedia(constraints)]
    |-- Success --> status: "active", populate localStream/audioTrack/videoTrack
    |-- NotAllowedError --> status: "denied"
    |-- NotFoundError --> status: "not_found"
    |-- NotReadableError --> status: "error" (device in use by another app)
    |-- OverconstrainedError --> retry with relaxed constraints
    |-- AbortError --> status: "error"
    |
    v
[If video mode + video fails but audio succeeds]
    --> Degrade to audio-only, emit warning toast
```

### 3.3 Error Handling Strategy

Each `getUserMedia` error maps to a user-facing message:

| Error Name | User Message | Recovery Action |
|------------|-------------|-----------------|
| `NotAllowedError` | "Microphone/camera access denied. Check your browser permissions." | Show permission settings link; abort call |
| `NotFoundError` | "No microphone/camera found. Connect a device and try again." | Abort call |
| `NotReadableError` | "Your microphone/camera is in use by another application." | Abort call or retry |
| `OverconstrainedError` | (silent) | Retry with relaxed constraints (remove resolution hints) |
| `AbortError` | "Media capture was interrupted." | Abort call |

For the **caller** (outgoing call), if media acquisition fails:
- Do NOT send the call invite to the backend.
- Dispatch `FAIL` event to the state machine with a descriptive message.
- Show a toast with the error explanation.

For the **callee** (incoming call), if media acquisition fails after accepting:
- Send a `decline` to the backend with `reason: "failed"` (new reason code).
- Dispatch `FAIL` event locally.
- Show a toast explaining the failure.

### 3.4 Track Management

**Mute/Unmute (Audio)**:
```ts
toggleMute(): boolean {
  const audioTrack = localStream?.getAudioTracks()[0];
  if (!audioTrack) return true;
  audioTrack.enabled = !audioTrack.enabled;
  return !audioTrack.enabled; // true = muted
}
```

Setting `track.enabled = false` silences the track without releasing it. The track remains attached to the peer connection, sending silence frames. This avoids renegotiation.

**Camera Toggle (Video)**:
```ts
toggleCamera(): boolean {
  const videoTrack = localStream?.getVideoTracks()[0];
  if (!videoTrack) return true;
  videoTrack.enabled = !videoTrack.enabled;
  return !videoTrack.enabled; // true = camera off
}
```

Same pattern -- disabling the video track sends black frames to the remote peer without renegotiation.

**Device Switching**:
When the user switches to a different microphone or camera mid-call:
1. Call `navigator.mediaDevices.getUserMedia()` with the new `deviceId` constraint.
2. Get the new track from the returned stream.
3. Replace the track on the RTCPeerConnection sender via `sender.replaceTrack(newTrack)` (CALL-002 integration).
4. Stop the old track.
5. Update `localStream` by removing old track and adding new one.

### 3.5 Device Enumeration

Create a companion hook `useMediaDevices` that provides available input devices:

```ts
export interface MediaDeviceInfo {
  deviceId: string;
  label: string; // empty string if permission not yet granted
  kind: "audioinput" | "videoinput" | "audiooutput";
}

export function useMediaDevices() {
  const [devices, setDevices] = useState<MediaDeviceInfo[]>([]);
  
  // Listen for devicechange events (USB mic plugged in/out)
  useEffect(() => {
    const update = async () => {
      const list = await navigator.mediaDevices.enumerateDevices();
      setDevices(list.filter(d => d.kind !== "audiooutput"));
    };
    update();
    navigator.mediaDevices.addEventListener("devicechange", update);
    return () => navigator.mediaDevices.removeEventListener("devicechange", update);
  }, []);

  return {
    audioInputs: devices.filter(d => d.kind === "audioinput"),
    videoInputs: devices.filter(d => d.kind === "videoinput"),
  };
}
```

Note: `enumerateDevices()` returns devices with empty labels until the user has granted permission at least once. The hook should re-enumerate after a successful `getUserMedia()` call to populate labels.

### 3.6 Constraints Construction

```ts
function buildConstraints(mode: DirectCallMode, preferredAudioId?: string, preferredVideoId?: string): MediaStreamConstraints {
  const audio: MediaTrackConstraints = preferredAudioId
    ? { deviceId: { exact: preferredAudioId } }
    : true;

  if (mode === "audio") {
    return { audio, video: false };
  }

  const video: MediaTrackConstraints = {
    width: { ideal: 1280, max: 1920 },
    height: { ideal: 720, max: 1080 },
    frameRate: { ideal: 30, max: 30 },
    ...(preferredVideoId ? { deviceId: { exact: preferredVideoId } } : {}),
  };

  return { audio, video };
}
```

The `ideal` constraints allow the browser to select the closest matching resolution without failing on devices that cannot produce exactly 1280x720.

---

## 4. Implementation Plan

### 4.1 Phase 1: Core Capture Hook

<!-- NOTE: IMPLEMENTED — frontend/src/hooks/useMediaCapture.ts (315 lines). Exports useMediaCapture() at line 124. -->
**File**: `frontend/src/hooks/useMediaCapture.ts`

Responsibilities:
- Expose `acquire(mode)`, `release()`, `toggleMute()`, `toggleCamera()`.
- Track permission state via a `status` field.
- Return the `MediaStream` for attachment to `CallRuntimeResources.localStream`.
- Handle all error cases from Section 3.2.

### 4.2 Phase 2: Integration with Call State Machine

**File**: `frontend/src/pages/messages/ConversationView.tsx`

<!-- NOTE: IMPLEMENTED — see ConversationView.tsx:737-749 for outgoing call media acquisition and ConversationView.tsx:1290-1304 for incoming call accept. -->
**Outgoing call flow** (see `frontend/src/pages/messages/ConversationView.tsx:737`):

```ts
const startOutgoingCall = async (mode: DirectCallMode) => {
  if (!dmPartner || !callsEnabled) return;
  clearCallTimeout();
  dispatchCall({ type: "START_OUTGOING", mode, peerName: dmPartner.display_name ?? dmPartner.user_id });
  
  // CALL-003: Acquire media BEFORE sending invite
  const stream = await mediaCapture.acquire(mode);
  if (!stream) {
    // Permission denied or device not found -- abort
    dispatchCall({ type: "FAIL", message: mediaCapture.error?.message ?? "Could not access microphone/camera." });
    return;
  }
  
  // Attach to runtime resources
  // NOTE: callResourcesRef is now typed as CallRuntimeResources | null (see ConversationView.tsx:92).
  callResourcesRef.current = {
    ...callResourcesRef.current,
    localStream: stream,
    cleanedUp: false,
  };
  
  // Now proceed with signaling
  callMutation.mutate({ mode, calleeUserId: dmPartner.user_id, conversationId: convoId }, { ... });
};
```

**Incoming call flow** (modify `onAccept` handler):

<!-- NOTE: IMPLEMENTED at ConversationView.tsx:1290-1304 -->
The `onAccept` callback at `ConversationView.tsx:1290` acquires media before dispatching:

```ts
const handleAcceptCall = async () => {
  const stream = await mediaCapture.acquire(callMachine.mode);
  if (!stream) {
    // Cannot acquire media -- decline the call
    if (callMachine.callId) {
      callActionMutation.mutate({ action: "decline", callId: callMachine.callId });
    }
    dispatchCall({ type: "FAIL", message: mediaCapture.error?.message ?? "Could not access microphone/camera." });
    toast.error("Call failed: could not access your microphone.");
    return;
  }
  
  callResourcesRef.current = {
    ...callResourcesRef.current,
    localStream: stream,
    cleanedUp: false,
  };
  
  dispatchCall({ type: "LOCAL_ACCEPT" });
  if (callMachine.callId) {
    callActionMutation.mutate({ action: "accept", callId: callMachine.callId });
  }
};
```

### 4.3 Phase 3: State Machine Extension

Add a new event to `CallMachineEvent` (in `callStateMachine.ts`):

```ts
| { type: "MEDIA_ACQUIRED" }
| { type: "MEDIA_FAILED"; message?: string }
```

And a new transient phase `"acquiring_media"` between `outgoing_inviting` and `outgoing_ringing` (for caller) and between `incoming_ringing` and `outgoing_connecting` (for callee):

```ts
// New phase in CallUiState:
| "acquiring_media"
```

This allows the overlay UI to show "Requesting camera access..." while the browser permission dialog is displayed, preventing the user from clicking Accept/Cancel while the prompt is active.

### 4.4 Phase 4: UI Controls for Mute/Camera Toggle

<!-- NOTE: IMPLEMENTED — CallSessionOverlay.tsx (671 lines) already has isMuted/isCameraOff props (lines 50-51), CallControls component (line 167) with Mic/MicOff and Video/VideoOff buttons, and screen share toggle. -->

**File**: `frontend/src/pages/messages/CallSessionOverlay.tsx` (see line 167)

```tsx
{isConnected && (
  <>
    <Button variant={isMuted ? "secondary" : "ghost"} size="icon" onClick={onToggleMute} aria-label={isMuted ? "Unmute" : "Mute"}>
      {isMuted ? <MicOff className="h-4 w-4" /> : <Mic className="h-4 w-4" />}
    </Button>
    {session.mode === "video" && (
      <Button variant={isCameraOff ? "secondary" : "ghost"} size="icon" onClick={onToggleCamera} aria-label={isCameraOff ? "Turn camera on" : "Turn camera off"}>
        {isCameraOff ? <VideoOff className="h-4 w-4" /> : <Video className="h-4 w-4" />}
      </Button>
    )}
    <Button variant="destructive" onClick={onEnd} disabled={isBusy} aria-label="End call">
      <PhoneOff className="mr-2 h-4 w-4" />
      End call
    </Button>
  </>
)}
```

New props on `CallSessionOverlay`:
```ts
interface Props {
  // ... existing
  isMuted?: boolean;
  isCameraOff?: boolean;
  onToggleMute?: () => void;
  onToggleCamera?: () => void;
}
```

### 4.5 Phase 5: Device Enumeration UI

<!-- NOTE: useMediaDevices hook IMPLEMENTED at frontend/src/hooks/useMediaDevices.ts (107 lines). -->
Device selector integrates with `useMediaDevices` (see `frontend/src/hooks/useMediaDevices.ts`).

### 4.6 Phase 6: Integration with CALL-002 (RTCPeerConnection)

Once CALL-002 provides the `RTCPeerConnection`, the local stream's tracks are added:

```ts
const pc = new RTCPeerConnection(iceConfig);

// Add all local tracks to the connection
for (const track of localStream.getTracks()) {
  pc.addTrack(track, localStream);
}

// Receive remote tracks
pc.ontrack = (event) => {
  callResourcesRef.current.remoteStream = event.streams[0];
  // Attach to <audio> or <video> element for playback
};
```

Device switching mid-call uses `RTCRtpSender.replaceTrack()`:
```ts
const sender = pc.getSenders().find(s => s.track?.kind === "audio");
if (sender) await sender.replaceTrack(newAudioTrack);
```

### 4.7 Timing Diagram

```
Outgoing Call (Caller):
  User clicks "Start audio call"
    -> dispatchCall(START_OUTGOING)           [phase: outgoing_inviting]
    -> mediaCapture.acquire("audio")          [phase: acquiring_media]
    -> getUserMedia({audio:true, video:false})
    -> Browser shows permission prompt (if first time)
    -> Permission granted, stream returned
    -> callResourcesRef.localStream = stream
    -> callMutation.mutate(invite)            [phase: outgoing_ringing]
    -> Backend creates call session
    -> SSE: call.accept from callee
    -> dispatchCall(REMOTE_ACCEPT)            [phase: connected]
    -> CALL-002: addTrack to RTCPeerConnection

Incoming Call (Callee):
  SSE: call.invite received
    -> dispatchCall(INCOMING_INVITE)          [phase: incoming_ringing]
    -> User clicks Accept
    -> mediaCapture.acquire(mode)             [phase: acquiring_media]
    -> getUserMedia(constraints)
    -> Permission granted
    -> callResourcesRef.localStream = stream
    -> dispatchCall(LOCAL_ACCEPT)             [phase: outgoing_connecting]
    -> callActionMutation(accept)
    -> CALL-002: establish peer connection
    -> dispatchCall(CONNECT)                  [phase: connected]
```

---

## Testing Strategy

### Unit Tests (pytest)

**Test file**: `tests/test_call_3.py`

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

**Test file**: `frontend/e2e/call-3.spec.ts`

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
| CALL-002 | RTCPeerConnection hook for track attachment | Implemented | No -- must merge after |

### Depended On By

| Ticket | What It Needs |
|---|---|
| CALL-004 | Local/remote MediaStream for rendering |
| CALL-005 | Local media tracks for mute/camera controls |

### Merge Strategy

Sequential after CALL-002. Frontend hook only. No backend changes.

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
| `frontend/src/hooks/useMediaCapture.ts` | 1-315 | Media capture hook (IMPLEMENTED) |
| `frontend/src/hooks/useMediaCapture.ts` | 124 | `useMediaCapture()` export |
| `frontend/src/hooks/useMediaCapture.ts` | 72 | `categorizeError()` — DOMException error classification |
| `frontend/src/hooks/useMediaCapture.ts` | 50 | `buildConstraints()` — audio/video constraints builder |
| `frontend/src/hooks/useMediaDevices.ts` | 1-107 | Device enumeration hook (IMPLEMENTED) |
| `frontend/src/lib/webrtc.ts` | 15 | `acquireLocalMedia()` — getUserMedia wrapper |
| `frontend/src/lib/webrtc.ts` | 54 | `acquireScreenMedia()` — getDisplayMedia wrapper |
| `frontend/src/pages/messages/callStateMachine.ts` | 190-222 | `CallRuntimeResources` interface + `teardownCallResources()` |
| `frontend/src/pages/messages/callStateMachine.ts` | 6-20 | `CallMachineState` interface |
| `frontend/src/pages/messages/CallSessionOverlay.tsx` | 1-671 | Call UI overlay with mute/camera/recording/screenshare controls |
| `frontend/src/pages/messages/CallSessionOverlay.tsx` | 167 | `CallControls` component (Mic/MicOff, Video/VideoOff buttons) |
| `frontend/src/pages/messages/ConversationView.tsx` | 50 | `useMediaCapture` import |
| `frontend/src/pages/messages/ConversationView.tsx` | 94 | `mediaCapture` hook invocation |
| `frontend/src/pages/messages/ConversationView.tsx` | 737-749 | Outgoing call — acquire media before invite |
| `frontend/src/pages/messages/ConversationView.tsx` | 1290-1304 | Incoming call — acquire media on accept |
| `frontend/src/hooks/useRtcPeerConnection.ts` | 159-183 | `acquireLocalMedia()` call + addTrack to RTCPeerConnection |
| `frontend/src/lib/featureFlags.ts` | 53 | `isMessagingWebrtcDirectCallEnabled()` |
| `frontend/src/pages/alerts/PushDevices.tsx` | 51-62 | Notification.requestPermission() pattern (reference) |
| `app/services/messaging_call_sessions.py` | 8 | `CallMode = Literal["audio", "video"]` |
| `frontend/e2e/webrtc-media.spec.ts` | 1-1375 | E2E media capture tests (IMPLEMENTED) |
| `frontend/src/hooks/useMediaCapture.test.ts` | — | Does not exist yet — unit tests needed |
| `frontend/src/hooks/useMediaDevices.test.ts` | — | Does not exist yet — unit tests needed |
