# CALL-003: Implement getUserMedia Capture with Permission Handling

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

## 5. Testing Strategy

### 5.1 Unit Tests (Vitest)

<!-- NOTE: This file does not exist yet — new implementation required. -->
**File**: `frontend/src/hooks/useMediaCapture.test.ts` (new, proposed path updated)

Mock `navigator.mediaDevices` globally:

```ts
const mockGetUserMedia = vi.fn();
const mockEnumerateDevices = vi.fn();

Object.defineProperty(navigator, "mediaDevices", {
  value: {
    getUserMedia: mockGetUserMedia,
    enumerateDevices: mockEnumerateDevices,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
  },
  writable: true,
});
```

**Test cases**:

1. **Happy path -- audio mode**: `acquire("audio")` calls `getUserMedia({ audio: true, video: false })`, returns stream, sets status to "active".
2. **Happy path -- video mode**: `acquire("video")` calls `getUserMedia({ audio: true, video: {...} })`, returns stream with both audio and video tracks.
3. **Permission denied**: Mock `getUserMedia` rejecting with `new DOMException("Permission denied", "NotAllowedError")`. Assert status becomes "denied", error.type is "NotAllowedError".
4. **Device not found**: Mock rejection with `NotFoundError`. Assert status is "not_found".
5. **Device in use**: Mock rejection with `NotReadableError`. Assert status is "error", message mentions "in use".
6. **Overconstrained fallback**: First call rejects with `OverconstrainedError`, second call (relaxed constraints) succeeds. Assert final status is "active".
7. **Release stops tracks**: Call `release()` after successful acquire. Assert all track `stop()` methods were called.
8. **Toggle mute**: After acquire, call `toggleMute()`. Assert `audioTrack.enabled` is toggled.
9. **Toggle camera**: After acquire in video mode, call `toggleCamera()`. Assert `videoTrack.enabled` is toggled.
10. **API not available**: Delete `navigator.mediaDevices`. Assert status is "error" with appropriate message.

### 5.2 Integration Tests (Vitest -- ConversationView)

**File**: `frontend/src/pages/messages/ConversationView.call_flows.test.tsx` (extend)

Add test cases that verify media acquisition is called at the right state transitions:

```ts
it("acquires audio media before sending call invite", async () => {
  mockGetUserMedia.mockResolvedValue(createMockStream("audio"));
  createCallInvite.mockResolvedValue({ call_id: "call-1" });
  renderView();
  
  await user.click(screen.getByRole("button", { name: "Start audio call" }));
  
  expect(mockGetUserMedia).toHaveBeenCalledWith({ audio: true, video: false });
  expect(createCallInvite).toHaveBeenCalled(); // Only after media acquired
});

it("does not send invite if getUserMedia fails", async () => {
  mockGetUserMedia.mockRejectedValue(new DOMException("", "NotAllowedError"));
  renderView();
  
  await user.click(screen.getByRole("button", { name: "Start audio call" }));
  
  expect(createCallInvite).not.toHaveBeenCalled();
  expect(screen.getByText(/could not access/i)).toBeInTheDocument();
});

it("acquires media when accepting incoming call", async () => {
  mockGetUserMedia.mockResolvedValue(createMockStream("video"));
  acceptCallInvite.mockResolvedValue({ call_id: "incoming-1" });
  renderView();
  
  // Simulate incoming call event
  act(() => {
    window.dispatchEvent(new CustomEvent("messaging:call-event", {
      detail: { event_type: "call.invite", conversation_id: "c1", call_id: "incoming-1", caller_user_id: "u2", callee_user_id: "u1", mode: "video" },
    }));
  });
  
  await user.click(screen.getByRole("button", { name: "Accept call" }));
  
  expect(mockGetUserMedia).toHaveBeenCalledWith({ audio: true, video: expect.objectContaining({ width: expect.any(Object) }) });
});
```

### 5.3 E2E Tests (Playwright)

<!-- NOTE: IMPLEMENTED — frontend/e2e/webrtc-media.spec.ts (1375 lines) already exists. -->
**File**: `frontend/e2e/webrtc-media.spec.ts`

Playwright supports mocking `getUserMedia` via `page.addInitScript()` and `browserContext.grantPermissions()`:

```ts
// Grant microphone + camera permissions to avoid browser prompts
const context = await browser.newContext({
  permissions: ["microphone", "camera"],
});

// Or mock getUserMedia entirely:
await page.addInitScript(() => {
  const createFakeStream = () => {
    const audioTrack = { kind: "audio", enabled: true, stop: () => {}, id: "fake-audio" };
    const videoTrack = { kind: "video", enabled: true, stop: () => {}, id: "fake-video" };
    return {
      getTracks: () => [audioTrack, videoTrack],
      getAudioTracks: () => [audioTrack],
      getVideoTracks: () => [videoTrack],
      addTrack: () => {},
      removeTrack: () => {},
    };
  };
  navigator.mediaDevices.getUserMedia = async () => createFakeStream() as any;
  navigator.mediaDevices.enumerateDevices = async () => [
    { deviceId: "default", kind: "audioinput", label: "Default Mic", groupId: "g1", toJSON: () => ({}) },
    { deviceId: "cam1", kind: "videoinput", label: "HD Webcam", groupId: "g2", toJSON: () => ({}) },
  ];
});
```

**Test scenarios for E2E**:

1. **Section 78.1 -- Audio call acquires microphone**: Start an audio call, verify `getUserMedia` was called with audio-only constraints (via a flag set by the init script mock).
2. **Section 78.2 -- Video call acquires camera + mic**: Start a video call, verify both tracks exist.
3. **Section 78.3 -- Permission denied aborts call**: Override `getUserMedia` to throw `NotAllowedError`, click call button, verify the call state shows failure and no invite API call is made.
4. **Section 78.4 -- Mute toggle during connected call**: Mock a connected state, click mute button, verify the audio track's `enabled` property is false.
5. **Section 78.5 -- Camera toggle during video call**: Same pattern for video track.
6. **Section 78.6 -- Device enumeration shows available devices**: Navigate to call settings/in-call menu, verify device list matches mocked `enumerateDevices` results.
7. **Section 78.7 -- Tracks stopped on call end**: End a call, verify all track `stop()` methods were invoked (assert via counter in mock).
8. **Section 78.8 -- Callee media failure sends decline**: Accept an incoming call with `getUserMedia` mocked to fail, verify a decline API call is sent.

### 5.4 Testing Permission Denied Flows

The permission denied state is the most critical UX scenario. Test matrix:

| Scenario | Expected Behavior | Assertion |
|----------|------------------|-----------|
| First-ever call, user denies prompt | Call transitions to "failure", toast shown | `screen.getByText(/denied/i)`, `createCallInvite` not called |
| Previously denied (remembered by browser) | `getUserMedia` rejects immediately (no prompt) | Same as above, but near-instant |
| Denied during incoming accept | Backend receives decline with media_failed reason | `declineCallInvite` called |
| Camera denied but mic allowed (video call) | Degrade to audio-only, show warning toast | `toast.warning(...)`, stream has audio track only |
| All devices removed mid-call | `track.onended` fires | Dispatch `FAIL` to state machine |

### 5.5 Testing Device Enumeration

```ts
it("re-enumerates devices after permission is granted", async () => {
  // Before permission: labels are empty
  mockEnumerateDevices.mockResolvedValue([
    { deviceId: "a1", kind: "audioinput", label: "", groupId: "g1" },
  ]);
  
  const { result } = renderHook(() => useMediaDevices());
  expect(result.current.audioInputs[0].label).toBe("");
  
  // After getUserMedia succeeds: labels populate
  mockEnumerateDevices.mockResolvedValue([
    { deviceId: "a1", kind: "audioinput", label: "Built-in Mic", groupId: "g1" },
  ]);
  
  await act(async () => {
    await mediaCapture.acquire("audio");
  });
  
  // useMediaDevices should re-query after permission grant
  expect(result.current.audioInputs[0].label).toBe("Built-in Mic");
});

it("handles devicechange event (hot-plug)", async () => {
  const { result } = renderHook(() => useMediaDevices());
  expect(result.current.audioInputs).toHaveLength(1);
  
  // Simulate USB mic plugged in
  mockEnumerateDevices.mockResolvedValue([
    { deviceId: "a1", kind: "audioinput", label: "Built-in Mic", groupId: "g1" },
    { deviceId: "a2", kind: "audioinput", label: "USB Mic", groupId: "g2" },
  ]);
  
  await act(async () => {
    navigator.mediaDevices.dispatchEvent(new Event("devicechange"));
  });
  
  expect(result.current.audioInputs).toHaveLength(2);
});
```

### 5.6 Test File Organization

| File | Scope | Framework |
|------|-------|-----------|
| `frontend/src/hooks/useMediaCapture.test.ts` | Hook logic in isolation (does not exist yet) | Vitest |
| `frontend/src/hooks/useMediaDevices.test.ts` | Device enumeration hook (does not exist yet) | Vitest |
| `frontend/src/pages/messages/ConversationView.call_flows.test.tsx` | Integration with state machine (extend existing) | Vitest + RTL |
| `frontend/e2e/webrtc-media.spec.ts` | Full browser integration, permission flows | Playwright |

All unit tests mock `navigator.mediaDevices` at the module level. E2E tests use Playwright's `browserContext.grantPermissions()` for happy paths and `page.addInitScript()` overrides for failure simulation.

---

## 6. Error Handling Matrix

| Error Scenario | Browser Error | User-Facing Message | Recovery Action |
|----------------|--------------|---------------------|-----------------|
| Permission denied | `NotAllowedError` | "Camera/mic permission denied. Please allow access in browser settings." | Show permission instructions dialog |
| Device not found | `NotFoundError` | "No camera/microphone found." | Show device troubleshooting tips |
| Device in use | `NotReadableError` | "Camera/mic is in use by another app." | Suggest closing other apps |
| Overconstrained | `OverconstrainedError` | "Requested quality not supported by device." | Fall back to lower resolution |
| Secure context required | `NotAllowedError` (HTTP) | "Secure connection (HTTPS) required for media access." | Redirect to HTTPS |
| getUserMedia not supported | `TypeError` | "Your browser does not support media capture." | Suggest Chrome/Firefox |
| Track ended unexpectedly | `ended` event | "Media device disconnected." | Attempt re-acquisition |

---

## 7. Observability & Monitoring

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `webrtc_get_user_media_total` | Counter | `result={success,denied,error}` | getUserMedia attempts |
| `webrtc_get_user_media_duration_ms` | Histogram | -- | Time to acquire media |
| `webrtc_device_change_total` | Counter | -- | Device hotplug events |
| `webrtc_track_ended_total` | Counter | `kind={audio,video}` | Unexpected track ends |
| `webrtc_permission_prompt_total` | Counter | `result={granted,denied}` | Permission prompt outcomes |

---

## 8. Performance Considerations

| Concern | Mitigation |
|---------|-----------|
| getUserMedia blocks UI thread | Async call; show spinner during acquisition |
| Multiple rapid device changes | Debounce devicechange listener (500ms) |
| High-resolution video on weak devices | Start with 720p; downgrade on OverconstrainedError |
| Memory leak from unreleased tracks | stopAllTracks() in cleanup; ref-count tracks per component |
| Enumeration on every mount | Cache device list for 5 seconds; refresh on devicechange |

---

## 9. Rollout Plan

| Flag | Default | Description |
|------|---------|-------------|
| `WEBRTC_VIDEO_ENABLED` | `true` | Enable video capture (audio always on) |
| `WEBRTC_SCREEN_SHARE_ENABLED` | `false` | Enable screen sharing |
| `WEBRTC_HD_VIDEO_ENABLED` | `false` | Allow 1080p requests (vs 720p max) |

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
