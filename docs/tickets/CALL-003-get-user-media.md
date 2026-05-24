# CALL-003: Implement getUserMedia Capture with Permission Handling

## 1. Overview & Motivation

### Problem Statement

The WebRTC direct call system currently has a complete signaling layer (invite/accept/decline/end lifecycle via `app/services/messaging_call_lifecycle.py`), a frontend state machine (`frontend/src/pages/messages/callStateMachine.ts`), and a call overlay UI (`frontend/src/pages/messages/CallSessionOverlay.tsx`). However, there is **no `getUserMedia()` call anywhere in the frontend codebase**. The call system transitions through `outgoing_inviting -> outgoing_ringing -> connected -> ended` states without ever acquiring microphone or camera access from the user's device.

This means:
- No audio is captured or transmitted during an "audio" call.
- No video is captured or transmitted during a "video" call.
- The `localStream` and `remoteStream` fields on `CallRuntimeResources` (line 155-157 of `callStateMachine.ts`) are never populated.
- The `teardownCallResources()` function correctly stops tracks and closes the peer connection, but is operating on null streams.

### Audio vs Video Modes

The backend defines two call modes via `CallMode = Literal["audio", "video"]` in `app/services/messaging_call_sessions.py` (line 8). The frontend mirrors this as `DirectCallMode = "audio" | "video"` in `frontend/src/api/endpoints/messaging.ts` (line 242). The mode is set at invite creation time via the `initial_mode` parameter and persists on `CallSessionRecord.initial_mode`.

The frontend state machine carries this as `CallMachineState.mode` (line 9 of `callStateMachine.ts`), set during `START_OUTGOING` or `INCOMING_INVITE` events. The `CallSessionOverlay` reads this to display mode-appropriate UI copy ("Incoming video call" vs "Incoming audio call") and icons (`Video` vs `PhoneCall`).

Media capture constraints differ by mode:
- **Audio mode**: `{ audio: true, video: false }` -- microphone only.
- **Video mode**: `{ audio: true, video: true }` -- microphone + camera.

### Why This Matters

Without `getUserMedia`, the entire call flow is purely cosmetic. The state machine progresses through visual states (ringing, connecting, connected) but no real-time communication occurs. CALL-003 bridges this gap by acquiring local media tracks that CALL-002 (RTCPeerConnection) will attach to the peer connection for transmission.

---

## 2. Current State Analysis

### Existing Media Infrastructure

The codebase has exactly **two references** to `MediaStream` in the frontend:

1. **`callStateMachine.ts` lines 156-157** -- Type declarations on `CallRuntimeResources`:
   ```ts
   export interface CallRuntimeResources {
     peerConnection?: { close: () => void } | null;
     localStream?: MediaStream | null;
     remoteStream?: MediaStream | null;
     detachListeners?: Array<() => void>;
     teardownTimers?: Array<number>;
     cleanedUp?: boolean;
   }
   ```

2. **`callStateMachine.test.ts` lines 65-66** -- Test mocks that cast plain objects to `MediaStream`:
   ```ts
   localStream: { getTracks: () => [{ stop: stopLocal1 }, { stop: stopLocal2 }] } as unknown as MediaStream,
   remoteStream: { getTracks: () => [{ stop: stopRemote }] } as unknown as MediaStream,
   ```

There is **no** `navigator.mediaDevices.getUserMedia()` call, no `enumerateDevices()`, no `MediaStreamConstraints` construction, and no permission request handling anywhere in `frontend/src/`.

### Existing Permission Patterns (Reference Implementation)

The closest permission-request pattern in the codebase is in `frontend/src/pages/alerts/PushDevices.tsx` (lines 46-74), which handles `Notification.requestPermission()`:

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

The `ConversationView.tsx` (line 83) creates the call state machine:
```ts
const [callMachine, dispatchCall] = React.useReducer(callStateReducer, undefined, createInitialCallMachineState);
```

Media capture should be triggered at specific state transitions:
- **Outgoing call (caller)**: After `START_OUTGOING` dispatches (line 520), before the `callMutation.mutate()` call (line 521). The caller needs local media ready before signaling.
- **Incoming call (callee)**: After `LOCAL_ACCEPT` dispatches (triggered by the Accept button at line 122 of `CallSessionOverlay.tsx`). The callee acquires media only after agreeing to take the call.

The `startOutgoingCall` function (line 517 of `ConversationView.tsx`) is the caller-side entry point. The `onAccept` prop passed to `CallSessionOverlay` is the callee-side entry point.

### Feature Flag Gating

WebRTC calls are gated by `isMessagingWebrtcDirectCallEnabled()` from `frontend/src/lib/featureFlags.ts` (line 53). This function checks:
- `VITE_MESSAGING_WEBRTC_DIRECT_CALL_ENABLED` (master toggle)
- `VITE_MESSAGING_WEBRTC_DIRECT_CALL_KILL_SWITCH` (emergency off)
- `VITE_MESSAGING_WEBRTC_DIRECT_CALL_MODE` (rollout mode: enabled/disabled/selective/internal)
- Tenant and cohort allow-lists for gradual rollout

The `callsEnabled` computed value (line 466 of `ConversationView.tsx`) determines whether call buttons render.

### Teardown Path

The `teardownCallResources` function (lines 163-186 of `callStateMachine.ts`) already handles stopping tracks:
```ts
for (const stream of [resources.localStream, resources.remoteStream]) {
  for (const track of stream?.getTracks() ?? []) {
    track.stop();
  }
}
```

This ensures that once media is acquired, it will be properly released on call end, failure, or component unmount. The effect at line 481 triggers teardown when the machine reaches terminal states (`ended`, `failed`, `failure`, `declined`, `busy`, `timeout`).

---

## 3. Technical Design

### 3.1 Media Capture Hook: `useMediaCapture`

Create a new hook at `frontend/src/pages/messages/useMediaCapture.ts` that encapsulates all `getUserMedia` logic:

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

**File**: `frontend/src/pages/messages/useMediaCapture.ts` (new)

Responsibilities:
- Expose `acquire(mode)`, `release()`, `toggleMute()`, `toggleCamera()`.
- Track permission state via a `status` field.
- Return the `MediaStream` for attachment to `CallRuntimeResources.localStream`.
- Handle all error cases from Section 3.2.

### 4.2 Phase 2: Integration with Call State Machine

**File**: `frontend/src/pages/messages/ConversationView.tsx`

**Outgoing call flow** (modify `startOutgoingCall` at line 517):

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
  // NOTE: callResourcesRef is currently typed as `{ cleanedUp?: boolean } | null`.
  // It must be widened to `CallRuntimeResources | null` (from callStateMachine.ts)
  // before this assignment will type-check.
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

The `onAccept` callback passed to `CallSessionOverlay` (currently dispatches `LOCAL_ACCEPT` at line 82 of `callStateMachine.ts`) needs to be wrapped:

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

**File**: `frontend/src/pages/messages/CallSessionOverlay.tsx`

Add mute and camera-off buttons to the `isConnected` footer section:

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

Add a device selector dropdown (shown when connected) that lists available microphones and cameras. This integrates with `useMediaDevices` and calls `switchAudioDevice`/`switchVideoDevice` on selection.

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

**File**: `frontend/src/pages/messages/useMediaCapture.test.ts` (new)

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

**File**: `frontend/e2e/webrtc-media.spec.ts` (new)

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
| `frontend/src/pages/messages/useMediaCapture.test.ts` | Hook logic in isolation | Vitest |
| `frontend/src/pages/messages/useMediaDevices.test.ts` | Device enumeration hook | Vitest |
| `frontend/src/pages/messages/ConversationView.call_flows.test.tsx` | Integration with state machine (extend existing) | Vitest + RTL |
| `frontend/e2e/webrtc-media.spec.ts` | Full browser integration, permission flows | Playwright |

All unit tests mock `navigator.mediaDevices` at the module level. E2E tests use Playwright's `browserContext.grantPermissions()` for happy paths and `page.addInitScript()` overrides for failure simulation.
