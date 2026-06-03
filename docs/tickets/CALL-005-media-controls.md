# CALL-005: Add In-Call Media Controls (Mute, Camera, End) with Duration Timer and Quality Indicator

**Status**: Implemented

## 1. Overview & Motivation

The WebRTC direct call feature (gated behind `VITE_MESSAGING_WEBRTC_DIRECT_CALL_ENABLED`) currently provides call signalling via `app/routers/messaging.py` (endpoints at `/messages/calls/*`), a state machine (`callStateMachine.ts`), and a UI overlay (`CallSessionOverlay.tsx`) for call lifecycle states. CALL-004 added media stream rendering (remote/local `<video>` and `<audio>` elements with `srcObject` management). However, once a call reaches the `"connected"` state, the user has **no interactive media controls**:

<!-- NOTE: This ticket is now FULLY IMPLEMENTED. CallSessionOverlay.tsx (671 lines) includes:
- Mute toggle: CallControls component at line 167 with Mic/MicOff buttons (lines 171-178)
- Camera toggle: Video/VideoOff buttons (lines 182-190)
- Duration timer: CallTimer component at line 131
- Recording controls: onRequestRecording/onStopRecording at lines 204-227
- Screen share toggle: Monitor/MonitorOff buttons at lines 192-203
- End call button: lines 230-237
- Connection quality indicator via useCallQuality hook in ConversationView.tsx
The props interface (line 42) includes localStream, remoteStream, isMuted, isCameraOff, recording props, and screen share props.
-->

### Business requirements

1. **Mute toggle**: Toggle local audio track `enabled` state. Visual feedback (icon change + background highlight) must be immediate. Accessibility: aria-label must reflect current state ("Mute microphone" / "Unmute microphone").
2. **Camera toggle**: Toggle local video track `enabled` state. Only shown for `mode === "video"` calls. When camera is off, the local PiP preview (from CALL-004) must show a "camera off" placeholder.
3. **End call button**: Remains in the control bar but receives updated styling (circular, red, centered or right-aligned depending on layout).
4. **Duration timer**: Counts up from `00:00` the moment `phase === "connected"`. Resets on call end. Displayed as monospace tabular-nums text.
5. **Connection quality indicator**: Reads `RTCPeerConnection.getStats()` periodically to derive a 3-tier quality signal (good/fair/poor). Displays a WiFi-bar or signal icon with color coding.

### Scope boundaries

- This ticket does NOT cover screen sharing (future CALL-006).
- This ticket does NOT change the call signalling protocol or backend.
- This ticket does NOT add hold/resume functionality.
- Media acquisition (`getUserMedia`) is handled by CALL-003; this ticket only manipulates tracks that already exist on `CallRuntimeResources.localStream`.

---

## 2. Current State Analysis

### 2.1 CallSessionOverlay.tsx (671 lines)

**Location**: `frontend/src/pages/messages/CallSessionOverlay.tsx` (see line 42 for Props interface)

The component is a Radix UI `<Dialog>` that renders conditionally based on `session.state`. It now receives full media props:

```ts
interface Props {
  session: CallSessionUi;
  isBusy?: boolean;
  localStream?: MediaStream | null;
  remoteStream?: MediaStream | null;
  isMuted?: boolean;
  isCameraOff?: boolean;
  isRecording?: boolean;
  isScreenSharing?: boolean;
  onAccept, onDecline, onEnd, onDismiss: () => void;
  onToggleMute, onToggleCamera?: () => void;
  onRequestRecording, onStopRecording?: () => void;
  onToggleScreenShare?: () => void;
  screenShareSupported, recordingEnabled?: boolean;
}
```

**Connected-state rendering includes full CallControls component (line 167) with mute, camera, recording, screenshare, and end call buttons.**

<!-- NOTE: The descriptions below of missing controls are outdated. All controls are now implemented. Icons imported at line 2 include Phone, PhoneCall, PhoneIncoming, PhoneOff, Video, Mic, MicOff, VideoOff, ShieldAlert, Signal, Circle, Monitor, MonitorOff. -->

### 2.2 callStateMachine.ts (222 lines)

**Location**: `frontend/src/pages/messages/callStateMachine.ts` (see line 6)

**`CallMachineState` interface (lines 6-20):**
```ts
export interface CallMachineState {
  phase: CallUiState;
  role: CallRole | null;
  mode: DirectCallMode;         // "audio" | "video"
  callId?: string;
  peerName: string;
  reasonMessage?: string;
  retryCount: number;
  maxRetries: number;
  isOnline: boolean;
  isTabVisible: boolean;
}
```

Notably, there are **no fields for media control state** (mute, camera off). The state machine is purely concerned with call lifecycle phases and network resilience. Media control state is inherently local (it only affects the user's own tracks) and does not need to be part of the signalling state machine.

**`CallRuntimeResources` interface (lines 190-197)** (see `frontend/src/pages/messages/callStateMachine.ts:190`):
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

The `localStream` field is the key handle for media controls. `localStream.getAudioTracks()` returns the microphone track(s); `localStream.getVideoTracks()` returns the camera track(s). Setting `track.enabled = false` mutes/disables without stopping the track (which would require re-acquisition).

**`teardownCallResources` (lines 199-222)** (see `frontend/src/pages/messages/callStateMachine.ts:199`): Already calls `track.stop()` on all tracks of both streams. This means: after `END_LOCAL` or `END_REMOTE`, all tracks are permanently stopped. Toggling must use `track.enabled`, not `track.stop()`.

The `peerConnection` field is typed as `{ close: () => void } | null` -- a minimal interface. For connection quality stats, we need `RTCPeerConnection.getStats()`. The type must be widened or the quality hook must accept `RTCPeerConnection` directly.

### 2.3 ConversationView.tsx integration

**Location**: `frontend/src/pages/messages/ConversationView.tsx` (1461 lines)

<!-- NOTE: All integration is now IMPLEMENTED:
- callResourcesRef typed as CallRuntimeResources | null (line 92)
- useRtcPeerConnection hook at line 618 provides rtcLocalStream/rtcRemoteStream
- useMediaCapture at line 94 provides mediaCapture.stream
- useCallRecording at line 640
- CallSessionOverlay receives all props including streams, mute, camera, recording at line 1282+
-->

### 2.4 Existing test coverage

**Unit tests**: `callStateMachine.test.ts` (202 lines) covers state transitions and `teardownCallResources` idempotency (see `frontend/src/pages/messages/callStateMachine.test.ts`).

**Integration tests**: `ConversationView.call_flows.test.tsx` (~180 lines) tests:
- Outgoing call state transitions (ringing -> connected -> ended)
- Incoming call accept flow
- Busy rejection handling
- Stale event deduplication

Neither test file exercises mute/camera toggle behavior, because no such functionality exists.

### 2.5 UI component inventory

Available shadcn/ui components in `frontend/src/components/ui/`:
- `button.tsx`: Supports `variant` (default, destructive, outline, secondary, ghost, link) and `size` (default, sm, lg, **icon**). The `icon` size (`h-9 w-9`) is ideal for circular control buttons.
- `tooltip.tsx`: `Tooltip`, `TooltipTrigger`, `TooltipContent` from `@radix-ui/react-tooltip`. Useful for labeling icon-only controls.
- `badge.tsx`: Could be used for quality indicator pill.

Lucide icons available (already in `package.json`): `Mic`, `MicOff`, `Camera`, `CameraOff`, `Video`, `VideoOff`, `Wifi`, `WifiOff`, `Signal`, `SignalHigh`, `SignalMedium`, `SignalLow`, `SignalZero`, `Timer`, `Clock`.

---

## 3. Technical Design

### 3.1 New Props on CallSessionOverlay

The overlay must receive access to the local media stream and peer connection for media controls and quality monitoring:

```ts
interface Props {
  session: CallSessionUi;
  isBusy?: boolean;
  localStream?: MediaStream | null;
  peerConnection?: RTCPeerConnection | null;
  onAccept: () => void;
  onDecline: () => void;
  onEnd: () => void;
  onDismiss: () => void;
}
```

`localStream` provides access to audio/video tracks for mute/camera toggles.
`peerConnection` provides access to `getStats()` for quality monitoring.

### 3.2 Mute Toggle

**State:**
```ts
const [isMuted, setIsMuted] = React.useState(false);
```

**Handler:**
```ts
const toggleMute = React.useCallback(() => {
  if (!localStream) return;
  const audioTracks = localStream.getAudioTracks();
  const newEnabled = !audioTracks[0]?.enabled;
  audioTracks.forEach((track) => { track.enabled = newEnabled; });
  setIsMuted(!newEnabled);
}, [localStream]);
```

Key design decisions:
- We read the **current track state** (`!audioTracks[0]?.enabled`) rather than relying solely on React state, preventing drift if tracks are manipulated externally.
- We set `track.enabled` (not `track.stop()`). `enabled = false` sends silence frames to the peer, maintaining the RTP stream. `stop()` would require re-acquiring the track from `getUserMedia`.
- The initial state (`isMuted = false`) must be synchronized if the stream is acquired with tracks already disabled. A `useEffect` will reset `isMuted` when `localStream` changes.

**Reset on stream change:**
```ts
React.useEffect(() => {
  if (!localStream) return;
  const audioTrack = localStream.getAudioTracks()[0];
  setIsMuted(audioTrack ? !audioTrack.enabled : false);
}, [localStream]);
```

**UI rendering:**
```tsx
<Tooltip>
  <TooltipTrigger asChild>
    <Button
      variant={isMuted ? "destructive" : "secondary"}
      size="icon"
      className="rounded-full h-12 w-12"
      onClick={toggleMute}
      aria-label={isMuted ? "Unmute microphone" : "Mute microphone"}
      aria-pressed={isMuted}
    >
      {isMuted ? <MicOff className="h-5 w-5" /> : <Mic className="h-5 w-5" />}
    </Button>
  </TooltipTrigger>
  <TooltipContent>{isMuted ? "Unmute" : "Mute"}</TooltipContent>
</Tooltip>
```

The `variant="destructive"` when muted provides a strong red visual signal. `aria-pressed` communicates toggle state to screen readers.

### 3.3 Camera Toggle

**State:**
```ts
const [isCameraOff, setIsCameraOff] = React.useState(false);
```

**Handler:**
```ts
const toggleCamera = React.useCallback(() => {
  if (!localStream) return;
  const videoTracks = localStream.getVideoTracks();
  if (videoTracks.length === 0) return; // audio-only call, no-op
  const newEnabled = !videoTracks[0]?.enabled;
  videoTracks.forEach((track) => { track.enabled = newEnabled; });
  setIsCameraOff(!newEnabled);
}, [localStream]);
```

**Conditional rendering (only for video calls):**
```tsx
{session.mode === "video" && (
  <Tooltip>
    <TooltipTrigger asChild>
      <Button
        variant={isCameraOff ? "destructive" : "secondary"}
        size="icon"
        className="rounded-full h-12 w-12"
        onClick={toggleCamera}
        aria-label={isCameraOff ? "Turn on camera" : "Turn off camera"}
        aria-pressed={isCameraOff}
      >
        {isCameraOff ? <CameraOff className="h-5 w-5" /> : <Camera className="h-5 w-5" />}
      </Button>
    </TooltipTrigger>
    <TooltipContent>{isCameraOff ? "Camera on" : "Camera off"}</TooltipContent>
  </Tooltip>
)}
```

**Local PiP placeholder when camera is off:**

When `isCameraOff` is true, the local PiP `<video>` element (from CALL-004) should be overlaid with a "camera off" placeholder:

```tsx
{isCameraOff && (
  <div className="absolute inset-0 flex items-center justify-center bg-muted/90 rounded-xl">
    <CameraOff className="h-8 w-8 text-muted-foreground" />
  </div>
)}
```

This is rendered inside the PiP container (`absolute bottom-4 right-4 w-40 h-28 rounded-xl`), positioned above the frozen video frame.

### 3.4 End Call Button (Restyled)

The existing end call button is restyled to match the control bar aesthetic:

```tsx
<Tooltip>
  <TooltipTrigger asChild>
    <Button
      variant="destructive"
      size="icon"
      className="rounded-full h-12 w-12"
      onClick={onEnd}
      disabled={isBusy}
      aria-label="End call"
    >
      <PhoneOff className="h-5 w-5" />
    </Button>
  </TooltipTrigger>
  <TooltipContent>End call</TooltipContent>
</Tooltip>
```

The text label "End call" is removed in favor of a circular icon-only button matching the mute/camera buttons. The tooltip provides the text label on hover.

### 3.5 Duration Timer

**Hook: `useCallDuration`**

Extracted as a reusable hook to keep the overlay component focused on rendering:

```ts
function useCallDuration(isConnected: boolean): string {
  const [elapsed, setElapsed] = React.useState(0);
  const startRef = React.useRef<number | null>(null);

  React.useEffect(() => {
    if (!isConnected) {
      setElapsed(0);
      startRef.current = null;
      return;
    }
    startRef.current = Date.now();
    const interval = window.setInterval(() => {
      if (startRef.current) {
        setElapsed(Math.floor((Date.now() - startRef.current) / 1000));
      }
    }, 1000);
    return () => window.clearInterval(interval);
  }, [isConnected]);

  const minutes = Math.floor(elapsed / 60);
  const seconds = elapsed % 60;
  return `${minutes.toString().padStart(2, "0")}:${seconds.toString().padStart(2, "0")}`;
}
```

Design notes:
- Uses `Date.now()` delta rather than incrementing a counter to avoid drift from `setInterval` jitter.
- Resets to `00:00` when `isConnected` becomes false (handles reconnection scenarios -- if the call reconnects, the timer continues from the original start time because `startRef.current` is only reset when `isConnected` goes `false`).
- Returns a formatted string for direct rendering.

**Rendering:**
```tsx
<span
  className="text-sm font-mono tabular-nums text-muted-foreground"
  aria-label={`Call duration: ${duration}`}
  aria-live="off"
>
  {duration}
</span>
```

`aria-live="off"` prevents screen readers from announcing every second. The `aria-label` provides a one-time readable description if the user navigates to it.

### 3.6 Connection Quality Indicator

**Hook: `useConnectionQuality`**

```ts
type ConnectionQuality = "good" | "fair" | "poor" | "unknown";

function useConnectionQuality(
  peerConnection: RTCPeerConnection | null | undefined,
  isConnected: boolean,
): ConnectionQuality {
  const [quality, setQuality] = React.useState<ConnectionQuality>("unknown");

  React.useEffect(() => {
    if (!peerConnection || !isConnected) {
      setQuality("unknown");
      return;
    }

    const pollStats = async () => {
      try {
        const stats = await peerConnection.getStats();
        let totalRoundTripTime = 0;
        let roundTripMeasurements = 0;
        let packetsLost = 0;
        let packetsReceived = 0;

        stats.forEach((report) => {
          if (report.type === "candidate-pair" && report.state === "succeeded") {
            if (typeof report.currentRoundTripTime === "number") {
              totalRoundTripTime += report.currentRoundTripTime;
              roundTripMeasurements += 1;
            }
          }
          if (report.type === "inbound-rtp") {
            packetsLost += report.packetsLost ?? 0;
            packetsReceived += report.packetsReceived ?? 0;
          }
        });

        const avgRtt = roundTripMeasurements > 0
          ? totalRoundTripTime / roundTripMeasurements
          : null;
        const lossRate = packetsReceived > 0
          ? packetsLost / (packetsLost + packetsReceived)
          : 0;

        // Thresholds (aligned with WebRTC best practices):
        // Good: RTT < 150ms AND loss < 2%
        // Fair: RTT < 400ms AND loss < 5%
        // Poor: anything worse
        if (avgRtt !== null && avgRtt < 0.15 && lossRate < 0.02) {
          setQuality("good");
        } else if (avgRtt !== null && avgRtt < 0.4 && lossRate < 0.05) {
          setQuality("fair");
        } else if (avgRtt !== null) {
          setQuality("poor");
        } else {
          setQuality("unknown");
        }
      } catch {
        setQuality("unknown");
      }
    };

    // Poll every 3 seconds (frequent enough for feedback, not so frequent as to be expensive)
    const interval = window.setInterval(pollStats, 3000);
    pollStats(); // immediate first poll
    return () => window.clearInterval(interval);
  }, [peerConnection, isConnected]);

  return quality;
}
```

**Rendering:**
```tsx
const qualityConfig: Record<ConnectionQuality, { icon: React.ReactNode; color: string; label: string }> = {
  good: { icon: <Signal className="h-4 w-4" />, color: "text-green-500", label: "Good connection" },
  fair: { icon: <Signal className="h-4 w-4" />, color: "text-yellow-500", label: "Fair connection" },
  poor: { icon: <Signal className="h-4 w-4" />, color: "text-red-500", label: "Poor connection" },
  unknown: { icon: <Signal className="h-4 w-4" />, color: "text-muted-foreground", label: "Connection quality unknown" },
};

// In JSX:
<Tooltip>
  <TooltipTrigger asChild>
    <span className={cn("inline-flex items-center", qualityConfig[quality].color)} aria-label={qualityConfig[quality].label}>
      {qualityConfig[quality].icon}
    </span>
  </TooltipTrigger>
  <TooltipContent>{qualityConfig[quality].label}</TooltipContent>
</Tooltip>
```

### 3.7 Control Bar Layout

The connected state replaces the current `DialogFooter` with a dedicated control bar:

```tsx
{isConnected && (
  <div className="flex items-center justify-center gap-4 px-4 py-3" role="toolbar" aria-label="Call controls">
    {/* Left: Quality + Timer */}
    <div className="flex items-center gap-2 mr-auto">
      <ConnectionQualityIndicator quality={quality} />
      <span className="text-sm font-mono tabular-nums text-muted-foreground">{duration}</span>
    </div>

    {/* Center: Media controls */}
    <div className="flex items-center gap-3">
      <MuteButton isMuted={isMuted} onToggle={toggleMute} />
      {session.mode === "video" && (
        <CameraButton isCameraOff={isCameraOff} onToggle={toggleCamera} />
      )}
      <EndCallButton onEnd={onEnd} isBusy={isBusy} />
    </div>

    {/* Right: Peer name */}
    <div className="ml-auto text-sm text-muted-foreground truncate max-w-[120px]">
      {session.peerName}
    </div>
  </div>
)}
```

For video calls, the control bar is positioned at the bottom of the expanded video container (overlaid with a semi-transparent background):
```tsx
<div className="absolute bottom-0 left-0 right-0 bg-black/60 backdrop-blur-sm rounded-b-2xl">
  {/* control bar content */}
</div>
```

For audio calls, the control bar is the standard `DialogFooter` area below the avatar section.

### 3.8 State Machine Considerations

The `callStateMachine.ts` **does not** need modification for this ticket. Media control state (mute, camera off) is:
- Purely local (not sent to the peer via signalling)
- Ephemeral (resets when the call ends)
- UI-only (does not affect call lifecycle transitions)

Therefore, mute/camera state lives as `useState` inside `CallSessionOverlay` and is reset whenever the component unmounts or `isConnected` becomes false.

However, we must extend `CallRuntimeResources` for the quality indicator:

```ts
export interface CallRuntimeResources {
  peerConnection?: RTCPeerConnection | null;  // WIDENED from { close: () => void }
  localStream?: MediaStream | null;
  remoteStream?: MediaStream | null;
  detachListeners?: Array<() => void>;
  teardownTimers?: Array<number>;
  cleanedUp?: boolean;
}
```

The `peerConnection` field type is widened from `{ close: () => void }` to `RTCPeerConnection | null`. This is backward-compatible because `RTCPeerConnection` satisfies `{ close: () => void }`. The `teardownCallResources` function only calls `.close()`, so no changes are needed there.

### 3.9 Keyboard Accessibility

All control buttons must be keyboard accessible:
- `M` key: Toggle mute (when overlay is focused)
- `V` key: Toggle camera (when overlay is focused, video calls only)
- `Escape`: End call (already handled by Dialog's `onOpenChange`)

Implementation via a `useEffect` keydown listener scoped to the dialog:

```ts
React.useEffect(() => {
  if (!isConnected) return;
  const handler = (e: KeyboardEvent) => {
    if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return;
    if (e.key === "m" || e.key === "M") { e.preventDefault(); toggleMute(); }
    if ((e.key === "v" || e.key === "V") && session.mode === "video") { e.preventDefault(); toggleCamera(); }
  };
  document.addEventListener("keydown", handler);
  return () => document.removeEventListener("keydown", handler);
}, [isConnected, toggleMute, toggleCamera, session.mode]);
```

---

## 4. Implementation Plan

### Phase 1: Core media controls (Mute + Camera + End) -- 1 day

**Files modified:**

| File | Change |
|------|--------|
| `frontend/src/pages/messages/CallSessionOverlay.tsx` | Add `localStream` prop, `isMuted`/`isCameraOff` state, toggle handlers, control bar JSX, new icon imports |
| `frontend/src/pages/messages/ConversationView.tsx` | Pass `localStream={callResourcesRef.current?.localStream}` to overlay; widen `callResourcesRef` type |
| `frontend/src/pages/messages/callStateMachine.ts` | Widen `peerConnection` type to `RTCPeerConnection | null` |

**Steps:**

1. **Add new imports to `CallSessionOverlay.tsx`:**
   - Icons: `Mic, MicOff, Camera, CameraOff` from `lucide-react`
   - Components: `Tooltip, TooltipTrigger, TooltipContent` from `@/components/ui/tooltip`

2. **Extend Props interface** to accept `localStream?: MediaStream | null`.

3. **Add `isMuted` + `isCameraOff` state** with synchronization effects.

4. **Add `toggleMute` + `toggleCamera` callbacks** using `track.enabled` manipulation.

5. **Replace the connected-state `DialogFooter` content** with the new control bar layout (mute button + optional camera button + end call button).

6. **In `ConversationView.tsx`**, pass `localStream` from `callResourcesRef.current?.localStream ?? null` to the overlay. Since `callResourcesRef` is a mutable ref that gets populated by the WebRTC setup code, we also add a `forceUpdate` trigger when the stream becomes available (using a state counter incremented in the effect that detects stream attachment).

### Phase 2: Duration timer -- 0.5 day

**Files modified:**

| File | Change |
|------|--------|
| `frontend/src/pages/messages/CallSessionOverlay.tsx` | Add `useCallDuration` hook, render timer in control bar |

**Steps:**

1. **Add `useCallDuration` hook** (inline in the same file or extracted to a `useCallDuration.ts` if preferred).

2. **Render duration string** in the control bar between the quality indicator and the control buttons.

3. **Ensure timer resets** when call transitions out of `connected` state (handled by the `isConnected` dependency).

### Phase 3: Connection quality indicator -- 0.5 day

**Files modified:**

| File | Change |
|------|--------|
| `frontend/src/pages/messages/CallSessionOverlay.tsx` | Add `peerConnection` prop, `useConnectionQuality` hook, quality icon rendering |
| `frontend/src/pages/messages/callStateMachine.ts` | Widen `peerConnection` type |
| `frontend/src/pages/messages/ConversationView.tsx` | Pass `peerConnection` prop to overlay |

**Steps:**

1. **Widen `CallRuntimeResources.peerConnection`** type in `callStateMachine.ts`.

2. **Add `peerConnection` prop** to `CallSessionOverlay`.

3. **Implement `useConnectionQuality` hook** with `getStats()` polling.

4. **Render quality indicator** with color-coded `Signal` icon and tooltip.

### Phase 4: Keyboard shortcuts + accessibility polish -- 0.5 day

**Files modified:**

| File | Change |
|------|--------|
| `frontend/src/pages/messages/CallSessionOverlay.tsx` | Add keydown listener effect, `role="toolbar"`, `aria-pressed` attributes |

**Steps:**

1. **Add keydown handler** for `M` (mute) and `V` (camera) shortcuts.

2. **Add `role="toolbar"` and `aria-label="Call controls"`** to the control bar container.

3. **Ensure all buttons have `aria-pressed`** reflecting toggle state.

4. **Add screen reader announcements** via `aria-live="polite"` region for state changes (e.g., "Microphone muted", "Camera turned off").

### Phase 5: Integration verification -- 0.5 day

1. Verify that toggling mute during a connected call sets `localStream.getAudioTracks()[0].enabled = false`.
2. Verify that toggling camera during a connected video call sets `localStream.getVideoTracks()[0].enabled = false`.
3. Verify that the timer starts counting on `CONNECT` event and stops on `END_LOCAL`/`END_REMOTE`.
4. Verify that the quality indicator transitions between good/fair/poor as network conditions change.
5. Verify that all controls are disabled/hidden when `isConnected` is false.
6. Verify that track `enabled` state is NOT affected by `teardownCallResources` (it calls `stop()` which is permanent -- but only fires on call end, not on toggle).

### Estimated total: 3 days

---

## Testing Strategy

### Unit Tests (pytest)

**Test file**: `tests/test_call_5.py`

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

**Test file**: `frontend/e2e/call-5.spec.ts`

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
| CALL-003 | Local media tracks for mute/camera toggle | Implemented | No -- must merge after |
| CALL-004 | Media rendering in overlay | Implemented | No -- must merge after |

### Depended On By

| Ticket | What It Needs |
|---|---|
| CALL-006 | Media controls for E2E testing |

### Merge Strategy

Sequential after CALL-003/004. Frontend component changes only.

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
| `frontend/src/pages/messages/CallSessionOverlay.tsx` | 1-671 | Full call overlay with all controls (IMPLEMENTED) |
| `frontend/src/pages/messages/CallSessionOverlay.tsx` | 42-68 | Props interface (media, mute, camera, recording, screenshare) |
| `frontend/src/pages/messages/CallSessionOverlay.tsx` | 82-115 | `VideoRenderer` sub-component |
| `frontend/src/pages/messages/CallSessionOverlay.tsx` | 117-128 | `AudioRenderer` sub-component |
| `frontend/src/pages/messages/CallSessionOverlay.tsx` | 131-147 | `CallTimer` sub-component |
| `frontend/src/pages/messages/CallSessionOverlay.tsx` | 150-237 | `CallControls` sub-component (mute, camera, recording, screenshare, end) |
| `frontend/src/pages/messages/ConversationView.tsx` | 618-637 | useRtcPeerConnection hook providing streams |
| `frontend/src/pages/messages/ConversationView.tsx` | 639-647 | useCallRecording hook |
| `frontend/src/pages/messages/ConversationView.tsx` | 1282-1290 | CallSessionOverlay mount with all props |
| `frontend/src/hooks/useMediaCapture.ts` | 1-315 | Media capture with mute/camera toggle support |
| `frontend/src/hooks/useCallRecording.ts` | 1-83+ | Call recording hook |
| `frontend/src/pages/messages/callStateMachine.ts` | 190-222 | CallRuntimeResources + teardownCallResources |
| `frontend/src/lib/featureFlags.ts` | 127 | isCallRecordingEnabled |
| `frontend/e2e/webrtc-media.spec.ts` | 1-1375 | E2E media tests (IMPLEMENTED) |
| `frontend/e2e/webrtc-calls.spec.ts` | 1-661 | E2E call tests (IMPLEMENTED) |
