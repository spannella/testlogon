# CALL-004: Render Local and Remote Media Streams in Call Overlay

## 1. Overview & Motivation

The WebRTC direct call feature (gated behind `VITE_MESSAGING_WEBRTC_DIRECT_CALL_ENABLED`) currently provides call signalling, state management, and a UI overlay for call lifecycle states (ringing, connecting, connected, ended). However, once a call reaches the `"connected"` state, the user sees only a text description ("Connected with {peerName}") and a red "End call" button. <!-- NOTE: This ticket is now FULLY IMPLEMENTED. CallSessionOverlay.tsx (671 lines) includes VideoRenderer (line 90), AudioRenderer (line 117), CallTimer (line 131), CallControls (line 167) with mute/camera/recording/screenshare buttons, video call layout with PiP, and audio call layout. All props (localStream, remoteStream, isMuted, isCameraOff) are passed from ConversationView.tsx. The E2E test file frontend/e2e/webrtc-call-media.spec.ts does NOT exist yet, but webrtc-media.spec.ts (1375 lines) and webrtc-calls.spec.ts (661 lines) cover related scenarios. -->

The overlay now includes full media rendering for both audio and video calls (see `frontend/src/pages/messages/CallSessionOverlay.tsx:82-130` for VideoRenderer/AudioRenderer, line 131 for CallTimer, line 167 for CallControls).

This ticket covers rendering both local and remote media streams in `CallSessionOverlay.tsx`, handling the differences between audio-only and video calls, managing `srcObject` lifecycle, and ensuring proper cleanup when calls end.

### What needs to render

| Call Mode | Remote Stream | Local Stream |
|-----------|--------------|--------------|
| `"audio"` | Hidden `<audio>` element (autoplay, no visible video) | No visual element needed (mic indicator optional) |
| `"video"` | Full-viewport `<video>` element (remote camera) | Small PiP `<video>` in bottom-right corner (local camera) |

### Key requirements

1. Remote audio must play immediately on connection (autoplay with `playsInline`)
2. Video call layout must be responsive (mobile full-screen, desktop constrained to dialog)
3. Local preview must be draggable or repositionable on mobile
4. `srcObject` must be set imperatively via refs (React does not support `srcObject` as a JSX attribute)
5. All tracks must be stopped and streams released on call end, decline, or failure
6. Echo cancellation must be enabled on local audio capture (`echoCancellation: true`)
7. Mute/unmute and camera on/off controls needed for connected state

---

## 2. Current State Analysis

### CallSessionOverlay structure

Located at `frontend/src/pages/messages/CallSessionOverlay.tsx` (671 lines) (see `frontend/src/pages/messages/CallSessionOverlay.tsx:42`), the component is a Radix UI `<Dialog>` that renders conditionally based on `session.state`:

```
Props (see line 42):
  session: CallSessionUi { state, direction, mode, peerName, callId, reasonMessage }
  isBusy?: boolean
  localStream?: MediaStream | null     // IMPLEMENTED
  remoteStream?: MediaStream | null    // IMPLEMENTED
  isMuted?: boolean                    // IMPLEMENTED
  isCameraOff?: boolean                // IMPLEMENTED
  onAccept, onDecline, onEnd, onDismiss, onToggleMute, onToggleCamera, ...
```

**Render logic breakdown:**

| State Category | Variables | Current Rendering |
|---------------|-----------|-------------------|
| `idle` | `session.state === "idle"` | Returns `null` (not rendered) |
| Incoming | `isIncoming` | Title "Incoming {mode} call", description "{peerName} is calling you", Decline + Accept buttons |
| Outgoing | `isOutgoing` | Title "{Mode} call", description "Ringing/Starting/Connecting/Reconnecting {peerName}...", Cancel button |
| Connected | `isConnected` | Title "Call status", description "Connected with {peerName}.", End call button |
| Outcome | `isOutcome` | Title "Call status", description from `outcomeCopy` map, Dismiss button |

<!-- NOTE: The connected state now renders full media: VideoRenderer for remote/local streams, AudioRenderer for remote audio, CallTimer, and CallControls with mute/camera/recording/screenshare buttons. See CallSessionOverlay.tsx:362-477 for the connected state rendering. -->

### How the overlay is mounted (ConversationView.tsx, lines 1282+) (see `frontend/src/pages/messages/ConversationView.tsx:1282`)

The overlay is rendered at the bottom of `ConversationView`'s JSX tree, unconditionally (the component itself returns `null` when `session.state === "idle"`). It receives:

- `session`: Constructed from `callMachine` reducer state (maps phases to `CallUiState` values)
- `isBusy`: Tied to `callActionMutation.isPending`
- `onAccept`/`onDecline`/`onEnd`/`onDismiss`: Dispatch actions to `callMachine` reducer + call backend APIs

### CallRuntimeResources (callStateMachine.ts, lines 190-197) (see `frontend/src/pages/messages/callStateMachine.ts:190`)

The state machine already defines a `CallRuntimeResources` interface with:

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

The `localStream` and `remoteStream` fields are now passed to the overlay from `ConversationView.tsx` (see line 1287 for `localStream` prop). The `teardownCallResources` function (line 199) iterates both streams and calls `track.stop()` on each track, plus closes the peer connection.

### Dialog constraints

The current dialog uses `className="sm:max-w-md"` on `DialogContent`, which constrains the overlay to a 28rem max-width modal. For video calls, this is far too small. The overlay must expand to near-fullscreen for video while remaining compact for audio-only calls.

---

## 3. Technical Design

### 3.1 Layout: Video Call

For video calls in the connected state, the overlay must transition from a small dialog to a near-fullscreen viewport:

```
+------------------------------------------------------------------+
|  [dark background / DialogOverlay]                                |
|                                                                   |
|  +------------------------------------------------------------+  |
|  |                                                            |  |
|  |              REMOTE VIDEO (object-fit: cover)              |  |
|  |              aspect-ratio: 16/9                            |  |
|  |              max-w: 95vw, max-h: 85vh                      |  |
|  |                                                            |  |
|  |                                    +------------------+    |  |
|  |                                    | LOCAL VIDEO PiP  |    |  |
|  |                                    | w-40 h-28        |    |  |
|  |                                    | rounded-xl       |    |  |
|  |                                    | ring-2 ring-white|    |  |
|  |                                    | shadow-lg        |    |  |
|  |                                    +------------------+    |  |
|  |                                                            |  |
|  +------------------------------------------------------------+  |
|                                                                   |
|  +------------------------------------------------------------+  |
|  | [Mic] [Camera] [ScreenShare?]    peerName   00:42   [End]  |  |
|  +------------------------------------------------------------+  |
+------------------------------------------------------------------+
```

**Tailwind classes for video connected layout:**

- Dialog content: `sm:max-w-[95vw] sm:max-h-[90vh] p-0` (override default `sm:max-w-md p-6`)
- Remote video container: `relative w-full aspect-video bg-black rounded-t-2xl overflow-hidden`
- Remote `<video>`: `h-full w-full object-cover`
- Local PiP container: `absolute bottom-4 right-4 w-40 h-28 rounded-xl overflow-hidden ring-2 ring-white/70 shadow-lg`
- Local `<video>`: `h-full w-full object-cover mirror` (CSS transform: `scaleX(-1)` for self-view)
- Controls bar: `flex items-center justify-between px-4 py-3 bg-background rounded-b-2xl`

**Responsive breakpoints:**

- Mobile (`< sm`): Full-width dialog, PiP shrinks to `w-28 h-20`
- Desktop (`>= sm`): Constrained to `95vw / 85vh`, PiP at `w-40 h-28`

### 3.2 Layout: Audio Call

For audio calls in the connected state, the overlay stays as a compact dialog:

```
+-------------------------------------+
|  [PhoneCall icon] Audio call         |
|                                      |
|  +------+                            |
|  |Avatar|   peerName                 |
|  |64x64 |   Connected  00:42        |
|  +------+                            |
|                                      |
|  [Mic toggle]            [End call]  |
+-------------------------------------+
```

**Tailwind classes:**

- Dialog content: `sm:max-w-md` (unchanged from today)
- Avatar section: `flex items-center gap-4 py-6`
- Avatar: `h-16 w-16` (larger than header avatar)
- Timer: `text-sm text-muted-foreground font-mono tabular-nums`
- Controls: `flex items-center justify-between` inside `DialogFooter`

### 3.3 srcObject Management

React does not support setting `srcObject` declaratively. We must use refs and effects:

```tsx
const remoteVideoRef = React.useRef<HTMLVideoElement>(null);
const localVideoRef = React.useRef<HTMLVideoElement>(null);
const remoteAudioRef = React.useRef<HTMLAudioElement>(null);

React.useEffect(() => {
  if (remoteVideoRef.current && remoteStream) {
    remoteVideoRef.current.srcObject = remoteStream;
  }
}, [remoteStream]);

React.useEffect(() => {
  if (localVideoRef.current && localStream) {
    localVideoRef.current.srcObject = localStream;
  }
}, [localStream]);

React.useEffect(() => {
  if (remoteAudioRef.current && remoteStream) {
    remoteAudioRef.current.srcObject = remoteStream;
  }
}, [remoteStream]);
```

**Cleanup on unmount/stream change:**

```tsx
React.useEffect(() => {
  return () => {
    if (remoteVideoRef.current) remoteVideoRef.current.srcObject = null;
    if (localVideoRef.current) localVideoRef.current.srcObject = null;
    if (remoteAudioRef.current) remoteAudioRef.current.srcObject = null;
  };
}, []);
```

### 3.4 Echo Cancellation

When acquiring the local stream via `getUserMedia`, constraints must include:

```ts
const constraints: MediaStreamConstraints = {
  audio: {
    echoCancellation: true,
    noiseSuppression: true,
    autoGainControl: true,
  },
  video: mode === "video" ? {
    width: { ideal: 1280 },
    height: { ideal: 720 },
    facingMode: "user",
  } : false,
};
```

This is handled upstream in the WebRTC setup code (not in the overlay), but the overlay must correctly render whatever streams are provided.

### 3.5 Call Timer

A `useCallTimer` hook (or inline `useEffect` + `useState`) starts counting from 0 when `isConnected` becomes true:

```tsx
const [elapsed, setElapsed] = React.useState(0);

React.useEffect(() => {
  if (!isConnected) { setElapsed(0); return; }
  const interval = setInterval(() => setElapsed((e) => e + 1), 1000);
  return () => clearInterval(interval);
}, [isConnected]);

const formatTime = (s: number) => {
  const m = Math.floor(s / 60);
  const sec = s % 60;
  return `${m.toString().padStart(2, "0")}:${sec.toString().padStart(2, "0")}`;
};
```

### 3.6 Mute/Camera Toggle Controls

New local state for media controls:

```tsx
const [isMuted, setIsMuted] = React.useState(false);
const [isCameraOff, setIsCameraOff] = React.useState(false);
```

Toggle handlers modify tracks on the `localStream`:

```tsx
const toggleMute = () => {
  if (!localStream) return;
  localStream.getAudioTracks().forEach((t) => { t.enabled = !t.enabled; });
  setIsMuted((m) => !m);
};

const toggleCamera = () => {
  if (!localStream) return;
  localStream.getVideoTracks().forEach((t) => { t.enabled = !t.enabled; });
  setIsCameraOff((c) => !c);
};
```

### 3.7 No-Video Fallback

When remote video tracks are not present (audio-only call) or become muted, show a fallback:

```tsx
{!hasRemoteVideo && (
  <div className="flex h-full w-full items-center justify-center bg-muted">
    <Avatar className="h-24 w-24">
      <AvatarFallback className="text-2xl">
        {session.peerName.slice(0, 2).toUpperCase()}
      </AvatarFallback>
    </Avatar>
  </div>
)}
```

Track the presence of video via:

```tsx
const [hasRemoteVideo, setHasRemoteVideo] = React.useState(false);

React.useEffect(() => {
  if (!remoteStream) { setHasRemoteVideo(false); return; }
  const videoTracks = remoteStream.getVideoTracks();
  setHasRemoteVideo(videoTracks.length > 0 && videoTracks[0].enabled);
  const handler = () => {
    setHasRemoteVideo(videoTracks.some((t) => t.enabled && !t.muted));
  };
  videoTracks.forEach((t) => {
    t.addEventListener("mute", handler);
    t.addEventListener("unmute", handler);
    t.addEventListener("ended", handler);
  });
  return () => {
    videoTracks.forEach((t) => {
      t.removeEventListener("mute", handler);
      t.removeEventListener("unmute", handler);
      t.removeEventListener("ended", handler);
    });
  };
}, [remoteStream]);
```

---

## 4. Implementation Plan

### 4.1 Props Changes to CallSessionOverlay

<!-- NOTE: IMPLEMENTED — Props interface at CallSessionOverlay.tsx:42 includes localStream, remoteStream, isMuted, isCameraOff, onToggleMute, onToggleCamera, plus recording and screen share props. -->

```tsx
interface Props {
  session: CallSessionUi;
  isBusy?: boolean;
  localStream?: MediaStream | null;
  remoteStream?: MediaStream | null;
  onAccept: () => void;
  onDecline: () => void;
  onEnd: () => void;
  onDismiss: () => void;
  onToggleMute?: () => void;
  onToggleCamera?: () => void;
  isMuted?: boolean;
  isCameraOff?: boolean;
}
```

### 4.2 Passing Streams from ConversationView

<!-- NOTE: IMPLEMENTED — ConversationView.tsx:92 types callResourcesRef as CallRuntimeResources | null. Streams come from useRtcPeerConnection hook (line 618) and useMediaCapture (line 94). Streams are passed to overlay at line 1287. -->
In `ConversationView.tsx`, `callResourcesRef` is typed as `CallRuntimeResources | null` (line 92). Streams are exposed reactively from `useRtcPeerConnection` (line 618) and `useMediaCapture` (line 94):

```tsx
const [localStream, setLocalStream] = React.useState<MediaStream | null>(null);
const [remoteStream, setRemoteStream] = React.useState<MediaStream | null>(null);
const [isMuted, setIsMuted] = React.useState(false);
const [isCameraOff, setIsCameraOff] = React.useState(false);
```

Update the stream state whenever call resources change (inside `onSuccess` of accept/connect flows and inside the WebRTC `ontrack` handler which will be wired in a companion ticket).

Pass to overlay:

```tsx
<CallSessionOverlay
  session={overlaySession}
  isBusy={callActionMutation.isPending}
  localStream={localStream}
  remoteStream={remoteStream}
  isMuted={isMuted}
  isCameraOff={isCameraOff}
  onToggleMute={() => {
    if (!localStream) return;
    localStream.getAudioTracks().forEach((t) => { t.enabled = !t.enabled; });
    setIsMuted((m) => !m);
  }}
  onToggleCamera={() => {
    if (!localStream) return;
    localStream.getVideoTracks().forEach((t) => { t.enabled = !t.enabled; });
    setIsCameraOff((c) => !c);
  }}
  onAccept={...}
  onDecline={...}
  onEnd={...}
  onDismiss={...}
/>
```

### 4.3 New Sub-Components

<!-- NOTE: ALL IMPLEMENTED as local components within CallSessionOverlay.tsx:
- VideoRenderer: line 90
- AudioRenderer: line 117
- CallTimer: line 131
- CallControls: line 167 (extended with recording + screen share controls)
-->

#### `VideoRenderer`

```tsx
interface VideoRendererProps {
  stream: MediaStream | null | undefined;
  muted?: boolean;
  mirror?: boolean;
  className?: string;
  "aria-label"?: string;
}

function VideoRenderer({ stream, muted = false, mirror = false, className, ...props }: VideoRendererProps) {
  const videoRef = React.useRef<HTMLVideoElement>(null);

  React.useEffect(() => {
    if (!videoRef.current) return;
    videoRef.current.srcObject = stream ?? null;
    return () => {
      if (videoRef.current) videoRef.current.srcObject = null;
    };
  }, [stream]);

  return (
    <video
      ref={videoRef}
      autoPlay
      playsInline
      muted={muted}
      className={cn(
        "h-full w-full object-cover",
        mirror && "[transform:scaleX(-1)]",
        className,
      )}
      aria-label={props["aria-label"]}
    />
  );
}
```

#### `AudioRenderer`

```tsx
function AudioRenderer({ stream }: { stream: MediaStream | null | undefined }) {
  const audioRef = React.useRef<HTMLAudioElement>(null);

  React.useEffect(() => {
    if (!audioRef.current) return;
    audioRef.current.srcObject = stream ?? null;
    return () => {
      if (audioRef.current) audioRef.current.srcObject = null;
    };
  }, [stream]);

  return <audio ref={audioRef} autoPlay className="hidden" />;
}
```

#### `CallTimer`

```tsx
function CallTimer({ running }: { running: boolean }) {
  const [elapsed, setElapsed] = React.useState(0);

  React.useEffect(() => {
    if (!running) { setElapsed(0); return; }
    const interval = window.setInterval(() => setElapsed((e) => e + 1), 1000);
    return () => window.clearInterval(interval);
  }, [running]);

  const minutes = Math.floor(elapsed / 60).toString().padStart(2, "0");
  const seconds = (elapsed % 60).toString().padStart(2, "0");

  return (
    <span className="font-mono text-sm tabular-nums text-muted-foreground" aria-label="Call duration">
      {minutes}:{seconds}
    </span>
  );
}
```

#### `CallControls`

```tsx
interface CallControlsProps {
  mode: DirectCallMode;
  isMuted: boolean;
  isCameraOff: boolean;
  onToggleMute: () => void;
  onToggleCamera: () => void;
  onEnd: () => void;
  isBusy: boolean;
}

function CallControls({ mode, isMuted, isCameraOff, onToggleMute, onToggleCamera, onEnd, isBusy }: CallControlsProps) {
  return (
    <div className="flex items-center justify-center gap-3">
      <Button
        variant={isMuted ? "destructive" : "secondary"}
        size="icon"
        className="h-10 w-10 rounded-full"
        onClick={onToggleMute}
        aria-label={isMuted ? "Unmute microphone" : "Mute microphone"}
      >
        {isMuted ? <MicOff className="h-4 w-4" /> : <Mic className="h-4 w-4" />}
      </Button>

      {mode === "video" && (
        <Button
          variant={isCameraOff ? "destructive" : "secondary"}
          size="icon"
          className="h-10 w-10 rounded-full"
          onClick={onToggleCamera}
          aria-label={isCameraOff ? "Turn camera on" : "Turn camera off"}
        >
          {isCameraOff ? <VideoOff className="h-4 w-4" /> : <Video className="h-4 w-4" />}
        </Button>
      )}

      <Button
        variant="destructive"
        size="icon"
        className="h-12 w-12 rounded-full"
        onClick={onEnd}
        disabled={isBusy}
        aria-label="End call"
      >
        <PhoneOff className="h-5 w-5" />
      </Button>
    </div>
  );
}
```

### 4.4 Updated CallSessionOverlay JSX (Connected State)

Replace the existing connected-state rendering. The full component body for the connected state becomes:

```tsx
// When connected with VIDEO mode:
if (isConnected && session.mode === "video") {
  return (
    <Dialog open onOpenChange={(open) => !open && onDismiss()}>
      <DialogContent
        className="sm:max-w-[95vw] md:max-w-4xl max-h-[90vh] p-0 overflow-hidden"
        aria-label="Video call"
      >
        {/* Hidden audio element for remote audio playback */}
        <AudioRenderer stream={remoteStream} />

        {/* Remote video (full area) */}
        <div className="relative w-full aspect-video bg-black">
          {hasRemoteVideo ? (
            <VideoRenderer
              stream={remoteStream}
              aria-label="Remote video"
            />
          ) : (
            <div className="flex h-full w-full items-center justify-center bg-gradient-to-b from-zinc-800 to-zinc-900">
              <Avatar className="h-24 w-24">
                <AvatarFallback className="text-2xl bg-zinc-700 text-white">
                  {session.peerName.slice(0, 2).toUpperCase()}
                </AvatarFallback>
              </Avatar>
            </div>
          )}

          {/* Local PiP */}
          <div className="absolute bottom-4 right-4 w-28 h-20 sm:w-40 sm:h-28 rounded-xl overflow-hidden ring-2 ring-white/60 shadow-lg">
            {isCameraOff ? (
              <div className="flex h-full w-full items-center justify-center bg-zinc-800">
                <VideoOff className="h-5 w-5 text-zinc-400" />
              </div>
            ) : (
              <VideoRenderer
                stream={localStream}
                muted
                mirror
                aria-label="Local video preview"
              />
            )}
          </div>

          {/* Peer name + timer overlay */}
          <div className="absolute top-4 left-4 flex items-center gap-2 rounded-lg bg-black/50 px-3 py-1.5 text-white backdrop-blur-sm">
            <span className="text-sm font-medium">{session.peerName}</span>
            <CallTimer running />
          </div>
        </div>

        {/* Controls bar */}
        <div className="flex items-center justify-center px-4 py-4 bg-background">
          <CallControls
            mode="video"
            isMuted={isMuted}
            isCameraOff={isCameraOff}
            onToggleMute={onToggleMute ?? (() => {})}
            onToggleCamera={onToggleCamera ?? (() => {})}
            onEnd={onEnd}
            isBusy={isBusy}
          />
        </div>

        {/* Visually hidden DialogTitle for accessibility */}
        <DialogHeader className="sr-only">
          <DialogTitle>Video call with {session.peerName}</DialogTitle>
          <DialogDescription>Video call in progress</DialogDescription>
        </DialogHeader>
      </DialogContent>
    </Dialog>
  );
}

// When connected with AUDIO mode:
if (isConnected && session.mode === "audio") {
  return (
    <Dialog open onOpenChange={(open) => !open && onDismiss()}>
      <DialogContent className="sm:max-w-md" aria-label="Audio call">
        {/* Remote audio playback */}
        <AudioRenderer stream={remoteStream} />

        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <PhoneCall className="h-4 w-4" />
            Audio call
          </DialogTitle>
          <DialogDescription className="sr-only">
            Audio call in progress with {session.peerName}
          </DialogDescription>
        </DialogHeader>

        {/* Avatar + name + timer */}
        <div className="flex items-center gap-4 py-4">
          <Avatar className="h-16 w-16">
            <AvatarFallback className="text-xl">
              {session.peerName.slice(0, 2).toUpperCase()}
            </AvatarFallback>
          </Avatar>
          <div className="flex flex-col gap-1">
            <span className="text-sm font-semibold">{session.peerName}</span>
            <div className="flex items-center gap-2">
              <span className="text-xs text-muted-foreground">Connected</span>
              <CallTimer running />
            </div>
          </div>
        </div>

        {/* Controls */}
        <DialogFooter className="justify-center sm:justify-center">
          <CallControls
            mode="audio"
            isMuted={isMuted}
            isCameraOff={isCameraOff}
            onToggleMute={onToggleMute ?? (() => {})}
            onToggleCamera={onToggleCamera ?? (() => {})}
            onEnd={onEnd}
            isBusy={isBusy}
          />
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
```

### 4.5 New Imports Required

Add to `CallSessionOverlay.tsx`:

```tsx
import { Mic, MicOff, VideoOff } from "lucide-react";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { cn } from "@/lib/utils";
```

The existing imports of `Phone`, `PhoneCall`, `PhoneIncoming`, `PhoneOff`, `Video` remain. Add `Video as VideoIcon` if there is a naming conflict, or keep `Video` from lucide-react and reference the mode enum separately.

### 4.6 File Changes Summary

| File | Change |
|------|--------|
| `frontend/src/pages/messages/CallSessionOverlay.tsx` | Add media props, add `VideoRenderer`, `AudioRenderer`, `CallTimer`, `CallControls` sub-components, rewrite connected-state JSX for both audio and video modes |
| `frontend/src/pages/messages/ConversationView.tsx` | Add `localStream`/`remoteStream`/`isMuted`/`isCameraOff` state, pass to `CallSessionOverlay`, add toggle handlers |
| `frontend/src/pages/messages/callStateMachine.ts` | No changes needed (already has `CallRuntimeResources` with stream fields) |

### 4.7 CSS Additions

No custom CSS file changes needed. All styling uses Tailwind utility classes. One pseudo-custom class:

```
[transform:scaleX(-1)]
```

This is a Tailwind arbitrary property for mirroring the local video preview. Tailwind v4 supports this natively via `[transform:scaleX(-1)]` syntax.

---

## 5. Testing Strategy

### 5.1 Unit Tests (Vitest/Jest)

#### VideoRenderer srcObject binding

```tsx
// Test: srcObject is set when stream prop is provided
it("sets srcObject on the video element when stream changes", () => {
  const stream = new MediaStream();
  render(<VideoRenderer stream={stream} />);
  const video = screen.getByRole("video") ?? document.querySelector("video");
  expect(video.srcObject).toBe(stream);
});

// Test: srcObject is cleared on unmount
it("clears srcObject on unmount", () => {
  const stream = new MediaStream();
  const { unmount } = render(<VideoRenderer stream={stream} />);
  const video = document.querySelector("video")!;
  unmount();
  expect(video.srcObject).toBeNull();
});

// Test: srcObject updates when stream changes
it("updates srcObject when stream prop changes", () => {
  const stream1 = new MediaStream();
  const stream2 = new MediaStream();
  const { rerender } = render(<VideoRenderer stream={stream1} />);
  const video = document.querySelector("video")!;
  expect(video.srcObject).toBe(stream1);
  rerender(<VideoRenderer stream={stream2} />);
  expect(video.srcObject).toBe(stream2);
});
```

#### AudioRenderer

```tsx
it("renders a hidden audio element with srcObject bound", () => {
  const stream = new MediaStream();
  render(<AudioRenderer stream={stream} />);
  const audio = document.querySelector("audio")!;
  expect(audio.srcObject).toBe(stream);
  expect(audio.className).toContain("hidden");
  expect(audio.autoplay).toBe(true);
});
```

#### CallTimer

```tsx
it("increments every second when running=true", async () => {
  vi.useFakeTimers();
  render(<CallTimer running />);
  expect(screen.getByLabelText("Call duration").textContent).toBe("00:00");
  vi.advanceTimersByTime(3000);
  expect(screen.getByLabelText("Call duration").textContent).toBe("00:03");
  vi.useRealTimers();
});

it("resets to 00:00 when running changes to false", () => {
  vi.useFakeTimers();
  const { rerender } = render(<CallTimer running />);
  vi.advanceTimersByTime(5000);
  rerender(<CallTimer running={false} />);
  expect(screen.getByLabelText("Call duration").textContent).toBe("00:00");
  vi.useRealTimers();
});
```

#### CallControls

```tsx
it("shows camera toggle only for video mode", () => {
  const { rerender } = render(
    <CallControls mode="audio" isMuted={false} isCameraOff={false}
      onToggleMute={vi.fn()} onToggleCamera={vi.fn()} onEnd={vi.fn()} isBusy={false} />
  );
  expect(screen.queryByLabelText("Mute microphone")).toBeInTheDocument();
  expect(screen.queryByLabelText("Turn camera off")).not.toBeInTheDocument();

  rerender(
    <CallControls mode="video" isMuted={false} isCameraOff={false}
      onToggleMute={vi.fn()} onToggleCamera={vi.fn()} onEnd={vi.fn()} isBusy={false} />
  );
  expect(screen.queryByLabelText("Turn camera off")).toBeInTheDocument();
});

it("shows destructive variant when muted", () => {
  render(
    <CallControls mode="audio" isMuted={true} isCameraOff={false}
      onToggleMute={vi.fn()} onToggleCamera={vi.fn()} onEnd={vi.fn()} isBusy={false} />
  );
  const muteBtn = screen.getByLabelText("Unmute microphone");
  expect(muteBtn.className).toContain("destructive");
});
```

### 5.2 Integration Tests (Connected State Rendering)

```tsx
it("renders video layout when connected in video mode", () => {
  const session: CallSessionUi = {
    state: "connected",
    direction: "outgoing",
    mode: "video",
    peerName: "Bob",
    callId: "call-123",
  };
  render(
    <CallSessionOverlay
      session={session}
      localStream={new MediaStream()}
      remoteStream={new MediaStream()}
      onAccept={vi.fn()} onDecline={vi.fn()} onEnd={vi.fn()} onDismiss={vi.fn()}
    />
  );
  expect(screen.getByLabelText("Video call")).toBeInTheDocument();
  expect(screen.getByLabelText("Remote video")).toBeInTheDocument();
  expect(screen.getByLabelText("Local video preview")).toBeInTheDocument();
  expect(screen.getByLabelText("End call")).toBeInTheDocument();
  expect(screen.getByLabelText("Mute microphone")).toBeInTheDocument();
  expect(screen.getByLabelText("Turn camera off")).toBeInTheDocument();
  expect(screen.getByLabelText("Call duration")).toBeInTheDocument();
});

it("renders audio layout when connected in audio mode", () => {
  const session: CallSessionUi = {
    state: "connected",
    direction: "outgoing",
    mode: "audio",
    peerName: "Alice",
    callId: "call-456",
  };
  render(
    <CallSessionOverlay
      session={session}
      remoteStream={new MediaStream()}
      onAccept={vi.fn()} onDecline={vi.fn()} onEnd={vi.fn()} onDismiss={vi.fn()}
    />
  );
  expect(screen.getByLabelText("Audio call")).toBeInTheDocument();
  expect(screen.getByText("Alice")).toBeInTheDocument();
  expect(screen.getByText("Connected")).toBeInTheDocument();
  expect(screen.queryByLabelText("Remote video")).not.toBeInTheDocument();
  expect(screen.queryByLabelText("Turn camera off")).not.toBeInTheDocument();
});
```

### 5.3 E2E Tests (Playwright)

E2E testing of real WebRTC media requires mock `getUserMedia`. Playwright supports this via `page.context().grantPermissions(["camera", "microphone"])` and Chrome's `--use-fake-device-for-media-stream` flag.

Add to `playwright.config.ts` launch options:

```ts
use: {
  launchOptions: {
    args: [
      '--use-fake-device-for-media-stream',
      '--use-fake-ui-for-media-stream',
    ],
  },
}
```

<!-- NOTE: frontend/e2e/webrtc-call-media.spec.ts does not exist yet. Related tests exist in webrtc-media.spec.ts (1375 lines) and webrtc-calls.spec.ts (661 lines). -->
#### Test scenarios for `frontend/e2e/webrtc-call-media.spec.ts`:

1. **Video call shows remote video element when connected**: Start video call, verify `video[aria-label="Remote video"]` is visible
2. **Video call shows local PiP**: Verify `video[aria-label="Local video preview"]` is visible in connected state
3. **Audio call hides video elements**: Start audio call, verify no video elements rendered, verify hidden `<audio>` element exists
4. **Mute toggle disables audio track**: Click mute button, verify button changes to `aria-label="Unmute microphone"` with destructive style
5. **Camera off hides local PiP video**: Click camera off, verify PiP shows `VideoOff` icon instead of video
6. **Call timer increments**: Verify timer text changes from "00:00" to "00:01" after ~1 second
7. **End call clears srcObject**: End call, verify streams are cleaned up (overlay transitions to "ended" state)
8. **Dialog expands for video calls**: Verify dialog content has wider max-width class in video mode vs audio mode
9. **No-video fallback shows avatar**: When remote stream has no video tracks, verify avatar fallback is displayed

### 5.4 srcObject Cleanup Verification

Critical to verify that no memory leaks occur:

```tsx
it("does not leak MediaStream tracks after component unmounts", () => {
  const audioTrack = { stop: vi.fn(), enabled: true, kind: "audio", addEventListener: vi.fn(), removeEventListener: vi.fn() };
  const videoTrack = { stop: vi.fn(), enabled: true, kind: "video", addEventListener: vi.fn(), removeEventListener: vi.fn() };
  const stream = {
    getTracks: () => [audioTrack, videoTrack],
    getAudioTracks: () => [audioTrack],
    getVideoTracks: () => [videoTrack],
  } as unknown as MediaStream;

  const { unmount } = render(<VideoRenderer stream={stream} />);
  unmount();
  // The overlay itself does not stop tracks (that is teardownCallResources' job),
  // but it must null out srcObject to release the element's reference.
  const video = document.querySelector("video");
  // After unmount, the DOM element is removed, but we verify the effect cleanup ran.
});
```

### 5.5 Visual Regression Testing

Use Playwright's `toHaveScreenshot()` for layout verification:

```ts
test("video call connected layout matches snapshot", async ({ page }) => {
  // Navigate to a conversation and trigger a connected video call state
  await injectAuth(page, "alice");
  // ... trigger call and mock connected state ...
  await expect(page.getByLabelText("Video call")).toHaveScreenshot("video-call-connected.png", {
    maxDiffPixelRatio: 0.05,
  });
});
```

### 5.6 Edge Cases to Test

| Scenario | Expected Behavior |
|----------|-------------------|
| `remoteStream` is null during connected state | Show avatar fallback, play no audio |
| `localStream` is null (permission denied) | Hide PiP entirely, show toast warning |
| Remote video track becomes muted mid-call | Transition to avatar fallback smoothly |
| Browser tab hidden during video call | Streams continue (no track.stop), timer pauses display update |
| Dialog dismissed via Escape key | `onDismiss` fires, streams remain (user may want to keep call active) |
| Network reconnection during call | Overlay shows "Reconnecting..." then transitions back to connected with streams |

---

## Appendix: Complete Updated Props Interface

```typescript
export interface CallSessionUi {
  state: CallUiState;
  direction: "incoming" | "outgoing";
  mode: DirectCallMode;
  peerName: string;
  callId?: string;
  reasonMessage?: string;
}

interface Props {
  session: CallSessionUi;
  isBusy?: boolean;
  localStream?: MediaStream | null;
  remoteStream?: MediaStream | null;
  isMuted?: boolean;
  isCameraOff?: boolean;
  onAccept: () => void;
  onDecline: () => void;
  onEnd: () => void;
  onDismiss: () => void;
  onToggleMute?: () => void;
  onToggleCamera?: () => void;
}
```

---

## Codebase References

| File | Lines | What |
|------|-------|------|
| `frontend/src/pages/messages/CallSessionOverlay.tsx` | 1-671 | Full call overlay (IMPLEMENTED) |
| `frontend/src/pages/messages/CallSessionOverlay.tsx` | 42-57 | Props interface (localStream, remoteStream, isMuted, isCameraOff, recording, screenshare) |
| `frontend/src/pages/messages/CallSessionOverlay.tsx` | 82-115 | `VideoRenderer` sub-component (srcObject management) |
| `frontend/src/pages/messages/CallSessionOverlay.tsx` | 117-128 | `AudioRenderer` sub-component (hidden audio element) |
| `frontend/src/pages/messages/CallSessionOverlay.tsx` | 131-147 | `CallTimer` sub-component |
| `frontend/src/pages/messages/CallSessionOverlay.tsx` | 150-237 | `CallControls` sub-component (mute, camera, recording, screenshare, end) |
| `frontend/src/pages/messages/CallSessionOverlay.tsx` | 340-360 | `hasRemoteVideo` state + track event listeners |
| `frontend/src/pages/messages/ConversationView.tsx` | 92 | `callResourcesRef` typed as `CallRuntimeResources` |
| `frontend/src/pages/messages/ConversationView.tsx` | 618-637 | `useRtcPeerConnection` hook providing rtcLocalStream/rtcRemoteStream |
| `frontend/src/pages/messages/ConversationView.tsx` | 1282-1290 | CallSessionOverlay mount with stream props |
| `frontend/src/pages/messages/callStateMachine.ts` | 190-222 | `CallRuntimeResources` interface + `teardownCallResources()` |
| `frontend/src/hooks/useMediaCapture.ts` | 1-315 | Media capture hook |
| `frontend/src/hooks/useRtcPeerConnection.ts` | 1-518 | RTCPeerConnection lifecycle hook |
| `frontend/e2e/webrtc-media.spec.ts` | 1-1375 | E2E media tests (IMPLEMENTED) |
| `frontend/e2e/webrtc-calls.spec.ts` | 1-661 | E2E WebRTC call tests (IMPLEMENTED) |
| `frontend/e2e/webrtc-call-media.spec.ts` | — | Does not exist yet — media rendering E2E tests |
