# CALL-013: Video Call Screen Sharing

**Status**: Implemented  
**Author**: Engineering  
**Date**: 2026-05-28  
**Priority**: High  
**Estimated effort**: 8-12 days  
**Dependencies**: CALL-002 (RTCPeerConnection), CALL-005 (Media Controls), CALL-012 (Group Video Calls)

> **NOTE — Feature is FULLY IMPLEMENTED.** Key files:
> - `frontend/src/lib/webrtc.ts` (149 lines, up from 92): `acquireScreenMedia()` at line 54, `isScreenShareSupported()` at line 92
> - `frontend/src/hooks/useScreenShare.ts` (219 lines): Screen share hook
> - `frontend/src/pages/messages/CallSessionOverlay.tsx` (671 lines): Screen share button (line 192-206), sharing/presenting indicators (lines 433-445), props include `isScreenSharing`, `onToggleScreenShare`, `screenShareSupported`
> - `frontend/src/pages/messages/GroupCallOverlay.tsx` (489 lines): Screen share button (line 396-401), presentation layout (lines 301-311), simultaneous share prevention UI (disabled button at line 291), `toggleScreenShare` at line 243
> - `app/services/messaging_call_signaling.py`: `webrtc.screen_share_start` and `webrtc.screen_share_stop` in `ALLOWED_SIGNALING_TYPES` (lines 28-29) and `STATE_ALLOWED_SIGNALING_TYPES` connected/accepted states (lines 45, 51)
> - `app/routers/messaging.py:13152`: `CallSignalingIn.type` regex updated to include screen share types
> - `app/services/group_call_service.py:357-391`: `_check_screen_share_conflict` for simultaneous share prevention
> - `app/core/settings.py:1052`: `messaging_screen_share_enabled` feature flag (defaults to `"true"`)
> - `frontend/e2e/call-screenshare.spec.ts` (517 lines): E2E tests

---

## 1. Overview & Motivation

### Problem Statement

The platform supports both 1:1 WebRTC video calls (`CallSessionOverlay.tsx`, `useRtcPeerConnection.ts`) and group video calls (`GroupCallOverlay.tsx`, `app/routers/group_calls.py`) but neither call type provides screen sharing capability. Users who need to present slides, demonstrate software, review documents, or collaborate visually during calls are forced to rely on external tools (Zoom, Google Meet) or awkward workarounds like holding their phone up to their monitor.

The WebRTC utility module (`frontend/src/lib/webrtc.ts`) only implements `acquireLocalMedia(mode)` using `navigator.mediaDevices.getUserMedia()` (line 15). There is no `getDisplayMedia()` implementation anywhere in the codebase.
<!-- UPDATE: webrtc.ts NOW has acquireScreenMedia (line 54) and isScreenShareSupported (line 92) in addition to the original 4 functions. File is now 149 lines. -->

The group call system already has partial infrastructure for screen sharing: `GroupCallMediaStatus` includes a `screen: bool` field (line 3109 of `app/models.py`), the `PATCH /{call_id}/media` endpoint accepts `screen` in `GroupCallMediaUpdateIn` (line 3192), and the `ParticipantTile` component renders a `MonitorUp` icon when `participant.media_status.screen` is true (lines 421-425 of `GroupCallOverlay.tsx`). However, no actual screen capture, track replacement, or layout switching is implemented -- the `screen` field is purely cosmetic state with no media backing.
<!-- UPDATE: GroupCallMediaStatus at models.py:3219-3225 has audio/video/screen. GroupCallMediaUpdateIn at models.py:3302-3308 accepts Optional[bool] for screen. The screen share functionality IS now fully implemented: acquireScreenMedia in webrtc.ts, useScreenShare hook, screen share button in both overlays, simultaneous share prevention in group_call_service.py. -->

The 1:1 call system has zero screen sharing support. `CallSessionOverlay.tsx` has no screenshare button in its `CallControls` component (lines 157-211), no screen sharing state tracking, and the `CallSessionRecord` dataclass in `messaging_call_sessions.py` (line 19) has no `screen_sharing` field. The signaling types in `messaging_call_signaling.py` (line 14) do not include screen share events.
<!-- UPDATE: CallControls now includes screen share button (lines 192-206) with isScreenSharing/onToggleScreenShare/screenShareSupported props. ALLOWED_SIGNALING_TYPES NOW includes webrtc.screen_share_start (line 28) and webrtc.screen_share_stop (line 29). CallSessionRecord still has no screen_sharing field (ephemeral state as designed). -->

### Goals

1. Add `acquireScreenMedia()` to `frontend/src/lib/webrtc.ts` using the browser `getDisplayMedia()` API with graceful permission denial and track-ended handling.
2. Add a screen share toggle button to both `CallSessionOverlay.tsx` (1:1 calls) and `GroupCallOverlay.tsx` (group calls) with proper visual state feedback.
3. Implement track replacement on the existing `RTCPeerConnection` using `RTCRtpSender.replaceTrack()` to swap between camera and screen tracks without SDP renegotiation.
4. For group calls, signal screen sharing state via the existing `PATCH /{call_id}/media` endpoint with `screen: true/false`.
5. For 1:1 calls, add new signaling event types (`webrtc.screen_share_start`, `webrtc.screen_share_stop`) to notify the remote peer.
6. Implement "presentation mode" layout switching: when any participant is screen sharing, the screen share content gets primary viewport (80%) while camera feeds move to a sidebar strip.
7. Handle all edge cases: browser denying permission, user clicking "Stop sharing" in the browser chrome, multiple participants attempting to share simultaneously, and screen sharing during audio-only calls.

### User Stories

| # | As a... | I want to... | So that... |
|---|---------|-------------|-----------|
| 1 | 1:1 call participant | Press a "Share Screen" button during a connected video call | I can show my screen to the other person |
| 2 | 1:1 call participant | See the other person's shared screen in a large viewport | I can view their content clearly |
| 3 | Group call participant | Share my screen with all participants | I can present slides or demo software to the group |
| 4 | Group call participant | See who is screen sharing via a visual indicator | I know whose screen is being displayed |
| 5 | Screen sharer | Stop sharing by clicking the toggle button OR the browser's native "Stop sharing" bar | I have multiple ways to end the share |
| 6 | Participant | Have the layout automatically switch to presentation mode when someone shares | The shared content is prominently displayed |
| 7 | Participant | See both the shared screen and the sharer's camera (PiP) | I can see their reactions while viewing their screen |
| 8 | Audio call participant | Not see a screen share button | The UI does not offer features that require video infrastructure |
| 9 | Presenter | See a preview of what I am sharing in a small PiP window | I can confirm the correct content is being shared without losing context of the call |
| 10 | Group call creator | Know which participant is currently screen sharing | I can moderate the presentation and manage turn-taking |
| 11 | Participant | Be notified when someone starts or stops sharing their screen | I know when to pay attention to the shared content and when it returns to normal view |
| 12 | Mobile user | Have the screen share button hidden if my device does not support it | I am not confused by non-functional UI elements |
| 13 | Presenter on a slow connection | Have screen content prioritized over camera resolution | The shared document or slides remain readable even if my camera quality degrades |
| 14 | Group call participant | Be informed why I cannot share when someone else is already sharing | I understand the limitation and can wait for my turn |
| 15 | Call recorder | Have the screen share automatically captured in the call recording | The recording reflects what participants actually saw during the call |
| 16 | Presenter | Have text and UI elements on my shared screen remain sharp and legible | Participants can read code, documents, and slide text clearly |
| 17 | 1:1 call participant | Continue hearing the other person's audio unchanged while they share their screen | Screen sharing does not interrupt the conversation |

### Scope

**In scope**: `getDisplayMedia()` utility, screen share toggle in both overlays, `replaceTrack()` on RTCPeerConnection, signaling for 1:1 screen share events, media state update for group screen shares, presentation mode layout, browser "Stop sharing" detection, simultaneous share prevention in groups, camera track preservation and restoration.

**Out of scope (non-goals)**:
- Screen sharing during audio-only calls (requires adding a video track to an audio-only connection, which mandates SDP renegotiation -- deferred to a future ticket)
- System audio capture alongside screen share (browser support is inconsistent; `getDisplayMedia` audio is Chromium-only and opt-in)
- Screen share recording integration (CALL-009 already records the composite stream; when screen share replaces the camera track, MediaRecorder automatically captures it)
- Annotation/drawing overlay on shared screens
- Remote control of shared screens
- Screen share in broadcast calls (BCAST-011)
- Multi-stream screen sharing (sharing camera AND screen as separate tracks simultaneously -- this requires SDP renegotiation with addTrack, not replaceTrack)
- Virtual background or blurring during screen share
- Screen share with DRM-protected content (browsers block `getDisplayMedia` on DRM-protected tabs)
- Collaborative whiteboard or shared canvas features

### Competitive Analysis

| Platform | Screen Share Approach | Presentation Layout | Simultaneous Shares | Tab Audio | Mobile Support |
|----------|----------------------|--------------------|--------------------|-----------|---------------|
| **Zoom** | `getDisplayMedia` + separate video stream (not replaceTrack); dual-stream architecture sends camera and screen simultaneously | Full-screen share with floating camera strip, "Side-by-side" mode, customizable layouts | Allows multiple shares (up to 25 with SFU) | Yes (Chrome tab audio) | Android only; iOS via screen broadcast extension |
| **Google Meet** | `getDisplayMedia` + `replaceTrack`; newer versions use insertable streams | Screen dominates with bottom-row camera tiles | One at a time; new share overrides old | Yes (Chrome tab audio) | Android only; iOS not supported |
| **Microsoft Teams** | `getDisplayMedia` with custom constraints; PowerPoint integration uses separate pipeline | "Content only" or "Standout" modes; presenter appears over slides | One at a time per meeting; "Take control" feature | Yes (system audio on Windows desktop app) | Limited; desktop-only for full screen share |
| **Discord** | `getDisplayMedia` for "Go Live" streaming; separate screen share channel | Screen share is its own stream/tile in the grid | One share per voice channel | Yes (application audio on Chromium) | Not supported on mobile |
| **Our platform (proposed)** | `getDisplayMedia` + `replaceTrack` (no renegotiation); single video stream swaps between camera and screen | Auto-switch to presentation mode; sidebar camera strip | One at a time (group); both can share (1:1) | No (v1 -- audio capture deferred) | Android Chromium only; hidden on iOS |

**Key takeaways from competitive analysis**:
1. All major platforms use `getDisplayMedia` -- there is no alternative API.
2. `replaceTrack` is the simplest and most compatible approach for v1. Multi-stream (camera + screen simultaneously) is a v2 enhancement requiring SDP renegotiation or insertable streams.
3. One-at-a-time sharing in groups is the industry standard for simple implementations. Multi-share requires SFU infrastructure we do not have yet.
4. Auto-switching to presentation layout when a share starts is universal.
5. Tab audio sharing is Chromium-only and can be added as a future enhancement.

---

## 2. Current State Analysis

### 2.1 WebRTC Utility Module (`frontend/src/lib/webrtc.ts`, 92 lines)

The module exports four functions:

| Function | Line | Purpose |
|----------|------|---------|
| `acquireLocalMedia(mode)` | 15 | `getUserMedia` with audio + optional video. Retries with minimal constraints on `OverconstrainedError`. |
| `createIceCandidateBuffer()` | 48 | Buffers ICE candidates until remote description is set, then flushes to `pc.addIceCandidate`. |
| `generateNonce()` | 82 | 32-char hex nonce for signaling deduplication via `crypto.randomUUID().replace(/-/g, "").slice(0, 32)`. |
| `generateEventId(prefix)` | 89 | Unique event ID with prefix string via `` `${prefix}_${crypto.randomUUID()}` ``. |

<!-- VERIFIED: acquireLocalMedia at webrtc.ts:15-41. createIceCandidateBuffer at webrtc.ts:48-77. generateNonce at webrtc.ts:82-84. generateEventId at webrtc.ts:89-91. Total file 92 lines. -->

`acquireLocalMedia` constructs constraints with `facingMode: "user"` and 1280x720 ideal resolution (lines 20-26). The `getDisplayMedia()` API uses a fundamentally different constraints object (`{ video: { displaySurface: "monitor" } }`) and does not support `facingMode` or resolution ideals in the same way. A separate function is required.
<!-- VERIFIED: acquireLocalMedia at webrtc.ts:15-41. Constraints at lines 20-26 are getUserMedia-specific. getDisplayMedia requires different constraint shape. -->

**Error handling pattern**: `acquireLocalMedia` uses `try/catch` with a special retry path for `OverconstrainedError` (lines 30-40). When the video constraints cannot be met, it retries with `{ audio: true, video: true }` (minimal constraints). `getDisplayMedia` does not encounter `OverconstrainedError` in the same way (the browser picker handles source selection), so the retry logic is not applicable. However, `getDisplayMedia` can throw `NotAllowedError` (user cancelled picker), `AbortError` (browser cancelled), and `NotFoundError` (API unavailable). The new `acquireScreenMedia` should match the existing error-throwing pattern for consistent caller handling.

**API availability guard**: `acquireLocalMedia` checks `navigator.mediaDevices?.getUserMedia` at line 16 and throws a `DOMException("Media devices API not available", "NotFoundError")` if the API is missing. The screen share function must perform the same guard for `navigator.mediaDevices?.getDisplayMedia`.

### 2.2 `useRtcPeerConnection.ts` (519 lines)

The hook manages the full RTCPeerConnection lifecycle for 1:1 calls. Key observations for screen sharing:

**Hook interface** (lines 23-36): `UseRtcPeerConnectionParams` accepts `callId`, `conversationId`, `role` (caller/callee), `mode` (audio/video), `phase` (the `CallUiState`), `peerId`, `userId`, `enabled`, `retryCount`, and three callbacks (`onConnect`, `onConnectionLost`, `onFail`). The return type (lines 38-44) provides `localStream`, `remoteStream`, `resources`, `connectionState`, and `performIceRestart`. Screen sharing state is not part of this interface and will be managed by a separate `useScreenShare` hook that receives the `peerConnection` from `resources.peerConnection`.
<!-- VERIFIED: UseRtcPeerConnectionParams at useRtcPeerConnection.ts:23-36. UseRtcPeerConnectionReturn at useRtcPeerConnection.ts:38-44. -->

**Activation logic** (lines 59-67): The `shouldActivate` function determines when the hook sets up the peer connection based on the call phase and the user's role. The hook only activates in `outgoing_ringing` (caller), `outgoing_connecting` (callee/reconnect), or `connected` (both). Screen sharing is only relevant in the `connected` phase, which is already covered.
<!-- VERIFIED: shouldActivate at useRtcPeerConnection.ts:59-67. Connected phase included for both caller and callee. -->

**Track addition (lines 182-184)**: Local tracks are added via `pc.addTrack(track, localMediaStream)` inside a `for...of` loop. This returns an `RTCRtpSender` object, but the return value is discarded. For `replaceTrack()`, we need access to the sender. Two approaches:
1. Store the video sender from `addTrack()` in a ref (minimal change)
2. Use `pc.getSenders().find(s => s.track?.kind === "video")` at share time (no state change needed, slightly less efficient)

Option 2 is preferred because it avoids modifying the existing setup flow and works even if the sender list changes due to renegotiation.
<!-- VERIFIED: addTrack at useRtcPeerConnection.ts:182-184. Return value (RTCRtpSender) is not captured. pc.getSenders() is available on all RTCPeerConnection instances and returns the current sender list. -->

**Stream state (lines 85-88)**: `localStream` and `remoteStream` are React state managed via `useState`. When the screen share track replaces the camera track, the `localStream` state does not change (the MediaStream object identity stays the same, only the track within it changes). This means `localStream` continues to be valid for the local PiP preview during screen sharing, but the video element will show the screen instead of the camera. The camera track should be preserved in a ref so it can be restored when sharing stops.
<!-- VERIFIED: localStream/remoteStream state at useRtcPeerConnection.ts:85-86. setLocalStream at line 176. -->

**TURN credential fetch** (lines 119-131): The setup function first fetches TURN credentials via `fetchTurnCredentials(callId)` and maps them to `RTCIceServer[]`. If TURN fetch fails, the hook continues with empty ICE servers (STUN/host candidates only). This is relevant because screen sharing does not require new TURN credentials -- the existing peer connection's TURN allocation is reused by `replaceTrack()`.
<!-- VERIFIED: TURN fetch at useRtcPeerConnection.ts:119-131. -->

**Peer connection creation** (lines 134-148): The `RTCPeerConnection` is created with the fetched ICE servers. The reference is stored in `pcRef` (line 149). The `useScreenShare` hook will access the peer connection via the `resources.peerConnection` ref exposed by the hook's return value.
<!-- VERIFIED: RTCPeerConnection creation at useRtcPeerConnection.ts:136-143. pcRef.current assignment at line 149. -->

**Dev-mode testability** (lines 152-156): In dev mode, the hook exposes `__rtcPeerConnection`, `__rtcLocalStream`, and `__rtcRemoteStream` on `window`. The screen share hook should similarly expose `__rtcScreenStream` for E2E test inspection.
<!-- VERIFIED: Dev mode window exposure at useRtcPeerConnection.ts:152-156. -->

**Remote stream ontrack handler** (lines 193-199): When the remote peer's track changes (via `replaceTrack`), the `ontrack` event fires on the receiver's side. The handler adds the incoming track to the `remote` MediaStream. Since `replaceTrack` replaces the track on the same transceiver, a new `ontrack` event may or may not fire depending on the browser. In Chrome, `replaceTrack` does NOT trigger `ontrack` -- the existing track simply starts producing different content. In Firefox, behavior is similar. This means the remote peer receives the screen share content seamlessly without needing to handle a new track event.
<!-- VERIFIED: ontrack handler at useRtcPeerConnection.ts:193-199. Adds tracks from event.streams[0] or event.track to remote MediaStream. -->

**ICE candidate trickle** (lines 249-269): Outbound ICE candidates are sent via the signaling API. This pipeline is unchanged by screen sharing.
<!-- VERIFIED: pc.onicecandidate at useRtcPeerConnection.ts:249-269. -->

**SSE event handler** (lines 272-353): Handles `webrtc.offer`, `webrtc.answer`, `webrtc.ice_candidate`. New `webrtc.screen_share_start` and `webrtc.screen_share_stop` events will be handled here to trigger layout changes on the remote peer's side. The handler is registered via `window.addEventListener("messaging:webrtc-signal", ...)` at line 355.
<!-- VERIFIED: SSE handler at useRtcPeerConnection.ts:272-353. Event listener registration at line 355. Handler checks detail.call_id and detail.sender_user_id before processing. -->

**ICE restart** (lines 416-456): `performIceRestart` creates a fresh offer with `{ iceRestart: true }`, optionally refreshing TURN credentials first. Screen sharing does not affect ICE restart -- if a restart occurs while screen sharing, the screen track continues to be sent on the restored connection (since `replaceTrack` replaced the track on the sender object, which persists across ICE restarts).
<!-- VERIFIED: performIceRestart at useRtcPeerConnection.ts:416-456. -->

**Resources ref (lines 391-399)**: `CallRuntimeResources` (defined in `callStateMachine.ts` at line 190) stores `peerConnection`, `localStream`, `remoteStream`, `detachListeners`, `teardownTimers`, and `cleanedUp`. The `teardownCallResources` function (callStateMachine.ts:199) stops all tracks on both streams and closes the peer connection. The screen share track must be stopped in this teardown if the call ends while sharing.
<!-- VERIFIED: CallRuntimeResources at callStateMachine.ts:190-197. teardownCallResources at callStateMachine.ts:199-222. Stops tracks on localStream and remoteStream. -->
<!-- CORRECTED: was "teardownCallResources at callStateMachine.ts:199-217", actually 199-222 (includes cleanedUp=true at line 221, closing brace at 222) -->

**Teardown on disable** (lines 474-492): When `enabled` becomes false or `callId` is cleared, the hook tears down resources and clears all state (localStream, remoteStream, connectionState, setupCallIdRef). The `useScreenShare` hook must respond to this by stopping screen tracks and resetting its own state.
<!-- VERIFIED: Teardown effect at useRtcPeerConnection.ts:474-492. -->

### 2.3 `CallSessionOverlay.tsx` (598 lines)

**Component props** (lines 41-63): The `Props` interface accepts `session` (CallSessionUi), `localStream`, `remoteStream`, `peerConnection`, mute/camera state, recording state, and handlers. No screen share props exist.
<!-- VERIFIED: Props interface at CallSessionOverlay.tsx:41-63. -->

**`VideoRenderer` sub-component** (lines 75-108): Renders a `<video>` element with `autoPlay`, `playsInline`, `muted`, and optional mirror transform. Crucially, the CSS class uses `object-cover` (line 101) which crops the video to fill its container. For screen share content, `object-contain` is needed to show the full screen without cropping. The renderer needs a new `objectFit` prop or the parent must override the class.
<!-- VERIFIED: VideoRenderer at CallSessionOverlay.tsx:75-108. object-cover at line 101. -->

**`AudioRenderer` sub-component** (lines 110-122): Hidden `<audio>` element for remote audio playback. Unchanged by screen sharing.
<!-- VERIFIED: AudioRenderer at CallSessionOverlay.tsx:110-122. -->

**`CallTimer` sub-component** (lines 124-141): Elapsed time counter. Unchanged by screen sharing.
<!-- VERIFIED: CallTimer at CallSessionOverlay.tsx:124-141. -->

**`CallControls` sub-component** (lines 143-211): The `CallControls` sub-component renders controls in this order:

1. **Mute toggle** (lines 160-168): `<Button>` with `Mic`/`MicOff` icon
2. **Camera toggle** (lines 170-180): `<Button>` with `Video`/`VideoOff` icon, only shown for `mode === "video"`
3. **End call** (lines 182-191): `<Button variant="destructive">` with `PhoneOff` icon
4. **Recording** (lines 193-209): `<Button>` with `Circle` icon, only shown when `recordingEnabled`

The screen share button will be inserted between the camera toggle and the end call button (position 3, before end call). It should only render when `mode === "video"` and the call is in the `connected` state.

**`CallControls` props** (lines 143-155): Must be extended with `isScreenSharing`, `onToggleScreenShare`, and `screenShareEnabled` props.
<!-- VERIFIED: CallControlsProps at CallSessionOverlay.tsx:143-155. No screen share props. -->

**Connection quality indicator** (lines 221-257): The `ConnectionQualityIndicator` component renders a `Signal` icon with tooltip showing RTT and packet loss. This is positioned in the top-left overlay during video calls (line 378). Screen sharing does not affect this component, but the quality indicator becomes more important during screen sharing since screen content (high-detail, low-motion) is more sensitive to quality degradation than camera video.
<!-- VERIFIED: ConnectionQualityIndicator at CallSessionOverlay.tsx:228-257. Positioned at line 378. -->

**Main component state tracking** (lines 268-324): The `CallSessionOverlay` function component tracks call phase (incoming, outgoing, connected, outcome) and remote video availability via `hasRemoteVideo` state. The `hasRemoteVideo` state is derived from `remoteStream.getVideoTracks()` with mute/unmute/ended event listeners (lines 301-324). When screen sharing starts, the remote video track content changes but the track object itself is unchanged (since `replaceTrack` operates at the RTP level). Therefore, `hasRemoteVideo` correctly remains `true` during screen sharing.
<!-- VERIFIED: hasRemoteVideo state at CallSessionOverlay.tsx:301-324. Track event listeners at lines 308-323. -->

**Video call connected layout** (lines 333-441): Currently renders remote video full-area with local video in a PiP corner (lines 361-374). When the remote peer is screen sharing, this layout must switch to presentation mode: screen share content fills the main area, and the peer's camera moves to a PiP. When the local user is screen sharing, their local PiP shows the screen share content (or optionally their camera).
<!-- VERIFIED: Remote video at lines 344-358 uses VideoRenderer with remote stream. Local PiP at lines 361-374 in bottom-right corner. Layout change required for presentation mode. -->

**Recording indicator** (lines 389-394): A red "REC" badge with pulse animation in the top-right corner. A similar "Sharing" badge will be placed nearby for screen share indication.
<!-- VERIFIED: Recording indicator at CallSessionOverlay.tsx:389-394. data-testid="recording-indicator". -->

**Controls bar** (lines 397-411): `CallControls` rendered in a flex container centered at the bottom. The screen share button will be added to the `CallControls` component.
<!-- VERIFIED: Controls bar at CallSessionOverlay.tsx:397-411. -->

**Recording consent dialog** (lines 414-431): Overlay dialog shown when the remote peer requests recording consent. This pattern can be reused for potential future "screen share consent" prompts if needed.
<!-- VERIFIED: Recording consent dialog at CallSessionOverlay.tsx:414-431. -->

**Audio call layout** (lines 444-527): Connected audio call renders an avatar, name, timer, and audio-only controls. No video rendering, no PiP. The screen share button will NOT be shown in this layout because screen sharing requires a video track, and audio-only calls have no video transceiver.
<!-- VERIFIED: Audio call connected layout at CallSessionOverlay.tsx:444-527. No video elements. -->

**Non-connected states** (lines 530-596): Incoming ring, outgoing ring, and outcome (ended/declined/busy) dialogs. Screen sharing is only available in the connected state.
<!-- VERIFIED: Non-connected states at CallSessionOverlay.tsx:530-596. -->

### 2.4 `GroupCallOverlay.tsx` (429 lines)

**Imports** (lines 1-42): Already imports `MonitorUp` from `lucide-react` (line 21). Also imports `Grid3X3` and `LayoutDashboard` for layout toggle (lines 22-23).
<!-- VERIFIED: MonitorUp import at GroupCallOverlay.tsx:21. Grid3X3 at line 22. LayoutDashboard at line 23. -->
<!-- CORRECTED: was "Grid3X3 at line 23, LayoutDashboard at line 24", actually Grid3X3 at line 22, LayoutDashboard at line 23 -->

**`GroupCallOverlay` component** (lines 182-371): The overlay component manages:
- **Layout state** (line 184): `layout` state with `"grid" | "speaker"` options.
- **Local media state** (lines 185-189): `localMedia` state of type `GroupCallMediaStatus` with `{ audio: true, video: true, screen: false }`.
- **Call data polling** (lines 192-196): `useQuery` with `refetchInterval: 3000` fetches call state every 3 seconds. This is how other participants' screen share state is discovered.
- **Media mutation** (lines 227-233): `mediaMut` calls `updateGroupCallMedia(callId, { screen: true/false })`. The `onSuccess` callback updates `localMedia` state with the response's `media_status`. This path is already complete for persisting screen share state -- we just need to trigger it.
- **Participant filtering** (lines 235-236): `activeParticipants` filters for `state === "active"`. Screen share state is available on each participant's `media_status.screen`.
- **Toggle functions** (lines 239-240): `toggleAudio` and `toggleVideo` call `mediaMut.mutate(...)`. A corresponding `toggleScreenShare` must be added.
<!-- VERIFIED: layout state at GroupCallOverlay.tsx:184. localMedia state at lines 185-189. callData polling at lines 192-196 with 3s interval. mediaMut at lines 227-233. activeParticipants at lines 235-236. toggleAudio/toggleVideo at lines 239-240. -->

**Grid column calculation** (lines 243-250): Computes CSS grid column classes based on participant count (1-2: 1-2 cols, 3-4: 2 cols, 5-6: 2-3 cols, 7+: 2-4 cols). This layout computation must be bypassed when presentation mode is active.
<!-- VERIFIED: gridCols computation at GroupCallOverlay.tsx:243-250. -->

**Top bar** (lines 258-277): Shows participant count, mode label, and layout toggle button. During presentation mode, the layout toggle should be disabled or hidden.
<!-- VERIFIED: Top bar at GroupCallOverlay.tsx:258-277. Layout toggle button at lines 267-275. -->

**Layout modes** (lines 280-311):
- **Grid layout** (lines 281-286): All participants in equal-sized tiles, CSS grid with computed column class.
- **Speaker layout** (lines 287-309): First participant rendered large (`flex-1`), rest in a horizontal thumbnail strip at the bottom.

Neither layout accounts for screen sharing. When a participant is screen sharing, the layout should switch to presentation mode regardless of the user's manual layout selection (grid/speaker):
- Screen share content in a large primary area (approximately 75-80% of viewport)
- All participant camera feeds in a vertical sidebar strip on the right (approximately 20-25% of viewport)
- The sharer's camera feed is shown as a PiP overlay on the screen share area
<!-- VERIFIED: Grid layout at GroupCallOverlay.tsx:281-286. Speaker layout at lines 287-309. No presentation mode. -->

**Controls bar** (lines 314-368): Renders audio toggle, video toggle, leave call, end call (creator only). No screen share button exists. The controls are rendered in a centered flex container with `gap-4`.
<!-- VERIFIED: Controls bar at GroupCallOverlay.tsx:314-368. Four buttons: audio toggle (315-327), video toggle (329-341), leave (343-353), end (355-367). -->

**`ParticipantTile`** (lines 382-428): The tile component renders:
- Avatar when video is off (lines 395-399)
- Video placeholder icon when video is on (lines 402-406) -- note: this is a UI-only placeholder, not an actual `<video>` element since CALL-012 is UI state management without real WebRTC media.
- Name overlay with "(You)" suffix for local participant (lines 409-411)
- Muted mic indicator in top-left corner (lines 414-418)
- **Screen share indicator** in top-right corner (lines 421-425): Blue `MonitorUp` icon badge when `participant.media_status.screen === true`.
<!-- VERIFIED: ParticipantTile at GroupCallOverlay.tsx:382-428. Screen share badge at lines 421-425. -->

### 2.5 Group Call Backend (`app/routers/group_calls.py`, 276 lines)

**Auth dependency** (lines 53-67): The `_get_user` function extracts `user_id` via `get_messaging_user_id` from the messaging router, and `role` from the session context. This is reused for all group call endpoints.
<!-- VERIFIED: _get_user at group_calls.py:53-67. -->

**`PATCH /{call_id}/media`** (lines 255-275): Accepts `GroupCallMediaUpdateIn` with optional `audio`, `video`, `screen` booleans. Calls `update_media_state()` from the service layer. Returns `GroupCallMediaUpdateOut` with the full `GroupCallMediaStatus`. Error handling catches `GroupCallError` and returns the appropriate HTTP status.
<!-- VERIFIED: PATCH media endpoint at group_calls.py:255-275. -->

**`GroupCallMediaStatus` model** (lines 3106-3109 of `models.py`):
```python
class GroupCallMediaStatus(BaseModel):
    audio: bool = True
    video: bool = True
    screen: bool = False
```

**`GroupCallMediaUpdateIn` model** (lines 3189-3192 of `models.py`):
```python
class GroupCallMediaUpdateIn(BaseModel):
    audio: Optional[bool] = None
    video: Optional[bool] = None
    screen: Optional[bool] = None
```

Both models are already complete for screen sharing state tracking. No backend model changes needed for group calls.
<!-- VERIFIED: GroupCallMediaStatus at models.py:3106-3109. GroupCallMediaUpdateIn at models.py:3189-3192. Both already have screen field. -->

### 2.6 Group Call Service (`app/services/group_call_service.py`, 477 lines)

**`update_media_state` function** (lines 357-383): Accepts `call_id`, `user_id`, and optional `audio`, `video`, `screen` booleans. Retrieves the participant record, merges the update into the existing `media_status` map, and writes it back to DynamoDB. The function does NOT currently check for simultaneous screen shares -- if participant A has `screen: true` and participant B sends `screen: true`, both succeed. This needs to be fixed.
<!-- VERIFIED: update_media_state at group_call_service.py:357-383. No simultaneous share prevention. -->

**DynamoDB single-table design**: Group call data is stored in a single table with composite keys:
- `PK=CALL#{call_id}, SK=META` -- call metadata (state, mode, participant count, timestamps)
- `PK=CALL#{call_id}, SK=PART#{user_id}` -- per-participant record (media_status, joined_at, connection_quality)

The `media_status` is stored as a DynamoDB map attribute: `{"audio": True, "video": True, "screen": False}`. This is read back in the `_participant_out` helper (group_calls.py:75-89) and mapped to `GroupCallMediaStatus`.
<!-- VERIFIED: DDB design at group_call_service.py:1-8 (module docstring). META row creation at lines 106-122. PART row creation at lines 195-208. media_status map at line 202. -->
<!-- CORRECTED: was "_participant_out helper (group_calls.py:76-89)", actually function def starts at line 75 -->

**`join_call` function** (lines 162-232): When a participant joins, their `media_status` is initialized with `{"audio": True, "video": meta.get("mode") == "video", "screen": False}` (line 202). The `screen: False` default is correct.
<!-- VERIFIED: join_call media_status initialization at group_call_service.py:202. -->

**`leave_call` function** (lines 235-277): Marks participant as `state: "left"` and decrements count. Does NOT reset `media_status.screen`. If a participant was sharing their screen and leaves, the `screen: true` flag persists on their (now inactive) record. However, since the participant list is filtered to `state === "active"` on the frontend (GroupCallOverlay.tsx line 236), the departed sharer's screen flag is invisible. No change needed here -- the simultaneous share prevention logic will also filter on active participants.
<!-- VERIFIED: leave_call at group_call_service.py:235-277. No media_status reset on leave. Active filter at GroupCallOverlay.tsx:236. -->

**`_end_call_internal` function** (lines 309-339): Ends the call and marks all active participants as left. Does not touch media_status.
<!-- VERIFIED: _end_call_internal at group_call_service.py:309-339. -->

**`list_participants` function** (lines 342-347): Queries all `PART#` rows for a call. Used by `get_call_endpoint` to populate the `participants` array in the response.
<!-- VERIFIED: list_participants at group_call_service.py:342-347. -->

### 2.7 1:1 Call Signaling (`app/services/messaging_call_signaling.py`, 345 lines)

**`ALLOWED_SIGNALING_TYPES`** (lines 14-28):
```python
ALLOWED_SIGNALING_TYPES = {
    "call.invite", "call.ring", "call.accept", "call.decline",
    "webrtc.offer", "webrtc.answer", "webrtc.ice_candidate",
    "call.end",
    "call.recording_request", "call.recording_accept",
    "call.recording_decline", "call.recording_started",
    "call.recording_stopped",
}
```
<!-- VERIFIED: ALLOWED_SIGNALING_TYPES at messaging_call_signaling.py:14-28. 13 event types total. -->

Screen share events must be added: `"webrtc.screen_share_start"` and `"webrtc.screen_share_stop"`.

**Rate limiting constants** (lines 29-31):
- `MAX_SIGNALING_SKEW_SECONDS` (default 120): Maximum clock skew tolerance for `sent_at` timestamp.
- `NONCE_TTL_SECONDS` (default 600): TTL for nonce replay guard records.
- `MAX_SIGNALING_PAYLOAD_BYTES` (default 8192): Maximum payload size.

Screen share signaling events have small payloads (~100 bytes for `display_surface` metadata), well within the 8KB limit.
<!-- VERIFIED: Constants at messaging_call_signaling.py:29-31. -->

**`STATE_ALLOWED_SIGNALING_TYPES`** (lines 34-42): Controls which event types are allowed in each call state. Screen share events should be allowed in the `"connected"` state only (alongside recording events and WebRTC offer/answer/ICE for renegotiation).
```python
STATE_ALLOWED_SIGNALING_TYPES: dict[str, set[str]] = {
    "invited": {"call.invite", "call.ring", "call.accept", "call.decline", "call.end"},
    "accepted": {"webrtc.offer", "webrtc.answer", "webrtc.ice_candidate", "call.end"},
    "connected": {
        "webrtc.offer", "webrtc.answer", "webrtc.ice_candidate", "call.end",
        "call.recording_request", "call.recording_accept", "call.recording_decline",
        "call.recording_started", "call.recording_stopped",
    },
}
```
<!-- VERIFIED: STATE_ALLOWED_SIGNALING_TYPES at messaging_call_signaling.py:34-42. "connected" state allows webrtc.offer/answer/ice_candidate, call.end, and all recording events. Screen share events belong here. -->

**`_validate_envelope` function** (lines 98-121): Validates all required fields (type, version, event_id, call_id, conversation_id, sender_user_id, recipient_user_id, nonce, sent_at). Checks that `type` is in `ALLOWED_SIGNALING_TYPES` (line 100-101), version is 1 (line 104), nonce length is 8-128 chars (line 114), and timestamp is within skew window (lines 117-119).
<!-- VERIFIED: _validate_envelope at messaging_call_signaling.py:98-121. Type check at line 100. -->

**`route_signaling_event` function** (lines 171-341): The main validation and delivery pipeline:
1. Validate envelope fields (line 193)
2. Verify sender matches authenticated actor (lines 198-200)
3. Load conversation participants and verify both sender and recipient are members (lines 202-209)
4. Verify sender != recipient (lines 210-212)
5. Load call session and verify it belongs to the conversation (lines 214-224)
6. Verify both users are call participants (lines 225-231)
7. Check call state allows the event type (lines 232-239)
8. Replay guard via nonce reservation (lines 241-249)
9. Validate payload is a JSON-serializable object within size limits (lines 251-266)
10. Write event to DynamoDB Events table (lines 268-319)
11. Return `SignalingAck` (lines 334-341)

All screen share signaling events pass through this exact same pipeline with no modification needed (apart from adding the types to the allowed sets).
<!-- VERIFIED: route_signaling_event at messaging_call_signaling.py:171-341. Full validation pipeline. -->

### 2.8 1:1 Call Signaling HTTP Endpoint (`app/routers/messaging.py`)

**`CallSignalingIn` model** (lines 12884-12891): The Pydantic model has a `type` field with a regex pattern that only allows `webrtc.offer`, `webrtc.answer`, and `webrtc.ice_candidate`:
```python
class CallSignalingIn(BaseModel):
    type: str = Field(..., pattern=r"^(webrtc\.offer|webrtc\.answer|webrtc\.ice_candidate)$")
```
This regex must be updated to also allow `webrtc.screen_share_start` and `webrtc.screen_share_stop`. Additionally, the recording-related event types (`call.recording_request`, etc.) are already in `ALLOWED_SIGNALING_TYPES` but NOT in this regex -- they must go through a different endpoint or the regex was never updated for recording events. This needs investigation: either recording events use a separate endpoint, or they bypass this validation.

**IMPORTANT**: The `CallSignalingIn.type` regex pattern at line 12885 is MORE restrictive than `ALLOWED_SIGNALING_TYPES`. It only allows the three core WebRTC types, not recording events. This means recording signaling events must be sent through a different path (likely via SSE/events infrastructure rather than the REST signaling endpoint). Screen share events will need to be added to this regex to be sent via the same REST endpoint.
<!-- VERIFIED: CallSignalingIn at messaging.py:12884-12891. type regex at line 12885 only allows 3 WebRTC types. Recording events NOT in regex. -->

**`send_signaling_event` endpoint** (lines 12982-13019): POST `/messages/calls/{call_id}/signal`. Enforces WebRTC signaling enabled (`_enforce_webrtc_signaling_enabled`, line 12989), rate limiting (`_enforce_signaling_rate_limit`, line 12990), then constructs the envelope and calls `route_signaling_event`.
<!-- VERIFIED: send_signaling_event endpoint at messaging.py:12982-13019. -->

**Rate limiter** (lines 12939-12964): Uses DynamoDB atomic counter with time-bucketed keys. Default: 60 events per 10-second window. Screen share toggle events (2 events per share: start + stop) are negligible within this budget.
<!-- VERIFIED: Rate limiter at messaging.py:12939-12964. SIGNALING_RATE_LIMIT_MAX=60, SIGNALING_RATE_LIMIT_WINDOW_SECONDS=10. -->

### 2.9 `CallSessionRecord` (`app/services/messaging_call_sessions.py`, line 19)

The frozen dataclass (lines 19-48) has fields for call lifecycle, billing (CALL-011), and broadcast linkage (BCAST-011). No `screen_sharing` field exists. For 1:1 calls, screen sharing state is transient (only relevant during the active call) and does not need to be persisted in the call session record. The signaling events provide the audit trail. However, if we want to track whether screen sharing occurred during a call (for analytics or recording metadata), a `screen_shared: bool` field could be added. This is optional for v1.
<!-- VERIFIED: CallSessionRecord at messaging_call_sessions.py:19-48. Fields: call_id, conversation_id, caller/callee_user_id, initial_mode, state, start_ts, connect_ts, end_ts, end_reason, network_path, updated_at, lifecycle_events, idempotency_records, broadcast_session_id (BCAST-011), and CALL-011 billing fields (paid, rate_cents_per_min, billing_status, etc.). No screen_sharing field. -->

### 2.10 Browser API: `getDisplayMedia()`

| Browser | Support | Notes |
|---------|---------|-------|
| Chrome 72+ | Full | `preferCurrentTab` hint available since Chrome 104; `displaySurface` constraint works; `selfBrowserSurface: "include"` since Chrome 107 |
| Firefox 66+ | Full | No `preferCurrentTab`; `displaySurface` constraint supported; always shows full picker |
| Safari 13+ | Full | Requires user gesture; no `preferCurrentTab`; limited `displaySurface` support |
| Edge 79+ | Full | Chromium-based; same behavior as Chrome |
| Mobile Chrome (Android) | Partial | Android only (no iOS); some devices may not support; requires `android.permission.FOREGROUND_SERVICE_MEDIA_PROJECTION` |
| Mobile Safari | Not supported | `getDisplayMedia` is not available on iOS Safari or iOS Chrome (WebKit limitation) |
| Mobile Firefox (Android) | Not supported | `getDisplayMedia` is not available |

**Key behaviors**:
- `getDisplayMedia()` always triggers a browser-native picker dialog (cannot be bypassed)
- Returns a `MediaStream` with a video track (and optionally an audio track if the user selects tab sharing with audio)
- When the user clicks "Stop sharing" in the browser's native chrome bar, the track's `ended` event fires
- The track's `readyState` transitions to `"ended"` and cannot be restarted -- a new `getDisplayMedia()` call is required
- Unlike `getUserMedia`, `getDisplayMedia` does NOT require a prior `<iframe allow="display-capture">` policy in same-origin contexts
- The `displaySurface` property on the track's `getSettings()` result indicates what was shared: `"monitor"`, `"window"`, or `"browser"` (tab)
- Chrome shows three tabs in the picker: "Entire Screen", "Window", and "Chrome Tab". Firefox shows a single dropdown.

---

## 3. Technical Design

### 3.1 New Utility: `acquireScreenMedia()` in `webrtc.ts`

```typescript
/**
 * Acquire a screen capture stream via getDisplayMedia.
 * Returns the MediaStream on success. Throws categorized errors on failure:
 *   - NotAllowedError: user denied/cancelled the picker
 *   - NotFoundError: getDisplayMedia API not available (e.g. iOS Safari)
 *   - AbortError: browser cancelled the request
 *
 * The returned stream typically has one video track. An audio track may be
 * present if the user selected tab sharing with audio in Chrome.
 *
 * IMPORTANT: The video track will fire 'ended' when the user clicks
 * "Stop sharing" in the browser chrome. Callers must listen for this
 * event to clean up state.
 */
export async function acquireScreenMedia(): Promise<MediaStream> {
  if (!navigator.mediaDevices?.getDisplayMedia) {
    throw new DOMException(
      "Screen sharing is not supported in this browser",
      "NotFoundError",
    );
  }

  const constraints: DisplayMediaStreamOptions = {
    video: {
      // Prefer high resolution for screen content (text readability)
      width: { ideal: 1920 },
      height: { ideal: 1080 },
      frameRate: { ideal: 15, max: 30 },
      // Prefer sharing the current tab if the browser supports it (Chrome 104+)
      // @ts-expect-error -- preferCurrentTab is a Chrome-specific hint not in TS lib
      preferCurrentTab: false,
      // Hint to prefer "monitor" (full screen) in the picker
      // @ts-expect-error -- displaySurface hint not in all TS lib versions
      displaySurface: "monitor",
    },
    // Audio is opt-in; the browser picker lets the user choose.
    // We set false to keep it simple for v1. Tab audio can be enabled in v2.
    audio: false,
  };

  try {
    return await navigator.mediaDevices.getDisplayMedia(constraints);
  } catch (err) {
    // Re-throw DOMExceptions as-is for consistent error handling
    if (err instanceof DOMException) {
      throw err;
    }
    // Wrap unexpected errors
    throw new DOMException(
      `Screen sharing failed: ${err instanceof Error ? err.message : String(err)}`,
      "AbortError",
    );
  }
}

/**
 * Check whether the current browser supports screen sharing.
 * Used to conditionally render the screen share button.
 */
export function isScreenShareSupported(): boolean {
  return typeof navigator !== "undefined"
    && !!navigator.mediaDevices?.getDisplayMedia;
}
```

This function lives alongside `acquireLocalMedia` in `frontend/src/lib/webrtc.ts`. It follows the same error-throwing pattern so callers can use identical error handling (try/catch with DOMException name checking).

**Key differences from `acquireLocalMedia`**:
1. Uses `getDisplayMedia` instead of `getUserMedia` -- different API, different constraint shape.
2. No `OverconstrainedError` retry logic -- the browser picker handles source selection.
3. No `facingMode` constraint -- not applicable to screen capture.
4. `frameRate` is capped at 30fps with an ideal of 15fps -- screen content is typically low-motion (slides, documents) and does not need 60fps. Lower framerate saves bandwidth.
5. Resolution ideals are set to 1920x1080 -- screen content benefits from high resolution for text legibility.
6. `preferCurrentTab: false` -- we default to NOT preferring the current tab because users typically want to share another window or their full screen, not the app itself.

### 3.2 Screen Share Hook: `useScreenShare`

A new hook at `frontend/src/hooks/useScreenShare.ts` encapsulates the screen sharing lifecycle:

```typescript
import * as React from "react";
import { acquireScreenMedia, isScreenShareSupported } from "@/lib/webrtc";

// ─── Types ──────────────────────────────────────────────────────

interface UseScreenShareParams {
  /** The active RTCPeerConnection to replace tracks on. */
  peerConnection: RTCPeerConnection | null;
  /** The original camera MediaStream to restore when sharing stops. */
  localCameraStream: MediaStream | null;
  /** Whether the call is in connected state and screen share is available. */
  enabled: boolean;
  /** Callback when sharing starts successfully. */
  onShareStart?: () => void;
  /** Callback when sharing stops (user action or browser stop). */
  onShareStop?: () => void;
  /** Callback on error (permission denied, API unavailable). */
  onError?: (message: string) => void;
}

interface UseScreenShareReturn {
  /** Whether the user is currently sharing their screen. */
  isSharing: boolean;
  /** The screen capture MediaStream, if active. */
  screenStream: MediaStream | null;
  /** Toggle screen sharing on/off. */
  toggleScreenShare: () => Promise<void>;
  /** Force stop screen sharing (for cleanup). */
  stopScreenShare: () => void;
  /** Whether the browser supports screen sharing. */
  isSupported: boolean;
}

// ─── Hook ───────────────────────────────────────────────────────

export function useScreenShare(params: UseScreenShareParams): UseScreenShareReturn {
  const {
    peerConnection,
    localCameraStream,
    enabled,
    onShareStart,
    onShareStop,
    onError,
  } = params;

  const [isSharing, setIsSharing] = React.useState(false);
  const [screenStream, setScreenStream] = React.useState<MediaStream | null>(null);

  // Stable refs for callbacks
  const onShareStartRef = React.useRef(onShareStart);
  const onShareStopRef = React.useRef(onShareStop);
  const onErrorRef = React.useRef(onError);
  onShareStartRef.current = onShareStart;
  onShareStopRef.current = onShareStop;
  onErrorRef.current = onError;

  // Ref to track the original camera video track for restoration
  const cameraTrackRef = React.useRef<MediaStreamTrack | null>(null);

  // Debounce flag: true while a getDisplayMedia() picker is open
  const acquiringRef = React.useRef(false);

  // Check API availability once
  const isSupported = React.useMemo(() => isScreenShareSupported(), []);

  /**
   * Stop screen sharing: restore camera track and clean up.
   */
  const stopScreenShare = React.useCallback(() => {
    if (!isSharing && !screenStream) return;

    // Restore camera track on the video sender
    const pc = peerConnection;
    const cameraTrack = cameraTrackRef.current;
    if (pc && pc.connectionState !== "closed" && cameraTrack) {
      const videoSender = pc.getSenders().find(
        (s) => s.track?.kind === "video" || (s.track === null && cameraTrack.kind === "video"),
      );
      if (videoSender) {
        videoSender.replaceTrack(cameraTrack).catch(() => {
          // Best-effort restoration
        });
      }
    }

    // Stop screen stream tracks (removes browser "sharing" indicator)
    if (screenStream) {
      screenStream.getTracks().forEach((t) => t.stop());
    }

    setScreenStream(null);
    setIsSharing(false);
    cameraTrackRef.current = null;
    acquiringRef.current = false;

    onShareStopRef.current?.();
  }, [isSharing, screenStream, peerConnection]);

  /**
   * Toggle screen sharing on/off.
   */
  const toggleScreenShare = React.useCallback(async () => {
    // If currently sharing, stop
    if (isSharing) {
      stopScreenShare();
      return;
    }

    // Debounce: don't open picker if one is already open
    if (acquiringRef.current) return;

    // Validate prerequisites
    if (!peerConnection || peerConnection.connectionState === "closed") {
      onErrorRef.current?.("No active peer connection.");
      return;
    }

    acquiringRef.current = true;

    try {
      // 1. Acquire screen media
      const stream = await acquireScreenMedia();
      const screenTrack = stream.getVideoTracks()[0];

      if (!screenTrack) {
        stream.getTracks().forEach((t) => t.stop());
        onErrorRef.current?.("No video track in screen capture.");
        acquiringRef.current = false;
        return;
      }

      // 2. Find the video sender on the peer connection
      const videoSender = peerConnection.getSenders().find(
        (s) => s.track?.kind === "video",
      );

      if (!videoSender) {
        stream.getTracks().forEach((t) => t.stop());
        onErrorRef.current?.("No video sender available. Is camera enabled?");
        acquiringRef.current = false;
        return;
      }

      // 3. Preserve the camera track for later restoration
      cameraTrackRef.current = videoSender.track;

      // 4. Replace the camera track with the screen track
      await videoSender.replaceTrack(screenTrack);

      // 5. Listen for browser "Stop sharing" bar click
      screenTrack.onended = () => {
        // The browser stopped the share (user clicked native chrome bar)
        stopScreenShare();
      };

      // 6. Update state
      setScreenStream(stream);
      setIsSharing(true);
      acquiringRef.current = false;

      // 7. Expose for E2E tests
      if (import.meta.env.DEV) {
        (window as unknown as Record<string, unknown>).__rtcScreenStream = stream;
      }

      onShareStartRef.current?.();
    } catch (err) {
      acquiringRef.current = false;

      if (err instanceof DOMException) {
        if (err.name === "NotAllowedError") {
          // User cancelled the picker -- not an error, just a no-op
          onErrorRef.current?.("Screen sharing was cancelled.");
          return;
        }
        if (err.name === "NotFoundError") {
          onErrorRef.current?.("Screen sharing is not supported in this browser.");
          return;
        }
      }

      onErrorRef.current?.(
        `Screen sharing failed: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }, [isSharing, peerConnection, stopScreenShare]);

  // Clean up on unmount or when call ends
  React.useEffect(() => {
    if (!enabled && isSharing) {
      stopScreenShare();
    }
  }, [enabled, isSharing, stopScreenShare]);

  // Clean up on unmount
  React.useEffect(() => {
    return () => {
      if (screenStream) {
        screenStream.getTracks().forEach((t) => t.stop());
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return {
    isSharing,
    screenStream,
    toggleScreenShare,
    stopScreenShare,
    isSupported,
  };
}
```

**Key implementation details**:

1. **`toggleScreenShare()`**:
   - If not sharing: call `acquireScreenMedia()`, find the video sender via `pc.getSenders().find(s => s.track?.kind === "video")`, call `sender.replaceTrack(screenTrack)`, attach `track.onended` listener.
   - If sharing: call `sender.replaceTrack(cameraTrack)` to restore the camera, stop all screen stream tracks, clear state.

2. **`replaceTrack()` does NOT require renegotiation**: This is a critical design choice. `RTCRtpSender.replaceTrack()` swaps the track being sent without changing the SDP. The remote peer receives the new track content seamlessly through the existing RTCRtpReceiver. No new offer/answer exchange is needed. This means:
   - No SDP renegotiation latency
   - No risk of renegotiation failure
   - No ICE restart needed
   - The switch is instantaneous from the remote peer's perspective

3. **`track.onended` handler**: When the browser's native "Stop sharing" bar is clicked, the screen track fires `ended`. The hook must:
   - Restore the camera track on the sender
   - Stop the screen stream
   - Update `isSharing` to `false`
   - Call `onShareStop()` callback

4. **Cleanup on unmount / call end**: If the component unmounts or the call ends while sharing, the hook must stop the screen stream tracks (to remove the browser's "sharing" indicator bar) and restore the camera track if the peer connection is still alive.

5. **Camera track preservation**: The `cameraTrackRef` stores the original camera track. When the camera is off (`track.enabled = false`), the track still exists but produces black frames. The ref preserves the track regardless of its enabled state, so when sharing stops, the camera-off state is restored.

6. **Debouncing with `acquiringRef`**: While the browser's picker dialog is open, `acquiringRef` is `true`. Subsequent toggle calls are ignored. This prevents issues from rapid double-clicking the share button.

### 3.3 Track Replacement Strategy: `replaceTrack()` Deep Dive

```
Before screen share:
  RTCRtpSender[video] --> Camera Track --> Remote Peer sees camera
  RTCRtpSender[audio] --> Microphone Track --> Remote Peer hears mic

During screen share:
  RTCRtpSender[video] --> Screen Track --> Remote Peer sees screen
  RTCRtpSender[audio] --> Microphone Track --> Remote Peer hears mic (unchanged)
  Camera Track --> preserved in cameraTrackRef (track.enabled stays same, just not sent)

After screen share stops:
  RTCRtpSender[video] --> Camera Track (restored) --> Remote Peer sees camera
  Screen Track --> stopped (.stop() called, readyState = "ended")
```

**Why `replaceTrack()` and not `removeTrack()`/`addTrack()`**: The `removeTrack`/`addTrack` approach would require SDP renegotiation (new offer/answer) because it changes the media description in the SDP. `replaceTrack()` operates at the RTP level and swaps the media source without touching the SDP. This is simpler, faster, and avoids potential renegotiation failures.

**SDP considerations with `replaceTrack()`**:
- The SDP media section (`m=video`) remains unchanged. The codec, payload type, and SSRC stay the same.
- The encoder automatically adapts to the new track's resolution and content type. If the screen track is 1920x1080 and the camera was 1280x720, the encoder scales up within the existing SDP bandwidth parameters.
- Bandwidth adaptation: WebRTC's built-in bandwidth estimator (GCC - Google Congestion Control) will adjust the bitrate based on the new content. Screen content (high detail, low motion) typically requires higher bitrate for the same perceived quality compared to camera video. The encoder handles this automatically.
- `RTCRtpSender.getParameters()` returns the current encoding parameters. These are not modified by `replaceTrack()` -- the sender continues using the same `maxBitrate`, `scaleResolutionDownBy`, etc.
- Simulcast: If simulcast is configured on the sender (multiple `encodings` in `RTCRtpSendParameters`), `replaceTrack()` preserves all encodings. Each simulcast layer adapts to the new track.

**Codec considerations**:
- Screen content (text, UI, slides) benefits from codecs with good "screen content coding" tools. VP9 and AV1 have dedicated screen content modes. H.264 does not.
- `replaceTrack()` does not change the negotiated codec. If the SDP negotiated VP8, the screen content will be encoded with VP8 (which is less efficient for screen content but still works).
- For v1, we accept the negotiated codec. A future enhancement could use `setParameters()` to switch `contentHint` to `"detail"` for screen content, which hints to the encoder to prioritize sharpness over smoothness.

**Content hint optimization**:
```typescript
// Set content hint on the screen track to optimize encoder behavior
screenTrack.contentHint = "detail"; // Prioritize sharpness for text/UI
// (vs "motion" for camera video which prioritizes smoothness)
```

**Resolution handling**: Screen capture tracks typically have higher resolution than camera tracks (1920x1080 or even 2560x1440 for a full-screen share vs. 1280x720 for camera). `replaceTrack()` handles this transparently -- the encoder adapts to the new track resolution. However, the remote peer's `<video>` element may need to adjust its rendering. The `VideoRenderer` component currently uses `object-cover` (line 101 of CallSessionOverlay.tsx) which will crop the video to fill the container. Screen shares look better with `object-contain` to avoid cropping. The renderer should switch to `object-contain` when receiving a screen share.

**Track state during sharing**:
- The camera track's `readyState` remains `"live"` even though it is no longer being sent. It can be re-attached to the sender at any time.
- The camera track's `enabled` property is preserved. If the user had their camera off (`enabled = false`), the track is still valid and can be restored.
- The camera track does NOT produce frames while detached from the sender -- it is still attached to the original MediaStream but the stream is not connected to any sink. This means no CPU overhead from encoding the camera while screen sharing.

### 3.4 Signaling for 1:1 Screen Share

Two new signaling event types are added to notify the remote peer about screen share state changes.

**`webrtc.screen_share_start` schema**:
```json
{
  "type": "webrtc.screen_share_start",
  "version": 1,
  "event_id": "ss_start_<uuid>",
  "call_id": "<call_id>",
  "conversation_id": "<conversation_id>",
  "sender_user_id": "<sharer_id>",
  "recipient_user_id": "<peer_id>",
  "nonce": "<32-char hex>",
  "sent_at": 1716912345,
  "payload": {
    "display_surface": "monitor",
    "width": 1920,
    "height": 1080
  }
}
```

The `payload.display_surface` field indicates what the user selected in the browser picker. It is obtained from `screenTrack.getSettings().displaySurface`. The `width` and `height` fields are from `screenTrack.getSettings()` and help the remote peer optimize their layout.

**`webrtc.screen_share_stop` schema**:
```json
{
  "type": "webrtc.screen_share_stop",
  "version": 1,
  "event_id": "ss_stop_<uuid>",
  "call_id": "<call_id>",
  "conversation_id": "<conversation_id>",
  "sender_user_id": "<sharer_id>",
  "recipient_user_id": "<peer_id>",
  "nonce": "<32-char hex>",
  "sent_at": 1716912399,
  "payload": {
    "reason": "user_stopped"
  }
}
```

The `reason` field can be `"user_stopped"` (clicked toggle button), `"browser_stopped"` (clicked native browser chrome bar), or `"call_ended"` (call ended while sharing).

The remote peer uses these events to:
1. Switch the layout to/from presentation mode
2. Change the `<video>` element's `object-fit` from `cover` to `contain`
3. Update the UI to show "Peer is sharing their screen" indicator
4. Optionally adjust bandwidth preferences for the incoming stream

**Why signaling and not just detecting the track change?**: The remote peer receives the new track content automatically via `replaceTrack()`, but has no way to distinguish a screen share track from a camera track at the RTP level. The signaling event provides explicit metadata about the screen share state, enabling proper layout switching and UI feedback.

**Handling signaling events in `useRtcPeerConnection.ts`**: The SSE event handler (line 272) will be extended with two new branches:

```typescript
} else if (eventType === "webrtc.screen_share_start") {
  // Remote peer started screen sharing — dispatch custom event for overlay
  window.dispatchEvent(
    new CustomEvent("messaging:peer-screen-share", {
      detail: {
        callId: detail.call_id,
        peerId: detail.sender_user_id,
        action: "start",
        displaySurface: payload.display_surface ?? "unknown",
        width: typeof payload.width === "number" ? payload.width : null,
        height: typeof payload.height === "number" ? payload.height : null,
      },
    }),
  );
} else if (eventType === "webrtc.screen_share_stop") {
  // Remote peer stopped screen sharing
  window.dispatchEvent(
    new CustomEvent("messaging:peer-screen-share", {
      detail: {
        callId: detail.call_id,
        peerId: detail.sender_user_id,
        action: "stop",
        reason: payload.reason ?? "unknown",
      },
    }),
  );
}
```

The `CallSessionOverlay` (or its parent `ConversationView`) listens for `messaging:peer-screen-share` events to update `peerIsScreenSharing` state.

### 3.5 Signaling for Group Screen Share

Group calls already have the `PATCH /{call_id}/media` endpoint with `screen: bool`. When a participant starts sharing:

1. Frontend calls `acquireScreenMedia()` and `replaceTrack()` locally
2. Frontend calls `updateGroupCallMedia(callId, { screen: true })`
3. Backend `update_media_state()` (group_call_service.py:357-383) updates the participant's `media_status.screen` to `true` in DDB
4. Other participants poll `GET /{call_id}` (3-second interval, GroupCallOverlay.tsx:195) and see the updated `media_status`
5. Frontend layout switches to presentation mode when any participant has `screen: true`

When sharing stops (toggle off or browser stop):

1. Frontend calls `sender.replaceTrack(cameraTrack)` and stops the screen stream
2. Frontend calls `updateGroupCallMedia(callId, { screen: false })`
3. Backend updates `media_status.screen` to `false`
4. Other participants see the change on next poll and revert layout

**Simultaneous share prevention**: Only one participant can share at a time in a group call. The backend should enforce this by rejecting `screen: true` updates when another participant already has `screen: true`. The frontend should also check locally before attempting to start a share, and show a toast like "Alice is already sharing their screen" if someone else is sharing.

**Conflict resolution algorithm**:

```python
# In group_call_service.py, inside update_media_state():

def _check_screen_share_conflict(call_id: str, requesting_user_id: str) -> str | None:
    """
    Check if another active participant is already screen sharing.
    Returns the conflicting user_id, or None if no conflict.
    """
    participants = list_participants(call_id)
    for p in participants:
        if p.get("state") != "active":
            continue
        if p.get("user_id") == requesting_user_id:
            continue
        media = p.get("media_status") or {}
        if media.get("screen"):
            return str(p.get("user_id") or "")
    return None
```

The check runs BEFORE writing the update to DDB. If a conflict is found, the endpoint returns HTTP 409:

```json
{
  "detail": "Another participant (alice) is already sharing their screen"
}
```

**Race condition**: Two participants could both pass the conflict check simultaneously and both write `screen: true`. This is a benign race -- the worst case is two people sharing simultaneously for up to 3 seconds (one poll interval) until the frontend detects the conflict. For v1, this is acceptable. A DynamoDB conditional write (check that no other participant has `screen: true`) would prevent this but adds complexity.

### 3.6 Presentation Mode Layout

#### 3.6.1 1:1 Calls (`CallSessionOverlay.tsx`)

When the remote peer is screen sharing:

```
+------------------------------------------------------------------+
| [Signal] Peer name  ·  Timer         [Screen sharing] [REC]      |
+------------------------------------------------------------------+
|                                                                    |
|                                                                    |
|              Remote Screen Share (object-contain)                  |
|              ~80% of viewport height                               |
|              bg-black (letterboxing for non-matching aspect)       |
|                                                                    |
|                                         +------------------+      |
|                                         | Remote Camera    |      |
|                                         | (PiP, 160x120)  |      |
|                                         +------------------+      |
|                                                                    |
|                          +------------------+                      |
|                          | Local Camera     |                      |
|                          | (PiP, 160x120)  |                      |
|                          +------------------+                      |
+------------------------------------------------------------------+
| [Mute] [Camera] [Screen Share] [End Call] [Recording]              |
+------------------------------------------------------------------+
```

When the local user is screen sharing:

```
+------------------------------------------------------------------+
| [Signal] Peer name  ·  Timer         [You are sharing]  [REC]    |
+------------------------------------------------------------------+
|                                                                    |
|              Remote Camera (full area, object-cover)               |
|              (normal layout — remote peer sees the screen share)   |
|                                                                    |
|                                         +------------------+      |
|                                         | Local Screen     |      |
|                                         | Preview (PiP)    |      |
|                                         +------------------+      |
+------------------------------------------------------------------+
| [Mute] [Camera] [Screen Share*] [End Call] [Recording]             |
+------------------------------------------------------------------+
  * Screen Share button is highlighted (active state, blue bg)
```

**Component hierarchy for presentation mode in 1:1**:

```tsx
{/* Presentation mode: remote peer is screen sharing */}
{peerIsScreenSharing && (
  <div className="relative w-full aspect-video bg-black">
    {/* Screen share content - object-contain for no cropping */}
    <VideoRenderer
      stream={remoteStream}
      className="object-contain"
      aria-label="Remote screen share"
    />
    {/* Peer camera PiP (if video on) */}
    {hasPeerCameraTrack && (
      <div className="absolute top-4 right-4 w-36 h-24 rounded-lg overflow-hidden ring-2 ring-white/40 shadow-lg">
        <VideoRenderer stream={peerCameraStream} aria-label="Remote camera" />
      </div>
    )}
    {/* Local camera PiP */}
    <div className="absolute bottom-4 right-4 w-28 h-20 rounded-xl overflow-hidden ring-2 ring-white/60 shadow-lg">
      {isCameraOff ? (
        <div className="flex h-full w-full items-center justify-center bg-zinc-800">
          <VideoOff className="h-5 w-5 text-zinc-400" />
        </div>
      ) : (
        <VideoRenderer stream={localStream} muted mirror aria-label="Local video preview" />
      )}
    </div>
    {/* "Screen sharing" banner */}
    <div className="absolute top-4 left-4 flex items-center gap-2 rounded-lg bg-blue-600/80 px-3 py-1.5 text-white text-sm font-medium backdrop-blur-sm">
      <MonitorUp className="h-4 w-4" />
      {peerName} is sharing their screen
    </div>
  </div>
)}
```

**Note on remote camera PiP**: With `replaceTrack()`, the remote stream's single video track alternates between camera and screen content. We cannot show both simultaneously in a single-stream architecture. The remote camera PiP is only possible in a dual-stream architecture (future enhancement). For v1, when the remote peer is screen sharing, their remote video shows the screen content, and there is no separate camera PiP for the remote peer.

#### 3.6.2 Group Calls (`GroupCallOverlay.tsx`)

When any participant is screen sharing, the layout switches from grid/speaker to presentation mode:

```
+------------------------------------------------------------------+
| Group Call - 4 participants (video)          [Grid|Speaker] btn   |
+------------------------------------------------------------------+
|                                                      | P1 camera  |
|                                                      | (You)      |
|                                                      +------------+
|       Screen Share Content                           | P2 camera  |
|       (object-contain, ~75-80% width)                | (Sharer*)  |
|                                                      +------------+
|                                                      | P3 camera  |
|                                                      |            |
|                                                      +------------+
|                                                      | P4 camera  |
|                                                      |            |
+------------------------------------------------------------------+
| [Mute] [Camera] [Screen Share] [Leave] [End]                      |
+------------------------------------------------------------------+
  * Sharer's camera tile has MonitorUp badge (existing, lines 421-425)
```

**Component hierarchy for presentation mode in group**:

```tsx
const screenSharer = activeParticipants.find(p => p.media_status.screen);
const effectiveLayout = screenSharer ? "presentation" : layout;

{effectiveLayout === "presentation" && screenSharer && (
  <div className="flex h-full gap-3">
    {/* Screen share area: 75-80% width */}
    <div className="flex-1 min-w-0 relative">
      <div className="h-full rounded-lg bg-gray-800 flex items-center justify-center">
        {/* In real WebRTC impl, this would be <video> for sharer's screen track */}
        <div className="text-center text-gray-400">
          <MonitorUp className="h-16 w-16 mx-auto mb-2" />
          <p className="text-sm font-medium">
            {screenSharer.display_name || screenSharer.user_id} is presenting
          </p>
        </div>
      </div>
    </div>
    {/* Participant sidebar: 20-25% width */}
    <div className="w-40 lg:w-48 flex flex-col gap-2 overflow-y-auto">
      {activeParticipants.map((p) => (
        <ParticipantTile
          key={p.user_id}
          participant={p}
          isLocal={p.user_id === userId}
        />
      ))}
    </div>
  </div>
)}
```

The sidebar strip is a vertical column of participant camera tiles (each ~150-192px wide). The screen share content fills the remaining space. The sharer's camera tile shows both their camera feed and the existing `MonitorUp` icon badge.

If nobody is screen sharing, the grid/speaker toggle controls the layout as before. The presentation mode overrides the user's layout selection while a share is active, and reverts to the previous selection when sharing stops.

**Layout toggle disabled during presentation**: The grid/speaker toggle button in the top bar should be disabled and show a tooltip "Layout locked during screen share" when `effectiveLayout === "presentation"`:

```tsx
<Button
  variant="ghost"
  size="icon"
  className="h-8 w-8 text-white hover:bg-gray-700"
  onClick={() => setLayout(layout === "grid" ? "speaker" : "grid")}
  disabled={!!screenSharer}
  aria-label={`Switch to ${layout === "grid" ? "speaker" : "grid"} view`}
>
  {layout === "grid" ? <LayoutDashboard className="h-4 w-4" /> : <Grid3X3 className="h-4 w-4" />}
</Button>
```

### 3.7 Backend Changes Summary

| File | Change | Scope |
|------|--------|-------|
| `app/services/messaging_call_signaling.py` | Add `"webrtc.screen_share_start"`, `"webrtc.screen_share_stop"` to `ALLOWED_SIGNALING_TYPES` (line 14) and to `STATE_ALLOWED_SIGNALING_TYPES["connected"]` (line 37) | 4 lines changed |
| `app/routers/messaging.py` | Update `CallSignalingIn.type` regex pattern (line 12885) to include `webrtc\.screen_share_start` and `webrtc\.screen_share_stop` | 1 line changed |
| `app/routers/group_calls.py` | No code changes; error handling at lines 265-266 already catches `GroupCallError` with appropriate HTTP status | 0 lines |
<!-- CORRECTED: was "lines 261-263", actually except GroupCallError at line 265, raise HTTPException at line 266 -->
| `app/services/group_call_service.py` | Add `_check_screen_share_conflict()` helper (~20 lines) and conflict check in `update_media_state()` before setting `screen: true` (~5 lines) | ~25 lines |
| `app/core/settings.py` | Add `messaging_screen_share_enabled` feature flag | 3 lines |

**No new DynamoDB tables or models are required.** The existing `GroupCallMediaStatus` model and `group_call_sessions` table already support the `screen` field. The 1:1 screen share state is ephemeral (communicated via signaling events) and does not need persistence.

---

## 4. Implementation Plan

### Phase 1: WebRTC Utility + Support Function (1 day)

**File**: `frontend/src/lib/webrtc.ts`
- Add `acquireScreenMedia()` function after `acquireLocalMedia()` (after line 41). ~40 lines.
<!-- VERIFIED: acquireLocalMedia ends at webrtc.ts:41. New function goes after line 41. -->
- Add `isScreenShareSupported()` function. ~5 lines.
- Export both new functions from the module.
- Add TypeScript type augmentation for `preferCurrentTab` and `displaySurface` on `DisplayMediaStreamOptions` if needed.

**Estimated line changes**: +50 lines to `webrtc.ts`

**Verification**: Unit test with mock `getDisplayMedia` to confirm error categorization and constraint passing.

### Phase 2: Screen Share Hook (2 days)

**File**: `frontend/src/hooks/useScreenShare.ts` (new file)
- Implement `useScreenShare` hook with the full interface described in section 3.2.
- Handle all lifecycle events:
  - `acquireScreenMedia()` --> get screen track
  - `pc.getSenders()` --> find video sender
  - `sender.replaceTrack(screenTrack)` --> swap to screen
  - `screenTrack.onended` --> auto-stop + restore camera
  - `sender.replaceTrack(cameraTrack)` --> restore camera
  - Cleanup on unmount --> stop screen tracks
- Add `contentHint = "detail"` on screen tracks for encoder optimization.
- Add ref-based camera track preservation.
- Handle `getDisplayMedia` errors (permission denied, API unavailable) with descriptive messages.
- Add debounce for concurrent toggle prevention.
- Expose `__rtcScreenStream` on `window` in dev mode for E2E test access.

**Estimated lines**: ~200 lines new file

**Verification**: Unit tests with mock RTCPeerConnection and MediaStream.

### Phase 3: 1:1 Call Signaling Backend (0.5 days)

**File**: `app/services/messaging_call_signaling.py`
1. Add `"webrtc.screen_share_start"` and `"webrtc.screen_share_stop"` to `ALLOWED_SIGNALING_TYPES` set (line 14). +2 lines.
2. Add both types to `STATE_ALLOWED_SIGNALING_TYPES["connected"]` set (line 37). +2 lines.

**File**: `app/routers/messaging.py`
3. Update `CallSignalingIn.type` regex pattern (line 12885) to include the new event types:
```python
type: str = Field(..., pattern=r"^(webrtc\.(offer|answer|ice_candidate|screen_share_start|screen_share_stop))$")
```
+1 line changed.

**Estimated line changes**: 5 lines across 2 files

**Verification**: Backend unit test confirming new signaling types are accepted in `connected` state and rejected in `invited`/`accepted` states.

### Phase 4: 1:1 Call Signaling Frontend (1 day)

**File**: `frontend/src/hooks/useRtcPeerConnection.ts`
1. Add handler branches for `webrtc.screen_share_start` and `webrtc.screen_share_stop` events in the SSE event handler (after line 352). +25 lines.
2. Dispatch `messaging:peer-screen-share` custom events with metadata.

**File**: `frontend/src/hooks/useScreenShare.ts`
3. Add optional `sendSignaling` callback parameter to send signaling events when screen share starts/stops.
4. Call `sendSignalingEvent()` with the appropriate event type and payload in `toggleScreenShare()` and `stopScreenShare()`.

**File**: `frontend/src/api/endpoints/messaging.ts`
5. Update `SignalingPayload` type to include the new event types in its type union.

**Estimated line changes**: +35 lines across 3 files

**Verification**: Integration test sending screen share signaling events and verifying they arrive via SSE.

### Phase 5: Group Call Simultaneous Share Prevention (0.5 days)

**File**: `app/services/group_call_service.py`
1. Add `_check_screen_share_conflict(call_id, requester_user_id)` function:
   - Query active participants for the call via `list_participants(call_id)`.
   - Check if any active participant other than `requester_user_id` has `media_status.screen == true`.
   - Return the conflicting user_id or None.
   ~20 lines.

2. In `update_media_state()`, before setting `screen: true`:
   - Call `_check_screen_share_conflict()`
   - If conflict found, raise `GroupCallError(409, "Another participant is already sharing their screen")`
   ~5 lines.

**File**: `app/routers/group_calls.py`
3. The existing error handling (lines 265-266) already catches `GroupCallError` and returns the appropriate HTTP status, so no router changes needed.
<!-- CORRECTED: was "lines 261-263", actually except GroupCallError at line 265, raise HTTPException at line 266 -->

**Estimated line changes**: +25 lines to `group_call_service.py`

**Verification**: Unit test confirming 409 when two participants try to share simultaneously. Idempotency test confirming same user can re-set screen=true.

### Phase 6: CallSessionOverlay Screen Share UI (2 days)

**File**: `frontend/src/pages/messages/CallSessionOverlay.tsx`

1. **Add imports**: `MonitorUp` from `lucide-react`. +1 line.

2. **Extend `Props` interface** (line 41): Add `isScreenSharing?: boolean`, `onToggleScreenShare?: () => void`, `screenShareSupported?: boolean`, `peerIsScreenSharing?: boolean`, `peerScreenShareSurface?: string`. +5 lines to interface.

3. **Extend `CallControlsProps` interface** (line 143): Add `isScreenSharing`, `onToggleScreenShare`, `screenShareSupported`. +3 lines.

4. **Add screen share button to `CallControls`** (after line 180, before end call):
   ```tsx
   {screenShareSupported && mode === "video" && (
     <Tooltip>
       <TooltipTrigger asChild>
         <Button
           size="icon"
           variant={isScreenSharing ? "default" : "secondary"}
           className={cn(
             "h-10 w-10 rounded-full",
             isScreenSharing && "bg-blue-600 text-white hover:bg-blue-700",
           )}
           onClick={onToggleScreenShare}
           aria-label={isScreenSharing ? "Stop sharing screen" : "Share screen"}
           data-testid="toggle-screen-share"
         >
           <MonitorUp className="h-4 w-4" />
         </Button>
       </TooltipTrigger>
       <TooltipContent>
         {isScreenSharing ? "Stop Sharing" : "Share Screen"}
       </TooltipContent>
     </Tooltip>
   )}
   ```
   +17 lines.

5. **Presentation mode layout** (in the video call connected section, after line 333):
   - When `peerIsScreenSharing` is true: change `VideoRenderer` to use `object-contain`, add "Peer is sharing their screen" banner. +20 lines.
   - When `isScreenSharing` is true: add blue "Sharing your screen" badge similar to the red "REC" indicator. +10 lines.

6. **Pass new props in the controls bar** (line 398-410): Wire through `isScreenSharing`, `onToggleScreenShare`, `screenShareSupported`. +3 lines.

**Estimated line changes**: +60 lines to `CallSessionOverlay.tsx`

### Phase 7: GroupCallOverlay Screen Share UI (2 days)

**File**: `frontend/src/pages/messages/GroupCallOverlay.tsx`

1. **Add screen share toggle function** inside `GroupCallOverlay` component:
   ```typescript
   const handleToggleScreenShare = async () => {
     if (localMedia.screen) {
       // Stop sharing
       stopScreenShare();
       mediaMut.mutate({ screen: false });
     } else {
       // Check if someone else is sharing
       const sharer = activeParticipants.find(
         (p) => p.media_status.screen && p.user_id !== userId
       );
       if (sharer) {
         toast.error(`${sharer.display_name || sharer.user_id} is already sharing their screen`);
         return;
       }
       try {
         await startScreenShare();
         mediaMut.mutate({ screen: true });
       } catch (err) {
         // Error handled by useScreenShare hook
       }
     }
   };
   ```
   +20 lines.

2. **Add screen share button** to controls bar (after video toggle, before leave button):
   ```tsx
   <Button
     variant="ghost"
     size="icon"
     className={cn(
       "h-12 w-12 rounded-full",
       localMedia.screen
         ? "bg-blue-600 text-white hover:bg-blue-700"
         : "bg-gray-700 text-white hover:bg-gray-600",
     )}
     onClick={handleToggleScreenShare}
     aria-label={localMedia.screen ? "Stop sharing screen" : "Share screen"}
     data-testid="toggle-screen-share"
   >
     <MonitorUp className="h-5 w-5" />
   </Button>
   ```
   +15 lines.

3. **Presentation mode layout**: Add a new layout branch activated when any `activeParticipants[i].media_status.screen === true`:
   ```tsx
   const screenSharer = activeParticipants.find(p => p.media_status.screen);
   const effectiveLayout = screenSharer ? "presentation" : layout;
   ```
   Render flex row: 75-80% for screen share content, 20-25% for participant sidebar. +40 lines.

4. **Disable grid/speaker toggle** while presentation mode is active. +3 lines (add `disabled={!!screenSharer}` to button).

5. **Handle 409 error from backend**: When `mediaMut` returns 409 (another participant sharing), show toast with error message. +5 lines.

**Estimated line changes**: +85 lines to `GroupCallOverlay.tsx`

### Phase 8: Integration Wiring + Feature Flag (1 day)

Wire the `useScreenShare` hook into the call overlays:

**File**: `frontend/src/pages/messages/ConversationView.tsx` (or wherever call state is managed)
1. Instantiate `useScreenShare` with the peer connection and local stream from `useRtcPeerConnection`.
2. Pass `isScreenSharing`, `onToggleScreenShare`, `screenShareSupported`, `peerIsScreenSharing` as props to `CallSessionOverlay`.
3. Listen for `messaging:peer-screen-share` custom events to update `peerIsScreenSharing` state.
4. Send screen share signaling events via `sendSignalingEvent()` in the `onShareStart`/`onShareStop` callbacks.

**File**: `frontend/src/pages/messages/GroupCallOverlay.tsx`
5. Instantiate `useScreenShare` inside the overlay component (group calls manage their own media state).
6. On share start/stop, additionally call `mediaMut.mutate()` to update group media state.

**File**: `app/core/settings.py`
7. Add `messaging_screen_share_enabled` feature flag.

**File**: `frontend/.env.local.example` and `frontend/.env.local`
8. Add `VITE_MESSAGING_SCREEN_SHARE_ENABLED=true`.

**Estimated line changes**: +50 lines across 4 files

### Phase 9: Edge Case Handling + Polish (1 day)

1. **Browser "Stop sharing" click**: The `track.onended` handler in `useScreenShare` fires, which:
   - Restores the camera track via `replaceTrack()`
   - Sends `webrtc.screen_share_stop` signaling event (1:1) or `PATCH media { screen: false }` (group)
   - Updates local state

2. **Call ends while sharing**: `teardownCallResources()` in `callStateMachine.ts` (line 199) already stops all tracks on `localStream` and `remoteStream`. Add a check for screen stream:
<!-- VERIFIED: teardownCallResources at callStateMachine.ts:199-222. -->
   ```typescript
   // In teardownCallResources or useScreenShare cleanup:
   if (screenStream) {
     screenStream.getTracks().forEach(t => t.stop());
   }
   ```

3. **Camera was already off when sharing starts**: If `isCameraOff` is true (video track `enabled = false`), the sharer has no visible camera content but the track still exists. When sharing stops, the video sender should get the original camera track with `enabled = false` (preserving the camera-off state). The `cameraTrackRef` in `useScreenShare` preserves the track object including its `enabled` state.

4. **`getDisplayMedia` not available** (iOS Safari, older browsers): `acquireScreenMedia()` throws `NotFoundError`. The `useScreenShare` hook catches this and calls `onError("Screen sharing is not supported in this browser")`. The screen share button should be hidden when `isSupported` is false. Detection is built into the hook via `isScreenShareSupported()`.

5. **Permission denied**: User clicks the screen share button but cancels the browser picker. `acquireScreenMedia()` throws `NotAllowedError`. The hook catches this, shows a toast ("Screen sharing was cancelled"), and does not change state.

6. **Multiple rapid toggles**: Debounced via `acquiringRef` flag in the hook. If a `getDisplayMedia` call is in progress (browser picker is open), subsequent toggle requests are ignored.

7. **ICE restart during screen share**: If an ICE restart occurs while screen sharing, the `replaceTrack()` on the sender is preserved. The screen track continues to be sent on the restored connection. No special handling needed.

8. **Screen share during recording**: CALL-009's `MediaRecorder` captures the composite stream from the peer connection. When `replaceTrack()` swaps to the screen track, `MediaRecorder` automatically captures the screen content. No changes to recording are needed.

**Estimated line changes**: +30 lines across 3 files

---

## Testing Strategy

### Unit Tests (pytest)

**Test file**: `tests/test_call_13.py`

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

**Test file**: `frontend/e2e/call-13.spec.ts`

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
| CALL-002 | RTCPeerConnection for track replacement | Implemented | Yes |
| CALL-005 | Media controls for share button | Implemented | Yes |
| CALL-012 | Group call overlay for presentation layout | Implemented | Yes |

### Depended On By

No downstream dependents identified.

### Merge Strategy

Sequential after CALL-005/012. Extends both 1:1 and group call overlays with screen share.

### Merge Checklist

- [ ] Backend endpoint/service changes registered in `app/main.py`
- [ ] Frontend hooks and components created/modified
- [ ] Settings and feature flags configured
- [ ] DDB tables added if needed (`scripts/local-ddb-init.py`)
- [ ] E2E tests pass in CI
- [ ] No breaking changes to existing call endpoints

## Appendix B: Codebase Citations

<!-- All line numbers verified against the current codebase state. -->

| Reference | File | Line(s) | Description |
|-----------|------|---------|-------------|
| `acquireLocalMedia` | `frontend/src/lib/webrtc.ts` | 15-41 | getUserMedia; `acquireScreenMedia` NOW at line 54, `isScreenShareSupported` at line 92 |
| `createIceCandidateBuffer` | `frontend/src/lib/webrtc.ts` | 48-77 | ICE candidate buffering with flush |
| `generateNonce` | `frontend/src/lib/webrtc.ts` | 82-84 | 32-char hex nonce via crypto.randomUUID |
| `generateEventId` | `frontend/src/lib/webrtc.ts` | 89-91 | Prefixed unique event ID |
| `UseRtcPeerConnectionParams` | `frontend/src/hooks/useRtcPeerConnection.ts` | 23-36 | Hook params interface |
| `UseRtcPeerConnectionReturn` | `frontend/src/hooks/useRtcPeerConnection.ts` | 38-44 | Hook return interface |
| `shouldActivate` | `frontend/src/hooks/useRtcPeerConnection.ts` | 59-67 | Phase/role activation logic |
| `localStream/remoteStream state` | `frontend/src/hooks/useRtcPeerConnection.ts` | 85-88 | React useState for streams |
| `TURN credential fetch` | `frontend/src/hooks/useRtcPeerConnection.ts` | 119-131 | fetchTurnCredentials in setup |
| `RTCPeerConnection creation` | `frontend/src/hooks/useRtcPeerConnection.ts` | 136-148 | PC creation with ICE servers |
| `pcRef assignment` | `frontend/src/hooks/useRtcPeerConnection.ts` | 149 | Store PC in ref |
| `Dev mode window exposure` | `frontend/src/hooks/useRtcPeerConnection.ts` | 152-156 | __rtcPeerConnection, __rtcLocalStream, __rtcRemoteStream |
| `pc.addTrack` | `frontend/src/hooks/useRtcPeerConnection.ts` | 182-184 | Adds local tracks; sender return value discarded |
| `pc.ontrack handler` | `frontend/src/hooks/useRtcPeerConnection.ts` | 193-199 | Adds remote tracks to MediaStream |
| `ICE candidate trickle` | `frontend/src/hooks/useRtcPeerConnection.ts` | 249-269 | Outbound ICE candidate signaling |
| `SSE event handler` | `frontend/src/hooks/useRtcPeerConnection.ts` | 272-353 | Handles offer/answer/ice_candidate only |
| `Event listener registration` | `frontend/src/hooks/useRtcPeerConnection.ts` | 355 | addEventListener for messaging:webrtc-signal |
| `CallRuntimeResources stored` | `frontend/src/hooks/useRtcPeerConnection.ts` | 391-399 | Resources ref for cleanup |
| `performIceRestart` | `frontend/src/hooks/useRtcPeerConnection.ts` | 416-456 | ICE restart with iceRestart:true offer |
| `Teardown on disable` | `frontend/src/hooks/useRtcPeerConnection.ts` | 474-492 | Cleanup when enabled=false |
| `CallRuntimeResources interface` | `frontend/src/pages/messages/callStateMachine.ts` | 190-197 | peerConnection, localStream, remoteStream, etc. |
| `teardownCallResources` | `frontend/src/pages/messages/callStateMachine.ts` | 199-222 | Stops tracks, closes PC |
| `Props interface` | `frontend/src/pages/messages/CallSessionOverlay.tsx` | 41-70 | NOW includes isScreenSharing, onToggleScreenShare, screenShareSupported, peerIsScreenSharing |
| `VideoRenderer` | `frontend/src/pages/messages/CallSessionOverlay.tsx` | 75-108 | object-cover at line 101 |
| `CallControlsProps` | `frontend/src/pages/messages/CallSessionOverlay.tsx` | 143-167 | NOW includes isScreenSharing, onToggleScreenShare, screenShareSupported |
| `CallControls` | `frontend/src/pages/messages/CallSessionOverlay.tsx` | 167-211 | NOW includes screen share button (lines 192-206) with MonitorOff/Monitor icons |
| `ConnectionQualityIndicator` | `frontend/src/pages/messages/CallSessionOverlay.tsx` | 228-257 | Signal icon with RTT/loss tooltip |
| `hasRemoteVideo state` | `frontend/src/pages/messages/CallSessionOverlay.tsx` | 301-324 | Remote video track monitoring |
| `Video call connected layout` | `frontend/src/pages/messages/CallSessionOverlay.tsx` | 333-441 | Remote full-area + local PiP |
| `Recording indicator` | `frontend/src/pages/messages/CallSessionOverlay.tsx` | 389-394 | Red REC badge |
| `Controls bar` | `frontend/src/pages/messages/CallSessionOverlay.tsx` | 397-411 | CallControls in flex container |
| `Audio call layout` | `frontend/src/pages/messages/CallSessionOverlay.tsx` | 444-527 | No video elements |
| `MonitorUp import` | `frontend/src/pages/messages/GroupCallOverlay.tsx` | 21 | Already imported |
| `layout state` | `frontend/src/pages/messages/GroupCallOverlay.tsx` | 184 | "grid" or "speaker" |
| `localMedia state` | `frontend/src/pages/messages/GroupCallOverlay.tsx` | 185-189 | audio, video, screen booleans |
| `callData polling` | `frontend/src/pages/messages/GroupCallOverlay.tsx` | 192-196 | 3-second refetchInterval |
| `mediaMut` | `frontend/src/pages/messages/GroupCallOverlay.tsx` | 227-233 | Calls updateGroupCallMedia for audio/video/screen |
| `activeParticipants` | `frontend/src/pages/messages/GroupCallOverlay.tsx` | 235-236 | Filter for state==="active" |
| `toggleAudio/toggleVideo` | `frontend/src/pages/messages/GroupCallOverlay.tsx` | 239-240 | Media toggle functions |
| `gridCols computation` | `frontend/src/pages/messages/GroupCallOverlay.tsx` | 243-250 | CSS grid columns by count |
| `Top bar + layout toggle` | `frontend/src/pages/messages/GroupCallOverlay.tsx` | 258-277 | Participant count + toggle button |
| `Grid layout` | `frontend/src/pages/messages/GroupCallOverlay.tsx` | 281-286 | Equal-sized participant tiles |
| `Speaker layout` | `frontend/src/pages/messages/GroupCallOverlay.tsx` | 287-309 | First participant large + thumbnail strip |
| `Controls bar` | `frontend/src/pages/messages/GroupCallOverlay.tsx` | 314-368 | Audio, video, leave, end |
| `ParticipantTile` | `frontend/src/pages/messages/GroupCallOverlay.tsx` | 382-428 | Avatar, video, name, badges |
| `ParticipantTile screen badge` | `frontend/src/pages/messages/GroupCallOverlay.tsx` | 421-425 | Shows `MonitorUp` icon when screen=true |
| `GroupCallMediaStatus` | `app/models.py` | 3106-3109 | Has `screen: bool = False` field |
| `GroupCallMediaUpdateIn` | `app/models.py` | 3189-3192 | Has `screen: Optional[bool] = None` |
| `_get_user auth` | `app/routers/group_calls.py` | 53-67 | Cookie auth + CSRF extraction |
| `_participant_out helper` | `app/routers/group_calls.py` | 75-89 | Maps media_status dict to model |
| `PATCH media endpoint` | `app/routers/group_calls.py` | 255-275 | Accepts screen boolean, persists to DDB |
| `update_media_state` | `app/services/group_call_service.py` | 357-383 | Merges and writes media_status |
| `join_call media_status init` | `app/services/group_call_service.py` | 202 | screen: False default on join |
| `leave_call` | `app/services/group_call_service.py` | 235-277 | Marks left, no media_status reset |
| `list_participants` | `app/services/group_call_service.py` | 342-347 | Query PART# rows |
| `ALLOWED_SIGNALING_TYPES` | `app/services/messaging_call_signaling.py` | 14-29 | NOW includes webrtc.screen_share_start (28) and webrtc.screen_share_stop (29) |
| `STATE_ALLOWED_SIGNALING_TYPES` | `app/services/messaging_call_signaling.py` | 34-57 | Connected + accepted states NOW include screen share types (lines 45, 51) |
| `_validate_envelope` | `app/services/messaging_call_signaling.py` | 98-121 | Type check, version, nonce, timestamp |
| `route_signaling_event` | `app/services/messaging_call_signaling.py` | 171-341 | Full validation + delivery pipeline |
| `CallSignalingIn type regex` | `app/routers/messaging.py` | 13152 | NOW allows offer/answer/ice_candidate + screen_share_start/stop |
| `send_signaling_event endpoint` | `app/routers/messaging.py` | 12982-13019 | POST /messages/calls/{call_id}/signal |
| `Rate limiter` | `app/routers/messaging.py` | 12939-12964 | 60 events per 10s window |
| `CallSessionRecord` | `app/services/messaging_call_sessions.py` | 19-48 | No screen_sharing field |
| `CallSessionRecord billing fields` | `app/services/messaging_call_sessions.py` | 34-48 | BCAST-011 linkage (34-35), CALL-011 billing (36-48) |
<!-- CORRECTED: was "36-48", actually BCAST-011 broadcast_session_id at lines 34-35, CALL-011 billing at lines 36-48 -->

## Appendix C: Glossary & Acronyms

| Term | Definition |
|------|-----------|
| **SDP** | Session Description Protocol -- text-based format describing media capabilities (codecs, transport, etc.) exchanged during WebRTC offer/answer negotiation |
| **ICE** | Interactive Connectivity Establishment -- protocol for NAT traversal and candidate pair selection in WebRTC |
| **STUN** | Session Traversal Utilities for NAT -- lightweight protocol for discovering the public IP/port of a peer behind NAT |
| **TURN** | Traversal Using Relays around NAT -- relay server that forwards media when direct peer-to-peer connection fails |
| **GCC** | Google Congestion Control -- WebRTC's built-in bandwidth estimation algorithm that adapts bitrate based on network conditions |
| **RTP** | Real-time Transport Protocol -- the media transport layer used by WebRTC to send audio/video packets |
| **RTCP** | RTP Control Protocol -- companion to RTP that provides feedback on transmission quality (packet loss, jitter, RTT) |
| **RTCPeerConnection** | The main WebRTC API interface representing a connection between the local device and a remote peer |
| **RTCRtpSender** | WebRTC API interface for sending a single media track (audio or video) over a peer connection |
| **RTCRtpReceiver** | WebRTC API interface for receiving a single media track from a remote peer |
| **replaceTrack()** | Method on `RTCRtpSender` that swaps the track being sent without SDP renegotiation |
| **getDisplayMedia()** | Browser API for capturing the user's screen, window, or tab as a `MediaStream` |
| **getUserMedia()** | Browser API for capturing camera and microphone input as a `MediaStream` |
| **MediaStream** | Web API representing a stream of media content (audio and/or video tracks) |
| **MediaStreamTrack** | Web API representing a single media track (one audio or one video track) within a MediaStream |
| **contentHint** | Property on `MediaStreamTrack` that hints to the encoder about the content type ("motion" for camera, "detail" for screen) |
| **displaySurface** | Property in the track settings from `getDisplayMedia` indicating what was shared: "monitor" (full screen), "window", or "browser" (tab) |
| **PiP** | Picture-in-Picture -- a small overlay video window showing one stream over another |
| **SFU** | Selective Forwarding Unit -- a media server that receives streams from participants and forwards them selectively, enabling scalable group calls |
| **Mesh** | A peer-to-peer network topology where each participant connects directly to every other participant |
| **DDB** | DynamoDB -- AWS NoSQL database used for all persistent storage in this platform |
| **SSE** | Server-Sent Events -- a protocol for one-way server-to-client event streaming, used for real-time signaling delivery |
| **CSRF** | Cross-Site Request Forgery -- an attack vector mitigated by the `x-csrf-token` header required on all mutating cookie-auth requests |
| **DLP** | Data Loss Prevention -- enterprise security controls to prevent sensitive data from being shared or leaked |

## Appendix D: Related Tickets

| Ticket | Title | Relationship |
|--------|-------|-------------|
| CALL-002 | RTCPeerConnection Setup | Provides the peer connection infrastructure that screen sharing builds on |
| CALL-005 | Media Controls | Provides the mute/camera toggle UI pattern that screen share button follows |
| CALL-008 | ICE Restart | Provides the reconnection mechanism that works alongside screen sharing |
| CALL-009 | Call Recording | Recording automatically captures screen share content via MediaRecorder |
| CALL-010 | Call Recording in Messenger | Extended recording with download; screen share recorded transparently |
| CALL-011 | Pay-Per-Minute Calls | Billing is unaffected by screen sharing; billing timer continues normally |
| CALL-012 | Group Video Calls | Provides the group call infrastructure and existing `screen` field in media status |
| BCAST-008 | Recording Download | Broadcast recording; separate concern from screen sharing |
| BCAST-011 | Go Private | Broadcast-to-private call transition; screen sharing deferred for broadcasts |
| VOD-013 | Video Sharing in Messages | Different feature; VOD sharing is file-based, not real-time screen capture |

## Appendix E: Future Enhancements (Post-v1)

These items are explicitly out of scope for v1 but represent natural extensions of the screen sharing feature:

1. **Tab audio sharing**: Enable the `audio: true` constraint in `acquireScreenMedia()` and mix tab audio with microphone audio using `AudioContext`. Requires careful handling of echo cancellation.

2. **Dual-stream architecture**: Send camera AND screen as separate tracks simultaneously via `addTrack()` (requires SDP renegotiation). This allows the remote peer to see both the screen share AND the sharer's camera at full quality, without either degrading the other.

3. **Annotation overlay**: Add a transparent canvas overlay on the shared screen for drawing, highlighting, and laser pointer. Requires a shared drawing protocol (either via signaling or a separate WebSocket channel).

4. **Remote control**: Allow the viewer to request control of the shared screen (mouse + keyboard input). Extremely complex; requires a native agent or browser extension on the sharer's machine. Not achievable with browser APIs alone.

5. **Screen share in audio-only calls**: Currently deferred because audio-only calls have no video transceiver. Adding screen share to an audio-only call would require `addTrack()` to create a video transceiver, followed by SDP renegotiation. The remote peer must also be prepared to handle the new video track.

6. **Screen share in broadcasts (BCAST-011)**: Broadcasts use a different media topology (likely SFU or WHIP/WHEP). Screen sharing in broadcasts requires the SFU to handle the screen track, which is a separate concern.

7. **Multi-share in groups**: Allow multiple participants to share simultaneously (like Zoom with up to 25 shares). Requires SFU infrastructure to selectively forward streams.

8. **Screen share quality presets**: Allow the sharer to choose between "Text/Slides" (high resolution, low framerate) and "Video/Animation" (lower resolution, higher framerate) presets.

9. **Screen share thumbnails in chat history**: After a screen share ends, automatically capture a thumbnail and attach it to the call history entry as a visual record.

10. **Bandwidth reservation for screen share**: When screen sharing starts, automatically reduce camera resolution to reserve bandwidth for the screen content. Restore camera resolution when sharing stops.
