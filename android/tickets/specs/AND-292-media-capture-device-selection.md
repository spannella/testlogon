---
id: AND-292
title: Media capture + device selection
milestone: M7
epic: E39
priority: P1
size: M
depends_on: [AND-288]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
---

# AND-292 — Media capture + device selection

## 1. Overview & Goal

This ticket delivers the local media capture layer for the TestLogon native Android
client: turning the device camera and microphone into controllable WebRTC media
tracks and exposing user-facing controls to toggle them, switch between the front
and back cameras, mute audio, and select a capture resolution. It builds directly
on AND-288, which wired `webrtc-android` into the build, secured camera/mic runtime
permissions, and proved a sample loopback render path. AND-288 produced the
`PeerConnectionFactory`, `EglBase` context, and permission gating; AND-292 produces
the `LocalMediaController` that owns the `VideoCapturer`, `VideoSource`,
`AudioSource`, and the `VideoTrack`/`AudioTrack` pair, plus the Compose UI that
drives it.

The scope is strictly *local* capture and device selection. It does not establish a
peer connection, negotiate SDP, or stream to the backend — that belongs to later
M7 signaling tickets. The deliverable is a self-contained, previewable capture
surface: the user sees their own camera feed rendered locally, can flip cameras,
mute/unmute the mic, toggle the camera on/off, and pick a resolution preset, with
all state surviving lifecycle changes and reflected in a single `StateFlow<CaptureUiState>`.

Success means: capture toggles and camera switch work reliably on real hardware,
state is observable and testable, and the controller hands a ready-to-use
`VideoTrack`/`AudioTrack` to the (future) connection layer through a clean interface.

## 2. Context & References

- Module: a new `feature-call` module (or `feature-media` if it already exists from
  AND-288) under the `app -> feature-* -> core-*` layering. WebRTC primitives and
  the EGL context live in `core-webrtc` (created in AND-288); this ticket consumes
  them and adds capture/device logic.
- Package base: `com.testlogon.android`. Capture code lives under
  `com.testlogon.android.feature.call.media` and `com.testlogon.android.core.webrtc`.
- Stack: Kotlin 2.0.21, Jetpack Compose + Material 3, Hilt (KSP), Coroutines/Flow,
  `webrtc-android` (Stream's `io.getstream:stream-webrtc-android`, per AND-288).
- minSdk 24, compileSdk/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- Dependency: **AND-288** (webrtc-android integration + permissions) — provides
  `PeerConnectionFactory`, `EglBase`, `CameraEnumerator`, and the runtime permission
  flow for `CAMERA` and `RECORD_AUDIO`. This ticket assumes those are present and
  that permissions have been granted before capture is started.
- No backend interaction. The FastAPI dev host (http://18.222.237.167:8000),
  cookie/CSRF session, and OpenAPI contract are **not** touched by this ticket.

## 3. Functional Requirements

FR-1 — **Camera capture toggle.** The user can start and stop the camera. When on,
the local video track is enabled and rendered to a local preview surface. When off,
the capturer is stopped (releasing the camera HAL) and the preview shows a placeholder.

FR-2 — **Microphone mute toggle.** The user can mute/unmute the mic. Muting sets the
local `AudioTrack.setEnabled(false)` (no HAL teardown — mute must be instant and
reversible). The UI reflects the muted state with a distinct icon/label.

FR-3 — **Camera switch.** When two or more cameras exist, the user can flip between
front and back. Switching uses `CameraVideoCapturer.switchCamera()` and updates the
`isFrontFacing` mirror state so the preview mirrors correctly (front mirrored, back not).
If only one camera exists, the switch control is disabled.

FR-4 — **Resolution selection.** The user can choose a capture resolution from a
fixed set of presets (see §6). Changing resolution restarts the capturer with the new
`width`/`height`/`fps` via `videoCapturer.changeCaptureFormat(...)` (or stop+start where
`changeCaptureFormat` is unsupported by the capturer implementation).

FR-5 — **Lifecycle correctness.** Capture stops when the screen is backgrounded
(`ON_STOP`) and resumes prior state on `ON_START` if the camera was on. The camera HAL
must be released on `ON_STOP` so other apps can use it. State (on/off, muted, facing,
resolution) survives configuration changes and process-death-free backgrounding.

FR-6 — **Track exposure.** The controller exposes the live `VideoTrack` and
`AudioTrack` (nullable until capture starts) so a downstream connection ticket can
attach them to a `PeerConnection` without re-creating sources.

## 4. Technical Design

### 4.1 Controller interface

```kotlin
package com.testlogon.android.feature.call.media

interface LocalMediaController {
    val state: StateFlow<CaptureUiState>
    val videoTrack: StateFlow<VideoTrack?>
    val audioTrack: StateFlow<AudioTrack?>

    fun startCamera()
    fun stopCamera()
    fun setMicMuted(muted: Boolean)
    fun switchCamera()
    fun setResolution(preset: ResolutionPreset)

    /** Binds a local renderer (SurfaceViewRenderer) for preview. */
    fun attachPreview(sink: VideoSink)
    fun detachPreview(sink: VideoSink)

    /** Releases capturer, sources, tracks, and HAL. Idempotent. */
    fun dispose()
}
```

### 4.2 Implementation

```kotlin
class DefaultLocalMediaController @Inject constructor(
    private val factory: PeerConnectionFactory,          // from AND-288
    private val eglBase: EglBase,                         // from AND-288
    @ApplicationContext private val appContext: Context,
    @CaptureDispatcher private val dispatcher: CoroutineDispatcher, // single-thread
) : LocalMediaController {

    private val enumerator: CameraEnumerator =
        if (Camera2Enumerator.isSupported(appContext)) Camera2Enumerator(appContext)
        else Camera1Enumerator(true)

    private var capturer: CameraVideoCapturer? = null
    private var videoSource: VideoSource? = null
    private var audioSource: AudioSource? = null
    private var surfaceHelper: SurfaceTextureHelper? = null
    // ...
}
```

Key flows:

- **Source/track creation (lazy, on first `startCamera`).** Create a
  `SurfaceTextureHelper` on the EGL context, create `VideoSource(isScreencast=false)`,
  initialize the capturer with `capturer.initialize(surfaceHelper, appContext, videoSource.capturerObserver)`,
  then `factory.createVideoTrack("ARDAMSv0", videoSource)`. Audio:
  `factory.createAudioSource(MediaConstraints())` then
  `factory.createAudioTrack("ARDAMSa0", audioSource)`. Tracks default to
  `setEnabled(true)`.

- **Capturer selection.** `createCapturer(frontFacing: Boolean)` walks
  `enumerator.deviceNames` choosing `isFrontFacing`/`isBackFacing`. Front is default.

- **Threading.** All capturer/source mutations run on a single-threaded
  `@CaptureDispatcher` to avoid WebRTC native re-entrancy; the `StateFlow` updates are
  posted via `MutableStateFlow.update {}` and are thread-safe.

- **Switch camera** uses `CameraVideoCapturer.switchCamera(handler)` and updates
  `isFrontFacing` in the success callback (`onCameraSwitchDone(isFront)`).

- **Resolution change** calls `capturer.changeCaptureFormat(w, h, fps)`; on capturer
  implementations that throw, fall back to `stopCapture()` + `startCapture(w, h, fps)`.

### 4.3 ViewModel + UI

```kotlin
@HiltViewModel
class CaptureViewModel @Inject constructor(
    private val media: LocalMediaController,
) : ViewModel() {
    val uiState: StateFlow<CaptureUiState> = media.state
    fun onToggleCamera() = if (media.state.value.cameraOn) media.stopCamera() else media.startCamera()
    fun onToggleMute() = media.setMicMuted(!media.state.value.micMuted)
    fun onSwitchCamera() = media.switchCamera()
    fun onSelectResolution(p: ResolutionPreset) = media.setResolution(p)
    override fun onCleared() { media.dispose() }
}
```

Compose: a `CaptureScreen(state, onToggleCamera, onToggleMute, onSwitchCamera, onSelectResolution)`
hosts an `AndroidView` wrapping a `SurfaceViewRenderer` (initialized with
`eglBase.eglBaseContext`, `setMirror(state.isFrontFacing)`, `setScalingType(SCALE_ASPECT_FILL)`),
attached via `media.attachPreview(renderer)` in a `DisposableEffect`. A Material 3 control
bar provides toggle buttons; resolution is a `DropdownMenu`/segmented control.
`LifecycleEventObserver` drives FR-5.

## 5. API Contract

**N/A — no backend API.** This ticket is entirely local-device media capture and
introduces no network calls, request/response shapes, or OpenAPI dependency. Sending
the produced tracks over a `PeerConnection` and any session/signaling REST/WebSocket
contract is owned by the downstream M7 signaling/connection ticket (the first ticket
in E39 that establishes a `PeerConnection`). The only "contract" here is the internal
`LocalMediaController` interface in §4.1, which that ticket consumes.

## 6. Data & State Management

### 6.1 UI state

```kotlin
data class CaptureUiState(
    val cameraOn: Boolean = false,
    val micMuted: Boolean = false,
    val isFrontFacing: Boolean = true,
    val resolution: ResolutionPreset = ResolutionPreset.HD_720,
    val cameraCount: Int = 0,
    val capturing: Boolean = false,      // true while start/stop in flight
    val error: CaptureError? = null,
)

enum class ResolutionPreset(val width: Int, val height: Int, val fps: Int) {
    SD_480(640, 480, 30),
    HD_720(1280, 720, 30),
    FHD_1080(1920, 1080, 30);
}
```

- Single source of truth: `MutableStateFlow<CaptureUiState>` inside
  `DefaultLocalMediaController`, exposed read-only. The ViewModel re-exposes it; the
  controller is the owner so state survives ViewModel recreation when the controller
  is `@ActivityRetainedScoped` (Hilt).
- **Scoping decision:** bind `LocalMediaController` as `@ActivityRetainedScoped` so a
  configuration change does not tear down the camera. Process death is acceptable to
  reset to defaults (camera off) — capture is not restored across process death.
- No persistence to Room/DataStore is required for capture toggles. Optionally persist
  the last `ResolutionPreset` and `isFrontFacing` preference to DataStore for next-launch
  convenience; this is a **nice-to-have**, not an acceptance requirement.
- `cameraCount` is computed once from `enumerator.deviceNames.size` and used to enable/
  disable the switch control. *(Note: unlike the web reference, which re-enumerates on the
  `devicechange` event — see `src/hooks/useMediaDevices.ts` — built-in front/back cameras
  on Android are fixed, so a one-time count is acceptable; external/USB cameras are out of
  scope for this ticket.)*

## 7. Error Handling & Resilience

- **Capturer failures.** `CameraVideoCapturer.CameraEventsHandler` callbacks
  (`onCameraError`, `onCameraDisconnected`, `onCameraFreezed`) map to
  `CaptureError.CameraUnavailable`/`CameraInUse`. On error, set `cameraOn=false`,
  release the capturer, and surface a retriable error in `CaptureUiState.error`.
- **Camera in use by another app** (HAL `ERROR_CAMERA_IN_USE`) → user-facing message
  "Camera is in use by another app" with a Retry action that re-attempts `startCamera()`.
- **Permission revoked at runtime.** Although AND-288 owns the permission *grant* flow,
  this ticket must defensively check `ContextCompat.checkSelfPermission` before
  `startCamera`/`setMicMuted(false)` and emit `CaptureError.PermissionDenied` rather than
  crashing if a permission was revoked from Settings while backgrounded.
- **Switch race.** Ignore `switchCamera` calls while a switch or start is in flight
  (`capturing == true`); WebRTC's switch is async and re-entrant calls corrupt state.
- **Resolution change failure.** If `changeCaptureFormat` throws, fall back to
  stop+start; if that also fails, revert `resolution` to the previous value and emit a
  non-fatal error.
- **No network retry/backoff** applies (no network). The unreliable dev-backend
  resilience guidance is out of scope here.
- **Idempotent dispose.** `dispose()` and `stopCamera()` are safe to call repeatedly and
  during teardown; all native objects are null-checked and nulled after `release()`.

## 8. Security & Privacy

- Camera and microphone are sensitive sensors. The active-capture state MUST be visually
  obvious: an on-screen indicator whenever the camera or mic track is enabled. Android 12+
  shows the system privacy indicator automatically; do not attempt to suppress it.
- Stop capture and release the camera HAL on `ON_STOP` (FR-5) so the app is never holding
  the camera while backgrounded — both a privacy and a resource requirement.
- No media frames are written to disk, logged, or transmitted in this ticket. Preview is
  rendered to an in-memory `SurfaceViewRenderer` only. No screenshots or recordings.
- Do not log raw frame data, device serial identifiers, or full camera device names at
  any log level. Camera identity in logs is limited to `front`/`back`.
- Permissions (`CAMERA`, `RECORD_AUDIO`) are declared and requested in AND-288; this
  ticket only consumes the granted state. `<uses-feature android:name="android.hardware.camera" android:required="false" />`
  must remain non-required so the app installs on camera-less devices (switch/capture
  controls disable gracefully when `cameraCount == 0`).

## 9. Accessibility & i18n

- All controls (camera toggle, mute, switch, resolution) have `contentDescription`s that
  reflect current state, e.g. "Turn camera off" vs "Turn camera on", "Unmute microphone"
  vs "Mute microphone". State changes announce via `Modifier.semantics { stateDescription = ... }`.
- Touch targets are >= 48dp; control bar usable one-handed.
- All strings live in `res/values/strings.xml` (`capture_*` keys) — no hardcoded UI text.
  Resolution preset labels ("720p", "1080p") are locale-formatted where applicable.
- Color is not the sole signal for muted/on states — icon shape changes too (e.g.
  mic vs mic-off glyph).
- Preview mirroring follows `isFrontFacing`; this is visual only and has no a11y impact,
  but the switch announcement states "Switched to front camera"/"Switched to back camera".

## 10. Telemetry & Logging

- Structured, low-cardinality events via the app's analytics interface (no PII, no frame data):
  - `media_capture_started` { facing, resolution }
  - `media_capture_stopped`
  - `media_camera_switched` { to: front|back }
  - `media_mic_muted` / `media_mic_unmuted`
  - `media_resolution_changed` { from, to }
  - `media_capture_error` { type, recoverable } — `type` ∈ CameraUnavailable, CameraInUse,
    PermissionDenied, ResolutionUnsupported.
- Logging uses the core logging facade at DEBUG for lifecycle transitions
  (start/stop/switch) and WARN for capturer error callbacks. No verbose per-frame logging.
- Track creation/disposal logs the track id (`ARDAMSv0`/`ARDAMSa0`) only, never device serials.

## 11. Testing Strategy

**Unit (JVM, `core-testing` utilities, MockK):**
- `DefaultLocalMediaControllerTest` with mocked `PeerConnectionFactory`,
  `CameraEnumerator`, and `CameraVideoCapturer`:
  - `startCamera` creates sources/tracks once and sets `cameraOn=true`,
    `videoTrack`/`audioTrack` non-null.
  - `setMicMuted(true)` calls `audioTrack.setEnabled(false)` and sets `micMuted=true`;
    HAL is not torn down.
  - `switchCamera` invokes `capturer.switchCamera`, flips `isFrontFacing` on the success
    callback, and is ignored while `capturing==true`.
  - `setResolution` calls `changeCaptureFormat` with the preset dimensions; fallback path
    on exception calls stop+start; revert on double failure.
  - `cameraCount==1` → switch is a no-op / control disabled.
  - `dispose` releases capturer, sources, tracks (verify `release()`), is idempotent.
  - Permission-revoked path emits `PermissionDenied` without throwing.
  - Use `kotlinx-coroutines-test` `TestDispatcher` for `@CaptureDispatcher`; assert
    `StateFlow` emissions with Turbine.

**Instrumented (androidTest, real hardware/emulator with camera):**
- Loopback smoke: `startCamera` produces frames at the local renderer (assert
  `onFrame` is called within a timeout) — extends the AND-288 sample render proof.
- Lifecycle: `ON_STOP` releases camera (no frames), `ON_START` resumes when previously on.

**Compose UI (`createComposeRule`):**
- `CaptureScreen` toggle buttons emit the correct callbacks; content descriptions update
  with state; switch button disabled when `cameraCount<=1`.

**Manual device matrix:** at least one Camera2-supported device and one fallback
(Camera1) device; verify mirror correctness front vs back, and that another app can open
the camera after backgrounding.

## 12. Dependencies & Sequencing

- **Depends on AND-288** (P0): `webrtc-android` linked, `PeerConnectionFactory`/`EglBase`
  provided via Hilt, `CAMERA`/`RECORD_AUDIO` runtime permissions implemented, sample
  loopback render proven. AND-292 cannot start until AND-288's DI module exposes the
  factory and EGL context.
- **Blocks:** the downstream M7 signaling/connection ticket that attaches the local
  `VideoTrack`/`AudioTrack` to a `PeerConnection` (consumer of §4.1). That ticket is not
  enumerated in this ticket's source bullets; reference it as "the E39 connection ticket"
  and keep the `LocalMediaController` interface stable so it can depend on AND-292.
- Internal sequencing: (1) controller interface + Hilt binding, (2) source/track creation
  + start/stop, (3) mute, (4) switch, (5) resolution, (6) preview + lifecycle, (7) UI + a11y.

## 13. Risks & Open Questions

- **R1 — Camera2 vs Camera1 enumerator divergence.** `changeCaptureFormat` and switch
  behavior differ; the stop+start fallback mitigates but adds a visible flicker on
  resolution change. *Mitigation:* prefer Camera2 when supported; accept brief black frame
  on resolution change.
- **R2 — HAL release timing.** Releasing the camera on `ON_STOP` and re-acquiring on
  `ON_START` can race on fast app-switch; guard with the single capture dispatcher.
- **R3 — Track id collisions / reuse by downstream ticket.** The connection ticket may
  expect specific track ids; `ARDAMSv0`/`ARDAMSa0` follow WebRTC convention — confirm with
  the connection ticket owner. *Open question.*
- **OQ1 — Resolution preset list:** are SD/720/1080 sufficient, or is an "Auto"
  (capability-negotiated best) preset wanted? Defaulting to fixed presets for this ticket.
- **OQ2 — Persist last device/resolution to DataStore?** Treated as nice-to-have; confirm
  whether product wants it before adding the DataStore dependency.
- **OQ3 — Audio routing** (speaker/earpiece/BT) is *not* in scope here; assumed owned by a
  later audio-routing ticket. Flagging to avoid scope creep.

## 14. Acceptance Criteria

AC-1 (FR-1) — Tapping the camera control starts capture and shows a live local preview;
tapping again stops capture, releases the camera HAL, and shows the placeholder.
`cameraOn` toggles accordingly in `CaptureUiState`.

AC-2 (FR-2) — Tapping mute sets the audio track disabled and updates `micMuted=true` with
a distinct muted icon/label; unmute restores it. Mute does not stop or restart the mic HAL.

AC-3 (FR-3) — On a device with >= 2 cameras, the switch control flips between front and
back, the preview mirroring updates (front mirrored, back not), and `isFrontFacing`
reflects the active camera. On a single-camera device the control is disabled.

AC-4 (FR-4) — Selecting a different resolution preset restarts/reconfigures capture at the
chosen dimensions and `resolution` updates; an unsupported preset reverts cleanly with a
non-fatal error and no crash.

AC-5 (FR-5) — Backgrounding releases the camera (another app can open it); foregrounding
restores the prior camera-on state; toggle/mute/facing/resolution survive a rotation.

AC-6 (FR-6) — After `startCamera`, `videoTrack` and `audioTrack` StateFlows emit non-null
`VideoTrack`/`AudioTrack` instances usable by a `PeerConnection`.

AC-7 — All controls expose accurate, state-aware `contentDescription`s; no hardcoded UI
strings (all in `strings.xml`).

AC-8 — Camera/capturer error callbacks surface a recoverable `CaptureError` with a Retry
path and never crash the app; `dispose()` is idempotent and leaks no native objects.

## 15. Definition of Done

- `LocalMediaController` interface + `DefaultLocalMediaController` implemented, Hilt-bound
  `@ActivityRetainedScoped`, consuming AND-288's `PeerConnectionFactory`/`EglBase`.
- `CaptureViewModel`, `CaptureScreen`, control bar, and `SurfaceViewRenderer` preview
  implemented with lifecycle handling.
- All FR-1..FR-6 implemented; all AC-1..AC-8 demonstrably pass on a physical device.
- Unit tests for the controller (start/stop/mute/switch/resolution/dispose/permission)
  pass with >= 80% line coverage on the controller class; Compose UI tests for control
  callbacks and content descriptions pass; instrumented loopback + lifecycle test passes
  on at least one camera-equipped device.
- Telemetry events emitted as specified; no per-frame or PII logging.
- Strings externalized; accessibility content descriptions verified with TalkBack.
- No detekt/ktlint violations; builds under AGP 8.7.3 / Gradle 8.9, JDK 17; CI green on
  the `android-port` branch.
- Code reviewed; `LocalMediaController` interface documented as the stable contract for the
  downstream E39 connection ticket.

## 16. Citations & Assumption Audit

Each key technical claim in this spec, with a verdict and an exact source pointer.
"OpenAPI" pointers reference the backend contract index/spec; "frontend" pointers reference
the web reference app under `reference/src/`; "framework ref" pointers reference official
Android/WebRTC documentation for framework choices.

1. **Claim:** This ticket introduces no backend API / network calls (§2, §5).
   **VERDICT:** Verified. **SOURCE:** No local-capture/device-selection endpoint exists in
   the backend. The only media/WebRTC-adjacent endpoints are `POST /broadcast/sessions/{session_id}/inputs/{input_id}/webrtc-offer` (op `webrtc_offer_route...`, req `BroadcastWebRTCOfferIn`, resp `BroadcastWebRTCOfferOut`) and `POST /messaging/messages/calls/{call_id}/turn-credentials` (resp `TurnCredentialsOut`), both of which belong to the downstream signaling/connection layer, not local capture. (OpenAPI index.)

2. **Claim:** Sending tracks over a `PeerConnection` and any SDP/ICE/TURN signaling is owned
   by a downstream M7/E39 connection ticket, not this one (§5, §12).
   **VERDICT:** Verified. **SOURCE:** OpenAPI `POST /broadcast/sessions/{session_id}/inputs/{input_id}/webrtc-offer` (SDP offer exchange) and `POST /messaging/messages/calls/{call_id}/turn-credentials` (TURN issuance) exist on the backend, confirming signaling is a separate concern; the frontend performs SDP/ICE in `src/hooks/useRtcPeerConnection.ts` and TURN fetch in `src/api/endpoints/messaging.ts` — both distinct from local capture in `src/hooks/useMediaCapture.ts`.

3. **Claim:** Mute is implemented by disabling the track (`AudioTrack.setEnabled(false)`), not
   by tearing down the mic HAL; mute is instant and reversible (FR-2, AC-2).
   **VERDICT:** Verified (contract parity). **SOURCE:** The web reference mutes by toggling
   `audioTrack.enabled` without stopping the track — `src/pages/messages/ConversationView.tsx`
   (`audioTrack.enabled = !audioTrack.enabled`). Android `MediaStreamTrack.setEnabled(boolean)`
   is the equivalent (framework ref: WebRTC Android `org.webrtc.MediaStreamTrack`).

4. **Claim:** The camera-switch control is disabled / no-op when fewer than two cameras exist
   (FR-3, AC-3).
   **VERDICT:** Verified (contract parity). **SOURCE:** Web reference returns early from
   `switchCamera` when `devices.length < 2` — `src/hooks/useMediaCapture.ts: switchCamera`.

5. **Claim:** Camera switch uses `CameraVideoCapturer.switchCamera(handler)` and updates
   `isFrontFacing` in the `onCameraSwitchDone(isFront)` success callback (§4.2, FR-3).
   **VERDICT:** Verified. **SOURCE:** framework ref — stream-webrtc-android
   `org.webrtc.CameraVideoCapturer` exposes `switchCamera(CameraSwitchHandler)` and the
   `CameraSwitchHandler.onCameraSwitchDone(boolean isFrontCamera)` callback
   (https://getstream.github.io/webrtc-android/stream-webrtc-android/org.webrtc/-camera-video-capturer/index.html).

6. **Claim:** Resolution presets are SD 640×480, HD 1280×720, FHD 1920×1080 at 30fps (§6, FR-4).
   **VERDICT:** Verified (contract parity). **SOURCE:** Web reference video constraints use
   `width {ideal:1280,max:1920}`, `height {ideal:720,max:1080}`, `frameRate {ideal:30,max:30}`
   — `src/hooks/useMediaCapture.ts: buildConstraints`. The Android presets are a superset
   discretization of the same ranges; default `HD_720` matches the web `ideal`.

7. **Claim:** Resolution change uses `videoCapturer.changeCaptureFormat(w,h,fps)` with a
   stop+start fallback; an unsupported resolution reverts cleanly with a non-fatal error
   (FR-4, AC-4, §7).
   **VERDICT:** Verified. **SOURCE:** framework ref — `org.webrtc.CameraVideoCapturer` /
   `VideoCapturer` expose `changeCaptureFormat(int, int, int)` and
   `startCapture(width, height, framerate)` (stream-webrtc-android docs, link in #5).
   Contract parity for the revert-on-unsupported behavior: the web reference catches
   `OverconstrainedError` and retries with relaxed constraints —
   `src/hooks/useMediaCapture.ts: acquire` (OverconstrainedError branch).

8. **Claim:** Capturer error callbacks (`onCameraError`, `onCameraDisconnected`,
   `onCameraFreezed`) map to recoverable errors; "camera in use by another app" is surfaced
   with a Retry path (§7, AC-8).
   **VERDICT:** Verified. **SOURCE:** framework ref — `CameraVideoCapturer.CameraEventsHandler`
   defines `onCameraError`, `onCameraDisconnected`, `onCameraFreezed`, `onCameraOpening`,
   `onFirstFrameAvailable`, `onCameraClosed` (stream-webrtc-android docs). Contract parity for
   the error taxonomy: the web reference categorizes `NotReadableError` as
   "in use by another application" and `NotFoundError`/`NotAllowedError` —
   `src/hooks/useMediaCapture.ts: categorizeError`.

9. **Claim:** `Camera2Enumerator.isSupported(context)` selects Camera2 vs `Camera1Enumerator`;
   front/back chosen by walking `enumerator.deviceNames` (§4.2).
   **VERDICT:** Verified. **SOURCE:** framework ref — `org.webrtc.Camera2Enumerator`,
   `Camera1Enumerator`, and the `CameraEnumerator` interface (`deviceNames`,
   `isFrontFacing`, `isBackFacing`, `createCapturer`) are standard stream-webrtc-android
   APIs.

10. **Claim:** Track ids `ARDAMSv0` (video) / `ARDAMSa0` (audio) follow WebRTC convention
    (§4.2, §10).
    **VERDICT:** Verified (convention) / Unverified-assumption (downstream expectation).
    **SOURCE:** framework ref — `ARDAMSv0`/`ARDAMSa0` are the canonical AppRTC sample track
    ids used throughout WebRTC Android samples. Whether the downstream E39 connection ticket
    requires these exact ids is an open question (see §13 R3) and cannot be verified from
    current sources.

11. **Claim:** Android 12+ shows a system privacy indicator for active camera/mic and it must
    not be suppressed (§8).
    **VERDICT:** Verified. **SOURCE:** framework ref — Android privacy indicators, API 31+
    (https://developer.android.com/about/versions/12/behavior-changes-all#privacy-indicators).

12. **Claim:** `<uses-feature android:name="android.hardware.camera" android:required="false" />`
    keeps the app installable on camera-less devices (§8).
    **VERDICT:** Verified. **SOURCE:** framework ref — Google Play `uses-feature` filtering
    (https://developer.android.com/guide/topics/manifest/uses-feature-element).

13. **Claim:** Defensively re-check `ContextCompat.checkSelfPermission` for CAMERA/RECORD_AUDIO
    before start, since permission can be revoked while backgrounded (§7).
    **VERDICT:** Verified. **SOURCE:** framework ref — runtime permission revocation behavior
    (https://developer.android.com/training/permissions/requesting). Contract parity: the web
    reference also re-derives permission state and handles `NotAllowedError` at acquire time
    (`src/hooks/useMediaCapture.ts`).

14. **Claim:** Stack is Kotlin 2.0.21 / Compose+M3 / Hilt(KSP) / Coroutines, stream-webrtc-android,
    minSdk 24, compile/target 35, AGP 8.7.3, Gradle 8.9 (§2).
    **VERDICT:** Unverified-assumption (inherited from AND-288). **SOURCE:** Not verifiable
    from the backend OpenAPI or the web frontend; these are Android-port build choices
    established in AND-288 and assumed consistent here.

### Corrections made

- **§6 (cameraCount):** Added a clarifying note that the web reference re-enumerates devices
  on the `devicechange` hot-plug event (`src/hooks/useMediaDevices.ts`), whereas this spec
  computes `cameraCount` once. This is acceptable because Android built-in front/back cameras
  are fixed and external cameras are out of scope — but the divergence is now documented
  rather than left as an unstated assumption.
- No factual errors were found in the API/method/field claims. The core framework API names
  (`switchCamera`, `onCameraSwitchDone`, `changeCaptureFormat`, `CameraEventsHandler`,
  `Camera2Enumerator`), the mute-via-`enabled` approach, the <2-camera switch gating, and the
  resolution constraint set all verified against authoritative sources, so the remaining edits
  are limited to this clarification plus the appended audit/test sections.

### Open assumptions

- **Track id contract (R3, claim #10):** Whether the downstream E39 connection ticket expects
  exactly `ARDAMSv0`/`ARDAMSa0` is unverifiable — that ticket is not enumerated and no source
  pins the ids. Conventional ids used pending confirmation.
- **Build/toolchain versions (claim #14):** Kotlin/AGP/Gradle/SDK versions are inherited from
  AND-288 and not independently verifiable from the provided backend or frontend sources.
- **Audio routing (OQ3):** speaker/earpiece/BT routing is assumed owned by a later ticket; no
  source confirms ownership.
- **DataStore persistence of last device/resolution (OQ2):** product decision, not verifiable
  from sources.

## 17. Test Plan

Test-target legend: **JVM** = local JVM unit/Robolectric (no device); **emu35** = headless
emulator AVD `test35` (x86_64, Android 15 / API 35, CI); **device** = physical Samsung Galaxy
A15 5G (SM-A156U, serial R5CX821TA9R, Android 14 / API 34, arm64-v8a). Camera/mic hardware,
HAL release, and real front/back switching MUST run on **device** (emulators provide only
synthetic cameras and cannot prove real HAL release or true front/back mirroring).

**TC-AND-292-01 — Controller: startCamera creates sources/tracks once (happy path)**
- Type: unit. Target: JVM (MockK + `kotlinx-coroutines-test` TestDispatcher, Turbine).
- Preconditions: mocked `PeerConnectionFactory`, `CameraEnumerator` (2 devices), permissions granted.
- Steps: call `startCamera()`; await state. Call `startCamera()` again.
- Expected: video/audio source + `VideoTrack`/`AudioTrack` created exactly once; `videoTrack`/`audioTrack` StateFlows emit non-null; `cameraOn=true`, `capturing` settles false; tracks default `setEnabled(true)`.
- Traces: AC-1, AC-6.

**TC-AND-292-02 — Controller: mute toggles track.enabled without HAL teardown**
- Type: unit. Target: JVM.
- Preconditions: camera started (TC-01 state).
- Steps: `setMicMuted(true)` then `setMicMuted(false)`.
- Expected: `audioTrack.setEnabled(false)` then `(true)` verified; `micMuted` reflects; capturer/audioSource NOT released or recreated.
- Traces: AC-2.

**TC-AND-292-03 — Controller: switchCamera flips facing and is guarded while in flight**
- Type: unit. Target: JVM.
- Preconditions: 2-camera enumerator; camera started.
- Steps: call `switchCamera()`; invoke captured `CameraSwitchHandler.onCameraSwitchDone(false)`. Then call `switchCamera()` twice rapidly while `capturing==true`.
- Expected: `capturer.switchCamera(handler)` invoked; `isFrontFacing` flips to false on callback; the re-entrant second call is ignored (verify only one in-flight switch).
- Traces: AC-3.

**TC-AND-292-04 — Controller: single-camera disables switch**
- Type: unit. Target: JVM.
- Preconditions: enumerator with 1 device.
- Steps: read state after init; call `switchCamera()`.
- Expected: `cameraCount==1`; `switchCamera` is a no-op (capturer.switchCamera never called).
- Traces: AC-3.

**TC-AND-292-05 — Controller: setResolution reconfigures, with fallback and revert**
- Type: unit. Target: JVM.
- Preconditions: camera started at `HD_720`.
- Steps: (a) `setResolution(FHD_1080)` → `changeCaptureFormat` succeeds. (b) Force `changeCaptureFormat` to throw → assert stop+start fallback. (c) Force both to throw.
- Expected: (a) `changeCaptureFormat(1920,1080,30)` called, `resolution=FHD_1080`. (b) `stopCapture()`+`startCapture(...)` invoked. (c) `resolution` reverts to prior value, non-fatal `CaptureError` emitted, no crash.
- Traces: AC-4.

**TC-AND-292-06 — Controller: dispose releases all native objects and is idempotent**
- Type: unit. Target: JVM.
- Preconditions: camera started.
- Steps: call `dispose()`; call `dispose()` and `stopCamera()` again.
- Expected: `release()` verified on capturer, videoSource, audioSource, tracks, surfaceHelper; fields nulled; repeated calls do not throw.
- Traces: AC-8.

**TC-AND-292-07 — Controller: permission revoked emits PermissionDenied (security)**
- Type: unit. Target: JVM (Robolectric to stub `checkSelfPermission`).
- Preconditions: `checkSelfPermission(CAMERA)` returns DENIED.
- Steps: call `startCamera()`.
- Expected: no capturer created; `CaptureError.PermissionDenied` emitted; no crash; `cameraOn=false`.
- Traces: AC-8.

**TC-AND-292-08 — Contract: error-callback taxonomy maps to recoverable CaptureError**
- Type: contract (no MockWebServer — local-only; mock `CameraEventsHandler` callbacks). Target: JVM.
- Preconditions: camera starting.
- Steps: invoke `onCameraError`, `onCameraDisconnected`, `onCameraFreezed`.
- Expected: each maps to `CameraUnavailable`/`CameraInUse` as specified; `cameraOn=false`; capturer released; error marked retriable.
- Traces: AC-8.

**TC-AND-292-09 — Compose-UI: control callbacks and switch enablement**
- Type: Compose-UI. Target: emu35 (`createComposeRule`).
- Preconditions: rendered `CaptureScreen` with seeded states.
- Steps: tap camera/mute/switch buttons; select a resolution from the menu; render once with `cameraCount=1` and once with `cameraCount=2`.
- Expected: each tap invokes the matching callback exactly once; switch button disabled when `cameraCount<=1`, enabled when `>=2`; resolution selection invokes `onSelectResolution` with the chosen preset.
- Traces: AC-1, AC-2, AC-3, AC-4.

**TC-AND-292-10 — Compose-UI: accessibility content descriptions and externalized strings**
- Type: Compose-UI / accessibility. Target: emu35.
- Preconditions: rendered `CaptureScreen`.
- Steps: assert `contentDescription`/`stateDescription` for camera (on/off), mute (mute/unmute), switch (front/back); toggle states and re-assert; assert no hardcoded literals (strings resolved from `capture_*` resources); verify touch targets >= 48dp.
- Expected: descriptions are state-accurate and flip with state; all visible text comes from `strings.xml`; mic/mic-off use distinct glyphs (color is not the sole signal).
- Traces: AC-7.

**TC-AND-292-11 — Instrumented: real camera produces frames at the local preview (happy path, hardware)**
- Type: instrumented/e2e. Target: **device** (MUST — real camera HAL; emulator synthetic camera does not prove this).
- Preconditions: CAMERA/RECORD_AUDIO granted on SM-A156U.
- Steps: launch capture screen; `startCamera()`; attach a `VideoSink` and assert `onFrame` is called within a timeout.
- Expected: frames arrive at the renderer; `cameraOn=true`; `videoTrack` non-null.
- Traces: AC-1, AC-6.

**TC-AND-292-12 — Instrumented: lifecycle releases the camera HAL on background, restores on foreground**
- Type: instrumented/e2e. Target: **device** (MUST — verifies a second app can open the camera; HAL release is not faithfully testable on emulator).
- Preconditions: camera on.
- Steps: drive `ON_STOP`; confirm frames stop and the camera is released (open the system camera app or a second `CameraDevice` to confirm availability); drive `ON_START`.
- Expected: on `ON_STOP` the HAL is released (external open succeeds) and frames stop; on `ON_START` capture resumes because it was previously on.
- Traces: AC-5.

**TC-AND-292-13 — Instrumented: front/back switch mirroring and rotation state survival (hardware)**
- Type: instrumented/e2e. Target: **device** (MUST — real dual-camera mirroring; emulator lacks a true back camera).
- Preconditions: SM-A156U (front + back cameras), camera on, front facing.
- Steps: tap switch; verify preview `setMirror(false)` for back, `setMirror(true)` for front; rotate the device; re-read state.
- Expected: `isFrontFacing` flips and preview mirroring follows (front mirrored, back not); after rotation, `cameraOn`/`micMuted`/`isFrontFacing`/`resolution` are preserved (config-change survival via `@ActivityRetainedScoped`).
- Traces: AC-3, AC-5.

**TC-AND-292-14 — Manual: privacy indicator and camera-in-use recovery (security)**
- Type: manual. Target: **device** (Android 14 system privacy indicator + real second-app contention).
- Preconditions: SM-A156U.
- Steps: start camera and confirm the system privacy indicator (green dot) appears for camera and mic; open another app holding the camera, then attempt `startCamera()`; tap Retry after releasing the other app.
- Expected: privacy indicator shows and is not suppressed; contention surfaces "Camera is in use by another app" with a working Retry that succeeds once the camera is free; no crash.
- Traces: AC-8.

### Coverage matrix

| Acceptance criterion | Covered by |
| --- | --- |
| AC-1 (camera toggle / preview / HAL release on stop) | TC-01, TC-09, TC-11, TC-12 |
| AC-2 (mute via track.enabled, no HAL teardown) | TC-02, TC-09 |
| AC-3 (camera switch + mirror; disabled on single camera) | TC-03, TC-04, TC-09, TC-13 |
| AC-4 (resolution reconfigure / revert on unsupported) | TC-05, TC-09 |
| AC-5 (background release, foreground restore, rotation survival) | TC-12, TC-13 |
| AC-6 (video/audio track StateFlows emit usable tracks) | TC-01, TC-11 |
| AC-7 (state-aware content descriptions; externalized strings) | TC-10 |
| AC-8 (recoverable errors + Retry; idempotent dispose; no leaks) | TC-06, TC-07, TC-08, TC-14 |
