---
id: AND-292
title: Media capture + device selection
milestone: M7
epic: E39
priority: P1
size: M
status: draft
depends_on: [AND-288]
blocks: []
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
  disable the switch control.

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
