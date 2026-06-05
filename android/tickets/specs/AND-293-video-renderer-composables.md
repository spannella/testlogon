---
id: AND-293
title: Video renderer composables
milestone: M7
epic: E39
priority: P1
size: M
status: draft
depends_on: [AND-288]
blocks: []
---

# AND-293 — Video renderer composables

## 1. Overview & Goal

Provide reusable Jetpack Compose wrappers around the WebRTC `SurfaceViewRenderer`
so feature code can render both the local camera preview and remote peer video
tracks declaratively, without touching the imperative WebRTC view lifecycle.
This ticket delivers the *view* layer only: a pair of composables
(`LocalVideoRenderer`, `RemoteVideoRenderer`) plus a shared lower-level
`VideoRenderer` primitive, a scaling/mirroring model, and the
`EglBase.Context` plumbing required to initialise the renderer. It does **not**
own peer-connection setup, signaling, or track negotiation — those live in the
call/session feature tickets that consume these composables.

The driving requirement from the backlog is concise: *"Local + remote video
render."* Concretely, the goal is that given a `VideoTrack` (org.webrtc) and a
shared `EglBase.Context` (both produced by AND-288's WebRTC integration), a
caller can place a composable in any layout and see frames painted, with correct
aspect-ratio handling, correct mirroring of the front-facing local camera, and
deterministic attach/detach so no surface leaks or "black frame after
rotation/recompose" defects occur.

## 2. Context & References

- **Module:** `core-webrtc` (new sub-package `…webrtc.ui`) or `core-ui` video
  package, exposed to `feature-call`. Canonical namespace
  `com.testlogon.android`; composables live in
  `com.testlogon.android.core.webrtc.ui`.
- **Depends on AND-288** (`webrtc-android integration + permissions`, P0): adds
  the `io.github.webrtc-sdk:android` (`org.webrtc.*`) dependency, the
  `PeerConnectionFactory` bootstrap, the shared `EglBase`, and runtime
  camera/mic permissions. AND-293 assumes `EglBase.Context` and `VideoTrack`
  instances are already available; it must not duplicate factory init.
- **Consumers:** the call-screen feature ticket(s) under epic E39 wire real
  tracks into these composables. Signaling/SDP, ICE, and track lifecycle are
  out of scope here and owned downstream.
- **Web reference:** the `frontend/` app renders WebRTC via `<video>`
  elements with `object-fit: cover|contain`; this ticket mirrors that scaling
  semantics on Android via `RendererCommon.ScalingType`.
- **Platform:** Kotlin 2.0.21, Compose + Material 3, minSdk 24, compileSdk 35,
  AGP 8.7.3. `SurfaceViewRenderer` is hosted via `AndroidView`.
- **Stack note:** This is a real-time WebRTC surface, distinct from
  Media3/ExoPlayer HLS playback (used elsewhere for VOD); the two share no code.

## 3. Functional Requirements

FR-1. Expose `RemoteVideoRenderer(track: VideoTrack?, eglContext: EglBase.Context, …)`
that renders a remote peer's video track and shows a placeholder when
`track == null` (not yet connected / track removed).

FR-2. Expose `LocalVideoRenderer(track: VideoTrack?, eglContext: EglBase.Context, mirror: Boolean = true, …)`
that renders the local camera preview, mirrored by default for front camera.

FR-3. Both composables MUST support a `scalingType` parameter mapping to
`RendererCommon.ScalingType` with two app-level modes: `FIT` (letterbox, no
crop → `SCALE_ASPECT_FIT`) and `FILL` (crop to fill → `SCALE_ASPECT_BALANCED`
for matched, `SCALE_ASPECT_FILL` when mismatched). Default `FILL` for remote
full-screen, `FILL` for local PiP.

FR-4. The underlying `SurfaceViewRenderer` MUST be initialised exactly once
with the shared `eglContext`, attached as the track's sink on enter, and
released (sink removed + `release()`) on dispose — with no leak across
recomposition or configuration change.

FR-5. Track swaps MUST be handled: when the `track` argument changes from
A→B (or A→null), the old track's sink is removed and the new one added without
recreating the `SurfaceViewRenderer`.

FR-6. `mirror` and `scalingType` changes MUST update the live renderer in place
(no view recreation, no flicker).

FR-7. Provide an `enableHardwareScaler` toggle (default true) and a
`keepScreenOn` modifier hook so the call screen can keep the display awake while
rendering remote video.

FR-8. Provide a Compose `@Preview`-friendly path: when no `EglBase.Context` is
available (preview/inspection mode, `LocalInspectionMode.current == true`),
render a static placeholder instead of attempting WebRTC init.

## 4. Technical Design

`SurfaceViewRenderer` is an Android `View`, so it is hosted with `AndroidView`.
The renderer is a mutable, lifecycle-bearing object; we manage it through
`remember` + `DisposableEffect` keyed by `eglContext`, and drive track/scaling
updates through the `update` lambda and dedicated `LaunchedEffect`s.

```kotlin
package com.testlogon.android.core.webrtc.ui

import org.webrtc.EglBase
import org.webrtc.RendererCommon.ScalingType
import org.webrtc.SurfaceViewRenderer
import org.webrtc.VideoTrack

enum class VideoScaling { FIT, FILL }

@Composable
fun VideoRenderer(
    track: VideoTrack?,
    eglContext: EglBase.Context,
    modifier: Modifier = Modifier,
    mirror: Boolean = false,
    scaling: VideoScaling = VideoScaling.FILL,
    enableHardwareScaler: Boolean = true,
    placeholder: @Composable () -> Unit = { VideoPlaceholder() },
)

@Composable
fun LocalVideoRenderer(
    track: VideoTrack?,
    eglContext: EglBase.Context,
    modifier: Modifier = Modifier,
    mirror: Boolean = true,
    scaling: VideoScaling = VideoScaling.FILL,
)

@Composable
fun RemoteVideoRenderer(
    track: VideoTrack?,
    eglContext: EglBase.Context,
    modifier: Modifier = Modifier,
    scaling: VideoScaling = VideoScaling.FILL,
)
```

Core implementation of the shared primitive:

```kotlin
@Composable
fun VideoRenderer(
    track: VideoTrack?,
    eglContext: EglBase.Context,
    modifier: Modifier,
    mirror: Boolean,
    scaling: VideoScaling,
    enableHardwareScaler: Boolean,
    placeholder: @Composable () -> Unit,
) {
    if (LocalInspectionMode.current) { placeholder(); return }

    val renderer = remember(eglContext) { mutableStateOf<SurfaceViewRenderer?>(null) }
    val currentTrack = remember { mutableStateOf<VideoTrack?>(null) }

    Box(modifier) {
        AndroidView(
            modifier = Modifier.matchParentSize(),
            factory = { ctx ->
                SurfaceViewRenderer(ctx).apply {
                    init(eglContext, /* rendererEvents = */ null)
                    setEnableHardwareScaler(enableHardwareScaler)
                    renderer.value = this
                }
            },
            update = { view ->
                view.setMirror(mirror)
                view.setScalingType(scaling.toFitType(), scaling.toFillType())
            },
            onRelease = { view ->
                currentTrack.value?.removeSink(view)
                view.release()
                renderer.value = null
                currentTrack.value = null
            },
        )
        if (track == null) placeholder()
    }

    // Attach/detach + swap, decoupled from view (re)creation.
    LaunchedEffect(renderer.value, track) {
        val view = renderer.value ?: return@LaunchedEffect
        if (currentTrack.value === track) return@LaunchedEffect
        currentTrack.value?.removeSink(view)
        track?.addSink(view)
        currentTrack.value = track
    }
}

private fun VideoScaling.toFitType(): ScalingType =
    if (this == VideoScaling.FIT) ScalingType.SCALE_ASPECT_FIT else ScalingType.SCALE_ASPECT_BALANCED
private fun VideoScaling.toFillType(): ScalingType =
    if (this == VideoScaling.FIT) ScalingType.SCALE_ASPECT_FIT else ScalingType.SCALE_ASPECT_FILL
```

Design notes:
- `init()`/`release()` are keyed to the `AndroidView` factory/`onRelease`,
  which Compose ties to the node's enter/leave — guaranteeing exactly-once init
  and a matched release even across config changes (the node is recreated, the
  old one released).
- Track attach lives in a `LaunchedEffect(renderer, track)` so a track swap does
  not recreate the surface; the `===` identity guard prevents redundant
  re-`addSink`.
- `mirror`/`scaling` flow through `update`, which Compose re-invokes on each
  recomposition where inputs change — in-place mutation, no flicker (FR-6).
- `VideoPlaceholder` is a Material 3 surface with a centered avatar/spinner;
  remote default shows a "Connecting…" state, local shows a camera-off glyph.

## 5. API Contract

N/A — this ticket adds no network calls and consumes no FastAPI endpoints. It
operates purely on in-process `org.webrtc.VideoTrack` / `EglBase.Context`
objects supplied by the WebRTC stack (AND-288) and the downstream call/signaling
feature. The relevant signaling REST/WebSocket contract (SDP offer/answer, ICE)
is owned by the call-session ticket in epic E39 and is out of scope here. The
only "contract" AND-293 defines is the Kotlin composable surface in §4.

## 6. Data & State Management

- **No persisted state.** No Room, no DataStore, no ViewModel introduced by this
  ticket. Renderer state is purely view-local and lifecycle-scoped.
- **Inputs** (`track`, `eglContext`, `mirror`, `scaling`) are owned by the
  caller's ViewModel as part of its `StateFlow<CallUiState>`; this ticket is a
  pure function of those inputs.
- **Internal mutable state:** the `SurfaceViewRenderer` handle and the currently
  attached `VideoTrack`, both held in `remember { mutableStateOf(...) }` and
  reset to `null` on dispose. These are the only mutable cells and never escape
  the composable.
- **Identity contract:** callers MUST pass stable `VideoTrack` instances (same
  object reference while the track is unchanged). The attach logic uses
  reference identity (`===`) to detect swaps; passing a new wrapper each
  recomposition would cause needless re-attach. This constraint is documented on
  the public composable KDoc.
- **EglBase ownership:** `eglContext` is owned and released by AND-288's WebRTC
  module, NOT by these composables. `release()` here releases only the
  `SurfaceViewRenderer`, never the shared `EglBase`.

## 7. Error Handling & Resilience

- **Null track:** rendered as the placeholder (FR-1/FR-8); not an error state.
- **init() failure** (rare; bad EGL context): wrap `init()` in try/catch, log at
  `ERROR`, leave the placeholder visible, and surface nothing crashy to the user.
  The renderer remains `null` so no sink is attached.
- **Double-release safety:** `release()` is idempotent in our wrapper because we
  null the handle; the `===` guards prevent removing a sink from a released view.
- **Recomposition storms / config change:** because attach is in a keyed
  `LaunchedEffect` and init/release are tied to node lifecycle, rotation and
  dark-mode toggles re-create the surface cleanly with no black-frame hangover
  (explicitly tested, FR-4).
- **No frames arriving** (network stall, decoder starvation): outside this
  ticket's control. We optionally pass a `RendererCommon.RendererEvents` callback
  exposing `onFirstFrameRendered`/`onFrameResolutionChanged` so the consuming
  call screen can show a "reconnecting" overlay; the resilience policy (timeouts,
  ICE restart) is owned downstream.
- This is a real-time media surface — there is no retry/backoff or offline-cache
  story at the renderer level (those project-wide HTTP rules do not apply to the
  WebRTC media path).

## 8. Security & Privacy

- **Camera/mic permissions** are requested and gated by AND-288; this ticket
  renders only tracks it is handed and must not start capture itself.
- **Local preview privacy:** `LocalVideoRenderer` displays the user's own camera.
  When the composable leaves composition (navigating away, app backgrounded),
  `release()` detaches the sink so no frames are painted off-screen. Actual
  camera capture stop is owned by the capturer lifecycle (AND-288/feature), but
  this ticket guarantees the *view* stops consuming frames promptly.
- **No data leaves the device** from this layer; no logging of frame contents or
  PII. Track IDs may be logged at DEBUG only (opaque identifiers).
- **Screenshots/recents:** the call screen may set `FLAG_SECURE`; this ticket
  exposes `keepScreenOn` but defers `FLAG_SECURE` policy to the call feature.

## 9. Accessibility & i18n

- Renderers are decorative video surfaces; each accepts an optional
  `contentDescription` (default localized strings:
  `R.string.video_local_preview`, `R.string.video_remote_feed`) set on the
  hosting `Box` via `Modifier.semantics`. Frame content is not announced.
- Placeholder text ("Connecting…", "Camera off") is sourced from `strings.xml`
  and fully translatable; no hardcoded user-facing strings.
- Placeholder respects Material 3 theming, dynamic color, and dark mode; no
  fixed colors.
- Mirroring affects only the local preview and does not impact TalkBack reading
  order. Touch targets are not introduced by the renderer itself (controls are
  overlaid by the feature and own their own a11y).
- RTL-safe: layout uses `matchParentSize`/`fillMaxSize`, no
  start/end-sensitive offsets.

## 10. Telemetry & Logging

- **Logging:** namespaced `Timber`/`Log` tag `WebRtcRenderer`. Log at:
  `init` (DEBUG, with renderer hash + scaling), track attach/detach (DEBUG, with
  truncated track id), `onFirstFrameRendered` (INFO), and any `init`/`release`
  exception (ERROR). No frame data, no PII.
- **Telemetry events** (via the app's analytics abstraction, if wired by E39):
  `video_first_frame` with attributes `{role: local|remote, latency_ms_since_attach}`
  and `video_resolution_changed {role, width, height, rotation}` emitted from the
  optional `RendererEvents` callback. Emission is opt-in by the consumer; this
  ticket only exposes the hook, it does not own the analytics pipeline.
- No metrics network calls added here.

## 11. Testing Strategy

- **Unit (JVM):** test the pure helpers `VideoScaling.toFitType()/toFillType()`
  for both `FIT` and `FILL` mappings. Test the attach-decision logic by
  extracting it into a testable `shouldSwap(current, next)` function.
- **Robolectric / Compose UI test (`core-testing`):**
  - Renders without crashing given a fake `EglBase.Context` and a mocked
    `VideoTrack`; asserts `addSink` is called exactly once (Mockito/MockK verify).
  - Track swap A→B: `removeSink(A)` then `addSink(B)` called once each, no
    second `init`.
  - track → null: placeholder node is asserted present
    (`onNodeWithContentDescription`/test tag), `removeSink` called.
  - `LocalInspectionMode` path renders placeholder and never calls `init`.
  - Dispose (remove from composition): `removeSink` + `release` verified once.
  - `mirror`/`scaling` change: `setMirror`/`setScalingType` verified called with
    new args, `init` NOT called again (no recreation).
- **Manual / instrumented loopback:** building on AND-288's loopback sample,
  wire the local capturer's `VideoTrack` into both `LocalVideoRenderer` and
  `RemoteVideoRenderer` on a real device; visually confirm: local renders
  mirrored, remote renders unmirrored, rotation keeps painting, FIT letterboxes
  and FILL crops correctly. This satisfies the backlog acceptance "Local +
  remote video render."
- **Leak check:** LeakCanary run across navigate-in/out cycles asserts no
  `SurfaceViewRenderer`/`EglRenderer` retention.

## 12. Dependencies & Sequencing

- **Hard dependency: AND-288** (P0) must land first — it provides the
  `org.webrtc` dependency, `PeerConnectionFactory`/`EglBase` bootstrap, and
  permissions. AND-293 cannot compile or run without it.
- **Transitive:** AND-288 depends on AND-004 (project/Gradle build wiring).
- **Blocks:** the call-screen UI ticket(s) in epic E39 that lay these
  composables into the live call layout (PiP local over full-screen remote).
  Those tickets own the real `VideoTrack` production and signaling; they are the
  natural integration point and consume AND-293's public surface verbatim.
- **Parallelizable:** placeholder/Material 3 styling can proceed against
  `core-ui` independently once AND-288 stubs exist.

## 13. Risks & Open Questions

- **R1 — Surface vs. Texture renderer:** `SurfaceViewRenderer` cannot be
  composited/animated/overlapped as freely as a `TextureView`-based renderer.
  For a PiP-over-fullscreen layout, z-ordering and rounded-corner clipping on the
  local preview may require `setZOrderMediaOverlay(true)` or switching the local
  view to a `TextureViewRenderer`. Decision: ship `SurfaceViewRenderer` per the
  backlog scope; expose an internal flag to swap the local view to texture-based
  if PiP clipping proves inadequate. *Open question for the E39 call-screen
  ticket.*
- **R2 — EglBase context lifetime:** if AND-288 releases `EglBase` while a
  renderer is live, `release()` ordering matters. Mitigation: document that the
  shared `EglBase` outlives all renderers; renderers key their `init` to the
  context instance and self-release first.
- **R3 — First-frame black flash** on some OEMs until `onFirstFrameRendered`.
  Mitigation: keep placeholder visible until first frame via the optional
  `RendererEvents` callback.
- **R4 — Scaling parity with web:** `SCALE_ASPECT_BALANCED` vs `SCALE_ASPECT_FILL`
  may not pixel-match the web `object-fit: cover`. Open question: confirm the
  desired crop behavior with design before finalizing `FILL` mapping.

## 14. Acceptance Criteria

AC-1. Given a non-null remote `VideoTrack` and a valid `EglBase.Context`,
`RemoteVideoRenderer` paints live frames on a physical device (backlog: remote
video render). *(verified manually + loopback)*

AC-2. Given a non-null local `VideoTrack`, `LocalVideoRenderer` paints frames
mirrored by default (backlog: local video render). Setting `mirror = false`
removes mirroring in place without view recreation.

AC-3. `scaling = FIT` letterboxes (no crop); `scaling = FILL` crops to fill.
Both map to the documented `RendererCommon.ScalingType` values.

AC-4. `track == null` shows the localized placeholder; transitioning null→track
and track→null adds/removes the sink correctly (verified `addSink`/`removeSink`
call counts in test).

AC-5. Swapping `track` A→B removes A's sink and adds B's without a second
`init()` call (verified in instrumented test).

AC-6. Leaving composition releases the renderer and removes the sink exactly
once; LeakCanary reports no `SurfaceViewRenderer` retention across navigate
in/out cycles.

AC-7. Rotation and dark-mode toggles keep video painting (no persistent black
frame) — verified manually on device.

AC-8. `LocalInspectionMode` (`@Preview`) renders the placeholder and never calls
`init()`.

## 15. Definition of Done

- `VideoRenderer`, `LocalVideoRenderer`, `RemoteVideoRenderer`, `VideoScaling`,
  and `VideoPlaceholder` implemented in
  `com.testlogon.android.core.webrtc.ui`, with public KDoc covering the
  stable-`VideoTrack`-identity contract.
- All localized strings added to `strings.xml`; no hardcoded user-facing text.
- Unit + Robolectric/Compose UI tests for §11 pass in CI; LeakCanary clean.
- Loopback manual verification on at least one physical device documented in the
  PR (local mirrored, remote unmirrored, FIT/FILL, rotation), satisfying the
  backlog acceptance.
- No new network calls, no new persisted state, no `EglBase` ownership added.
- ktlint/detekt clean; builds against compileSdk 35 / AGP 8.7.3 / JDK 17 on the
  `android-port` branch; merged behind AND-288.
- Public composable API reviewed by the E39 call-screen ticket owner so the
  downstream integration consumes it without changes.
