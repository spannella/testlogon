---
id: AND-293
title: Video renderer composables
milestone: M7
epic: E39
priority: P1
size: M
depends_on: [AND-288]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
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
- **Web reference:** the `frontend/` app renders live WebRTC peer video via a
  `<video>` element (`CallSessionOverlay.tsx: VideoRenderer`) using Tailwind
  `object-cover` (CSS `object-fit: cover`) for BOTH local and remote feeds; the
  local preview additionally gets `muted` + `mirror` (`[transform:scaleX(-1)]`),
  remote is unmirrored. **Correction (review):** an earlier draft claimed the web
  used `object-fit: cover|contain` for the call surface — verified false. The
  *live call* path is `cover`-only (our `FILL`); `object-contain` (our `FIT`)
  appears only in VOD/media playback (`MediaPlayer.tsx`) and KYC capture preview
  (`MediaSettingsPage.tsx`), not in the peer-video surface. We still expose a
  `FIT` mode on Android for parity/flexibility, but FILL is the web-matched
  default. Android maps these via `RendererCommon.ScalingType`.
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
- **R4 — Scaling parity with web:** the web live-call surface is `object-fit:
  cover` (verified, `CallSessionOverlay.tsx`), which is an unconditional aspect-fill
  crop. Our `FILL` mode maps to `SCALE_ASPECT_BALANCED` (matched) /
  `SCALE_ASPECT_FILL` (mismatched); `SCALE_ASPECT_BALANCED` does **not**
  guarantee a full edge-to-edge crop the way CSS `cover` does, so the BALANCED
  branch may letterbox slightly where the web would crop. Open question: confirm
  with design whether `FILL` should map to `SCALE_ASPECT_FILL` unconditionally to
  pixel-match web `cover`, accepting more aggressive cropping.

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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. "framework
ref" denotes an Android/WebRTC framework fact verified against documentation
(not derivable from this repo's reference sources, which are a web app + backend
OpenAPI).

1. **Claim:** This ticket adds no network calls / consumes no FastAPI
   endpoints (§5).
   **VERDICT:** Verified.
   **SOURCE:** `reference/openapi.index.txt` — the only WebRTC-adjacent
   endpoints are signaling/broadcast (`POST /broadcast/sessions/{session_id}/inputs/{input_id}/webrtc-offer`
   → `BroadcastWebRTCOfferIn`/`BroadcastWebRTCOfferOut`, and the
   `/messages/calls/{call_id}/...` recording/consent routes). None render video;
   all are owned by signaling/recording tickets downstream. The renderer
   composables touch no HTTP.

2. **Claim:** The web client renders live peer video with `object-fit: cover`
   for both local and remote feeds (§2, §13-R4).
   **VERDICT:** Corrected (was "`object-fit: cover|contain`").
   **SOURCE:** `src/pages/messages/CallSessionOverlay.tsx: VideoRenderer`
   (`className={cn("h-full w-full object-cover", ...)}`). `object-contain` is
   used only in non-live surfaces: `src/components/shared/MediaPlayer.tsx` (VOD)
   and `src/pages/calls/MediaSettingsPage.tsx` (KYC preview). The live call path
   is cover-only.

3. **Claim:** The web mirrors the local preview by default and leaves remote
   unmirrored; mirroring is a horizontal flip (§2, §4, FR-2, AC-2).
   **VERDICT:** Verified.
   **SOURCE:** `src/pages/messages/CallSessionOverlay.tsx` — local renderer is
   invoked with `mirror` (and `muted`, `aria-label="Local video preview"`);
   remote renderer omits `mirror` (prop defaults to `false`). Mirror is applied
   as `mirror && "[transform:scaleX(-1)]"`.

4. **Claim:** Mirroring the local preview is appropriate because the local
   camera is the front ("user") camera (§1, FR-2).
   **VERDICT:** Verified (web parity).
   **SOURCE:** `src/lib/webrtc.ts: acquireLocalMedia` — video constraints use
   `facingMode: "user"`. (Android front-vs-back capturer selection is owned by
   AND-288; this ticket only flips the view.)

5. **Claim:** The web detaches the media sink when the renderer leaves the DOM
   (parity for FR-4 "release on dispose") (§4, §8, AC-6).
   **VERDICT:** Verified.
   **SOURCE:** `src/pages/messages/CallSessionOverlay.tsx: VideoRenderer` —
   `useEffect` cleanup sets `videoRef.current.srcObject = null` on unmount/stream
   change. Android analogue: `removeSink` + `release()` in `onRelease`.

6. **Claim:** `SurfaceViewRenderer` is an `org.webrtc` `View` initialised via
   `init(EglBase.Context, RendererCommon.RendererEvents)` and torn down via
   `release()` (§4, FR-4).
   **VERDICT:** Unverified-assumption (framework ref).
   **SOURCE:** WebRTC Android API (`org.webrtc.SurfaceViewRenderer`,
   `org.webrtc.EglBase`). No Android/WebRTC source exists in this repo's
   reference (web app only), so the exact signatures cannot be repo-verified;
   they match the published `io.github.webrtc-sdk:android` API and should be
   confirmed against the version AND-288 pins.

7. **Claim:** Scaling maps to `RendererCommon.ScalingType` values
   `SCALE_ASPECT_FIT` (FIT), and `SCALE_ASPECT_BALANCED`/`SCALE_ASPECT_FILL`
   (FILL) via `setScalingType(fit, fill)` (§3 FR-3, §4, AC-3).
   **VERDICT:** Unverified-assumption (framework ref).
   **SOURCE:** WebRTC Android API (`org.webrtc.RendererCommon.ScalingType`,
   `SurfaceViewRenderer.setScalingType`). Enum names match the published API;
   the design correctly notes (§13-R4) that BALANCED is not a strict CSS-`cover`
   equivalent — that is a real framework caveat, not a repo claim.

8. **Claim:** `setMirror`, `setEnableHardwareScaler`, and per-track
   `addSink`/`removeSink` (on `org.webrtc.VideoTrack`) exist and are the
   attach/detach/mutation primitives (§4, FR-5, FR-6).
   **VERDICT:** Unverified-assumption (framework ref).
   **SOURCE:** WebRTC Android API (`SurfaceViewRenderer.setMirror`,
   `.setEnableHardwareScaler`; `VideoTrack.addSink(VideoSink)` /
   `.removeSink(VideoSink)` — `SurfaceViewRenderer` implements `VideoSink`).
   Confirm against the AND-288-pinned SDK version.

9. **Claim:** Compose hosting via `AndroidView` with `factory`/`update`/
   `onRelease`, plus `LocalInspectionMode.current` to short-circuit preview
   (§4, FR-8, AC-8).
   **VERDICT:** Unverified-assumption (framework ref).
   **SOURCE:** Jetpack Compose API
   (`androidx.compose.ui.viewinterop.AndroidView` with the `onRelease`
   parameter; `androidx.compose.ui.platform.LocalInspectionMode`). These are
   standard Compose UI APIs available on the project's Compose version; not
   repo-verifiable here.

10. **Claim:** `EglBase`/`EglBase.Context` and `VideoTrack` are owned and
    released by AND-288, not by this ticket (§2, §6, §13-R2).
    **VERDICT:** Unverified-assumption (cross-ticket contract).
    **SOURCE:** AND-288 ("webrtc-android integration + permissions") scope as
    referenced in this spec's §2/§12. AND-288's spec is the authoritative source
    for the EglBase lifecycle; this is a stated dependency, not a verified fact.

11. **Claim:** Optional `RendererCommon.RendererEvents`
    (`onFirstFrameRendered`, `onFrameResolutionChanged`) can drive a
    "reconnecting"/telemetry hook (§7, §10, §13-R3).
    **VERDICT:** Unverified-assumption (framework ref).
    **SOURCE:** WebRTC Android API
    (`org.webrtc.RendererCommon.RendererEvents`). Callback names match the
    published API; confirm against the pinned SDK.

12. **Claim:** The real-time WebRTC path shares no code with Media3/ExoPlayer
    HLS/VOD playback (§2 stack note).
    **VERDICT:** Verified (by analogy to web separation).
    **SOURCE:** In the web reference these are distinct: live calls use
    `<video srcObject=MediaStream>` (`CallSessionOverlay.tsx`), whereas VOD uses
    the HTMLMediaElement player in `src/components/shared/MediaPlayer.tsx`. The
    Android equivalence (WebRTC vs Media3) is the standard separation; treat the
    Android specifics as a framework assumption.

### Corrections made

- **§2 web reference:** changed "`object-fit: cover|contain`" to reflect the
  actual web live-call surface, which is `object-cover` only
  (`CallSessionOverlay.tsx`); clarified that `object-contain` (our `FIT`) is a
  VOD/KYC-only style. (Citation 2.)
- **§13-R4:** sharpened the scaling-parity risk: web `cover` is an unconditional
  aspect-fill crop, so our `SCALE_ASPECT_BALANCED` branch may letterbox where the
  web crops; flagged the open design question of mapping `FILL` to
  `SCALE_ASPECT_FILL` unconditionally. (Citation 7.)
- **Frontmatter:** `status: draft` → `status: reviewed`; added
  `reviewed_on: 2026-06-06`.

### Open assumptions

- **All `org.webrtc.*` API surface** (`SurfaceViewRenderer.init/release/
  setMirror/setScalingType/setEnableHardwareScaler`, `RendererCommon.ScalingType`
  / `RendererEvents`, `VideoTrack.addSink/removeSink`): unverifiable from this
  repo — the reference is a web app and the backend OpenAPI; there is no Android
  WebRTC source. Must be confirmed against the exact `io.github.webrtc-sdk:android`
  version AND-288 pins. Risk: minor API drift between WebRTC SDK builds (e.g.,
  `init` overloads, sink-attachment surface).
- **Compose `AndroidView(onRelease = ...)` and `LocalInspectionMode`:** standard
  Jetpack Compose APIs but version-dependent; not repo-verifiable. Confirm
  against the project's Compose BOM.
- **AND-288 EglBase/VideoTrack lifecycle and permission gating:** a cross-ticket
  contract, not verified here; depends on AND-288 landing as described.
- **`@Preview`/`LocalInspectionMode` placeholder behavior on a real device:**
  cannot be exercised until consumers (E39) wire real tracks; verified only at
  the composable boundary.

## 17. Test Plan

Test target legend: **JVM** = local JVM unit/Robolectric (no device);
**emu35** = headless AVD `test35`, x86_64, Android 15 / API 35 (CI fast lane);
**deviceA15** = physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R),
Android 14 / API 34, arm64-v8a. Anything that paints real WebRTC frames, decodes
hardware video, or depends on OEM SurfaceView/EGL behavior MUST run on
**deviceA15** (the headless x86 emulator does not faithfully reproduce
arm64 hardware decode/SurfaceView compositing or first-frame timing).

- **TC-AND-293-01 — Scaling enum → ScalingType mapping (happy path).**
  Type: unit. Target: JVM.
  Preconditions: `VideoScaling.toFitType()/toFillType()` extracted as pure
  functions.
  Steps: call both helpers for `FIT` and `FILL`.
  Expected: `FIT` → (`SCALE_ASPECT_FIT`, `SCALE_ASPECT_FIT`); `FILL` →
  (`SCALE_ASPECT_BALANCED`, `SCALE_ASPECT_FILL`), matching §4 / Citation 7.
  Traces: AC-3.

- **TC-AND-293-02 — Track-swap decision logic.**
  Type: unit. Target: JVM.
  Preconditions: attach decision extracted to `shouldSwap(current, next)` using
  reference identity.
  Steps: assert `shouldSwap(a, a)==false`, `shouldSwap(a, b)==true`,
  `shouldSwap(a, null)==true`, `shouldSwap(null, b)==true`.
  Expected: identity-based swap detection matches §6 identity contract.
  Traces: AC-4, AC-5.

- **TC-AND-293-03 — Renders and attaches sink exactly once (happy path).**
  Type: contract/MockWebServer-style with mocked WebRTC (MockK; no actual
  MockWebServer — no HTTP). Target: JVM (Robolectric) / emu35.
  Preconditions: fake `EglBase.Context`, mocked `VideoTrack` and
  `SurfaceViewRenderer`.
  Steps: compose `VideoRenderer(track, eglContext)`; let it settle.
  Expected: `init(eglContext, …)` called once; `track.addSink(view)` called
  exactly once; no `removeSink`.
  Traces: AC-4.

- **TC-AND-293-04 — Track swap A→B reattaches without re-init.**
  Type: Compose-UI. Target: JVM (Robolectric) / emu35.
  Preconditions: as TC-03, two mocked tracks A and B.
  Steps: compose with A, then recompose with B.
  Expected: `A.removeSink(view)` ×1, `B.addSink(view)` ×1, `init` NOT called a
  second time, `release` not called.
  Traces: AC-5.

- **TC-AND-293-05 — Null track shows placeholder and removes sink.**
  Type: Compose-UI. Target: JVM (Robolectric) / emu35.
  Preconditions: mocked track A attached, placeholder tagged with
  `contentDescription`/test tag.
  Steps: compose with A, then recompose with `track = null`.
  Expected: `A.removeSink(view)` called; placeholder node asserted present via
  `onNodeWithContentDescription(...)`; no crash; no `addSink(null)`.
  Traces: AC-4.

- **TC-AND-293-06 — mirror & scaling change in place (no recreation).**
  Type: Compose-UI. Target: JVM (Robolectric) / emu35.
  Preconditions: mocked renderer.
  Steps: compose with `mirror=true, scaling=FILL`; recompose with
  `mirror=false, scaling=FIT`.
  Expected: `setMirror(false)` and `setScalingType(SCALE_ASPECT_FIT,
  SCALE_ASPECT_FIT)` invoked; `init` NOT called again; no `release`.
  Traces: AC-2, AC-3.

- **TC-AND-293-07 — Dispose releases renderer and sink exactly once.**
  Type: Compose-UI. Target: JVM (Robolectric) / emu35.
  Preconditions: mocked track A attached.
  Steps: place the composable behind a toggle; remove it from composition.
  Expected: `A.removeSink(view)` ×1 then `view.release()` ×1; handle nulled; a
  subsequent disposal does not double-`release` (idempotency per §7).
  Traces: AC-6.

- **TC-AND-293-08 — LocalInspectionMode renders placeholder, never inits.**
  Type: Compose-UI. Target: JVM (Robolectric).
  Preconditions: wrap composable in `CompositionLocalProvider(LocalInspectionMode
  provides true)`.
  Steps: compose `VideoRenderer`/`LocalVideoRenderer`/`RemoteVideoRenderer`.
  Expected: placeholder node present; `init` and `addSink` never called.
  Traces: AC-8.

- **TC-AND-293-09 — init() failure is non-crashy.**
  Type: Compose-UI. Target: JVM (Robolectric).
  Preconditions: mocked `SurfaceViewRenderer.init` throws (bad EGL).
  Steps: compose with a non-null track.
  Expected: exception caught and logged at ERROR (tag `WebRtcRenderer`);
  placeholder remains; renderer handle stays null; `addSink` never called; no
  app crash (§7).
  Traces: AC-4, AC-8.

- **TC-AND-293-10 — Accessibility: content descriptions present.**
  Type: Compose-UI (a11y assertions). Target: emu35.
  Preconditions: default strings `R.string.video_local_preview` /
  `R.string.video_remote_feed`.
  Steps: compose local and remote renderers; query semantics tree.
  Expected: hosting `Box` exposes the localized `contentDescription`; placeholder
  text resolves from `strings.xml` (no hardcoded literals); mirroring does not
  alter semantics order (§9). Optionally run with TalkBack on deviceA15 to
  confirm the label is announced once and frame content is not.
  Traces: AC-2, AC-4 (and §9 a11y).

- **TC-AND-293-11 — Real remote + local frames render on hardware (happy path).**
  Type: instrumented/e2e (loopback). **Target: deviceA15 (MUST).**
  Preconditions: AND-288 loopback sample provides a real local-capturer
  `VideoTrack` and a shared `EglBase.Context`; camera permission granted.
  Steps: wire the capturer track into both `LocalVideoRenderer` and
  `RemoteVideoRenderer`; observe for ≥3 s.
  Expected: both surfaces paint live frames; `onFirstFrameRendered` fires; local
  is mirrored, remote is not; no black surface. (Emulator's synthetic camera and
  x86 decode do not validate real arm64 hardware compositing — hence physical
  device.)
  Traces: AC-1, AC-2.

- **TC-AND-293-12 — FIT letterboxes vs FILL crops on hardware.**
  Type: instrumented/manual (visual). **Target: deviceA15 (MUST).**
  Preconditions: loopback track with a known aspect ratio (e.g., 16:9) into a
  non-matching container (e.g., square/portrait).
  Steps: toggle `scaling` between `FIT` and `FILL`.
  Expected: `FIT` shows letterbox bars (no crop); `FILL` fills the container
  (cropped), visually matching the web `object-cover` behavior. Note BALANCED vs
  FILL caveat from §13-R4.
  Traces: AC-3.

- **TC-AND-293-13 — Rotation & dark-mode keep painting (no black frame).**
  Type: instrumented/e2e. **Target: deviceA15 (MUST).**
  Preconditions: loopback rendering active.
  Steps: rotate device portrait↔landscape several times; toggle system dark mode.
  Expected: video continues painting after each config change with no persistent
  black frame; surface is re-created and re-attached cleanly (§4/§7). Real OEM
  SurfaceView config-change behavior is not reproduced on the headless emulator.
  Traces: AC-7.

- **TC-AND-293-14 — No SurfaceViewRenderer/EGL leak across navigate in/out.**
  Type: instrumented/e2e with LeakCanary. Target: deviceA15 (preferred) or
  emu35.
  Preconditions: LeakCanary enabled in the debug loopback app.
  Steps: navigate into the renderer screen and back out 5–10 times.
  Expected: LeakCanary reports no retained `SurfaceViewRenderer`/`EglRenderer`;
  the shared `EglBase` is NOT released by the composable (§6/§8).
  Traces: AC-6.

- **TC-AND-293-15 — Local-preview privacy: frames stop off-screen.**
  Type: instrumented (security/privacy). **Target: deviceA15 (MUST).**
  Preconditions: `LocalVideoRenderer` active on the camera.
  Steps: navigate away / background the app; verify the renderer left
  composition.
  Steps (verify): assert `removeSink` was invoked so the view stops consuming
  frames (camera capture stop itself is AND-288's responsibility); on-device,
  confirm no preview is painted off-screen.
  Expected: sink removed promptly on leave; no off-screen frame painting (§8).
  Traces: AC-6 (and §8 privacy).

### Coverage matrix

| AC (§14) | Covered by |
| --- | --- |
| AC-1 (remote + local paint on device) | TC-11 |
| AC-2 (local mirrored by default; in-place mirror toggle) | TC-06, TC-10, TC-11 |
| AC-3 (FIT letterbox / FILL crop; ScalingType mapping) | TC-01, TC-06, TC-12 |
| AC-4 (null→track / track→null add/remove sink; placeholder) | TC-02, TC-03, TC-05, TC-09, TC-10 |
| AC-5 (swap A→B, no second init) | TC-02, TC-04 |
| AC-6 (release + sink removed once; no leak) | TC-07, TC-14, TC-15 |
| AC-7 (rotation/dark-mode keep painting) | TC-13 |
| AC-8 (LocalInspectionMode renders placeholder, never inits) | TC-08, TC-09 |
