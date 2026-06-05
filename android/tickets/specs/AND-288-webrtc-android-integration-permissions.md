---
id: AND-288
title: webrtc-android integration + permissions
milestone: M7
epic: E39
priority: P0
size: M
status: draft
depends_on: [AND-004]
blocks: [AND-289, AND-290, AND-291, AND-294]
---

# AND-288 — webrtc-android integration + permissions

## 1. Overview & Goal

This ticket establishes the WebRTC foundation for the TestLogon native Android port. It introduces a new `core-webrtc` Gradle module that depends on and wraps the `webrtc-android` artifact (the `io.getstream:stream-webrtc-android` distribution of the Google libwebrtc binaries), wires the dependency into the build via the version catalog, declares and requests the camera/microphone runtime permissions, and proves the integration end-to-end with a **local loopback** sample screen that captures the front camera and renders it to an `org.webrtc.SurfaceViewRenderer` via a self-connected pair of `PeerConnection`s.

The goal is strictly **infrastructure and proof-of-link**. No signaling, no backend calls, no remote peer, no TURN/STUN. The deliverable is: the native libraries link and load at runtime on `arm64-v8a`/`armeabi-v7a`/`x86_64`; the `PeerConnectionFactory` initializes once without crashing; camera and mic permissions are requested through a reusable Compose flow; and a developer-only loopback sample shows live local video. Everything downstream (`AND-289` PeerConnection wrapper/lifecycle, `AND-290` signaling transport, `AND-291` TURN/STUN, `AND-294` foundation tests) builds on the module skeleton, the permission API, and the `EglBase`/`PeerConnectionFactory` provisioning defined here.

Success means a clean `:app:assembleDebug`, the loopback sample rendering on a physical device, and the camera/mic permission UX behaving correctly across grant, deny, and permanent-deny paths.

## 2. Context & References

- **Repo / branch:** `spannella/testlogon`, Android app under `android/`, branch `android-port`.
- **Namespace:** all packages under `com.testlogon.android`. This module is `com.testlogon.android.core.webrtc`.
- **Module layering:** `app -> feature-* -> core-*`. This adds `core-webrtc` at the `core-*` tier. It depends on `core-ui` (theming, permission scaffolding helpers) and `core-model` only; it must **not** depend on `core-network` (no signaling here).
- **Stack baseline:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow, minSdk 24, compileSdk/targetSdk 35, JDK 17, Gradle 8.9, AGP 8.7.3.
- **DI baseline:** AND-004 provides `@HiltAndroidApp` and the component graph; this module contributes a `@Module @InstallIn(SingletonComponent::class)` for the `EglBase` and `PeerConnectionFactory`.
- **WebRTC artifact:** `io.getstream:stream-webrtc-android` (Stream's maintained packaging of upstream libwebrtc; chosen over the unmaintained `org.webrtc:google-webrtc` which is removed from Maven and lacks 16KB-page / recent NDK builds). Pin to a fixed version (proposed `1.3.8`) in the catalog.
- **Downstream owners:** `AND-289` owns the production `PeerConnection` wrapper and lifecycle; the loopback in this ticket is a throwaway sample, not that wrapper. `AND-290` owns `/signal` transport. `AND-291` owns ICE/TURN config.
- **No backend interaction** in this ticket; the dev FastAPI host is irrelevant here.

## 3. Functional Requirements

FR-1. A new Gradle module `core-webrtc` exists, applies the shared Android-library + Hilt convention plugins, and compiles independently.

FR-2. The `stream-webrtc-android` dependency is declared in `gradle/libs.versions.toml` and consumed by `core-webrtc` via `api(libs.webrtc.android)` (exported as `api` so downstream `feature-*` modules see `org.webrtc.*` types).

FR-3. `PeerConnectionFactory.initialize(...)` is invoked exactly once per process, before any factory/`EglBase` use, guarded against double-init.

FR-4. A single shared `EglBase` and a single `PeerConnectionFactory` are provided as Hilt `@Singleton`s.

FR-5. A reusable permission API requests `CAMERA` and `RECORD_AUDIO` at runtime. It exposes current state (granted / denied / permanently denied) as observable state and a `request()` trigger, usable from any feature.

FR-6. A developer-only loopback sample (`WebRtcLoopbackScreen`) is reachable behind a debug nav entry. After permissions are granted it:
  - creates a `VideoCapturer` (front `Camera2Enumerator` device),
  - produces a local `VideoTrack` and `AudioTrack`,
  - establishes a loopback by connecting two local `PeerConnection`s (offer/answer/ICE entirely in-process, no network),
  - renders the received remote video track into a `SurfaceViewRenderer`.

FR-7. When permission is denied, the sample shows a rationale + a "request again" affordance; when permanently denied, it shows a deep-link to app Settings.

FR-8. All native resources (capturer, tracks, peer connections, renderer, `EglBase`) are released on screen disposal; no leaked surfaces or capturer threads.

FR-9. The sample must not be present in `release` builds (gated by `BuildConfig.DEBUG` and/or a debug-only nav graph), to avoid shipping camera-capturing dead code.

## 4. Technical Design

### 4.1 Module & build wiring

`android/core-webrtc/build.gradle.kts`:

```kotlin
plugins {
    alias(libs.plugins.testlogon.android.library)
    alias(libs.plugins.testlogon.android.hilt)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "com.testlogon.android.core.webrtc"
}

dependencies {
    api(libs.webrtc.android)            // exports org.webrtc.* to consumers
    implementation(projects.coreUi)
    implementation(projects.coreModel)
    implementation(libs.androidx.activity.compose)   // permission launcher
    androidTestImplementation(projects.coreTesting)
}
```

`gradle/libs.versions.toml` additions:

```toml
[versions]
webrtcAndroid = "1.3.8"

[libraries]
webrtc-android = { group = "io.getstream", name = "stream-webrtc-android", version.ref = "webrtcAndroid" }
```

`settings.gradle.kts`: add `include(":core-webrtc")`.

The library bundles `.so` files for `arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`. No `abiFilters` restriction is required for debug; the app's existing splits config governs release. JNI symbols load lazily on first `PeerConnectionFactory` use, so a successful `assembleDebug` is necessary but not sufficient — runtime init on-device is the real link test (covered in §11).

### 4.2 Factory initialization & DI

```kotlin
@Module
@InstallIn(SingletonComponent::class)
object WebRtcModule {

    @Provides @Singleton
    fun provideEglBase(): EglBase = EglBase.create()

    @Provides @Singleton
    fun provideRootEglContext(eglBase: EglBase): EglBase.Context =
        eglBase.eglBaseContext

    @Provides @Singleton
    fun providePeerConnectionFactory(
        @ApplicationContext context: Context,
        eglContext: EglBase.Context,
    ): PeerConnectionFactory {
        PeerConnectionFactoryInitializer.ensureInitialized(context)
        val encoder = DefaultVideoEncoderFactory(eglContext, true, true)
        val decoder = DefaultVideoDecoderFactory(eglContext)
        return PeerConnectionFactory.builder()
            .setVideoEncoderFactory(encoder)
            .setVideoDecoderFactory(decoder)
            .createPeerConnectionFactory()
    }
}

internal object PeerConnectionFactoryInitializer {
    @Volatile private var initialized = false
    fun ensureInitialized(context: Context) {
        if (initialized) return
        synchronized(this) {
            if (initialized) return
            PeerConnectionFactory.initialize(
                PeerConnectionFactory.InitializationOptions
                    .builder(context.applicationContext)
                    .setEnableInternalTracer(false)
                    .createInitializationOptions()
            )
            initialized = true
        }
    }
}
```

`EglBase`/`PeerConnectionFactory` are heavyweight, hold native handles, and must be singletons; per the upstream contract `initialize()` must precede any factory construction and must run once per process — hence the double-checked guard.

### 4.3 Permission API

```kotlin
enum class PermissionStatus { GRANTED, DENIED, PERMANENTLY_DENIED, NOT_REQUESTED }

data class AvPermissionsState(
    val camera: PermissionStatus,
    val microphone: PermissionStatus,
) {
    val allGranted: Boolean get() =
        camera == PermissionStatus.GRANTED && microphone == PermissionStatus.GRANTED
}

@Composable
fun rememberAvPermissionsController(): AvPermissionsController
```

`AvPermissionsController` exposes `state: State<AvPermissionsState>` and `fun request()`. Internally it wraps `rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions())` for `Manifest.permission.CAMERA` and `Manifest.permission.RECORD_AUDIO`. After a denial it inspects `Activity.shouldShowRequestPermissionRationale(...)`: `false` after a denial that was actually delivered ⇒ `PERMANENTLY_DENIED`. A `fun openAppSettings()` helper launches `Settings.ACTION_APPLICATION_DETAILS_SETTINGS` for the permanently-denied path. State refreshes on `ON_RESUME` (covers the user toggling permission in Settings and returning).

### 4.4 Loopback sample

```kotlin
@Composable
fun WebRtcLoopbackScreen(viewModel: WebRtcLoopbackViewModel = hiltViewModel())

@HiltViewModel
class WebRtcLoopbackViewModel @Inject constructor(
    private val factory: PeerConnectionFactory,
    private val eglBase: EglBase,
    @ApplicationContext private val context: Context,
) : ViewModel() {
    val uiState: StateFlow<LoopbackUiState>
    fun start(localRenderer: SurfaceViewRenderer, remoteRenderer: SurfaceViewRenderer)
    fun stop()
    override fun onCleared()  // releases all native resources
}

sealed interface LoopbackUiState {
    data object Idle : LoopbackUiState
    data object AwaitingPermission : LoopbackUiState
    data object Connecting : LoopbackUiState
    data object Rendering : LoopbackUiState
    data class Failed(val message: String) : LoopbackUiState
}
```

Loopback mechanics: create `pcLocal` and `pcRemote`, both with empty `iceServers` and `sdpSemantics = UNIFIED_PLAN`. Cross-wire their `onIceCandidate` callbacks (each adds the other's candidate directly — no network). `pcLocal.addTrack(localVideoTrack)` and the audio track; perform `createOffer` on `pcLocal` → `setLocalDescription` → `pcRemote.setRemoteDescription` → `createAnswer` → back. `pcRemote.onAddTrack` yields the remote `VideoTrack`, which is `addSink(remoteRenderer)`. The local preview attaches the captured track's sink to `localRenderer`. Renderers are `init(eglBase.eglBaseContext, null)`.

Compose hosts the two renderers via `AndroidView { SurfaceViewRenderer(it) }`; `DisposableEffect` calls `release()` on each renderer and `viewModel.stop()` on dispose.

### 4.5 Manifest

`core-webrtc/src/main/AndroidManifest.xml` (merged into app):

```xml
<uses-permission android:name="android.permission.CAMERA" />
<uses-permission android:name="android.permission.RECORD_AUDIO" />
<uses-permission android:name="android.permission.MODIFY_AUDIO_SETTINGS" />
<uses-feature android:name="android.hardware.camera" android:required="false" />
<uses-feature android:name="android.hardware.microphone" android:required="false" />
```

`required="false"` keeps Play Store availability broad; the app degrades gracefully where hardware is absent (handled downstream, but the flag is set here).

## 5. API Contract

**Not applicable — no backend interaction in this ticket.** This is a build-wiring + native-integration + permissions ticket with a purely in-process loopback. There are no HTTP requests, no JSON shapes, and no cookie/CSRF/auth involvement. The first network contract in this epic is the signaling transport over `/signal` (SSE/poll for remote SDP/ICE), owned by **AND-290**; ICE server/TURN credential fetch (`turn-credentials`) is owned by **AND-291**. The only "contracts" this ticket defines are the in-process Kotlin/JNI surfaces in §4 (`WebRtcModule` providers, `AvPermissionsController`, `WebRtcLoopbackViewModel`).

## 6. Data & State Management

- **No persistence.** Nothing is written to Room or DataStore. WebRTC objects are transient native handles owned by the `SingletonComponent` (factory, `EglBase`) or by the loopback `ViewModel` (capturer, tracks, peer connections).
- **UI state:** `WebRtcLoopbackViewModel` exposes `StateFlow<LoopbackUiState>` per the project's StateFlow<UiState> convention. Permission state is exposed as Compose `State<AvPermissionsState>` from `AvPermissionsController` (UI-scoped, recomputed on resume — not stored).
- **Lifecycle ownership:**
  - Process-scoped singletons (`EglBase`, `PeerConnectionFactory`) are never released during the app lifetime by design; they are created lazily on first injection.
  - Screen-scoped resources (`VideoCapturer`, `SurfaceTextureHelper`, `VideoSource`/`AudioSource`, tracks, both `PeerConnection`s, both `SurfaceViewRenderer`s) are created in `start()` and released in `stop()`/`onCleared()`. Release order: stop capture → `dispose()` tracks/sources → `close()`/`dispose()` peer connections → `release()` renderers → quit `SurfaceTextureHelper`.
- **Threading:** all `PeerConnection` and capturer calls are funneled through the factory's signaling thread or a single dedicated `SurfaceTextureHelper` thread; UI state transitions are posted back via `viewModelScope` on `Dispatchers.Main`.

## 7. Error Handling & Resilience

- **Native load failure:** if `PeerConnectionFactory.initialize` or factory construction throws (e.g., `UnsatisfiedLinkError` from a missing ABI), the loopback `start()` catches it and emits `LoopbackUiState.Failed("WebRTC native libraries failed to load")`; the error is logged with the thrown message. This is the runtime link assertion.
- **No camera available:** `Camera2Enumerator.deviceNames` empty or no front device ⇒ `Failed("No camera available")`. Capturer `onCameraError`/`onCameraDisconnected` callbacks transition to `Failed` with the underlying reason.
- **Permission denied / permanently denied:** never crash. Denied ⇒ rationale UI with retry; permanently denied ⇒ Settings deep-link. `start()` is a no-op (emits `AwaitingPermission`) until `allGranted`.
- **SDP/ICE failure in loopback:** any `onCreateFailure`/`onSetFailure` from the in-process negotiation ⇒ `Failed(message)`; resources still released cleanly.
- **No retries/backoff** apply — there is no network. (The bounded-backoff-for-idempotent-GETs policy is a network concern that begins at AND-290.)
- **Resilience guarantee:** repeated `start()/stop()` cycles and navigating away mid-negotiation must not leak threads or surfaces; verified by the lifecycle instrumentation test in §11.

## 8. Security & Privacy

- **Sensitive permissions:** `CAMERA` and `RECORD_AUDIO` are runtime "dangerous" permissions. They are requested only when the user actively opens the loopback sample (in-context request), never at launch. Rationale is shown before re-request after a denial.
- **No capture without consent:** the capturer is created only after both permissions are `GRANTED`; on revocation-and-return the screen tears down capture.
- **No data egress:** loopback media never leaves the device; no recording, no file writes, no upload. There is no PII handling and no auth/cookie surface in this ticket.
- **Tracing disabled:** `setEnableInternalTracer(false)` — no WebRTC internal trace files written.
- **Release hygiene:** the sample screen and its debug nav entry are excluded from `release` builds so production binaries contain no developer camera-capture path.
- **ProGuard/R8:** add keep rules for `-keep class org.webrtc.** { *; }` (JNI-reflected classes) to `core-webrtc/consumer-rules.pro` to prevent stripping that would surface as runtime `NoSuchMethodError` in release.

## 9. Accessibility & i18n

- The loopback is a **developer-only** debug surface; it is not user-facing and exempt from full localization. However, the **reusable permission UI** (`AvPermissionsController` rationale text, Settings prompt, button labels) is user-facing infrastructure and must be production-quality:
  - All strings in `core-webrtc/src/main/res/values/strings.xml` (e.g., `webrtc_perm_rationale`, `webrtc_perm_settings`, `webrtc_perm_grant`); no hardcoded text.
  - `SurfaceViewRenderer` `AndroidView`s carry `contentDescription` ("Local camera preview" / "Remote loopback video") and respect TalkBack focus order.
  - Touch targets (grant / open-settings buttons) ≥ 48dp; Material 3 dynamic color and text scaling honored.
  - Rationale and error text meet WCAG AA contrast under the app theme.

## 10. Telemetry & Logging

- **Logging only** (no analytics backend in scope). Use the project logging facade tagged `WebRtcLoopback` / `WebRtc`:
  - INFO once on first factory init: ABI (`Build.SUPPORTED_ABIS[0]`), webrtc-android version, `EglBase` created.
  - DEBUG on loopback state transitions (`Idle→AwaitingPermission→Connecting→Rendering`) and ICE connection state changes.
  - WARN on permission denial / permanent denial (no PII, just the status enum).
  - ERROR on native load failure, camera error, SDP/ICE failure (with throwable).
- **Debug-only verbosity:** WebRTC's own `Logging.enableLogToDebugOutput(Logging.Severity.LS_WARNING)` enabled only when `BuildConfig.DEBUG`.
- No media frames, no images, and no permission-prompt content are ever logged. Structured analytics events for real calls are deferred to the call-feature tickets, not this foundation ticket.

## 11. Testing Strategy

**Unit (JVM, `core-testing`):**
- `PermissionStatusMapperTest`: maps (granted bool, shouldShowRationale bool, wasRequested bool) → correct `PermissionStatus`, including the permanently-denied case.
- `AvPermissionsStateTest`: `allGranted` logic across the matrix.
- `PeerConnectionFactoryInitializerTest`: `ensureInitialized` is idempotent / thread-safe (initialize invoked once under concurrent callers, using a mocked static).

**Instrumentation (androidTest, physical/AVD with camera):**
- `WebRtcLinkTest`: injects `PeerConnectionFactory` via a Hilt test component and asserts non-null construction — this is the authoritative **"library links"** assertion (exercises JNI load on the test device's ABI).
- `LoopbackRenderTest`: grants `CAMERA`/`RECORD_AUDIO` via `GrantPermissionRule`, launches `WebRtcLoopbackScreen`, drives `start()`, and asserts `uiState` reaches `Rendering` within a timeout and the remote renderer receives ≥1 frame (frame-listener counter) — the **"sample loopback renders"** assertion.
- `LoopbackLifecycleTest`: start→stop→start and recreate the activity; assert no thread/surface leak (capturer thread count returns to baseline; no `EglBase` re-init crash).

**Manual QA checklist:** fresh install → open sample → grant prompt appears (in-context) → live preview; deny → rationale + retry; deny permanently → Settings deep-link → return → preview works. Verify on `arm64-v8a` and `x86_64`.

**Acceptance mapping:** "Library links" ⇒ `WebRtcLinkTest`; "permissions requested" ⇒ permission unit tests + manual prompt verification; "sample loopback renders" ⇒ `LoopbackRenderTest`.

Foundation/lifecycle tests for the *production* wrapper and signaling are owned by **AND-294** (mocked transport); this ticket only proves the integration.

## 12. Dependencies & Sequencing

- **Depends on:** **AND-004** (Hilt DI baseline) — required so `WebRtcModule` can install into `SingletonComponent` and the loopback `ViewModel` is `@HiltViewModel`. Implicitly relies on the module/convention-plugin scaffolding from the M1 setup tickets (consumed via the shared `testlogon.android.library`/`testlogon.android.hilt` plugins).
- **Blocks (consumers of this foundation):**
  - **AND-289** — PeerConnection wrapper + lifecycle (uses the shared `PeerConnectionFactory`/`EglBase` and replaces the throwaway loopback with the production wrapper).
  - **AND-290** — Signaling transport over `/signal` (adds the network layer the loopback deliberately omits).
  - **AND-291** — TURN/STUN credentials (configures real `iceServers`).
  - **AND-294** — WebRTC foundation tests (mocked-transport signaling/lifecycle).
- **Sequencing note:** keep the loopback sample isolated in a debug source set / debug nav graph so AND-289 can delete it without touching the singleton providers or permission API, which are the durable artifacts.

## 13. Risks & Open Questions

- **R1 — Artifact choice/availability:** `org.webrtc:google-webrtc` is unmaintained and unpublished on Maven Central. **Decision:** use `io.getstream:stream-webrtc-android`. Open question: confirm the exact latest stable version at implementation time (catalog placeholder `1.3.8`) and that it ships 16KB-page-aligned `.so` files for targetSdk 35.
- **R2 — APK size / ABI bloat:** native `.so`s add several MB per ABI. Mitigation: rely on the app's existing ABI splits / App Bundle for release; do not blanket-bundle `x86` in release.
- **R3 — Permanent-denial detection edge cases:** `shouldShowRequestPermissionRationale` heuristics differ across OEMs/API levels; mitigate with the resume-time re-check and the always-available Settings deep-link.
- **R4 — Emulator camera:** AVDs may lack a usable front camera, making `LoopbackRenderTest` flaky in CI. Mitigation: run render test on a device farm / mark as `@RequiresDevice`, keep the link test (no camera needed beyond factory init) as the CI gate.
- **R5 — Native init threading:** double-init or init-after-use crashes the process. Mitigated by the `PeerConnectionFactoryInitializer` guard; verified by unit test.
- **Open question:** should `MODIFY_AUDIO_SETTINGS` and audio-mode management live here or in a later call-audio ticket? Proposed: declare the permission here, defer `AudioManager` mode handling to the call feature.

## 14. Acceptance Criteria

1. `:app:assembleDebug` and `:core-webrtc:assembleDebug` succeed with the `webrtc-android` dependency declared in `libs.versions.toml` and consumed via `api(libs.webrtc.android)`. (Backlog: "Library links" — build half.)
2. On a physical device, injecting `PeerConnectionFactory` constructs successfully (no `UnsatisfiedLinkError`); `WebRtcLinkTest` passes on `arm64-v8a` and `x86_64`. (Backlog: "Library links" — runtime half.)
3. Opening the loopback sample without prior grant triggers the runtime permission prompt for `CAMERA` and `RECORD_AUDIO` in-context (not at app launch). (Backlog: "permissions requested".)
4. Denying shows rationale + retry; permanently denying shows a working Settings deep-link; returning from Settings with permission granted reaches the rendering state without restart. (Backlog: "permissions requested".)
5. With permissions granted, the loopback sample reaches `LoopbackUiState.Rendering` and live local video is visible in the remote renderer (≥1 frame delivered); `LoopbackRenderTest` passes. (Backlog: "sample loopback renders".)
6. Navigating away / stopping releases all native resources with no leaked capturer threads or surfaces; `LoopbackLifecycleTest` passes.
7. The loopback sample and its nav entry are absent from `release` builds.
8. No network calls occur during loopback (verifiable via no Retrofit/OkHttp usage in `core-webrtc` and no traffic on the wire).

## 15. Definition of Done

- `core-webrtc` module created, included in `settings.gradle.kts`, applies the shared convention plugins, namespace `com.testlogon.android.core.webrtc`.
- `webrtc-android` pinned in the version catalog and exported via `api`; consumer ProGuard keep rules for `org.webrtc.**` added.
- `WebRtcModule` provides singleton `EglBase` and `PeerConnectionFactory` with the idempotent initializer guard.
- `AvPermissionsController` + `rememberAvPermissionsController()` implemented with grant/deny/permanent-deny handling, Settings deep-link, resume re-check, and externalized strings.
- Debug-only `WebRtcLoopbackScreen` + `WebRtcLoopbackViewModel` implemented with full resource teardown.
- Manifest declares `CAMERA`, `RECORD_AUDIO`, `MODIFY_AUDIO_SETTINGS` and optional `uses-feature` hardware flags.
- Unit tests (permission mapping, initializer idempotency) and instrumentation tests (`WebRtcLinkTest`, `LoopbackRenderTest`, `LoopbackLifecycleTest`) implemented and green; render/lifecycle tests gated to device-capable runners.
- Logging facade wired with the specified levels; WebRTC internal tracing disabled; debug-only WebRTC logging.
- All acceptance criteria in §14 verified; code reviewed and merged to `android-port`; CI `assembleDebug` + unit tests pass; no new R8/lint regressions.
