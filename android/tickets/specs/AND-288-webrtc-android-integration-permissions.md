---
id: AND-288
title: webrtc-android integration + permissions
milestone: M7
epic: E39
priority: P0
size: M
depends_on: [AND-004]
blocks: [AND-289, AND-290, AND-291, AND-294]
status: reviewed
reviewed_on: 2026-06-06
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
- **Downstream owners:** `AND-289` owns the production `PeerConnection` wrapper and lifecycle; the loopback in this ticket is a throwaway sample, not that wrapper. `AND-290` owns the signaling transport — the web client SENDS SDP/ICE via `POST /messaging/messages/calls/{call_id}/signal` and RECEIVES peer signaling over the messaging SSE stream (event `messaging:webrtc-signal`), so it is not a single bidirectional `/signal` channel. `AND-291` owns ICE/TURN config, fetched via `POST /messaging/messages/calls/{call_id}/turn-credentials` (verified — see §16). These downstream paths are documented here only for context; none are called by this ticket.
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

**Not applicable — no backend interaction in this ticket.** This is a build-wiring + native-integration + permissions ticket with a purely in-process loopback. There are no HTTP requests, no JSON shapes, and no cookie/CSRF/auth involvement. The first network contract in this epic is the signaling transport, owned by **AND-290**: outbound SDP/ICE is `POST /messaging/messages/calls/{call_id}/signal` (request `CallSignalingIn`, success `CallSignalingOut`/`SignalingAck`), and inbound peer signaling arrives over the messaging SSE stream (not poll); ICE server/TURN credential fetch is `POST /messaging/messages/calls/{call_id}/turn-credentials` (note: POST, not GET; empty body; response `TurnCredentialsOut` → `{ ttl_seconds, expires_at, ice_servers[] }`), owned by **AND-291**. Both require `Authorization: Bearer` + `X-SESSION-ID` (and, in the web client, an `X-CSRF-Token` from the `ui_csrf` cookie with `credentials: include`). The only "contracts" this ticket defines are the in-process Kotlin/JNI surfaces in §4 (`WebRtcModule` providers, `AvPermissionsController`, `WebRtcLoopbackViewModel`).

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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. "framework ref" marks Android/library documentation choices that are not in the backend/frontend sources.

1. **Claim:** This ticket makes no backend HTTP calls; the first network contract in the epic belongs to AND-290/AND-291. **VERDICT: Verified.** No WebRTC/signaling endpoint is invoked by build-wiring/permissions code. The only related endpoints in the API surface are the messaging call endpoints below, which are out of scope here. Source: OpenAPI index has no generic `/signal` or `/webrtc` foundation endpoint; only `POST /messaging/messages/calls/{call_id}/signal` and `POST /messaging/messages/calls/{call_id}/turn-credentials` exist, both consumed only by call features (`src/hooks/useRtcPeerConnection.ts`).

2. **Claim (corrected):** Downstream signaling is "`/signal` transport (SSE/poll for remote SDP/ICE)". **VERDICT: Corrected.** Outbound signaling is `POST /messaging/messages/calls/{call_id}/signal`; inbound peer signaling is delivered over the messaging SSE stream (custom event `messaging:webrtc-signal`), not a poll and not the same `/signal` URL. Source: OpenAPI `POST /messaging/messages/calls/{call_id}/signal` (op=send_signaling_event...; req=`CallSignalingIn`; resp=200:`CallSignalingOut`); `src/api/endpoints/messaging.ts: sendSignalingEvent` (line 1043, `POST /messaging/messages/calls/${callId}/signal`); `src/hooks/useRtcPeerConnection.ts` (window event `messaging:webrtc-signal`, line ~355).

3. **Claim (corrected):** TURN/ICE credentials fetched via "`turn-credentials`" (method unspecified, implied GET). **VERDICT: Corrected.** It is a **POST with an empty body**: `POST /messaging/messages/calls/{call_id}/turn-credentials`. Source: OpenAPI `POST /messaging/messages/calls/{call_id}/turn-credentials` (op=issue_turn_credentials_endpoint...; resp=200:`TurnCredentialsOut`); `src/api/endpoints/messaging.ts: fetchTurnCredentials` (line 1065, `api.post(... , {})`).

4. **Claim:** TURN response shape used downstream by AND-291. **VERDICT: Verified.** `TurnCredentialsResp = { ttl_seconds: number; expires_at: number; ice_servers: TurnIceServer[] }`, where `TurnIceServer = { urls: string[]; username: string; credential: string }`. Source: `src/api/types.ts`/`src/api/endpoints/messaging.ts: TurnCredentialsResp, TurnIceServer` (lines 1053–1063); OpenAPI schema `TurnCredentialsOut`.

5. **Claim:** Signaling/TURN endpoints require auth (relevant to downstream AND-290/291 context, not this ticket). **VERDICT: Verified.** Both require `authorization` and `X-SESSION-ID` params; the web transport also attaches `X-CSRF-Token` from the `ui_csrf` cookie and sends `credentials: "include"`. Source: OpenAPI index `params=call_id,authorization,X-SESSION-ID` for both endpoints; `src/api/client.ts` (Authorization Bearer line 158–159, `X-CSRF-Token` from `ui_csrf` line 168–170, `credentials: "include"` line 124/183/220).

6. **Claim:** The web client negotiates with **unified-plan** SDP semantics; the loopback should set `sdpSemantics = UNIFIED_PLAN`. **VERDICT: Verified (web) / framework ref (Android).** Web uses unified-plan (browser default, noted explicitly). Source: `src/hooks/useRtcPeerConnection.ts` line ~139 ("Use unified-plan (default in modern browsers)"). Android equivalent `PeerConnection.RTCConfiguration.sdpSemantics = UNIFIED_PLAN`: framework ref (org.webrtc API).

7. **Claim:** ICE candidates must be buffered until the remote description is set, then flushed. **VERDICT: Verified.** The web client implements an explicit ICE candidate buffer flushed after `setRemoteDescription`. The loopback's in-process cross-wiring must preserve this ordering. Source: `src/lib/webrtc.ts: createIceCandidateBuffer` (lines 106–135); `src/hooks/useRtcPeerConnection.ts` `iceBuffer.flush(pc)` after `setRemoteDescription` (lines 296–297, 327).

8. **Claim:** `getUserMedia` permission-denied surfaces as a distinct error the UI must handle (parallels Android runtime-permission deny). **VERDICT: Verified (web analogue).** Web maps `NotAllowedError` → permission denied, `NotFoundError` → no device. Android uses runtime permissions instead, but the deny/no-device UX requirement is mirrored. Source: `src/lib/webrtc.ts: acquireLocalMedia` (lines 15–41); `src/hooks/useRtcPeerConnection.ts` NotAllowedError mapping (lines 164–168).

9. **Claim:** Artifact is `io.getstream:stream-webrtc-android`; `org.webrtc:google-webrtc` is unmaintained/unpublished. **VERDICT: Unverified-assumption.** Not present in any backend/frontend source (the web client uses the browser's native WebRTC, not a Maven artifact). This is an Android packaging decision. framework ref: Stream `stream-webrtc-android` (Maven `io.getstream:stream-webrtc-android`). The specific version `1.3.8` and its 16KB-page `.so` alignment for targetSdk 35 remain to be confirmed at implementation time (already flagged as R1).

10. **Claim:** `PeerConnectionFactory.initialize(...)` must run exactly once before factory/EglBase use; `EglBase`/`PeerConnectionFactory` are heavyweight native singletons. **VERDICT: Unverified-assumption (framework ref).** Consistent with the org.webrtc contract but not verifiable from the provided sources. framework ref: org.webrtc `PeerConnectionFactory.initialize` / `EglBase`.

11. **Claim:** Runtime permissions `CAMERA` + `RECORD_AUDIO` are "dangerous" and must be requested at point-of-use; permanent denial detected via `shouldShowRequestPermissionRationale`. **VERDICT: Unverified-assumption (framework ref).** Standard Android behavior, not in the provided sources; OEM/API variance is correctly flagged in R3. framework ref: Android permissions API (`ActivityResultContracts.RequestMultiplePermissions`, `ActivityCompat#shouldShowRequestPermissionRationale`, `Settings.ACTION_APPLICATION_DETAILS_SETTINGS`).

12. **Claim:** Stack baseline (Kotlin 2.0.21, compileSdk/targetSdk 35, minSdk 24, AGP 8.7.3, Gradle 8.9, Hilt/KSP). **VERDICT: Unverified-assumption.** No Android build files are in the provided reference set (frontend is TS/React); inherited from AND-004 / project setup tickets. Cannot be verified against backend/frontend sources.

13. **Claim:** Loopback performs offer/answer/ICE entirely in-process with empty `iceServers` and renders the remote track to a `SurfaceViewRenderer`. **VERDICT: Unverified-assumption (framework ref).** Pure Android/org.webrtc design; not represented in the web sources (the web app always uses real signaling + TURN). framework ref: org.webrtc `PeerConnection`, `SurfaceViewRenderer`, `Camera2Enumerator`.

### Corrections made
- §2 "Downstream owners": replaced the inaccurate "`AND-290` owns `/signal` transport" with the real send path `POST /messaging/messages/calls/{call_id}/signal` plus the SSE inbound channel; noted TURN is fetched via the verified POST endpoint.
- §5 "API Contract": replaced "signaling transport over `/signal` (SSE/poll…)" and the GET-implying "`turn-credentials`" with the verified methods/paths/schemas (`CallSignalingIn`/`CallSignalingOut`, `TurnCredentialsOut`), corrected TURN to **POST empty-body**, corrected inbound transport to **SSE (not poll)**, and added the real auth requirements (`Authorization` + `X-SESSION-ID` + web `X-CSRF-Token`/`ui_csrf`/`credentials: include`).
- Frontmatter: removed duplicate `status` key, set `status: reviewed`, added `reviewed_on: 2026-06-06`.
- No factual errors were found in the core build-wiring, DI, permission, lifecycle, or loopback designs (claims 9–13 are framework-level and remain as documented assumptions, not corrections).

### Open assumptions
- **Artifact + version (claim 9):** `io.getstream:stream-webrtc-android` `1.3.8` and its 16KB-page `.so` alignment — not in sources; must be confirmed against Maven at implementation (R1).
- **org.webrtc lifecycle/init/render contracts (claims 6 Android-half, 10, 13):** verifiable only against org.webrtc docs/source, which are outside the provided reference set.
- **Android permission semantics + permanent-denial heuristic (claim 11):** framework behavior with documented OEM variance (R3); not in sources.
- **Android build baseline (claim 12):** no Gradle/build files in the reference set; inherited from AND-004.

## 17. Test Plan

Test targets: **JVM** = JVM unit/Robolectric (local, no device); **AVD test35** = headless emulator, API 35 x86_64 (CI); **A15** = physical Samsung Galaxy A15 5G (SM-A156U, R5CX821TA9R), API 34 arm64-v8a. Hardware/ABI-dependent cases MUST run on **A15**; fast logic/UI cases run on JVM or AVD.

- **TC-AND-288-01** — Type: unit (JVM). Target: JVM. Preconditions: `PeerConnectionFactoryInitializer` with mocked static `PeerConnectionFactory.initialize`. Steps: invoke `ensureInitialized(ctx)` from N concurrent threads, then again single-threaded. Expected: `initialize` is called exactly once; no exception; second-pass is a no-op. Traces: AC-2 (runtime link guard), AC under R5.

- **TC-AND-288-02** — Type: unit (JVM). Target: JVM. Preconditions: permission status mapper. Steps: feed the matrix (granted bool × shouldShowRationale bool × wasRequested bool). Expected: maps to `GRANTED`/`DENIED`/`PERMANENTLY_DENIED`/`NOT_REQUESTED`; the (denied=true, rationale=false, wasRequested=true) case → `PERMANENTLY_DENIED`. Traces: AC-3, AC-4.

- **TC-AND-288-03** — Type: unit (JVM). Target: JVM. Preconditions: `AvPermissionsState`. Steps: evaluate `allGranted` across camera×mic status combinations. Expected: true only when both `GRANTED`. Traces: AC-3, AC-4.

- **TC-AND-288-04** — Type: integration/build. Target: CI build host (Gradle). Preconditions: `webrtc-android` in `libs.versions.toml`, `api(libs.webrtc.android)` in `core-webrtc`, `:core-webrtc` in `settings.gradle.kts`. Steps: run `:core-webrtc:assembleDebug` then `:app:assembleDebug`. Expected: both succeed; `org.webrtc.*` types resolve in a consumer module (compile-only smoke). Traces: AC-1.

- **TC-AND-288-05** — Type: contract/MockWebServer. Target: JVM (Robolectric/MockWebServer). Preconditions: none — this is a **negative network assertion** for the foundation. Steps: instrument `core-webrtc` runtime with a MockWebServer/OkHttp interceptor (or static scan) while driving loopback start/stop. Expected: **zero** HTTP requests issued; no Retrofit/OkHttp dependency is reachable from `core-webrtc`. Traces: AC-8.

- **TC-AND-288-06** — Type: instrumented/e2e. Target: **A15 (MUST)**. Preconditions: Hilt test component; app installed on arm64-v8a device. Steps: inject `PeerConnectionFactory` via the test graph and construct it. Expected: non-null factory; **no `UnsatisfiedLinkError`** (JNI loads for arm64-v8a); INFO log records ABI + webrtc version. Traces: AC-2. (Rerun on AVD test35 to cover x86_64 per AC-2.)

- **TC-AND-288-07** — Type: instrumented/e2e. Target: **AVD test35** (x86_64 leg of AC-2). Preconditions: API 35 emulator. Steps: same factory-injection link assertion as TC-06. Expected: factory constructs without `UnsatisfiedLinkError` on x86_64; confirms both ABI legs of AC-2 and surfaces API-34-vs-35 init differences. Traces: AC-2.

- **TC-AND-288-08** — Type: instrumented/e2e (render). Target: **A15 (MUST — real front camera)**. Preconditions: `GrantPermissionRule` for `CAMERA`+`RECORD_AUDIO`; loopback screen launched. Steps: drive `start(localRenderer, remoteRenderer)`; attach a frame listener to the remote renderer; wait up to timeout. Expected: `uiState` reaches `LoopbackUiState.Rendering`; remote renderer receives ≥1 frame. Traces: AC-5. (Emulator camera is unreliable per R4 → physical device required.)

- **TC-AND-288-09** — Type: Compose-UI / instrumented. Target: AVD test35 (no camera needed). Preconditions: permissions NOT yet granted; loopback opened. Steps: observe that the runtime permission prompt for CAMERA+RECORD_AUDIO appears **on opening the sample**, not at app launch; verify app launch alone triggered no prompt. Expected: in-context prompt shown; `start()` is a no-op emitting `AwaitingPermission` until granted. Traces: AC-3.

- **TC-AND-288-10** — Type: Compose-UI / instrumented. Target: AVD test35. Preconditions: loopback opened. Steps: deny the permission once → assert rationale + "request again" affordance; deny permanently (set rationale=false) → assert Settings deep-link affordance; tap it → assert `Settings.ACTION_APPLICATION_DETAILS_SETTINGS` intent fired; simulate grant-in-Settings and `ON_RESUME` → assert state re-checks and reaches rendering path without activity restart. Expected: all three branches behave as specified; never crashes. Traces: AC-4. (For real OEM heuristic behavior per R3, smoke-rerun on A15.)

- **TC-AND-288-11** — Type: instrumented (lifecycle/leak). Target: **A15 (MUST — real capturer threads)**. Preconditions: permissions granted; loopback rendering. Steps: perform start→stop→start cycles and an activity recreation mid-negotiation; capture capturer/`SurfaceTextureHelper` thread count and surface handles before/after. Expected: thread count returns to baseline; no leaked surfaces; no `EglBase` re-init crash; singletons survive recreation. Traces: AC-6.

- **TC-AND-288-12** — Type: instrumented (error path / offline-analogue). Target: AVD test35 (no camera). Preconditions: emulator with no usable front camera (the R4 flaky-host condition). Steps: open loopback with permissions granted and `Camera2Enumerator` reporting no front device. Expected: graceful `LoopbackUiState.Failed("No camera available")`; no crash; resources released; ERROR logged. Traces: AC-5 (negative), AC-6. (This deliberately exercises the device-absent/“flaky dev host” path on the emulator.)

- **TC-AND-288-13** — Type: security/release-hygiene. Target: CI build host + AVD test35. Preconditions: `release` variant assembled. Steps: assemble release; inspect that `WebRtcLoopbackScreen` and its debug nav entry are absent (debug source set / `BuildConfig.DEBUG` gate); verify R8 keep rule `-keep class org.webrtc.** { *; }` is applied (no stripped JNI symbols → smoke factory init in a release-shrunk test build). Expected: no loopback/camera-capture path in release; no `NoSuchMethodError` from R8 stripping. Traces: AC-7, AC-2 (release link safety).

- **TC-AND-288-14** — Type: Compose-UI (accessibility) + manual. Target: AVD test35 (automated) + A15 (TalkBack manual). Preconditions: permission UI + loopback shown. Steps: assert `contentDescription` on both `SurfaceViewRenderer` `AndroidView`s ("Local camera preview"/"Remote loopback video"); grant/open-settings touch targets ≥ 48dp; strings sourced from `strings.xml` (no hardcoded text); WCAG AA contrast on rationale/error; TalkBack focus order is sensible (manual on A15). Expected: all a11y checks pass. Traces: AC-3, AC-4 (permission UI quality).

### Coverage matrix (§14 AC → TCs)
- AC-1 (build / `api` wiring): TC-04
- AC-2 (runtime link, no `UnsatisfiedLinkError`, arm64 + x86_64): TC-01, TC-06 (arm64, MUST device), TC-07 (x86_64), TC-13 (release link safety)
- AC-3 (in-context permission prompt): TC-02, TC-03, TC-09, TC-14
- AC-4 (deny/permanent-deny/Settings round-trip): TC-02, TC-03, TC-10, TC-14
- AC-5 (loopback reaches Rendering, ≥1 frame): TC-08 (MUST device), TC-12 (negative no-camera)
- AC-6 (no thread/surface leak across lifecycle): TC-11 (MUST device), TC-12
- AC-7 (sample/nav absent from release): TC-13
- AC-8 (no network during loopback): TC-05
