---
id: AND-317
title: Broadcast host ViewModels
milestone: M7
epic: E41
priority: P1
size: L
depends_on: [AND-308]
blocks: [AND-318]
status: reviewed
reviewed_on: 2026-06-06
---

# AND-317 — Broadcast host ViewModels

## 1. Overview & Goal

This ticket delivers the presentation-layer state machine for the broadcast *host* experience in the native Android app (`com.testlogon.android`). It introduces a single source of truth — `BroadcastHostViewModel` — plus the `HostSessionState` finite-state machine (FSM), `HostSessionEvent` intent set, and the supporting `HostSessionStateMachine` reducer that drive every host screen: pre-flight, scheduling confirmation, connecting, live, paused, ended, and error.

The goal is to centralize *all* host session lifecycle logic in deterministic, unit-testable Kotlin code that mediates between the host-facing Compose UI and the lower-level data/WebRTC layers built in AND-307 (session create/schedule) and AND-308 (WebRTC ingest). This ViewModel owns the canonical session status, the WebRTC ingest connection status, derived health, and the legal transition graph; it does **not** own UI rendering (downstream feature screens), low-level RTCPeerConnection wiring (AND-308), nor input toggling (AND-310) or control RPCs (AND-309) beyond invoking their use cases and folding their results into state.

Success is defined by AND-318: the FSM and the ViewModel are fully unit-tested with deterministic coroutine tests and a fake repository/ingest controller, with no Android framework or network dependency required to run.

## 2. Context & References

- **Architecture:** `app -> feature-broadcast -> core-*`. This ticket lives in `feature-broadcast` (host package) and consumes `core-data`, `core-network`, `core-model`, `core-testing`. ViewModels expose `StateFlow<UiState>`; data calls return typed `ApiResult<T>`.
- **Upstream (depends_on):**
  - **AND-308 — WebRTC ingest** (`webrtc-ingest`, P0). Provides `WebRtcIngestController` (`inputs` + `webrtc-offer` publish of camera/mic). AND-317 observes its connection state and surfaces it; it does not implement SDP/ICE handling.
  - **AND-307 — Host session create/schedule** (transitive). Provides `BroadcastHostRepository` create/schedule/cancel-schedule operations.
- **Peers in M7/E41 (consumers, not dependencies):**
  - **AND-309 — Host controls** (start/stop/resume/reschedule, health report) invokes events on this ViewModel.
  - **AND-310 — Inputs management** toggles inputs through state owned here.
  - **AND-318 — Broadcast host tests** (this ticket *blocks* it) verifies the FSM and control transitions.
- **Backend:** FastAPI + DynamoDB; dev host `http://18.222.237.167:8000` (plaintext, unreliable). Cookie-based auth + `X-CSRF-Token`; 401 → single `POST /ui/session/refresh` then retry. OpenAPI at `/openapi.json`. Web reference: `frontend/src/api/endpoints/*.ts`, `frontend/src/api/types.ts`.
- **Stack:** Kotlin 2.0.21, Compose/Material 3, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6, DataStore. minSdk 24 / targetSdk 35, JDK 17.

## 3. Functional Requirements

FR-1. Provide a `HostSessionState` sealed FSM enumerating: `Idle`, `Scheduling`, `Scheduled`, `PreFlight`, `Connecting`, `Live`, `Paused`, `Reconnecting`, `Ending`, `Ended`, `Error`. Each carries the data needed to render that phase.

FR-2. Provide a `HostSessionEvent` sealed intent set covering every host action and external signal: load/restore, schedule, cancel schedule, go-live (start), pause, resume, reschedule, stop/end, ingest-status changed, health-tick, refresh, and dismiss-error.

FR-3. Implement `HostSessionStateMachine.reduce(state, event)` as a **pure function** producing `(nextState, effects)`. Illegal transitions (e.g., `Pause` while `Idle`) return the current state unchanged plus a `LogIllegalTransition` effect; they must never crash.

FR-4. `BroadcastHostViewModel` exposes `val uiState: StateFlow<HostSessionState>` and a single `fun onEvent(event: HostSessionEvent)`. It executes effects (repository/ingest calls) off the FSM output and re-dispatches resulting internal events.

FR-5. The ViewModel must reflect the WebRTC ingest connection status from AND-308 by collecting `WebRtcIngestController.status: StateFlow<IngestStatus>` and translating it into `IngestStatusChanged` events. While `Live`, an ingest drop transitions to `Reconnecting`; recovery returns to `Live`; exhausted retries transition to `Error`.

FR-6. The ViewModel derives a `HostHealth` snapshot (uptime, ingest state, dropped-frame/bitrate hints when supplied, last-error) on a periodic health tick while `Live`/`Paused`/`Reconnecting`, exposed within the state object for AND-309's health report UI.

FR-7. Session lifecycle must survive process death / config change: persist the active `sessionId` and last-known status to DataStore so a relaunch enters `PreFlight`/`Reconnecting` and rehydrates from `GET /broadcast/sessions/{session_id}` (CORRECTED path — singular `broadcast`, no `/host/` segment; verified against OpenAPI and `src/api/endpoints/broadcast.ts: getSession`).

FR-8. All long-running work runs in `viewModelScope` on an injected `CoroutineDispatcher` (default = `Dispatchers.Default`) so tests can substitute `StandardTestDispatcher`.

FR-9. The ViewModel must be idempotent against duplicate events (e.g., double-tap "Go Live" must not open two ingest connections) by gating on the current state and an in-flight guard.

## 4. Technical Design

Package: `com.testlogon.android.feature.broadcast.host`.

### 4.1 State model

```kotlin
sealed interface HostSessionState {
    val sessionId: String?

    data object Idle : HostSessionState { override val sessionId: String? get() = null }

    data class Scheduling(override val sessionId: String?, val draft: SessionDraft) : HostSessionState
    data class Scheduled(override val sessionId: String, val startsAt: Instant) : HostSessionState
    data class PreFlight(override val sessionId: String, val devices: DeviceSelection) : HostSessionState
    data class Connecting(override val sessionId: String, val attempt: Int) : HostSessionState
    data class Live(
        override val sessionId: String,
        val startedAt: Instant,
        val ingest: IngestStatus,
        val health: HostHealth,
    ) : HostSessionState
    data class Paused(override val sessionId: String, val since: Instant, val health: HostHealth) : HostSessionState
    data class Reconnecting(override val sessionId: String, val attempt: Int, val since: Instant) : HostSessionState
    data class Ending(override val sessionId: String) : HostSessionState
    data class Ended(override val sessionId: String, val endedAt: Instant) : HostSessionState
    data class Error(
        override val sessionId: String?,
        val cause: HostError,
        val recoverable: Boolean,
        val previous: HostSessionState? = null,
    ) : HostSessionState
}
```

### 4.2 Events & effects

```kotlin
sealed interface HostSessionEvent {
    data class Load(val sessionId: String?) : HostSessionEvent
    data class Schedule(val draft: SessionDraft) : HostSessionEvent
    data object CancelSchedule : HostSessionEvent
    data object GoLive : HostSessionEvent
    data object Pause : HostSessionEvent
    data object Resume : HostSessionEvent
    data class Reschedule(val startsAt: Instant) : HostSessionEvent
    data object Stop : HostSessionEvent
    data class IngestStatusChanged(val status: IngestStatus) : HostSessionEvent
    data object HealthTick : HostSessionEvent
    data object Refresh : HostSessionEvent
    data object DismissError : HostSessionEvent
    // internal results re-dispatched by the VM after effects complete
    data class SessionLoaded(val result: ApiResult<HostSession>) : HostSessionEvent
    data class ControlResult(val action: ControlAction, val result: ApiResult<HostSession>) : HostSessionEvent
}

sealed interface HostEffect {
    data class LoadSession(val sessionId: String) : HostEffect
    data class CallControl(val action: ControlAction) : HostEffect   // start/stop/pause/resume/reschedule
    data object OpenIngest : HostEffect
    data object CloseIngest : HostEffect
    data object StartHealthTicker : HostEffect
    data object StopHealthTicker : HostEffect
    data class Persist(val sessionId: String, val status: HostSessionStatus) : HostEffect
    data class LogIllegalTransition(val from: String, val event: String) : HostEffect
}
```

### 4.3 Reducer (pure)

```kotlin
object HostSessionStateMachine {
    data class Result(val state: HostSessionState, val effects: List<HostEffect>)
    fun reduce(state: HostSessionState, event: HostSessionEvent): Result
}
```

Transition matrix (primary edges):

| From | Event | To | Effects |
|---|---|---|---|
| Idle/Scheduled | Schedule | Scheduling | CallControl(Schedule) |
| Scheduling | ControlResult(ok) | Scheduled | Persist |
| Scheduled/PreFlight | GoLive | Connecting(attempt=1) | CallControl(Start), OpenIngest |
| Connecting | IngestStatusChanged(Connected) | Live | StartHealthTicker, Persist |
| Live | Pause | Paused | CloseIngest / mute inputs (NO server pause endpoint — see note) |
| Paused | Resume | Live | CallControl(Resume) |
| Live | IngestStatusChanged(Disconnected) | Reconnecting | (none; AND-308 owns retry) |
| Reconnecting | IngestStatusChanged(Connected) | Live | StartHealthTicker |
| Reconnecting | IngestStatusChanged(Failed) | Error(recoverable) | CloseIngest, StopHealthTicker |
| Live/Paused/Reconnecting | Stop | Ending | CallControl(Stop), CloseIngest, StopHealthTicker |
| Ending | ControlResult(ok) | Ended | Persist |
| any | ControlResult(err) | Error(prev=state) | LogIllegalTransition is *not* used here |
| Error(recoverable) | Refresh | previous ?: Idle | LoadSession |

Any unmatched (state, event) pair returns `Result(state, listOf(LogIllegalTransition(state::class.simpleName, event::class.simpleName)))`.

> **CORRECTION (verified):** There is **no** `POST .../pause` control endpoint on the backend. `Pause` is therefore a **client-side-only** state (mute primary input / close ingest locally) with no server control RPC; only `Resume` maps to a real call (`POST /broadcast/sessions/{id}/resume`). `ControlAction.Pause` MUST NOT emit a `CallControl(Pause)` effect. Verified: OpenAPI index has `/broadcast/sessions/{session_id}/resume` but no `.../pause` (the only `/pause` in the API is the unrelated `/ui/agent/orchestrator/{worker_id}/pause`); frontend `src/api/endpoints/broadcast.ts` exposes only `startSession`/`stopSession` (no pause).

### 4.4 ViewModel

```kotlin
@HiltViewModel
class BroadcastHostViewModel @Inject constructor(
    private val repository: BroadcastHostRepository,
    private val ingest: WebRtcIngestController,        // from AND-308
    private val prefs: HostSessionPrefs,               // DataStore-backed
    @DefaultDispatcher private val dispatcher: CoroutineDispatcher,
    savedState: SavedStateHandle,
) : ViewModel() {

    private val _uiState = MutableStateFlow<HostSessionState>(HostSessionState.Idle)
    val uiState: StateFlow<HostSessionState> = _uiState.asStateFlow()

    fun onEvent(event: HostSessionEvent)              // reduce -> setState -> runEffects
    private fun runEffects(effects: List<HostEffect>)
}
```

`onEvent` is single-threaded via a `Mutex`/single dispatched channel so reduction is serialized. `runEffects` launches effects in `viewModelScope`; each repository/ingest result is folded back as an internal `ControlResult`/`SessionLoaded`/`IngestStatusChanged` event, so the reducer remains the *only* place state mutates. On `init`, the VM collects `ingest.status` and starts the health ticker only when an effect requests it (cancellable `Job`).

## 5. API Contract

This ViewModel does not define new endpoints; it composes use cases from AND-307/AND-308/AND-309. The contracts it relies on (consumed via `BroadcastHostRepository` returning `ApiResult<T>`):

> **CORRECTED — the original shapes below were wrong.** Authoritative path prefix is `/broadcast/sessions/{session_id}` (singular `broadcast`, no `/host/`). The response DTO is `BroadcastSessionOut` (web `BroadcastSession`), whose id field is `id` (NOT `session_id`); there is no nested `ingest` object and no `scheduled_start` field; scheduling time is `scheduled_at` (epoch **integer**, not ISO string). Health is a **separate** endpoint, not embedded in the session GET.

- `GET /broadcast/sessions/{session_id}` → rehydrate (FR-7). Real shape (subset, from `src/api/endpoints/broadcast.ts: BroadcastSession` / OpenAPI `BroadcastSessionOut`):
  ```json
  { "id": "bs_01H...", "profile_id": "bp_...", "status": "live",
    "scheduled_at": 1749146400, "schedule_status": "scheduled",
    "started_at": "2026-06-05T18:01:12Z", "stopped_at": null,
    "ingest_url": "...", "cloudfront_playback_url": "...", "created_at": "...", "updated_at": "..." }
  ```
  CORRECTED status vocabulary (web `BroadcastSessionStatus`): `status ∈ {draft, scheduled, provisioning, ready, live, stopping, stopped, cancelled, error}`. There is **no** `preflight`, `paused`, or `ended` server status — `PreFlight`/`Paused`/`Ended`/`Reconnecting` are **client-only** FSM phases. Map: server `ready` → client `PreFlight`; server `stopping` → client `Ending`; server `stopped`/`cancelled` → client `Ended`; server `provisioning` → client `Connecting`.
- Control RPCs (AND-309), all returning `BroadcastSessionOut`, request body `BroadcastSessionActionIn` = `{ "reason"?: string }` (default `"operator-request"`):
  - `POST /broadcast/sessions/{session_id}/start` → **202 Accepted** (async). Accepts optional `x-idempotency-key` and `x-correlation-id` headers — use `x-idempotency-key` to harden FR-9 idempotency server-side.
  - `POST /broadcast/sessions/{session_id}/stop` → **202 Accepted** (async). Same idempotency/correlation headers.
  - `POST /broadcast/sessions/{session_id}/resume` → 200. **No request body.**
  - `POST /broadcast/sessions/{session_id}/schedule` (`BroadcastScheduleIn` = `{ scheduled_at: int, name?, description? }`) and `POST .../reschedule` (`BroadcastRescheduleIn` = `{ scheduled_at: int }`) and `POST .../cancel-schedule` (no body) — all → `BroadcastSessionOut`.
  - **No `/pause` endpoint exists** (see §4.3 correction). `Pause` is client-only.
- Health (resolves OQ1 — backend DOES expose health, separately):
  - `GET /broadcast/sessions/{session_id}/health` → `BroadcastHealthOut` (web `BroadcastHealthResponse`): `{ ingest_bitrate_kbps, ingest_framerate, dropped_frames, dropped_frames_pct, connection_quality, viewer_count, output_errors, input_loss_seconds, updated_at }`.
  - `POST /broadcast/sessions/{session_id}/health/report` (`BroadcastHealthReportIn`, required `ingest_bitrate_kbps, ingest_framerate, dropped_frames, dropped_frames_pct`) → `BroadcastHealthOut`. `HostHealth` may be sourced from either local WebRTC stats or this endpoint.
- WebRTC ingest is wholly owned by AND-308 and surfaced only as `IngestStatus`. Underlying calls: `POST /broadcast/sessions/{session_id}/inputs` (`BroadcastInputCreateIn` = `{ input_type?: "primary"|"guest"|"screen", label? }` → `BroadcastInputCreateOut` with `input_id`, `ingest_url`) and `POST /broadcast/sessions/{session_id}/inputs/{input_id}/webrtc-offer` (`BroadcastWebRTCOfferIn` = `{ sdp_offer }` → `BroadcastWebRTCOfferOut`/web `BroadcastWebRTCAnswer`).

All mutating calls send `X-CSRF-Token` (from the `ui_csrf` cookie) via the shared OkHttp auth/CSRF interceptor (VERIFIED: `src/api/client.ts` reads `getCookie("ui_csrf")` and sets header `X-CSRF-Token`, with `credentials: "include"`). FastAPI 422 errors return `detail` as an array of `{loc, msg, type}` (`HTTPValidationError` → `ValidationError`); the shared `normalizeErrorDetail` also handles `detail` as a plain string or an object with a `code` (e.g. 403 `{code: "geo_blocked", message}`). These map to `HostError` through the shared `ErrorMapper` in `core-network`. Retry/backoff applies to the idempotent `GET` only; control POSTs are **not** blindly auto-retried — but `start`/`stop` are async **202** calls that accept an `x-idempotency-key`, so an explicit re-tap SHOULD reuse the same idempotency key to avoid duplicate side effects rather than rely on transport retry. N/A for endpoint *definition*: owned by AND-307/308/309.

## 6. Data & State Management

- **In-memory:** `StateFlow<HostSessionState>` is the single UI source of truth; Compose host screens (downstream) `collectAsStateWithLifecycle`.
- **Persistence (DataStore Preferences):** `HostSessionPrefs` stores `active_session_id: String?` and `last_status: HostSessionStatus`. Written via the `Persist` effect on every committed status change; cleared on `Ended`/`CancelSchedule`. No PII stored.
- **Restore path:** `init` reads `active_session_id`; if present, seeds `Reconnecting`/`PreFlight` and dispatches `Load(id)` to rehydrate from the GET. Room is **not** used here (no list/cache need at this layer; broadcast catalog caching is a separate ticket).
- **Health:** `HostHealth(uptime: Duration, ingest: IngestStatus, bitrateKbps: Int?, droppedFrames: Int?, lastError: HostError?)` recomputed on each `HealthTick` (default 2s cadence, injected for tests) from `startedAt` + latest `IngestStatus`.
- **Derived flags** (computed properties, not stored): `canGoLive`, `canPause`, `canStop`, `isReconnecting` — drive button enablement in AND-309/AND-310 without leaking transition rules into UI.

## 7. Error Handling & Resilience

- `HostError` taxonomy: `Network`, `Timeout`, `Auth`, `Csrf`, `Conflict` (e.g., session already live), `IngestFailed`, `Validation(field)`, `Unknown`. Mapped from `ApiResult.Error` and `IngestStatus.Failed`.
- **Timeouts:** rely on the shared 20s OkHttp call timeout for the dev host. A control call timeout → `Error(recoverable=true)` preserving `previous` so `Refresh`/retry can resume.
- **401 handling:** delegated to the shared interceptor (single `POST /ui/session/refresh` then retry). A second 401 → `HostError.Auth` and `Error` state prompting re-login (no infinite loops).
- **Ingest loss while Live:** transition `Live → Reconnecting`; AND-308 owns ICE-restart/backoff. The VM bounds total reconnect time (default 30s, injected); on exhaustion → `Error(IngestFailed, recoverable=true)` with `CloseIngest`/`StopHealthTicker`.
- **Illegal transitions:** never throw — return unchanged state + `LogIllegalTransition` effect (telemetry only).
- **Idempotency:** in-flight guard prevents duplicate `GoLive`/`Stop` from opening/closing ingest twice (FR-9).
- **Offline/stale:** if rehydrate GET fails offline, stay in `Reconnecting` with a stale banner flag rather than dropping to `Idle`.

## 8. Security & Privacy

- No credentials handled here; session cookies and `ui_csrf` are managed by the persistent OkHttp `CookieJar` and CSRF interceptor (core-network). The VM never reads cookie values.
- DataStore persists only `active_session_id` (opaque server id) and a status enum — no usernames, tokens, or media. DataStore is app-private storage; no `allowBackup` of the prefs file (excluded via backup rules).
- Camera/mic permission state is owned by AND-308/the host screen; the VM treats absent permission as a `PreFlight` blocker (`HostError.Validation("permissions")`) and never requests permissions itself.
- No secrets, tokens, or PII in logs (see §10); `sessionId` is opaque and acceptable to log at debug level.

## 9. Accessibility & i18n

Largely deferred to the host Compose screens (AND-309/AND-310), but this ticket supports them:
- The state object exposes a stable `statusLabelKey: Int` (string resource id) per phase rather than hard-coded English, so all phase labels (Connecting, Live, Reconnecting, Paused, Ended) are localizable. No raw user-facing strings originate in the ViewModel.
- Error messages are produced as `@StringRes` keys + format args, not literals, enabling translation and `TalkBack`-friendly announcements downstream.
- Time/duration values (`uptime`, `startsAt`) are carried as `Instant`/`Duration` and formatted by the UI with locale-aware formatters — the VM stores no pre-formatted strings.

## 10. Telemetry & Logging

- Inject `HostAnalytics` (interface in core-data) and emit structured events on committed transitions: `host_session_state_changed { session_id, from, to }`, `host_control_invoked { action, result }`, `host_ingest_state { state, attempt }`, `host_reconnect_exhausted`, `host_illegal_transition { from, event }`.
- Logging via the shared `Logger` at: `debug` for every reduce (`from -> to`), `warn` for illegal transitions and recoverable errors, `error` for terminal `Error`. No PII; `session_id` only.
- Health snapshots are **not** spammed to analytics; only state changes and explicit health-report opens (AND-309) emit events.
- All analytics calls are fire-and-forget on `viewModelScope` and fully mockable for AND-318.

## 11. Testing Strategy

Acceptance is "Unit-tested"; tests proper land in AND-318, but this ticket must ship code that is unit-testable and includes the FSM's own table tests.

- **Reducer tests (pure, no coroutines):** parameterized table covering every legal edge in §4.3 plus a representative sample of illegal pairs asserting `state` unchanged + single `LogIllegalTransition`. Property-style check: from any state, every event yields a non-null `Result` and never throws.
- **ViewModel tests:** `kotlinx-coroutines-test` `StandardTestDispatcher` via the injected dispatcher; `MainDispatcherRule` from `core-testing`. Use `FakeBroadcastHostRepository` and `FakeWebRtcIngestController` (settable `status` flow) and an in-memory `HostSessionPrefs`.
  - `GoLive` happy path: `Idle/Scheduled → Connecting → (ingest Connected) → Live`, asserting `OpenIngest` + `StartHealthTicker` ran once.
  - Reconnect: drop while `Live → Reconnecting → Live` on recovery; exhaustion → `Error(IngestFailed)`.
  - Control failure: `Stop` returns `ApiResult.Error` → `Error(previous=Live)`; `Refresh` restores.
  - Idempotency: two rapid `GoLive` open ingest once.
  - Restore: pre-seeded prefs → `Load` rehydrates to correct phase.
  - 401: repository surfaces `Auth` after refresh-retry exhausted → `Error(Auth)`.
- **Turbine** for `StateFlow` assertions. Target ≥90% line coverage on `HostSessionStateMachine` and `BroadcastHostViewModel`. No Robolectric/instrumentation required (no Android framework deps in this layer).

## 12. Dependencies & Sequencing

- **Hard dependency:** AND-308 (WebRTC ingest) must provide `WebRtcIngestController` + `IngestStatus`. AND-307 (transitively) provides `BroadcastHostRepository` create/schedule/cancel. If AND-308's controller interface is not final, define the consumed interface here and let AND-308 implement it (adapter to avoid blocking).
- **Blocks:** AND-318 (host tests) consumes the fakes/seams created here.
- **Coordinates with:** AND-309 (controls call `onEvent(Stop/Pause/Resume/Reschedule)`), AND-310 (inputs read derived flags). Their PRs should merge after this lands.
- **Sequencing:** land FSM (`HostSessionStateMachine` + sealed types) first as a self-contained PR (testable in isolation), then the ViewModel + DataStore + ingest wiring.

## 13. Risks & Open Questions

- **R1 — Ingest interface churn (AND-308):** controller status enum shape may shift. Mitigation: own the consumed `IngestStatus`/`WebRtcIngestController` interface in this module.
- **R2 — Reconnect ownership split:** unclear whether ICE-restart backoff lives in AND-308 or here. Assumption: AND-308 owns retry; this VM only bounds total reconnect window. *Open question for AND-308 owner.*
- **R3 — Server status vocabulary:** ~~assumed~~ **RESOLVED.** Server enum (web `BroadcastSessionStatus`) is `{draft, scheduled, provisioning, ready, live, stopping, stopped, cancelled, error}`. `preflight`/`paused`/`ended`/`reconnecting` are confirmed client-only; mapping documented in §5. The DTO is `BroadcastSessionOut` with id field `id`, not a `HostSession`/`session_id` shape.
- **R4 — Dev host unreliability:** flaky control POSTs may strand state in `Ending`. Mitigation: rehydrate-on-resume + explicit `Refresh`. Non-idempotent POSTs are not auto-retried.
- **OQ1:** ~~Does the backend emit health on the session GET?~~ **RESOLVED:** health is NOT on the session GET; it is a dedicated `GET /broadcast/sessions/{session_id}/health` (`BroadcastHealthOut`) plus host-pushed `POST .../health/report` (`BroadcastHealthReportIn`). `HostHealth` may source from local WebRTC stats and/or these endpoints.
- **OQ2:** Is `Reschedule` allowed while `Live`, or only `Scheduled`? Spec assumes `Scheduled`-only.

## 14. Acceptance Criteria

1. `HostSessionState`, `HostSessionEvent`, `HostEffect`, and `HostSessionStateMachine.reduce` exist in `com.testlogon.android.feature.broadcast.host` with signatures per §4.
2. `reduce` is a pure function: identical input always yields identical output, throws on no input, and returns the unchanged state + exactly one `LogIllegalTransition` for any illegal `(state, event)` pair.
3. Every transition in the §4.3 matrix is implemented and covered by a passing table test.
4. `BroadcastHostViewModel` exposes `StateFlow<HostSessionState>` and a single `onEvent`; all mutation flows through the reducer; effects re-dispatch internal events.
5. Collecting `WebRtcIngestController.status` drives `Live ↔ Reconnecting`, with reconnect-window exhaustion → `Error(IngestFailed, recoverable=true)`.
6. Double-`GoLive` opens ingest exactly once; double-`Stop` closes exactly once (idempotency tests pass).
7. Active `sessionId` + status persist to DataStore and rehydrate on relaunch via `GET /broadcast/sessions/{session_id}` (CORRECTED path).
8. Control-call failures and exhausted 401-refresh produce `Error` states preserving `previous`, recoverable via `Refresh`.
9. All long-running work uses the injected dispatcher; tests run deterministically under `StandardTestDispatcher` with no real network/Android deps.
10. Unit tests for the FSM and ViewModel pass in CI with ≥90% line coverage on the two core classes.

## 15. Definition of Done

- Code merged to `android-port` under `android/feature-broadcast/.../host/`, builds with AGP 8.7.3 / Gradle 8.9 / JDK 17, passing `./gradlew :feature-broadcast:detekt :feature-broadcast:testDebugUnitTest`.
- No new public API leaks transition rules to UI; only `uiState`, `onEvent`, and derived flags are exposed.
- No PII/tokens in logs or DataStore; backup-excluded prefs verified.
- All §14 acceptance criteria verified by passing unit tests; coverage report attached to the PR.
- KDoc on `HostSessionStateMachine`, the sealed types, and `BroadcastHostViewModel`; transition matrix documented in code.
- Hilt module binds `BroadcastHostRepository`, `WebRtcIngestController` (or adapter), `HostSessionPrefs`, and `@DefaultDispatcher`; app compiles with DI graph resolved.
- PR description links AND-308 (dep) and AND-318 (blocked); reviewed and approved by an E41 owner.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer.

1. **Rehydrate endpoint is `GET /broadcast/sessions/{session_id}`.** VERDICT: **Corrected** (spec said `/broadcasts/host/sessions/...`). SOURCE: OpenAPI `GET /broadcast/sessions/{session_id}` (op `get_session_route...`, resp `200:BroadcastSessionOut`); `src/api/endpoints/broadcast.ts: getSession`.
2. **Session response DTO is `BroadcastSessionOut` (web `BroadcastSession`); id field is `id`, scheduling time is `scheduled_at` (epoch int), timestamps `started_at`/`stopped_at`; no nested `ingest` object.** VERDICT: **Corrected** (spec JSON used `session_id`, `scheduled_start`, nested `ingest`). SOURCE: OpenAPI `components.schemas.BroadcastSessionOut` (fields `id`, `status`, `scheduled_at`, `schedule_status`, `started_at`, `stopped_at`); `src/api/endpoints/broadcast.ts: BroadcastSession`.
3. **Session status vocabulary = `{draft, scheduled, provisioning, ready, live, stopping, stopped, cancelled, error}`; `preflight`/`paused`/`ended` are NOT server statuses.** VERDICT: **Corrected** (spec said `{scheduled, preflight, live, paused, ended}`). SOURCE: `src/api/endpoints/broadcast.ts: BroadcastSessionStatus`. (OpenAPI types `status` as a free string, so the web type is authoritative.)
4. **No `POST .../pause` control endpoint exists; `Pause` is client-only.** VERDICT: **Corrected** (spec listed `/pause` as a control RPC). SOURCE: OpenAPI index has `/broadcast/sessions/{session_id}/resume` and `.../start`, `.../stop` but no `.../pause`; the only `/pause` in the API is `POST /ui/agent/orchestrator/{worker_id}/pause` (unrelated); `src/api/endpoints/broadcast.ts` exports only `startSession`/`stopSession`.
5. **`/start` and `/stop` return 202 Accepted (async) and accept `x-idempotency-key` + `x-correlation-id` headers; body `BroadcastSessionActionIn = {reason?: string="operator-request"}`.** VERDICT: **Corrected/augmented** (spec implied 200 and "non-idempotent, not retried"; idempotency key was unmentioned). SOURCE: OpenAPI `POST /broadcast/sessions/{session_id}/start` & `.../stop` (`resp=202:BroadcastSessionOut`, `params=...,x-correlation-id,x-idempotency-key,...`); `components.schemas.BroadcastSessionActionIn`; `src/api/endpoints/broadcast.ts: startSession/stopSession`.
6. **`/resume` exists (200), no request body; returns `BroadcastSessionOut`.** VERDICT: **Verified.** SOURCE: OpenAPI `POST /broadcast/sessions/{session_id}/resume` (op `resume_broadcast_route...`).
7. **`/schedule`, `/reschedule`, `/cancel-schedule` exist and return `BroadcastSessionOut`; schedule/reschedule use `scheduled_at` (epoch int).** VERDICT: **Verified.** SOURCE: OpenAPI `POST .../schedule` (`req=app__routers__broadcast__BroadcastScheduleIn`), `.../reschedule` (`BroadcastRescheduleIn`), `.../cancel-schedule`; `src/api/endpoints/broadcastSchedule.ts: scheduleSession/rescheduleSession/cancelSchedule` (`ScheduleSessionReq.scheduled_at: number`).
8. **Health is a dedicated endpoint, not embedded in the session GET: `GET .../health` (`BroadcastHealthOut`) and `POST .../health/report` (`BroadcastHealthReportIn`).** VERDICT: **Corrected** (resolves OQ1; spec implied health on session GET or local-only). SOURCE: OpenAPI `GET /broadcast/sessions/{session_id}/health`, `POST .../health/report`; `components.schemas.BroadcastHealthReportIn` (required `ingest_bitrate_kbps, ingest_framerate, dropped_frames, dropped_frames_pct`); `src/api/endpoints/broadcast.ts: getHealth/reportHealth`.
9. **WebRTC offer endpoint is `POST /broadcast/sessions/{session_id}/inputs/{input_id}/webrtc-offer`, body `{sdp_offer}`; inputs created via `POST .../inputs` with `{input_type, label}`.** VERDICT: **Verified.** SOURCE: OpenAPI `.../inputs/{input_id}/webrtc-offer` (`req=BroadcastWebRTCOfferIn`), `.../inputs` (`req=BroadcastInputCreateIn`, `input_type` pattern `^(primary|guest|screen)$`); `src/api/endpoints/broadcast-inputs.ts: sendWebRTCOffer/addInput`.
10. **Mutating calls send `X-CSRF-Token` from the `ui_csrf` cookie with `credentials: include`.** VERDICT: **Verified.** SOURCE: `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`, `credentials: "include"`).
11. **401 → single `POST /ui/session/refresh` then one retry; a second 401 → logout/re-login (no infinite loop).** VERDICT: **Verified.** SOURCE: OpenAPI `POST /ui/session/refresh`; `src/api/client.ts` (refresh-once via shared `refreshPromise`, single retry, `logout("session_expired")` on retry 401).
12. **422 error body shape is `detail: ValidationError[]` (`{loc, msg, type}`); client also handles string `detail` and `{code}` objects (e.g. 403 `geo_blocked`).** VERDICT: **Corrected/refined** (spec wrote `string | [{msg}] | {code,...}`). SOURCE: OpenAPI `components.schemas.HTTPValidationError` → `ValidationError`; `src/api/client.ts: normalizeErrorDetail` (string/array/object handling, geo_blocked `code`).
13. **DataStore Preferences for `active_session_id`/`last_status`; backup-excluded; ViewModel + StateFlow + Hilt + injected dispatcher.** VERDICT: **Unverified-assumption** (Android client-architecture choices; no backend/web source). SOURCE: framework ref — Jetpack DataStore (developer.android.com/topic/libraries/architecture/datastore), Hilt ViewModel (developer.android.com/training/dependency-injection/hilt-jetpack), `kotlinx-coroutines-test` injected-dispatcher pattern.
14. **AND-308 `WebRtcIngestController` / `IngestStatus` shape and ownership of ICE-restart/backoff.** VERDICT: **Unverified-assumption** (dependency not yet final; interface owned in this module per R1). SOURCE: spec §2/§12 (AND-308); no authoritative source available.

### Corrections made

- C1 (claims 1, 7-AC): endpoint path `/broadcasts/host/sessions/...` → `/broadcast/sessions/...` (FR-7, §5, AC-7).
- C2 (claim 2): session JSON example rewritten to real `BroadcastSessionOut` field names (`id`, `scheduled_at` epoch int, `started_at`/`stopped_at`; removed nested `ingest` and `scheduled_start`).
- C3 (claim 3): status enum corrected; added explicit client↔server status mapping in §5; R3 marked resolved.
- C4 (claim 4): removed `/pause` as a real control RPC; `Pause` documented as client-only in §4.3 and §5; transition matrix `CallControl(Pause)` row corrected.
- C5 (claim 5): start/stop documented as 202 async with `x-idempotency-key`/`x-correlation-id`; §5 retry paragraph refined to use idempotency key on re-tap.
- C6 (claim 8): health documented as dedicated `GET .../health` + `POST .../health/report`; OQ1 resolved.
- C7 (claim 12): 422/error `detail` shape refined to FastAPI `ValidationError[]` plus client `normalizeErrorDetail` variants.

### Open assumptions

- OA1: AND-308 `WebRtcIngestController`/`IngestStatus` contract (claim 14) — upstream not final; this module defines the consumed interface as a seam. Unverifiable until AND-308 lands.
- OA2: All Android-layer choices (DataStore keys, Hilt wiring, `@DefaultDispatcher`, Turbine/Robolectric absence) (claim 13) — client architecture, no backend/web contract to verify against; validated only against framework docs.
- OA3: OQ2 (is `Reschedule` allowed while `Live`?) — backend exposes `/reschedule` but does not document the legal pre-state; spec assumes `Scheduled`-only. Unverifiable from OpenAPI (no documented state guard).
- OA4: Exact server-side status emitted immediately after a 202 `start`/`stop` (e.g. `provisioning` vs `live`, `stopping` vs `stopped`) — async; not deterministically documented. Client polls `GET` to converge.

## 17. Test Plan

Test target legend: **JVM** = JVM unit/Robolectric (local, no device); **Emu35** = headless emulator AVD `test35` (x86_64, API 35); **PhysA15** = physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). This ticket is a pure presentation/state-machine layer (no Android framework, network, or media at runtime), so the bulk of cases are JVM unit / contract (MockWebServer). Physical-device cases apply only where real WebRTC ingest/camera/mic behavior must be exercised end-to-end with the real controller (AND-308 integration), which is why PhysA15 is preferred there over the emulator (emulators lack real camera/mic capture and arm64 codec behavior).

- **TC-AND-317-01** — Type: unit (JVM). Target: `HostSessionStateMachine.reduce`. Preconditions: none. Steps: feed every legal `(state,event)` edge from the §4.3 matrix as a parameterized table. Expected: each yields the documented `nextState` and exact `effects` list (e.g. `Scheduled/PreFlight + GoLive → Connecting(attempt=1)` with `[CallControl(Start), OpenIngest]`; `Connecting + IngestStatusChanged(Connected) → Live` with `[StartHealthTicker, Persist]`). Traces: AC-1, AC-3.
- **TC-AND-317-02** — Type: unit (JVM). Target: `reduce` illegal transitions. Preconditions: none. Steps: feed a representative sample of illegal pairs (e.g. `Idle + Pause`, `Ended + GoLive`, `Live + Schedule`). Expected: state returned unchanged + exactly one `LogIllegalTransition(from, event)` effect; never throws; identical input → identical output (purity). Traces: AC-2.
- **TC-AND-317-03** — Type: unit (JVM). Target: `reduce` Pause edge. Preconditions: state = `Live`. Steps: dispatch `Pause`. Expected: `nextState = Paused` and effects **do NOT** contain `CallControl(Pause)` (client-only; per §4.3 correction there is no server pause). `Resume` from `Paused` DOES yield `CallControl(Resume)`. Traces: AC-3.
- **TC-AND-317-04** — Type: unit (JVM, coroutines-test). Target: `BroadcastHostViewModel` GoLive happy path. Preconditions: `FakeBroadcastHostRepository` returns ok; `FakeWebRtcIngestController`; `StandardTestDispatcher`. Steps: from `Scheduled`, `onEvent(GoLive)`; advance; emit ingest `Connected`. Expected (Turbine on `uiState`): `Scheduled → Connecting → Live`; `OpenIngest` + `StartHealthTicker` each ran once; `Persist(status=live)` written. Traces: AC-4, AC-9.
- **TC-AND-317-05** — Type: unit (JVM, coroutines-test). Target: ingest reconnect cycle. Preconditions: state `Live`. Steps: fake controller emits `Disconnected`; then `Connected` before window expiry. Expected: `Live → Reconnecting → Live`; health ticker resumes; no `Error`. Traces: AC-5.
- **TC-AND-317-06** — Type: unit (JVM, coroutines-test). Target: reconnect-window exhaustion. Preconditions: state `Live`; injected reconnect window (e.g. 30s). Steps: controller emits `Disconnected`/`Failed`; advance past window with no recovery. Expected: `Reconnecting → Error(IngestFailed, recoverable=true)`; `CloseIngest` + `StopHealthTicker` ran. Traces: AC-5.
- **TC-AND-317-07** — Type: unit (JVM, coroutines-test). Target: idempotency guard. Preconditions: state `Scheduled`. Steps: dispatch two rapid `GoLive` (and separately two rapid `Stop` from `Live`). Expected: `OpenIngest` called exactly once for double-GoLive; `CloseIngest` exactly once for double-Stop; in-flight guard blocks the second. Traces: AC-6.
- **TC-AND-317-08** — Type: unit (JVM, coroutines-test). Target: control-failure → recoverable Error. Preconditions: state `Live`; repository returns `ApiResult.Error` for stop. Steps: `onEvent(Stop)`; fold `ControlResult(err)`. Expected: `Error(cause, recoverable=true, previous=Live)`; subsequent `Refresh` re-loads and restores prior phase. Traces: AC-8.
- **TC-AND-317-09** — Type: contract/MockWebServer (JVM). Target: `BroadcastHostRepository` against real wire shapes. Preconditions: MockWebServer enqueues a `BroadcastSessionOut` JSON body (real fields: `id`, `status:"live"`, `scheduled_at` int, `started_at`). Steps: call rehydrate `GET /broadcast/sessions/{id}`; call start (assert request path `/broadcast/sessions/{id}/start`, response **202**). Expected: parsing maps `id`→sessionId and `status`→client phase per §5 mapping; 202 accepted as success; no crash on absent `ingest` object. Traces: AC-7, AC-4.
- **TC-AND-317-10** — Type: contract/MockWebServer (JVM). Target: idempotency + CSRF on control POST. Preconditions: MockWebServer. Steps: invoke start twice from a retry path; inspect recorded requests. Expected: `X-CSRF-Token` header present (from cookie jar) and `x-idempotency-key` is identical across the original and the re-tap so the server can dedupe. Traces: AC-6, AC-8.
- **TC-AND-317-11** — Type: contract/MockWebServer (JVM). Target: 422 / validation error mapping. Preconditions: MockWebServer returns 422 with `{"detail":[{"loc":["body","scheduled_at"],"msg":"...","type":"value_error"}]}`. Steps: invoke schedule with bad payload. Expected: mapped to `HostError.Validation("scheduled_at")` (field extracted from `loc`); not `Unknown`. Traces: AC-8.
- **TC-AND-317-12** — Type: contract/MockWebServer (JVM). Target: 401 refresh-then-retry. Preconditions: MockWebServer enqueues 401, then (after a refresh hit) 200. Steps: invoke a control call; assert exactly one `POST /ui/session/refresh` then one retry. Expected: success after single refresh; a second consecutive 401 → `HostError.Auth` + `Error(Auth)` state, no loop. Traces: AC-8.
- **TC-AND-317-13** — Type: unit (JVM, coroutines-test). Target: process-death restore + offline/flaky-dev-host path. Preconditions: in-memory `HostSessionPrefs` pre-seeded `active_session_id` + `last_status=live`; repository rehydrate `GET` fails with network error. Steps: construct VM (`init`), let restore run. Expected: VM seeds `Reconnecting` (not `Idle`), dispatches `Load`, and on GET failure stays `Reconnecting` with stale-banner flag (does not drop to `Idle`). Traces: AC-7, AC-8.
- **TC-AND-317-14** — Type: unit (JVM). Target: no-PII security invariant on persistence/logs. Preconditions: spy `Logger`/`HostAnalytics`; DataStore prefs. Steps: drive a full lifecycle. Expected: persisted keys are only `active_session_id` (opaque) + status enum; no tokens/usernames/media; log/analytics payloads contain only `session_id`, `from`, `to`, `action` — assert no cookie/CSRF value ever logged; prefs cleared on `Ended`/`CancelSchedule`. Traces: AC-7 (and §8 security DoD).
- **TC-AND-317-15** — Type: instrumented/e2e (PhysA15 — MUST run on physical device). Target: real AND-308 `WebRtcIngestController` + camera/mic capture driving `Live ↔ Reconnecting`. Preconditions: physical SM-A156U (arm64-v8a, API 34) with camera+mic permissions granted; reachable dev host. Steps: GoLive with real WebRTC ingest (`/inputs` + `/inputs/{id}/webrtc-offer`); toggle network to force ingest drop, then restore. Expected: VM observes real `IngestStatus` transitions → `Live → Reconnecting → Live`; on sustained loss → `Error(IngestFailed)`. Why physical: emulator `test35` lacks real camera/mic capture and arm64 codec/ABI behavior; WebRTC ingest must exercise real mic/camera + TURN. Traces: AC-5, AC-9.
- **TC-AND-317-16** — Type: unit (JVM). Target: permission-blocker handling (security/permission case). Preconditions: host screen reports camera/mic permission absent (PreFlight). Steps: dispatch `GoLive` while permission marker absent. Expected: VM does NOT call `OpenIngest`/request permissions itself; state surfaces `HostError.Validation("permissions")` as a `PreFlight` blocker. Traces: AC-4 (and §8).
- **TC-AND-317-17** — Type: unit (JVM). Target: accessibility/i18n contract of state object. Preconditions: none. Steps: inspect each `HostSessionState` phase and `Error` cause. Expected: each carries a `statusLabelKey: Int` (`@StringRes`) and error messages are `@StringRes` + args — no raw English strings, no pre-formatted dates (Instant/Duration carried raw). Ensures downstream TalkBack/translation. Traces: AC-1, AC-4.

### Coverage matrix

| AC (§14) | Covered by |
|---|---|
| AC-1 (types/reduce exist per §4) | TC-01, TC-17 |
| AC-2 (reduce pure; illegal → unchanged + one LogIllegalTransition) | TC-02 |
| AC-3 (every §4.3 transition table-tested) | TC-01, TC-03 |
| AC-4 (StateFlow + single onEvent; mutation via reducer; effects re-dispatch) | TC-04, TC-09, TC-16, TC-17 |
| AC-5 (Live ↔ Reconnecting; exhaustion → Error(IngestFailed)) | TC-05, TC-06, TC-15 |
| AC-6 (double-GoLive opens once; double-Stop closes once) | TC-07, TC-10 |
| AC-7 (persist + rehydrate via GET /broadcast/sessions/{id}) | TC-09, TC-13, TC-14 |
| AC-8 (control failure + 401 exhaustion → Error preserving previous; Refresh recovers) | TC-08, TC-11, TC-12, TC-13 |
| AC-9 (injected dispatcher; deterministic under StandardTestDispatcher; no real net/Android) | TC-04, TC-09, TC-15 |
| AC-10 (FSM + VM ≥90% line coverage in CI) | TC-01–TC-08, TC-13, TC-14, TC-16, TC-17 (aggregate) |
