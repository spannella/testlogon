---
id: AND-309
title: Host controls
milestone: M7
epic: E41
priority: P0
size: M
status: draft
depends_on: [AND-308]
blocks: []
---

# AND-309 — Host controls

## 1. Overview & Goal

AND-309 delivers the live **host lifecycle control surface** for a broadcast
session inside the TestLogon native Android app. Once a host has created/scheduled
a session (AND-307) and started publishing camera/mic via WebRTC ingest (AND-308),
this ticket gives the host an in-app control panel to drive the session through its
remaining states: **start**, **stop**, **resume**, and **reschedule**, plus a
continuously-updated **health report** that surfaces ingest and broadcast quality.

The goal is that a host can take a session live, pause/stop it, resume it, or push
it to a later time, and at all times see an authoritative, server-confirmed view of
session status and stream health — entirely from the device, with no web fallback.
"Lifecycle controls work live" (the acceptance bullet) means every control issues a
real backend mutation, the UI reflects the server-confirmed state (not optimistic
guesses), and the host sees health telemetry refreshing while broadcasting.

This is a P0 feature. It is the operational core of the host experience: without it a
host can only begin a broadcast (AND-308) but cannot manage it.

## 2. Context & References

- **Repo:** `spannella/testlogon`, Android app under `android/`, branch `android-port`.
- **Package base:** `com.testlogon.android` (all classes below live under this namespace).
- **Module placement:** new code lands in `feature-host` (the host broadcasting
  feature module introduced by AND-307/AND-308) and `core-network`/`core-model`/`core-data`.
- **Upstream dependency — AND-308 (WebRTC ingest):** owns the `inputs` + `webrtc-offer`
  publish path and the `HostBroadcastSession`/ingest objects this ticket controls.
  AND-309 consumes the active session id and the live `PeerConnection` stats source it exposes.
- **Sibling — AND-307 (create/schedule):** owns session creation and the initial
  schedule; AND-309 reuses its `HostSession` model and reschedule semantics.
- **Web reference:** host control endpoints mirror `frontend/src/api/endpoints/host*.ts`
  and shared types in `frontend/src/api/types.ts`. Confirm exact paths against
  `/openapi.json` on the dev backend before wiring.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext,
  unreliable). Cookie-based session + `X-CSRF-Token` echo of `ui_csrf` cookie; on 401
  call `POST /ui/session/refresh` once then retry. All mutations here are non-idempotent
  POSTs and therefore are **not** auto-retried (see §7).
- **Auth:** host must be an authenticated, authorized owner of the session (see §8).

## 3. Functional Requirements

FR-1. **Start.** From a session in `scheduled` or `ready` state, the host can take it
live. Issues a start mutation; on success the session transitions to `live` and the
control panel switches to the live layout (stop/pause + health report visible).

FR-2. **Stop.** From a `live` (or `paused`) session the host can end it. Stop is
terminal: it transitions the session to `ended`, tears down the WebRTC publish
(delegated to AND-308's ingest controller), and disables all controls except "Done".
A confirmation dialog gates Stop because it is irreversible.

FR-3. **Resume.** A session that is `paused` (or transiently `interrupted` due to a
dropped ingest) can be resumed back to `live`. Resume is only offered when the server
reports a resumable state; it re-establishes the ingest if needed.

FR-4. **Reschedule.** A session in `scheduled`/`ready` (i.e. not yet live, not ended)
can be moved to a new start time. The host picks a future date/time; the change is
sent to the backend and the displayed scheduled time updates on confirmation.
Rescheduling a `live` or `ended` session is not permitted (control hidden/disabled).

FR-5. **Health report.** While the session is `live` or `paused`, the panel polls a
health endpoint and merges it with local WebRTC `RTCStats` (from AND-308) to display:
ingest state (connected/degraded/disconnected), uplink bitrate (kbps), frames/sec,
dropped-frame %, round-trip time (ms), viewer count, and an overall health badge
(`healthy` / `degraded` / `unhealthy`). The report refreshes on an interval (default
5s) and on each control action.

FR-6. **State-driven affordances.** Each control is shown/enabled strictly per the
current `SessionStatus`. Illegal transitions are never selectable. The mapping is the
single source of truth used both for rendering and for guarding dispatch.

FR-7. **Server-confirmed UI.** No control flips the UI to the target state before the
backend confirms. While a mutation is in flight the relevant button shows a spinner and
all controls are disabled to prevent double-dispatch.

FR-8. **Offline/stale handling.** If health polling fails or the device is offline, the
last-known report is shown with a "stale as of <time>" banner; controls that require
the server remain available but will surface errors on failure (see §7).

## 4. Technical Design

### Layering
`feature-host` (Compose UI + ViewModel) → `core-data` (HostControlRepository) →
`core-network` (HostControlApi via Retrofit) → backend. Models in `core-model`.

### Model (core-model)

```kotlin
enum class SessionStatus { SCHEDULED, READY, LIVE, PAUSED, INTERRUPTED, ENDED, CANCELLED }

data class HostSession(
    val id: String,
    val title: String,
    val status: SessionStatus,
    val scheduledStartAt: Instant?,   // null once live/ended
    val startedAt: Instant?,
    val endedAt: Instant?,
    val resumable: Boolean,           // server hint for FR-3
)

enum class HealthLevel { HEALTHY, DEGRADED, UNHEALTHY, UNKNOWN }

data class HostHealthReport(
    val level: HealthLevel,
    val ingestConnected: Boolean,
    val uplinkKbps: Int?,
    val fps: Int?,
    val droppedFramePct: Double?,
    val rttMs: Int?,
    val viewerCount: Int?,
    val capturedAt: Instant,
)
```

### Allowed transitions (FR-6, single source of truth)

```kotlin
object HostControlPolicy {
    fun canStart(s: SessionStatus) = s == SessionStatus.SCHEDULED || s == SessionStatus.READY
    fun canStop(s: SessionStatus)  = s == SessionStatus.LIVE || s == SessionStatus.PAUSED ||
                                     s == SessionStatus.INTERRUPTED
    fun canResume(s: SessionStatus, resumable: Boolean) =
        resumable && (s == SessionStatus.PAUSED || s == SessionStatus.INTERRUPTED)
    fun canReschedule(s: SessionStatus) =
        s == SessionStatus.SCHEDULED || s == SessionStatus.READY
}
```

### ViewModel (feature-host)

```kotlin
@HiltViewModel
class HostControlViewModel @Inject constructor(
    private val repo: HostControlRepository,
    private val ingest: HostIngestController,   // provided by AND-308
    savedState: SavedStateHandle,
) : ViewModel() {
    private val sessionId: String = savedState["sessionId"]!!
    val uiState: StateFlow<HostControlUiState>

    fun onStart()
    fun onStop()
    fun onResume()
    fun onReschedule(newStartAt: Instant)
    fun onConfirmStopDialog(confirmed: Boolean)
    fun retryHealth()
}

data class HostControlUiState(
    val session: HostSession? = null,
    val health: HostHealthReport? = null,
    val healthStale: Boolean = false,
    val inFlight: HostAction? = null,        // disables controls while non-null
    val showStopConfirm: Boolean = false,
    val transientError: UiError? = null,     // one-shot, consumed by UI
    val loading: Boolean = true,
)

enum class HostAction { START, STOP, RESUME, RESCHEDULE }
```

Health polling runs inside `viewModelScope` as a `while` loop guarded by `status in {LIVE, PAUSED, INTERRUPTED}`, cancelled in `onCleared()` and suspended when the
session is not live. Local `RTCStats` from `HostIngestController.statsFlow` is merged
with the server report; when they disagree the server's `level`/`ingestConnected` wins
for the badge while bitrate/fps prefer the more recent local sample.

### UI (Compose / Material 3)
`HostControlScreen(viewModel)` renders a status header (title + status chip + live
timer), a `HealthReportCard`, and a `HostControlBar` whose buttons are gated by
`HostControlPolicy`. A `DatePickerDialog`+`TimePickerDialog` pair backs reschedule.
The Stop confirmation uses an `AlertDialog`. In-flight actions render a button-level
`CircularProgressIndicator` and disable the whole bar.

## 5. API Contract

All paths are under the cookie-authenticated `/ui` surface; verify exact shapes against
`/openapi.json`. All bodies are JSON; all mutations send `X-CSRF-Token`.

**Start** — `POST /ui/host/sessions/{id}/start`
Request: `{}` (empty body). Response 200:
```json
{ "id": "ses_123", "status": "live", "started_at": "2026-06-05T18:00:00Z" }
```

**Stop** — `POST /ui/host/sessions/{id}/stop`
Request: `{}`. Response 200:
```json
{ "id": "ses_123", "status": "ended", "ended_at": "2026-06-05T18:42:10Z" }
```

**Resume** — `POST /ui/host/sessions/{id}/resume`
Request: `{}`. Response 200: `{ "id": "ses_123", "status": "live" }`.
409 if not resumable.

**Reschedule** — `POST /ui/host/sessions/{id}/reschedule`
Request:
```json
{ "scheduled_start_at": "2026-06-08T15:00:00Z" }
```
Response 200:
```json
{ "id": "ses_123", "status": "scheduled", "scheduled_start_at": "2026-06-08T15:00:00Z" }
```
422 if `scheduled_start_at` is in the past or session not reschedulable.

**Health** — `GET /ui/host/sessions/{id}/health`  (idempotent → retry-eligible, §7)
Response 200:
```json
{
  "level": "degraded",
  "ingest_connected": true,
  "uplink_kbps": 1850,
  "fps": 24,
  "dropped_frame_pct": 3.4,
  "rtt_ms": 180,
  "viewer_count": 12,
  "captured_at": "2026-06-05T18:05:00Z"
}
```

**Retrofit service (core-network):**

```kotlin
interface HostControlApi {
    @POST("ui/host/sessions/{id}/start")
    suspend fun start(@Path("id") id: String): HostSessionDto
    @POST("ui/host/sessions/{id}/stop")
    suspend fun stop(@Path("id") id: String): HostSessionDto
    @POST("ui/host/sessions/{id}/resume")
    suspend fun resume(@Path("id") id: String): HostSessionDto
    @POST("ui/host/sessions/{id}/reschedule")
    suspend fun reschedule(@Path("id") id: String, @Body body: RescheduleRequest): HostSessionDto
    @GET("ui/host/sessions/{id}/health")
    suspend fun health(@Path("id") id: String): HostHealthDto
}

data class RescheduleRequest(@Json(name = "scheduled_start_at") val scheduledStartAt: String)
```

Repository methods return `ApiResult<T>` (`Success`/`Error(detail)`). FastAPI `detail`
is decoded via the shared mapper handling `string | [{msg}] | {code,...}`.

## 6. Data & State Management

- **In-flight session:** the canonical `HostSession` is owned by `HostControlRepository`
  and exposed as `StateFlow<HostSession?>`. Mutations update this flow from the server
  response so the UI is always server-confirmed (FR-7). The repository is a singleton
  scoped to the host-broadcast graph.
- **DataStore (prefs):** persist the last active `sessionId` and last-known
  `SessionStatus` so the app can reattach to an in-progress broadcast after process death
  and re-fetch authoritative state on resume. Persist health-poll interval if made
  configurable (default 5s).
- **Room (cache):** health reports are **ephemeral**; only the single most-recent
  `HostHealthReport` is retained (in-memory + a single-row DataStore snapshot used solely
  to render the "stale as of" banner offline). No history table is required for this ticket.
- **No optimistic writes.** Local state mutates only after a `Success` response or, for
  failures, reverts to the prior server state and raises `transientError`.
- **Live timer** derives from `startedAt`; recomputed each second via a `Flow` tick,
  independent of network.

## 7. Error Handling & Resilience

- **Timeouts:** dev backend is unreliable — OkHttp call timeout 20s for all host
  endpoints. Health GET additionally uses a shorter 8s read timeout so a slow poll does
  not stall the loop.
- **Retry policy:** only the **idempotent health GET** is retried (bounded exponential
  backoff, max 2 retries, 500ms→2s). Start/stop/resume/reschedule are non-idempotent
  POSTs and are **never** auto-retried; failures surface to the user with an explicit
  manual retry affordance.
- **401:** the OkHttp authenticator calls `POST /ui/session/refresh` once and replays
  the original request; a second 401 routes to re-auth and aborts the action.
- **409 (resume not resumable) / 422 (bad reschedule):** mapped to inline,
  human-readable messages; UI re-syncs from server state.
- **Health poll failure / offline:** keep last report, set `healthStale = true`, show
  "stale as of <capturedAt>" banner; loop continues with backoff. Controls remain usable.
- **Ingest drop during live:** if `HostIngestController` reports disconnect, UI shows
  `INTERRUPTED` and offers **Resume**; the server health endpoint is the tiebreaker.
- **Double-dispatch guard:** `inFlight != null` disables the entire control bar.
- **Process death mid-broadcast:** on relaunch, reattach via persisted `sessionId`,
  fetch fresh session + health, and reconcile (e.g. server says `ended` → show ended).

## 8. Security & Privacy

- All endpoints are cookie-authenticated; a persistent cookie jar (OkHttp
  `PersistentCookieJar` backed by encrypted DataStore) is required as established
  project-wide. Mutations must echo the `ui_csrf` cookie as the `X-CSRF-Token` header.
- **Authorization:** only the session owner may control it; backend enforces ownership
  and returns 403 for non-owners. UI hides host controls unless `GET /ui/me` confirms the
  current user owns the session.
- **Stop is irreversible** and tears down media capture; gated behind explicit
  confirmation to avoid accidental termination of a live broadcast.
- **No PII in health telemetry** beyond aggregate viewer count; no viewer identities are
  exposed to the host through this surface.
- Plaintext HTTP dev host: never log cookies, CSRF token, or full URLs with session ids
  at non-debug levels.

## 9. Accessibility & i18n

- All controls have `contentDescription`/`semantics` (e.g. "Start broadcast",
  "Stop broadcast", "Resume broadcast", "Reschedule"). The status chip and health badge
  expose their meaning as text, not color alone (color + label + icon).
- Health metrics announced via `liveRegion = LiveRegionMode.Polite` so screen-reader
  users hear meaningful changes (e.g. ingest disconnected) without spamming on every tick.
- Touch targets ≥ 48dp; control bar reflows for large-font and landscape.
- All strings in `strings.xml` (no hardcoded UI text); date/time pickers and the live
  timer use locale-aware formatting (`DateTimeFormatter` with device locale/zone).
  Numeric metrics formatted via `NumberFormat`.

## 10. Telemetry & Logging

- Emit analytics events: `host_start`, `host_stop`, `host_resume`, `host_reschedule`
  (each with `session_id`, outcome `success|error`, error code, latency ms), and
  `host_health_sample` (sampled, e.g. 1-in-12 ticks) with `level`, `uplink_kbps`, `fps`,
  `dropped_frame_pct`, `rtt_ms`, `viewer_count`.
- Structured logs at INFO for control dispatch/result, WARN for health-stale/offline,
  ERROR for failed mutations (with mapped `detail`, never raw cookies/CSRF).
- A `health_degraded` / `health_unhealthy` event fires on transitions between health
  levels (edge-triggered, not per-tick) to aid post-broadcast diagnosis.

## 11. Testing Strategy

- **Unit — `HostControlPolicy`:** exhaustive table tests over all `SessionStatus` ×
  control combinations asserting the exact allowed/blocked matrix (FR-6).
- **Unit — ViewModel (`core-testing`, Turbine + `MainDispatcherRule`):**
  - start: `SCHEDULED` → in-flight → `LIVE`, controls update, no optimistic flip.
  - stop: requires confirm dialog; confirm → `ENDED`, ingest teardown invoked.
  - resume: offered only when `resumable`; 409 maps to error + state re-sync.
  - reschedule: past time rejected (422) → inline error; valid time updates
    `scheduledStartAt`.
  - health loop: emits reports on interval; on failure sets `healthStale` and keeps
    last report; resumes after recovery.
  - double-dispatch: second action ignored while `inFlight != null`.
- **Network — `HostControlApi`:** MockWebServer tests for each path incl. 200/401(refresh
  + replay)/403/409/422; verify `X-CSRF-Token` header present on POSTs; health GET retried
  with backoff, POSTs not retried.
- **UI — Compose:** `createAndroidComposeRule` tests assert button enablement per status,
  spinner during in-flight, stop confirmation dialog, stale banner, and semantics labels.
- **Manual / live:** against dev backend, run a real session create→ingest→start→
  health→reschedule(while scheduled)→resume→stop happy path and verify
  server-confirmed transitions (acceptance: "lifecycle controls work live").

## 12. Dependencies & Sequencing

- **Depends on AND-308 (WebRTC ingest)** — requires the active `HostBroadcastSession`,
  `HostIngestController` (teardown + `statsFlow`), and the publish path. AND-309 cannot be
  exercised live without ingest.
- Transitively depends on **AND-307** (session create/schedule) for the `HostSession`
  model and reschedule semantics, and on **AND-290** (via AND-308) for media plumbing.
- Relies on existing project infrastructure: cookie jar + CSRF interceptor + 401 refresh
  authenticator, `ApiResult`/`detail` mapper, Hilt graph, DataStore.
- **Blocks:** none recorded in backlog. Downstream host UX polish/notification tickets in
  M7 may build on these controls but are not listed as dependents here.
- Sequencing: implement model + policy + API first (testable in isolation), then
  repository, then ViewModel + health loop, then Compose UI, then live integration with
  AND-308's ingest controller.

## 13. Risks & Open Questions

- **R1 — Exact endpoint paths/verbs.** Assumed `/ui/host/sessions/{id}/{action}`; must be
  confirmed against `/openapi.json` and `frontend/src/api/endpoints/host*.ts`. Mitigation:
  thin API layer, single point of change.
- **R2 — Resume semantics.** Unclear whether resume re-uses the prior ingest or requires a
  fresh `webrtc-offer`. Open question for AND-308 owner; design routes resume through
  `HostIngestController` so either is accommodated.
- **R3 — Health source of truth.** Server health vs local `RTCStats` may diverge; current
  rule (server wins for badge, local preferred for fresh bitrate/fps) may need tuning after
  live testing.
- **R4 — Reschedule of a `live` session.** Backend behavior undefined; spec forbids it
  client-side. Confirm server rejects with 422 to keep client/server consistent.
- **R5 — Backend unreliability** could make a control appear to fail after it actually
  succeeded (response lost). Because POSTs are not retried, the UI re-fetches authoritative
  session state on error so the user sees true state; confirm endpoints are safe to re-issue
  if the user manually retries.
- **Open:** is the health poll interval server-configurable, and is there a push (SSE/WS)
  channel that should replace polling later? Out of scope here.

## 14. Acceptance Criteria

AC-1. From a `scheduled`/`ready` session, **Start** takes it `live`; UI switches to live
layout only after server confirmation. (FR-1, FR-7)

AC-2. **Stop** requires confirmation, transitions the session to `ended`, tears down
ingest, and disables further controls. (FR-2)

AC-3. **Resume** is offered only when the server reports the session resumable; resuming a
`paused`/`interrupted` session returns it to `live`; a non-resumable resume (409) shows an
error and re-syncs state. (FR-3)

AC-4. **Reschedule** is available only pre-live; a valid future time updates the displayed
scheduled time on confirmation; a past time is rejected (422) with an inline message. (FR-4)

AC-5. While live/paused, the **health report** refreshes on interval and shows ingest
state, bitrate, fps, dropped-frame %, RTT, viewer count, and an overall badge; on poll
failure the last report is shown with a "stale as of" banner. (FR-5, FR-8)

AC-6. Controls are enabled strictly per `HostControlPolicy`; illegal transitions are never
selectable, and no control is dispatchable while another action is in flight. (FR-6, FR-7)

AC-7. All host mutations send `X-CSRF-Token`; a single 401 triggers refresh-and-retry; only
the health GET is auto-retried. (§7, §8)

AC-8. End-to-end against the dev backend: create→ingest→start→health→reschedule→resume→stop
all succeed with server-confirmed state ("lifecycle controls work live").

## 15. Definition of Done

- All Functional Requirements (FR-1..FR-8) implemented in `feature-host` + supporting
  `core-*` modules under `com.testlogon.android`.
- `HostControlApi`, `HostControlRepository`, `HostControlViewModel`, `HostControlPolicy`,
  and `HostControlScreen` merged with the signatures in §4–§5 (or documented deviations).
- Unit, network (MockWebServer), and Compose UI tests in §11 pass in CI; `HostControlPolicy`
  matrix has 100% branch coverage.
- One successful manual live run against `http://18.222.237.167:8000` recorded, covering all
  four controls + health (AC-8).
- Accessibility (semantics, 48dp targets, live region) and i18n (no hardcoded strings,
  locale-aware date/time/number formatting) verified.
- Telemetry events (§10) emitted and validated; no secrets logged.
- Endpoint paths reconciled against `/openapi.json`; open questions R1–R5 either resolved or
  filed as follow-ups with owners.
- `./gradlew :feature-host:lint :feature-host:test` and detekt pass on `android-port`.
