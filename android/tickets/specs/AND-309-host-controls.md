---
id: AND-309
title: Host controls
milestone: M7
epic: E41
priority: P0
size: M
depends_on: [AND-308]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
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
- **Web reference (CORRECTED):** there is **no** `host*.ts` file. The control endpoints
  live in `frontend/src/api/endpoints/broadcast.ts` (`startSession`, `stopSession`,
  `getHealth`, `reportHealth`, `getHealthHistory`), `broadcastSchedule.ts`
  (`rescheduleSession`), and `broadcastPrivate.ts` (`resumeBroadcast`). The shared DTOs
  (`BroadcastSession`, `BroadcastHealthResponse`) are declared **inline in those files**,
  not in `frontend/src/api/types.ts`. All paths are under `/broadcast/sessions/{id}/...`
  (NOT `/ui/host/sessions/...`). Verified against `reference/openapi.index.txt`.
- **Backend (CORRECTED):** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext, unreliable). The web client (`src/api/client.ts`) authenticates with
  **both** an `Authorization: Bearer <accessToken>` header *and* cookies
  (`credentials: include`), and sends `X-CSRF-Token` (echo of the `ui_csrf` cookie) on
  **every** request (GET and POST alike), not only mutations. It also forwards
  `X-IMPERSONATION-TOKEN` when impersonating. On 401 it calls `POST /ui/session/refresh`
  once then replays the original request. Start/stop are non-idempotent POSTs (the backend
  accepts an optional `x-idempotency-key` param) and are **not** auto-retried (see §7).
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

> **CORRECTION (wire status values).** The backend `status` is a free-form **string**
> (`BroadcastSessionOut.status`, not an enum). The actual values used by the web client
> (`broadcast.ts: BroadcastSessionStatus`) are:
> `draft | scheduled | provisioning | ready | live | stopping | stopped | cancelled | error`.
> There is **no** `paused`, **no** `interrupted`, and the terminal state is `stopped`
> (not `ended`). The client enum below should therefore map: `STOPPED` (not `ENDED`),
> add `DRAFT/PROVISIONING/STOPPING/ERROR`, and treat `PAUSED`/`INTERRUPTED` as
> client-only synthetic states (e.g. derived from local ingest drop) — they are NOT
> server-reported, so `canResume` cannot rely on a server `paused` status. Confirm the
> resume endpoint's accepted source states with the AND-308 owner (see R2/§16).

```kotlin
// NOTE: STOPPED replaces ENDED; PAUSED/INTERRUPTED are client-synthetic (see correction above).
enum class SessionStatus { DRAFT, SCHEDULED, PROVISIONING, READY, LIVE, STOPPING, STOPPED, CANCELLED, ERROR, PAUSED, INTERRUPTED }

// CORRECTED field mapping to BroadcastSessionOut:
//   title       -> wire `name` (nullable string); there is no `title` field.
//   scheduledStartAt -> wire `scheduled_at` is an INTEGER Unix timestamp (epoch seconds), nullable.
//   startedAt   -> wire `started_at` is an ISO-8601 STRING (nullable).
//   endedAt     -> wire `stopped_at` (ISO string, nullable); there is no `ended_at`.
//   resumable   -> NOT present in BroadcastSessionOut; the server gives no resumable hint.
//                  Must be derived client-side (e.g. from local ingest state) — see R2/§16.
data class HostSession(
    val id: String,
    val name: String?,                // wire: name (nullable)
    val status: SessionStatus,        // wire: free string -> mapped, unknown -> a fallback
    val scheduledAt: Instant?,        // wire: scheduled_at (epoch SECONDS, Int) -> Instant
    val startedAt: Instant?,          // wire: started_at (ISO string)
    val stoppedAt: Instant?,          // wire: stopped_at (ISO string); replaces endedAt
    val resumable: Boolean,           // CLIENT-DERIVED (no server field); see FR-3 / R2
)

// CORRECTED to match BroadcastHealthOut (wire field names in comments). NOTE: the server
// has NO `level`, NO `ingest_connected`, and NO `rtt_ms`. It exposes `connection_quality`
// (a free string), and timestamps as `updated_at` (epoch SECONDS integer, not ISO).
// `level`/`ingestConnected`/`rttMs` below are CLIENT-DERIVED (badge mapping + local RTCStats).
enum class HealthLevel { HEALTHY, DEGRADED, UNHEALTHY, UNKNOWN }

data class HostHealthReport(
    val connectionQuality: String,    // wire: connection_quality (string; map -> level badge)
    val level: HealthLevel,           // CLIENT-DERIVED from connection_quality
    val ingestBitrateKbps: Int,       // wire: ingest_bitrate_kbps (required)
    val ingestFramerate: Double,      // wire: ingest_framerate (required, number)
    val droppedFrames: Int,           // wire: dropped_frames (required)
    val droppedFramesPct: Double,     // wire: dropped_frames_pct (required)
    val outputErrors: Int,            // wire: output_errors (required)
    val inputLossSeconds: Double,     // wire: input_loss_seconds (required)
    val viewerCount: Int,             // wire: viewer_count (required)
    val sessionId: String,            // wire: session_id (required)
    val updatedAt: Instant,           // wire: updated_at (epoch SECONDS integer)
    val rttMs: Int? = null,           // CLIENT-ONLY from local RTCStats; NOT a server field
    val ingestConnected: Boolean? = null, // CLIENT-DERIVED; NOT a server field
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

> **CORRECTED.** The real surface is `/broadcast/sessions/{session_id}/...`, NOT
> `/ui/host/sessions/...`. Auth is `Authorization: Bearer` + cookies; `X-CSRF-Token`
> (echo of `ui_csrf`) is sent on **all** requests (incl. GET), per `src/api/client.ts`.
> Path param name in OpenAPI is `session_id`. Start/stop are documented as **202 Accepted**
> (async provider work), not 200. Resume/reschedule are 200. Only `422 HTTPValidationError`
> is documented for the error cases (the 409 previously claimed for resume is NOT in the
> OpenAPI — treat as unverified, see §16).

**Start** — `POST /broadcast/sessions/{session_id}/start`  (op `start_session_route…`)
Request body `BroadcastSessionActionIn`: `{ "reason": "operator-request" }` (`reason` optional,
1–512 chars, defaults to `"operator-request"`; web client sends it explicitly). Optional headers
`x-correlation-id`, `x-idempotency-key`. **Response 202** = `BroadcastSessionOut` (full session):
```json
{ "id": "ses_123", "status": "live", "started_at": "2026-06-05T18:00:00Z",
  "profile_id": "prof_1", "created_by": "usr_1", "created_at": "...", "updated_at": "..." }
```

**Stop** — `POST /broadcast/sessions/{session_id}/stop`  (op `stop_session_route…`)
Request `BroadcastSessionActionIn` (same `{ "reason": ... }`). Optional `x-idempotency-key`.
**Response 202** = `BroadcastSessionOut`. Terminal status is `"stopped"` with `stopped_at`
(ISO string) — NOT `ended`/`ended_at`:
```json
{ "id": "ses_123", "status": "stopped", "stopped_at": "2026-06-05T18:42:10Z", "...": "..." }
```

**Resume** — `POST /broadcast/sessions/{session_id}/resume`  (op `resume_broadcast_route…`,
web: `broadcastPrivate.ts: resumeBroadcast`)
Request: **no body**. Response 200 = `BroadcastSessionOut`. OpenAPI documents only
`422 HTTPValidationError`; a 409 "not resumable" is an **unverified assumption** (§16).

**Reschedule** — `POST /broadcast/sessions/{session_id}/reschedule`  (op
`reschedule_session_route…`, web: `broadcastSchedule.ts: rescheduleSession`)
Request `BroadcastRescheduleIn`: `scheduled_at` is an **integer Unix timestamp**
(epoch seconds), NOT `scheduled_start_at` ISO:
```json
{ "scheduled_at": 1781622000 }
```
Response 200 = `BroadcastSessionOut` (with updated integer `scheduled_at`).
`422 HTTPValidationError` if `scheduled_at` is in the past / below min lead time or the
session is not reschedulable.

**Health** — `GET /broadcast/sessions/{session_id}/health`  (op `get_session_health_route…`;
idempotent → retry-eligible, §7). **Response 200** = `BroadcastHealthOut`. Field names differ
from the original draft (no `level`/`ingest_connected`/`uplink_kbps`/`fps`/`rtt_ms`/`captured_at`):
```json
{
  "session_id": "ses_123",
  "connection_quality": "degraded",
  "ingest_bitrate_kbps": 1850,
  "ingest_framerate": 24.0,
  "dropped_frames": 42,
  "dropped_frames_pct": 3.4,
  "output_errors": 0,
  "input_loss_seconds": 0.0,
  "viewer_count": 12,
  "updated_at": 1749146700
}
```
(Related: `GET …/health/history` → `BroadcastHealthHistoryOut`, and
`POST …/health/report` (`BroadcastHealthReportIn`) which the *publisher* uses to push stats —
out of scope here but available if local RTCStats should be reported upstream.)

**Retrofit service (core-network):**

```kotlin
// CORRECTED paths (/broadcast/sessions/...), bodies, and the reschedule field.
// start/stop return HTTP 202; stop/start carry a SessionActionDto body (reason).
interface HostControlApi {
    @POST("broadcast/sessions/{id}/start")
    suspend fun start(@Path("id") id: String, @Body body: SessionActionDto = SessionActionDto()): HostSessionDto
    @POST("broadcast/sessions/{id}/stop")
    suspend fun stop(@Path("id") id: String, @Body body: SessionActionDto = SessionActionDto()): HostSessionDto
    @POST("broadcast/sessions/{id}/resume")
    suspend fun resume(@Path("id") id: String): HostSessionDto   // no body
    @POST("broadcast/sessions/{id}/reschedule")
    suspend fun reschedule(@Path("id") id: String, @Body body: RescheduleRequest): HostSessionDto
    @GET("broadcast/sessions/{id}/health")
    suspend fun health(@Path("id") id: String): HostHealthDto
}

// reason 1..512 chars; backend default "operator-request"
data class SessionActionDto(@Json(name = "reason") val reason: String = "operator-request")
// CORRECTED: integer Unix timestamp (epoch seconds), field name scheduled_at
data class RescheduleRequest(@Json(name = "scheduled_at") val scheduledAt: Long)
```

> **Auth transport note (CORRECTED).** Do NOT special-case CSRF to mutations only: the web
> client attaches `X-CSRF-Token` to every request, and an `Authorization: Bearer` header in
> addition to cookies. The Android OkHttp stack must mirror both (CSRF interceptor on all
> verbs + bearer token), plus forward `X-IMPERSONATION-TOKEN` if impersonation is supported.

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
- **422 (bad reschedule, and any invalid action):** the documented error for these
  endpoints is `422 HTTPValidationError` (FastAPI). Map its `detail` (`string | [{msg}] |
  {code,...}`, per `src/api/client.ts: normalizeErrorDetail`) to inline messages; UI
  re-syncs from server state. **CORRECTION:** a dedicated `409 not-resumable` is NOT in the
  OpenAPI — handle resume rejection as 422 (and treat 409, if it appears at runtime,
  defensively). Unverified, see §16.
- **Health poll failure / offline:** keep last report, set `healthStale = true`, show
  "stale as of <capturedAt>" banner; loop continues with backoff. Controls remain usable.
- **Ingest drop during live:** if `HostIngestController` reports disconnect, UI shows
  `INTERRUPTED` and offers **Resume**; the server health endpoint is the tiebreaker.
- **Double-dispatch guard:** `inFlight != null` disables the entire control bar.
- **Process death mid-broadcast:** on relaunch, reattach via persisted `sessionId`,
  fetch fresh session + health, and reconcile (e.g. server says `ended` → show ended).

## 8. Security & Privacy

- Endpoints are authenticated by **both** a bearer token (`Authorization: Bearer`) and
  cookies (per `src/api/client.ts`); a persistent cookie jar (OkHttp `PersistentCookieJar`
  backed by encrypted DataStore) is required as established project-wide.
  **CORRECTION:** the `ui_csrf` cookie must be echoed as `X-CSRF-Token` on **every** request
  (GET health polling included), not only mutations.
- **Authorization:** only an authorized owner/operator may control a session; backend
  returns 403 for non-owners (`detail` may carry a `code` like `role_required`, mapped via
  `normalizeErrorDetail`). UI hides host controls unless `GET /ui/me` confirms the current
  user. **Note:** `BroadcastSessionOut` has `created_by` but exposes no explicit "is owner"
  flag, so ownership is inferred from `created_by` == current user (or enforced purely
  server-side via 403); confirm the exact rule (§16, Open assumptions).
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

- **R1 — Exact endpoint paths/verbs. [RESOLVED]** The original `/ui/host/sessions/...`
  guess was wrong; confirmed against `openapi.index.txt` and the web client as
  `/broadcast/sessions/{session_id}/{start|stop|resume|reschedule|health}` (start/stop=POST
  202, resume/reschedule=POST 200, health=GET 200). Mitigation retained: thin API layer.
- **R2 — Resume semantics.** Unclear whether resume re-uses the prior ingest or requires a
  fresh `webrtc-offer`. Open question for AND-308 owner; design routes resume through
  `HostIngestController` so either is accommodated.
- **R3 — Health source of truth.** Server health vs local `RTCStats` may diverge; current
  rule (server wins for badge, local preferred for fresh bitrate/fps) may need tuning after
  live testing.
- **R4 — Reschedule of a `live`/`stopped` session.** Backend behavior not enumerated beyond
  `422 HTTPValidationError`; spec forbids it client-side. Confirm server rejects with 422
  (the only documented error code) to keep client/server consistent.
- **R5 — Backend unreliability** could make a control appear to fail after it actually
  succeeded (response lost). Because POSTs are not retried, the UI re-fetches authoritative
  session state on error so the user sees true state; confirm endpoints are safe to re-issue
  if the user manually retries.
- **Open:** is the health poll interval server-configurable, and is there a push (SSE/WS)
  channel that should replace polling later? Out of scope here.

## 14. Acceptance Criteria

AC-1. From a `scheduled`/`ready` session, **Start** takes it `live`; UI switches to live
layout only after server confirmation. (FR-1, FR-7)

AC-2. **Stop** requires confirmation, transitions the session to `stopped` (HTTP 202;
the wire terminal status is `stopped`, not `ended`), tears down ingest, and disables
further controls. (FR-2)

AC-3. **Resume** is offered only when the session is client-resumable (no server
`resumable` field exists — derived client-side); resuming returns the session to `live`;
a rejected resume (422, or a defensively-handled 409) shows an error and re-syncs state. (FR-3)

AC-4. **Reschedule** is available only pre-live; a valid future time updates the displayed
scheduled time on confirmation; a past time is rejected (422) with an inline message. (FR-4)

AC-5. While live/paused, the **health report** refreshes on interval and shows ingest
state, bitrate, fps, dropped-frame %, RTT, viewer count, and an overall badge; on poll
failure the last report is shown with a "stale as of" banner. (FR-5, FR-8)

AC-6. Controls are enabled strictly per `HostControlPolicy`; illegal transitions are never
selectable, and no control is dispatchable while another action is in flight. (FR-6, FR-7)

AC-7. All host requests (mutations AND the health GET) send `X-CSRF-Token` plus the bearer
token; a single 401 triggers `POST /ui/session/refresh` then one replay; only the health GET
is auto-retried on transient failure. (§7, §8)

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

## 16. Citations & Assumption Audit

Each numbered item: the claim, VERDICT (Verified / Corrected / Unverified-assumption), and SOURCE.

1. **Start endpoint** is `POST /broadcast/sessions/{session_id}/start`, returns **202** with a
   `BroadcastSessionOut`, request `BroadcastSessionActionIn` (`reason`, optional). — **Corrected**
   (draft said `POST /ui/host/sessions/{id}/start`, empty body, 200).
   Source: OpenAPI `POST /broadcast/sessions/{session_id}/start` (op `start_session_route…`,
   resp `202:BroadcastSessionOut`); `src/api/endpoints/broadcast.ts: startSession`;
   schema `BroadcastSessionActionIn`.
2. **Stop endpoint** is `POST /broadcast/sessions/{session_id}/stop`, returns **202**
   `BroadcastSessionOut`; terminal status is `stopped` with `stopped_at`. — **Corrected**
   (draft said `/ui/host/...`, 200, `ended`/`ended_at`).
   Source: OpenAPI `POST /broadcast/sessions/{session_id}/stop` (`202:BroadcastSessionOut`);
   `broadcast.ts: stopSession`; `BroadcastSessionOut.status` / `stopped_at` (string).
3. **Resume endpoint** is `POST /broadcast/sessions/{session_id}/resume`, **no body**, 200
   `BroadcastSessionOut`. — **Corrected** (path).
   Source: OpenAPI `POST /broadcast/sessions/{session_id}/resume` (`resume_broadcast_route…`,
   `req=`, `200:BroadcastSessionOut`); `src/api/endpoints/broadcastPrivate.ts: resumeBroadcast`.
4. **Reschedule endpoint** is `POST /broadcast/sessions/{session_id}/reschedule`, body
   `BroadcastRescheduleIn` with field **`scheduled_at`** (integer Unix timestamp), 200
   `BroadcastSessionOut`. — **Corrected** (draft used `scheduled_start_at` ISO string).
   Source: OpenAPI `POST /broadcast/sessions/{session_id}/reschedule`; schema
   `BroadcastRescheduleIn` (`scheduled_at: integer`, "New Unix timestamp, >= min lead time");
   `src/api/endpoints/broadcastSchedule.ts: rescheduleSession` / `RescheduleSessionReq`.
5. **Health endpoint** is `GET /broadcast/sessions/{session_id}/health`, 200 `BroadcastHealthOut`
   with fields `session_id, viewer_count, ingest_bitrate_kbps, ingest_framerate, dropped_frames,
   dropped_frames_pct, connection_quality, output_errors, input_loss_seconds, updated_at(int epoch)`.
   — **Corrected** (draft used `level, ingest_connected, uplink_kbps, fps, dropped_frame_pct,
   rtt_ms, captured_at`, none of which exist).
   Source: OpenAPI `GET /broadcast/sessions/{session_id}/health` (`200:BroadcastHealthOut`);
   schema `BroadcastHealthOut`; `src/api/endpoints/broadcast.ts: getHealth` /
   `BroadcastHealthResponse`.
6. **No `rtt_ms` / `ingest_connected` server field.** RTT and ingest-connected are client-derived
   from local WebRTC `RTCStats` (AND-308). — **Corrected/Unverified mapping** (server gives
   `connection_quality` string + `input_loss_seconds`). Source: schema `BroadcastHealthOut` (no
   such fields); framework ref WebRTC `RTCStatsReport`
   https://developer.mozilla.org/en-US/docs/Web/API/RTCStatsReport .
7. **Session status values** are `draft|scheduled|provisioning|ready|live|stopping|stopped|
   cancelled|error`; `status` is a free string in the schema. There is no `paused`/`interrupted`/
   `ended`. — **Corrected** (draft enum invented `PAUSED/INTERRUPTED/ENDED`).
   Source: `src/api/endpoints/broadcast.ts: BroadcastSessionStatus`; schema
   `BroadcastSessionOut.status` (plain string).
8. **No server `resumable` hint.** `BroadcastSessionOut` has no resumable field; FR-3 gating must
   be client-derived. — **Corrected** (draft modeled `resumable: Boolean` as a server hint).
   Source: schema `BroadcastSessionOut` (properties list).
9. **Session fields**: `name` (nullable, not `title`), `scheduled_at` (integer epoch, nullable),
   `started_at`/`stopped_at` (ISO strings, nullable), `created_by`, `id`, `profile_id`. — **Corrected**
   (draft used `title`, `endedAt`, and an Instant `scheduledStartAt`).
   Source: schema `BroadcastSessionOut`; `broadcast.ts: BroadcastSession`.
10. **Auth transport**: client sends `Authorization: Bearer <accessToken>` **and** cookies
    (`credentials: include`); `X-CSRF-Token` (from `ui_csrf` cookie) on **every** request, plus
    `X-IMPERSONATION-TOKEN` when impersonating. — **Corrected** (draft said cookie-only, CSRF on
    mutations only). Source: `src/api/client.ts` (lines setting Authorization, csrf, impersonation).
11. **401 handling**: one `POST /ui/session/refresh`, then a single replay of the original request;
    a second 401 logs out. — **Verified.** Source: `src/api/client.ts: refreshSession` + 401 block;
    OpenAPI `POST /ui/session/refresh` (`200:`).
12. **Error `detail` shape** is `string | [{msg}] | {code,...}` and is normalized for display.
    — **Verified.** Source: `src/api/client.ts: normalizeErrorDetail` / `mapAuthorizationError`;
    OpenAPI `HTTPValidationError` (422) used by all these routes.
13. **`/ui/me` exists** for current-user/ownership confirmation. — **Verified** (endpoint exists);
    ownership rule itself **Unverified** (no owner flag on session). Source: OpenAPI `GET /ui/me`;
    schema `BroadcastSessionOut.created_by`.
14. **Start/stop accept `x-idempotency-key`** (so a manual retry after a lost response is safe);
    resume/reschedule do not list it. — **Verified.** Source: OpenAPI params on
    `…/start` and `…/stop` (`x-correlation-id,x-idempotency-key`).
15. **Health report ingestion path** `POST /broadcast/sessions/{id}/health/report`
    (`BroadcastHealthReportIn`) and history `GET …/health/history` (`BroadcastHealthHistoryOut`)
    exist. — **Verified** (referenced as adjacent, out of scope). Source: OpenAPI those two ops;
    `broadcast.ts: reportHealth, getHealthHistory`.
16. **Framework choices** (Compose Material 3 control UI, Hilt VM, OkHttp/Retrofit transport,
    DataStore persistence, `viewModelScope` polling loop). — **Unverified-assumption** (project
    convention, not in sources). Framework refs: Compose
    https://developer.android.com/jetpack/compose , Hilt
    https://developer.android.com/training/dependency-injection/hilt-android , DataStore
    https://developer.android.com/topic/libraries/architecture/datastore , `liveRegion`
    https://developer.android.com/reference/kotlin/androidx/compose/ui/semantics/LiveRegionMode .

### Corrections made
- C1. Endpoint base `/ui/host/sessions/{id}` → `/broadcast/sessions/{session_id}` for all five
  controls (items 1–5).
- C2. Start/stop response code 200 → **202**; bodies are full `BroadcastSessionOut`, and stop/start
  carry an optional `reason` (`BroadcastSessionActionIn`), not an empty `{}` (items 1–2).
- C3. Reschedule field `scheduled_start_at` (ISO string) → **`scheduled_at`** (integer Unix
  timestamp) (item 4; §5 + Retrofit DTO).
- C4. Health DTO fully reshaped to `BroadcastHealthOut` (no `level/ingest_connected/uplink_kbps/
  fps/rtt_ms/captured_at`; real fields incl. `connection_quality`, `updated_at` epoch int) (item 5).
- C5. Session status enum/fields corrected: real string values, `stopped` not `ended`,
  `stopped_at`/`name`/`scheduled_at(int)`; `resumable` is client-derived (items 7–9).
- C6. Auth corrected to bearer **and** cookies, CSRF on every request, plus impersonation header
  (item 10; §2, §5, §8).
- C7. Resume "409 not resumable" downgraded to a defensive assumption; documented error is 422
  (item below; §7).

### Open assumptions
- A1. **Resume 409.** OpenAPI documents only `422 HTTPValidationError` for resume; the draft's
  dedicated `409 not-resumable` cannot be confirmed. Treated as unverified; client handles 422 and
  defends against 409 if it appears. (No source documents 409.)
- A2. **Resume source states / ingest reuse (R2).** Which statuses the backend accepts for resume,
  and whether a fresh `webrtc-offer` is required, is not in the sources — owned by AND-308.
- A3. **Ownership rule.** `BroadcastSessionOut` exposes `created_by` but no explicit owner flag;
  whether the client should gate on `created_by == me` or rely solely on server 403 is unconfirmed.
- A4. **`connection_quality` value set.** The string is free-form in the schema; the exact tokens
  (e.g. `healthy|degraded|unhealthy`) used to drive the badge must be confirmed at runtime.
- A5. **Health poll interval (5s) / push channel.** Not server-specified; a client default. SSE/WS
  replacement remains out of scope (R-Open).
- A6. **Synthetic `paused`/`interrupted`.** These client states (from local ingest drop) have no
  server equivalent; reconciliation against server `status` on each health/action response is the
  intended tiebreaker but is unverifiable without a live drop test.

## 17. Test Plan

Test targets: **JVM** (local JUnit/Robolectric), **MWS** (MockWebServer contract), **Emu** (headless
AVD `test35`, API 35 x86_64), **Phys** (physical Samsung Galaxy A15 5G, SM-A156U, API 34 arm64,
serial R5CX821TA9R). Cases needing real WebRTC media/ingest, FCM, or ABI/API-level behavior MUST run
on **Phys**; deterministic UI/instrumented suites run on **Emu**.

- **TC-AND-309-01 — Start happy path (contract).** Type: contract/MockWebServer (MWS, JVM).
  Target: `HostControlApi.start` + repository.
  Preconditions: MWS enqueues **202** `BroadcastSessionOut` `{status:"live", started_at:"…"}`.
  Steps: call `start(id)` with default `SessionActionDto`. Expected: request is
  `POST /broadcast/sessions/{id}/start`, body `{"reason":"operator-request"}`, header
  `X-CSRF-Token` present and `Authorization: Bearer …`; result maps to `HostSession(status=LIVE,
  startedAt!=null)`; repository `StateFlow` emits server-confirmed LIVE (no optimistic flip).
  Traces: AC-1.
- **TC-AND-309-02 — Stop requires confirm, reaches stopped + teardown (unit).** Type: unit (JVM,
  Turbine). Target: `HostControlViewModel.onStop/onConfirmStopDialog`.
  Preconditions: session LIVE; repo stubbed to return `status:"stopped"` (202).
  Steps: `onStop()` → assert `showStopConfirm=true` and no network call; `onConfirmStopDialog(true)`
  → in-flight STOP, then state STOPPED. Expected: `HostIngestController.teardown()` invoked exactly
  once; controls disabled except Done; cancel path (`false`) issues no request. Traces: AC-2, AC-6.
- **TC-AND-309-03 — Reschedule sends integer `scheduled_at` (contract).** Type: contract/MWS (JVM).
  Target: `HostControlApi.reschedule`.
  Preconditions: MWS enqueues 200 `BroadcastSessionOut` with updated integer `scheduled_at`.
  Steps: `reschedule(id, RescheduleRequest(scheduledAt=1781622000))`. Expected: request body is
  `{"scheduled_at":1781622000}` (integer, NOT `scheduled_start_at`, NOT ISO); response maps to
  `HostSession.scheduledAt`. Traces: AC-4.
- **TC-AND-309-04 — Reschedule past time rejected 422 (contract).** Type: contract/MWS (JVM).
  Target: repository error mapping. Preconditions: MWS enqueues **422** `HTTPValidationError`
  `{"detail":[{"msg":"scheduled_at must be in the future"}]}`.
  Steps: call reschedule with a past timestamp. Expected: `ApiResult.Error` with normalized message
  from `detail[].msg`; UI shows inline error; no optimistic state change; state re-synced. Traces: AC-4.
- **TC-AND-309-05 — Resume rejection handled (contract).** Type: contract/MWS (JVM).
  Target: `HostControlApi.resume` + error mapping. Preconditions: MWS enqueues 422 (and a second
  variant enqueues 409 to verify defensive handling). Steps: call `resume(id)` with **no body**.
  Expected: request is bodiless `POST …/resume`; both 422 and 409 produce a user-visible error and a
  state re-sync (no crash, no state flip). Traces: AC-3.
- **TC-AND-309-06 — Health DTO parses real field names (contract).** Type: contract/MWS (JVM).
  Target: `HostControlApi.health` deserialization. Preconditions: MWS enqueues a literal
  `BroadcastHealthOut` body (`connection_quality, ingest_bitrate_kbps, ingest_framerate,
  dropped_frames, dropped_frames_pct, output_errors, input_loss_seconds, viewer_count, session_id,
  updated_at` epoch int). Steps: GET health. Expected: all fields parse; `updatedAt` converts epoch
  seconds→Instant; `level` is derived from `connection_quality`; absent legacy fields cause no error.
  Traces: AC-5.
- **TC-AND-309-07 — Health GET retried, POSTs never retried (contract).** Type: contract/MWS (JVM).
  Target: OkHttp retry policy. Preconditions: MWS enqueues 503 then 200 for health; 503 once for
  start. Steps: poll health; separately call start. Expected: health retried with bounded backoff
  (≤2 retries) and ultimately succeeds; start surfaces the 503 immediately with **no** auto-retry and
  a manual-retry affordance. Traces: AC-7.
- **TC-AND-309-08 — 401 refresh-and-replay (contract).** Type: contract/MWS (JVM).
  Target: OkHttp authenticator. Preconditions: MWS: first health/start → 401; `POST /ui/session/refresh`
  → 200; replay → 200. Steps: issue a request while a 401 is queued. Expected: exactly one
  `/ui/session/refresh`, then the original request replayed once and succeeding; a second consecutive
  401 aborts to re-auth. Traces: AC-7.
- **TC-AND-309-09 — `HostControlPolicy` matrix (unit).** Type: unit (JVM). Target:
  `HostControlPolicy`. Preconditions: none. Steps: table test over all `SessionStatus` ×
  {start,stop,resume,reschedule} including `resumable` true/false. Expected: start only in
  SCHEDULED/READY; reschedule only in SCHEDULED/READY; stop in LIVE/PAUSED/INTERRUPTED; resume only
  when client-resumable in PAUSED/INTERRUPTED; STOPPED/CANCELLED/ERROR/DRAFT/PROVISIONING/STOPPING
  allow none (except stop where live-ish). 100% branch coverage. Traces: AC-6.
- **TC-AND-309-10 — Offline / stale health banner (unit + Compose).** Type: unit (JVM) + Compose-UI
  (Emu). Target: ViewModel health loop + `HealthReportCard`. Preconditions: one successful health
  sample, then network error (`ApiError(0)`). Steps: let loop fail. Expected: last report retained,
  `healthStale=true`, banner "stale as of <updatedAt>"; loop continues with backoff; controls remain
  usable; banner exposes text (not color-only). Traces: AC-5, AC-8(resilience).
- **TC-AND-309-11 — Double-dispatch guard + spinner (Compose-UI).** Type: Compose-UI (Emu).
  Target: `HostControlScreen`/`HostControlBar`. Preconditions: a slow (delayed) start response.
  Steps: tap Start, then attempt to tap Stop/Start again while in-flight. Expected: whole bar
  disabled, button shows `CircularProgressIndicator`; only one network call issued. Traces: AC-6, AC-7.
- **TC-AND-309-12 — Accessibility & i18n (Compose-UI).** Type: Compose-UI (Emu). Target:
  `HostControlScreen`. Preconditions: rendered live layout. Steps: query semantics; toggle large font
  + locale. Expected: each control has a contentDescription ("Start broadcast"/"Stop broadcast"/
  "Resume broadcast"/"Reschedule"); status chip + health badge convey meaning via text+icon not color
  alone; metrics region is `liveRegion=Polite`; touch targets ≥48dp; no hardcoded strings; date/time
  via locale-aware formatter. Traces: AC-5, AC-6.
- **TC-AND-309-13 — Non-owner 403 hides/blocks controls (instrumented).** Type: instrumented (Emu).
  Target: ViewModel + screen ownership gate. Preconditions: `GET /ui/me` returns a user != session
  `created_by`; control call stubbed to 403 with `detail.code=role_required`. Steps: open screen as
  non-owner; attempt a control. Expected: controls hidden/disabled; if dispatched, 403 mapped to the
  permission message; no media teardown side effects. Traces: AC-7 (security), §8.
- **TC-AND-309-14 — Live e2e: ingest→start→health→reschedule(pre-live)→resume→stop (instrumented/e2e,
  PHYSICAL DEVICE REQUIRED).** Type: instrumented/e2e (**Phys** — needs real camera/mic WebRTC ingest
  from AND-308 and real arm64/API-34 behavior; emulator cannot exercise real capture).
  Preconditions: authenticated owner; dev backend `http://18.222.237.167:8000` reachable; AND-308
  ingest available. Steps: create+ingest a session, Start, observe health refreshing, (on a fresh
  scheduled session) Reschedule to a future time, force an ingest drop and Resume, then Stop with
  confirm. Expected: every transition is server-confirmed (LIVE, updated `scheduled_at`, back to LIVE,
  then `stopped`); health card updates on interval; on flaky-host failures controls show errors and
  re-fetch true state; no secrets logged. Traces: AC-1..AC-8 (esp. AC-8).

### Coverage matrix
| Acceptance criterion | Test case(s) |
|---|---|
| AC-1 Start → live, server-confirmed | TC-01, TC-14 |
| AC-2 Stop confirm → stopped + teardown | TC-02, TC-14 |
| AC-3 Resume gating + rejection handling | TC-05, TC-09, TC-14 |
| AC-4 Reschedule pre-live, valid/past(422) | TC-03, TC-04, TC-14 |
| AC-5 Health refresh + stale banner | TC-06, TC-10, TC-12, TC-14 |
| AC-6 Policy gating + in-flight guard | TC-02, TC-09, TC-11, TC-12 |
| AC-7 CSRF/bearer, 401 refresh, retry policy | TC-01, TC-07, TC-08, TC-13 |
| AC-8 End-to-end live run | TC-14 (supported by TC-10 resilience) |
