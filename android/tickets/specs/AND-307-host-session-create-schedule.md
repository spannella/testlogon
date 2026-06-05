---
id: AND-307
title: Host session create/schedule
milestone: M7
epic: E41
priority: P1
size: M
status: draft
depends_on: [AND-278]
blocks: [AND-308, AND-309]
---

# AND-307 — Host session create/schedule

## 1. Overview & Goal

This ticket delivers the **host (broadcaster) side** of the TestLogon live
broadcast feature on Android: the ability for an authenticated host to **create**
a broadcast session, **schedule** it for a future start time, and
**cancel a scheduled** session before it goes live. It is the first ticket in the
M7 host-broadcasting epic (E41) and the entry point for the entire host
publishing flow.

Scope, verbatim from the backlog: *Create/schedule/cancel-schedule session.* The
single acceptance criterion is *Host can create + schedule a session.*

Where AND-278 (this ticket's hard dependency) defined the **read-side** broadcast
transport (`BroadcastApi` list/detail GETs, the `BroadcastSession` domain model,
the `BroadcastSessionStatus` enum), this ticket adds the **mutating** host
operations on top of that same seam: `POST` create, `PATCH`/`POST` schedule, and
the cancel-schedule mutation. It owns the host-facing Retrofit methods, their
request/response DTOs and mappers, a `HostBroadcastRepository` in `core-data`, a
`CreateBroadcastViewModel` with a `StateFlow<CreateBroadcastUiState>`, and the
Compose screen the host uses to title, schedule, and create/cancel a session.

This ticket establishes the **session object** that every later E41 ticket
operates on: AND-308 (WebRTC ingest) publishes camera/mic *into* the session
created here; AND-309 (host controls) starts/stops/reschedules it. It therefore
deliberately stops at session *creation and scheduling* — it does **not** start
the stream, capture media, run WebRTC, or render live host controls. The
deliverable is: a host can open the "Go Live" screen, enter a title, choose
"start now" (create) or pick a future time (schedule), submit, see the resulting
session, and cancel a scheduled session — all wired through a tested repository
and ViewModel.

## 2. Context & References

- **Repo / location:** `spannella/testlogon`, monorepo subfolder `android/`,
  branch `android-port`. Mutating transport lands in **`core-network`**
  (`com.testlogon.android.core.network.broadcast`), the repository in
  **`core-data`** (`com.testlogon.android.core.data.broadcast`), and the
  ViewModel + Compose screen in a host broadcast feature module
  **`feature-broadcast-host`**
  (`com.testlogon.android.feature.broadcast.host`).
- **Canonical package:** `com.testlogon.android` everywhere.
- **Stack pins relevant here:** Kotlin 2.0.21, Jetpack Compose + Material 3,
  Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit **2.11.0**, OkHttp
  **4.12.0**, Moshi **1.15.x** (codegen via KSP), `java.time.Instant` via core
  library desugaring, JDK 17, minSdk 24 / compile/target 35, AGP 8.7.3, Gradle
  8.9.
- **Module layering:** `app -> feature-* -> core-*`. Host mutation transport in
  `core-network`/`core-model`, repository in `core-data`, ViewModel/UI in
  `feature-broadcast-host`. No `feature`/`app` symbols leak into `core-*`.
- **Upstream dependency — AND-278 (Broadcast API + DTOs):** owns `BroadcastApi`,
  `BroadcastSessionDto`/`BroadcastSessionListRespDto`/`BroadcastHostDto`,
  `BroadcastSession`/`BroadcastSessionStatus`/`BroadcastHost`, the
  `BroadcastMappers.kt` `toDomain()` functions, the shared `InstantJsonAdapter`,
  and `BroadcastApiModule`. This ticket **extends** `BroadcastApi` with host
  mutations and **reuses** the existing DTOs/mappers for response decoding rather
  than re-declaring them. Backlog lists `Deps: AND-278`.
- **Transitive upstream (via AND-278 / auth):** AND-027 (cookie session
  endpoints), AND-011 (persistent cookie jar), AND-012 (CSRF interceptor — now
  *load-bearing* because this ticket introduces mutating verbs), AND-013
  (401-refresh authenticator), AND-015 (FastAPI `detail` → `ApiError`), AND-018
  (`ApiResult<T>`), AND-010/AND-009 (shared Retrofit/OkHttp, ~20s timeouts),
  AND-019/AND-020/AND-021 (Material 3 theme, input composables, state
  composables), AND-022/AND-024/AND-025 (navigation host, authenticated graph,
  auth-gated routing).
- **Web reference (authoritative for shapes):**
  `frontend/src/api/endpoints/broadcast.ts` (host create/schedule/cancel
  endpoints) and the broadcast slice of `frontend/src/api/types.ts`. OpenAPI at
  `/openapi.json` is the final authority; Section 5 is reconciled against it
  before merge.
- **Downstream siblings (this epic, E41 / M7):**
  - **AND-308 (WebRTC ingest)** — depends on AND-307; publishes camera/mic via
    `inputs` + `webrtc-offer` into the session created here.
  - **AND-309 (Host controls)** — depends on AND-308; owns
    start/stop/resume/**reschedule** and health report for an already-created
    session (the runtime lifecycle, distinct from the create-time scheduling
    here).
  - AND-310 (Inputs management) is transitively downstream via AND-308.

## 3. Functional Requirements

FR-1. Extend `BroadcastApi` with host mutation methods: **create** a session
(`POST broadcast/sessions`), **schedule / reschedule at create-time**
(`PATCH broadcast/sessions/{sessionId}`), and **cancel a scheduled session**
(`POST broadcast/sessions/{sessionId}/cancel`). Exact verbs/paths reconciled
against `/openapi.json` + `broadcast.ts`; Section 5 is the working contract.

FR-2. Each method is `suspend`, takes a typed `@Body` request DTO (never a raw
`Map`/`JsonObject`), and returns a `BroadcastSessionDto` (the AND-278 superset)
so the resulting/updated session decodes through the existing mappers.

FR-3. **Create** supports two modes from one screen: *start now* (no
`scheduled_start_at` → backend returns a session ready to go live, typically
`status:"scheduled"` or a host-pending status) and *schedule* (a future
`scheduled_start_at` Instant). The request also carries `title` (required) and
optional `description`.

FR-4. **Schedule / reschedule (create-time)** sets or changes
`scheduled_start_at` on a not-yet-live session via `PATCH`. (Runtime reschedule
of a live/started session is **AND-309**; this ticket only schedules a session
that has not yet started.)

FR-5. **Cancel-schedule** cancels a `SCHEDULED`/`UPCOMING` session the host
created, transitioning it to `CANCELLED`. Cancelling is only offered for sessions
the current host owns and that have not gone live.

FR-6. Define request DTOs with Moshi `@JsonClass(generateAdapter = true)`:
`CreateBroadcastSessionReqDto(title, description?, scheduled_start_at?)` and
`UpdateBroadcastScheduleReqDto(scheduled_start_at)`. Wire fields snake_case;
`scheduled_start_at` is an `Instant` serialized via the shared
`InstantJsonAdapter` (ISO-8601 UTC). Cancel takes no body (or an optional reason
— reconciled in Q-3).

FR-7. Provide a `HostBroadcastRepository` (`core-data`) exposing
`suspend fun createSession(req): ApiResult<BroadcastSession>`,
`suspend fun scheduleSession(id, startAt): ApiResult<BroadcastSession>`, and
`suspend fun cancelSchedule(id): ApiResult<BroadcastSession>`. The repository
wraps `BroadcastApi` calls in `ApiResult` (AND-018), maps non-2xx via AND-015,
and converts DTOs to domain via the AND-278 mappers.

FR-8. Provide a `CreateBroadcastViewModel` exposing
`val uiState: StateFlow<CreateBroadcastUiState>` and intents `onTitleChange`,
`onDescriptionChange`, `onScheduleModeChange(Now | At(Instant))`,
`onScheduledTimeChange(Instant)`, `submit()`, and `cancelSchedule()`. All network
work runs in `viewModelScope` on an injected IO dispatcher.

FR-9. **Validation (client-side, before submit):** `title` is non-blank
(trimmed, ≤ a max length, default 120 chars — confirm Q-4); when schedule mode is
`At`, `scheduledStartAt` must be **in the future** relative to a `Clock` (a small
skew buffer, e.g. ≥ 1 minute ahead). Invalid input yields field-level errors in
`uiState` and disables the submit button; it does **not** hit the network.

FR-10. Provide the Compose screen `CreateBroadcastScreen` (Material 3): a title
field, optional description field, a "Start now / Schedule for later" toggle, a
date-time picker (Material 3 `DatePicker` + `TimePicker`) shown only in schedule
mode, a primary submit button ("Go live" / "Schedule"), and — when editing an
already-scheduled session — a "Cancel scheduled broadcast" action behind a
confirmation dialog. Loading/empty/error/offline states use the AND-021
composables.

FR-11. **Navigation:** register a typed route `broadcastCreate` (optionally
`broadcastCreate/{sessionId}` for editing an existing scheduled session) in the
authenticated nav graph (AND-024). On successful **create**, the screen either
navigates to the host go-live screen (AND-308, when present) or pops back with a
result; on successful **cancel**, it pops back. Until AND-308 lands, a successful
create navigates back with the new session id surfaced via a nav result / event.

FR-12. CSRF and cookies are **not** declared per method — the global AND-012
interceptor attaches `X-CSRF-Token` (from the `ui_csrf` cookie) to these
mutations and the AND-011 jar carries the session. `BroadcastApi` stays
header-agnostic.

FR-13. The create/schedule/cancel mutations are **non-idempotent POST/PATCH** and
MUST NOT be auto-retried by the AND-016 backoff (which is GET-only). On transient
failure the ViewModel surfaces a retryable error and the **user** re-submits;
duplicate-create protection is discussed in R-1.

## 4. Technical Design

Production code spans three layers: `core-network` (interface methods + request
DTOs + request mappers), `core-data` (`HostBroadcastRepository`), and
`feature-broadcast-host` (ViewModel + Compose screen + nav).

### 4.1 Request DTOs (core-network)

```kotlin
package com.testlogon.android.core.network.broadcast

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import java.time.Instant

@JsonClass(generateAdapter = true)
data class CreateBroadcastSessionReqDto(
    val title: String,
    val description: String? = null,
    // null => "start now"; non-null => schedule for a future Instant (ISO-8601 UTC)
    @Json(name = "scheduled_start_at") val scheduledStartAt: Instant? = null,
)

@JsonClass(generateAdapter = true)
data class UpdateBroadcastScheduleReqDto(
    @Json(name = "scheduled_start_at") val scheduledStartAt: Instant,
)

@JsonClass(generateAdapter = true)
data class CancelBroadcastReqDto(
    val reason: String? = null, // optional; omitted if backend takes no body (Q-3)
)
```

Responses reuse the AND-278 `BroadcastSessionDto` and its `toDomain()` mapper —
no new response DTOs.

### 4.2 `BroadcastApi` additions (core-network)

```kotlin
// added to the existing interface from AND-278
import retrofit2.http.Body
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.Path

interface BroadcastApi {
    // ... AND-278 read methods (listSessions, getSession) ...

    /** Create a broadcast session ("start now" when scheduled_start_at is null). */
    @POST("broadcast/sessions")
    suspend fun createSession(
        @Body body: CreateBroadcastSessionReqDto,
    ): BroadcastSessionDto

    /** Set/change the scheduled start of a not-yet-live session. */
    @PATCH("broadcast/sessions/{sessionId}")
    suspend fun updateSchedule(
        @Path("sessionId") sessionId: String,
        @Body body: UpdateBroadcastScheduleReqDto,
    ): BroadcastSessionDto

    /** Cancel a scheduled/upcoming session before it goes live. */
    @POST("broadcast/sessions/{sessionId}/cancel")
    suspend fun cancelSession(
        @Path("sessionId") sessionId: String,
        @Body body: CancelBroadcastReqDto = CancelBroadcastReqDto(),
    ): BroadcastSessionDto
}
```

Paths are leading-slash-free (AND-010 convention). If `/openapi.json` shows
cancel as a `DELETE broadcast/sessions/{id}/schedule` or a `PATCH` with
`status:"cancelled"`, the method signature is adjusted to match (Q-2); the
repository/ViewModel surface is unchanged.

### 4.3 Repository (core-data)

```kotlin
package com.testlogon.android.core.data.broadcast

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.broadcast.BroadcastSession
import java.time.Instant

interface HostBroadcastRepository {
    suspend fun createSession(
        title: String, description: String?, scheduledStartAt: Instant?,
    ): ApiResult<BroadcastSession>

    suspend fun scheduleSession(id: String, startAt: Instant): ApiResult<BroadcastSession>

    suspend fun cancelSchedule(id: String): ApiResult<BroadcastSession>
}
```

```kotlin
class DefaultHostBroadcastRepository @Inject constructor(
    private val api: BroadcastApi,
    @IoDispatcher private val io: CoroutineDispatcher,
) : HostBroadcastRepository {

    override suspend fun createSession(
        title: String, description: String?, scheduledStartAt: Instant?,
    ): ApiResult<BroadcastSession> = withContext(io) {
        apiCall { // shared apiCall{} from AND-018/AND-015 maps body + errors
            api.createSession(
                CreateBroadcastSessionReqDto(title.trim(), description?.trim(), scheduledStartAt)
            ).toDomain()
        }
    }

    override suspend fun scheduleSession(id: String, startAt: Instant) = withContext(io) {
        apiCall { api.updateSchedule(id, UpdateBroadcastScheduleReqDto(startAt)).toDomain() }
    }

    override suspend fun cancelSchedule(id: String) = withContext(io) {
        apiCall { api.cancelSession(id).toDomain() }
    }
}
```

`apiCall { }` is the shared helper that runs the suspend block, returns
`ApiResult.Success` on 2xx, and maps `HttpException`/`IOException`/
`JsonDataException` to `ApiResult.Error` via AND-015. Bound via a Hilt
`@Binds` in a `core-data` module.

### 4.4 UI state + ViewModel (feature-broadcast-host)

```kotlin
package com.testlogon.android.feature.broadcast.host

import java.time.Instant

sealed interface ScheduleMode {
    data object Now : ScheduleMode
    data class At(val startAt: Instant) : ScheduleMode
}

data class CreateBroadcastUiState(
    val title: String = "",
    val description: String = "",
    val scheduleMode: ScheduleMode = ScheduleMode.Now,
    val pickedTime: Instant? = null,           // backing value for the picker
    val titleError: Int? = null,               // string-res id, null = valid
    val timeError: Int? = null,
    val isSubmitting: Boolean = false,
    val isCancelling: Boolean = false,
    val canSubmit: Boolean = false,            // derived: valid && !isSubmitting
    val submitError: ApiError? = null,         // AND-015 typed error
    val editingSessionId: String? = null,      // non-null when editing a scheduled session
)

sealed interface CreateBroadcastEvent {
    data class Created(val sessionId: String, val scheduled: Boolean) : CreateBroadcastEvent
    data class Cancelled(val sessionId: String) : CreateBroadcastEvent
}
```

```kotlin
@HiltViewModel
class CreateBroadcastViewModel @Inject constructor(
    private val repo: HostBroadcastRepository,
    private val clock: Clock,                  // injected for testable "future" checks
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val _uiState = MutableStateFlow(CreateBroadcastUiState(
        editingSessionId = savedStateHandle["sessionId"],
    ))
    val uiState: StateFlow<CreateBroadcastUiState> = _uiState.asStateFlow()

    private val _events = Channel<CreateBroadcastEvent>(Channel.BUFFERED)
    val events = _events.receiveAsFlow()

    fun onTitleChange(v: String) { /* update + revalidate */ }
    fun onDescriptionChange(v: String) { /* update */ }
    fun onScheduleModeChange(mode: ScheduleMode) { /* update + revalidate */ }
    fun onScheduledTimeChange(at: Instant) { /* update pickedTime + revalidate */ }

    fun submit() {
        val s = validate() ?: return            // sets field errors, no-op if invalid
        viewModelScope.launch {
            _uiState.update { it.copy(isSubmitting = true, submitError = null) }
            val startAt = (s.scheduleMode as? ScheduleMode.At)?.startAt
            val result = repo.createSession(s.title, s.description.ifBlank { null }, startAt)
            when (result) {
                is ApiResult.Success -> _events.send(
                    CreateBroadcastEvent.Created(result.data.id, scheduled = startAt != null))
                is ApiResult.Error -> _uiState.update {
                    it.copy(isSubmitting = false, submitError = result.error) }
            }
        }
    }

    fun cancelSchedule() { /* guarded by editingSessionId; calls repo.cancelSchedule */ }

    private fun validate(): CreateBroadcastUiState? { /* FR-9 rules; uses clock.instant() */ }
}
```

### 4.5 Compose screen (feature-broadcast-host)

```kotlin
@Composable
fun CreateBroadcastScreen(
    onCreated: (sessionId: String, scheduled: Boolean) -> Unit,
    onCancelled: (sessionId: String) -> Unit,
    onBack: () -> Unit,
    vm: CreateBroadcastViewModel = hiltViewModel(),
)
```

The screen collects `uiState` with
`collectAsStateWithLifecycle()`, collects one-shot `events` in a
`LaunchedEffect` to drive navigation callbacks, renders title/description
`OutlinedTextField`s (AND-020), a segmented "Start now / Schedule" control, and a
Material 3 `DatePickerDialog` + `TimePicker` in schedule mode. The submit button
shows a spinner while `isSubmitting`. A `submitError` renders via the AND-021
inline error composable with a retry affordance. The cancel action (edit mode)
opens an `AlertDialog` confirmation before calling `vm.cancelSchedule()`.

### 4.6 Navigation (feature-broadcast-host / app)

A typed route object `BroadcastCreateRoute(sessionId: String? = null)` is added
to the authenticated nav graph (AND-024). The host enters from a "Go Live" entry
point (e.g. the More hub / a broadcast tab) — the entry-point placement is
confirmed with AND-067/AND-024. On `Created`, navigation either routes to the
AND-308 host go-live destination (when available) or pops back with the new
session id as a nav result.

### 4.7 Gradle / Hilt wiring

No new external dependencies — Retrofit, Moshi (+KSP), Hilt, Compose, and
Material 3 are already present. New: `feature-broadcast-host/build.gradle.kts`
(depends on `:core-data`, `:core-model`, `:core-ui`, Compose/Hilt), and a Hilt
`@Binds HostBroadcastRepository` module in `core-data`. The `BroadcastApi`
additions live in the existing `core-network` module (already provided by
`BroadcastApiModule`, AND-278).

## 5. API Contract

Base path (`dev`): `http://18.222.237.167:8000/`. All mutations ride the cookie
session and carry the `X-CSRF-Token` header (AND-012). Shapes below are the
working contract, reconciled against `/openapi.json` + `broadcast.ts` before
merge.

### POST `broadcast/sessions` — create (start now)
Request:
```json
{ "title": "Friday Night Live", "description": "Weekly Q&A" }
```
Response `201`/`200` — a created session (AND-278 superset). "Start now" returns
a host-ready session; `playback.hls_url` is typically absent until ingest begins
(AND-308):
```json
{
  "id": "bcs_01HY9",
  "title": "Friday Night Live",
  "description": "Weekly Q&A",
  "status": "scheduled",
  "host": { "id": "usr_42", "username": "dana", "display_name": "Dana Ruiz" },
  "scheduled_start_at": null
}
```

### POST `broadcast/sessions` — create (scheduled)
Request:
```json
{
  "title": "Album listening party",
  "description": null,
  "scheduled_start_at": "2026-06-07T18:00:00Z"
}
```
Response `201`/`200` — `status:"scheduled"`, `scheduled_start_at` echoed.

### PATCH `broadcast/sessions/{sessionId}` — schedule / reschedule
Request:
```json
{ "scheduled_start_at": "2026-06-08T20:30:00Z" }
```
Response `200` — the updated session with the new `scheduled_start_at`. `404` if
unknown; `409`/`422` if the session has already started (reschedule of a live
session is AND-309).

### POST `broadcast/sessions/{sessionId}/cancel` — cancel schedule
Request: `{}` (or `{ "reason": "..." }` if supported — Q-3).
Response `200` — the session with `status:"cancelled"`. `409`/`422` if already
live/ended.

**Error envelope (all endpoints):** FastAPI `detail` union
(`string | [{msg,type,loc}] | {code,...}`) decoded to `ApiError` by **AND-015**;
notably `422` validation errors (e.g. past `scheduled_start_at`, blank title)
carry a `loc` pointing at the offending field, which the ViewModel maps to a
field-level error where possible (R-2). `403` indicates the user is not a host /
not the session owner.

## 6. Data & State Management

- **UI state:** `CreateBroadcastUiState` is the single source of truth, exposed
  as `StateFlow` from `CreateBroadcastViewModel` and collected with
  `collectAsStateWithLifecycle()`. `canSubmit` is derived from validity +
  `isSubmitting`. One-shot navigation/toast outcomes flow through a `Channel`
  →`events` `Flow` (not in the state object), so they fire exactly once across
  recomposition/config-change.
- **Form persistence:** the title/description/schedule selections survive process
  death via `SavedStateHandle` (and the route's `sessionId` for edit mode). The
  Material 3 picker state is remembered in composition.
- **No Room cache:** create/schedule/cancel are mutations; this ticket does not
  cache the host's draft beyond `SavedStateHandle`, nor does it own the
  host-sessions *list* (that read list, if any, belongs to AND-279/a host
  dashboard). On success it returns the freshly created/updated
  `BroadcastSession` to the caller; any list invalidation/refresh is the
  consumer's concern.
- **Session/auth state** lives in cookies (AND-011); CSRF (`ui_csrf` →
  `X-CSRF-Token`) is attached globally (AND-012). The ViewModel reads neither.
- **Time:** the ViewModel injects a `java.time.Clock` so "is the scheduled time
  in the future" is deterministic and testable; UTC `Instant` is the wire/domain
  representation, with local-timezone presentation handled in the picker UI.
- **Threading:** repository calls run on an injected `@IoDispatcher`; the
  ViewModel launches in `viewModelScope`. No blocking on the main thread.

## 7. Error Handling & Resilience

- **Validation-first:** invalid title/time never reach the network (FR-9); errors
  render inline and disable submit.
- **Non-2xx** is decoded by AND-015 into a typed `ApiError` and surfaced as
  `uiState.submitError` with a localized message and a retry affordance. `422`
  with a `loc` is mapped to a field-level error (title or time) when the `loc`
  identifies a known field; otherwise it shows as a form-level error (R-2).
  `403`/`401`-after-refresh routes to an appropriate not-authorized / re-login
  state (AND-013/AND-025).
- **Transport failures** (`SocketTimeoutException`, `UnknownHostException`,
  `IOException`) on the unreliable dev host map to an **offline/retryable** error
  state (AND-021 offline composable). Because these are **non-idempotent POST/
  PATCH**, the client does **not** auto-retry (AND-016 is GET-only); the user
  re-submits manually.
- **Duplicate-submit guard:** `isSubmitting`/`isCancelling` disable the buttons
  while a mutation is in flight, preventing accidental double-create. Server-side
  idempotency (e.g. an idempotency key) is desirable but out of scope unless the
  backend requires it (R-1).
- **State-conflict (409/422 on schedule/cancel):** a session that already went
  live cannot be rescheduled/cancelled here; the error message directs the host
  to the live host controls (AND-309). The mapper from AND-278 already tolerates
  unknown/odd status values returned in the response.
- **Cancel confirmation:** cancel is destructive and gated behind an
  `AlertDialog` so it cannot fire on a single tap.

## 8. Security & Privacy

- **Authenticated, authorized surface:** create/schedule/cancel require the
  cookie session (AND-027 family) **and** host authorization. The client adds no
  manual `Cookie`/`Authorization` headers; identity rides the jar. A `403`
  (non-host or non-owner) is handled as a not-authorized state, not a crash.
- **CSRF is mandatory here:** these are the first *mutating* broadcast verbs, so
  the global AND-012 interceptor's `X-CSRF-Token` (echoing the `ui_csrf` cookie)
  is load-bearing. A test asserts the header is present on create/schedule/cancel
  requests (see T-7).
- **Cleartext on dev:** request bodies (titles, descriptions, scheduled times)
  ride plaintext HTTP on the dev host — a known dev-only risk permitted by the
  scoped cleartext config (AND-006); `staging`/`prod` are HTTPS-only.
- **No sensitive logging:** the redacting HTTP logger (AND-009) is debug-only;
  this ticket adds no body logging. Titles/descriptions are user content and must
  not be dumped to logcat in release.
- **No new permissions / no local secret storage:** camera/mic permissions for
  actual streaming are AND-288/AND-308's concern; this ticket only creates the
  session metadata.
- **Input handling:** title/description are sent as-is (trimmed); server-side
  validation/sanitization is authoritative. The client enforces only length/
  non-blank, not content policy.

## 9. Accessibility & i18n

- **A11y:** all controls have `contentDescription`/semantics — title and
  description fields labeled and associated with their error text via
  `Modifier.semantics { error(...) }`; the Start-now/Schedule toggle is a
  labeled selectable group; the submit and cancel buttons announce
  loading/disabled state. The date/time pickers use Material 3's accessible
  components. Minimum 48dp touch targets; error messages are programmatically
  associated, not color-only. Dynamic font scaling supported.
- **i18n:** every string (labels, button text, validation/error messages,
  confirmation dialog) is a string resource (AND-111), no hardcoded literals.
  The scheduled time is shown in the **device locale and timezone** (the picker
  works in local time; the wire value is UTC `Instant`); relative phrasing like
  "starts in 2h" is not required here. RTL layouts supported (AND-114). Server
  error text from AND-015 is surfaced per the i18n policy.

## 10. Telemetry & Logging

- **Analytics events** (via the app's analytics seam, redaction per AND-052):
  `broadcast_create_started` (mode = now|scheduled), `broadcast_create_succeeded`
  (`session_id`, `scheduled` bool), `broadcast_create_failed`
  (error code/category, no PII/body), `broadcast_schedule_cancelled`
  (`session_id`). No titles/descriptions in event params.
- **HTTP logging** inherited from AND-009 (debug-only, redacted). No new payload
  logging; request bodies (user content) must not reach logcat in release.
- **Build-time signal:** KSP must generate adapters for the new request DTOs; a
  missing adapter fails the build (no reflection fallback, AND-010 policy).

## 11. Testing Strategy

**Transport (core-network, JVM + MockWebServer)** using the production Moshi/
Retrofit config (shared `InstantJsonAdapter`):

- **T-1 — create (now)** `createSession(CreateBroadcastSessionReqDto("Friday
  Night Live", "Weekly Q&A", null))` issues `POST /broadcast/sessions`; the
  request body JSON has `title`, `description`, and **no** `scheduled_start_at`
  key (null omitted); the `201` response decodes and `toDomain()` yields the
  expected `BroadcastSession`.
- **T-2 — create (scheduled)** request body serializes `scheduled_start_at` as
  ISO-8601 UTC matching the input `Instant`; response `status:"scheduled"` maps
  to `BroadcastSessionStatus.SCHEDULED` with the right `scheduledStartAt`.
- **T-3 — update schedule** `updateSchedule(id, ...)` issues
  `PATCH /broadcast/sessions/bcs_01HY9` with the new `scheduled_start_at`; path
  param interpolated; response decodes.
- **T-4 — cancel** `cancelSession(id)` issues
  `POST /broadcast/sessions/bcs_01HY9/cancel`; response `status:"cancelled"` maps
  to `CANCELLED`.
- **T-5 — error propagation** a `422` with a `detail` array surfaces as
  `HttpException(code=422)` carrying the body for AND-015.

**Repository (core-data, JVM)** with a faked/Mock `BroadcastApi`:

- **T-6 — `ApiResult` wrapping** success → `ApiResult.Success(BroadcastSession)`;
  `HttpException`/`IOException` → `ApiResult.Error` with the AND-015-mapped error;
  the create call trims the title and omits a blank description.

**CSRF/headers (core-network integration):**

- **T-7 — CSRF header present** with the AND-012 interceptor + a seeded `ui_csrf`
  cookie, create/schedule/cancel requests carry `X-CSRF-Token` (GET reads do
  not).

**ViewModel (feature-broadcast-host, JVM, `runTest` + `Turbine`)** with a fake
repository and a fixed `Clock`:

- **T-8 — validation** blank title → `titleError` set, `canSubmit == false`,
  `submit()` performs no repo call; a past `scheduled_start_at` → `timeError`
  set; a valid future time clears errors and enables submit.
- **T-9 — submit success** valid input → `isSubmitting` toggles true→ then a
  `CreateBroadcastEvent.Created(sessionId, scheduled)` is emitted exactly once;
  `scheduled` reflects now vs. scheduled mode.
- **T-10 — submit failure** repo error → `submitError` populated,
  `isSubmitting == false`, no event emitted; a `422` with field `loc` maps to the
  matching field error (R-2).
- **T-11 — cancel** in edit mode, `cancelSchedule()` calls the repo and emits
  `Cancelled(sessionId)`; with no `editingSessionId` it is a no-op.
- **T-12 — duplicate-submit guard** a second `submit()` while `isSubmitting` is
  true does not start a second repo call.

**Compose UI (feature-broadcast-host, instrumented or Robolectric):**

- **T-13 — UI** typing a title enables submit; selecting "Schedule" reveals the
  picker; the loading spinner shows during submit; the cancel confirmation dialog
  appears before cancel fires; an error renders the AND-021 error composable with
  retry.

Coverage target: ≥90% on the new transport, repository, and ViewModel surface;
every endpoint has a verb/path/body assertion; every validation rule and each
success/failure branch has a dedicated assertion.

## 12. Dependencies & Sequencing

**Hard upstream (must merge first):**
- **AND-278** — Broadcast API + DTOs. Provides `BroadcastApi`, the
  `BroadcastSessionDto`/host DTOs, the `toDomain()` mappers, the shared
  `InstantJsonAdapter`, and `BroadcastApiModule` that this ticket extends and
  reuses. Blocking per backlog `Deps: AND-278`.

**Transitive upstream (already required by AND-278 / auth & UI baselines):**
AND-027 (session), AND-011 (cookie jar), **AND-012 (CSRF — now load-bearing)**,
AND-013 (401 refresh), AND-015 (`ApiError`), AND-018 (`ApiResult`),
AND-010/AND-009 (Retrofit/OkHttp), AND-019/AND-020/AND-021 (theme, inputs, state
composables), AND-022/AND-024/AND-025 (nav host, authenticated graph, auth
gating), AND-111 (i18n plumbing).

**Downstream (this ticket blocks):**
- **AND-308 (WebRTC ingest)** — `Deps: AND-307`. Publishes camera/mic into the
  session this ticket creates; consumes the created `BroadcastSession` id and the
  navigation hand-off to the host go-live screen.
- **AND-309 (Host controls)** — `Deps: AND-308` (transitively AND-307). Owns the
  *runtime* lifecycle (start/stop/resume/**reschedule**/health) of an
  already-created session; the create-time scheduling here is the precondition.
- AND-310 (Inputs management) is transitively downstream via AND-308.

**Sequencing within the ticket:** (1) reconcile the create/schedule/cancel
verbs, paths, and body field names against `/openapi.json` +
`frontend/src/api/endpoints/broadcast.ts`; (2) add request DTOs + `BroadcastApi`
methods (+ MockWebServer tests T-1..T-5); (3) add `HostBroadcastRepository`
(+ T-6); (4) build `CreateBroadcastViewModel` + UI state (+ T-7..T-12);
(5) build `CreateBroadcastScreen` + nav route (+ T-13); (6) wire the "Go Live"
entry point.

## 13. Risks & Open Questions

- **R-1 Duplicate create.** A retried/double-tapped create could produce two
  sessions. Mitigation: in-flight button disable (`isSubmitting`) and no
  auto-retry on POST. If the backend supports an idempotency key, send one;
  otherwise accept best-effort and let AND-279/host dashboard dedupe. Guarded by
  T-12.
- **R-2 Field-level 422 mapping.** Mapping a FastAPI `422` `loc` back to the
  right form field depends on the `loc` naming (`body.title`,
  `body.scheduled_start_at`). Mitigation: map known `loc` tails to fields, fall
  back to a form-level error. Guarded by T-10.
- **R-3 Start-now semantics.** "Start now" may (a) create a session in a
  host-pending/`scheduled` status that AND-308 then transitions live, or (b)
  immediately create a `live`-intent session. Mitigation: this ticket only
  creates; the `Created` event carries `scheduled` so navigation can branch.
  Confirm via OpenAPI.
- **R-4 Entry point / navigation target.** The host "Go Live" entry point and the
  post-create destination depend on AND-308 (not yet merged) and the host hub
  IA. Mitigation: until AND-308 lands, create pops back with a nav result; the
  route is designed to accept the AND-308 destination later.
- **Q-1** Is create `POST broadcast/sessions` returning `201` with the session,
  or a thinner create-response (just an id)? *Proposed:* assume the full AND-278
  superset; if thinner, follow with a `getSession`.
- **Q-2** Is cancel `POST .../cancel`, `DELETE .../schedule`, or a
  `PATCH status:"cancelled"`? *Proposed:* `POST .../cancel`; reconcile with
  OpenAPI/`broadcast.ts`. Guarded by T-4.
- **Q-3** Does cancel accept/require a `reason` body? *Proposed:* optional;
  send `{}` if not. 
- **Q-4** Title max length and whether description is length-bounded server-side?
  *Proposed:* client cap title at 120 chars; confirm against `/openapi.json`.
- **Q-5** Can a host create multiple concurrent scheduled sessions, and is there
  a per-host limit that should be surfaced pre-submit? *Proposed:* allow; surface
  any backend `409`/limit error via AND-015. (Defer enforcement to backend.)
- **Q-6** Does scheduling distinguish `scheduled` vs `upcoming` at create time,
  or is `upcoming` purely a read-side derivation? *Proposed:* send only
  `scheduled_start_at`; let the backend assign status. (AND-278 preserves both.)

## 14. Acceptance Criteria

- **AC-1 (backlog).** A host can **create** and **schedule** a session: from
  `CreateBroadcastScreen`, entering a title and choosing "Start now" creates a
  session (`POST broadcast/sessions`, no `scheduled_start_at`), and choosing a
  future time creates a scheduled session (with `scheduled_start_at`); both
  succeed end-to-end through repository → ViewModel → UI, proven by T-1, T-2, T-9,
  and the UI test T-13.
- **AC-2.** A host can **cancel a scheduled** session
  (`POST broadcast/sessions/{id}/cancel`), transitioning it to `CANCELLED`,
  behind a confirmation dialog (T-4, T-11, T-13).
- **AC-3.** `BroadcastApi` declares `createSession`, `updateSchedule`, and
  `cancelSession` with typed `@Body` request DTOs returning `BroadcastSessionDto`;
  verbs/paths/bodies match Section 5, asserted with MockWebServer (T-1..T-4).
- **AC-4.** Request DTOs serialize via Moshi codegen with `scheduled_start_at` as
  ISO-8601 UTC; null schedule omits the key on "start now" (T-1, T-2).
- **AC-5.** `HostBroadcastRepository` wraps each call in `ApiResult` (AND-018),
  maps non-2xx via AND-015, and maps responses through AND-278's `toDomain()`
  (T-5, T-6).
- **AC-6.** Client-side validation rejects a blank title and a non-future
  scheduled time before any network call, with field-level errors and a disabled
  submit (T-8).
- **AC-7.** Mutations carry `X-CSRF-Token` via the global AND-012 interceptor and
  are **not** auto-retried (POST/PATCH); the in-flight guard prevents double
  submission (T-7, T-12).
- **AC-8.** Errors (transport offline, `422` validation, `403`/`409` conflict)
  surface as typed, localized, retryable UI states using the AND-021 composables;
  `422` field `loc` maps to the matching field where possible (T-10, T-13).
- **AC-9.** On success the ViewModel emits a one-shot `Created`/`Cancelled` event
  driving navigation exactly once across recomposition/config change; form state
  survives process death via `SavedStateHandle` (T-9, T-11).
- **AC-10.** All strings are resources; controls are accessible (labels, error
  semantics, 48dp targets, RTL); the scheduled time renders in the device
  locale/timezone. All tests pass in CI; modules build clean under AGP 8.7.3 /
  Gradle 8.9 / JDK 17 with KSP adapters present and no lint/detekt regressions.

## 15. Definition of Done

- Request DTOs (`CreateBroadcastSessionReqDto`, `UpdateBroadcastScheduleReqDto`,
  `CancelBroadcastReqDto`) and the `BroadcastApi` host methods live in
  `core-network` (`com.testlogon.android.core.network.broadcast`);
  `HostBroadcastRepository` + impl + Hilt binding live in `core-data`
  (`com.testlogon.android.core.data.broadcast`); `CreateBroadcastViewModel`,
  `CreateBroadcastUiState`, and `CreateBroadcastScreen` live in
  `feature-broadcast-host` (`com.testlogon.android.feature.broadcast.host`).
- Open questions Q-1..Q-6 are resolved against `/openapi.json` and
  `frontend/src/api/endpoints/broadcast.ts`; verbs, paths, and request field
  names reflect the confirmed contract.
- Tests T-1 through T-13 are implemented and green in CI; ≥90% line coverage on
  the new surface; every endpoint has a verb/path/body assertion and each
  validation/success/failure branch has a dedicated assertion.
- The create route is registered in the authenticated nav graph (AND-024), the
  "Go Live" entry point is wired, and the post-create navigation hands off
  cleanly (popping back with the new session id until AND-308's go-live
  destination exists).
- CSRF is verified present on mutations; no manual cookie/CSRF/auth headers in
  the interface; no user-content request bodies in release logs (verified in
  review).
- `./gradlew :core-network:testDebugUnitTest :core-data:testDebugUnitTest
  :feature-broadcast-host:testDebugUnitTest` (and the Compose UI test task) pass
  locally and in CI with no new lint/detekt violations (AND-005 config).
- Code reviewed and merged to `android-port`; the host broadcasting flow is
  unblocked — **AND-308 has a created `BroadcastSession` to ingest into** and
  **AND-309 has a scheduled session to start/stop/reschedule at runtime**.
- A one-line note in the `core-network` / `feature-broadcast-host` README records
  the host create/schedule/cancel path/verb map and the CSRF requirement on these
  mutations.
