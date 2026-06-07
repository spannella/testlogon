---
id: AND-307
title: Host session create/schedule
milestone: M7
epic: E41
priority: P1
size: M
depends_on: [AND-278]
blocks: [AND-308, AND-309]
status: reviewed
reviewed_on: 2026-06-06
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
(`POST broadcast/sessions`), **schedule (set title/description/start time)**
(`POST broadcast/sessions/{sessionId}/schedule`), and **cancel a scheduled
session** (`POST broadcast/sessions/{sessionId}/cancel-schedule`). **[CORRECTED
v2026-06-06 against OpenAPI]** The schedule verb is **POST `.../schedule`**, not
`PATCH broadcast/sessions/{sessionId}` (no such PATCH route exists), and the
cancel path is **`.../cancel-schedule`**, not `.../cancel`. Verbs/paths confirmed
against the OpenAPI index; Section 5 is the working contract. Note also that the
web `broadcast.ts` does NOT call schedule/cancel-schedule (it only does
create/start/stop/delete), so the Android client is the first consumer of these
two routes — they are verified from OpenAPI alone.

FR-2. Each method is `suspend`, takes a typed `@Body` request DTO (never a raw
`Map`/`JsonObject`), and returns a `BroadcastSessionDto` (the AND-278 superset)
so the resulting/updated session decodes through the existing mappers.

FR-3. **[CORRECTED v2026-06-06 against OpenAPI]** `POST broadcast/sessions`
(`BroadcastSessionCreateIn`) takes **`profile_id` (required)** plus optional
ingest/stream-key/ad config — it does **NOT** accept `title`, `description`, or
any scheduled-start field. The title (`name`), `description`, and the scheduled
start time are therefore **set on the `POST .../schedule` call**, not at create.
The screen models two modes: *start now* (create only, then hand off to AND-308
go-live) and *schedule* (create, then immediately POST `.../schedule` with
`scheduled_at` + `name`/`description`). The "single create call carries title +
optional schedule" design in the draft was based on an unverified DTO and is
incorrect; see Section 5 and §16.

FR-4. **Schedule (create-time)** sets `name`, optional `description`, and the
required `scheduled_at` on a not-yet-live session via **`POST
broadcast/sessions/{sessionId}/schedule`** (`BroadcastScheduleIn`). `scheduled_at`
is a **Unix epoch-seconds integer** (`>= min lead time from now`), NOT an ISO-8601
string. (Runtime *reschedule* of a session is the separate `POST
.../reschedule` route + `BroadcastRescheduleIn`, owned by **AND-309**; this ticket
uses only `.../schedule`.)

FR-5. **Cancel-schedule** cancels a `SCHEDULED`/`UPCOMING` session the host
created, transitioning it to `CANCELLED`. Cancelling is only offered for sessions
the current host owns and that have not gone live.

FR-6. **[CORRECTED v2026-06-06]** Define request DTOs with Moshi
`@JsonClass(generateAdapter = true)`:
`CreateBroadcastSessionReqDto(profile_id, ingest_url?, stream_key_ref?,
stream_key_rotation_interval_seconds?)` and
`ScheduleBroadcastReqDto(scheduled_at: Long, name?: String, description?:
String)`. Wire fields snake_case. **`scheduled_at` is a `Long` epoch-seconds
value (Unix timestamp), serialized as a JSON integer — NOT an `Instant`/ISO-8601
string, so the `InstantJsonAdapter` is NOT used for the request body.** The
ViewModel converts the picked local time to `Instant.epochSecond` for the wire.
**Cancel takes NO request body** (the `cancel-schedule` route has `req=` empty in
OpenAPI), so there is no `CancelBroadcastReqDto`/`reason` (resolves Q-3).

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

FR-9. **Validation (client-side, before submit):** the title (`name`) is non-blank
when scheduling (trimmed, **≤ 200 chars** per `BroadcastScheduleIn.name`
maxLength — resolves Q-4; description ≤ 2000); when schedule mode is `At`, the
chosen `scheduled_at` must be **in the future** relative to a `Clock` (use a skew
buffer ≥ the backend "min lead time"; default to ≥ 1 minute and surface any
backend `422` lead-time rejection). Invalid input yields field-level errors in
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

// [CORRECTED v2026-06-06 against OpenAPI: BroadcastSessionCreateIn requires
// profile_id and has NO title/description/scheduled_start_at]
@JsonClass(generateAdapter = true)
data class CreateBroadcastSessionReqDto(
    @Json(name = "profile_id") val profileId: String,
    @Json(name = "ingest_url") val ingestUrl: String? = null,
    @Json(name = "stream_key_ref") val streamKeyRef: String? = null,
    @Json(name = "stream_key_rotation_interval_seconds")
    val streamKeyRotationIntervalSeconds: Int? = null,
)

// [CORRECTED v2026-06-06: route is POST .../schedule with BroadcastScheduleIn;
// scheduled_at is a Unix epoch-SECONDS integer, name = the title (max 200),
// description max 2000]
@JsonClass(generateAdapter = true)
data class ScheduleBroadcastReqDto(
    @Json(name = "scheduled_at") val scheduledAt: Long,   // Unix epoch seconds
    val name: String? = null,
    val description: String? = null,
)

// Cancel-schedule takes NO body (OpenAPI req= empty) — no DTO needed.
```

Responses reuse the AND-278 `BroadcastSessionDto` (decoded from
`BroadcastSessionOut`) and its `toDomain()` mapper — no new response DTOs. Note
the response has **no `host` object**: ownership is the `created_by` string and
the title is the nullable `name` field (see §5 / §16).

### 4.2 `BroadcastApi` additions (core-network)

```kotlin
// added to the existing interface from AND-278
import retrofit2.http.Body
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.Path

interface BroadcastApi {
    // ... AND-278 read methods (listSessions, getSession) ...

    // [CORRECTED v2026-06-06 against OpenAPI]
    /** Create a broadcast session. Requires profile_id; sets no title/schedule. */
    @POST("broadcast/sessions")
    suspend fun createSession(
        @Body body: CreateBroadcastSessionReqDto,
    ): BroadcastSessionDto

    /** Set title/description and the scheduled start of a not-yet-live session. */
    @POST("broadcast/sessions/{sessionId}/schedule")
    suspend fun scheduleSession(
        @Path("sessionId") sessionId: String,
        @Body body: ScheduleBroadcastReqDto,
    ): BroadcastSessionDto

    /** Cancel a scheduled session before it goes live. No request body. */
    @POST("broadcast/sessions/{sessionId}/cancel-schedule")
    suspend fun cancelSchedule(
        @Path("sessionId") sessionId: String,
    ): BroadcastSessionDto
}
```

Paths are leading-slash-free (AND-010 convention). **Verified against the OpenAPI
index:** create = `POST /broadcast/sessions` (201 `BroadcastSessionOut`), schedule
= `POST /broadcast/sessions/{session_id}/schedule` (200 `BroadcastSessionOut`),
cancel = `POST /broadcast/sessions/{session_id}/cancel-schedule` (200
`BroadcastSessionOut`, no body). There is **no** `PATCH .../{id}` route and **no**
`.../cancel` route; the draft's Q-2 is resolved (it is `cancel-schedule`, not a
`DELETE` or status-PATCH). A separate `DELETE /broadcast/sessions/{id}` (hard
delete) and `POST .../reschedule` (runtime, AND-309) exist but are out of scope.

### 4.3 Repository (core-data)

```kotlin
package com.testlogon.android.core.data.broadcast

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.broadcast.BroadcastSession
import java.time.Instant

// [CORRECTED v2026-06-06] createSession takes profile_id (title/desc/schedule
// are applied via scheduleSession, which carries name/description/scheduled_at).
interface HostBroadcastRepository {
    suspend fun createSession(
        profileId: String, ingestUrl: String? = null,
    ): ApiResult<BroadcastSession>

    /** scheduledAt = Unix epoch SECONDS; name = title (<=200), description (<=2000). */
    suspend fun scheduleSession(
        id: String, scheduledAt: Long, name: String?, description: String?,
    ): ApiResult<BroadcastSession>

    suspend fun cancelSchedule(id: String): ApiResult<BroadcastSession>
}
```

```kotlin
class DefaultHostBroadcastRepository @Inject constructor(
    private val api: BroadcastApi,
    @IoDispatcher private val io: CoroutineDispatcher,
) : HostBroadcastRepository {

    override suspend fun createSession(
        profileId: String, ingestUrl: String?,
    ): ApiResult<BroadcastSession> = withContext(io) {
        apiCall { // shared apiCall{} from AND-018/AND-015 maps body + errors
            api.createSession(
                CreateBroadcastSessionReqDto(profileId = profileId, ingestUrl = ingestUrl)
            ).toDomain()
        }
    }

    override suspend fun scheduleSession(
        id: String, scheduledAt: Long, name: String?, description: String?,
    ) = withContext(io) {
        apiCall {
            api.scheduleSession(
                id, ScheduleBroadcastReqDto(scheduledAt, name?.trim(), description?.trim())
            ).toDomain()
        }
    }

    override suspend fun cancelSchedule(id: String) = withContext(io) {
        apiCall { api.cancelSchedule(id).toDomain() }
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

**[SECTION 5 CORRECTED v2026-06-06 against the OpenAPI spec — the original bodies
were unverified and largely wrong: see §16.]**

### POST `broadcast/sessions` — create  (`BroadcastSessionCreateIn` → `201 BroadcastSessionOut`)
Request (only `profile_id` is required; title/description/schedule are NOT sent here):
```json
{ "profile_id": "bp_01HX0" }
```
Response `201` — a `BroadcastSessionOut`. Required fields: `id`, `profile_id`,
`status`, `created_by`, `created_at`, `updated_at`. There is **no `host`
object** (owner = `created_by` string) and **no `title`** (the title is the
nullable `name` field):
```json
{
  "id": "bcs_01HY9",
  "profile_id": "bp_01HX0",
  "status": "draft",
  "name": null,
  "description": null,
  "scheduled_at": null,
  "schedule_status": null,
  "created_by": "usr_42",
  "created_at": "2026-06-07T17:00:00Z",
  "updated_at": "2026-06-07T17:00:00Z"
}
```

### POST `broadcast/sessions/{sessionId}/schedule` — schedule (`BroadcastScheduleIn` → `200 BroadcastSessionOut`)
Sets the title (`name`), `description`, and the required `scheduled_at`
(**Unix epoch SECONDS integer**, must be `>= min lead time from now`):
```json
{
  "scheduled_at": 1781020800,
  "name": "Album listening party",
  "description": "Weekly Q&A"
}
```
Response `200` — the updated `BroadcastSessionOut` with `name`,
`scheduled_at` (integer) and `schedule_status` populated; `status` is typically
`"scheduled"`. `422` if `scheduled_at` is in the past / under min lead time, or
`name` exceeds 200 / `description` exceeds 2000.

### POST `broadcast/sessions/{sessionId}/cancel-schedule` — cancel schedule (`200 BroadcastSessionOut`)
Request: **no body** (`req=` empty in OpenAPI). Response `200` — the session with
`status:"cancelled"` (and `cancelled_at` set). `422` if the session is not in a
cancellable state (e.g. already live/ended).

**Error envelope (all endpoints):** the OpenAPI declares only `422
HTTPValidationError` (FastAPI standard) for these three routes; `HTTPValidationError`
is `{ "detail": [{ "loc": [...], "msg": "...", "type": "..." }] }`. Decoded to
`ApiError` by **AND-015**; a `422` for a past `scheduled_at` or an over-length
`name` carries a `loc` (e.g. `["body","scheduled_at"]`,
`["body","name"]`) the ViewModel maps to a field-level error where possible (R-2).
`401`/`403` (unauthenticated / not a host or owner) are **not** enumerated in the
OpenAPI for these routes but are handled defensively (AND-013 refresh / AND-025
auth gating) — treated as an unverified assumption (§16). The earlier draft's
field name `scheduled_start_at` is wrong; the wire field is `scheduled_at`.

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
  in the future" is deterministic and testable. **[CORRECTED v2026-06-06]** The
  **wire** representation of `scheduled_at` is a **Unix epoch-seconds integer**
  (not ISO-8601). The domain/UI may hold an `Instant`, but the request DTO sends
  `instant.epochSecond` (a `Long`); local-timezone presentation is handled in the
  picker UI. (Response timestamps like `created_at` are ISO-8601 strings, but
  `scheduled_at` in `BroadcastSessionOut` is also an integer.)
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
  works in local time; the wire value is a Unix epoch-seconds integer);
  relative phrasing like
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

- **T-1 — create** `createSession(CreateBroadcastSessionReqDto(profileId =
  "bp_01HX0"))` issues `POST /broadcast/sessions`; the request body JSON has
  `profile_id` and omits null optional keys; the `201` `BroadcastSessionOut`
  response decodes and `toDomain()` yields the expected `BroadcastSession`.
  **[CORRECTED: body is profile_id, not title/description.]**
- **T-2 — schedule** `scheduleSession(id, scheduledAt = 1781020800L, name, desc)`
  issues `POST /broadcast/sessions/bcs_01HY9/schedule`; the request body
  serializes `scheduled_at` as a **JSON integer** (epoch seconds, not ISO-8601),
  plus `name`/`description`; response `status:"scheduled"` maps to
  `BroadcastSessionStatus.SCHEDULED` with the right `scheduledAt`.
- **T-3 — schedule path param** `scheduleSession("bcs_01HY9", ...)` interpolates
  the path correctly to `.../bcs_01HY9/schedule`; response decodes.
- **T-4 — cancel-schedule** `cancelSchedule(id)` issues
  `POST /broadcast/sessions/bcs_01HY9/cancel-schedule` with **no body**; response
  `status:"cancelled"` maps to `CANCELLED`. **[CORRECTED: path is
  `/cancel-schedule`, not `/cancel`; no request body.]**
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
- **Q-1 [RESOLVED v2026-06-06].** `POST broadcast/sessions` returns `201
  BroadcastSessionOut` (the full session), required `id, profile_id, status,
  created_by, created_at, updated_at`. No follow-up `getSession` needed.
- **Q-2 [RESOLVED v2026-06-06].** Cancel is `POST .../cancel-schedule` (verified
  in the OpenAPI index) — NOT `.../cancel`, a `DELETE`, or a status-PATCH. Guarded
  by T-4.
- **Q-3 [RESOLVED v2026-06-06].** Cancel-schedule takes **no body** (`req=` empty
  in OpenAPI); there is no `reason` field. Send no body.
- **Q-4 [RESOLVED v2026-06-06].** Title is the `BroadcastScheduleIn.name` field,
  maxLength **200** (not 120); `description` maxLength **2000**. Client caps
  accordingly. (Note: title is not a create-time field at all.)
- **Q-5** Can a host create multiple concurrent scheduled sessions, and is there
  a per-host limit that should be surfaced pre-submit? *Proposed:* allow; surface
  any backend `409`/limit error via AND-015. (Defer enforcement to backend.)
- **Q-6** Does scheduling distinguish `scheduled` vs `upcoming` at create time,
  or is `upcoming` purely a read-side derivation? *Proposed:* send only
  `scheduled_start_at`; let the backend assign status. (AND-278 preserves both.)

## 14. Acceptance Criteria

- **AC-1 (backlog).** A host can **create** and **schedule** a session: from
  `CreateBroadcastScreen`, "Start now" creates a session (`POST broadcast/sessions`
  with `profile_id`), and "Schedule for later" creates then schedules it
  (`POST broadcast/sessions/{id}/schedule` with `scheduled_at` + `name`); both
  succeed end-to-end through repository → ViewModel → UI, proven by T-1, T-2, T-9,
  and the UI test T-13. **[CORRECTED: title/schedule go on the schedule call.]**
- **AC-2.** A host can **cancel a scheduled** session
  (`POST broadcast/sessions/{id}/cancel-schedule`, no body), transitioning it to
  `CANCELLED`, behind a confirmation dialog (T-4, T-11, T-13).
- **AC-3.** `BroadcastApi` declares `createSession`, `scheduleSession`, and
  `cancelSchedule` with typed `@Body` request DTOs (cancel has no body) returning
  `BroadcastSessionDto`; verbs/paths/bodies match Section 5, asserted with
  MockWebServer (T-1..T-4).
- **AC-4.** Request DTOs serialize via Moshi codegen with `scheduled_at` as a
  **Unix epoch-seconds integer** (not ISO-8601); `createSession` omits null
  optional keys (T-1, T-2).
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

- Request DTOs (`CreateBroadcastSessionReqDto` with `profile_id`,
  `ScheduleBroadcastReqDto` with `scheduled_at`/`name`/`description`; cancel has
  no body) and the `BroadcastApi` host methods (`createSession`,
  `scheduleSession`, `cancelSchedule`) live in
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

## 16. Citations & Assumption Audit

Reviewed 2026-06-06 against the OpenAPI index/spec and the frontend reference
source. Each numbered claim lists the claim, a VERDICT, and the exact SOURCE.

1. **Create endpoint = `POST /broadcast/sessions`.** VERDICT: Verified.
   SOURCE: OpenAPI `POST /broadcast/sessions` (op `create_session_route...`,
   `req=BroadcastSessionCreateIn`, `resp=201:BroadcastSessionOut`); frontend
   `src/api/endpoints/broadcast.ts: createSession` (`api.post("/broadcast/sessions")`).
2. **Create request body has `title`, `description`, optional `scheduled_start_at`.**
   VERDICT: Corrected. The real `BroadcastSessionCreateIn` requires **`profile_id`**
   and offers only `ingest_url`, `stream_key_ref`,
   `stream_key_rotation_interval_seconds`, and ad-config fields — no
   title/description/schedule. SOURCE: OpenAPI `components.schemas.BroadcastSessionCreateIn`
   (required: `["profile_id"]`); frontend `src/api/endpoints/broadcast.ts:
   CreateSessionReq`.
3. **Schedule endpoint = `PATCH /broadcast/sessions/{sessionId}`.** VERDICT:
   Corrected → **`POST /broadcast/sessions/{session_id}/schedule`**. No `PATCH
   .../{id}` route exists. SOURCE: OpenAPI `POST /broadcast/sessions/{session_id}/schedule`
   (op `schedule_session_route...`, `req=app__routers__broadcast__BroadcastScheduleIn`,
   `resp=200:BroadcastSessionOut`).
4. **Schedule body field `scheduled_start_at`, an ISO-8601 `Instant` via
   `InstantJsonAdapter`.** VERDICT: Corrected → field is **`scheduled_at`, a Unix
   epoch-seconds integer** (required, `>= min lead time`); also optional `name`
   (≤200) and `description` (≤2000). The InstantJsonAdapter is NOT used for the
   request body. SOURCE: OpenAPI
   `components.schemas.app__routers__broadcast__BroadcastScheduleIn`
   (`scheduled_at: integer`, `name`, `description`; required `["scheduled_at"]`).
5. **Title field named `title`, max 120.** VERDICT: Corrected → the title is
   `name` (maxLength **200**), `description` maxLength **2000**, and it lives on
   the schedule body, not create. SOURCE: same as #4.
6. **Cancel endpoint = `POST /broadcast/sessions/{sessionId}/cancel`.** VERDICT:
   Corrected → **`POST /broadcast/sessions/{session_id}/cancel-schedule`**.
   SOURCE: OpenAPI `POST /broadcast/sessions/{session_id}/cancel-schedule`
   (op `cancel_schedule_route...`, `resp=200:BroadcastSessionOut`).
7. **Cancel accepts an optional `reason` body.** VERDICT: Corrected → cancel-schedule
   takes **no request body** (`req=` empty). SOURCE: OpenAPI index line for
   `cancel-schedule` (`req=` empty). (Distinct from start/stop's
   `BroadcastSessionActionIn { reason }`.)
8. **Response is a session "superset" with `host: {id, username, display_name}`.**
   VERDICT: Corrected → `BroadcastSessionOut` has **no `host` object**; owner is the
   `created_by` string. Required fields: `id, profile_id, status, created_by,
   created_at, updated_at`. Title is the nullable `name`; schedule time is
   `scheduled_at` (integer). SOURCE: OpenAPI `components.schemas.BroadcastSessionOut`;
   frontend `src/api/endpoints/broadcast.ts: BroadcastSession`.
9. **All mutations carry `X-CSRF-Token` from the `ui_csrf` cookie (global
   interceptor).** VERDICT: Verified. SOURCE: frontend `src/api/client.ts`
   (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`; `credentials:
   "include"`).
10. **`status` is a typed enum incl. `scheduled`/`cancelled`.** VERDICT: Verified
    (web models `draft | scheduled | provisioning | ready | live | stopping |
    stopped | cancelled | error`); on the wire `status` is a free string, so the
    AND-278 mapper must tolerate unknown values. SOURCE: frontend
    `src/api/endpoints/broadcast.ts: BroadcastSessionStatus`; OpenAPI
    `BroadcastSessionOut.status: string`.
11. **Cancel transitions session to `status:"cancelled"`.** VERDICT: Verified
    (response type) / partially Unverified (exact value). The route returns
    `BroadcastSessionOut`; `cancelled_at` is a field and `cancelled` is a known
    status, but the precise post-cancel status string is not pinned by the schema.
    SOURCE: OpenAPI `BroadcastSessionOut` (`cancelled_at`, `status`).
12. **Web `broadcast.ts` calls schedule/cancel-schedule.** VERDICT: Corrected →
    the web client only implements create/start/stop/delete/playback; it does NOT
    call `/schedule` or `/cancel-schedule`. Android is the first consumer; those
    two routes are verified from OpenAPI only. SOURCE: `src/api/endpoints/broadcast.ts`
    (no schedule/cancel functions present).
13. **POST/PATCH mutations must not be auto-retried (AND-016 GET-only).** VERDICT:
    Unverified-assumption (Android-internal policy; not in the backend sources).
    Note the schedule/cancel routes are POST, so "PATCH" wording in the draft is
    moot. SOURCE: internal AND-016 reference (not in OpenAPI/frontend).
14. **`403` = not host / not owner; `401` refresh applies.** VERDICT:
    Unverified-assumption. The OpenAPI declares only `422 HTTPValidationError` for
    these three routes; 401/403 are not enumerated. SOURCE: OpenAPI index resp
    columns for the three routes (`...;422:HTTPValidationError` only).
15. **`422` is FastAPI `HTTPValidationError` with `detail[].loc`.** VERDICT:
    Verified. SOURCE: OpenAPI `components.schemas.HTTPValidationError`
    (`detail: [{loc, msg, type}]`).
16. **Stack pins (Compose, Material 3 DatePicker/TimePicker, `collectAsStateWithLifecycle`,
    core-library desugaring for `java.time`).** VERDICT: Unverified-assumption
    (framework choices, not backend contract). SOURCE (framework ref):
    Material 3 date/time pickers — https://developer.android.com/develop/ui/compose/components/datepickers ;
    lifecycle-aware collection — https://developer.android.com/topic/libraries/architecture/coroutines#statef ;
    desugaring — https://developer.android.com/studio/write/java8-support .

### Corrections made

- Create body: `title/description/scheduled_start_at` → **`profile_id` (+ optional
  ingest/stream-key)** (claims #2, #5; FR-3, FR-6, §4.1, §4.3, §5, T-1, AC-1, AC-4).
- Schedule route: `PATCH /broadcast/sessions/{id}` → **`POST .../{id}/schedule`**
  (claim #3; FR-1, FR-4, §4.2, §5, T-2/T-3, AC-1, AC-3).
- Schedule field: `scheduled_start_at` ISO-8601 `Instant` → **`scheduled_at` Unix
  epoch-seconds `Long`/integer**; title is **`name` (≤200)**, description **≤2000**
  (claims #4, #5; FR-6, FR-9, §4.1, §6, §9, §5, AC-4, Q-4).
- Cancel route: `POST .../{id}/cancel` (+ optional `reason`) → **`POST
  .../{id}/cancel-schedule` with no body** (claims #6, #7; FR-1, FR-6, §4.2, §5,
  T-4, AC-2, Q-2, Q-3).
- Response shape: removed the fictitious `host` object; owner = `created_by`,
  title = `name` (claim #8; §4.1, §5).
- DTO/method renames: `UpdateBroadcastScheduleReqDto`→`ScheduleBroadcastReqDto`,
  `CancelBroadcastReqDto` removed, `updateSchedule`→`scheduleSession`,
  `cancelSession`→`cancelSchedule` (§4.1, §4.2, §4.3, §15).
- Resolved Q-1..Q-4 against the sources.

### Open assumptions

- **`profile_id` provenance (NEW, unresolved).** Create now requires a
  `profile_id` the original spec never modeled. Where the host's broadcast profile
  comes from (a `GET /broadcast/profiles` pick, a default, or `POST
  /broadcast/profiles` first) is **not specified** by this ticket and is not
  resolvable from AND-278/the backlog. Assumption: a profile already exists and
  its id is supplied to the create call; if not, a profile-selection step (likely a
  separate ticket) is a prerequisite. *Why unverifiable:* no backlog/spec source
  defines the host profile UX.
- **"Start now" semantics (R-3).** Whether a freshly created session is `draft`
  vs immediately go-live-ready is not pinned; `BroadcastSessionOut.status` is a
  free string and the actual go-live is AND-308's `start`. *Why unverifiable:*
  status transitions are server-side and not enumerated.
- **401/403 behavior** for these routes (claim #14) — not enumerated in OpenAPI.
- **Min schedule lead time** — `scheduled_at` must be `>= min lead time from now`
  but the exact value is server-side; client uses a ≥1-minute buffer and surfaces
  any `422`.
- **AND-278 DTO field names** (`BroadcastSessionDto`/mapper) are assumed to track
  `BroadcastSessionOut` (esp. `name`, `created_by`, integer `scheduled_at`); not
  re-verified here as AND-278 is a separate (unmerged) ticket.
- **Android framework pins** (claim #16) are standard choices, not contract-verified.

## 17. Test Plan

Test-target legend: **JVM** = local JVM unit/Robolectric (no device); **emu35** =
headless AVD `test35` (x86_64, API 35) for CI UI/instrumented suites; **deviceA15**
= physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a) for real-hardware
behavior. This ticket has **no** camera/biometric/WebRTC/FCM/Telecom surface, so
nearly all cases run on JVM/emu35; one ABI/API-parity smoke is pinned to
deviceA15.

- **TC-AND-307-01 — Create happy path (contract).** Type: contract/MockWebServer.
  Target: JVM (`core-network`). Preconditions: MockWebServer enqueues `201` with a
  `BroadcastSessionOut` body (`id, profile_id, status, created_by, created_at,
  updated_at`). Steps: call `BroadcastApi.createSession(CreateBroadcastSessionReqDto(profileId="bp_01HX0"))`.
  Expected: request line `POST /broadcast/sessions`; body JSON contains
  `profile_id` and omits null optionals; response decodes; `toDomain()` yields the
  expected `BroadcastSession`. Traces: AC-1, AC-3, AC-4.
- **TC-AND-307-02 — Schedule serializes epoch-seconds integer (contract).** Type:
  contract/MockWebServer. Target: JVM. Preconditions: MockWebServer enqueues `200`
  with `status:"scheduled"`, `scheduled_at` integer, `name` set. Steps: call
  `scheduleSession("bcs_01HY9", scheduledAt=1781020800L, name="Album party",
  description="...")`. Expected: request `POST /broadcast/sessions/bcs_01HY9/schedule`;
  body has `scheduled_at` as a **JSON number** (not a quoted ISO string) plus
  `name`/`description`; response maps to `SCHEDULED` with `scheduledAt` preserved.
  Traces: AC-1, AC-3, AC-4.
- **TC-AND-307-03 — Cancel-schedule path + empty body (contract).** Type:
  contract/MockWebServer. Target: JVM. Preconditions: enqueue `200` with
  `status:"cancelled"`. Steps: call `cancelSchedule("bcs_01HY9")`. Expected:
  request `POST /broadcast/sessions/bcs_01HY9/cancel-schedule` with **empty body**
  (Content-Length 0 / no JSON); response maps to `CANCELLED`. Traces: AC-2, AC-3.
- **TC-AND-307-04 — 422 validation error propagation (contract).** Type:
  contract/MockWebServer. Target: JVM. Preconditions: enqueue `422` with
  `{"detail":[{"loc":["body","scheduled_at"],"msg":"...","type":"value_error"}]}`.
  Steps: call `scheduleSession(...)` with a past time. Expected: the repository
  returns `ApiResult.Error` carrying an AND-015 `ApiError` whose mapped `loc`
  identifies `scheduled_at`. Traces: AC-5, AC-8.
- **TC-AND-307-05 — Repository ApiResult wrapping + trimming (unit).** Type: unit.
  Target: JVM (`core-data`) with a fake `BroadcastApi`. Preconditions: fake returns
  a success DTO; a second case throws `IOException`. Steps: call `createSession`
  and `scheduleSession(name=" Padded ")`. Expected: success → `ApiResult.Success`;
  `IOException` → `ApiResult.Error`; `name`/`description` are trimmed before send.
  Traces: AC-5.
- **TC-AND-307-06 — CSRF header present on mutations, absent rationale on GET
  (contract).** Type: contract/MockWebServer + integration (real OkHttp stack with
  AND-012 interceptor + seeded `ui_csrf` cookie). Target: JVM/emu35. Preconditions:
  cookie jar seeded with `ui_csrf=abc`. Steps: issue create, schedule, and
  cancel-schedule. Expected: each request carries `X-CSRF-Token: abc`; no manual
  `Cookie`/`Authorization` header set in the interface. Traces: AC-7.
- **TC-AND-307-07 — Client-side validation gates the network (unit).** Type: unit.
  Target: JVM (ViewModel + fixed `Clock` + fake repo). Preconditions: schedule
  mode. Steps: (a) blank `name`; (b) `scheduled_at` in the past; (c) `name` >200
  chars; (d) valid future time + valid name. Expected: (a)-(c) set the matching
  field error, `canSubmit=false`, `submit()` makes **no** repo call; (d) clears
  errors, enables submit. Traces: AC-6.
- **TC-AND-307-08 — Submit success emits one-shot Created event (unit).** Type:
  unit (`runTest` + Turbine). Target: JVM. Preconditions: fake repo returns success.
  Steps: valid input → `submit()`. Expected: `isSubmitting` toggles true→false-path
  and exactly one `CreateBroadcastEvent.Created(sessionId, scheduled)` is emitted;
  `scheduled` reflects now-vs-scheduled mode; re-collection after a simulated
  config change does not re-deliver. Traces: AC-1, AC-9.
- **TC-AND-307-09 — Submit failure surfaces typed error, no event (unit).** Type:
  unit. Target: JVM. Preconditions: fake repo returns `ApiResult.Error` (a `422`
  with `loc=["body","name"]`). Steps: `submit()`. Expected: `submitError`
  populated, `isSubmitting=false`, no `Created` event; the `422` `loc` maps to the
  `name` field error (fallback to form-level if unknown). Traces: AC-8.
- **TC-AND-307-10 — Cancel in edit mode + guard (unit).** Type: unit. Target: JVM.
  Preconditions: `editingSessionId="bcs_01HY9"` (case A) vs null (case B). Steps:
  `cancelSchedule()`. Expected: A → repo `cancelSchedule` called, one `Cancelled`
  event; B → no-op (no repo call). Traces: AC-2.
- **TC-AND-307-11 — Duplicate-submit guard (unit).** Type: unit. Target: JVM.
  Preconditions: first `submit()` in flight (`isSubmitting=true`). Steps: call
  `submit()` again immediately. Expected: the second call starts **no** second repo
  invocation. Traces: AC-7.
- **TC-AND-307-12 — Compose screen behavior + accessibility (Compose-UI).** Type:
  Compose-UI. Target: emu35 (Robolectric acceptable for logic; emu35 for true
  rendering/semantics). Preconditions: screen with default state. Steps: type a
  name (submit enables); toggle "Schedule for later" (DatePicker/TimePicker
  appear); trigger submit (spinner shows); drive an error state (AND-021 error
  composable + retry shows); tap cancel (confirmation `AlertDialog` appears before
  `cancelSchedule`). A11y assertions: name/description fields have labels and
  error semantics (`semantics { error(...) }`), toggle is a labeled selectable
  group, buttons announce disabled/loading, touch targets ≥48dp, errors are
  programmatically associated (not color-only). Traces: AC-1, AC-2, AC-8, AC-10.
- **TC-AND-307-13 — Offline / flaky-dev-host path, no auto-retry (integration).**
  Type: integration. Target: JVM/emu35 with MockWebServer simulating
  `SocketPolicy.NO_RESPONSE` / connection drop (and a `UnknownHostException` case).
  Preconditions: schedule submit. Steps: submit while the host is unreachable.
  Expected: `submitError` becomes a retryable offline state via the AND-021
  offline composable; the client does **not** auto-retry the POST; a manual retry
  re-issues exactly one request. Traces: AC-7, AC-8.
- **TC-AND-307-14 — Auth/permission defensive handling (contract).** Type:
  contract/MockWebServer. Target: JVM. Preconditions: enqueue `403` then `401`
  (note: not enumerated in OpenAPI — assumption per §16 #14). Steps: call create.
  Expected: `403` → not-authorized UI state (no crash); `401` defers to the
  AND-013 refresh authenticator / AND-025 gating. Traces: AC-7, AC-8.
- **TC-AND-307-15 — ABI/API parity smoke (instrumented, physical device).** Type:
  instrumented/e2e. Target: **deviceA15 (physical, arm64-v8a, API 34)** — MUST run
  on the device to catch arm64-vs-x86 and API-34-vs-35 differences in `java.time`
  desugaring (epoch-seconds conversion) and Moshi codegen. Preconditions: app
  installed on SM-A156U; MockWebServer or dev host reachable. Steps: run the
  create→schedule→cancel flow end-to-end. Expected: identical request
  bodies/decoding as emu35; `scheduled_at` integer round-trips correctly; no
  ABI-specific crashes. Traces: AC-1, AC-2, AC-4, AC-10.

### Coverage matrix

| AC | Covered by |
| --- | --- |
| AC-1 (create + schedule) | TC-01, TC-02, TC-08, TC-12, TC-15 |
| AC-2 (cancel-schedule) | TC-03, TC-10, TC-12, TC-15 |
| AC-3 (API verbs/paths/bodies) | TC-01, TC-02, TC-03 |
| AC-4 (Moshi serialization, epoch-seconds) | TC-01, TC-02, TC-15 |
| AC-5 (ApiResult + AND-015 mapping) | TC-04, TC-05 |
| AC-6 (client-side validation) | TC-07 |
| AC-7 (CSRF + no auto-retry + dup guard) | TC-06, TC-11, TC-13, TC-14 |
| AC-8 (typed/localized/retryable errors, loc→field) | TC-04, TC-09, TC-12, TC-13, TC-14 |
| AC-9 (one-shot event + process-death state) | TC-08 |
| AC-10 (a11y/i18n/build) | TC-12, TC-15 |
