---
id: AND-275
title: Scheduler
milestone: M6
epic: E37
priority: P1
size: M
status: draft
depends_on: [AND-270]
blocks: []
---

# AND-275 — Scheduler

## 1. Overview & Goal

This ticket delivers the **Scheduler**: the create/edit experience that lets a
user place a piece of content (a post, broadcast, or message campaign) onto the
calendar at a chosen date/time, optionally with recurrence, and later **reschedule**
or cancel it. It is the write-side counterpart to the read-only calendar views in
epic **E37 (Calendar & scheduling, M6)** and consumes the API and DTO layer that
ships in **AND-270 (Calendar API + DTOs)**.

The feature is exposed through `feature-calendar` as a modal/sheet flow reachable
from the calendar grid (tap an empty slot → "Schedule") and from any schedulable
content draft ("Schedule for later"). The flow presents a form — content
reference, start time, time zone, optional recurrence rule, optional end — that
validates locally, then issues a `POST` (create) or `PATCH` (reschedule/edit)
against the scheduler endpoints. State is exposed by a `SchedulerViewModel` as a
`StateFlow<SchedulerUiState>`, requests go through a `SchedulerRepository` that
returns `ApiResult<ScheduledItem>`, and the screen renders loading, validation,
saving, saved, conflict, offline, and error states; it survives configuration
change and process death.

Goal: a production-ready, accessible, tested scheduler whose acceptance gate is
**"Schedule create/edit works"** — proven by tests that round-trip a create and
an edit through the repository to the (mocked) API and re-hydrate the form from a
persisted item.

Scope boundary: this ticket owns the **scheduler form screen, its ViewModel, the
`SchedulerRepository`, and the request/validation logic** (the Android analogue of
the web `scheduler.ts`). It does **not** own the calendar grid/event rendering or
the `ScheduledItem`/recurrence DTOs and endpoints themselves — those belong to
**AND-270** and the broader calendar views; this ticket consumes them.

## 2. Context & References

- **Repo / module:** `spannella/testlogon`, Android app under `android/`, branch
  `android-port`. Code lands in `feature-calendar` with shared models from
  `core-model` and networking from `core-network`. Namespace/applicationId base:
  `com.testlogon.android`. Feature package: `com.testlogon.android.feature.calendar.scheduler`.
- **Web reference:** the source ticket scopes `scheduler.ts`. Mirror its
  request/response shapes and validation. DTOs (events, recurrence) are defined in
  the web API layer `frontend/src/api/endpoints/calendar.ts` and shared types in
  `frontend/src/api/types.ts`; the Kotlin equivalents are produced by AND-270.
- **Backend:** FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` is
  **plaintext HTTP and unreliable**; OpenAPI at `/openapi.json`. Auth is
  cookie-based with a `ui_csrf` cookie echoed as `X-CSRF-Token`; a persistent
  cookie jar and single-shot `POST /ui/session/refresh`-on-401 retry are provided
  by `core-network` (AND-009 / AND-027 lineage).
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt (KSP),
  Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6, DataStore.
  minSdk 24, compile/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- **Dependencies:** **AND-270** (P0) must land first — it provides the
  `ScheduledItem`, `RecurrenceRule`, and request DTOs plus the `CalendarApi`
  Retrofit interface that this ticket extends/uses.

## 3. Functional Requirements

FR-1 **Entry points.** The scheduler form opens (a) from the calendar grid by
selecting a date/time slot, prefilling `startAt`; and (b) from a schedulable
content draft via "Schedule for later", prefilling `contentRef`.

FR-2 **Create.** The user picks a content reference (if not prefilled), a start
date and time, a time zone (defaulting to the device zone), and an optional
recurrence. Submitting issues a create request; on success the item appears on the
calendar and the sheet dismisses with a confirmation.

FR-3 **Edit / reschedule.** Opening the form for an existing `ScheduledItem`
(passed by `itemId`) loads its current values; the user may change start time, time
zone, recurrence, or cancel. Submitting issues a reschedule request. Editing a
recurring item prompts for scope: **this occurrence** vs **this and following** vs
**all** (maps to the recurrence-edit semantics from AND-270).

FR-4 **Validation (local, pre-submit).** Start time must be in the future
(strictly greater than `now` + a 60-second grace). For recurrence, `interval >= 1`
and, when `until` is set, `until > startAt`. A content reference is required. The
submit affordance is disabled until the form is valid; field-level errors render
inline.

FR-5 **Conflict handling.** If the backend rejects the slot (e.g. another item
already occupies it, or the time has passed server-side), surface a non-fatal
conflict state with the server `detail` message and keep the form populated so the
user can adjust and retry.

FR-6 **State persistence.** Form input survives configuration change and process
death (saved/restored `SavedStateHandle`). A submit in flight is not
double-fired on rotation.

FR-7 **Cancel/dismiss.** Dismissing with unsaved edits prompts for confirmation;
dismissing a pristine form does not.

FR-8 **Offline.** When offline (no successful network), submit is blocked with an
offline banner; the form remains editable and retryable when connectivity returns.

## 4. Technical Design

Module: `feature-calendar`, package
`com.testlogon.android.feature.calendar.scheduler`.

UI state and intents:

```kotlin
sealed interface SchedulerUiState {
    data object Loading : SchedulerUiState                 // edit mode: fetching item
    data class Editing(
        val mode: SchedulerMode,                           // Create | Edit(itemId)
        val form: SchedulerForm,
        val fieldErrors: Map<SchedulerField, String> = emptyMap(),
        val isSubmitting: Boolean = false,
        val isOffline: Boolean = false,
        val transientError: String? = null,               // conflict / server detail
    ) : SchedulerUiState
    data class Saved(val item: ScheduledItem) : SchedulerUiState   // terminal -> dismiss
}

enum class SchedulerField { Content, StartAt, TimeZone, RecurrenceInterval, RecurrenceUntil }

sealed interface SchedulerMode {
    data object Create : SchedulerMode
    data class Edit(val itemId: String) : SchedulerMode
}

data class SchedulerForm(
    val contentRef: ContentRef? = null,
    val startAt: Instant? = null,
    val zoneId: String = ZoneId.systemDefault().id,
    val recurrence: RecurrenceInput? = null,             // null = one-off
    val editScope: RecurrenceEditScope = RecurrenceEditScope.THIS_ONLY,
)

data class RecurrenceInput(
    val freq: RecurrenceFreq,                             // DAILY|WEEKLY|MONTHLY (from AND-270)
    val interval: Int = 1,
    val until: Instant? = null,
)

enum class RecurrenceEditScope { THIS_ONLY, THIS_AND_FOLLOWING, ALL }
```

ViewModel (Hilt, `SavedStateHandle` carries `itemId`/`startAtSeed`/`contentRef`):

```kotlin
@HiltViewModel
class SchedulerViewModel @Inject constructor(
    private val repo: SchedulerRepository,
    private val clock: Clock,
    savedState: SavedStateHandle,
) : ViewModel() {
    val uiState: StateFlow<SchedulerUiState>
    fun onContentSelected(ref: ContentRef)
    fun onStartAtChanged(instant: Instant)
    fun onZoneChanged(zoneId: String)
    fun onRecurrenceChanged(input: RecurrenceInput?)
    fun onEditScopeChanged(scope: RecurrenceEditScope)
    fun onSubmit()
    fun onDismissError()
    fun onRetry()
}
```

Repository (consumes the `CalendarApi` from AND-270; returns typed `ApiResult`):

```kotlin
interface SchedulerRepository {
    suspend fun loadItem(itemId: String): ApiResult<ScheduledItem>
    suspend fun create(request: ScheduleCreateRequest): ApiResult<ScheduledItem>
    suspend fun reschedule(
        itemId: String,
        request: ScheduleUpdateRequest,
    ): ApiResult<ScheduledItem>
    suspend fun cancel(itemId: String, scope: RecurrenceEditScope): ApiResult<Unit>
}
```

Validation is a pure function for unit-testing in isolation:

```kotlin
object SchedulerValidator {
    fun validate(form: SchedulerForm, now: Instant): Map<SchedulerField, String>
    // empty map == valid
}
```

Navigation: a destination `scheduler?itemId={itemId}&startAt={epochSec}&contentRef={ref}`
on the single-Activity Nav-Compose graph; presented as a Material 3
`ModalBottomSheet` (or full-screen sheet on compact width). The composable
`SchedulerSheet(state, onIntent, onDismiss)` is stateless and driven by `uiState`.
Date/time entry uses Material 3 `DatePicker` + `TimePicker`; recurrence uses a
segmented control + stepper + optional "until" date.

## 5. API Contract

Endpoints are owned/defined by **AND-270**; this ticket exercises the
create/update/cancel verbs. Paths are under the cookie-authenticated `/ui` surface
(confirm exact names against `/openapi.json` during implementation — adjust DTO
field names to match the generated AND-270 models, which are authoritative).

**Create** — `POST /ui/calendar/scheduled`

```json
{
  "content_ref": { "type": "post", "id": "pst_9f3a" },
  "start_at": "2026-06-10T18:30:00Z",
  "time_zone": "America/Chicago",
  "recurrence": { "freq": "WEEKLY", "interval": 1, "until": "2026-09-01T00:00:00Z" }
}
```

Response `201`:

```json
{
  "id": "sch_01J2C7",
  "content_ref": { "type": "post", "id": "pst_9f3a" },
  "start_at": "2026-06-10T18:30:00Z",
  "time_zone": "America/Chicago",
  "recurrence": { "freq": "WEEKLY", "interval": 1, "until": "2026-09-01T00:00:00Z" },
  "status": "scheduled",
  "created_at": "2026-06-05T14:00:00Z"
}
```

**Reschedule / edit** — `PATCH /ui/calendar/scheduled/{id}`

```json
{
  "start_at": "2026-06-11T20:00:00Z",
  "time_zone": "America/Chicago",
  "recurrence": null,
  "edit_scope": "this_and_following"
}
```

Response `200`: same `ScheduledItem` shape as create. Omitted fields are left
unchanged (partial update); `recurrence: null` clears recurrence.

**Cancel** — `DELETE /ui/calendar/scheduled/{id}?scope=all` → `204`.

Headers: all mutating requests send the `X-CSRF-Token` header (value from the
`ui_csrf` cookie) and ride the persistent cookie jar; both are applied by the
shared OkHttp interceptors. On `401` the network layer performs one
`POST /ui/session/refresh` then retries.

Errors use the FastAPI `detail` convention mapped by `core-network`:
`detail` may be a `string`, a list `[{ "msg": "..." }]`, or an object
`{ "code": "slot_conflict", ... }`. A `409` with `code: slot_conflict` maps to the
conflict UI state; `422` maps field-level messages back onto `SchedulerField`
where the loc path is recognized.

## 6. Data & State Management

- **Source of truth:** the backend `ScheduledItem`. This ticket does not introduce
  new Room tables; on successful create/edit it invalidates the calendar cache
  owned by AND-270 (calls `calendarCache.invalidateRange(...)`) so the grid
  re-fetches. If AND-270's cache is not yet present, success simply triggers a
  `NavResult`/event the calendar screen observes to refresh.
- **In-flight state:** `isSubmitting` gates the submit button and ignores repeat
  taps; `onSubmit()` is idempotent while a request is active (a `Job` guard).
- **Draft persistence:** `SchedulerForm` is serialized into `SavedStateHandle`
  (Instants as epoch-seconds longs, enums as names) so rotation/process-death
  restore the exact form. No DataStore persistence — drafts are intentionally
  ephemeral to the sheet's lifecycle.
- **Time handling:** `startAt` is stored as a UTC `Instant`; the display layer
  renders it in the selected `zoneId`. The request serializes ISO-8601 UTC for
  `start_at` and the IANA zone id for `time_zone`. `Clock` is injected so tests can
  pin "now".
- **Edit hydration:** in `Edit` mode the ViewModel calls `repo.loadItem(itemId)`,
  maps the `ScheduledItem` into a `SchedulerForm`, and shows `Editing`.

## 7. Error Handling & Resilience

- **Timeouts/transport:** mutating POST/PATCH/DELETE are **not** auto-retried
  (non-idempotent on the dev host); they surface a retryable error with the
  mapped `detail`. The edit-mode `loadItem` GET is idempotent and uses the shared
  bounded-backoff retry (≤2 retries, ~20s ceiling) from `core-network`.
- **Conflict (`409 slot_conflict`):** rendered as `transientError` inside
  `Editing`, form retained; user adjusts time and re-submits.
- **Validation (`422`):** mapped to `fieldErrors`; if a loc path can't be mapped,
  fall back to a top-level `transientError`.
- **Auth (`401`):** handled by the network layer's single refresh+retry; a second
  `401` propagates as an auth error that routes to re-login.
- **Offline / unknown host:** `ApiResult` network failure → `isOffline = true`,
  submit blocked, "Retry" available.
- **Process death mid-submit:** the in-flight request is lost (no WorkManager in
  scope); on restore the form is shown un-submitted and the user re-submits. This
  is acceptable for P1 and noted in §13.

## 8. Security & Privacy

- All requests are cookie-authenticated over the shared OkHttp client; the
  scheduler never reads or persists raw credentials or cookies.
- CSRF: every mutation includes `X-CSRF-Token` from `ui_csrf`; missing-token
  responses (`403`) surface a generic error and trigger a session refresh.
- The dev backend is plaintext HTTP; release builds must point at an HTTPS host and
  use cleartext only via the existing dev `network_security_config` (no new
  cleartext exceptions added here).
- No PII beyond content references and timestamps is handled; nothing is written to
  logs in cleartext (see §10). `SavedStateHandle` draft contents are process-local.

## 9. Accessibility & i18n

- All form controls have `contentDescription`/`semantics`; the date and time
  pickers use Material 3 components which carry built-in TalkBack support. The
  submit button announces its disabled/enabled state and reason.
- Inline field errors are associated with their field via `semantics { error(msg) }`
  so TalkBack reads them; the conflict banner uses `liveRegion = Polite`.
- Touch targets ≥ 48dp; layout reflows for compact and expanded widths and for
  font scaling to 200% without truncation.
- All strings live in `strings.xml` (no hardcoded UI text); dates/times are
  formatted via `java.time` + locale-aware formatters and the user-selected
  `zoneId`. Recurrence summaries ("Weekly until Sep 1") are composed from
  pluralizable string resources.

## 10. Telemetry & Logging

- Analytics events (via the app's existing analytics facade): `scheduler_opened`
  (mode), `scheduler_submit_attempt` (mode, hasRecurrence), `scheduler_submit_success`
  (mode, itemId), `scheduler_submit_error` (mode, errorKind: validation|conflict|network|auth),
  `scheduler_cancelled`. No content bodies or PII in event params.
- Logging: structured `Timber` logs at `d` for state transitions and `w` for mapped
  API errors (error kind + HTTP status only, never request bodies or cookies).
  OkHttp body logging stays at the `core-network` debug level and is off in release.

## 11. Testing Strategy

Acceptance gate: **"Schedule create/edit works."**

- **Unit — validator:** `SchedulerValidatorTest` covers future-time grace, missing
  content, `interval < 1`, `until <= startAt`, and the all-valid path.
- **Unit — ViewModel (Turbine + fake repo):**
  - create happy path: fill form → `onSubmit()` → emits `isSubmitting=true` then
    `Saved(item)`; verifies the `ScheduleCreateRequest` sent (start_at UTC, zone,
    recurrence).
  - edit hydration: `Edit(itemId)` → `Loading` → `Editing` with form mapped from a
    fixture `ScheduledItem`; change start → submit → `ScheduleUpdateRequest` carries
    `edit_scope` and new `start_at`; emits `Saved`.
  - conflict: repo returns `409 slot_conflict` → `Editing` with `transientError`,
    form retained, not `Saved`.
  - offline: repo returns network failure → `isOffline=true`, no request retried.
  - double-submit guard: two `onSubmit()` calls → exactly one repo invocation.
- **Repository — contract (MockWebServer):** asserts method/path/body for create
  (`POST /ui/calendar/scheduled`), reschedule (`PATCH .../{id}`), cancel
  (`DELETE .../{id}?scope=`), `X-CSRF-Token` presence, and `detail` mapping for
  string/list/object shapes; verifies GET `loadItem` is retried but POST/PATCH are
  not.
- **UI (Compose):** `SchedulerSheetTest` — submit disabled until valid, inline
  error semantics present, conflict banner announced, dismiss-with-unsaved prompt,
  state survives `StateRestorationTester`.
- Fixtures live in `core-testing`; all networked tests use MockWebServer (no live
  dev host).

## 12. Dependencies & Sequencing

- **Hard dependency: AND-270 (P0)** — provides `ScheduledItem`, `RecurrenceRule`/
  `RecurrenceFreq`, request DTOs, the `CalendarApi` Retrofit interface, and the
  calendar cache invalidation hook. This ticket cannot merge until AND-270's DTOs
  and endpoints are stable; until then, develop against AND-270's interfaces and a
  fake repository.
- **Soft adjacency:** the calendar grid views (other E37 tickets) provide the slot
  entry point and consume the post-create refresh signal; coordinate the
  `NavResult` contract with them. If they are not yet merged, the scheduler is still
  independently launchable via deep route for testing.
- **Platform:** relies on `core-network` cookie jar + CSRF + 401-refresh
  interceptors already in place on `android-port`.
- **Blocks:** none recorded in the backlog.

## 13. Risks & Open Questions

- **R1 — DTO drift.** Exact endpoint paths and field names depend on AND-270 /
  `/openapi.json`; the JSON in §5 is the expected shape and must be reconciled
  during implementation. *Mitigation:* generate from AND-270's authoritative models.
- **R2 — Recurrence edit semantics.** Whether the backend supports
  `this_and_following`/`all` scopes (vs only single-occurrence) is unconfirmed.
  *Open question for AND-270 / backend.* If unsupported, hide the scope chooser and
  treat all edits as single-item.
- **R3 — Unreliable dev host.** Non-idempotent submits cannot be safely retried; a
  timeout after a successful server write could show an error despite success.
  *Mitigation:* on retry, treat a subsequent `409`/duplicate as "already scheduled";
  consider an `Idempotency-Key` header if AND-270/backend supports it (open
  question).
- **R4 — Time-zone correctness** across DST boundaries for recurring items is
  subtle; rely on backend-side recurrence expansion and only send the rule + zone.
- **R5 — No durable submit** across process death (no WorkManager in scope).
  Acceptable for P1; revisit if reliability complaints arise.

## 14. Acceptance Criteria

- AC-1 (gate) From the calendar/draft entry point a user can create a scheduled
  item: a valid form submits `POST /ui/calendar/scheduled` and, on `201`, the sheet
  dismisses to `Saved` and the calendar reflects the new item. Verified by ViewModel
  + repository tests.
- AC-2 (gate) Opening an existing item in edit mode hydrates the form from the
  `ScheduledItem`, and changing the start time submits `PATCH /ui/calendar/scheduled/{id}`
  with the new `start_at`/`time_zone`/`edit_scope` and yields `Saved`.
- AC-3 Local validation blocks submit for past start times, missing content,
  `interval < 1`, and `until <= startAt`, with inline field errors.
- AC-4 A `409 slot_conflict` surfaces the server `detail` without losing form state;
  the user can adjust and retry.
- AC-5 Offline blocks submit with a banner and offers retry; no non-idempotent
  request is auto-retried.
- AC-6 Form state survives rotation and process death; concurrent submits fire the
  repository exactly once.
- AC-7 All mutations carry `X-CSRF-Token`; a single `401` is transparently
  recovered via session refresh.

## 15. Definition of Done

- `SchedulerViewModel`, `SchedulerUiState`, `SchedulerForm`, `SchedulerValidator`,
  `SchedulerRepository`(+impl), and `SchedulerSheet` implemented in
  `feature-calendar` under `com.testlogon.android.feature.calendar.scheduler`,
  wired with Hilt and the Nav-Compose `scheduler` destination.
- Consumes AND-270's `CalendarApi`/DTOs (no duplicate DTOs introduced) and triggers
  calendar refresh/cache invalidation on success.
- All §11 tests written and green in CI; create and edit paths covered end-to-end
  against MockWebServer; no test hits the live dev host.
- All user-facing strings externalized; TalkBack and 200% font-scale checks pass.
- No new cleartext network exceptions; CSRF and cookie handling verified.
- `ktlint`/`detekt` clean; PR builds on `android-port` with AGP 8.7.3 / Gradle 8.9 /
  JDK 17; reviewed and merged behind the E37 calendar surface.
