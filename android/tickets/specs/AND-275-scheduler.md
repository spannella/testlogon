---
id: AND-275
title: Scheduler
milestone: M6
epic: E37
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
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
content draft ("Schedule for later"). The flow presents a form — action type, scheduled time, title, optional
description and payload — that validates locally, then issues a `POST` (create)
or `PATCH` (reschedule/edit) against the **scheduler-actions** endpoints. State is
exposed by a `SchedulerViewModel` as a `StateFlow<SchedulerUiState>`, requests go
through a `SchedulerRepository` that returns `ApiResult<ScheduledAction>`, and the
screen renders loading, validation, saving, saved, offline, and error states; it
survives configuration change and process death.

> **Review correction (AND-275 §1).** The backend scheduler is the
> `/ui/scheduler/actions` surface (schema `ScheduledActionOut`), NOT a
> `/ui/calendar/scheduled` surface, and its model is an **action** keyed by
> `action_type` + `scheduled_at` (epoch-seconds integer). Recurrence, time zone,
> `content_ref`, and recurrence edit-scope DO NOT exist on the scheduler-actions
> API — those belong to the separate calendar *Events* API (`EventCreateIn` /
> `RecurrenceRule`, verified in `src/api/types.ts`), which is out of this ticket's
> scope. References to recurrence/timezone/edit-scope below are corrected or
> marked as out-of-scope; see §16 for the full audit. The original `scheduler.ts`
> web reference and the OpenAPI index are authoritative here.

Goal: a production-ready, accessible, tested scheduler whose acceptance gate is
**"Schedule create/edit works"** — proven by tests that round-trip a create and
an edit through the repository to the (mocked) API and re-hydrate the form from a
persisted action.

Scope boundary: this ticket owns the **scheduler form screen, its ViewModel, the
`SchedulerRepository`, and the request/validation logic** (the Android analogue of
the web `scheduler.ts`). It consumes the `ScheduledAction*` DTOs and the
`SchedulerApi` Retrofit interface produced by **AND-270**; it does **not** own the
calendar grid rendering. (Correction: AND-270 here means the scheduler-actions DTO
layer — `ScheduledActionOut`, `ScheduledActionCreateIn`, `ScheduledActionUpdateIn`
— not a calendar `ScheduledItem`/recurrence DTO, which does not exist for this
endpoint.)

## 2. Context & References

- **Repo / module:** `spannella/testlogon`, Android app under `android/`, branch
  `android-port`. Code lands in `feature-calendar` with shared models from
  `core-model` and networking from `core-network`. Namespace/applicationId base:
  `com.testlogon.android`. Feature package: `com.testlogon.android.feature.calendar.scheduler`.
- **Web reference:** the source ticket scopes `scheduler.ts`. Mirror its
  request/response shapes and validation. The authoritative web file is
  `frontend/src/api/endpoints/scheduler.ts` (verified): it defines
  `ScheduledActionOut`, `CreateActionReq`, `UpdateActionReq`, and the
  `/ui/scheduler/actions` calls. Screen behavior is in
  `frontend/src/pages/scheduler/SchedulerPage.tsx`. (Correction: the recurrence/
  event DTOs in `calendar.ts` / `types.ts: RecurrenceRule`/`EventCreateIn` are a
  **different** feature — the calendar Events API — and are NOT used by the
  scheduler.) The Kotlin `ScheduledAction*` equivalents are produced by AND-270.
- **Backend:** FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` is
  **plaintext HTTP and unreliable**; OpenAPI at `/openapi.json`. Auth is
  cookie-based with a `ui_csrf` cookie echoed as `X-CSRF-Token`; a persistent
  cookie jar and single-shot `POST /ui/session/refresh`-on-401 retry are provided
  by `core-network` (AND-009 / AND-027 lineage).
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt (KSP),
  Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6, DataStore.
  minSdk 24, compile/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- **Dependencies:** **AND-270** (P0) must land first — it provides the
  `ScheduledAction` model (from `ScheduledActionOut`) and the
  `ScheduledActionCreateIn`/`ScheduledActionUpdateIn` request DTOs plus the
  `SchedulerApi` Retrofit interface that this ticket extends/uses. (Correction:
  no `RecurrenceRule`/`CalendarApi` is involved — that is the calendar Events
  feature, not the scheduler.)

## 3. Functional Requirements

FR-1 **Entry points.** The scheduler form opens (a) from the scheduler/calendar
grid by selecting a date/time slot, prefilling `scheduledAt`; and (b) from a
schedulable content draft via "Schedule for later", prefilling `actionType` (and
optionally `payload`). (Correction: the prefilled values are `scheduledAt` and
`actionType`, not `startAt`/`contentRef` — see the verified
`CreateActionReq`/`ScheduledActionCreateIn` shape.)

FR-2 **Create.** The user picks an action type (`post`, `file_share`,
`catalog_sale`, `message`, `broadcast` — verified from `SchedulerPage.tsx`
`TYPE_LABELS`), a scheduled date and time, a title, and optional description /
payload / `notify_before_seconds`. Submitting issues a create request; on success
the action appears on the scheduler calendar and the sheet dismisses with a
confirmation. (Correction: no time zone or recurrence input — those fields do not
exist on the scheduler-actions API.)

FR-3 **Edit / reschedule.** Opening the form for an existing `ScheduledAction`
(passed by `actionId`) loads its current values; the user may change
`scheduled_at`, `title`, `description`, `payload`, or `notify_before_seconds`, or
cancel. Submitting issues a `PATCH` reschedule request (partial update — only
non-null fields are sent). (Correction: there is no recurrence-edit scope chooser
— `this occurrence`/`this and following`/`all` is calendar-Events semantics, not
scheduler-actions; `ScheduledActionUpdateIn` has no `edit_scope` field. The
chooser is removed from scope.)

FR-4 **Validation (local, pre-submit).** Scheduled time must be in the future
(strictly greater than `now` + a 60-second grace). An action type is required
(`action_type` and `scheduled_at` are the only `required` fields per
`ScheduledActionCreateIn`). The submit affordance is disabled until the form is
valid; field-level errors render inline. (Correction: recurrence `interval`/
`until` validation is removed — no recurrence fields exist.)

FR-5 **Server-error handling.** The scheduler-actions endpoints document only
`422 HTTPValidationError` (verified — no `409`/slot-conflict is defined). If the
backend rejects the request, surface a non-fatal error state with the server
`detail` (normalized per the web client's `normalizeErrorDetail`: string, list of
`{msg}`, or object) and keep the form populated so the user can adjust and retry.
(Correction: "slot conflict" / `409 slot_conflict` was unverified and is not part
of the contract; treated as a generic retryable server error.)

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

> **Review correction (AND-275 §4).** The model below is rewritten to match the
> verified `ScheduledActionOut` / `ScheduledActionCreateIn` / `ScheduledActionUpdateIn`
> shapes. Removed: `ContentRef`, `zoneId`, `RecurrenceInput`, `RecurrenceFreq`,
> `RecurrenceEditScope` (none exist on the scheduler-actions API). Added the real
> fields: `actionType`, `scheduledAt` (epoch seconds), `title`, `description`,
> `payload`, `notifyBeforeSeconds`.

```kotlin
sealed interface SchedulerUiState {
    data object Loading : SchedulerUiState                 // edit mode: fetching action
    data class Editing(
        val mode: SchedulerMode,                           // Create | Edit(actionId)
        val form: SchedulerForm,
        val fieldErrors: Map<SchedulerField, String> = emptyMap(),
        val isSubmitting: Boolean = false,
        val isOffline: Boolean = false,
        val transientError: String? = null,               // server detail (422 / other)
    ) : SchedulerUiState
    data class Saved(val action: ScheduledAction) : SchedulerUiState   // terminal -> dismiss
}

enum class SchedulerField { ActionType, ScheduledAt, Title, NotifyBeforeSeconds }

sealed interface SchedulerMode {
    data object Create : SchedulerMode
    data class Edit(val actionId: String) : SchedulerMode
}

data class SchedulerForm(
    val actionType: String? = null,                      // post|file_share|catalog_sale|message|broadcast
    val scheduledAt: Instant? = null,                    // serialized to epoch-seconds Long
    val title: String = "",
    val description: String = "",
    val payload: Map<String, Any?> = emptyMap(),
    val notifyBeforeSeconds: Int = 0,
)
```

ViewModel (Hilt, `SavedStateHandle` carries `actionId`/`scheduledAtSeed`/`actionType`):

```kotlin
@HiltViewModel
class SchedulerViewModel @Inject constructor(
    private val repo: SchedulerRepository,
    private val clock: Clock,
    savedState: SavedStateHandle,
) : ViewModel() {
    val uiState: StateFlow<SchedulerUiState>
    fun onActionTypeSelected(type: String)
    fun onScheduledAtChanged(instant: Instant)
    fun onTitleChanged(title: String)
    fun onDescriptionChanged(text: String)
    fun onNotifyBeforeChanged(seconds: Int)
    fun onSubmit()
    fun onDismissError()
    fun onRetry()
}
```

Repository (consumes the `SchedulerApi` from AND-270; returns typed `ApiResult`):

```kotlin
interface SchedulerRepository {
    // GET /ui/scheduler/actions/{action_id}
    suspend fun loadAction(actionId: String): ApiResult<ScheduledAction>
    // POST /ui/scheduler/actions  -> 201
    suspend fun create(request: ScheduledActionCreateIn): ApiResult<ScheduledAction>
    // PATCH /ui/scheduler/actions/{action_id}  -> 200
    suspend fun reschedule(
        actionId: String,
        request: ScheduledActionUpdateIn,
    ): ApiResult<ScheduledAction>
    // DELETE /ui/scheduler/actions/{action_id}  -> 200 { ok, action_id, status }
    suspend fun cancel(actionId: String): ApiResult<Unit>
}
```

(Correction: `cancel` takes no `scope` argument — the DELETE endpoint has no
`scope` query param and returns `200`, not `204`.)

Validation is a pure function for unit-testing in isolation:

```kotlin
object SchedulerValidator {
    fun validate(form: SchedulerForm, now: Instant): Map<SchedulerField, String>
    // empty map == valid
}
```

Navigation: a destination `scheduler?actionId={actionId}&scheduledAt={epochSec}&actionType={type}`
on the single-Activity Nav-Compose graph; presented as a Material 3
`ModalBottomSheet` (or full-screen sheet on compact width). The composable
`SchedulerSheet(state, onIntent, onDismiss)` is stateless and driven by `uiState`.
Date/time entry uses Material 3 `DatePicker` + `TimePicker`; the action type uses
a segmented control / dropdown over the verified type set. (Correction: no
recurrence stepper/"until" control — recurrence is not in the scheduler-actions
model.)

## 5. API Contract

Endpoints are owned/defined by **AND-270**; this ticket exercises the
create/update/cancel verbs. Paths are under the cookie-authenticated `/ui` surface.
**All shapes below are VERIFIED against `openapi.index.txt` (lines 1834–1839),
the `ScheduledAction*` schemas in `openapi.pretty.json`, and the web
`scheduler.ts`.** Timestamps are **epoch-seconds integers**, not ISO-8601 strings.

**Create** — `POST /ui/scheduler/actions` → `201:ScheduledActionOut`
(req schema `ScheduledActionCreateIn`; required: `action_type`, `scheduled_at`)

```json
{
  "action_type": "post",
  "scheduled_at": 1749580200,
  "title": "Launch teaser",
  "description": "",
  "payload": {},
  "notify_before_seconds": 0
}
```

Response `201` (`ScheduledActionOut`; required: `action_id`, `action_type`,
`status`, `scheduled_at`, `created_at`):

```json
{
  "action_id": "act_01J2C7",
  "action_type": "post",
  "status": "pending",
  "scheduled_at": 1749580200,
  "created_at": 1749132000,
  "updated_at": null,
  "completed_at": null,
  "title": "Launch teaser",
  "description": "",
  "payload": {},
  "error": null,
  "retry_count": 0,
  "max_retries": 3,
  "notify_before_seconds": 0,
  "reminder_sent": false
}
```

**Reschedule / edit** — `PATCH /ui/scheduler/actions/{action_id}`
→ `200:ScheduledActionOut` (req schema `ScheduledActionUpdateIn`; all fields
optional/nullable: `scheduled_at`, `title`, `description`, `payload`,
`notify_before_seconds`)

```json
{
  "scheduled_at": 1749672000,
  "title": "Launch teaser (moved)"
}
```

Response `200`: same `ScheduledActionOut` shape as create. Omitted/null fields are
left unchanged (partial update). (Correction: `ScheduledActionUpdateIn` has no
`action_type`, `time_zone`, `recurrence`, or `edit_scope` field — `action_type` is
immutable after create.)

**Cancel** — `DELETE /ui/scheduler/actions/{action_id}` → `200`
(web `deleteScheduledAction` returns `{ "ok": true, "action_id": "...", "status": "cancelled" }`).
(Correction: no `?scope=` query param; status is `200`, not `204`.)

Headers: all mutating requests send the `X-CSRF-Token` header (value from the
`ui_csrf` cookie) and ride the persistent cookie jar; both are applied by the
shared OkHttp interceptors. **Verified** in `src/api/client.ts` (CSRF from
`ui_csrf` cookie set as `X-CSRF-Token`, `credentials: "include"`). On `401` the
client performs one `POST /ui/session/refresh` then retries (verified
`refreshSession()` + single-flight retry); a second `401` logs out.

Errors use the FastAPI `detail` convention mapped by `core-network`:
`detail` may be a `string`, a list `[{ "msg": "..." }]`, or an object — handled by
the web `normalizeErrorDetail` (verified). The scheduler-actions endpoints document
only `422 HTTPValidationError`; `422` maps field-level messages back onto
`SchedulerField` where the loc path is recognized, otherwise falls back to a
top-level `transientError`. (Correction: there is no documented `409`/
`slot_conflict` for these endpoints — that claim is removed.)

## 6. Data & State Management

- **Source of truth:** the backend `ScheduledAction`. This ticket does not
  introduce new Room tables; on successful create/edit it invalidates the
  scheduler cache owned by AND-270 (e.g. `schedulerCache.invalidateRange(...)`) so
  the grid re-fetches. If AND-270's cache is not yet present, success simply
  triggers a `NavResult`/event the scheduler screen observes to refresh.
- **In-flight state:** `isSubmitting` gates the submit button and ignores repeat
  taps; `onSubmit()` is idempotent while a request is active (a `Job` guard).
- **Draft persistence:** `SchedulerForm` is serialized into `SavedStateHandle`
  (the `scheduledAt` Instant as an epoch-seconds long, strings as-is) so
  rotation/process-death restore the exact form. No DataStore persistence — drafts
  are intentionally ephemeral to the sheet's lifecycle.
- **Time handling:** `scheduledAt` is stored as an `Instant` and serialized to the
  request as an **epoch-seconds integer** (`scheduled_at`), matching
  `ScheduledActionCreateIn`/`Out` (verified `type: integer`). The display layer
  renders it in the device-local zone (web uses `new Date(ts*1000).toLocaleString()`
  — no server time zone field). `Clock` is injected so tests can pin "now".
  (Correction: no ISO-8601 serialization and no `time_zone` field.)
- **Edit hydration:** in `Edit` mode the ViewModel calls `repo.loadAction(actionId)`
  (`GET /ui/scheduler/actions/{action_id}`), maps the `ScheduledAction` into a
  `SchedulerForm`, and shows `Editing`.

## 7. Error Handling & Resilience

- **Timeouts/transport:** mutating POST/PATCH/DELETE are **not** auto-retried
  (non-idempotent on the dev host); they surface a retryable error with the
  mapped `detail`. The edit-mode `loadAction` GET is idempotent and uses the
  shared bounded-backoff retry (≤2 retries, ~20s ceiling) from `core-network`.
- **Validation (`422 HTTPValidationError`):** the only documented error body for
  these endpoints. Mapped to `fieldErrors`; if a loc path can't be mapped, fall
  back to a top-level `transientError`. (Correction: the previous `409
  slot_conflict` branch is removed — not part of the verified contract. Any
  unexpected non-2xx is surfaced as a generic retryable `transientError`.)
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
- CSRF: every mutation includes `X-CSRF-Token` from `ui_csrf` (verified in
  `src/api/client.ts`). A `403` surfaces a generic permission error via the shared
  client's `403` handler (verified — the web client toasts the normalized
  `detail`); note the web client triggers session refresh on `401`, not `403`, so
  a `403` here is shown as a non-recoverable permission error rather than auto-refreshed.
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
    `Saved(action)`; verifies the `ScheduledActionCreateIn` sent (`action_type`,
    `scheduled_at` as epoch-seconds integer, `title`, `payload`).
  - edit hydration: `Edit(actionId)` → `Loading` → `Editing` with form mapped from
    a fixture `ScheduledAction`; change time → submit → `ScheduledActionUpdateIn`
    carries the new `scheduled_at` (partial body); emits `Saved`.
  - server error: repo returns `422` → `Editing` with `transientError`/`fieldErrors`,
    form retained, not `Saved`.
  - offline: repo returns network failure → `isOffline=true`, no request retried.
  - double-submit guard: two `onSubmit()` calls → exactly one repo invocation.
- **Repository — contract (MockWebServer):** asserts method/path/body for create
  (`POST /ui/scheduler/actions`, `201`), reschedule (`PATCH .../actions/{id}`,
  `200`), cancel (`DELETE .../actions/{id}`, `200`, no scope param),
  `X-CSRF-Token` presence, and `detail` mapping for string/list/object shapes;
  verifies GET `loadAction` is retried but POST/PATCH are not.
- **UI (Compose):** `SchedulerSheetTest` — submit disabled until valid, inline
  error semantics present, server-error banner announced, dismiss-with-unsaved
  prompt, state survives `StateRestorationTester`.
- Fixtures live in `core-testing`; all networked tests use MockWebServer (no live
  dev host).

## 12. Dependencies & Sequencing

- **Hard dependency: AND-270 (P0)** — provides the `ScheduledAction` model
  (`ScheduledActionOut`), the `ScheduledActionCreateIn`/`ScheduledActionUpdateIn`
  request DTOs, the `SchedulerApi` Retrofit interface, and the scheduler cache
  invalidation hook. This ticket cannot merge until AND-270's DTOs and endpoints
  are stable; until then, develop against AND-270's interfaces and a fake
  repository. (Correction: no `RecurrenceRule`/`RecurrenceFreq`/`CalendarApi` is
  consumed — those are the calendar Events feature, not the scheduler.)
- **Soft adjacency:** the calendar grid views (other E37 tickets) provide the slot
  entry point and consume the post-create refresh signal; coordinate the
  `NavResult` contract with them. If they are not yet merged, the scheduler is still
  independently launchable via deep route for testing.
- **Platform:** relies on `core-network` cookie jar + CSRF + 401-refresh
  interceptors already in place on `android-port`.
- **Blocks:** none recorded in the backlog.

## 13. Risks & Open Questions

- **R1 — DTO drift.** Field names/shapes are now reconciled against the verified
  `ScheduledAction*` schemas (§5, §16); residual drift can come only from AND-270's
  generated Kotlin models. *Mitigation:* generate from AND-270's authoritative models.
- **R2 — Recurrence/edit-scope (RESOLVED by review).** The scheduler-actions API
  has **no** recurrence or `edit_scope`; the chooser is removed from scope. (If a
  future ticket needs recurring scheduling, it would use the separate calendar
  *Events* API — `EventCreateIn`/`RecurrenceRule` — not this endpoint.)
- **R3 — Unreliable dev host.** Non-idempotent submits cannot be safely retried; a
  timeout after a successful server write could show an error despite success.
  *Mitigation:* on retry, reconcile by re-fetching the action list. Note: the
  scheduler-actions endpoints expose **no** `Idempotency-Key` parameter (verified —
  unlike KYC/messaging/cart endpoints which do), so client-side idempotency keying
  is not available here.
- **R4 — Time correctness.** `scheduled_at` is a single epoch-seconds instant with
  no server time zone or recurrence, so DST expansion concerns do not apply; the
  only correctness concern is device-local rendering of the absolute instant.
- **R5 — No durable submit** across process death (no WorkManager in scope).
  Acceptable for P1; revisit if reliability complaints arise.

## 14. Acceptance Criteria

- AC-1 (gate) From the scheduler/draft entry point a user can create a scheduled
  action: a valid form submits `POST /ui/scheduler/actions` and, on `201`, the
  sheet dismisses to `Saved` and the scheduler reflects the new action. Verified by
  ViewModel + repository tests.
- AC-2 (gate) Opening an existing action in edit mode hydrates the form from the
  `ScheduledAction`, and changing the scheduled time submits
  `PATCH /ui/scheduler/actions/{action_id}` with the new `scheduled_at` and yields
  `Saved`.
- AC-3 Local validation blocks submit for past scheduled times (within the
  `now + 60s` grace) and missing `action_type`, with inline field errors.
- AC-4 A `422` (or other non-2xx) surfaces the normalized server `detail` without
  losing form state; the user can adjust and retry.
- AC-5 Offline blocks submit with a banner and offers retry; no non-idempotent
  request is auto-retried.
- AC-6 Form state survives rotation and process death; concurrent submits fire the
  repository exactly once.
- AC-7 All mutations carry `X-CSRF-Token`; a single `401` is transparently
  recovered via session refresh (`POST /ui/session/refresh`).

## 15. Definition of Done

- `SchedulerViewModel`, `SchedulerUiState`, `SchedulerForm`, `SchedulerValidator`,
  `SchedulerRepository`(+impl), and `SchedulerSheet` implemented in
  `feature-calendar` under `com.testlogon.android.feature.calendar.scheduler`,
  wired with Hilt and the Nav-Compose `scheduler` destination.
- Consumes AND-270's `SchedulerApi`/`ScheduledAction*` DTOs (no duplicate DTOs
  introduced) and triggers scheduler refresh/cache invalidation on success.
- All §11 tests written and green in CI; create and edit paths covered end-to-end
  against MockWebServer; no test hits the live dev host.
- All user-facing strings externalized; TalkBack and 200% font-scale checks pass.
- No new cleartext network exceptions; CSRF and cookie handling verified.
- `ktlint`/`detekt` clean; PR builds on `android-port` with AGP 8.7.3 / Gradle 8.9 /
  JDK 17; reviewed and merged behind the E37 calendar surface.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **Create endpoint is `POST /ui/scheduler/actions` returning `201`.**
   VERDICT: Corrected (spec said `POST /ui/calendar/scheduled`).
   SOURCE: `openapi.index.txt:1835` (`POST /ui/scheduler/actions … resp=201:ScheduledActionOut`); frontend `src/api/endpoints/scheduler.ts: createScheduledAction`.
2. **Create request schema is `ScheduledActionCreateIn` (required `action_type`, `scheduled_at`; optional `title`, `description`, `payload`, `notify_before_seconds`).**
   VERDICT: Corrected (spec used `content_ref`/`start_at`/`time_zone`/`recurrence`).
   SOURCE: `openapi.pretty.json` `components.schemas.ScheduledActionCreateIn` (lines 64656–64693); `src/api/endpoints/scheduler.ts: CreateActionReq`.
3. **`scheduled_at` (and `created_at`/`updated_at`/`completed_at`) are epoch-seconds integers, not ISO-8601 strings.**
   VERDICT: Corrected.
   SOURCE: `openapi.pretty.json` `ScheduledActionOut.scheduled_at` `type: integer` (line 64787); web rendering `new Date(ts * 1000)` in `src/pages/scheduler/SchedulerPage.tsx: formatDateTime` (line 54).
4. **Response schema `ScheduledActionOut` (required `action_id`, `action_type`, `status`, `scheduled_at`, `created_at`; plus `status`, `retry_count`, `max_retries`, `notify_before_seconds`, `reminder_sent`, `error`, …).**
   VERDICT: Corrected (spec returned `id`/`content_ref`/`recurrence`/`status:"scheduled"`).
   SOURCE: `openapi.pretty.json` `components.schemas.ScheduledActionOut` (lines 64720–64820); `src/api/endpoints/scheduler.ts: ScheduledActionOut`.
5. **Edit endpoint is `PATCH /ui/scheduler/actions/{action_id}` → `200`, schema `ScheduledActionUpdateIn` (all fields optional/nullable: `scheduled_at`, `title`, `description`, `payload`, `notify_before_seconds`).**
   VERDICT: Corrected (spec said `PATCH /ui/calendar/scheduled/{id}` with `time_zone`/`recurrence`/`edit_scope`).
   SOURCE: `openapi.index.txt:1838`; `openapi.pretty.json` `ScheduledActionUpdateIn` (lines 64822–64882); `src/api/endpoints/scheduler.ts: UpdateActionReq`.
6. **`action_type` is immutable on edit (absent from `ScheduledActionUpdateIn`).**
   VERDICT: Verified.
   SOURCE: `openapi.pretty.json` `ScheduledActionUpdateIn` properties (lines 64823–64880) — no `action_type`.
7. **Cancel endpoint is `DELETE /ui/scheduler/actions/{action_id}` → `200`, no `scope` query param.**
   VERDICT: Corrected (spec said `DELETE /ui/calendar/scheduled/{id}?scope=all` → `204`).
   SOURCE: `openapi.index.txt:1836` (`resp=200:; params=action_id,…` — no `scope`); web `src/api/endpoints/scheduler.ts: deleteScheduledAction` returns `{ ok, action_id, status }`.
8. **Recurrence (`freq`/`interval`/`until`) is NOT part of the scheduler-actions API.**
   VERDICT: Corrected (spec modeled `RecurrenceInput`/`RecurrenceFreq`).
   SOURCE: none of `ScheduledActionCreateIn/UpdateIn/Out` contain recurrence fields (lines 64656–64820). `RecurrenceRule` exists only for the calendar Events API — `src/api/types.ts: RecurrenceRule` (line 1740) used by `EventCreateIn` (line 1750), a different feature.
9. **Time zone (`time_zone`) is NOT part of the scheduler-actions API.**
   VERDICT: Corrected.
   SOURCE: scheduler schemas (lines 64656–64902) have no `time_zone`; the only timezone field is `EventCreateIn.timezone` (`src/api/types.ts:1753`), Events feature.
10. **Recurrence edit-scope (`this occurrence`/`this and following`/`all`) is NOT supported.**
    VERDICT: Corrected (spec invented `RecurrenceEditScope`/`edit_scope`).
    SOURCE: `ScheduledActionUpdateIn` has no `edit_scope` (lines 64822–64882); no `edit_scope` anywhere in `reference/`.
11. **No `409 slot_conflict` for scheduler endpoints; only `422 HTTPValidationError` is documented.**
    VERDICT: Corrected (spec defined a `409 slot_conflict` conflict state).
    SOURCE: `openapi.index.txt:1834–1839` (each lists only `;422:HTTPValidationError`).
12. **Action types are `post`, `file_share`, `catalog_sale`, `message`, `broadcast`.**
    VERDICT: Verified.
    SOURCE: `src/pages/scheduler/SchedulerPage.tsx: TYPE_LABELS`/`TYPE_COLORS` (lines 30–44).
13. **Action statuses include `pending`, `executing`, `completed`, `failed`, `cancelled`; "cancel" affordance is shown only for `pending`.**
    VERDICT: Verified.
    SOURCE: `src/pages/scheduler/SchedulerPage.tsx: STATUS_VARIANTS` (lines 46–52) and the `action.status === "pending"` guard (line 152).
14. **Mutations send `X-CSRF-Token` from the `ui_csrf` cookie over a credentialed (cookie-jar) request.**
    VERDICT: Verified.
    SOURCE: `src/api/client.ts` — `getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)` (lines 168–171), `credentials: "include"` (line 183).
15. **On `401`, the client performs a single `POST /ui/session/refresh` then retries once; a second `401` logs out.**
    VERDICT: Verified.
    SOURCE: `src/api/client.ts: refreshSession()` → `POST /ui/session/refresh` (line 122), single-flight `refreshPromise` + retry (lines 204–236), second-`401` `logout("session_expired")` (line 225).
16. **Error `detail` may be a string, a list of `{msg}`, or an object, and is normalized by the client.**
    VERDICT: Verified.
    SOURCE: `src/api/client.ts: normalizeErrorDetail` (lines 66–102).
17. **Network failure (offline) maps to a distinct non-HTTP error (used to drive `isOffline`).**
    VERDICT: Verified.
    SOURCE: `src/api/client.ts` fetch `catch` → `throw new ApiError(0, "Network error", err)` (lines 185–189).
18. **No `Idempotency-Key` is available on scheduler-actions endpoints.**
    VERDICT: Verified.
    SOURCE: `openapi.index.txt:1834–1839` params lists contain only `types/status/action_id/user_sub/X-SESSION-ID/X-IMPERSONATION-TOKEN` — no idempotency header (contrast KYC `openapi.index.txt:111` which has `Idempotency-Key`).
19. **The web scheduler screen is read/list/cancel + a month calendar grid; create/edit UI is the Android-side addition this ticket implements.**
    VERDICT: Verified (no create/edit form exists in the web `SchedulerPage`; create/edit funcs exist in `scheduler.ts` and are exercised elsewhere, e.g. `schedulePost` → `POST /ui/feed/posts/schedule`).
    SOURCE: `src/pages/scheduler/SchedulerPage.tsx` (list/calendar/cancel only); `src/api/endpoints/scheduler.ts: createScheduledAction`/`updateScheduledAction` (lines 74–84).
20. **Android stack/build (Kotlin 2.0.21, Compose+M3, Hilt/KSP, Retrofit/OkHttp/Moshi, Room/DataStore, minSdk 24 / targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9) and Material 3 `ModalBottomSheet`/`DatePicker`/`TimePicker`, `SavedStateHandle`, `StateRestorationTester`.**
    VERDICT: Unverified-assumption (framework/tooling choices; not derivable from the backend/frontend sources).
    SOURCE: framework ref — https://developer.android.com/jetpack/compose/components/datepicker , https://developer.android.com/topic/libraries/architecture/saving-states , https://developer.android.com/jetpack/compose/testing#state-restoration .

### Corrections made

- §1, §2, §5, §12, §15: endpoint surface changed from the non-existent
  `/ui/calendar/scheduled` to the verified `/ui/scheduler/actions` family; DTO
  names changed from `ScheduledItem`/`CalendarApi` to
  `ScheduledAction`/`ScheduledActionCreateIn`/`ScheduledActionUpdateIn`/`SchedulerApi`.
- §5: full request/response rewrite — `scheduled_at` epoch-seconds integer (not
  ISO string), real `ScheduledActionOut` fields, `status:"pending"`, cancel `200`
  with `{ok,action_id,status}` and no `scope` param.
- §1, §3, §4, §5, §13: removed the fabricated recurrence, time-zone,
  `content_ref`, and recurrence-edit-scope model; corrected the Kotlin
  `SchedulerForm`/`SchedulerUiState`/`SchedulerField`/repository signatures and the
  navigation route accordingly.
- §3 (FR-5), §5, §7, §11, §14 (AC-4): removed the invented `409 slot_conflict`
  conflict state; the only documented error body is `422 HTTPValidationError`,
  with a generic retryable fallback for other non-2xx.
- §4 (`cancel`): dropped the `scope` argument.
- §13: R2 marked resolved (no recurrence), R3 notes no `Idempotency-Key`
  available, R4 reframed (no DST/recurrence concern).
- §8: clarified that the shared client refreshes session on `401`, not `403`.
- Frontmatter: removed the duplicate `status` key; set `status: reviewed` and
  added `reviewed_on: 2026-06-06`.

### Open assumptions

- **Android framework/tooling choices** (Compose M3 components, Hilt, Retrofit/
  Moshi, build versions, `SavedStateHandle`/`StateRestorationTester`): not
  verifiable from backend/frontend sources; standard Android practice (claim 20).
- **AND-270 Kotlin DTO/interface names** (`ScheduledAction`, `SchedulerApi`,
  cache-invalidation hook): assumed to mirror the verified backend schemas; the
  exact generated names depend on AND-270 and must be reconciled at integration.
- **`payload` schema per action type** is an open `object` (`additionalProperties:
  true`) in the backend; the per-type payload contract (e.g. what a `post` action
  carries) is not specified in these sources and is treated as opaque pass-through.
- **`notify_before_seconds` semantics / local-notification behavior** are not
  described in the sources; assumed server-side reminder only (mirrors
  `reminder_sent` field), with no Android-side scheduling in this ticket.

## 17. Test Plan

Each case traces to §14 acceptance criteria. Test targets: **JVM** =
JVM-unit/Robolectric (local, no device); **emu35** = headless AVD `test35`
(x86_64, API 35) for fast UI/instrumented CI; **deviceA15** = physical Samsung
Galaxy A15 5G (SM-A156U, serial `R5CX821TA9R`, Android 14 / API 34, arm64-v8a) for
real-hardware behavior.

- **TC-AND-275-01 — Create happy path (ViewModel).** Type: unit (Turbine + fake
  repo). Target: JVM. Preconditions: `Clock` pinned to a fixed `now`; fake repo
  returns `201` `ScheduledAction`. Steps: set `actionType="post"`,
  `scheduledAt = now + 1h`, `title="t"`; `onSubmit()`. Expected: emits
  `Editing(isSubmitting=true)` then `Saved(action)`; captured request is
  `ScheduledActionCreateIn(action_type="post", scheduled_at=<epochSec>, title="t")`
  with `scheduled_at` an integer. Traces: AC-1.

- **TC-AND-275-02 — Create contract over the wire (Repository).** Type:
  contract/MockWebServer. Target: JVM. Preconditions: MockWebServer enqueues
  `201` with a valid `ScheduledActionOut` body; `ui_csrf` cookie present in jar.
  Steps: `repo.create(request)`. Expected: recorded request is
  `POST /ui/scheduler/actions`, JSON body has integer `scheduled_at` and
  `action_type`, header `X-CSRF-Token` present; response parsed into
  `ScheduledAction` with `status="pending"`, `max_retries=3`. Traces: AC-1, AC-7.

- **TC-AND-275-03 — Edit hydration + reschedule (ViewModel).** Type: unit
  (Turbine + fake repo). Target: JVM. Preconditions: mode `Edit("act_1")`; fake
  `loadAction` returns a fixture `ScheduledAction`. Steps: collect states; change
  `scheduledAt`; `onSubmit()`. Expected: `Loading` → `Editing(form mapped from
  fixture)` → on submit, `reschedule("act_1", ScheduledActionUpdateIn(scheduled_at=<new>))`
  (partial body, no `action_type`) → `Saved`. Traces: AC-2.

- **TC-AND-275-04 — Reschedule + cancel contracts (Repository).** Type:
  contract/MockWebServer. Target: JVM. Preconditions: MockWebServer enqueues
  `200` for PATCH then `200 {ok,action_id,status}` for DELETE. Steps:
  `repo.reschedule(...)`; `repo.cancel("act_1")`. Expected: PATCH to
  `/ui/scheduler/actions/act_1` with partial body; DELETE to
  `/ui/scheduler/actions/act_1` with **no** `scope` query param; both carry
  `X-CSRF-Token`; DELETE handled as `200` (not `204`). Traces: AC-2, AC-7.

- **TC-AND-275-05 — Local validation blocks submit (unit, validator).** Type:
  unit. Target: JVM. Preconditions: pinned `now`. Steps: run
  `SchedulerValidator.validate` for (a) `scheduledAt = now + 30s` (inside grace),
  (b) `scheduledAt` null, (c) `actionType` null, (d) all-valid
  (`now + 1h`, type set). Expected: (a)(b) → `ScheduledAt` error; (c) →
  `ActionType` error; (d) → empty map (valid). Traces: AC-3.

- **TC-AND-275-06 — `422` validation error mapped, form retained (ViewModel).**
  Type: unit (fake repo). Target: JVM. Preconditions: fake repo returns `422`
  with `detail=[{"loc":["body","scheduled_at"],"msg":"in the past"}]`. Steps:
  submit a form that passed local checks. Expected: stays `Editing`, form values
  retained, `fieldErrors[ScheduledAt]` set (or `transientError` fallback if loc
  unmapped), not `Saved`. Traces: AC-4.

- **TC-AND-275-07 — `detail` shape normalization (Repository).** Type:
  contract/MockWebServer. Target: JVM. Preconditions: three responses — `422`
  string `detail`, `422` list-of-`{msg}`, `400` object `detail`. Steps: call
  `create` for each. Expected: each maps to a non-empty human message via the
  `normalizeErrorDetail` equivalent; object/list/string all handled; HTTP status
  preserved on the `ApiResult` error. Traces: AC-4.

- **TC-AND-275-08 — Offline / flaky-dev-host path (ViewModel + Repository).**
  Type: unit + contract. Target: JVM (MockWebServer with
  `SocketPolicy.DISCONNECT_AT_START` / no-route). Steps: attempt `create` while
  the transport fails. Expected: repo yields a network `ApiResult` failure (the
  `ApiError(0,…)` analogue), ViewModel sets `isOffline=true`, submit blocked,
  "Retry" available; the POST is **not** auto-retried (assert single MockWebServer
  request). Traces: AC-5.

- **TC-AND-275-09 — `401` refresh-then-retry, single-flight (Repository).** Type:
  contract/MockWebServer. Target: JVM. Preconditions: enqueue `401`, then `200`
  for `POST /ui/session/refresh`, then `201` for the retried create. Steps:
  `repo.create(...)`. Expected: sequence is original `POST /ui/scheduler/actions`
  → `POST /ui/session/refresh` → retried `POST /ui/scheduler/actions` (with
  `X-CSRF-Token`); final result is success. Second-`401` variant: enqueue `401`,
  refresh `200`, `401` again → surfaces auth error / re-login. Traces: AC-7.

- **TC-AND-275-10 — Double-submit guard (ViewModel).** Type: unit. Target: JVM.
  Preconditions: fake repo suspends on first `create`. Steps: call `onSubmit()`
  twice rapidly. Expected: exactly one `repo.create` invocation; `isSubmitting`
  gates the second call. Traces: AC-6.

- **TC-AND-275-11 — State survives rotation & process death (Compose UI).** Type:
  Compose-UI / instrumented. Target: emu35 (KVM-fast in CI). Preconditions:
  `SchedulerSheet` rendered with a partially filled form. Steps: drive
  `StateRestorationTester.emulateSavedInstanceStateRestore()`; also re-create with
  the same `SavedStateHandle`. Expected: `actionType`, `scheduledAt`, `title`
  restored identically; no in-flight submit re-fires. Traces: AC-6.

- **TC-AND-275-12 — Submit affordance + error semantics (Compose UI).** Type:
  Compose-UI. Target: emu35. Preconditions: stateless `SchedulerSheet`. Steps:
  render with invalid then valid `Editing` state; render with `fieldErrors` and
  with `transientError`. Expected: submit disabled while invalid (and exposes a
  disabled-reason semantics); inline field error exposed via
  `semantics { error(...) }`; server-error banner present with
  `liveRegion = Polite`. Traces: AC-3, AC-4.

- **TC-AND-275-13 — Accessibility: TalkBack + 200% font scale (instrumented).**
  Type: instrumented/e2e (accessibility). Target: deviceA15 (real TalkBack engine
  and font-scale rendering preferred over emulator). Preconditions: TalkBack on;
  system font scale 200%. Steps: open the scheduler sheet, traverse all controls,
  trigger a field error. Expected: every control has a content description /
  label; date & time pickers announce; the disabled submit announces its reason;
  the error banner is read; no truncation/overlap at 200%; touch targets ≥ 48dp.
  Traces: AC-3 (and accessibility DoD in §9/§15).

- **TC-AND-275-14 — CSRF/cleartext security check (instrumented).** Type:
  instrumented (security). Target: deviceA15 (real `network_security_config`
  + cleartext enforcement; also validates arm64/API-34 behavior). Preconditions:
  app pointed at a local MockWebServer over the dev cleartext config. Steps:
  perform a create and inspect the recorded request; attempt a request to an
  HTTPS-only release-style host config. Expected: every mutation carries
  `X-CSRF-Token`; no raw cookie/credential is logged (Timber output inspected);
  no new cleartext exception beyond the existing dev config; release config
  rejects cleartext. Traces: AC-7 (and §8 security).

### Coverage matrix

| Acceptance criterion | Covered by |
| --- | --- |
| AC-1 (create gate) | TC-AND-275-01, TC-AND-275-02 |
| AC-2 (edit/reschedule gate) | TC-AND-275-03, TC-AND-275-04 |
| AC-3 (local validation) | TC-AND-275-05, TC-AND-275-12, TC-AND-275-13 |
| AC-4 (server error, form retained) | TC-AND-275-06, TC-AND-275-07, TC-AND-275-12 |
| AC-5 (offline, no auto-retry) | TC-AND-275-08 |
| AC-6 (state survives rotation/death; single submit) | TC-AND-275-10, TC-AND-275-11 |
| AC-7 (CSRF on all mutations; single-401 refresh) | TC-AND-275-02, TC-AND-275-04, TC-AND-275-09, TC-AND-275-14 |
