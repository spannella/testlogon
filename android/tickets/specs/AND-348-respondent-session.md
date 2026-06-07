---
id: AND-348
title: Respondent session
milestone: M7
epic: E45
priority: P1
size: M
depends_on: [AND-347]
blocks: [AND-349]
status: reviewed
reviewed_on: 2026-06-06
---

# AND-348 — Respondent session

## 1. Overview & Goal

This ticket implements the **respondent session lifecycle** for the public
questionnaire-response flow: starting a session against a published
questionnaire, persisting (saving) in-progress answers, validating them
server-side, and resuming an existing session after process death, app restart,
or navigation away. It is the stateful backbone between the **dynamic form
renderer** (AND-347, which renders field widgets and captures local input) and
**submit + PDF** (AND-349, which finalizes the session and produces output).

The deliverable is a `feature-respond` session layer: a Retrofit service
binding for `/questionnaires/published/{slug}/sessions/*`, a Room-backed local
draft cache (so a partially answered questionnaire survives offline and process
death), a `RespondentSessionRepository` that reconciles local drafts with
server state, and a `RespondentSessionViewModel` exposing
`StateFlow<RespondentSessionUiState>` consumed by the renderer screen.

Concrete goal / acceptance: a user can begin answering a published
questionnaire, leave the screen (or kill the app), return, and find their
answers restored from the last saved point, with server-side validation errors
surfaced inline per field. Submission itself is **out of scope** and owned by
AND-349.

## 2. Context & References

- **Repo:** `spannella/testlogon`, Android app under `android/`, branch
  `android-port`. Module `feature-respond` (created in AND-347); this ticket
  adds the session sub-package.
- **Namespace / applicationId base:** `com.testlogon.android`. Package for this
  work: `com.testlogon.android.feature.respond.session`.
- **Upstream dependency — AND-347 (Dynamic form renderer):** owns
  `QuestionnaireSchema`, the field-type model (`text/choice/scale/date/upload/…`),
  and the Compose widgets. AND-348 consumes the schema and the renderer's
  per-field answer values; it does **not** render fields.
- **Downstream dependency — AND-349 (Submit + PDF):** consumes the
  finalized/validated session id produced here to call submit and to handle the
  public `App Link` `/questionnaires/published/:slug/respond`.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. Error `detail`
  follows the project union shape (`string | [{msg}] | {code,...}`).
- **Auth:** the public respond flow is unauthenticated for anonymous
  respondents, but the cookie jar + `X-CSRF-Token` echo machinery from core-network
  still applies for mutating calls (save/validate are POST/PUT). Reuse the
  shared OkHttp client, persistent cookie jar, and CSRF interceptor.
- **Stack baseline:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP),
  Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6,
  DataStore. minSdk 24, compile/target 35.

## 3. Functional Requirements

FR-1. **Start session.** On entering the respond screen for a published
questionnaire `slug`, the app obtains a session. If a local draft exists for
that `slug` with a still-valid server `session_id`, resume it; otherwise call
`POST /questionnaires/published/{slug}/sessions` to create one.

FR-2. **Resume.** If the app is reopened, or the screen recomposed after process
death, the previously persisted draft (answers + `session_id` + schema version)
is restored and merged with the latest server snapshot via
`GET /questionnaires/published/{slug}/sessions/{session_id}`.

FR-3. **Save (autosave + explicit).** Answer changes are debounced and persisted
locally immediately, then synced to the server via
`PUT /questionnaires/published/{slug}/sessions/{session_id}` (partial answer
patch). An explicit "Save" action flushes pending changes immediately.

FR-4. **Validate.** A validation pass
(`POST /questionnaires/published/{slug}/sessions/{session_id}/validate`) returns
per-field errors (required, format, range, etc.) without submitting. Validation
is triggered on explicit "Save & continue", on page/section advance, and is
re-triggered after a fix. Errors are mapped to field ids for inline display by
the renderer.

FR-5. **Offline tolerance.** Local save must never block on network. When the
server is unreachable, answers are kept in the Room draft with a `dirty` flag
and a `sync_pending` UI state; sync resumes when connectivity returns or on the
next user-triggered save.

FR-6. **Schema-version safety.** CORRECTED: the server has no integer
`schema_version`; the schema identity is `version_id` (string, from the session
object and `PublishedQuestionnaireVersion.version_id`; an int `version_number` also
exists on the published version). If the session's `version_id` differs from the
cached draft's, surface a `SchemaChanged` state and require the user to reload the
schema (re-fetched by AND-347) before further saves; do not silently discard
answers. There is no documented 409 conflict response (see §7 / R5).

FR-7. **Single active session per slug per device.** The draft store keys on
`slug`; starting a fresh session (user choice "Start over") clears the draft and
the prior `session_id`.

FR-8. **Hand-off to submit.** When validation passes, expose the validated
`session_id` and a `canSubmit = true` flag for AND-349. This ticket does not
call submit.

## 4. Technical Design

### Module / package layout

```
feature-respond/
  src/main/java/com/testlogon/android/feature/respond/session/
    RespondentSessionViewModel.kt
    RespondentSessionUiState.kt
    RespondentSessionRepository.kt        (interface)
    RespondentSessionRepositoryImpl.kt
    di/RespondentSessionModule.kt
core-network/.../respond/
    RespondentSessionApi.kt               (Retrofit)
    dto/SessionDtos.kt
core-data/.../respond/
    SessionDraftDao.kt
    SessionDraftEntity.kt
```

### Domain model (core-model)

```kotlin
data class RespondentSession(
    val sessionId: String,                   // server `response_session_id`
    val slug: String,                        // nav arg; NOT returned by the server session object
    val questionnaireId: String,             // server `questionnaire_id`
    val versionId: String,                   // server `version_id` (string) — the schema identity (CORRECTED: server has no `schema_version` int field)
    val answers: Map<String, AnswerValue>,   // questionId -> value (from AND-347), wire key `answers_by_question_id`
    val status: SessionStatus,               // IN_PROGRESS, SUBMITTED, EXPIRED (EXPIRED is a client-only marker; server only emits in_progress|submitted)
    val currentSectionIndex: Int?,           // server `current_section_index`
    val currentQuestionId: String?,          // server `current_question_id`
    val startedAt: Instant,                  // server `started_at` (CORRECTED: server field is `started_at`, not `updated_at`)
)

// CORRECTED: server status enum is `in_progress | submitted`. There is no server-side
// `validated`/`draft` status; validity is derived from QuestionnaireValidationResponse.can_submit.
// EXPIRED is a client-only state used when GET returns 404 (see §7).
enum class SessionStatus { IN_PROGRESS, SUBMITTED, EXPIRED }

// CORRECTED: server validation issues carry `code` + `message` (+ optional `blocking`, `rule_id`);
// there is no `field_id`/`msg` on the issue. The field/question id is the MAP KEY (see §5).
data class FieldValidationError(
    val questionId: String,   // the map key in QuestionnaireValidationResponse.errors (may be a `group:`/`form:` prefixed key)
    val message: String,      // ValidationIssue.message
    val code: String,         // ValidationIssue.code (required by schema)
    val blocking: Boolean?,   // ValidationIssue.blocking
    val ruleId: String?,      // ValidationIssue.rule_id
)
```

`AnswerValue` is the sealed type defined by AND-347 (text/choice/scale/date/
upload-ref/etc.); this ticket serializes it but does not define its variants.

### ViewModel

```kotlin
@HiltViewModel
class RespondentSessionViewModel @Inject constructor(
    private val repo: RespondentSessionRepository,
    savedState: SavedStateHandle,
) : ViewModel() {
    private val slug: String = checkNotNull(savedState["slug"])
    val uiState: StateFlow<RespondentSessionUiState>

    fun onAnswerChanged(fieldId: String, value: AnswerValue)  // debounced local + sync
    fun saveNow()                                             // flush pending
    fun validate()                                            // POST .../validate
    fun resume()                                              // start-or-resume
    fun startOver()                                           // clear draft + new session
    fun reloadSchema()                                        // after SchemaChanged
}
```

UI state:

```kotlin
data class RespondentSessionUiState(
    val phase: Phase = Phase.Loading,                 // Loading, Ready, Error
    val sessionId: String? = null,
    val answers: Map<String, AnswerValue> = emptyMap(),
    val fieldErrors: Map<String, FieldValidationError> = emptyMap(),
    val syncStatus: SyncStatus = SyncStatus.Idle,     // Idle, Saving, SyncPending, Synced, Failed
    val schemaChanged: Boolean = false,
    val canSubmit: Boolean = false,
    val message: UiMessage? = null,
)
```

### Autosave mechanics

`onAnswerChanged` writes to the Room draft synchronously (via repo, on
`Dispatchers.IO`) and emits to a `MutableSharedFlow<Unit>` collected with
`debounce(800.milliseconds)` inside `viewModelScope`; the debounced collector
calls `repo.syncDraft(slug)`. `saveNow()` cancels the debounce window and syncs
immediately. The local write and the server sync are independent: local never
fails on network.

### Repository

```kotlin
interface RespondentSessionRepository {
    suspend fun startOrResume(slug: String): ApiResult<RespondentSession>
    suspend fun saveLocal(slug: String, fieldId: String, value: AnswerValue)
    suspend fun syncDraft(slug: String): ApiResult<RespondentSession>
    suspend fun validate(slug: String): ApiResult<List<FieldValidationError>>
    suspend fun clear(slug: String)
    fun observeDraft(slug: String): Flow<SessionDraftEntity?>
}
```

`startOrResume` logic: read local draft → if present and `sessionId != null`,
call `GET .../sessions/{id}`; on 200 reconcile (server wins for
`versionId`/`status`, local dirty answers win for unsynced fields), on 404 treat
session as `EXPIRED` and create new; if no draft, `POST` to create. (CORRECTED:
OpenAPI only declares 200/422 for these paths — 404 is the realistic "missing
session" code; a literal 410 is an unverified assumption and is handled defensively
alongside 404. `schemaVersion`→`versionId`, since the server has no integer
`schema_version`.)

## 5. API Contract

Base: `http://18.222.237.167:8000`. All mutating calls send the persisted cookie
jar and the `X-CSRF-Token` header (CSRF cookie echo), per core-network. GET is
idempotent and eligible for bounded-backoff retry; POST/PUT are **not** retried
automatically.

### Retrofit interface

```kotlin
// CORRECTED: OpenAPI path params are {published_slug} and {response_session_id};
// start req = ResponseSessionStartReq → ResponseSessionEnvelope; GET/PUT → SessionStateEnvelope;
// validate req = QuestionnaireValidationRequest → QuestionnaireValidationResponse.
interface RespondentSessionApi {
    @POST("questionnaires/published/{published_slug}/sessions")
    suspend fun create(@Path("published_slug") slug: String,
                       @Body body: ResponseSessionStartReq): Response<ResponseSessionEnvelope>

    @GET("questionnaires/published/{published_slug}/sessions/{response_session_id}")
    suspend fun get(@Path("published_slug") slug: String,
                    @Path("response_session_id") sessionId: String): Response<SessionStateEnvelope>

    @PUT("questionnaires/published/{published_slug}/sessions/{response_session_id}")
    suspend fun save(@Path("published_slug") slug: String,
                     @Path("response_session_id") sessionId: String,
                     @Body body: SessionSaveReq): Response<SessionStateEnvelope>

    @POST("questionnaires/published/{published_slug}/sessions/{response_session_id}/validate")
    suspend fun validate(@Path("published_slug") slug: String,
                         @Path("response_session_id") sessionId: String,
                         @Body body: QuestionnaireValidationRequest): Response<QuestionnaireValidationResponse>
}
```

### Request / response JSON

`POST .../sessions` request (`ResponseSessionStartReq`). CORRECTED: there is no
`context`/`locale` field; the only property is an optional `questionnaire_id`. The
web client posts an empty body `{}` (`startPublishedResponseSession`). Response is
HTTP **200** (CORRECTED: not 201):
```json
{}
```
`ResponseSessionEnvelope` (200) — the session is an OPAQUE nested object under
`session` (CORRECTED: not a flat top-level `session_id`/`slug`/`schema_version`):
```json
{
  "session": {
    "response_session_id": "...",
    "questionnaire_id": "...",
    "version_id": "...",
    "status": "in_progress",
    "started_at": "2026-06-05T12:00:00Z",
    "current_section_index": 0,
    "current_question_id": null,
    "respondent_id": null
  }
}
```
> Note: in OpenAPI both `ResponseSessionEnvelope.session` and `SessionStateEnvelope.session`
> are typed `object` (additionalProperties). The concrete field names above come from the
> frontend type `QuestionnaireSessionState` (`src/api/types.ts`); treat the inner field set
> as frontend-derived, not OpenAPI-guaranteed.

`PUT .../sessions/{response_session_id}` request (`SessionSaveReq`). CORRECTED:
wire key is `answers_by_question_id` (not `answers`), plus optional
`current_section_index` and `current_question_id`. Whether it is a partial patch or
full replace is NOT specified by OpenAPI (free-form `object`); the web client sends
the full current answer map each save (see R1):
```json
{ "answers_by_question_id": { "q_rating": 5, "q_consent": true },
  "current_section_index": 1,
  "current_question_id": "q_consent" }
```
PUT/GET response is `SessionStateEnvelope` (200): `{ "session": {…}, "answers_by_question_id": {…} }`.

`POST .../validate` request (`QuestionnaireValidationRequest`). CORRECTED: body is
`answers_by_question_id` + `final_submit` (and optional `form_rules`/`group_rules`/
`contract_version="2026-03-validation-v1"`), NOT a `SaveSessionRequest`. The web
client sends `{ answers_by_question_id, final_submit: false }`:
```json
{ "answers_by_question_id": { "q_email": "bad" }, "final_submit": false }
```
`POST .../validate` → `QuestionnaireValidationResponse`. CORRECTED: the response is
`{ is_valid, can_submit, has_blocking_form_error, errors }` (NOT `{valid, errors:[…]}`),
where `errors` is a MAP keyed by question id (or a `group:`/`form:`-prefixed key) →
array of `ValidationIssue { code, message, blocking?, rule_id? }` (NOT objects with
`field_id`/`msg`):
```json
{
  "is_valid": false,
  "can_submit": false,
  "has_blocking_form_error": false,
  "errors": {
    "q_email":   [ { "code": "format",   "message": "Invalid email", "blocking": true } ],
    "q_consent": [ { "code": "required", "message": "This field is required", "blocking": true } ]
  }
}
```

DTOs are Moshi-annotated and mapped to domain in a `SessionMapper`. CORRECTED: the
FastAPI error shape for these endpoints is the standard `HTTPValidationError`
(`{ "detail": [ { "loc": [...], "msg": "...", "type": "..." } ] }`, status **422**),
NOT the `string | [{msg}] | {code,...}` union the draft assumed. The existing
core-network `ErrorBodyAdapter`/`ApiError` parses `detail`; field-level validation
errors for inline display come from `QuestionnaireValidationResponse.errors`, not
from the 422 `detail`.

## 6. Data & State Management

### Room draft entity (core-data)

```kotlin
@Entity(tableName = "session_drafts")
data class SessionDraftEntity(
    @PrimaryKey val slug: String,
    val sessionId: String?,         // server `response_session_id`
    val versionId: String?,         // CORRECTED: server `version_id` (string), not an int `schema_version`
    val answersJson: String,        // Moshi-serialized Map<String, AnswerValue>; wire key `answers_by_question_id`
    val status: String,             // CORRECTED: in_progress | submitted (+ client-only `expired`)
    val dirty: Boolean,             // unsynced local edits present
    val updatedAt: Long,            // epoch millis (local write time; server exposes `started_at`)
)

@Dao
interface SessionDraftDao {
    @Query("SELECT * FROM session_drafts WHERE slug = :slug")
    fun observe(slug: String): Flow<SessionDraftEntity?>

    @Query("SELECT * FROM session_drafts WHERE slug = :slug")
    suspend fun get(slug: String): SessionDraftEntity?

    @Upsert suspend fun upsert(entity: SessionDraftEntity)

    @Query("DELETE FROM session_drafts WHERE slug = :slug")
    suspend fun delete(slug: String)
}
```

Room is the single source of truth for in-progress answers; the ViewModel
observes `observeDraft(slug)` and maps to `RespondentSessionUiState.answers`.
The server snapshot updates the same row. `SavedStateHandle` holds only the
`slug` nav arg — answers are not duplicated there, since the draft survives
process death via Room. DataStore is **not** used for answers (drafts are
relational/per-slug, not user prefs).

State reconciliation: on `syncDraft`, `dirty=false` is set only after a 2xx
`SessionSaveReq`; on success the server `answers_by_question_id`/`version_id`/`status`
(from `SessionStateEnvelope`) overwrite the row but locally-newer dirty fields
(edited during the in-flight call) are re-merged before clearing `dirty`.

## 7. Error Handling & Resilience

- **Timeouts:** OkHttp call timeout ~20s (shared client). A GET
  (`get`/resume) may retry with bounded exponential backoff (e.g. 2 attempts,
  500ms→2s, jittered). POST/PUT/validate are **not** auto-retried; failure →
  `SyncStatus.Failed` with a manual "Retry save" affordance.
- **Offline / unreachable host:** local save always succeeds; UI shows
  `SyncStatus.SyncPending`. A connectivity callback or the next `saveNow()`
  flushes pending drafts.
- **401 on mutating call:** delegate to the core-network refresh-once
  interceptor (single retry). For anonymous respondents without a session this
  should not occur; if it does after retry, surface a non-fatal banner and keep
  the local draft. (UNVERIFIED: the exact refresh endpoint `POST /ui/session/refresh`
  was not located in the OpenAPI index/frontend during review — treat the path as
  core-network's existing concern, not asserted here. The respond flow itself sends
  the cookie jar + `X-CSRF-Token` exactly as the web client does.)
- **404 on session:** treat as `EXPIRED`; prompt the user, then auto-create a new
  session preserving local answers, replaying them via PUT. (CORRECTED: OpenAPI
  declares only 200/422 for the session paths; 404 is the realistic missing-session
  code. A literal 410 is an unverified assumption — handled defensively but not
  guaranteed by the contract.)
- **Schema/`version_id` mismatch:** set `schemaChanged = true`, block sync, require
  `reloadSchema()`. (CORRECTED: there is no documented 409 response and no integer
  `schema_version`; the check compares the session's `version_id` string against the
  cached draft's `version_id`. Detecting it via HTTP 409 is an unverified assumption.)
- **Malformed body:** Moshi parse failure → `ApiResult.Error` mapped to a
  generic recoverable message; local draft untouched.
- All errors flow through typed `ApiResult<T>`; no exceptions cross the
  ViewModel boundary.

## 8. Security & Privacy

- Respondent answers may contain PII; the Room `session_drafts` table lives in
  app-private storage. The draft is cleared on `startOver()` and on successful
  submit (triggered by AND-349). Add a `clear(slug)` call after submit completes.
- Mutating calls carry the `ui_csrf` cookie echoed as `X-CSRF-Token`; do not log
  the CSRF token or cookie values.
- Dev backend is plaintext HTTP — acceptable only for the dev host via the
  existing network-security-config cleartext allowlist; production base URL must
  be HTTPS. No answer payloads in logcat at `INFO`+.
- Upload field values reference uploaded blobs by id (upload mechanics owned by
  AND-347); this ticket stores only the reference, not file bytes.
- No analytics PII: telemetry uses `sessionId` (opaque) and `slug`, never answer
  content.

## 9. Accessibility & i18n

The session layer is non-visual; field rendering and a11y semantics are owned by
AND-347. This ticket contributes:

- **Inline error mapping:** validation errors are delivered keyed by `fieldId`
  so the renderer can attach `Modifier.semantics { error(message) }` and announce
  via `LiveRegion`.
- **Sync status announcements:** `SyncStatus` changes (Saving → Synced → Failed)
  are exposed for the screen to render an `assertive`/`polite` live region so
  non-sighted users hear save outcomes.
- **i18n:** all session-layer user-facing strings (sync/save/expired/
  schema-changed messages) are `strings.xml` resources, no hardcoded text. The
  `context.locale` sent on session create is the device locale (BCP-47).

## 10. Telemetry & Logging

Emit structured events via the shared analytics interface (no PII):

- `respond_session_started` `{ slug, sessionId, resumed: Boolean }`
- `respond_session_saved` `{ slug, sessionId, fields_changed: Int, synced: Boolean }`
- `respond_session_validate` `{ slug, sessionId, valid: Boolean, error_count: Int }`
- `respond_session_resume_failed` `{ slug, reason: "expired"|"network"|"schema" }`
- `respond_session_sync_failed` `{ slug, http_status: Int? }`

Logging: Timber at `DEBUG` for state transitions (no answer values); errors at
`WARN`/`ERROR` with HTTP status and `code`, never response bodies containing
answers.

## 11. Testing Strategy

**Unit (JUnit + Turbine + MockWebServer, core-testing):**
- `RespondentSessionRepositoryImpl`: start-vs-resume branch, 404→recreate+replay,
  schema-version conflict, dirty-merge during in-flight save, `clear`.
- Mapper: DTO↔domain, `QuestionnaireValidationResponse.errors` (map of questionId→
  `ValidationIssue[]`)→domain `Map<questionId, FieldValidationError>`, and 422
  `HTTPValidationError.detail` parsing.
- `RespondentSessionViewModel` with `StandardTestDispatcher`: debounce autosave
  fires once per quiet window, `saveNow` cancels debounce, offline keeps
  `SyncPending`, validation populates `fieldErrors`, `canSubmit` flips only after
  `valid=true`.

**Room (instrumented, in-memory DB):** `SessionDraftDao` upsert/observe/delete;
draft survives a simulated config change / process-death restore.

**Integration (MockWebServer):** full start→save→validate→resume sequence;
20s-timeout path; 401→refresh→retry once; bounded GET retry on resume.

**Acceptance test:** automated UI/integration test that answers fields, kills
and relaunches the ViewModel (new instance, same Room), and asserts answers are
restored — proving the "Save + resume a session" acceptance bullet.

Target: repository/ViewModel line coverage ≥ 85%.

## 12. Dependencies & Sequencing

- **Blocked by AND-347 (Dynamic form renderer):** requires `QuestionnaireSchema`,
  `AnswerValue` sealed type, and the renderer screen that hosts this ViewModel.
  Must merge after AND-347.
- **Blocks AND-349 (Submit + PDF):** AND-349 consumes the validated `sessionId`
  and `canSubmit`, and clears the draft post-submit; the public App Link
  `/questionnaires/published/:slug/respond` routes into the screen this session
  layer backs.
- **Cross-cutting:** core-network cookie jar + CSRF interceptor + `ApiResult`
  (established in M-early networking tickets); core-data Room database
  (add migration for `session_drafts`).
- Sequencing within the ticket: (1) DTOs + Retrofit API, (2) Room entity/DAO +
  migration, (3) repository + reconciliation, (4) ViewModel + autosave, (5)
  wire into AND-347 screen, (6) tests.

## 13. Risks & Open Questions

- **R1 — Save payload semantics:** RESOLVED on wire key (`answers_by_question_id`,
  per `SessionSaveReq`). Full-replace vs partial-merge is still OPEN: OpenAPI types
  the body as a free-form `object`, so semantics are not declared. The web client
  (`QuestionnaireRespondentPage.tsx`) sends the FULL current answer map every save,
  so this spec adopts full-replace to match the reference client.
- **R2 — Validate request body:** RESOLVED. `/validate` takes
  `QuestionnaireValidationRequest` (`answers_by_question_id` + `final_submit`); the
  web client sends the current answers with `final_submit:false`. So validation runs
  against client-supplied answers, not purely server-stored state.
- **R3 — Session expiry/TTL:** unknown server TTL; resume handles 404 (and,
  defensively, 410). OpenAPI declares only 200/422 for these paths, so the exact
  expiry status code remains OPEN.
- **R4 — Anonymous CSRF:** `client.ts` sets `X-CSRF-Token` only when the `ui_csrf`
  cookie is present (`if (csrf)`) and never primes it via a GET. So a priming GET is
  NOT something the web client does; whether anonymous POST succeeds without a
  `ui_csrf` cookie is an OPEN server-behavior question.
- **R5 — Schema-version field name:** RESOLVED/CORRECTED. There is no
  `schema_version`; schema identity is `version_id` (string) on the session and
  `PublishedQuestionnaireVersion` (`version_number` int also exists). The conflict
  check compares `version_id`.
- **R6 — Concurrent devices:** out of scope (FR-7 scopes one session per slug
  per device); multi-device last-write-wins is server-side and not handled here.

## 14. Acceptance Criteria

AC-1. Entering a published questionnaire creates a session via
`POST .../sessions` (no prior draft) and stores `session_id` locally.
AC-2. Editing a field persists to Room immediately and syncs to the server via
`PUT .../sessions/{id}` after the debounce window; `saveNow()` flushes instantly.
AC-3. **Resume:** after killing and relaunching the app, returning to the same
`slug` restores all previously saved answers (from Room, reconciled with
`GET .../sessions/{id}`). *(Primary acceptance: "Save + resume a session.")*
AC-4. `validate()` populates `fieldErrors` keyed by questionId from
`QuestionnaireValidationResponse.errors`; `canSubmit` is driven by the response's
`can_submit` flag (CORRECTED: not a derived `valid==true`).
AC-5. With the network unreachable, local saves succeed and UI shows
`SyncPending`; sync completes automatically/manually on reconnect with no
answer loss.
AC-6. An expired/missing session (404/410) recreates a session and replays local
answers without data loss.
AC-7. A differing server `version_id` (CORRECTED: not an int `schema_version`) sets
`schemaChanged = true`, blocks sync, and requires `reloadSchema()`.
AC-8. No answer content appears in logcat or telemetry payloads.

## 15. Definition of Done

- All Section 14 acceptance criteria pass, including the automated resume test.
- Code merged to `android-port` under `com.testlogon.android.feature.respond.session`
  with Hilt wiring and Room migration for `session_drafts`.
- Unit + Room + MockWebServer integration tests green in CI; repository/ViewModel
  coverage ≥ 85%.
- `RespondentSessionApi` paths verified against `/openapi.json`; open questions
  R1, R2, R5 resolved or explicitly deferred with tickets.
- `ktlint`/`detekt` clean; no hardcoded user-facing strings (all in
  `strings.xml`).
- `canSubmit`/`sessionId` hand-off contract documented for AND-349; draft
  `clear()` hook exposed for post-submit cleanup.
- No regressions in AND-347 renderer integration; PR reviewed and approved.

## 16. Citations & Assumption Audit

Each claim below is tagged Verified / Corrected / Unverified-assumption with the exact source.

1. **Start-session endpoint = `POST /questionnaires/published/{published_slug}/sessions`.**
   VERDICT: Verified (path) / Corrected (param name). SOURCE: OpenAPI
   `POST /questionnaires/published/{published_slug}/sessions`
   (op `start_response_session…`); frontend `src/api/endpoints/questionnaires.ts: startPublishedResponseSession`.
   The path is correct; the param is `{published_slug}` (draft wrote `{slug}`).
2. **Start request body.** VERDICT: Corrected. SOURCE: schema `ResponseSessionStartReq`
   (only optional `questionnaire_id`); frontend `startPublishedResponseSession` posts `{}`.
   Draft's `{ "context": { "locale": "en-US" } }` does not exist — removed.
3. **Start response = `ResponseSessionEnvelope` (200), `{ session: {…} }`.**
   VERDICT: Corrected. SOURCE: OpenAPI `resp=200:ResponseSessionEnvelope`; schema
   `ResponseSessionEnvelope` (single `session` object). Draft's flat 200/201
   `SessionResponse` with top-level `session_id`/`slug`/`schema_version` is wrong;
   response is 200 (not 201) and nested.
4. **GET state = `GET …/sessions/{response_session_id}` → `SessionStateEnvelope`.**
   VERDICT: Verified (path) / Corrected (param + resp schema). SOURCE: OpenAPI
   `GET …/sessions/{response_session_id}` `resp=200:SessionStateEnvelope`; schema
   `SessionStateEnvelope` = `{ session, answers_by_question_id }`; frontend
   `src/api/endpoints/questionnaires.ts: getPublishedResponseSessionState` →
   `src/api/types.ts: QuestionnaireSessionStateResp`.
5. **Save = `PUT …/sessions/{id}`, body `SessionSaveReq`.** VERDICT: Corrected.
   SOURCE: OpenAPI `PUT …/sessions/{response_session_id}` `req=SessionSaveReq`;
   schema `SessionSaveReq` = `answers_by_question_id` (+ `current_section_index`,
   `current_question_id`); frontend `savePublishedResponseSessionState`. Draft's
   `{ answers: {…} }` wire key was wrong.
6. **Save semantics (full replace vs patch).** VERDICT: Unverified-assumption.
   SOURCE: OpenAPI types body as free-form `object` (no semantics); frontend
   `src/pages/questionnaires/QuestionnaireRespondentPage.tsx: saveMutation` sends
   the full current answer map. Spec adopts full-replace to match the web client.
7. **Validate = `POST …/sessions/{id}/validate`, body `QuestionnaireValidationRequest`.**
   VERDICT: Verified (path) / Corrected (body schema). SOURCE: OpenAPI
   `POST …/sessions/{response_session_id}/validate`
   `req=QuestionnaireValidationRequest;resp=200:QuestionnaireValidationResponse`;
   schema `QuestionnaireValidationRequest` (`answers_by_question_id`, `final_submit`,
   `form_rules`, `group_rules`, `contract_version`); frontend `validateMutation`
   sends `{ answers_by_question_id, final_submit }`. Draft reused `SaveSessionRequest` — wrong.
8. **Validate response shape.** VERDICT: Corrected. SOURCE: schema
   `QuestionnaireValidationResponse` = `{ is_valid, can_submit, has_blocking_form_error,
   errors }` where `errors` is `Map<key, ValidationIssue[]>`; schema `ValidationIssue`
   = `{ code, message, blocking?, rule_id? }`; frontend `QuestionnaireRespondentPage.tsx`
   reads `errors[questionId]` and `can_submit`. Draft's `{ valid, errors:[{field_id,code,msg}] }`
   is wrong: no top-level `valid`, no `field_id`/`msg` on issues, errors is a map keyed
   by question id (or `group:`/`form:` prefix).
9. **`canSubmit` source.** VERDICT: Corrected. SOURCE: schema
   `QuestionnaireValidationResponse.can_submit`; frontend `hasBlocking = !can_submit`.
   Draft derived `canSubmit` from `valid==true`; corrected to read `can_submit`.
10. **Field/validation-error keying.** VERDICT: Corrected. SOURCE: schema
    `QuestionnaireValidationResponse.errors` (map) + `ValidationIssue`; frontend
    `errorMap[questionId]` and `key.startsWith("group:"|"form:")`. Inline errors key
    on question id (the map key), and `group:`/`form:` keys carry form-level issues.
11. **Error/`detail` shape on failure = `HTTPValidationError` (422).** VERDICT: Corrected.
    SOURCE: OpenAPI `resp=…;422:HTTPValidationError`; schema `HTTPValidationError`
    = `{ detail: ValidationError[] }`, `ValidationError` = `{ loc, msg, type }`.
    Draft's union `string | [{msg}] | {code,...}` is not what these endpoints return.
12. **Session status enum.** VERDICT: Corrected. SOURCE: frontend
    `src/api/types.ts: QuestionnaireSessionState.status = "in_progress" | "submitted"`.
    Draft's `DRAFT/VALIDATED/EXPIRED` is wrong; server emits `in_progress|submitted`
    (EXPIRED retained as a client-only marker for 404 handling).
13. **Schema identity field = `version_id` (string), not `schema_version` (int).**
    VERDICT: Corrected. SOURCE: `src/api/types.ts: QuestionnaireSessionState.version_id`
    and `PublishedQuestionnaireVersion.version_id`/`version_number`. No `schema_version`
    exists anywhere in OpenAPI or frontend types.
14. **Inner session fields (`response_session_id`, `questionnaire_id`, `started_at`,
    `current_section_index`, `current_question_id`, `respondent_id`).** VERDICT:
    Verified (frontend) / Unverified (OpenAPI). SOURCE: `src/api/types.ts:
    QuestionnaireSessionState`. OpenAPI types the `session` object as free-form
    `object`, so these names are frontend-derived, not OpenAPI-guaranteed.
15. **Auth: cookie jar + `X-CSRF-Token` from `ui_csrf` cookie on mutating calls.**
    VERDICT: Verified. SOURCE: `src/api/client.ts` — `credentials:"include"`,
    `const csrf = getCookie("ui_csrf"); if (csrf) headers.set("X-CSRF-Token", csrf)`.
    The header is sent whenever the cookie exists (all methods), with no priming GET.
16. **No CSRF priming GET / anonymous CSRF behavior.** VERDICT: Unverified-assumption.
    SOURCE: `src/api/client.ts` shows no priming GET; whether the server issues a
    `ui_csrf` cookie to anonymous respondents before first POST is server behavior
    not observable from these sources.
17. **401 refresh-once endpoint (`POST /ui/session/refresh`).** VERDICT:
    Unverified-assumption. SOURCE: not found in `reference/openapi.index.txt` nor in
    the frontend during this review; delegated to core-network as an existing concern.
18. **Compose error semantics / accessibility (`Modifier.semantics{ error(...) }`,
    live regions).** VERDICT: Unverified-assumption (framework ref). SOURCE: Android
    docs — Compose accessibility semantics
    (https://developer.android.com/develop/ui/compose/accessibility). Framework choice,
    not a backend contract.
19. **Stack baseline (Retrofit/OkHttp/Moshi/Room/Hilt, minSdk 24, target 35).**
    VERDICT: Unverified-assumption (framework ref). SOURCE: spec-internal stack
    decision; not derivable from backend/frontend sources.

### Corrections made

- Path params: `{slug}`/`{sessionId}` → `{published_slug}`/`{response_session_id}` (§4/§5).
- Start request body: removed non-existent `{context:{locale}}`; body is
  `ResponseSessionStartReq` (optional `questionnaire_id`), web client posts `{}` (§5).
- Start response: flat `SessionResponse` (201) → `ResponseSessionEnvelope` `{session}` (200) (§5).
- GET/PUT response: `SessionResponse` → `SessionStateEnvelope` `{session, answers_by_question_id}` (§5).
- Save body wire key: `answers` → `answers_by_question_id` (+ `current_section_index`,
  `current_question_id`); `SaveSessionRequest` → `SessionSaveReq` (§5).
- Validate body: `SaveSessionRequest` → `QuestionnaireValidationRequest`
  (`answers_by_question_id`, `final_submit`) (§5).
- Validate response: `{valid, errors:[{field_id,code,msg}]}` →
  `QuestionnaireValidationResponse {is_valid, can_submit, has_blocking_form_error,
  errors: Map<questionId|group:|form:, ValidationIssue[]>}`; `ValidationIssue =
  {code, message, blocking?, rule_id?}` (§4/§5).
- `canSubmit` source: `valid==true` → `can_submit` (§4 VM intent, AC-4).
- Error shape: union `string|[{msg}]|{code}` → `HTTPValidationError {detail:[{loc,msg,type}]}` (422) (§5).
- Domain/Room: `schemaVersion:Int` → `versionId:String`; status enum
  `DRAFT/VALIDATED/EXPIRED` → `IN_PROGRESS/SUBMITTED(/EXPIRED client-only)`;
  `updatedAt`(server) → `startedAt` (§4/§6).
- FR-6, AC-7, R5: `schema_version` mismatch → `version_id` mismatch; no documented 409 (§3/§7/§13/§14).
- Expiry codes: `404/410` → 404 (410 defensive/unverified; OpenAPI only declares 200/422) (§4/§7/§13).

### Open assumptions

- **Save full-replace vs partial-patch** — OpenAPI body is free-form `object`; adopted
  full-replace from the web client's observed behavior (item 6). Confirm server merge semantics.
- **Session expiry HTTP code** — only 200/422 declared; 404 assumed, 410 defensive (items 11, R3).
- **Schema-change detection mechanism** — no 409 documented; relies on comparing
  `version_id` strings, not an HTTP status (items 13, R5, §7).
- **Anonymous CSRF / priming** — server's anonymous `ui_csrf` issuance is unobservable
  here; no priming GET in the web client (items 15-16, R4).
- **401 refresh endpoint** — `POST /ui/session/refresh` not located; left to core-network (item 17).
- **Inner `session` field names** — frontend-derived; OpenAPI declares `session` as
  opaque `object` (item 14).
- **Android framework choices** (stack, Compose a11y, debounce window) — design decisions,
  not backend-verifiable (items 18-19).

## 17. Test Plan

Test targets: **JVM** = JVM unit/Robolectric (local, no device); **emu35** = headless
emulator AVD `test35` (x86_64, API 35); **deviceA15** = physical Samsung Galaxy A15 5G
(SM-A156U, serial R5CX821TA9R, API 34, arm64-v8a). MockWebServer cases run on JVM unless
they exercise real OS/network behavior.

- **TC-AND-348-01 — Start session, no prior draft (happy path).**
  Type: contract/MockWebServer (JVM). Target: `RespondentSessionRepositoryImpl` + `RespondentSessionApi`.
  Preconditions: empty Room; MockWebServer enqueues 200 `ResponseSessionEnvelope`
  `{session:{response_session_id, questionnaire_id, version_id, status:"in_progress", started_at}}`.
  Steps: call `startOrResume(slug)`. Expected: `POST /questionnaires/published/{slug}/sessions`
  with body `{}` (and `X-CSRF-Token` when a `ui_csrf` cookie is set); recorded path uses the
  `{published_slug}` segment; result maps to `RespondentSession(status=IN_PROGRESS)`; a draft
  row is upserted with `sessionId` + `versionId`. Traces: AC-1.

- **TC-AND-348-02 — Autosave debounce + PUT body shape.**
  Type: unit (JVM, `StandardTestDispatcher` + Turbine). Target: `RespondentSessionViewModel` + repo.
  Preconditions: active session in Room; MockWebServer 200 `SessionStateEnvelope`.
  Steps: emit three `onAnswerChanged` within the 800ms window; advance time past the window.
  Expected: exactly one `PUT …/sessions/{id}` fires; body is `SessionSaveReq`
  `{answers_by_question_id:{…}, current_section_index?, current_question_id?}` (NOT `{answers:…}`);
  Room written synchronously on each change. Traces: AC-2.

- **TC-AND-348-03 — `saveNow()` flushes immediately, cancelling debounce.**
  Type: unit (JVM). Target: `RespondentSessionViewModel`.
  Preconditions: one pending change inside the debounce window. Steps: call `saveNow()`.
  Expected: PUT fires immediately (before window elapses); no second PUT when the window later
  expires; `syncStatus` transitions Saving→Synced. Traces: AC-2.

- **TC-AND-348-04 — Resume restores answers across process death.**
  Type: instrumented (emu35; Robolectric variant on JVM acceptable). Target:
  `SessionDraftDao` + repo + new ViewModel instance, in-memory/real Room.
  Preconditions: draft row with `sessionId`, `versionId`, answers, `dirty=false`; MockWebServer
  GET 200 `SessionStateEnvelope` with same `version_id` and a superset of answers.
  Steps: construct a fresh ViewModel (same Room), call `resume()`; reconcile with
  `GET …/sessions/{id}`. Expected: prior answers restored from Room and merged with the server
  snapshot (server wins on `version_id`/`status`, local dirty wins on unsynced fields); no loss.
  Traces: AC-3 (primary "Save + resume").

- **TC-AND-348-05 — Validation populates field errors + drives canSubmit.**
  Type: contract/MockWebServer (JVM). Target: repo `validate` + `SessionMapper` + ViewModel.
  Preconditions: active session. MockWebServer 200 `QuestionnaireValidationResponse`
  `{is_valid:false, can_submit:false, has_blocking_form_error:false,
  errors:{"q_email":[{code:"format",message:"Invalid email",blocking:true}]}}`.
  Steps: call `validate()`. Expected: request body is `QuestionnaireValidationRequest`
  `{answers_by_question_id, final_submit:false}`; `fieldErrors["q_email"]` populated from the
  `errors` MAP (mapped via `ValidationIssue.message/code`, NOT `field_id`/`msg`); `canSubmit`
  follows `can_submit` (false here). Then enqueue `{is_valid:true, can_submit:true,
  has_blocking_form_error:false, errors:{}}` and re-validate → `canSubmit=true`,
  `fieldErrors` cleared. Traces: AC-4.

- **TC-AND-348-06 — Group/form-level validation keys handled.**
  Type: unit (JVM). Target: `SessionMapper`.
  Preconditions: `QuestionnaireValidationResponse.errors` contains `"form:terms"` and
  `"group:contact"` keys alongside a question id. Steps: map to domain.
  Expected: question-id issues map to inline `fieldErrors`; `group:`/`form:`-prefixed keys are
  retained as form/group-level messages (not dropped, not mis-attached to a field). Traces: AC-4.

- **TC-AND-348-07 — Offline local save never blocks; SyncPending.**
  Type: integration/MockWebServer (JVM). Target: repo + ViewModel.
  Preconditions: server unreachable (MockWebServer dispatcher throws / connection refused),
  simulating the flaky dev host. Steps: `onAnswerChanged` then `saveNow()`.
  Expected: Room write succeeds; no exception crosses the ViewModel boundary (typed `ApiResult.Error`);
  `syncStatus = SyncPending` and draft `dirty=true`; answers intact. Traces: AC-5, AC-8 (no crash/leak).

- **TC-AND-348-08 — Reconnect flushes pending dirty draft.**
  Type: integration/MockWebServer (JVM). Target: repo `syncDraft`.
  Preconditions: from TC-07 state (`dirty=true`). Steps: server now returns 200
  `SessionStateEnvelope`; trigger sync (connectivity callback or `saveNow()`).
  Expected: PUT replays buffered answers; on 2xx `dirty=false`; in-flight edits re-merged
  before clearing dirty; no answer loss. Traces: AC-5.

- **TC-AND-348-09 — Expired/missing session (404) recreates + replays.**
  Type: contract/MockWebServer (JVM). Target: repo `startOrResume`.
  Preconditions: draft row with stale `sessionId`. Steps: GET returns 404; repo recreates via
  POST (200 envelope) and replays local answers via PUT. Expected: new `response_session_id`
  stored; local answers preserved and re-sent; status path IN_PROGRESS; a literal 410 is handled
  the same way defensively. Traces: AC-6.

- **TC-AND-348-10 — version_id change blocks sync (SchemaChanged).**
  Type: unit (JVM). Target: repo reconciliation.
  Preconditions: draft `versionId="v1"`; GET returns `SessionStateEnvelope` with session
  `version_id="v2"`. Steps: `resume()`/`syncDraft`. Expected: `schemaChanged=true`, sync blocked,
  no PUT issued until `reloadSchema()`; answers not discarded (CORRECTED: compares `version_id`
  string, not an int `schema_version`, and not via HTTP 409). Traces: AC-7.

- **TC-AND-348-11 — 422 HTTPValidationError parsing.**
  Type: contract/MockWebServer (JVM). Target: `ErrorBodyAdapter`/`ApiError` mapping.
  Preconditions: PUT returns 422 `{detail:[{loc:["body","answers_by_question_id"],msg:"…",type:"…"}]}`.
  Steps: trigger save. Expected: parsed into `ApiResult.Error`/`ApiError` from `detail[].msg`
  (not the old union shape); local draft untouched; `syncStatus=Failed` with retry affordance.
  Traces: AC-5 (resilience), AC-2.

- **TC-AND-348-12 — No PII in logs/telemetry.**
  Type: unit (JVM, capturing Timber tree + fake analytics). Target: repo + ViewModel + logging.
  Preconditions: answers contain PII-like strings. Steps: run start→save→validate; capture logs
  and emitted telemetry. Expected: no answer values in logcat at INFO+; telemetry events
  (`respond_session_*`) carry only `slug`/`sessionId`/counts/flags; CSRF token/cookie never logged.
  Traces: AC-8.

- **TC-AND-348-13 — Real-network resume + cleartext dev host (physical device).**
  Type: instrumented/e2e (**deviceA15** — MUST run on the physical device for true
  arm64-v8a/API-34 behavior and real radio/connectivity transitions). Target: full screen
  + repo against the live dev host `http://18.222.237.167:8000`.
  Preconditions: device on network; network-security-config cleartext allowlist includes the dev
  host. Steps: start a session, answer fields, toggle airplane mode mid-edit, re-enable, then
  force-stop and relaunch the app and reopen the same slug. Expected: cleartext POST/PUT succeed
  to the dev host; offline edits buffered (SyncPending) and flushed on reconnect; after relaunch
  answers are restored. Note: emu35 cannot faithfully reproduce real radio/ABI behavior; use the
  device. Traces: AC-1, AC-3, AC-5.

- **TC-AND-348-14 — Inline error + sync-status accessibility (Compose-UI).**
  Type: Compose-UI (emu35; espresso/compose-test). Target: renderer host screen consuming
  `fieldErrors`/`syncStatus` (a11y contract owned here, rendered by AND-347).
  Preconditions: a field has a validation error; sync transitions Saving→Failed.
  Steps: trigger validation and a failed save. Expected: errored field exposes
  `semantics { error(message) }` and `aria/contentDescription`-equivalent; sync-status changes
  announced via a polite/assertive live region (TalkBack-observable); error text resolved from
  `strings.xml` (no hardcoded copy). Traces: AC-4, AC-5.

### Coverage matrix

| AC | Description | Test case(s) |
| --- | --- | --- |
| AC-1 | Create session on entry, store `session_id` | TC-01, TC-13 |
| AC-2 | Edit → Room immediately + debounced PUT; `saveNow()` flushes | TC-02, TC-03, TC-11 |
| AC-3 | Resume restores answers (primary) | TC-04, TC-13 |
| AC-4 | `validate()` populates field errors; `can_submit` drives `canSubmit` | TC-05, TC-06, TC-14 |
| AC-5 | Offline saves succeed (SyncPending); reconnect flush, no loss | TC-07, TC-08, TC-11, TC-13, TC-14 |
| AC-6 | 404/410 recreates + replays | TC-09 |
| AC-7 | Differing `version_id` → SchemaChanged, blocks sync | TC-10 |
| AC-8 | No answer content in logs/telemetry | TC-07, TC-12 |
