---
id: AND-348
title: Respondent session
milestone: M7
epic: E45
priority: P1
size: M
status: draft
depends_on: [AND-347]
blocks: [AND-349]
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

FR-6. **Schema-version safety.** If the server reports a schema version newer
than the cached draft's, surface a `SchemaChanged` state and require the user to
reload the schema (re-fetched by AND-347) before further saves; do not silently
discard answers.

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
    val sessionId: String,
    val slug: String,
    val schemaVersion: Int,
    val answers: Map<String, AnswerValue>,   // fieldId -> value (from AND-347)
    val status: SessionStatus,               // DRAFT, VALIDATED, EXPIRED
    val updatedAt: Instant,
)

enum class SessionStatus { DRAFT, VALIDATED, EXPIRED }

data class FieldValidationError(val fieldId: String, val message: String, val code: String?)
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
`schemaVersion`/`status`, local dirty answers win for unsynced fields), on 404/
410 treat session as `EXPIRED` and create new; if no draft, `POST` to create.

## 5. API Contract

Base: `http://18.222.237.167:8000`. All mutating calls send the persisted cookie
jar and the `X-CSRF-Token` header (CSRF cookie echo), per core-network. GET is
idempotent and eligible for bounded-backoff retry; POST/PUT are **not** retried
automatically.

### Retrofit interface

```kotlin
interface RespondentSessionApi {
    @POST("questionnaires/published/{slug}/sessions")
    suspend fun create(@Path("slug") slug: String,
                       @Body body: CreateSessionRequest): Response<SessionResponse>

    @GET("questionnaires/published/{slug}/sessions/{sessionId}")
    suspend fun get(@Path("slug") slug: String,
                    @Path("sessionId") sessionId: String): Response<SessionResponse>

    @PUT("questionnaires/published/{slug}/sessions/{sessionId}")
    suspend fun save(@Path("slug") slug: String,
                     @Path("sessionId") sessionId: String,
                     @Body body: SaveSessionRequest): Response<SessionResponse>

    @POST("questionnaires/published/{slug}/sessions/{sessionId}/validate")
    suspend fun validate(@Path("slug") slug: String,
                         @Path("sessionId") sessionId: String,
                         @Body body: SaveSessionRequest): Response<ValidateResponse>
}
```

### Request / response JSON

`POST .../sessions` request:
```json
{ "context": { "locale": "en-US" } }
```
`SessionResponse` (200/201):
```json
{
  "session_id": "sess_01HZ...",
  "slug": "customer-survey",
  "schema_version": 7,
  "status": "draft",
  "answers": { "q_name": "Ada", "q_rating": 4 },
  "updated_at": "2026-06-05T12:00:00Z"
}
```
`PUT .../sessions/{id}` request (partial patch):
```json
{ "answers": { "q_rating": 5, "q_consent": true } }
```
`POST .../validate` → `ValidateResponse`:
```json
{
  "valid": false,
  "errors": [
    { "field_id": "q_email", "code": "format", "msg": "Invalid email" },
    { "field_id": "q_consent", "code": "required", "msg": "This field is required" }
  ]
}
```

DTOs are Moshi-annotated and mapped to domain in a `SessionMapper`. The
top-level FastAPI error `detail` (`string | [{msg}] | {code,...}`) is parsed by
the existing core-network `ErrorBodyAdapter` into `ApiError`; field-level
validation errors come from `ValidateResponse.errors`, not from `detail`.

## 6. Data & State Management

### Room draft entity (core-data)

```kotlin
@Entity(tableName = "session_drafts")
data class SessionDraftEntity(
    @PrimaryKey val slug: String,
    val sessionId: String?,
    val schemaVersion: Int,
    val answersJson: String,        // Moshi-serialized Map<String, AnswerValue>
    val status: String,             // draft | validated | expired
    val dirty: Boolean,             // unsynced local edits present
    val updatedAt: Long,            // epoch millis
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
`SaveSessionRequest`; on success the server `answers`/`schema_version`/`status`
overwrite the row but locally-newer dirty fields (edited during the in-flight
call) are re-merged before clearing `dirty`.

## 7. Error Handling & Resilience

- **Timeouts:** OkHttp call timeout ~20s (shared client). A GET
  (`get`/resume) may retry with bounded exponential backoff (e.g. 2 attempts,
  500ms→2s, jittered). POST/PUT/validate are **not** auto-retried; failure →
  `SyncStatus.Failed` with a manual "Retry save" affordance.
- **Offline / unreachable host:** local save always succeeds; UI shows
  `SyncStatus.SyncPending`. A connectivity callback or the next `saveNow()`
  flushes pending drafts.
- **401 on mutating call:** delegate to the core-network refresh-once
  interceptor (`POST /ui/session/refresh` then single retry). For anonymous
  respondents without a session this should not occur; if it does after retry,
  surface a non-fatal banner and keep the local draft.
- **404 / 410 on session:** treat as `EXPIRED`; prompt the user, then
  auto-create a new session preserving local answers, replaying them via PUT.
- **409 schema conflict / `schema_version` mismatch:** set
  `schemaChanged = true`, block sync, require `reloadSchema()`.
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
- Mapper: DTO↔domain, `ValidateResponse.errors`→`Map<fieldId, error>`,
  `detail` union parsing.
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

- **R1 — Save payload semantics:** is `PUT .../sessions/{id}` a full replace or a
  partial patch? Spec assumes partial-merge `{answers:{...}}`. Confirm against
  `/openapi.json`; if full-replace, repository must send the complete answer map.
- **R2 — Validate request body:** does `/validate` require the latest answers in
  body, or validate server-stored state? Spec sends current answers to be safe.
- **R3 — Session expiry/TTL:** unknown server TTL; resume must handle 404/410
  gracefully (handled) but exact codes need confirmation.
- **R4 — Anonymous CSRF:** whether anonymous respondents receive a `ui_csrf`
  cookie before first POST; if not, create-session may need a priming GET.
- **R5 — Schema-version field name:** assumed `schema_version`; verify against
  OpenAPI and AND-347's schema model to keep the conflict check consistent.
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
AC-4. `validate()` populates `fieldErrors` keyed by `fieldId` from
`ValidateResponse.errors`; a valid result sets `canSubmit = true`.
AC-5. With the network unreachable, local saves succeed and UI shows
`SyncPending`; sync completes automatically/manually on reconnect with no
answer loss.
AC-6. An expired/missing session (404/410) recreates a session and replays local
answers without data loss.
AC-7. A newer server `schema_version` sets `schemaChanged = true`, blocks sync,
and requires `reloadSchema()`.
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
