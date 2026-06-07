---
id: AND-351
title: Questionnaire ViewModels
milestone: M7
epic: E45
priority: P1
size: L
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-346, AND-347]
blocks: [AND-348, AND-349, AND-350, AND-352]
---

# AND-351 — Questionnaire ViewModels

## 1. Overview & Goal

This ticket delivers the presentation-layer state machine for the respondent
questionnaire flow: the Hilt-injected `ViewModel`s, immutable `UiState`
models, and the reducer/intent plumbing that drive the dynamic form renderer
(AND-347) and downstream session/submit features (AND-348, AND-349). The
ViewModels own all transient form state — per-field answers, dirty/touched
tracking, validation results, page/section navigation, and submit lifecycle —
and expose it as `StateFlow<QuestionnaireUiState>` consumed by Compose.

The goal is a deterministic, side-effect-free **form state machine** that:

- Hydrates from the published questionnaire schema and DTOs produced by
  AND-346 (`questionnaires` API + respondent-session DTOs).
- Holds answers in a normalized `Map<FieldId, FieldAnswer>` so the renderer
  reads/writes a single field without recomposing siblings.
- Computes validation and (stubbed for now) visibility derived state on every
  intent, exposing it without mutating the schema.
- Models the submit lifecycle (`Idle → Validating → Submitting → Submitted /
  Error`) as explicit states, so navigation and PDF export (AND-349) attach to
  well-defined transitions.
- Is **unit-tested** in isolation (the sole acceptance bar for this ticket),
  with no Android framework, no real network, and no Compose dependencies in
  the test target.

Rendering of widgets, the conditional-logic engine, network session calls, and
PDF export are explicitly **out of scope** and owned by AND-347, AND-350,
AND-348, and AND-349 respectively. This ticket defines the contracts those
tickets plug into.

## 2. Context & References

- Module: `feature-questionnaire` (depends on `core-model`, `core-data`,
  `core-network`, `core-ui`, `core-testing`).
- Package root: `com.testlogon.android.feature.questionnaire`.
- ViewModels live in `…questionnaire.respondent.vm`; state types in
  `…questionnaire.respondent.state`.
- Upstream: **AND-346** — `QuestionnaireDto`, `QuestionnaireFieldDto`,
  `PublishedQuestionnaireDto`, `RespondentSessionDto`, and the `Questionnaires`
  Retrofit service (mirror of web `frontend/src/api/endpoints/questionnaires.ts`,
  shared types `frontend/src/api/types.ts`).
- Downstream consumers: **AND-347** (renderer reads `fields`/`answers`, emits
  intents), **AND-348** (session start/save/validate wires into submit
  lifecycle), **AND-349** (submit + PDF), **AND-350** (conditional
  logic/validation replaces the stub visibility/validation hooks defined here),
  **AND-352** (renderer + validation tests build on the testable state machine).
- Platform: Kotlin 2.0.21, Coroutines/Flow, Hilt (KSP), minSdk 24,
  compileSdk/targetSdk 35, JDK 17. `StateFlow<UiState>` + typed `ApiResult<T>`
  conventions per project standard.
- Backend reference: FastAPI published-questionnaire endpoints under
  `/questionnaires/published/{published_slug}/…` (OpenAPI `/openapi.json` on the
  unreliable dev host `http://18.222.237.167:8000`). **[CORRECTED]** the path
  param is `{published_slug}`, not `{slug}` (OpenAPI `GET
  /questionnaires/published/{published_slug}`). **[CORRECTED]** auth in the web
  reference client is `Authorization: Bearer <accessToken>` plus an
  `X-CSRF-Token` header copied from the `ui_csrf` cookie, sent with
  `credentials: "include"` (so the session cookie also rides along); it is not a
  pure cookie session (`src/api/client.ts`). On Android, `core-network` provides
  the persistent cookie jar and is expected to attach the bearer token and read
  the `ui_csrf` cookie to set `X-CSRF-Token`; the ViewModel reads neither.

## 3. Functional Requirements

FR-1 **Hydration.** Given a `PublishedQuestionnaireDto` (and optional resumed
`RespondentSessionDto`), the ViewModel builds an ordered field list and an
answer map seeded from session values or field defaults, then emits a `Ready`
state. Schema is treated as immutable input.

FR-2 **Answer mutation.** A `FieldChanged(fieldId, value)` intent updates only
that field's `FieldAnswer`, marks it `dirty = true`, and recomputes validation
for that field plus form-level validity. No other field's identity changes.

FR-3 **Touched tracking.** A `FieldBlurred(fieldId)` intent marks a field
`touched = true`. Field-level error messages are surfaced to the renderer only
when `touched || submitAttempted`.

FR-4 **Validation.** The ViewModel evaluates required/format/range constraints
declared on each `QuestionnaireFieldDto` and exposes a `FieldValidation` per
field and an aggregate `isValid: Boolean`. The validation rule engine is a
pluggable interface (`FieldValidator`); AND-350 supplies the full
conditional/cross-field implementation. This ticket ships the base validators
(required, min/max length, numeric range, choice membership, date bounds).

FR-5 **Visibility hook.** Each field exposes a derived `visible: Boolean`. This
ticket provides a `VisibilityEvaluator` interface defaulting to "all visible";
hidden fields are excluded from validation aggregation. AND-350 replaces the
default with branching rules.

FR-6 **Navigation.** For paged/sectioned questionnaires, expose
`currentPageIndex`, `pageCount`, and `Next`/`Previous`/`GoToPage` intents.
`Next` is blocked when the current page has invalid visible fields (sets
`submitAttempted = true` for that page's fields).

FR-7 **Submit lifecycle.** A `Submit` intent transitions
`Ready → Submitting`. Actual network submit is delegated to an injected
`SubmitGateway` (no-op stub in this ticket; real impl in AND-349). On success
emit `Submitted(receipt)`; on failure emit `Ready` with a non-fatal
`submitError`. Validation must pass before `Submitting`.

FR-8 **Save/resume seam.** Expose `currentAnswersSnapshot(): RespondentAnswers`
and accept a resumed session at construction so AND-348 can implement
save-and-resume without ViewModel changes.

FR-9 **Idempotent reload.** A `Retry` intent re-runs hydration when initial
load failed, preserving any already-entered answers.

## 4. Technical Design

### 4.1 State model (`…respondent.state`)

```kotlin
sealed interface QuestionnaireUiState {
    data object Loading : QuestionnaireUiState
    data class Error(val message: UiText, val canRetry: Boolean) : QuestionnaireUiState
    data class Ready(
        val questionnaireId: String,
        val title: String,
        val pages: List<FormPage>,           // ordered, from schema
        val currentPageIndex: Int,
        val fields: List<FormField>,          // flattened, render order
        val answers: Map<FieldId, FieldAnswer>,
        val validation: Map<FieldId, FieldValidation>,
        val submitAttempted: Boolean,
        val submitState: SubmitState,
    ) : QuestionnaireUiState {
        val isValid: Boolean get() =
            fields.none { it.visible && validation[it.id]?.isError == true }
        val pageCount: Int get() = pages.size
    }
    data class Submitted(val receipt: SubmitReceipt) : QuestionnaireUiState
}

@JvmInline value class FieldId(val value: String)

data class FormField(
    val id: FieldId,
    val type: FieldType,                       // TEXT, LONG_TEXT, CHOICE_SINGLE, CHOICE_MULTI, SCALE, DATE, UPLOAD, ...
    val label: String,
    val required: Boolean,
    val options: List<FieldOption>,
    val constraints: FieldConstraints,
    val pageIndex: Int,
    val visible: Boolean,
)

data class FieldAnswer(
    val value: AnswerValue,                    // Text/Number/Choice(Set)/DateIso/Upload(ref)/Empty
    val dirty: Boolean = false,
    val touched: Boolean = false,
)

data class FieldValidation(val isError: Boolean, val message: UiText?)

sealed interface SubmitState {
    data object None : SubmitState
    data object InProgress : SubmitState
    data class Failed(val message: UiText) : SubmitState
}
```

`AnswerValue` is a sealed type so the renderer (AND-347) gets exhaustive
`when` coverage. `UiText` is the existing `core-ui` resource/literal wrapper
for i18n.

### 4.2 Intents

```kotlin
sealed interface QuestionnaireIntent {
    data class FieldChanged(val id: FieldId, val value: AnswerValue) : QuestionnaireIntent
    data class FieldBlurred(val id: FieldId) : QuestionnaireIntent
    data object Next : QuestionnaireIntent
    data object Previous : QuestionnaireIntent
    data class GoToPage(val index: Int) : QuestionnaireIntent
    data object Submit : QuestionnaireIntent
    data object Retry : QuestionnaireIntent
}
```

### 4.3 ViewModel

```kotlin
@HiltViewModel
class RespondentQuestionnaireViewModel @Inject constructor(
    private val repository: QuestionnaireRepository,   // AND-346
    private val validators: FieldValidatorSet,         // base rules; AND-350 extends
    private val visibility: VisibilityEvaluator,       // default all-visible
    private val submitGateway: SubmitGateway,          // stub here; AND-349
    private val reducer: QuestionnaireReducer,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val slug: String = checkNotNull(savedStateHandle["slug"])
    private val resumedSessionId: String? = savedStateHandle["sessionId"]

    private val _state = MutableStateFlow<QuestionnaireUiState>(QuestionnaireUiState.Loading)
    val state: StateFlow<QuestionnaireUiState> = _state.asStateFlow()

    init { load() }

    fun onIntent(intent: QuestionnaireIntent) { /* dispatch to reducer / load / submit */ }

    fun currentAnswersSnapshot(): RespondentAnswers = /* derive from Ready.answers */

    private fun load() { /* repository.published(slug) -> hydrate via reducer */ }
    private fun submit() { /* validate -> InProgress -> submitGateway.submit(...) */ }
}
```

### 4.4 Pure reducer

All non-IO transitions are pure functions in `QuestionnaireReducer`, taking
`(Ready, Intent) -> Ready` plus the validators/visibility evaluator. This is
the unit-testable core; the ViewModel only orchestrates IO and threading.

```kotlin
class QuestionnaireReducer(
    private val validators: FieldValidatorSet,
    private val visibility: VisibilityEvaluator,
) {
    fun hydrate(schema: PublishedQuestionnaireDto, resume: RespondentSessionDto?): QuestionnaireUiState.Ready
    fun reduce(state: QuestionnaireUiState.Ready, intent: QuestionnaireIntent): QuestionnaireUiState.Ready
    fun recomputeValidation(state: QuestionnaireUiState.Ready): QuestionnaireUiState.Ready
}
```

### 4.5 Extension seams

```kotlin
fun interface FieldValidator { fun validate(field: FormField, answer: FieldAnswer): FieldValidation }
class FieldValidatorSet(private val validators: List<FieldValidator>)
fun interface VisibilityEvaluator { fun isVisible(field: FormField, answers: Map<FieldId, FieldAnswer>): Boolean }
interface SubmitGateway { suspend fun submit(answers: RespondentAnswers): ApiResult<SubmitReceipt> }
```

Hilt module `QuestionnaireVmModule` binds default `VisibilityEvaluator { _, _ -> true }`
and a `NoopSubmitGateway` returning `ApiResult.Success(SubmitReceipt.PENDING)`;
AND-350/AND-349 override with `@Binds`.

## 5. API Contract

This ticket performs **no new HTTP itself** — it consumes the `QuestionnaireRepository`
and DTOs from AND-346 and delegates submit to AND-349's `SubmitGateway`.

Schema source it depends on (owned by AND-346):

**[CORRECTED — verified against OpenAPI + web client].** The endpoint is
`GET /questionnaires/published/{published_slug}` and the response is an
**envelope** `PublishedQuestionnaireEnvelope` `{ "version": { … } }`, not a flat
`PublishedQuestionnaireDto`. The web client types `version` as
`PublishedQuestionnaireVersion` (`src/api/types.ts`):

```json
{
  "version": {
    "questionnaire_id": "q_123",
    "version_id": "ver_7",
    "version_number": 3,
    "published_slug": "intake-2026",
    "visibility": "public",
    "allow_anonymous": true,
    "schema_json": { /* opaque builder schema: sections, questions */ },
    "published_at": "2026-03-01T00:00:00Z"
  }
}
```

The actual field/page model lives inside **`schema_json`** (typed
`Record<string, unknown>` in the web client — i.e. an untyped builder blob).
Individual questions follow `QuestionnaireQuestion`: `question_id`, `section_id`,
`type` (one of `text | select | multiselect | radio | slider | date | time |
timezone | address`), `label`, `required`, optional `hint`, `config_json`
(`Record<string, unknown>` — holds options/min/max/etc.), and `position`. The
spec's earlier field model (`id`/`options`/`constraints`, types
`choice_single`/`scale`/`long_text`/`upload`) is the **Android domain model**
AND-346 maps the raw `schema_json`/`config_json` into; it is NOT the wire shape.
The Android `FormField.type` mapping must cover the wire types above (see R2 /
the `Unsupported` fallback).

Resume / session state is the `SessionStateEnvelope` returned by
`GET /questionnaires/published/{published_slug}/sessions/{response_session_id}`
(web type `QuestionnaireSessionStateResp`) — **[CORRECTED]** field names are
`session` + `answers_by_question_id`, and the session id is
`response_session_id` with page position `current_section_index` (not
`sessionId`/`answers`/`lastPageIndex`):

```json
{
  "session": {
    "response_session_id": "s_88",
    "questionnaire_id": "q_123",
    "version_id": "ver_7",
    "status": "in_progress",
    "started_at": "2026-03-02T10:00:00Z",
    "current_section_index": 0
  },
  "answers_by_question_id": { "f_name": "Ada", "f_pref": ["email"] }
}
```

Snapshot this ticket produces for save/submit (`RespondentAnswers`) — **[CORRECTED]**
must serialize to the backend `SessionSaveReq` / validation request shape, i.e.
`answers_by_question_id` keyed by `question_id`, with `current_section_index`
(and optional `current_question_id`); the submit/validate body
(`QuestionnaireValidationRequest`) additionally carries
`contract_version: "2026-03-validation-v1"` and `final_submit`:

```json
{ "answers_by_question_id": { "f_name": "Ada", "f_age": 36, "f_pref": ["email"] },
  "current_section_index": 0 }
```

Validation/submit responses (`QuestionnaireValidationResponse`, also embedded as
`result` in `SessionSubmitEnvelope`) expose `is_valid`, `can_submit`,
`has_blocking_form_error`, and `errors` (a `Record<scopeKey, ValidationIssue[]>`
where each issue is `{code, message, blocking?, rule_id?}`). The base validators
in this ticket are a client-side mirror; the authoritative server result arrives
via AND-348/AND-349.

FastAPI `detail` error mapping (string | `[{msg}]` | `{code,...}`) is handled in
`core-network` — **[VERIFIED]** against `src/api/client.ts: normalizeErrorDetail`
(handles all three shapes). The ViewModel only receives a typed
`ApiResult.Failure(AppError)` and maps it to `Error`/`SubmitState.Failed`.

## 6. Data & State Management

- **Single source of truth:** `MutableStateFlow<QuestionnaireUiState>`; UI is a
  pure projection. No mutable state escapes the ViewModel.
- **Normalized answers:** `Map<FieldId, FieldAnswer>`. Field-level mutation
  produces a new map with one entry replaced (structural sharing) so Compose
  recomposition is field-scoped when the renderer keys by `FieldId`.
- **Derived state** (`isValid`, `visible`, per-page validity) is computed, never
  stored redundantly, to prevent drift.
- **No Room cache** in this ticket — published schema is fetched live by AND-346;
  draft persistence (DataStore/session save) is AND-348. The
  `currentAnswersSnapshot()` seam is the only persistence touchpoint exposed.
- **Process death:** the route args (`slug`, `sessionId`) survive via
  `SavedStateHandle`; in-progress unsaved answers are intentionally not persisted
  here (covered when AND-348 wires periodic save). Document this limitation in code.
- **Threading:** reducer is pure/synchronous on the calling (main) dispatcher;
  IO (`load`, `submit`) runs in `viewModelScope` on `Dispatchers.IO` injected via
  a `DispatcherProvider` from `core-data`.

## 7. Error Handling & Resilience

- **Initial load failure:** `repository.published(slug)` returning
  `ApiResult.Failure` → `Error(message, canRetry = true)`. `Retry` re-runs `load()`
  while preserving any answers already captured (re-hydrate then re-apply the
  prior answer map for matching field ids).
- **Dev-host unreliability:** load is an idempotent GET, so bounded backoff retry
  (configured in `core-network` per project standard) applies; the ViewModel sets
  a ~20s budget expectation and surfaces an offline/stale `Error` state with retry.
- **Submit failure:** non-fatal — transition back to `Ready` with
  `submitState = Failed(message)`; user input is never lost. Submit is **not**
  auto-retried (non-idempotent POST is owned by AND-349).
- **Validation failure on Submit/Next:** stays in `Ready`, sets
  `submitAttempted = true` (or per-page), scrolls/focuses first invalid field via
  a one-shot `effect` channel (`SharedFlow<QuestionnaireEffect>`).
- **Malformed schema:** unknown `FieldType` maps to an `Unsupported` field that
  renders read-only (AND-347) and is excluded from validation — never crash.

## 8. Security & Privacy

- ViewModels hold respondent PII (names, answers) only in memory; nothing is
  logged at value level (see §10). `toString()` on `FieldAnswer`/`AnswerValue`
  is overridden to redact values (`Text(<redacted len=N>)`).
- No credentials handled here; transport auth (`Authorization: Bearer` token +
  `X-CSRF-Token` derived from the `ui_csrf` cookie, sent with the session cookie)
  is managed by `core-network`. **[CORRECTED]** the web reference attaches
  `X-CSRF-Token` on every request (not only mutations) and uses a bearer token in
  addition to the cookie (`src/api/client.ts`); the ViewModel reads neither
  cookies nor tokens.
- Upload field values carry only opaque references, not file bytes.
- Snapshots returned by `currentAnswersSnapshot()` are passed directly to the
  session/submit gateways and never written to logs or analytics.

## 9. Accessibility & i18n

- All user-facing strings (labels come from schema; error/validation copy is
  app-owned) flow through `UiText` → string resources. Validation messages are
  resource-backed (e.g., `R.string.qn_error_required`,
  `R.string.qn_error_range`).
- The state machine exposes structured `FieldValidation` so the renderer
  (AND-347) can set Compose `semantics { error(...) }` and live regions;
  surfacing-on-`touched` logic prevents premature, noisy screen-reader errors.
- Focus-first-invalid effect supports keyboard/TalkBack navigation.
- No hardcoded English in ViewModel/reducer code; numeric formatting deferred to
  the renderer using the device locale.

## 10. Telemetry & Logging

- Emit structured, value-free events via the existing `Analytics` interface
  (`core-data`): `questionnaire_loaded {questionnaireId, fieldCount}`,
  `questionnaire_page_changed {from, to}`, `questionnaire_validation_failed
  {invalidCount}`, `questionnaire_submit_attempt`,
  `questionnaire_submit_result {success, errorCode?}`.
- **Never** log answer values or field labels that may contain PII; log only
  `FieldId`s and counts.
- Debug-build `Timber` tracing of state transitions logs intent class name and
  resulting `submitState`, not answer contents.

## 11. Testing Strategy

The **sole acceptance** for this ticket is "Unit-tested." Tests run in the JVM
test source set (`feature-questionnaire/src/test`) with no Robolectric required
for the reducer.

- `QuestionnaireReducerTest` (pure, JUnit5 + Truth):
  - hydrate seeds answers from defaults and from a resumed session;
  - `FieldChanged` updates only the target field and sets `dirty`;
  - `FieldBlurred` sets `touched`; errors hidden until touched/submitAttempted;
  - required/min-max/range/choice-membership/date-bound validators each pass &
    fail as specified (parameterized);
  - `isValid` ignores hidden fields;
  - `Next` blocked on invalid page, allowed when valid; `Previous`/`GoToPage`
    clamp to bounds;
  - unknown field type becomes `Unsupported`, excluded from validation.
- `RespondentQuestionnaireViewModelTest` (`kotlinx-coroutines-test`
  `runTest` + `StandardTestDispatcher` from `core-testing`, fake
  `QuestionnaireRepository` and `SubmitGateway`):
  - load success → `Ready`; load failure → `Error(canRetry=true)`; `Retry`
    preserves answers;
  - `Submit` with invalid form stays `Ready`, sets `submitAttempted`, emits
    focus effect; valid form → `InProgress` → `Submitted`;
  - submit gateway failure → `Ready` + `SubmitState.Failed`, answers intact;
  - `currentAnswersSnapshot()` reflects current answer map and page index.
- Coverage target ≥ 90% lines on `reducer`/`vm`/`state` packages; enforced in CI.
- Test fixtures (`QuestionnaireFixtures`) added to `core-testing` for reuse by
  AND-352.

## 12. Dependencies & Sequencing

- **Depends on AND-346** (DTOs + `QuestionnaireRepository`) — hard blocker; the
  reducer consumes its types.
- **Depends on AND-347** for the `FormField`/`AnswerValue`/intent contract shape
  to be co-designed (renderer is the primary consumer). Practically these two
  are developed in tandem; this ticket owns the state types, AND-347 owns
  Composables.
- **Blocks AND-348** (session save/resume wires `currentAnswersSnapshot()` and
  resume hydration), **AND-349** (real `SubmitGateway` + PDF), **AND-350**
  (real `VisibilityEvaluator` + extended validators), and **AND-352** (tests
  build on the same fixtures and reducer).
- Sequencing: land state types + reducer + base validators first (unblocks
  AND-347 wiring), then ViewModel IO orchestration, then stub Hilt bindings.

## 13. Risks & Open Questions

- **R1 — Contract churn with AND-350.** The `FieldValidator`/`VisibilityEvaluator`
  seams must be stable so conditional logic plugs in without ViewModel changes.
  Mitigation: interfaces fixed in this ticket; AND-350 only supplies impls.
- **R2 — Schema field-type drift** vs. the web reference. Mitigation:
  `Unsupported` fallback + a test asserting every `frontend` field type maps.
- **R3 — Recomposition cost** on large forms if answers map isn't keyed
  properly. Mitigation: field-scoped keys, value-class `FieldId`, structural
  sharing.
- **Q1 — Page-level vs. whole-form validation on Submit:** assume whole-form on
  `Submit`, per-page on `Next`. Confirm with AND-347 UX.
- **Q2 — Should unsaved answers survive process death before AND-348 lands?**
  Assumed no (documented); revisit if QA flags data loss.
- **Q3 — Multi-select/`scale` answer normalization** (string vs. numeric in the
  snapshot) — align JSON shape with AND-346 DTOs and the FastAPI schema.

## 14. Acceptance Criteria

AC-1 `RespondentQuestionnaireViewModel` exposes `StateFlow<QuestionnaireUiState>`
and a single `onIntent(QuestionnaireIntent)` entry point; no mutable state leaks.

AC-2 Hydration from a `PublishedQuestionnaireDto` (and optional
`RespondentSessionDto`) produces `Ready` with correctly ordered fields/pages and
seeded answers.

AC-3 `FieldChanged` mutates only the targeted field's answer (verified by map
identity of untouched entries) and recomputes validation.

AC-4 Base validators (required, min/max length, numeric range, choice
membership, date bounds) produce correct `FieldValidation`, and `isValid`
excludes hidden fields — all proven by unit tests.

AC-5 Submit lifecycle transitions `Ready → Submitting → Submitted` on success
and `Ready → Submitting → Ready(submitError)` on failure, never losing answers;
invalid forms never reach `Submitting`.

AC-6 Load failure yields `Error(canRetry=true)`; `Retry` re-hydrates and
preserves entered answers.

AC-7 `currentAnswersSnapshot()` returns a `RespondentAnswers` matching current
state, suitable for AND-348/AND-349.

AC-8 The reducer is a pure function with no Android/Compose/network imports,
unit-tested with ≥ 90% line coverage; the full `:feature-questionnaire:test`
task passes in CI.

## 15. Definition of Done

- All §14 acceptance criteria met and demonstrated by green tests.
- `QuestionnaireUiState`, `QuestionnaireIntent`, `QuestionnaireReducer`,
  `RespondentQuestionnaireViewModel`, validator/visibility/submit seams, and
  Hilt `QuestionnaireVmModule` merged on `android-port` under
  `com.testlogon.android.feature.questionnaire`.
- `QuestionnaireFixtures` added to `core-testing` and consumed by tests.
- ktlint/detekt clean; KSP/Hilt graph compiles; no PII in logs/telemetry
  (verified by `toString()` redaction tests).
- Public seams (`FieldValidator`, `VisibilityEvaluator`, `SubmitGateway`)
  documented with KDoc identifying their downstream owners (AND-350, AND-349).
- Code review approved; CI (`assemble` + `:feature-questionnaire:test`) green;
  ticket cross-links to AND-346/347/348/349/350/352 verified.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **Published schema is fetched via `GET /questionnaires/published/{slug}`.**
   VERDICT: Corrected. The path param is `{published_slug}`.
   SOURCE: OpenAPI `GET /questionnaires/published/{published_slug}`
   (op `get_published_by_slug_…`); frontend `src/api/endpoints/questionnaires.ts:
   getPublishedQuestionnaireBySlug`.

2. **Response type is `PublishedQuestionnaireDto` (flat `id/slug/title/pages`).**
   VERDICT: Corrected. The response is the envelope
   `PublishedQuestionnaireEnvelope` `{ version: {...} }`; the typed body is
   `PublishedQuestionnaireVersion` (`questionnaire_id`, `version_id`,
   `version_number`, `published_slug`, `visibility`, `allow_anonymous`,
   `schema_json`, `published_at`). The field/page tree is inside `schema_json`
   (untyped `Record<string, unknown>`).
   SOURCE: OpenAPI schema `PublishedQuestionnaireEnvelope`; frontend
   `src/api/types.ts: PublishedQuestionnaireVersion`,
   `src/api/endpoints/questionnaires.ts: getPublishedQuestionnaireBySlug`
   (returns `{ version: PublishedQuestionnaireVersion }`).

3. **Field wire shape uses `id`, `type` (`text/scale/choice_single/...`),
   `options`, `constraints`.** VERDICT: Corrected. The wire question is
   `QuestionnaireQuestion`: `question_id`, `section_id`, `type`
   (`text | select | multiselect | radio | slider | date | time | timezone |
   address`), `label`, `required`, `hint?`, `config_json`, `position`. The spec's
   `FormField`/`FieldType`/`options`/`constraints` is the Android domain model
   that AND-346 maps from `config_json`; documented as such in §4.1/§5.
   SOURCE: frontend `src/api/types.ts: QuestionnaireQuestion`,
   `QuestionnaireQuestionType`.

4. **Resume DTO is `RespondentSessionDto` with `sessionId`/`answers`/
   `lastPageIndex`.** VERDICT: Corrected. Real shape is `SessionStateEnvelope`
   (web `QuestionnaireSessionStateResp`): `session` (with `response_session_id`,
   `questionnaire_id`, `version_id`, `status`, `started_at`,
   `current_section_index`, `current_question_id?`, `respondent_id?`) plus
   `answers_by_question_id`.
   SOURCE: OpenAPI schemas `SessionStateEnvelope`,
   `GET /questionnaires/published/{published_slug}/sessions/{response_session_id}`;
   frontend `src/api/types.ts: QuestionnaireSessionState /
   QuestionnaireSessionStateResp`.

5. **Snapshot `RespondentAnswers` is `{ answers, lastPageIndex }`.**
   VERDICT: Corrected. Save body is `SessionSaveReq`:
   `answers_by_question_id`, `current_section_index?`, `current_question_id?`.
   SOURCE: OpenAPI schema `SessionSaveReq`,
   `PUT /questionnaires/published/{published_slug}/sessions/{response_session_id}`;
   frontend `src/api/endpoints/questionnaires.ts:
   savePublishedResponseSessionState`.

6. **Submit/validate request shape.** VERDICT: Verified (added detail). Body is
   `QuestionnaireValidationRequest`: `answers_by_question_id`,
   `contract_version: "2026-03-validation-v1"` (const), `final_submit` (bool,
   default false), `form_rules`, `group_rules`. Submit returns
   `SessionSubmitEnvelope` `{ session, result }` where `result` is a
   `QuestionnaireValidationResponse`.
   SOURCE: OpenAPI schemas `QuestionnaireValidationRequest`,
   `SessionSubmitEnvelope`,
   `POST /questionnaires/published/{published_slug}/sessions/{response_session_id}/submit`;
   frontend `src/api/types.ts: QuestionnaireValidationReq`,
   `QUESTIONNAIRE_VALIDATION_CONTRACT_VERSION`.

7. **Validation result fields drive `isValid`/submit gating.** VERDICT: Verified.
   `QuestionnaireValidationResponse`: `is_valid`, `can_submit`,
   `has_blocking_form_error`, `errors` (`Record<scopeKey, ValidationIssue[]>`,
   each issue `{code, message, blocking?, rule_id?}`).
   SOURCE: OpenAPI schema `QuestionnaireValidationResponse`,
   `ValidationIssue`; frontend `src/api/types.ts: QuestionnaireValidationResp`,
   `QuestionnaireValidationIssue`.

8. **Auth is "cookie-based session + X-CSRF-Token", ViewModel never reads
   cookies.** VERDICT: Corrected. The web client sends `Authorization: Bearer
   <accessToken>` AND `X-CSRF-Token` (from the `ui_csrf` cookie) on every
   request, with `credentials: "include"` (cookie also sent). It is bearer +
   CSRF + cookie, not a pure cookie session; CSRF is not gated to mutations. The
   "ViewModel never reads cookies/tokens" part remains true.
   SOURCE: frontend `src/api/client.ts` (`getCookie("ui_csrf")`,
   `headers.set("X-CSRF-Token", csrf)`, `Authorization: Bearer`,
   `credentials: "include"`).

9. **FastAPI `detail` error mapping handles `string | [{msg}] | {code,...}`.**
   VERDICT: Verified. `normalizeErrorDetail` handles a raw string, an array of
   items with `.msg`, and an object form (with `mapAuthorizationError` reading
   `detail.code`).
   SOURCE: frontend `src/api/client.ts: normalizeErrorDetail`,
   `mapAuthorizationError`; all questionnaire ops list `422:HTTPValidationError`
   in the OpenAPI index.

10. **Submit is a non-idempotent POST; load is an idempotent GET (retry-safe).**
    VERDICT: Verified. `GET /questionnaires/published/{published_slug}` (load) vs
    `POST .../sessions/{response_session_id}/submit` (submit).
    SOURCE: OpenAPI index lines for those two ops.

11. **`@HiltViewModel` + `SavedStateHandle` route args; `StateFlow` exposure.**
    VERDICT: Unverified-assumption (framework choice, consistent with project
    standard). Reasonable per AndroidX guidance.
    SOURCE: framework ref —
    https://developer.android.com/topic/libraries/architecture/viewmodel
    and https://developer.android.com/training/dependency-injection/hilt-jetpack.

12. **minSdk 24, compileSdk/targetSdk 35, Kotlin 2.0.21, JDK 17, KSP/Hilt.**
    VERDICT: Unverified-assumption (project-wide build config; not derivable from
    the API/web sources). Should match the module `build.gradle`.
    SOURCE: framework ref — https://developer.android.com/build/multidex and
    project Gradle convention (not in the supplied reference set).

13. **`ResponseSessionStartReq` body for starting a session.** VERDICT: Verified
    (informational; session start is AND-348, not this ticket). Optional
    `questionnaire_id`; web client posts `{}`.
    SOURCE: OpenAPI schema `ResponseSessionStartReq`; frontend
    `src/api/endpoints/questionnaires.ts: startPublishedResponseSession`.

### Corrections made

- §2: endpoint param `{slug}` → `{published_slug}`; clarified auth is
  Bearer + `X-CSRF-Token` (from `ui_csrf` cookie) + cookie, not pure cookie
  session.
- §5: replaced the flat `PublishedQuestionnaireDto` JSON with the real
  `PublishedQuestionnaireEnvelope` / `PublishedQuestionnaireVersion` envelope
  (schema in `schema_json`); corrected question fields to
  `question_id/section_id/type/label/required/hint/config_json/position` and the
  wire type enum; corrected resume DTO to `SessionStateEnvelope`
  (`session` + `answers_by_question_id`, `response_session_id`,
  `current_section_index`); corrected snapshot to the `SessionSaveReq` /
  `QuestionnaireValidationRequest` shape (`answers_by_question_id`,
  `current_section_index`, `contract_version`, `final_submit`); added the
  `QuestionnaireValidationResponse`/`ValidationIssue` result shape; marked the
  `detail` mapping claim Verified with source.
- §8: corrected the CSRF/auth description (bearer + CSRF on every request).

### Open assumptions

- **Android framework/build choices** (Hilt, `SavedStateHandle`, `StateFlow`,
  minSdk/compileSdk, Kotlin/JDK versions): not verifiable from the OpenAPI or web
  reference; treated as project convention (claims 11–12).
- **The Android domain model** (`FormField`, `FieldType`, `AnswerValue`,
  `FieldConstraints`, `RespondentAnswers`, `SubmitReceipt`) is owned by this
  ticket/AND-346 and has no direct wire counterpart — `schema_json` and
  `config_json` are untyped on the wire, so the exact mapping is an internal
  contract, not server-verifiable. Risk R2 (`Unsupported` fallback) covers drift.
- **Per-page vs whole-form validation semantics** (Q1) and **process-death
  persistence** (Q2) are product/UX decisions, not in the sources.
- **`core-network` retry/backoff budget (~20s)** in §7 is a project-standard
  assumption, not specified by the API.

## 17. Test Plan

All cases target the pure reducer / ViewModel (the ticket's "Unit-tested"
acceptance), with a few contract and UI/instrumented cases listed for the
downstream integration points this ticket defines. Since this ticket ships **no
UI and no real HTTP** itself, the bulk runs as JVM unit tests; physical-device
cases are noted only where genuinely hardware-bound.

- TC-AND-351-01 — **Hydration happy path (defaults).**
  Type: unit (JVM, JUnit5+Truth). Target: `QuestionnaireReducer.hydrate`.
  Preconditions: a `PublishedQuestionnaireVersion` fixture mapped to two pages /
  several fields, no resumed session. Steps: call `hydrate(schema, null)`.
  Expected: returns `Ready` with pages/fields in `position` order,
  `currentPageIndex == 0`, answers seeded from field defaults (empty where none),
  `submitAttempted == false`, `submitState == None`. Traces: AC-2.

- TC-AND-351-02 — **Hydration from resumed session.**
  Type: unit. Target: `QuestionnaireReducer.hydrate`. Preconditions: same schema
  plus a `SessionStateEnvelope` fixture with `answers_by_question_id` and
  `current_section_index = 1`. Steps: `hydrate(schema, resume)`. Expected:
  answers map seeded from `answers_by_question_id` (keyed by `question_id`),
  `currentPageIndex == 1`; unknown answer keys ignored without crashing.
  Traces: AC-2, AC-7.

- TC-AND-351-03 — **FieldChanged mutates only the target field.**
  Type: unit. Target: `QuestionnaireReducer.reduce(FieldChanged)`.
  Preconditions: hydrated `Ready` with ≥3 fields. Steps: apply
  `FieldChanged(f2, value)`. Expected: `answers[f2]` updated with `dirty = true`;
  every other entry is reference-equal to the prior map's entry (verify by map
  identity); validation recomputed for `f2` and aggregate `isValid`.
  Traces: AC-3.

- TC-AND-351-04 — **FieldBlurred / touched gating of errors.**
  Type: unit. Target: `reduce(FieldBlurred)` + error surfacing. Preconditions:
  required field left empty (invalid) but not yet touched. Steps: assert no
  surfaced error pre-blur; apply `FieldBlurred(f)`; re-check. Expected: error is
  hidden until `touched || submitAttempted`, then surfaced. Traces: AC-3, AC-4.

- TC-AND-351-05 — **Base validators pass/fail (parameterized).**
  Type: unit (parameterized). Target: `FieldValidatorSet` (required, min/max
  length, numeric range, choice membership, date bounds). Preconditions: one
  fixture per rule with a passing and a failing answer. Steps: validate each.
  Expected: correct `FieldValidation.isError`/`message` per case; choice
  membership rejects values absent from `config_json` options; date bounds
  enforce min/max. Traces: AC-4.

- TC-AND-351-06 — **`isValid` excludes hidden fields.**
  Type: unit. Target: `Ready.isValid` + `VisibilityEvaluator`. Preconditions: an
  invalid required field marked not-visible by a stub evaluator. Steps: compute
  `isValid`. Expected: `true` (hidden invalid field excluded from aggregation);
  flipping it visible makes `isValid == false`. Traces: AC-4.

- TC-AND-351-07 — **Navigation: Next blocked on invalid page; clamping.**
  Type: unit. Target: `reduce(Next/Previous/GoToPage)`. Preconditions: page 0 has
  an invalid visible field. Steps: `Next` on invalid page, then fix and `Next`;
  `Previous` at index 0; `GoToPage(99)`. Expected: blocked `Next` keeps
  `currentPageIndex`, sets `submitAttempted` for that page's fields; valid `Next`
  advances; `Previous`/`GoToPage` clamp to `[0, pageCount-1]`. Traces: AC-2, AC-5.

- TC-AND-351-08 — **Unknown field type → Unsupported, excluded from validation.**
  Type: unit. Target: schema→domain mapping + validation. Preconditions: schema
  with a `type` value outside the known enum
  (`text/select/multiselect/radio/slider/date/time/timezone/address`). Steps:
  hydrate. Expected: field becomes `Unsupported`, never crashes, and is excluded
  from validation/`isValid`. Traces: AC-4. (Mitigates R2.)

- TC-AND-351-09 — **Submit happy path lifecycle.**
  Type: unit (ViewModel, `runTest` + `StandardTestDispatcher`). Target:
  `RespondentQuestionnaireViewModel.submit` with a fake `SubmitGateway` returning
  `Success`. Preconditions: hydrated, all valid. Steps: emit `Submit`; advance
  dispatcher. Expected: `Ready → submitState InProgress → Submitted(receipt)`;
  answers never lost. Traces: AC-5.

- TC-AND-351-10 — **Submit blocked by invalid form (no network).**
  Type: unit (ViewModel). Target: `submit` validation gate + effect channel.
  Preconditions: hydrated with an invalid required field; spy `SubmitGateway`.
  Steps: emit `Submit`. Expected: stays `Ready`, sets `submitAttempted = true`,
  emits a focus-first-invalid effect on the `SharedFlow`, and `SubmitGateway` is
  NEVER called. Traces: AC-5. (Security/integrity: prevents posting invalid PII.)

- TC-AND-351-11 — **Submit gateway failure is non-fatal.**
  Type: unit (ViewModel). Target: `submit` with fake gateway returning
  `ApiResult.Failure`. Preconditions: valid form. Steps: emit `Submit`. Expected:
  transitions back to `Ready` with `submitState = Failed(message)`; answer map
  unchanged; no auto-retry of the POST. Traces: AC-5.

- TC-AND-351-12 — **Load failure + Retry preserving answers (flaky dev-host /
  offline path).** Type: unit (ViewModel). Target: `load`/`Retry` with a fake
  `QuestionnaireRepository` that fails first then succeeds. Preconditions: first
  `published(slug)` returns `Failure` (simulating offline/unreachable dev host);
  user has entered some answers before retry is possible — to test answer
  preservation, seed a `Ready` with answers, force an error path, then `Retry`.
  Steps: observe `Error(canRetry=true)`; emit `Retry`; gateway now succeeds.
  Expected: re-hydration succeeds and previously entered answers are re-applied to
  matching field ids. Traces: AC-6.

- TC-AND-351-13 — **`currentAnswersSnapshot()` matches state and serializes to
  the wire shape.** Type: contract (JVM, with kotlinx-serialization/Moshi).
  Target: `currentAnswersSnapshot()` + DTO serialization. Preconditions: hydrated
  `Ready` with a text, numeric, and multi-choice answer and `currentPageIndex`.
  Steps: snapshot then serialize to the save/submit DTO. Expected: produces
  `answers_by_question_id` keyed by `question_id`, `current_section_index`
  matching `currentPageIndex`; for a validation/submit body, includes
  `contract_version = "2026-03-validation-v1"` and `final_submit`. Traces: AC-7.

- TC-AND-351-14 — **No PII in `toString()` / telemetry redaction.**
  Type: unit. Target: `FieldAnswer`/`AnswerValue.toString()` + `Analytics`
  events. Preconditions: answers containing realistic PII (name, free text).
  Steps: call `toString()`; capture emitted analytics. Expected: values redacted
  (e.g. `Text(<redacted len=N>)`); analytics carry only `FieldId`/counts, never
  values or labels. Traces: AC-1, AC-8. (Security/privacy.)

- TC-AND-351-15 — **Reducer purity / no Android-Compose-network imports.**
  Type: unit + static check. Target: `:feature-questionnaire` reducer/state
  source set. Preconditions: reducer compiled into the JVM `test` source set with
  no Robolectric. Steps: run `QuestionnaireReducerTest` headless; assert (via a
  detekt/ArchUnit-style rule or by the test module simply compiling without
  Android deps) no `android.*`/`androidx.compose.*`/`retrofit`/`okhttp` imports
  in reducer/state packages. Expected: green, ≥90% line coverage on
  `reducer`/`vm`/`state`. Traces: AC-8.

- TC-AND-351-16 — **(Optional, downstream) Renderer error semantics surface to
  accessibility.** Type: Compose-UI / instrumented. Target: a thin harness
  binding a `Ready` state with field errors to the AND-347 renderer contract.
  Preconditions: emulator AVD `test35` (API 35) — no special hardware needed.
  Steps: render a field whose `FieldValidation.isError == true` after blur;
  inspect semantics. Expected: Compose `semantics` exposes the error text / live
  region so TalkBack announces it; no error announced before `touched`.
  Run target: headless emulator `test35` (sufficient; physical device not
  required as no camera/biometric/network hardware is exercised). Traces:
  AC-4. NOTE: this verifies the contract this ticket exposes; the renderer itself
  is AND-347, so it is optional/forward-looking for AND-352.

### Coverage matrix

| Acceptance criterion | Covered by |
| --- | --- |
| AC-1 (StateFlow + single onIntent, no leak) | TC-14, TC-15 |
| AC-2 (hydration order + seeded answers) | TC-01, TC-02, TC-07 |
| AC-3 (FieldChanged isolation + recompute; touched) | TC-03, TC-04 |
| AC-4 (base validators; isValid excludes hidden) | TC-04, TC-05, TC-06, TC-08, TC-16 |
| AC-5 (submit lifecycle; invalid never submits) | TC-07, TC-09, TC-10, TC-11 |
| AC-6 (load failure + Retry preserves answers) | TC-12 |
| AC-7 (currentAnswersSnapshot matches state) | TC-02, TC-13 |
| AC-8 (pure reducer, ≥90% coverage, CI green) | TC-14, TC-15 |
