---
id: AND-351
title: Questionnaire ViewModels
milestone: M7
epic: E45
priority: P1
size: L
status: draft
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
  `/questionnaires/published/{slug}/…` (OpenAPI `/openapi.json` on the
  unreliable dev host `http://18.222.237.167:8000`). Cookie-based session +
  `X-CSRF-Token`; persistent cookie jar already provided by `core-network`.

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

`GET /questionnaires/published/{slug}` → `PublishedQuestionnaireDto`:

```json
{
  "id": "q_123",
  "slug": "intake-2026",
  "title": "Patient Intake",
  "pages": [
    { "index": 0, "title": "About you",
      "fields": [
        { "id": "f_name", "type": "text", "label": "Full name", "required": true,
          "constraints": { "minLength": 1, "maxLength": 120 } },
        { "id": "f_age", "type": "scale", "label": "Age", "required": true,
          "constraints": { "min": 0, "max": 120 } },
        { "id": "f_pref", "type": "choice_single", "label": "Contact",
          "options": [ {"id":"email","label":"Email"}, {"id":"sms","label":"SMS"} ] }
      ]
    }
  ]
}
```

Resume payload (AND-348) consumed at construction — `RespondentSessionDto`:

```json
{ "sessionId": "s_88", "answers": { "f_name": "Ada", "f_pref": ["email"] }, "lastPageIndex": 0 }
```

Snapshot this ticket produces for save/submit (`RespondentAnswers`):

```json
{ "answers": { "f_name": "Ada", "f_age": 36, "f_pref": ["email"] }, "lastPageIndex": 0 }
```

FastAPI `detail` error mapping (string | `[{msg}]` | `{code,...}`) is handled in
`core-network`; the ViewModel only receives a typed `ApiResult.Failure(AppError)`
and maps it to `Error`/`SubmitState.Failed`.

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
- No credentials handled here; the cookie + `X-CSRF-Token` session is managed by
  the `core-network` persistent cookie jar. The ViewModel never reads cookies.
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
