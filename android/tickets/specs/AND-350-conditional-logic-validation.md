---
id: AND-350
title: Conditional logic / validation
milestone: M7
epic: E45
priority: P2
size: L
status: draft
depends_on: [AND-347]
blocks: []
---

# AND-350 — Conditional logic / validation

## 1. Overview & Goal

AND-350 adds **branching/visibility logic** and **answer validation** on top of the dynamic
form renderer delivered by AND-347 for the published-questionnaire respondent flow in the
TestLogon native Android app. Where AND-347 renders every schema field statically and captures
input, AND-350 makes the form *reactive*: fields, groups, and whole sections show or hide based
on the respondent's current answers, and the renderer prevents an invalid or incomplete
response from being submitted.

The ticket has two tightly-coupled responsibilities:

1. **Conditional visibility** — evaluate per-field/per-group/per-section visibility rules
   (declared in the published schema as `config_json.visible_when` predicates) against the live
   answer map, so hidden fields are removed from the rendered tree and excluded from
   submission/validation.
2. **Validation** — enforce client-side constraints (required, type, length, range, regex,
   choice membership) for *fast inline feedback*, and reconcile against the **authoritative
   server validation** (`POST .../validate`) before allowing submit. Submit is blocked while
   `can_submit == false` or any blocking issue exists.

The guiding principle: the **client mirrors** the server's rule semantics for responsive UX,
but the **server is authoritative**. The client never lets a submit through that the server
would reject, and it always surfaces server-returned issues even for rules the client did not
locally model. Out of scope: authoring/editing rules (web-only draft endpoints), file-upload
field validation internals (owned by the upload field in AND-347), and PDF generation.

## 2. Context & References

- **Module:** `feature-questionnaire` (`com.testlogon.android.feature.questionnaire`),
  specifically the `render` and `validation` sub-packages. Depends on `core-model`
  (schema/answer/DTOs), `core-network` (`ApiResult<T>`, `QuestionnaireApi` from AND-346),
  `core-data` (`QuestionnaireRepository`), `core-ui` (input composables AND-020, state
  composables AND-021).
- **Upstream dependency — AND-347 (Dynamic form renderer):** owns the schema model
  (`FormSchema`, `FormSection`, `FormQuestion`, `FieldType`), the per-type field composables,
  and the `AnswerMap` capture surface. AND-350 consumes those types and inserts a visibility
  filter + validation gate around them; it does **not** re-implement field rendering.
- **AND-346 (Questionnaire API + DTOs):** owns `questionnaires.ts`-equivalent Retrofit
  `QuestionnaireApi` and the published-session DTOs. AND-350 adds the `validate` and `submit`
  operations and the validation request/response DTOs to that interface.
- **Web reference:** `frontend/src/api/endpoints/questionnaires.ts`,
  `frontend/src/api/types.ts`. Rule predicate semantics match the web respondent runtime.
- **Backend (authoritative):** FastAPI, `/openapi.json` on dev host
  `http://18.222.237.167:8000` (plaintext, unreliable — design for ~20s timeouts and
  offline/stale states). Relevant schemas: `QuestionnaireValidationRequest`,
  `QuestionnaireValidationResponse`, `ValidationIssue`, `PublishedQuestionnaireEnvelope`.
- **Auth:** cookie-based session (AND-011/012/013); all calls ride the persistent cookie jar
  and echo the `ui_csrf` cookie as `X-CSRF-Token`; 401 → single `POST /ui/session/refresh`
  then retry, handled transparently by the OkHttp stack.

## 3. Functional Requirements

FR-1. **Visibility evaluation.** Given the current `AnswerMap`, the renderer computes the set
of visible questions/groups/sections. A field is visible iff it has no `visible_when` predicate
or its predicate evaluates `true`. Visibility is recomputed synchronously on every answer
change before the next recomposition.

FR-2. **Hidden-field exclusion.** Hidden questions are (a) not rendered, (b) excluded from
`answers_by_question_id` sent to validate/submit, and (c) not subject to client validation.
Their captured value is retained in a *shadow* map so that re-showing a field restores the
prior value (no data loss when toggling a controlling field back and forth within the session).

FR-3. **Cascading.** Hiding a controlling field that itself controls others cascades: dependent
fields become hidden transitively. Cycles are detected and broken deterministically (see TD-4).

FR-4. **Inline client validation.** On blur / value-commit of a field, evaluate that field's
constraints and show a field-level error immediately. Constraints supported client-side:
`required`, `min_length`/`max_length`, `min`/`max` (numeric & scale), `pattern` (regex),
`choice membership`, and `date range`.

FR-5. **Server validation reconciliation.** Before enabling submit, and debounced after
material answer changes, call `POST .../validate` with `final_submit=false`. Merge returned
`errors` (keyed by question id) into UI state. Server issues always win on display; a question
shows the union of local + server issues, de-duplicated by `code`.

FR-6. **Submit gating.** The Submit action is enabled iff the latest server validation returned
`can_submit == true`. Pressing Submit triggers a final `validate` with `final_submit=true` (or
goes straight to `submit`, see API §5); if the server reports `is_valid == false` or
`has_blocking_form_error == true`, submission is aborted and issues are surfaced (form-level
issues via a banner, field-level via inline errors with auto-scroll to first error).

FR-7. **Form-level rules.** `group_rules` and `form_rules` (cross-field rules, e.g. "at least
one of X/Y") are passed through to the server and their `ValidationIssue`s (which may have no
`rule_id`-less or form-scoped binding) are displayed in a form-level error banner.

FR-8. **Resilience.** If `validate` fails (timeout/offline/5xx), the client falls back to its
local validation result for inline feedback but keeps Submit **disabled** with a non-blocking
"couldn't reach the server to confirm" message and a retry affordance. The client never enables
submit purely on local validation.

## 4. Technical Design

### 4.1 Rule model (`core-model`)

Visibility predicates are parsed from each question's `config_json.visible_when`. Model as a
sealed type so evaluation is total and testable:

```kotlin
sealed interface Condition {
  data class Compare(val questionId: String, val op: Op, val value: AnswerValue) : Condition
  data class All(val of: List<Condition>) : Condition          // AND
  data class Any(val of: List<Condition>) : Condition          // OR
  data class Not(val of: Condition) : Condition
  data object Always : Condition
}

enum class Op { EQ, NEQ, IN, NOT_IN, GT, GTE, LT, LTE, CONTAINS, IS_ANSWERED, IS_EMPTY }

@JsonClass(generateAdapter = false)
data class VisibilityRule(val condition: Condition)   // custom Moshi adapter, lenient
```

A custom `JsonAdapter<Condition>` (registered in the questionnaire Moshi instance) tolerates
unknown ops/keys by mapping them to `Condition.Always` (fail-open to *visible*) and logging a
redacted warning, so a schema using a server rule the client doesn't model never hides content
the respondent should see (server validation still enforces correctness).

### 4.2 Evaluator (pure, `validation` package)

```kotlin
object ConditionEvaluator {
  fun evaluate(condition: Condition, answers: AnswerMap): Boolean
}

class VisibilityResolver(private val schema: FormSchema) {
  /** Returns ids of questions/groups/sections that are currently visible. */
  fun resolve(answers: AnswerMap): VisibilitySnapshot
}

data class VisibilitySnapshot(
  val visibleQuestionIds: Set<String>,
  val visibleSectionIds: Set<String>,
)
```

`AnswerValue` is the AND-347 union (`StringVal`, `NumberVal`, `BoolVal`, `ListVal`, `DateVal`,
`Empty`). `Op` comparisons coerce by value kind; mismatched kinds evaluate to `false` (except
`IS_ANSWERED`/`IS_EMPTY`). Pure functions, no Android/coroutine deps → JVM unit-testable.

### 4.3 Validators (pure)

```kotlin
sealed interface FieldIssue { val code: String; val message: UiText; val blocking: Boolean }

interface FieldValidator { fun validate(q: FormQuestion, value: AnswerValue): List<FieldIssue> }

object LocalValidators {        // composed per FieldType from config_json
  fun forQuestion(q: FormQuestion): FieldValidator
}
```

Local validators are advisory; their issues are non-blocking for submit-gating purposes (only
the server's `can_submit`/`blocking` gate submit) but block nothing besides showing inline
errors and discouraging submit before the server round-trip.

### 4.4 ViewModel integration

The existing `QuestionnaireFormViewModel` (AND-347) gains validation/visibility state. New
state surface:

```kotlin
data class FormUiState(
  val schema: FormSchema,
  val answers: AnswerMap,
  val visible: VisibilitySnapshot,
  val fieldIssues: Map<String, List<FieldIssue>>,   // local + server merged
  val formIssues: List<FieldIssue>,                 // form/group scoped
  val validation: ValidationStatus,                 // Idle/Validating/Confirmed/Stale/Failed
  val canSubmit: Boolean,
  val submitting: Boolean,
) : UiState

sealed interface ValidationStatus {
  data object Idle : ValidationStatus
  data object Validating : ValidationStatus
  data class Confirmed(val canSubmit: Boolean) : ValidationStatus
  data object Stale : ValidationStatus            // answers changed since last server check
  data class Failed(val reason: UiText) : ValidationStatus  // could not reach server
}

class QuestionnaireFormViewModel @Inject constructor(
  private val repo: QuestionnaireRepository,
  private val resolver: VisibilityResolver,
) : ViewModel() {
  fun onAnswerChanged(questionId: String, value: AnswerValue)   // recompute visibility, mark Stale, schedule validate
  fun onFieldBlur(questionId: String)                           // run local validators inline
  fun submit()                                                  // final validate + submit
}
```

`onAnswerChanged` recomputes visibility synchronously, marks `validation = Stale`, sets
`canSubmit = false`, then schedules a **debounced (400 ms)** server `validate` via a
`MutableSharedFlow<Unit>` collected with `.debounce(400).mapLatest { runValidate() }` so rapid
typing collapses to one in-flight request (latest wins, prior cancelled).

### 4.5 Compose wiring

`FormFieldList` (AND-347) iterates only `state.visible.visibleQuestionIds`; show/hide uses
`AnimatedVisibility` keyed by question id so re-showing animates and preserves scroll. Each
field composable receives `issues: List<FieldIssue>` and renders the first blocking (else
first) message via the M3 `supportingText`/error state from AND-020. A `FormErrorBanner`
(state composable, AND-021) renders `state.formIssues`. The Submit button is
`enabled = state.canSubmit && !state.submitting`.

## 5. API Contract

Two operations are added to `QuestionnaireApi` (AND-346). Both ride the cookie session +
`X-CSRF-Token`.

**Validate (idempotent-ish POST; called debounced for live feedback):**
```
POST /questionnaires/published/{published_slug}/sessions/{response_session_id}/validate
```
**Submit (final, non-idempotent):**
```
POST /questionnaires/published/{published_slug}/sessions/{response_session_id}/submit
```

Both take `QuestionnaireValidationRequest`:
```json
{
  "contract_version": "2026-03-validation-v1",
  "answers_by_question_id": { "q_age": 40, "q_email": "a@b.com" },
  "group_rules": [ { "...": "opaque" } ],
  "form_rules":  [ { "...": "opaque" } ],
  "final_submit": false
}
```
`validate` returns `QuestionnaireValidationResponse`:
```json
{
  "contract_version": "2026-03-validation-v1",
  "is_valid": false,
  "can_submit": false,
  "has_blocking_form_error": false,
  "errors": {
    "q_email": [ { "code": "invalid_format", "message": "Enter a valid email",
                   "blocking": true, "rule_id": null } ]
  }
}
```
`submit` returns `SessionSubmitEnvelope` (200) on success. Both return `422` with
`HTTPValidationError` on transport-schema errors — map via the existing `detail` mapper
(AND-015): `detail` may be `string | [{msg}] | {code,...}`.

Retrofit + Moshi DTOs (in `core-network`, mapped to domain in repo):
```kotlin
@JsonClass(generateAdapter = true)
data class ValidationRequestDto(
  @Json(name="contract_version") val contractVersion: String = "2026-03-validation-v1",
  @Json(name="answers_by_question_id") val answers: Map<String, Any?>,
  @Json(name="group_rules") val groupRules: List<Map<String, Any?>> = emptyList(),
  @Json(name="form_rules") val formRules: List<Map<String, Any?>> = emptyList(),
  @Json(name="final_submit") val finalSubmit: Boolean = false,
)

@JsonClass(generateAdapter = true)
data class ValidationResponseDto(
  @Json(name="is_valid") val isValid: Boolean,
  @Json(name="can_submit") val canSubmit: Boolean,
  @Json(name="has_blocking_form_error") val hasBlockingFormError: Boolean,
  val errors: Map<String, List<ValidationIssueDto>>,
)

@JsonClass(generateAdapter = true)
data class ValidationIssueDto(
  val code: String, val message: String,
  val blocking: Boolean? = null, @Json(name="rule_id") val ruleId: String? = null,
)

interface QuestionnaireApi {
  @POST("questionnaires/published/{slug}/sessions/{sid}/validate")
  suspend fun validate(@Path("slug") slug: String, @Path("sid") sid: String,
                       @Body body: ValidationRequestDto): Response<ValidationResponseDto>
  @POST("questionnaires/published/{slug}/sessions/{sid}/submit")
  suspend fun submit(@Path("slug") slug: String, @Path("sid") sid: String,
                     @Body body: ValidationRequestDto): Response<SessionSubmitEnvelopeDto>
}
```
Repository wraps both in `ApiResult<T>`:
```kotlin
suspend fun validate(slug: String, sid: String, req: ValidationRequest): ApiResult<ValidationResult>
suspend fun submit(slug: String, sid: String, req: ValidationRequest): ApiResult<SubmitResult>
```

## 6. Data & State Management

- **Answer map** is the single source of truth (owned by the ViewModel, persisted via AND-347's
  mechanism). AND-350 adds the **shadow map** (FR-2) holding values of currently-hidden fields,
  also persisted so a process-death/restore preserves toggled-off answers.
- **Submission payload** = `answers_by_question_id` filtered to `visible.visibleQuestionIds`
  only. Hidden answers from the shadow map are **never** sent.
- **No new Room entities.** Validation results are transient UI state, not cached to Room; the
  published schema itself is cached by AND-346/347. DataStore is unused here.
- **Staleness:** any answer mutation sets `ValidationStatus.Stale` and `canSubmit=false` until
  the next successful `validate`, guaranteeing the gate reflects current answers.
- **Concurrency:** `mapLatest` ensures only the most recent `validate` result is applied;
  late responses for superseded answer states are dropped.

## 7. Error Handling & Resilience

- **Timeout / offline / 5xx on `validate`** → `ValidationStatus.Failed`; keep local inline
  errors, keep Submit disabled, show non-blocking banner "Couldn't confirm with the server"
  + Retry. Per project policy, `validate` is treated as a non-idempotent POST for retry
  purposes: **no automatic backoff retry**; retry is user-initiated. (Only idempotent GETs get
  AND-016 auto-retry.)
- **Timeout / offline on `submit`** → surface a blocking dialog with Retry/Cancel; do **not**
  auto-retry (could double-submit). On ambiguous timeout, advise re-checking session status.
- **422 / FastAPI detail** → map via AND-015; field-bound `detail` items routed to the matching
  question id when `loc` includes a question id, else to the form banner.
- **401** → handled by the refresh authenticator (AND-013) transparently; if refresh fails, the
  session is invalid → emit a one-shot event to route to login (AND-025), preserving in-memory
  answers where possible.
- **Schema rules the client can't parse** → fail-open to visible + rely on server validation
  (TD-4); never hide content or silently enable submit.
- **Cycle in visibility graph** → broken deterministically by id order; affected nodes default
  to visible; logged once.

## 8. Security & Privacy

- All requests use the persistent cookie jar + `X-CSRF-Token` (AND-011/012); no tokens or
  answers logged in plaintext (see §10).
- **Answer values are user PII.** Never include answer values in telemetry, crash reports, or
  non-debug logs. Logs reference question ids and issue `code`s only.
- Client-side validation is **advisory only** and never a security boundary; the server is the
  authority for what is accepted (defense against tampering with the locally-evaluated gate).
- Hidden-field values held in the shadow map are kept in process memory / encrypted-at-rest via
  the same store AND-347 uses; they are excluded from submission to avoid leaking answers to
  branches the respondent did not complete.
- Dev host is plaintext HTTP — acceptable for dev flavor only; release flavor must target HTTPS
  hosts (host selection AND-014); no cleartext traffic in release config.

## 9. Accessibility & i18n

- Field errors set `Modifier.semantics { error(message) }` on the input and are announced via
  the M3 error state; the form banner uses `liveRegion = Assertive` so newly-surfaced blocking
  errors are read on submit attempt.
- On a blocked submit, auto-scroll to and request focus on the first errored visible field;
  focus order follows visual order after visibility filtering.
- Show/hide transitions must not trap focus: when a focused field is hidden, focus moves to the
  next visible field, not lost to the root.
- Disabled Submit exposes `stateDescription` explaining *why* (e.g., "Resolve N errors to
  submit") rather than a bare disabled state.
- All client-generated messages are `UiText` string resources (no concatenation);
  server `message` strings are displayed verbatim (already localized by backend) and not
  re-translated. RTL-safe via standard Compose layout.

## 10. Telemetry & Logging

- Events (no PII; redacted): `qform_validate_requested {slug, sid, answer_count, visible_count}`,
  `qform_validate_result {is_valid, can_submit, has_blocking_form_error, error_field_count}`,
  `qform_submit_attempt`, `qform_submit_result {ok, blocked_by:"field"|"form"|null}`,
  `qform_visibility_recompute {hidden_count, duration_ms}`.
- Log issue `code`s and question ids only; **never** answer values or `message` text containing
  echoed input. Use the redacted logger pattern from AND-052.
- Debug builds may log the evaluated `VisibilitySnapshot` ids; release builds log counts only.

## 11. Testing Strategy

**Unit (JVM, `core-testing`):**
- `ConditionEvaluatorTest` — table-driven across every `Op`, value-kind coercions, mismatched
  kinds → false, `IS_ANSWERED`/`IS_EMPTY`, `All`/`Any`/`Not`/`Always`, unknown op → Always.
- `VisibilityResolverTest` — single/transitive cascade, re-show restores shadow value, cycle
  detection determinism, hidden fields excluded from snapshot.
- `LocalValidatorsTest` — required/length/range/regex/choice/date per `FieldType`.
- ViewModel tests (Turbine + `runTest`): answer change → `Stale` + `canSubmit=false`; debounce
  collapses N rapid edits to 1 validate; `mapLatest` drops superseded results; server errors
  merge & de-dupe with local; `Failed` keeps submit disabled; submit gating on `can_submit`.
- Moshi adapter round-trip for request/response DTOs incl. `null` `blocking`/`rule_id`.

**Repository contract (MockWebServer, AND-046):** validate 200 happy/blocking, 422 detail
shapes (string/list/object) mapped, 401→refresh→retry success, timeout→`ApiResult` error;
submit 200 envelope + timeout no-auto-retry assertion.

**Compose UI (instrumented, AND-048 harness):** controlling choice toggles dependent field
visibility (assertDoesNotExist/assertExists); inline error appears on blur; Submit disabled
until `can_submit`; blocked submit auto-scrolls/focuses first error; form banner announced;
hidden field's prior value restored on re-show.

## 12. Dependencies & Sequencing

- **Depends on AND-347** (dynamic form renderer) — hard dependency; AND-350 extends its schema
  model, field composables, and answer-capture surface. Cannot start before AND-347's
  `FormSchema`/`FieldType`/`AnswerMap` are merged.
- **Transitively depends on AND-346** (questionnaire API + DTOs) for `QuestionnaireApi` and
  published-session DTOs; AND-350 adds `validate`/`submit` ops + validation DTOs to it.
- **Consumes** `core-network` `ApiResult` (AND-018), `detail` error mapping (AND-015), cookie
  jar/CSRF/refresh (AND-011/012/013), input composables (AND-020), state composables (AND-021).
- **Sequencing:** land DTOs + repo methods + pure evaluator/validators first (independently
  testable), then ViewModel integration, then Compose wiring + UI tests.
- **Blocks:** none recorded in backlog (no downstream ticket lists AND-350 as a dependency).

## 13. Risks & Open Questions

- **R1 — Rule predicate shape.** The published schema stores rules in opaque `config_json`
  (`additionalProperties: true`). The exact `visible_when` JSON shape isn't pinned in OpenAPI.
  *Mitigation:* lenient adapter + fail-open; confirm shape against
  `frontend/src/api/endpoints/questionnaires.ts` runtime and a real published sample before
  implementation. **Open:** finalize the predicate grammar (op names, value encoding).
- **R2 — Client/server rule drift.** Client-mirrored validation may diverge from server.
  *Mitigation:* server is authoritative; client only gates on `can_submit`. Accept minor
  inline-message differences.
- **R3 — `group_rules`/`form_rules` provenance.** Are these sent *by the client* (echoed from
  schema) or computed server-side from the published version? OpenAPI lists them as request
  fields. **Open:** confirm whether the client must populate them or send empty arrays and let
  the server derive from the published version.
- **R4 — Validate chattiness on flaky dev host.** Debounced live validate could thrash a slow
  backend. *Mitigation:* 400 ms debounce + `mapLatest`; consider validate-on-blur-only fallback
  if latency is high. **Open:** acceptable validate cadence.
- **R5 — Submit idempotency.** Whether `submit` requires a prior `final_submit=true` validate or
  performs validation itself. Current design calls `submit` directly and treats its 200/!ok as
  authoritative; `validate` is for live UX. **Open:** confirm with backend.

## 14. Acceptance Criteria

From the backlog ("Conditional fields show/hide; validation blocks invalid submit"):

- **AC-1 (show/hide):** Given a schema with a `visible_when` predicate, when the controlling
  answer makes the predicate true/false, the dependent field appears/disappears in the rendered
  form within one recomposition, and transitive dependents cascade. *(Compose UI test.)*
- **AC-2 (exclusion):** Hidden fields are absent from `answers_by_question_id` in both
  `validate` and `submit` payloads; toggling a controlling field back restores the previously
  entered value of a re-shown field. *(Unit + UI test.)*
- **AC-3 (inline validation):** Invalid input on a visible field shows a field-level error on
  blur for required/length/range/regex/choice/date constraints. *(Unit + UI test.)*
- **AC-4 (submit blocked):** Submit is disabled whenever the latest server `validate` returned
  `can_submit == false`, when answers are `Stale`, or when server validation could not be
  reached; an attempted/forced submit with `is_valid == false` or `has_blocking_form_error`
  is aborted and surfaces field + form issues. *(Repo + UI test.)*
- **AC-5 (server reconciliation):** Server-returned `errors` (keyed by question id) and
  form-level issues are displayed (inline + banner), merged with and de-duplicated against
  local issues by `code`. *(Unit + repo test.)*
- **AC-6 (resilience):** On `validate` timeout/offline, the form remains usable with local
  inline feedback, Submit stays disabled, and a retry affordance is shown; no auto-retry of
  the POST. *(Repo + UI test.)*

## 15. Definition of Done

- Pure evaluator, validators, and DTOs implemented in `core-model`/`core-network` with the
  signatures above; `ValidationRequestDto`/`ValidationResponseDto`/`ValidationIssueDto` Moshi
  round-trip tested.
- `validate` and `submit` added to `QuestionnaireApi` and `QuestionnaireRepository`, returning
  `ApiResult<T>`, wired through cookie/CSRF/refresh stack, with `detail` mapping.
- `QuestionnaireFormViewModel` extended with visibility + validation state, debounced server
  validate, staleness gating, and submit flow; one-shot login-redirect on session loss.
- Compose renderer filters by visibility with `AnimatedVisibility`, renders inline + banner
  issues, focus/scroll-to-first-error, accessible disabled-submit reason.
- Telemetry events emitted, redacted (no answer values/PII); release logs counts only.
- All AC tests green: unit (evaluator/validators/VM), repository contract (MockWebServer),
  instrumented Compose UI; suites run in CI (AND-050/051).
- No cleartext traffic in release flavor; ktlint/detekt clean; merged to `android-port`.
- Open questions R1/R3/R5 resolved or explicitly deferred with a tracked follow-up before
  release tagging.
