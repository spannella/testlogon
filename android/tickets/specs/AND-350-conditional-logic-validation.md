---
id: AND-350
title: Conditional logic / validation
milestone: M7
epic: E45
priority: P2
size: L
status: reviewed
reviewed_on: 2026-06-06
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
  `frontend/src/api/types.ts`, `frontend/src/pages/questionnaires/QuestionnaireRespondentPage.tsx`.
  **Correction (review):** the web respondent runtime does **not** implement conditional
  visibility at all — it renders every question in the current section unconditionally and has
  no `visible_when` evaluation. The web *builder*'s rule grammar
  (`frontend/src/pages/questionnaires/validationRules.ts`) is purely a **validation** grammar
  (`rule_type` ∈ {`required_if`,`min`,`max`,`min_answered`,`mutually_exclusive`,
  `requires_if_answered`} with `config_json`), with no branching/visibility concept. The
  `Condition`/`Op` visibility predicate grammar below (§4.1) is therefore an **Android-specific
  design** not corroborated by any web contract; treat its exact JSON shape as an unverified
  assumption (R1) to be confirmed against a real published sample before implementation.
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

FR-7. **Form-level rules.** Cross-field/group rules (e.g. "at least one of X/Y") are enforced
server-side. **Correction (review):** the web respondent runtime does **not** send
`group_rules`/`form_rules` from the client — its validate/submit body is only
`{answers_by_question_id, final_submit}` (see `QuestionnaireRespondentPage.tsx`); the server
derives these rules from the published version. The Android client should likewise **omit /
send empty** `group_rules`/`form_rules` for the respondent flow (this resolves R3). Group- and
form-scoped issues come back in the same `errors` map keyed under the **`group:` and `form:`
prefixes** (e.g. `errors["form:<rule>"]`, `errors["group:<id>"]`), per the web runtime, and are
displayed in a form-level error banner; question-scoped issues are keyed by bare question id.

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

Both take `QuestionnaireValidationRequest`. Verified against OpenAPI
`components.schemas.QuestionnaireValidationRequest`: all fields optional except none are
`required`; `contract_version` is a `const`/default `"2026-03-validation-v1"`;
`answers_by_question_id` is a free-form object (`additionalProperties: true`); `group_rules` /
`form_rules` are arrays of free-form objects; `final_submit` defaults `false`. **Correction
(review):** the web respondent client sends **only** `{answers_by_question_id, final_submit}`
and omits `group_rules`/`form_rules` (server derives them — see FR-7/R3); the Android client
should do the same. Example respondent payload:
```json
{
  "answers_by_question_id": { "q_age": 40, "q_email": "a@b.com" },
  "final_submit": false
}
```
(`contract_version` may be sent explicitly to pin the contract, but defaults server-side.)
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
`submit` returns `SessionSubmitEnvelope` (200) on success. Verified against OpenAPI: the
envelope is `{ "session": object, "result": QuestionnaireValidationResponse }` (both required) —
i.e. `submit` runs server-side validation itself and echoes the resulting
`QuestionnaireValidationResponse` under `result`. **This resolves R5:** submit does not require a
prior `final_submit=true` validate call; the client may call `submit` directly and read
`result.is_valid`/`result.can_submit`/`result.has_blocking_form_error`/`result.errors` to surface
issues on a rejected submit. Both endpoints return `422` with `HTTPValidationError` on
transport-schema errors — map via the existing `detail` mapper (AND-015): `detail` may be
`string | [{msg}] | {code,...}` (verified against `normalizeErrorDetail` in
`frontend/src/api/client.ts`).

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

- **R1 — Rule predicate shape.** **CONFIRMED UNVERIFIABLE (review).** `config_json` and
  `schema_json` are typed `Record<string, unknown>` in `frontend/src/api/types.ts` and
  `additionalProperties: true` in OpenAPI — fully opaque. Worse, the **web respondent runtime
  implements no visibility at all** (it renders every question), so there is no `visible_when`
  contract to mirror; the `Condition`/`Op` grammar in §4.1 is an Android-only invention.
  *Mitigation:* lenient adapter + fail-open to visible; the server stays authoritative for
  acceptance. **Still open:** finalize the predicate grammar (op names, value encoding) against a
  real published sample / backend owner before implementation; this is a hard prerequisite.
- **R2 — Client/server rule drift.** Client-mirrored validation may diverge from server.
  *Mitigation:* server is authoritative; client only gates on `can_submit`. Accept minor
  inline-message differences.
- **R3 — `group_rules`/`form_rules` provenance.** **RESOLVED (review).** The web respondent
  runtime (`QuestionnaireRespondentPage.tsx`) sends only `{answers_by_question_id, final_submit}`
  and omits these arrays; the server derives group/form rules from the published version. The
  Android respondent client should likewise send them empty/omitted. (Note: the web *builder*
  does populate them via `validationRules.ts: toBackendRulePayload`, but that is the
  authoring/draft path, which is out of scope here.)
- **R4 — Validate chattiness on flaky dev host.** Debounced live validate could thrash a slow
  backend. *Mitigation:* 400 ms debounce + `mapLatest`; consider validate-on-blur-only fallback
  if latency is high. **Open:** acceptable validate cadence.
- **R5 — Submit idempotency.** **RESOLVED (review).** `SessionSubmitEnvelope` embeds a
  `result: QuestionnaireValidationResponse`, so `submit` performs its own server-side validation
  and does not require a prior `final_submit=true` validate. Calling `submit` directly and reading
  `result.*` is correct; `validate` remains for live UX. (Idempotency of repeated submits is still
  unverifiable from the spec — keep the no-auto-retry policy in §7.)

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

## 16. Citations & Assumption Audit

Each key technical claim with its verdict and exact source pointer.

1. **Validate endpoint =
   `POST /questionnaires/published/{published_slug}/sessions/{response_session_id}/validate`,
   request `QuestionnaireValidationRequest`, response 200 `QuestionnaireValidationResponse`.**
   VERIFIED — OpenAPI `POST /questionnaires/published/{published_slug}/sessions/{response_session_id}/validate`
   (index line 553); frontend `src/api/endpoints/questionnaires.ts: validatePublishedResponseSession`.
2. **Submit endpoint =
   `POST .../sessions/{response_session_id}/submit`, request `QuestionnaireValidationRequest`,
   response 200 `SessionSubmitEnvelope`.** VERIFIED — OpenAPI index line 552; frontend
   `src/api/endpoints/questionnaires.ts: submitPublishedResponseSession`.
3. **`QuestionnaireValidationRequest` fields = `contract_version`(const `2026-03-validation-v1`),
   `answers_by_question_id`(object), `group_rules`(array), `form_rules`(array),
   `final_submit`(bool, default false).** VERIFIED — OpenAPI
   `components.schemas.QuestionnaireValidationRequest`.
4. **`QuestionnaireValidationResponse` fields = `is_valid`, `can_submit`,
   `has_blocking_form_error`, `errors` (all required), plus `contract_version`; `errors` is
   `Map<String, List<ValidationIssue>>`.** VERIFIED — OpenAPI
   `components.schemas.QuestionnaireValidationResponse`.
5. **`ValidationIssue` = `code`(req str), `message`(req str), `blocking`(nullable bool),
   `rule_id`(nullable str).** VERIFIED — OpenAPI `components.schemas.ValidationIssue`. The
   `ValidationIssueDto` (nullable `blocking`/`rule_id`) is correct.
6. **`SessionSubmitEnvelope` = `{ session: object, result: QuestionnaireValidationResponse }`
   (both required); submit performs its own validation and echoes `result`.** VERIFIED (and
   CORRECTED into §5/R5) — OpenAPI `components.schemas.SessionSubmitEnvelope`; frontend
   `submitPublishedResponseSession` return type `{ session; result }`.
7. **Auth = cookie session + `ui_csrf` cookie echoed as `X-CSRF-Token`; credentials included on
   every request.** VERIFIED — `src/api/client.ts` (`getCookie("ui_csrf")` →
   `headers.set("X-CSRF-Token", csrf)`; `credentials: "include"`).
8. **401 handling = single retry via `POST /ui/session/refresh` then replay.** VERIFIED —
   `src/api/client.ts` (`withApiBase("/ui/session/refresh")`, refresh-once-then-retry on 401).
9. **422 `detail` may be `string | [{msg}] | {code,...}` and is normalized.** VERIFIED —
   `src/api/client.ts: normalizeErrorDetail` (handles string, array of `{msg}`/string, object
   with `code` or `msg`).
10. **Respondent validate/submit body sends only `{answers_by_question_id, final_submit}` and
    omits `group_rules`/`form_rules` (server derives them).** VERIFIED (and CORRECTED into
    §3 FR-7, §5, R3) — `src/pages/questionnaires/QuestionnaireRespondentPage.tsx`
    (`validateMutation`/`submitMutation` bodies).
11. **Submit gating keys off `can_submit` from the latest validate.** VERIFIED — respondent page
    `hasBlocking = !(validationResult.can_submit)`, Submit `disabled={hasBlocking || pending}`.
    Note: web does NOT also gate on staleness/unreached-server; AND-350's stricter gate
    (FR-6/FR-8: Stale and Failed → disabled) is an Android enhancement (see Open assumptions).
12. **Group/form-scoped issues are returned in the same `errors` map under `group:`/`form:`
    prefixes; question issues keyed by bare question id.** VERIFIED (and CORRECTED into FR-7) —
    respondent page `Object.entries(errorMap).filter(([key]) => key.startsWith("group:") ||
    key.startsWith("form:"))`.
13. **Form-level error banner uses an assertive live region; field errors use a polite one.**
    VERIFIED — respondent page error summary `role="alert" aria-live="assertive"`; field error
    `role="status" aria-live="polite"`. Spec §9 (banner Assertive) is correct.
14. **`visible_when` predicate grammar (`Condition`/`Op` in §4.1) matches the web respondent
    runtime.** CORRECTED → the web respondent runtime implements **no** conditional visibility
    (renders all questions); the web builder grammar
    (`src/pages/questionnaires/validationRules.ts`) is validation-only (`rule_type` enum, no
    branching). The §4.1 grammar is an Android-specific design, NOT a mirrored web contract.
    SOURCE — `QuestionnaireRespondentPage.tsx` (no visibility), `validationRules.ts`.
15. **Published question types.** VERIFIED — `src/api/types.ts: QuestionnaireQuestionType` =
    `text | select | multiselect | radio | slider | date | time | timezone | address`. (Spec's
    `FieldType`/`AnswerValue` union is owned by AND-347; the spec correctly defers to it. Note
    there is no dedicated `number`/`scale`/`email` type — numeric validation maps to `slider`
    and email/regex is `text` + `pattern`; flagged as assumption.)
16. **Start-session returns `response_session_id` inside the `session` object.** VERIFIED —
    `startPublishedResponseSession` returns `{ session }`; respondent page reads
    `res.session.response_session_id`. (Context for the `{sid}` path param; owned by AND-346.)
17. **Web debounce cadence.** The web respondent debounces validate at **350 ms** and autosave
    at **500 ms** (`QuestionnaireRespondentPage.tsx: queueSaveAndValidate`). The spec's 400 ms
    (§4.4) is an Android design choice, not the web value — UNVERIFIED-assumption as a
    requirement (acceptable; R4).
18. **Jetpack Compose `AnimatedVisibility` / M3 `supportingText`/error state / `liveRegion` /
    `stateDescription` / `semantics{error()}` for the UI (§4.5, §9).** UNVERIFIED-assumption
    (framework ref) — Android framework APIs, not derivable from backend/web sources. See
    Compose docs: https://developer.android.com/jetpack/compose/animation/composables-modifiers#animatedvisibility
    and accessibility semantics: https://developer.android.com/jetpack/compose/accessibility .
19. **Retrofit + Moshi transport, OkHttp cookie jar + refresh authenticator (§2, §5).**
    UNVERIFIED-assumption (framework ref) — Android stack choice; consistent with the web cookie/
    CSRF contract (claims 7–8) but the specific libraries are an Android decision.
    Refs: https://square.github.io/retrofit/ , https://square.github.io/okhttp/recipes/#handling-authentication .

### Corrections made

- **C1 (§2 Web reference):** Removed the false claim "rule predicate semantics match the web
  respondent runtime." The web respondent has no visibility logic; the builder grammar is
  validation-only. (Claim 14.)
- **C2 (§3 FR-7, §5, §13 R3):** The respondent client sends only
  `{answers_by_question_id, final_submit}`; `group_rules`/`form_rules` are omitted and derived
  server-side, not "passed through" by the client. (Claim 10.) R3 marked RESOLVED.
- **C3 (§3 FR-7):** Group/form issues are returned in the `errors` map under `group:`/`form:`
  prefixes, not as a separate untyped/unbound list. (Claim 12.)
- **C4 (§5, §13 R5):** Documented that `SessionSubmitEnvelope` embeds
  `result: QuestionnaireValidationResponse`, so `submit` self-validates; R5 marked RESOLVED.
- **C5 (§5):** Replaced the example request showing populated `group_rules`/`form_rules` with the
  real respondent payload; added verified field-level notes from the OpenAPI schema.
- **C6 (§13 R1):** Reframed R1 — the `visible_when` shape is not merely unpinned in OpenAPI; it
  has no web contract at all and remains a hard prerequisite to confirm before build.

### Open assumptions

- **OA1 — `visible_when` predicate grammar (§4.1).** Unverifiable: `config_json`/`schema_json`
  are opaque (`Record<string, unknown>` / `additionalProperties: true`) and the web respondent
  has no visibility code. Why: no source defines the JSON; must obtain a real published sample or
  backend confirmation. (R1.)
- **OA2 — Stricter submit gating on Stale/Failed (FR-6/FR-8/AC-4).** Beyond observed web
  behavior (web enables Submit until a validate returns `can_submit=false`; it does not block on
  "never validated" or "server unreachable"). Why: an intentional Android UX hardening with no
  web precedent — confirm it is acceptable product behavior.
- **OA3 — Shadow map for hidden-field values (FR-2/§6).** No web precedent (web has no hidden
  fields). Why: design depends on OA1's visibility model existing at all.
- **OA4 — 400 ms validate debounce (§4.4).** Web uses 350 ms validate / 500 ms save. Why: the
  exact acceptable cadence on the flaky dev host is unconfirmed (R4).
- **OA5 — Numeric/email/scale validation mapping.** No dedicated `number`/`email`/`scale`
  question type exists (claim 15); mapping `min`/`max` to `slider` and regex/email to
  `text`+`pattern` is assumed. Why: type union does not enumerate these; confirm config_json keys.
- **OA6 — Android framework choices** (Compose `AnimatedVisibility`, Retrofit/Moshi/OkHttp,
  refresh authenticator). Framework refs only (claims 18–19); not backend-derivable.

## 17. Test Plan

Test target legend: **JVM** = local JVM/Robolectric unit (no device); **MWS** =
MockWebServer contract; **EMU** = headless emulator AVD `test35` (x86_64, API 35);
**DEV** = physical Samsung Galaxy A15 5G (SM-A156U, R5CX821TA9R, arm64-v8a, API 34).
Compose-UI/instrumented cases run on EMU unless a physical-device reason is noted.

- **TC-AND-350-01 — Visibility toggle happy path.** Type: Compose-UI (instrumented).
  Target: EMU. Preconditions: schema with question `q_child` carrying a `visible_when` predicate
  referencing controlling `q_ctrl`; renderer wired to `VisibilityResolver`. Steps: (1) render
  form with `q_ctrl` unanswered → assert `q_child` `assertDoesNotExist`; (2) set `q_ctrl` to the
  value satisfying the predicate; (3) recompose. Expected: `q_child` `assertExists` within one
  recomposition (AnimatedVisibility shown), scroll preserved. Traces: AC-1.
- **TC-AND-350-02 — Transitive cascade + cycle determinism.** Type: unit (JVM). Target: JVM.
  Preconditions: `VisibilityResolver` over a schema where `q_a`→controls→`q_b`→controls→`q_c`,
  plus a synthetic cycle `q_x↔q_y`. Steps: hide `q_a`; resolve snapshot; separately resolve the
  cyclic schema. Expected: `q_b`,`q_c` absent from `visibleQuestionIds` (transitive); cyclic
  nodes resolve deterministically to visible by id order, no infinite loop. Traces: AC-1.
- **TC-AND-350-03 — Hidden-field exclusion + shadow restore.** Type: unit (JVM) + Compose-UI.
  Target: JVM (payload) / EMU (UI restore). Preconditions: `q_child` answered, then hidden by
  toggling `q_ctrl`. Steps: (1) build validate/submit payload → assert `answers_by_question_id`
  omits `q_child`; (2) in UI, toggle `q_ctrl` back so `q_child` re-shows. Expected: payload
  excludes hidden id; on re-show the prior `q_child` value is restored from the shadow map.
  Traces: AC-2.
- **TC-AND-350-04 — `ConditionEvaluator` op/coercion table.** Type: unit (JVM). Target: JVM.
  Preconditions: pure evaluator. Steps: table-driven over every `Op`
  (EQ/NEQ/IN/NOT_IN/GT/GTE/LT/LTE/CONTAINS/IS_ANSWERED/IS_EMPTY), each `AnswerValue` kind,
  mismatched kinds, and `All`/`Any`/`Not`/`Always`; include an unknown op string. Expected:
  mismatched kinds → false (except IS_ANSWERED/IS_EMPTY); unknown op parses to
  `Condition.Always` (fail-open visible). Traces: AC-1, AC-3.
- **TC-AND-350-05 — Inline local validators per field type.** Type: unit (JVM). Target: JVM.
  Preconditions: `LocalValidators.forQuestion` for `text`(pattern/length), `slider`(min/max),
  `select`/`multiselect`(choice membership), `date`(range), required. Steps: feed valid and
  invalid `AnswerValue`s. Expected: correct `FieldIssue` `code`s for invalid inputs, empty list
  for valid; all issues non-blocking for submit-gating. Traces: AC-3.
- **TC-AND-350-06 — Inline error shows on blur (UI).** Type: Compose-UI (instrumented).
  Target: EMU. Preconditions: a required `text` field with a `pattern`. Steps: enter invalid
  value, trigger blur/commit. Expected: field-level error rendered via M3 error state with the
  validator message; `aria`/semantics error set on the input. Traces: AC-3.
- **TC-AND-350-07 — Debounce + mapLatest collapse.** Type: unit (JVM, Turbine + runTest).
  Target: JVM. Preconditions: ViewModel with debounced (400 ms) validate via SharedFlow +
  `mapLatest`. Steps: emit N rapid `onAnswerChanged`; advance virtual time. Expected: exactly one
  `validate` call (latest answers); each change first sets `ValidationStatus.Stale` and
  `canSubmit=false`; a superseded in-flight result is dropped. Traces: AC-4.
- **TC-AND-350-08 — Server reconciliation merge & de-dupe.** Type: unit (JVM) + contract (MWS).
  Target: JVM / MWS. Preconditions: local issue `{code:"required"}` on `q1`; server returns
  `errors:{ "q1":[{code:"required",...},{code:"invalid_format",blocking:true}] }`. Steps: run
  validate, merge. Expected: `q1` shows union de-duplicated by `code` (one `required`, one
  `invalid_format`); server issue wins on display; blocking flag honored. Traces: AC-5.
- **TC-AND-350-09 — Validate 200 happy + blocking gating.** Type: contract (MWS).
  Target: MWS. Preconditions: MockWebServer scripted. Steps: (a) enqueue
  `{is_valid:true,can_submit:true,has_blocking_form_error:false,errors:{}}` → assert
  `canSubmit=true`; (b) enqueue `can_submit:false` with `errors:{"q_email":[...]}` → assert
  Submit disabled and inline error surfaced. Assert request body is exactly
  `{answers_by_question_id, final_submit:false}` (no `group_rules`/`form_rules`). Traces: AC-4,
  AC-5.
- **TC-AND-350-10 — Group/form-scoped issues → banner.** Type: contract (MWS) + Compose-UI.
  Target: MWS / EMU. Preconditions: validate returns
  `errors:{ "form:mutually_exclusive":[{code,message,blocking:true}], "group:g1":[...] }`. Steps:
  process response; render. Expected: those entries route to the form-level banner (assertive
  live region), not to a question; `can_submit=false` blocks submit. Traces: AC-4, AC-5.
- **TC-AND-350-11 — 422 detail shapes mapped.** Type: contract (MWS). Target: MWS.
  Preconditions: three scripted 422 bodies — `detail` as string, as `[{msg,loc}]`, and as
  `{code,...}`. Steps: call validate for each. Expected: each maps via AND-015 to a user message;
  `loc`-bound items with a question id route inline, else to the banner; `ApiResult` is an error.
  Traces: AC-5.
- **TC-AND-350-12 — Flaky dev-host / offline resilience (no auto-retry).** Type: contract (MWS).
  Target: MWS. Preconditions: MockWebServer set to `NO_RESPONSE`/socket-timeout (~20s), then a
  5xx. Steps: trigger validate. Expected: `ValidationStatus.Failed`; local inline feedback kept;
  Submit stays **disabled**; non-blocking "couldn't confirm" banner + Retry shown; **no automatic
  retry** of the POST (assert exactly one request); user-initiated Retry issues a new request.
  Traces: AC-4, AC-6.
- **TC-AND-350-13 — Submit timeout no double-submit + 401 refresh.** Type: contract (MWS).
  Target: MWS. Preconditions: (a) submit times out → assert blocking Retry/Cancel dialog, no
  auto-retry, single request; (b) validate returns 401 then refresh 200 then replay 200 → assert
  one `POST /ui/session/refresh` and a single replay with the original body and `X-CSRF-Token`
  header present. Traces: AC-4, AC-6.
- **TC-AND-350-14 — Blocked-submit a11y: scroll/focus + announce + disabled reason.**
  Type: Compose-UI (instrumented). Target: EMU. Preconditions: validate returns `can_submit=false`
  with a field error below the fold and a form-level issue. Steps: attempt submit. Expected:
  auto-scroll to and focus the first errored visible field (focus order = visual order after
  visibility filtering); form banner announced via assertive live region; disabled Submit exposes
  `stateDescription` ("Resolve N errors to submit"). Traces: AC-3, AC-4, AC-6.
- **TC-AND-350-15 — PII redaction in telemetry/logs.** Type: unit (JVM). Target: JVM.
  Preconditions: capture emitted telemetry events and logs during a validate/submit cycle with
  PII-bearing answers and a server `message` echoing input. Steps: run the cycle. Expected: events
  contain only counts/ids/`code`s (`qform_validate_result {is_valid,can_submit,...}`); no answer
  values and no server `message` text in non-debug logs; release logs counts only. Traces: AC-5
  (security/privacy support for surfacing issues).
- **TC-AND-350-16 — ABI/API parity smoke on physical device.** Type: instrumented/e2e.
  Target: **DEV (physical, required)**. Preconditions: app installed on SM-A156U (arm64-v8a,
  API 34). Rationale: validates the full visibility+validate+submit flow on real arm64/API-34
  hardware vs the x86_64/API-35 emulator (Moshi codegen, coroutine timing, debounce under real
  network). Steps: start session, toggle a controlling field, fix a field error, submit. Expected:
  identical functional behavior to EMU (visibility toggles, gating, submit success); no
  ABI/API-specific crash or codegen issue. Traces: AC-1, AC-2, AC-3, AC-4.

### Coverage matrix

| AC | Description | Covered by |
| --- | --- | --- |
| AC-1 | Show/hide + transitive cascade within one recomposition | TC-01, TC-02, TC-04, TC-16 |
| AC-2 | Hidden fields excluded from payloads; shadow restore on re-show | TC-03, TC-16 |
| AC-3 | Inline validation on blur (required/length/range/regex/choice/date) | TC-04, TC-05, TC-06, TC-14, TC-16 |
| AC-4 | Submit disabled on `can_submit=false`/Stale/unreached; forced submit aborts | TC-07, TC-09, TC-10, TC-12, TC-13, TC-14, TC-16 |
| AC-5 | Server `errors` (inline + banner) merged & de-duped by `code` | TC-08, TC-09, TC-10, TC-11, TC-15 |
| AC-6 | Validate timeout/offline: usable form, Submit disabled, retry, no auto-retry | TC-12, TC-13, TC-14 |
