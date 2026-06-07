---
id: AND-352
title: Questionnaire tests
milestone: M7
epic: E45
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-351, AND-350, AND-347, AND-346]
blocks: [AND-349, AND-395]
---

# AND-352 — Questionnaire tests

## 1. Overview & Goal

AND-352 delivers the automated test suite that locks down the behaviour of the
questionnaire feature on the native Android port: the **dynamic form renderer**
(AND-347), the **questionnaire/respondent ViewModels and form state machine**
(AND-351), and the **conditional logic / validation** engine (AND-350), all of
which consume the DTOs and schema mapping from AND-346.

The ticket scope is "Renderer + validation tests" with the single acceptance
criterion "Pass." This spec interprets that literally and rigorously: produce a
deterministic, hermetic, offline test suite (JVM unit tests + Compose UI tests)
that exercises (a) every supported field type's render-and-capture path, (b) the
form state machine transitions, (c) the conditional visibility/branching rules,
and (d) client-side validation that blocks an invalid submit. The goal is a
green, non-flaky suite wired into CI that fails loudly if any questionnaire
behaviour regresses.

This is a **Test** ticket: it adds no production code paths and no new user-facing
behaviour. Where production behaviour gaps are discovered, they are filed back
against the owning feature ticket (AND-347/350/351), not fixed here.

## 2. Context & References

- **Module under test:** `feature-questionnaire` (depends on `core-model`,
  `core-data`, `core-network`, `core-ui`), namespace
  `com.testlogon.android.feature.questionnaire`.
- **Upstream tickets:**
  - AND-346 — Questionnaire API + DTOs (`QuestionnaireApi`, schema mapping).
  - AND-347 — Dynamic form renderer (`QuestionFieldRenderer`).
  - AND-350 — Conditional logic / validation (`ConditionEvaluator`, `Validator`).
  - AND-351 — Questionnaire ViewModels (`RespondentSessionViewModel`,
    form state machine).
- **Downstream consumers (blocked until green):** AND-348 (session save/resume),
  AND-349 (submit + PDF), AND-395 (public respond).
- **Test infrastructure:** `core-testing` provides `MainDispatcherRule`,
  `TestApiResultFactory`, fake `CookieJar`, and a shared `MockWebServer`
  bootstrap. Compose tests use `androidx.compose.ui.test.junit4`
  (`createComposeRule` for isolated component tests; Robolectric for JVM-side
  Compose where feasible to avoid an emulator on CI).
- **Backend reference:** FastAPI dev host `http://18.222.237.167:8000`,
  `/openapi.json`; published respondent endpoints under
  `/questionnaires/published/{published_slug}/sessions/*` **[CORRECTED:** the path
  parameter is `published_slug`, not `slug` — verified in `OpenAPI GET
  /questionnaires/published/{published_slug}` and the `sessions` ops]. The suite
  does **not** hit the live host — all network is faked via `MockWebServer` or
  stubbed `QuestionnaireApi`.
- **Web parity reference:** `src/api/endpoints/questionnaires.ts` and
  `src/api/types.ts` define the canonical schema question-type vocabulary
  (`QuestionnaireQuestionType`) that the Android `core-model` mapping (AND-346)
  mirrors. **[CORRECTED:** vocabulary is lowercase `text`/`select`/`multiselect`/
  `radio`/`slider`/`date`/`time`/`timezone`/`address`; see FR-1.]

## 3. Functional Requirements

FR-1 **Renderer coverage.** A parameterised Compose test asserts every supported
field type renders its expected control and captures input back into form state.
**[CORRECTED]** The authoritative type vocabulary is the backend's
`QuestionnaireQuestionType` enum (lowercase string tokens), confirmed in
`src/api/types.ts: QuestionnaireQuestionType`: `text`, `select`, `multiselect`,
`radio`, `slider`, `date`, `time`, `timezone`, `address` (9 types). The earlier
draft's `TEXT`/`TEXTAREA`/`NUMBER`/`EMAIL`/`SINGLE_CHOICE`/`MULTI_CHOICE`/
`DROPDOWN`/`SCALE`/`DATE`/`BOOLEAN`/`FILE_UPLOAD` set was invented and does not
match the contract — there are no `number`, `email`, `boolean`, `textarea`, or
`file_upload` question types in the backend, and the choice controls are
`select` (dropdown), `multiselect`, and `radio`, while `slider` is the scale
control. Mapping for the native renderer: `text`→single-line text,
`select`→dropdown, `multiselect`→multi-select, `radio`→single-choice,
`slider`→numeric scale, `date`/`time`/`timezone`→pickers, `address`→composite
address control. Sub-variants (e.g. multiline, numeric/email keyboard,
min/max/scale bounds, choice options) come from each question's
`config_json` object (see `src/api/types.ts: QuestionnaireQuestion.config_json`),
not from distinct type tokens. Unknown/unmapped `type` values must render a
non-crashing fallback placeholder.

FR-2 **Input capture.** For each rendered field, simulating user input (text
entry, choice selection, slider drag, date/time pick) must emit the
corresponding value into the ViewModel's answer map. **[CORRECTED]** The answer
map is keyed by **`question_id`** (the contract's `answers_by_question_id`,
verified in `OpenAPI SessionSaveReq`/`QuestionnaireValidationRequest` and
`src/api/types.ts: QuestionnaireSessionStateResp.answers_by_question_id`), not a
generic "field id". There is no `file pick` path — `file_upload` is not a backend
question type (see FR-1 correction); drop that assertion.

FR-3 **State machine.** Tests cover `RespondentSessionViewModel` transitions:
`Loading → Ready → Submitting → Submitted` and the error branches
`Loading → Error` and `Submitting → Ready(withErrors)`. **[CORRECTED]**
Navigation is by **section index** (`current_section_index`), not "page" — the
contract has no page concept; the web client surfaces a "Page N/M" label that is
purely a presentation of `currentSectionIndex+1 / sections.length` (see
`src/pages/questionnaires/QuestionnaireRespondentPage.tsx`, `pageProgressLabel`).
Multi-section questionnaires cover `next()` / `previous()` section navigation with
bounds clamping, and `current_section_index` is persisted via `SessionSaveReq`.

FR-4 **Conditional logic.** Tests assert visibility rules from AND-350:
a field gated by a condition (e.g. trigger question == "yes") is hidden until the
trigger value is set, hidden fields are excluded from validation and from the
submit payload, and re-hiding a field clears its captured value.
**[UNVERIFIED ASSUMPTION — divergence flagged]** The exact `showIf`/condition
operator vocabulary (`eq`/`ne`/`in`/`gt`/`lt`/`and`/`or`) and a client-side
`ConditionEvaluator` are **not** present in the verifiable sources. The web
reference client (`QuestionnaireRespondentPage.tsx`) does **not** evaluate
visibility on the client at all: it renders every question in the current
section and delegates conditional/validation logic to the backend, which carries
opaque `form_rules` / `group_rules` arrays in the validation contract
(`OpenAPI QuestionnaireValidationRequest.form_rules`/`group_rules`, both
`array<object>` with `additionalProperties: true` — i.e. shape not pinned by
OpenAPI). The native condition DSL described here is therefore an AND-350 design
choice that must be confirmed against AND-350's implementation, not the web app.
The backend `schema_json` is also opaque (`additionalProperties: true`), so the
exact per-question condition field name (`condition`, `visible_if`, …) is
unverifiable from the sources; tests must align with whatever AND-346/350 land.

FR-5 **Validation.** Tests assert required-field, type, range (min/max, scale
bounds), length (min/max chars), and multi-choice min/max-selection rules.
Invalid state must (a) populate per-field error messages, (b) keep `canSubmit ==
false`, and (c) prevent the *final* submit from completing while blocking errors
exist. **[CORRECTED — error/validation contract]** The authoritative validation
contract is server-driven, not the generic "FastAPI `detail`" shape the draft
assumed. Validation is performed by `POST .../sessions/{id}/validate` (and
`/submit`) with body `{ answers_by_question_id, final_submit }` and returns
`QuestionnaireValidationResponse`: `{ is_valid, can_submit,
has_blocking_form_error, errors }`, where `errors` is a **map of `question_id` →
`ValidationIssue[]`** and each `ValidationIssue` is `{ code, message,
blocking?, rule_id? }` (verified: `OpenAPI QuestionnaireValidationResponse`,
`OpenAPI ValidationIssue`, `src/api/endpoints/questionnaires.ts:
validatePublishedResponseSession`). `canSubmit` derives from the response's
`can_submit` flag, not a locally-computed boolean. Error keys prefixed `group:`
or `form:` are non-field (group/form-level) errors and must surface in a summary,
not against a single field (verified: `QuestionnaireRespondentPage.tsx`,
`groupOrFormErrors`). For the native port, AND-350 may additionally run a
**client-side** validator to give offline/immediate feedback; that is a design
choice (see §16 Open assumptions) — tests that assert client-side rule semantics
must label them as exercising the AND-350 native engine, while tests that assert
the wire contract must use the real `QuestionnaireValidationResponse` shape.

FR-6 **Determinism.** No real time, no real network, no real I/O. Fixed clock,
seeded data, `runTest` virtual time. Suite must pass headless on CI with no
connected device for the JVM/Robolectric tiers.

FR-7 **Negative/edge cases.** Empty questionnaire schema, a schema with only
hidden fields, a malformed condition referencing a missing field id (must not
crash; treated as "always visible" with a logged warning).

## 4. Technical Design

Test source sets:

- `feature-questionnaire/src/test/...` — JVM unit + Robolectric Compose tests.
- `feature-questionnaire/src/androidTest/...` — instrumented Compose tests for
  field types that require a real `Activity`/IME (kept minimal; the bulk runs on
  the JVM via Robolectric).

Key production types under test (signatures owned by upstream tickets, referenced
here for the test contract):

```kotlin
// core-model (AND-346)
sealed interface QuestionField {
    val id: String
    val label: String
    val required: Boolean
    val condition: VisibilityCondition?
}
data class TextField(/* ... */) : QuestionField
data class ChoiceField(val options: List<Choice>, val multi: Boolean, /* ... */) : QuestionField
data class ScaleField(val min: Int, val max: Int, /* ... */) : QuestionField
// ... DateField, BooleanField, FileUploadField, etc.

data class QuestionnaireSchema(val pages: List<QuestionnairePage>)
data class QuestionnairePage(val id: String, val fields: List<QuestionField>)

// AND-350
fun interface ConditionEvaluator {
    fun isVisible(field: QuestionField, answers: Map<String, FieldValue>): Boolean
}
class Validator {
    fun validate(schema: QuestionnaireSchema, answers: Map<String, FieldValue>): Map<String, FieldError>
}

// AND-351
class RespondentSessionViewModel(/* api, savedStateHandle, dispatchers */) {
    val uiState: StateFlow<RespondentUiState>
    fun onAnswer(fieldId: String, value: FieldValue)
    fun next(); fun previous()
    fun submit()
}
sealed interface RespondentUiState { /* Loading, Ready(visibleFields, errors, canSubmit), Submitting, Submitted, Error */ }
```

Test scaffolding added by this ticket:

```kotlin
// core-testing or feature-questionnaire/src/test/.../fixtures
object QuestionnaireFixtures {
    fun schemaWithAllFieldTypes(): QuestionnaireSchema
    fun schemaWithConditional(triggerId: String = "q_consent"): QuestionnaireSchema
    fun multiPageSchema(pages: Int = 3): QuestionnaireSchema
    fun emptySchema(): QuestionnaireSchema
}

@RunWith(AndroidJUnit4::class) // Robolectric
class QuestionFieldRendererTest {
    @get:Rule val compose = createComposeRule()
    // parameterised over field type via JUnit @Parameter or repeated @Test methods
}

class RespondentSessionViewModelTest {
    @get:Rule val dispatcherRule = MainDispatcherRule()
    private val api = FakeQuestionnaireApi()
}

class ConditionEvaluatorTest        // pure JVM
class ValidatorTest                 // pure JVM
```

`FakeQuestionnaireApi` implements the AND-346 `QuestionnaireApi` Retrofit
interface as an in-memory fake returning canned `ApiResult<T>` values, so
ViewModel tests need no `MockWebServer`. One thin `MockWebServer`-backed test
verifies that the real Moshi adapters deserialize a captured published-schema
JSON body into the `core-model` types (guards AND-346 mapping from regressions).

Renderer tests use Compose semantics/test tags. The renderer (AND-347) must
expose stable `testTag("field_<id>")` and `contentDescription`s; if missing, this
ticket files the gap against AND-347 and uses `onNodeWithText` as an interim
locator.

## 5. API Contract

No new API surface is introduced by this Test ticket. The suite asserts against
the **existing** AND-346 contract. **[CORRECTED]** The previous draft's JSON
sample (top-level `slug`/`title`/`pages[].fields[]` with `type: "single_choice"`/
`"textarea"`/`"scale"`) does not match the contract. The verified shapes are:

```
GET /questionnaires/published/{published_slug}
200 OK   (op=get_published_by_slug..., resp=PublishedQuestionnaireEnvelope)
{
  "version": {                         // envelope wrapper: { "version": {...} }
    "questionnaire_id": "...",
    "version_id": "...",
    "version_number": 1,
    "published_slug": "intake-2026",
    "visibility": "public",            // "private" | "public" | "unlisted"
    "allow_anonymous": true,
    "published_at": "2026-...",
    "schema_json": {                   // opaque object in OpenAPI; shape below from web client
      "questionnaire_id": "...",
      "sections": [
        { "section_id": "s1", "title": "Consent", "position": 0, "questions": [
          { "question_id": "q_consent", "type": "radio", "label": "Consent?",
            "required": true, "position": 0,
            "config_json": { "options": [{"value":"yes","label":"Yes"},
                                         {"value":"no","label":"No"}] } },
          { "question_id": "q_reason", "type": "text", "label": "Why?",
            "required": true, "position": 1,
            "config_json": { "multiline": true /* + any condition the backend emits */ } },
          { "question_id": "q_rating", "type": "slider", "label": "Rate",
            "required": false, "position": 2,
            "config_json": { "min": 1, "max": 5 } }
        ]}
      ]
    }
  }
}
```

Note the corrected structure: enveloped under `version`; **`sections[].questions[]`**
(not `pages[].fields[]`); identifiers `section_id`/`question_id`; lowercase `type`
tokens; control sub-config (options, min/max, multiline) lives in
`config_json`. `schema_json` is declared `additionalProperties: true` in OpenAPI,
so the inner field names above are sourced from the web client
(`QuestionnaireRespondentPage.tsx`: `schema_json.sections[].questions[]`,
`question_id`, `label`, `required`) and from `src/api/types.ts:
QuestionnaireQuestion` (`question_id`, `type`, `label`, `required`, `hint`,
`config_json`, `position`).

**Validate / submit error contract [CORRECTED].** Field/submit errors do **not**
use the FastAPI `detail` shape. The respondent flow calls
`POST .../sessions/{response_session_id}/validate` and
`POST .../sessions/{response_session_id}/submit` with body
`{ "answers_by_question_id": {...}, "final_submit": <bool> }`
(`QuestionnaireValidationRequest`; note `contract_version` defaults to
`"2026-03-validation-v1"`) and receive `QuestionnaireValidationResponse`:

```
{
  "is_valid": false,
  "can_submit": false,
  "has_blocking_form_error": true,
  "errors": {
    "q_reason":   [ { "code": "required", "message": "This field is required.", "blocking": true, "rule_id": null } ],
    "group:age":  [ { "code": "group_rule", "message": "...", "blocking": true } ],
    "form:total": [ { "code": "form_rule",  "message": "...", "blocking": false } ]
  }
}
```

`errors` is a map keyed by `question_id` (with reserved `group:`/`form:`
prefixes for non-field errors); each value is a `ValidationIssue[]` of
`{ code, message, blocking?, rule_id? }`. **Submit returns 200** with a
`SessionSubmitEnvelope` `{ session, result: QuestionnaireValidationResponse }` —
a failed submit is surfaced via `result.is_valid == false` /
`result.can_submit == false`, **not** an HTTP 422 carrying `detail`. (The generic
`HTTPValidationError`/`detail` shape applies only to malformed-request 422s, e.g.
a bad path param.) The suite includes fixtures for: a passing
`QuestionnaireValidationResponse`, a field-error one, a `group:`/`form:`-keyed
one, and a true 422 `HTTPValidationError`, and asserts the `core-network` error
mapper surfaces a user-facing message without crashing for each. Verified:
`OpenAPI QuestionnaireValidationRequest`/`QuestionnaireValidationResponse`/
`ValidationIssue`/`SessionSubmitEnvelope`; `src/api/endpoints/questionnaires.ts:
validatePublishedResponseSession`/`submitPublishedResponseSession`;
`QuestionnaireRespondentPage.tsx`. Endpoint ownership for actual session
start/save/submit stays with AND-348/349.

## 6. Data & State Management

The suite verifies, not introduces, state management. Coverage:

- **Answer map:** `Map<String, FieldValue>` mutations via `onAnswer` are
  reflected in `uiState`; verified with Turbine (`uiState.test { ... }`).
- **Derived state:** `visibleFields` is recomputed from `ConditionEvaluator`
  on each answer change; `canSubmit` is derived `errors.isEmpty() && allRequiredVisibleAnswered`.
- **Process-death / resume:** a test writes answers, simulates `SavedStateHandle`
  restore, and asserts the answer map and `current_section_index` survive
  **[CORRECTED:** "current page index" → `current_section_index`, the contract's
  navigation cursor in `SessionSaveReq`/`QuestionnaireSessionState`]. (Full
  server-side save/resume is AND-348; this ticket only covers in-process restore.)
- **Hidden-field hygiene:** asserts hidden fields are absent from the computed
  submit payload (`buildSubmitPayload(answers, visibleFields)`).

No Room/DataStore writes are exercised here; persistence tests belong to AND-348.

## 7. Error Handling & Resilience

- **Load failure:** `FakeQuestionnaireApi` returns `ApiResult.Error` (timeout,
  4xx, 5xx); assert `uiState == Error` with a retry-able message and that
  `submit()` is a no-op while in `Error`/`Loading`.
- **Submit failure:** **[CORRECTED]** the common "submit failure" path is **not**
  an HTTP 422 — `POST .../submit` returns **200** with `result.is_valid == false`
  / `result.can_submit == false` and `result.errors` (`question_id` →
  `ValidationIssue[]`). Assert `Submitting → Ready` with those server errors
  merged into per-field `errors` (and `group:`/`form:` errors into a summary) and
  `canSubmit` set from `result.can_submit`. A genuine transport/HTTP error (5xx,
  timeout, real 422 `HTTPValidationError`) is the separate error branch and must
  also be covered.
- **Malformed schema:** unknown field `type` → fallback control, logged warning,
  no crash; condition referencing missing field id → treated visible, warning.
- **Flake resistance:** all coroutines run on `StandardTestDispatcher` with
  `advanceUntilIdle()`; no `Thread.sleep`, no real timeouts. Compose tests use
  `waitUntil`/`waitForIdle`, never fixed delays. CI marks the suite to fail the
  build on first failure; a `@FlakyTest`-tagged quarantine is explicitly **not**
  used (zero-tolerance for this suite).

## 8. Security & Privacy

Test-only ticket; no production attack surface added. Constraints:

- Fixtures use synthetic data only — no real PII, no real credentials, no
  captured production payloads with user data.
- The schema-mapping JSON fixture is a hand-authored sample, not a live capture.
- No live network: tests cannot leak the cookie/CSRF session; the fake
  `CookieJar` holds dummy values. Confirms (does not implement) that mutating
  requests include the `X-CSRF-Token` header by asserting the fake records it on
  the request it receives. **[VERIFIED]** The web client sets header
  `X-CSRF-Token` from the `ui_csrf` cookie and sends `credentials: "include"`
  (`src/api/client.ts`, lines 167-170 and `credentials: "include"`); the Android
  transport (AND-346/core-network) must mirror this. NOTE: the published
  respondent endpoints declare **no** auth params in OpenAPI (no `X-SESSION-ID`/
  `X-IMPERSONATION-TOKEN` on `/questionnaires/published/...`), so anonymous
  respond is contract-permitted (`PublishedQuestionnaireVersion.allow_anonymous`);
  whether CSRF is required for anonymous public submit is unverified — assert the
  header is *attached when a session cookie exists*, and do not assert it is
  rejected when absent.
- File-upload field test uses a small in-memory byte array, never a real file
  from device storage.

## 9. Accessibility & i18n

The renderer tests double as accessibility regression guards:

- Assert every interactive field node has a non-empty `contentDescription` or
  associated label via Compose semantics (`assertContentDescriptionContains` /
  merged-semantics label check); a missing label fails the test and is filed
  against AND-347.
- Assert error messages are exposed via `error` semantics
  (`SemanticsProperties.Error`) so TalkBack announces them.
- Assert required fields expose a programmatic required indicator, not colour
  alone.
- i18n: validation/error strings are asserted via string resource ids
  (`R.string.*`), not hardcoded literals, so the suite fails if a literal is
  introduced. A pseudo-locale (`en-XA`) smoke test confirms no truncation/crash
  in renderer layout.

## 10. Telemetry & Logging

No analytics events are emitted by tests. The suite asserts the **absence** of
noisy logging in happy paths and the **presence** of the warning log for the two
malformed-schema cases (FR-7) via a test `Timber.Tree`/`Logger` spy injected
through `core-testing`. No telemetry SDK is initialised in unit tests.

## 11. Testing Strategy

This ticket *is* the testing strategy for the feature. Tiers:

1. **Pure JVM unit (fastest, majority):** `ConditionEvaluatorTest`,
   `ValidatorTest`, `RespondentSessionViewModelTest` (with `MainDispatcherRule`,
   Turbine, `FakeQuestionnaireApi`). Target: every condition op (`eq`, `ne`,
   `in`, `gt`, `lt`, compound `and`/`or`), every validation rule, every state
   transition.
2. **Robolectric Compose:** `QuestionFieldRendererTest` parameterised over all
   **9** backend question types (`text`, `select`, `multiselect`, `radio`,
   `slider`, `date`, `time`, `timezone`, `address`) **[CORRECTED from "11"]** —
   render + input-capture assertions, run on the JVM in CI without an emulator.
3. **Instrumented (`androidTest`):** minimal smoke for IME-dependent fields
   (date picker, file picker intent) on a single API-34 emulator profile.
4. **Schema-mapping guard:** one `MockWebServer` test deserializing the §5 JSON.

Tooling: JUnit4, kotlinx-coroutines-test, Turbine, Truth/AssertK assertions,
MockWebServer 4.12, Robolectric, Compose UI Test. Coverage gate: line coverage
≥ 85% for `feature-questionnaire` renderer + validation + ViewModel packages,
measured with Kover; build fails below threshold. Test naming:
`backtick GIVEN_WHEN_THEN` style.

Representative cases (non-exhaustive):

- `renders radio and captures selection into answers_by_question_id`
- `hidden field excluded from validation and submit payload`
- `required visible field empty -> canSubmit is false and final submit blocked`
- `slider value above config_json.max -> ValidationIssue populated for question_id`
- `multiselect below config_json.minSelections -> ValidationIssue`
- `submit success (result.is_valid) -> Submitted; submit result.is_valid=false -> Ready with server field errors`
- `unknown question type -> fallback rendered, no crash`
- `condition referencing missing question_id -> field visible, warning logged`

## 12. Dependencies & Sequencing

- **Hard deps (must be merged & API-stable before this lands):** AND-346
  (DTOs/mapping), AND-347 (renderer + test tags), AND-350 (condition/validation),
  AND-351 (ViewModels/state machine). The source ticket lists AND-351 as the sole
  declared dep; AND-347/350 are transitive necessities for "renderer + validation
  tests" and are recorded in `depends_on` for accuracy.
- **Blocks:** AND-348, AND-349, AND-395 should not be marked done until this
  green suite exists, since they extend the same code paths.
- **Sequencing:** Land after the four deps; coordinate with AND-347 to add stable
  `testTag`s/`contentDescription`s if absent (small upstream PR). `core-testing`
  fixtures (`QuestionnaireFixtures`, `FakeQuestionnaireApi`) land first within
  this ticket so downstream tickets can reuse them.

## 13. Risks & Open Questions

- **R1 — Renderer lacks stable test hooks.** If AND-347 ships without
  `testTag`/semantics, tests become brittle text-locator based. *Mitigation:*
  add hooks via an AND-347 follow-up; treat as a blocking gap.
- **R2 — Compose-on-Robolectric gaps.** Some Compose interactions (slider drag,
  date picker) may be unreliable under Robolectric. *Mitigation:* push those few
  cases to the instrumented tier.
- **R3 — Validation rule vocabulary undefined.** AND-350's exact rule set
  (e.g., regex/pattern fields) is not fully enumerated in the backlog. *Open
  question:* confirm full rule list with AND-350 owner; spec currently covers
  required/type/range/length/selection-count.
- **R4 — Schema field-type enum drift** vs. web `types.ts`. *Mitigation:* the
  §5 mapping guard test fails if backend adds an unmapped type.
- **OQ1:** Are conditions ever cross-page (trigger on page 1, target on page 3)?
  Tests assume yes and cover it; confirm with AND-350/351.

## 14. Acceptance Criteria

AC-1 The suite compiles and **passes** (the source ticket's "Pass.") on CI with
no connected device for the JVM/Robolectric tiers.

AC-2 All 9 supported question types (`text`, `select`, `multiselect`, `radio`,
`slider`, `date`, `time`, `timezone`, `address`) have a render-and-capture test
**[CORRECTED from "11"]**; an unknown type renders a fallback without crashing.

AC-3 ViewModel state-machine transitions (Loading/Ready/Submitting/Submitted/
Error and error branches) are covered and assert via Turbine.

AC-4 Conditional visibility tests prove fields show/hide, hidden fields are
excluded from validation and submit payload, and re-hiding clears the value.

AC-5 Validation tests prove invalid input populates per-field errors, keeps
`canSubmit == false`, and that `submit()` does **not** call the API while invalid.

AC-6 Schema-mapping guard test deserializes the §5 JSON into `core-model` types
correctly.

AC-7 Suite is deterministic: passes 20/20 consecutive CI runs with zero flakes;
no `Thread.sleep`/real network/real clock.

AC-8 Kover coverage ≥ 85% on the renderer/validation/ViewModel packages; build
fails below threshold.

## 15. Definition of Done

- New tests under `feature-questionnaire/src/test` and (minimal)
  `src/androidTest`, plus reusable fixtures (`QuestionnaireFixtures`,
  `FakeQuestionnaireApi`) in `core-testing`.
- `./gradlew :feature-questionnaire:testDebugUnitTest` and the Robolectric tier
  are green locally and in CI; instrumented smoke green on the standard emulator
  profile.
- Kover report attached to CI; threshold gate enabled and passing.
- Any production gaps found (missing test tags, missing a11y labels, crash on
  malformed schema) are filed against the owning ticket (AND-347/350/351) with a
  reference, and worked around or covered by an `@Ignore`-with-link only if the
  fix is out of scope.
- No new production behaviour introduced; no live-host network in tests.
- Code reviewed; merged to `android-port`; all 15 sections' acceptance criteria
  verified by the reviewer.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources:
`OpenAPI 'METHOD /path'` (from `reference/openapi.index.txt`), schema names (from
`reference/openapi.pretty.json` `components.schemas.<Name>`), frontend paths
(under `reference/src/`), or `framework ref` URLs for Android tooling choices.

1. **Published questionnaire is fetched at `GET /questionnaires/published/{published_slug}`.**
   VERDICT: Corrected (draft said `{slug}`). SOURCE: `OpenAPI GET
   /questionnaires/published/{published_slug}` (op=get_published_by_slug...);
   `src/api/endpoints/questionnaires.ts: getPublishedQuestionnaireBySlug`.
2. **Response is an envelope `{ "version": {...} }`, not a bare schema.**
   VERDICT: Corrected. SOURCE: `OpenAPI PublishedQuestionnaireEnvelope` (single
   required `version: object`); `src/api/types.ts: PublishedQuestionnaireVersion`;
   `src/api/endpoints/questionnaires.ts` (`{ version: PublishedQuestionnaireVersion }`).
3. **Schema is `schema_json.sections[].questions[]`, not `pages[].fields[]`.**
   VERDICT: Corrected. SOURCE: `QuestionnaireRespondentPage.tsx`
   (`schema_json.sections`, `section.questions`, `question_id`); `src/api/types.ts:
   QuestionnaireSection`, `QuestionnaireQuestion`. (Inner `schema_json` is
   `additionalProperties:true` in OpenAPI, so structure is sourced from frontend.)
4. **Question-type vocabulary is lowercase: `text, select, multiselect, radio,
   slider, date, time, timezone, address` (9).** VERDICT: Corrected (draft listed
   11 invented UPPER_SNAKE tokens incl. `NUMBER/EMAIL/BOOLEAN/TEXTAREA/FILE_UPLOAD`).
   SOURCE: `src/api/types.ts: QuestionnaireQuestionType`.
5. **Question fields are `question_id, section_id, type, label, required, hint,
   config_json, position`; control sub-options live in `config_json`.** VERDICT:
   Verified. SOURCE: `src/api/types.ts: QuestionnaireQuestion`.
6. **Answers are keyed by `question_id` (`answers_by_question_id`).** VERDICT:
   Corrected (draft said "field id"). SOURCE: `OpenAPI SessionSaveReq`,
   `QuestionnaireValidationRequest`, `SessionStateEnvelope`; `src/api/types.ts:
   QuestionnaireSessionStateResp`.
7. **Navigation cursor is `current_section_index` (+ optional `current_question_id`),
   not a "page index"; "Page N/M" is a label derived from section index.** VERDICT:
   Corrected. SOURCE: `OpenAPI SessionSaveReq` (`current_section_index`,
   `current_question_id`); `src/api/types.ts: QuestionnaireSessionState`;
   `QuestionnaireRespondentPage.tsx` (`pageProgressLabel`).
8. **Session lifecycle endpoints:** start `POST .../sessions`
   (`ResponseSessionStartReq`→`ResponseSessionEnvelope`); get state
   `GET .../sessions/{response_session_id}` (`SessionStateEnvelope`); save
   `PUT .../sessions/{response_session_id}` (`SessionSaveReq`→`SessionStateEnvelope`).
   VERDICT: Verified. SOURCE: `OpenAPI` rows for those ops;
   `src/api/endpoints/questionnaires.ts: startPublishedResponseSession`,
   `getPublishedResponseSessionState`, `savePublishedResponseSessionState`.
9. **Validation/submit request is `{ answers_by_question_id, final_submit,
   contract_version="2026-03-validation-v1", form_rules, group_rules }`.** VERDICT:
   Corrected (draft assumed FastAPI `detail`). SOURCE: `OpenAPI
   QuestionnaireValidationRequest`; `src/api/endpoints/questionnaires.ts:
   validatePublishedResponseSession` / `submitPublishedResponseSession`.
10. **Validation response is `QuestionnaireValidationResponse { is_valid,
    can_submit, has_blocking_form_error, errors }`, `errors` = map question_id →
    `ValidationIssue[]`.** VERDICT: Corrected. SOURCE: `OpenAPI
    QuestionnaireValidationResponse`, `OpenAPI ValidationIssue`.
11. **`ValidationIssue` = `{ code, message, blocking?, rule_id? }` (code+message
    required).** VERDICT: Verified. SOURCE: `OpenAPI ValidationIssue`.
12. **Submit returns HTTP 200 `SessionSubmitEnvelope { session, result:
    QuestionnaireValidationResponse }`; a blocked submit is `result.is_valid=false`,
    NOT a 422.** VERDICT: Corrected (draft said "submit 422 -> server field
    errors"). SOURCE: `OpenAPI SessionSubmitEnvelope`;
    `submitPublishedResponseSession` returns `{ session, result }`.
13. **`group:`/`form:`-prefixed error keys are non-field (group/form-level)
    errors.** VERDICT: Verified. SOURCE: `QuestionnaireRespondentPage.tsx`
    (`groupOrFormErrors = ... key.startsWith("group:")||key.startsWith("form:")`).
14. **`canSubmit` follows the server's `can_submit` flag.** VERDICT: Verified.
    SOURCE: `QuestionnaireRespondentPage.tsx` (`hasBlocking = !validationResult.can_submit`).
15. **Mutating requests carry `X-CSRF-Token` from the `ui_csrf` cookie, with
    `credentials: "include"`.** VERDICT: Verified. SOURCE: `src/api/client.ts`
    (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`, `credentials:
    "include"`).
16. **Published respondent endpoints declare no auth headers; anonymous respond
    is contract-permitted (`allow_anonymous`).** VERDICT: Verified. SOURCE:
    `OpenAPI` published rows have `params=published_slug[,response_session_id]`
    only (no `X-SESSION-ID`/`X-IMPERSONATION-TOKEN`); `src/api/types.ts:
    PublishedQuestionnaireVersion.allow_anonymous`.
17. **Submit is debounced/validated server-side in the web client (350ms validate,
    500ms save); the web client renders questions generically and does not run a
    client-side condition/validation engine.** VERDICT: Verified. SOURCE:
    `QuestionnaireRespondentPage.tsx` (`queueSaveAndValidate` timers; single
    generic `<Input>` per question; no client visibility eval).
18. **Robolectric for JVM-side Compose; instrumented tier for IME/picker.**
    VERDICT: Verified (framework ref). SOURCE:
    https://robolectric.org/ and
    https://developer.android.com/develop/ui/compose/testing (Compose UI test).
19. **`SemanticsProperties.Error` exposes errors to TalkBack; semantics
    `contentDescription`/`error` are the a11y assertion surface.** VERDICT:
    Verified (framework ref). SOURCE:
    https://developer.android.com/develop/ui/compose/accessibility and
    https://developer.android.com/reference/kotlin/androidx/compose/ui/semantics/SemanticsProperties .
20. **kotlinx-coroutines-test virtual time / `StandardTestDispatcher` /
    `advanceUntilIdle` for determinism.** VERDICT: Verified (framework ref).
    SOURCE: https://kotlinlang.org/api/kotlinx.coroutines/kotlinx-coroutines-test/ .

### Corrections made

- §FM: `status: draft` → `status: reviewed`; added `reviewed_on: 2026-06-06`.
- §2 / §5: endpoint path param `{slug}` → `{published_slug}`; response is enveloped
  (`{ version: ... }`).
- §5: replaced the fabricated `pages[].fields[]` JSON (with `type:single_choice/
  textarea/scale`) with the verified `version.schema_json.sections[].questions[]`
  shape using lowercase types and `config_json`.
- §5 / §7 / §11: validation/submit error contract corrected from "FastAPI
  `detail`" to `QuestionnaireValidationResponse` (`errors` = question_id →
  `ValidationIssue[]`); "submit 422" corrected to HTTP-200
  `SessionSubmitEnvelope` with `result.is_valid=false`.
- FR-1 / §11 / AC-2: field-type list corrected from 11 invented UPPER_SNAKE types
  to the 9 backend lowercase `QuestionnaireQuestionType` tokens.
- FR-2 / §6: answer-map key "field id" → `question_id`; navigation "page index" →
  `current_section_index`; removed the non-existent `file_upload`/file-pick path.
- §8: CSRF header `X-CSRF-Token`/`ui_csrf` cookie verified and cited; added the
  anonymous-respond caveat.

### Open assumptions

- **Client-side condition/validation engine (AND-350).** The web reference does
  conditional logic and validation server-side; a native `ConditionEvaluator` /
  `Validator` and the `eq/ne/in/gt/lt/and/or` operator DSL described in FR-4/§3
  cannot be verified from the sources. Tests asserting client-side rule semantics
  must be labelled as exercising the AND-350 native engine; the AND-350 owner must
  confirm the operator set, the per-question condition field name, and whether
  conditions can be cross-section. Why unverifiable: `schema_json`,
  `form_rules`, and `group_rules` are all `additionalProperties:true` in OpenAPI.
- **`config_json` sub-keys** (`options`, `min`, `max`, `minSelections`,
  `multiline`, etc.) are illustrative; OpenAPI does not pin them
  (`config_json: Record<string, unknown>`). Confirm exact keys with AND-346.
- **`AC-5` "submit() does not call the API while invalid"** assumes a native
  client-side pre-submit gate. The web client instead always calls the server and
  reads `can_submit`. Keep AC-5 only if AND-351 implements a local gate; otherwise
  retarget it to "final submit is blocked while `can_submit==false`".
- **Coverage ≥85% (Kover) and 20/20 flake-free** (§AC-7/AC-8) are project policy
  targets, not derivable from the reference sources; treated as team conventions.
- **`schemaWithAllFieldTypes` / condition `op` strings** in §4 fixtures inherit
  the unverified DSL above and must track AND-346/350 once those land.

## 17. Test Plan

IDs `TC-AND-352-NN`. "Traces" link to §14 acceptance criteria. Targets:
JVM/Robolectric = local (no device); `test35` = headless API-35 x86_64 emulator;
`SM-A156U` = physical Galaxy A15 5G (API-34 arm64), serial R5CX821TA9R.

- **TC-AND-352-01 — Render + capture for all 9 question types.**
  Type: Compose-UI (Robolectric, JVM). Target: JVM/Robolectric.
  Preconditions: `QuestionnaireFixtures.schemaWithAllFieldTypes()` covering
  `text, select, multiselect, radio, slider, date, time, timezone, address`.
  Steps: render `QuestionFieldRenderer` per type via `testTag("field_<question_id>")`;
  simulate the type-appropriate input (text entry, option select, slider drag,
  date/time pick). Expected: each emits the correct value into
  `answers_by_question_id[question_id]`; control matches the type. Traces: AC-2.
- **TC-AND-352-02 — Unknown question type → fallback, no crash.**
  Type: Compose-UI (Robolectric). Target: JVM/Robolectric.
  Preconditions: schema with `type:"__unknown__"`. Steps: render. Expected:
  non-crashing fallback placeholder shown; warning logged (spy Tree). Traces: AC-2, AC-7.
- **TC-AND-352-03 — State machine happy path Loading→Ready→Submitting→Submitted.**
  Type: unit (Turbine + `MainDispatcherRule`). Target: JVM.
  Preconditions: `FakeQuestionnaireApi` returns a valid published schema and a
  submit `result.is_valid=true`. Steps: init VM, answer required questions,
  `submit()`; collect `uiState` with `uiState.test {}`. Expected: emits
  Loading→Ready→Submitting→Submitted in order. Traces: AC-1, AC-3.
- **TC-AND-352-04 — Load failure → Error, submit is no-op.**
  Type: unit/contract (MockWebServer + Turbine). Target: JVM.
  Preconditions: server returns 500 / timeout on the published GET. Steps: init
  VM; call `submit()` while in Error. Expected: `uiState==Error` with retry-able
  message; `submit()` issues no network call (assert MockWebServer request count
  unchanged). Traces: AC-3.
- **TC-AND-352-05 — Section navigation with bounds clamping.**
  Type: unit. Target: JVM. Preconditions: `multiPageSchema(3)` (3 sections).
  Steps: `next()` past last and `previous()` before first. Expected:
  `current_section_index` clamps to [0,2]; never out of bounds. Traces: AC-3.
- **TC-AND-352-06 — Conditional visibility (native AND-350 engine).**
  Type: unit. Target: JVM. Preconditions: `schemaWithConditional()` where
  `q_reason` is gated on `q_consent=="yes"`. Steps: assert hidden initially; set
  `q_consent="yes"`; assert visible; reset to `"no"`. Expected: field shows/hides;
  hidden field's value is cleared and absent from `buildSubmitPayload`. (Labelled
  as exercising the AND-350 native engine — see §16 Open assumptions.) Traces: AC-4.
- **TC-AND-352-07 — Hidden field excluded from validation + submit payload.**
  Type: unit. Target: JVM. Preconditions: as TC-06, condition false. Steps:
  inspect payload sent to `/validate` and `/submit`. Expected:
  `answers_by_question_id` omits hidden `question_id`; no error raised for it.
  Traces: AC-4, AC-5.
- **TC-AND-352-08 — Server validation response maps to per-field + summary errors.**
  Type: contract (MockWebServer). Target: JVM.
  Preconditions: `/validate` returns `QuestionnaireValidationResponse` with
  `is_valid=false, can_submit=false`, `errors={ "q_reason":[{code:"required",
  message,blocking:true}], "form:total":[{...}] }`. Steps: trigger validate.
  Expected: `q_reason` error bound to that field via `SemanticsProperties.Error`;
  `form:`-keyed issue rendered in the summary, not on a field; `canSubmit==false`
  from `can_submit`. Traces: AC-4, AC-5.
- **TC-AND-352-09 — Invalid state blocks final submit; valid result → Submitted.**
  Type: unit/contract (MockWebServer). Target: JVM.
  Preconditions: first `/submit` returns 200 `result.is_valid=false`; second
  returns `result.is_valid=true`. Steps: submit while invalid, fix answers,
  submit again. Expected: first → `Ready(withErrors)` with merged server errors,
  no `Submitted`; second → `Submitted`. (Note: this exercises the corrected
  HTTP-200 `SessionSubmitEnvelope` contract, not a 422.) Traces: AC-5, AC-3.
- **TC-AND-352-10 — Schema-mapping guard deserializes §5 JSON.**
  Type: contract (MockWebServer + Moshi). Target: JVM.
  Preconditions: hand-authored `PublishedQuestionnaireEnvelope` body matching §5.
  Steps: call `getPublishedQuestionnaireBySlug`; deserialize. Expected: maps to
  `core-model` with `version.schema_json.sections[].questions[]`, lowercase types,
  `config_json` preserved; fails loudly if backend adds an unmapped type. Traces: AC-6.
- **TC-AND-352-11 — Error-shape mapper handles all variants without crash.**
  Type: unit. Target: JVM. Preconditions: fixtures for (a) valid
  `QuestionnaireValidationResponse`, (b) field-error response, (c)
  `group:`/`form:` response, (d) true `HTTPValidationError` 422
  (`detail:[{loc,msg}]`), (e) `detail` as a plain string. Steps: feed each to the
  `core-network` mapper. Expected: each yields a user-facing message; no
  exception. Traces: AC-5, AC-7.
- **TC-AND-352-12 — Determinism / no real I/O across full suite.**
  Type: integration (Gradle). Target: JVM/Robolectric + `test35`.
  Preconditions: CI config. Steps: run suite 20× headless; static check for
  `Thread.sleep`/`System.currentTimeMillis`/real `OkHttp` base URL. Expected:
  20/20 green; zero banned-API matches; no connected device required for JVM/Robolectric
  tiers. Traces: AC-1, AC-7, AC-8 (Kover gate runs in same job).
- **TC-AND-352-13 — Process-death restore preserves answers + section index.**
  Type: unit (SavedStateHandle). Target: JVM. Preconditions: VM with answers and
  `current_section_index=2`. Steps: serialize via `SavedStateHandle`, recreate VM.
  Expected: `answers_by_question_id` and `current_section_index` survive restore.
  Traces: AC-3.
- **TC-AND-352-14 — Accessibility: labels, required indicator, error semantics.**
  Type: Compose-UI (Robolectric) + instrumented spot-check. Target:
  JVM/Robolectric, with a TalkBack-announcement spot-check on `SM-A156U`
  (physical device — real accessibility service behaviour can differ from
  emulator/Robolectric, so the announcement assertion MUST run on the device).
  Preconditions: schema with a required field and a field in error. Steps: assert
  each interactive node has non-empty `contentDescription`/label; required exposes
  a programmatic indicator (not colour only); error exposed via
  `SemanticsProperties.Error`; on device, verify TalkBack announces the error.
  Traces: AC-2.
- **TC-AND-352-15 — Instrumented IME/picker smoke (date/time pickers).**
  Type: instrumented/e2e. Target: `test35` for the baseline run; re-run on
  `SM-A156U` to cover API-34 + arm64 differences (date/time picker dialogs and IME
  behaviour differ across API 34↔35 and ABI). Preconditions: schema with `date`
  and `time` questions. Steps: launch real Activity, open picker, select value.
  Expected: value captured into `answers_by_question_id`; no crash on either
  profile. Traces: AC-2.
- **TC-AND-352-16 — Offline / flaky-dev-host save path.**
  Type: contract (MockWebServer fault injection). Target: JVM (logic) + `test35`
  (real connectivity loss via emulator airplane toggle for the integration check).
  Preconditions: `/sessions/{id}` PUT first fails (socket drop), then succeeds.
  Steps: edit an answer (triggers debounced save), drop connection, restore.
  Expected: VM stays in `Ready`, surfaces a non-fatal "autosave failed/retry"
  state (no crash, no lost answers), and the answer persists in memory; on
  reconnect the save succeeds. (No live host is contacted.) Traces: AC-7.

### Coverage matrix

| AC   | Covered by |
|------|-----------|
| AC-1 | TC-03, TC-12 |
| AC-2 | TC-01, TC-02, TC-14, TC-15 |
| AC-3 | TC-03, TC-04, TC-05, TC-09, TC-13 |
| AC-4 | TC-06, TC-07, TC-08 |
| AC-5 | TC-07, TC-08, TC-09, TC-11 |
| AC-6 | TC-10 |
| AC-7 | TC-02, TC-11, TC-12, TC-16 |
| AC-8 | TC-12 (Kover gate in same CI job) |
