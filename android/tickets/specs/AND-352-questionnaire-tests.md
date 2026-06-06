---
id: AND-352
title: Questionnaire tests
milestone: M7
epic: E45
priority: P2
size: M
status: draft
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
  `/questionnaires/published/{slug}/sessions/*`. The suite does **not** hit the
  live host — all network is faked via `MockWebServer` or stubbed
  `QuestionnaireApi`.
- **Web parity reference:** `frontend/src/api/endpoints/questionnaires.ts` and
  `frontend/src/api/types.ts` define the canonical schema field-type vocabulary
  that the Android `core-model` mapping (AND-346) mirrors.

## 3. Functional Requirements

FR-1 **Renderer coverage.** A parameterised Compose test asserts every supported
field type renders its expected control and captures input back into form state:
`TEXT`, `TEXTAREA`, `NUMBER`, `EMAIL`, `SINGLE_CHOICE`, `MULTI_CHOICE`,
`DROPDOWN`, `SCALE` (Likert/rating), `DATE`, `BOOLEAN`, `FILE_UPLOAD`. Unknown
field types must render a non-crashing fallback placeholder.

FR-2 **Input capture.** For each rendered field, simulating user input (text
entry, choice selection, slider drag, date pick, file pick) must emit the
corresponding `FieldValue` into the ViewModel's answer map keyed by field id.

FR-3 **State machine.** Tests cover `RespondentSessionViewModel` transitions:
`Loading → Ready → Submitting → Submitted` and the error branches
`Loading → Error` and `Submitting → Ready(withErrors)`. Multi-page
questionnaires cover `next()` / `previous()` page navigation with bounds clamping.

FR-4 **Conditional logic.** Tests assert visibility rules from AND-350:
a field gated by `showIf(fieldX == "yes")` is hidden until the trigger value is
set, hidden fields are excluded from validation and from the submit payload, and
re-hiding a field clears its captured value.

FR-5 **Validation.** Tests assert required-field, type (number/email), range
(min/max, scale bounds), length (min/max chars), and multi-choice
min/max-selection rules. Invalid state must (a) populate per-field error
messages, (b) keep `canSubmit == false`, and (c) prevent the submit action from
calling the API.

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
the **existing** AND-346 contract. The schema-mapping guard test pins the shape
of the published-questionnaire response that the renderer consumes:

```
GET /questionnaires/published/{slug}
200 OK
{
  "slug": "intake-2026",
  "title": "Intake Form",
  "pages": [
    { "id": "p1", "fields": [
      { "id": "q_consent", "type": "single_choice", "label": "Consent?",
        "required": true, "options": [{"value":"yes","label":"Yes"},{"value":"no","label":"No"}] },
      { "id": "q_reason", "type": "textarea", "label": "Why?", "required": true,
        "condition": { "field": "q_consent", "op": "eq", "value": "yes" } },
      { "id": "q_rating", "type": "scale", "label": "Rate", "min": 1, "max": 5 }
    ]}
  ]
}
```

Validation/submit error parity (asserted in tests via the fake) follows the
FastAPI `detail` contract: `string | [{ "loc": [...], "msg": "..." }] | { "code": "...", ... }`.
The suite includes a fixture for each `detail` variant and asserts the
`core-network` error mapper surfaces a user-facing message without crashing.
Endpoint ownership for actual session start/save/submit stays with AND-348/349.

## 6. Data & State Management

The suite verifies, not introduces, state management. Coverage:

- **Answer map:** `Map<String, FieldValue>` mutations via `onAnswer` are
  reflected in `uiState`; verified with Turbine (`uiState.test { ... }`).
- **Derived state:** `visibleFields` is recomputed from `ConditionEvaluator`
  on each answer change; `canSubmit` is derived `errors.isEmpty() && allRequiredVisibleAnswered`.
- **Process-death / resume:** a test writes answers, simulates `SavedStateHandle`
  restore, and asserts the answer map and current page index survive. (Full
  server-side save/resume is AND-348; this ticket only covers in-process restore.)
- **Hidden-field hygiene:** asserts hidden fields are absent from the computed
  submit payload (`buildSubmitPayload(answers, visibleFields)`).

No Room/DataStore writes are exercised here; persistence tests belong to AND-348.

## 7. Error Handling & Resilience

- **Load failure:** `FakeQuestionnaireApi` returns `ApiResult.Error` (timeout,
  4xx, 5xx); assert `uiState == Error` with a retry-able message and that
  `submit()` is a no-op while in `Error`/`Loading`.
- **Submit failure:** assert `Submitting → Ready` with server field errors merged
  into per-field `errors`, and `canSubmit` recomputed.
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
  `CookieJar` holds dummy values. Confirms (does not implement) that the submit
  path includes `X-CSRF-Token` by asserting the fake records the header on the
  request it receives.
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
   11 field types — render + input-capture assertions, run on the JVM in CI
   without an emulator.
3. **Instrumented (`androidTest`):** minimal smoke for IME-dependent fields
   (date picker, file picker intent) on a single API-34 emulator profile.
4. **Schema-mapping guard:** one `MockWebServer` test deserializing the §5 JSON.

Tooling: JUnit4, kotlinx-coroutines-test, Turbine, Truth/AssertK assertions,
MockWebServer 4.12, Robolectric, Compose UI Test. Coverage gate: line coverage
≥ 85% for `feature-questionnaire` renderer + validation + ViewModel packages,
measured with Kover; build fails below threshold. Test naming:
`backtick GIVEN_WHEN_THEN` style.

Representative cases (non-exhaustive):

- `renders single_choice and captures selection into answers`
- `hidden field excluded from validation and submit payload`
- `required visible field empty -> canSubmit is false and submit is no-op`
- `scale value above max -> field error populated`
- `multi_choice below minSelections -> error`
- `submit success -> Submitted; submit 422 -> Ready with server field errors`
- `unknown field type -> fallback rendered, no crash`
- `condition referencing missing field -> field visible, warning logged`

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

AC-2 All 11 supported field types have a render-and-capture test; an unknown type
renders a fallback without crashing.

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
