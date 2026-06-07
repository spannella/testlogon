---
id: AND-347
title: Dynamic form renderer
milestone: M7
epic: E45
priority: P1
size: L
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-346, AND-020]
blocks: [AND-348, AND-349, AND-350]
---

# AND-347 — Dynamic form renderer

## 1. Overview & Goal

Build a schema-driven Compose renderer that turns a published questionnaire's
question list into interactive form UI and captures respondent input into a
single observable answer map. Given a list of typed `Question` models (produced
by AND-346's DTO→domain mapping) the renderer must draw the correct composable
for every supported field type, surface label/hint/required affordances, and emit
each user edit through a stable callback keyed by `question_id`.

This ticket owns **rendering and input capture only**. It deliberately excludes
networking (AND-346), session start/save/resume (AND-348), submit + PDF
(AND-349), conditional visibility and validation rules (AND-350), and the
top-level form state machine / ViewModel (AND-351). The renderer is a pure,
stateless-by-default UI layer: it receives `Map<String, AnswerValue>` and a
`(String, AnswerValue) -> Unit` mutation callback and renders accordingly. This
keeps it unit/screenshot testable in isolation and lets the surrounding tickets
plug in state, validation, and branching without changing renderer internals.

Done means: every field type listed in §3 renders correctly across empty,
filled, disabled, and error states, and each captures input that round-trips out
through the callback. Acceptance from the backlog — "All field types render +
capture input" — is verified by Compose UI tests (groundwork in AND-046/AND-048
patterns; renderer-specific tests land here, broader suite in AND-352).

## 2. Context & References

- Backlog: AND-347 (Feature, P1, Deps AND-346 + AND-020), epic E45 (Questionnaires),
  milestone M7.
- Module: lives in `feature-questionnaire`
  (`com.testlogon.android.feature.questionnaire.render`), depending on `core-ui`
  (`com.testlogon.android.core.ui`) for input primitives and `core-model`
  (`com.testlogon.android.core.model.questionnaire`) for the domain types.
- AND-346 provides the domain models (`Question`, `QuestionType`,
  `QuestionConfig`, `PublishedQuestionnaire`, `Section`) and their Moshi
  adapters. The backend transports questions as a free-form object: each question
  carries `question_id`, `type` (string, `maxLength 32`), `label`, `required`,
  `hint`, and an open `config_json` object. **Verified** against
  `QuestionCreateReq` (`type` is `string maxLength 32`; `config_json` is an
  open `object`, `additionalProperties: true`) and `PublishedQuestionnaireEnvelope`
  (a single open `version` object) in the backend OpenAPI. **Correction:** the
  published questionnaire does NOT expose questions directly on
  `PublishedQuestionnaireEnvelope.version`; per the web client the respondent
  schema is nested under `version.schema_json.sections[].questions[]`
  (see `src/api/types.ts: PublishedQuestionnaireVersion.schema_json` and
  `src/pages/questionnaires/QuestionnaireRespondentPage.tsx`).
  AND-346 normalizes `type` into the `QuestionType` enum and parses `config_json`
  into a typed `QuestionConfig`. This renderer consumes those typed models.
  **Canonical `type` strings (Verified against `src/api/types.ts:
  QuestionnaireQuestionType` and `src/pages/questionnaires/questionConfig.ts:
  BuilderQuestionType`): `text`, `select`, `multiselect`, `radio`, `slider`,
  `date`, `time`, `timezone`, `address` — nine types, not the larger speculative
  set originally drafted in §3.** See the §3 correction note and the §16 audit.
- AND-020 provides reusable input composables: `TlTextField` (error/helper
  support), `TlPasswordField`, `TlButton`, and `TlOtpField`. The renderer reuses
  `TlTextField` for text/number/email; it does not reimplement primitives.
- Web reference: `frontend/src/api/endpoints/questionnaires.ts` and the published
  respondent renderer under `frontend/src/` are the source of truth for which
  field `type` strings exist and how `config_json` is interpreted; mirror those
  type strings exactly.
- Answer transport shape (consumed downstream by AND-348 `SessionSaveReq`):
  `answers_by_question_id: { [question_id]: value }`. The renderer's output map
  must serialize cleanly into that field.

## 3. Functional Requirements

The renderer MUST support these field types. **CORRECTED (was wrong in the
draft):** the canonical `type` strings are exactly the nine the web client
declares — see `src/api/types.ts: QuestionnaireQuestionType` and
`src/pages/questionnaires/questionConfig.ts`. The earlier draft list invented
types (`short_text`, `paragraph`, `number`, `email`, `phone`, `single_choice`,
`multiple_choice`, `dropdown`, `scale`, `rating`, `boolean`/`yes_no`, `datetime`,
`upload`/`file`, `signature`) that do NOT exist in the backend/web contract. They
have been removed. Each `config.*` key below is the **verified** `config_json`
key the web builder writes (`src/pages/questionnaires/questionConfig.ts:
defaultConfigForType` + `QuestionTypeConfigEditor.tsx`).

- `text` → single-line text input. `config.minLength`, `config.maxLength`,
  optional `config.pattern` (regex). (Web default: `{minLength:0, maxLength:200}`.)
- `select` → single-select chooser (Material 3 `ExposedDropdownMenuBox`) from
  `config.options` (a **`List<String>`**, not objects). One value emitted.
- `multiselect` → checkbox group (zero-or-more) from `config.options`
  (`List<String>`); honors `config.minSelections` / `config.maxSelections`.
- `radio` → radio group (one selectable) from `config.options` (`List<String>`).
- `slider` → discrete slider/segmented selector across
  `config.min..config.max` stepping by `config.step` (web default
  `{min:0, max:10, step:1}`). There are NO `minLabel`/`maxLabel` keys in the
  contract; endpoint labels, if any, must be derived from `min`/`max`.
- `date` → date picker (Material 3 `DatePicker`), ISO-8601 `yyyy-MM-dd` value;
  optional bounds `config.minDate` / `config.maxDate`.
- `time` → time picker, `HH:mm` value; optional `config.minTime` /
  `config.maxTime`.
- `timezone` → timezone chooser; allowed set `config.allowedTimezones`
  (`List<String>`; empty = all).
- `address` → structured address group; `config.requiredFields`
  (`List<String>`, web default `["line1","city","country"]`).

> Note: file upload / signature / number / email / phone are **not** part of the
> current questionnaire contract and have been dropped from scope. If the product
> later adds them, they arrive as new `type` strings and are safely caught by the
> `UNKNOWN` fallback below until the renderer adds support. (Original draft scope
> for upload/signature is now an explicit deferred assumption — see §16.)

Cross-cutting requirements:

- Each question renders its `label`; required questions append a visual required
  marker. `hint` renders as supporting/helper text below the control.
- An unknown/unsupported `type` MUST render a non-crashing fallback
  (`UnsupportedFieldPlaceholder`) showing the raw type and label, and MUST NOT
  throw. This protects against backend adding a `type` ahead of the app.
- Every control reflects an incoming value (rehydration) and emits changes via
  `onAnswerChanged(questionId, AnswerValue)`. Clearing a control emits
  `AnswerValue.Empty` (so downstream can distinguish "answered then cleared").
- The renderer accepts an `enabled: Boolean` (read-only/submitting) and a
  per-question `error: String?` (supplied by AND-350 validation) and renders it.
- Choice options preserve backend order. **Corrected:** in the web contract
  `config.options` is a plain `List<String>` (e.g. `["Option 1","Option 2"]`),
  so both option identity and display are the string value itself — there is no
  `{id,label}` object. AND-346's `ChoiceOption` may keep an `id`/`label` pair for
  internal convenience, but it MUST be populated from the same string (id == label
  == the option string) so the emitted answer matches what the backend stores.
  (Verified: `src/pages/questionnaires/questionConfig.ts: defaultConfigForType`
  and `validateQuestionConfig`; `QuestionTypeConfigEditor.tsx` edits options as CSV.)
- The renderer does NOT own scroll/section paging — it renders a flat list of
  questions for one section; the section container (AND-348/AND-351) supplies the
  list and `LazyColumn` host.

## 4. Technical Design

Domain types (owned by AND-346, referenced here). **CORRECTED** to the verified
nine-type contract (`src/api/types.ts: QuestionnaireQuestionType`,
`src/pages/questionnaires/questionConfig.ts`):

```kotlin
package com.testlogon.android.core.model.questionnaire

enum class QuestionType {
    TEXT, SELECT, MULTISELECT, RADIO, SLIDER,
    DATE, TIME, TIMEZONE, ADDRESS, UNKNOWN
}

data class Question(
    val questionId: String,
    val type: QuestionType,
    val rawType: String,        // preserved for UNKNOWN fallback display
    val label: String,
    val required: Boolean,
    val hint: String?,
    val config: QuestionConfig, // parsed from config_json
)

// Keys below are the verified config_json keys per type
// (questionConfig.ts: defaultConfigForType + QuestionTypeConfigEditor.tsx).
data class QuestionConfig(
    val options: List<String> = emptyList(),       // select/multiselect/radio (strings, not objects)
    val minLength: Int? = null,                    // text
    val maxLength: Int? = null,                    // text
    val pattern: String? = null,                   // text (regex)
    val minSelections: Int? = null,                // multiselect
    val maxSelections: Int? = null,                // multiselect
    val min: Int? = null,                          // slider
    val max: Int? = null,                          // slider
    val step: Int? = null,                         // slider
    val minDate: String? = null,                   // date (yyyy-MM-dd)
    val maxDate: String? = null,                   // date
    val minTime: String? = null,                   // time (HH:mm)
    val maxTime: String? = null,                   // time
    val allowedTimezones: List<String> = emptyList(), // timezone (empty = all)
    val requiredFields: List<String> = emptyList(),   // address
)
```

> `ChoiceOption(id, label)` from the original draft is dropped: the contract uses
> plain option strings. If AND-346 keeps a `ChoiceOption` wrapper it must set
> `id == label ==` the option string (see §3 correction).

Answer value model (owned by this ticket, in `core-model` so AND-348 can
serialize it):

**CORRECTED** to the value shapes the web client actually stores in
`answers_by_question_id` (`QuestionnaireRespondentPage.tsx`: answers are raw
strings, string-arrays, and numbers; `Bool`/`Choice(optionId)`/`Files`
variants from the draft do not correspond to any contract type and are removed):

```kotlin
sealed interface AnswerValue {
    data object Empty : AnswerValue
    data class Text(val value: String) : AnswerValue          // text/date/time/timezone -> string
    data class Number(val value: Double) : AnswerValue         // slider -> number
    data class Choice(val option: String) : AnswerValue        // select/radio -> option STRING
    data class MultiChoice(val options: List<String>) : AnswerValue // multiselect -> string[]
    data class AddressValue(val fields: Map<String, String>) : AnswerValue // address -> object
}
```

> `date`/`time`/`timezone` serialize as plain strings (`Text`); the web does not
> use a distinct date type in the answer map. `slider` serializes as a JSON number.
> `address` serializes as a JSON object keyed by `requiredFields` entries. All of
> these flow through `answers_by_question_id` (open object) unchanged.

Public renderer surface (this ticket):

```kotlin
package com.testlogon.android.feature.questionnaire.render

@Composable
fun QuestionField(
    question: Question,
    value: AnswerValue,
    onAnswerChanged: (questionId: String, value: AnswerValue) -> Unit,
    enabled: Boolean = true,
    error: String? = null,
    modifier: Modifier = Modifier,
)

@Composable
fun QuestionList(
    questions: List<Question>,
    answers: Map<String, AnswerValue>,
    onAnswerChanged: (questionId: String, value: AnswerValue) -> Unit,
    enabled: Boolean = true,
    errors: Map<String, String> = emptyMap(),
    modifier: Modifier = Modifier,
)
```

`QuestionField` is a `when (question.type)` dispatcher to private per-type
composables (`TextFieldQuestion`, `SelectQuestion`, `MultiSelectQuestion`,
`RadioQuestion`, `SliderQuestion`, `DatePickerQuestion`, `TimePickerQuestion`,
`TimezoneQuestion`, `AddressQuestion`, plus `UnsupportedFieldPlaceholder`). Each
per-type composable is independently previewable and testable.
`QuestionList` renders questions inside the caller-provided list (no internal
`LazyColumn`; it emits an `@Composable` column of `QuestionField`s so AND-351 can
host it in a `LazyColumn` with stable `key = question.questionId`).

Stateless design: the renderer holds no remembered answer state beyond transient
UI bits (e.g. dropdown expanded flag, picker-open flag) via
`rememberSaveable`. Authoritative answer state lives in the caller's ViewModel
(AND-351). Decimal/number parsing is local: the raw text is kept in
`rememberSaveable` to allow intermediate states (e.g. `"-"`, `"1."`), but only a
parseable value emits `AnswerValue.Number`; unparseable text emits
`AnswerValue.Empty` plus a local format hint.

**Corrected:** the current contract has no `upload`/`signature`/file types, so
no `ActivityResult` file pickers, `GetMultipleContents`, draw surface, or
`takePersistableUriPermission` handling is needed in this ticket. (If those
types are added later they enter via the `UNKNOWN` fallback and would be a
follow-up ticket.) Timezone/address pickers are pure in-Compose controls; `date`
and `time` use Material 3 `DatePicker` / `TimePicker` only.

## 5. API Contract

No direct network calls in this ticket — the renderer is a pure UI layer.
Network ownership: questionnaire fetch + DTOs (AND-346); session
start/save/validate (AND-348); submit/PDF (AND-349).

For traceability, the upstream/downstream shapes this renderer is wired against:

- Source question (from `GET /questionnaires/published/{published_slug}` →
  `PublishedQuestionnaireEnvelope.version.schema_json.sections[].questions[]`),
  per-question fields normalized by AND-346. **Corrected** example uses a real
  `type` (`slider`) and real `config_json` keys (`min`/`max`/`step`; no
  `minLabel`/`maxLabel`):

```json
{
  "question_id": "q_age",
  "type": "slider",
  "label": "Rate your experience",
  "required": true,
  "hint": "1 = poor, 10 = excellent",
  "config_json": { "min": 1, "max": 10, "step": 1 }
}
```

- Captured answer map (consumed by AND-348
  `PUT /questionnaires/published/{published_slug}/sessions/{response_session_id}`,
  `SessionSaveReq.answers_by_question_id`):

```json
{
  "answers_by_question_id": {
    "q_age": 4,
    "q_email": "a@b.com",
    "q_topics": ["t1", "t3"],
    "q_consent": true,
    "q_when": "2026-06-05"
  }
}
```

The renderer maps each `AnswerValue` to its JSON-serializable scalar/array form
via a pure `AnswerValue.toJsonValue(): Any?` helper (also in this ticket), so
AND-348 only assembles the outer object. `AnswerValue.Empty` → key omitted.

## 6. Data & State Management

- **Source of truth:** the caller's `StateFlow<UiState>` (AND-351) holds
  `answers: Map<String, AnswerValue>` and `errors: Map<String, String>`. The
  renderer is a one-way function of those plus the question list.
- **Transient UI state:** dropdown-expanded, picker-open, and in-progress
  numeric/text strings live in `rememberSaveable` inside per-type composables and
  are NOT lifted to the ViewModel.
- **Rehydration:** on recomposition / process restore the renderer reflects the
  incoming `value`. Number/decimal in-progress text is `rememberSaveable` keyed
  by `question.questionId` so partial entry survives rotation.
- **Stability:** `Question` and `AnswerValue` are immutable data classes
  (Compose-stable). `onAnswerChanged` should be a stable lambda (caller
  uses a remembered reference) to avoid recomposing the whole list on each edit.
- **Keys:** list items keyed by `questionId`; choice items keyed by the option
  string value (options are `List<String>` — see §3 correction).
- **Empty vs unanswered:** unanswered = key absent from `answers` (renderer
  receives `AnswerValue.Empty`); explicitly cleared = caller stores
  `AnswerValue.Empty`. Downstream validation (AND-350) distinguishes required
  failures from these.

## 7. Error Handling & Resilience

- **Unknown type:** `UNKNOWN`/unrecognized `rawType` renders
  `UnsupportedFieldPlaceholder(label, rawType)` — visible, non-interactive,
  never throws. Logged once per type (see §10).
- **Malformed config:** a choice (`select`/`multiselect`/`radio`) or `slider`
  with missing `options`/`min`/`max` degrades gracefully: choice with no options
  renders the label + an inline "No options available" note; `slider` with
  missing/invalid bounds defaults to `0..10 step 1` (matching the web default).
  No crash.
- **Slider bounds parsing:** non-numeric/invalid `min`/`max`/`step` fall back to
  the web default rather than throwing; the emitted value is always clamped to
  the effective `min..max`.
- **No network here:** timeouts/backoff/offline/401-refresh are owned by
  core-network (AND-009/016/013) and the fetch/session tickets (AND-346/348).
  The renderer must remain fully functional with stale/offline-loaded schema
  (it operates purely on in-memory models).
- **Validation errors:** the renderer only *displays* `error: String?`; it never
  computes validation (AND-350 owns rules).

## 8. Security & Privacy

- Respondent answers are PII. The renderer never logs answer values or
  `config_json` content (see §10); logs reference `questionId` and `type` only.
- No file/upload/signature capture in this ticket (those types are not in the
  contract — see §3 correction), so there are no `content://` URIs, persisted URI
  permissions, or local file bytes handled by the renderer.
- No clipboard auto-read; paste is user-initiated via standard IME.
- The public respond flow may be unauthenticated. **Verified** transport: the web
  client sends `Authorization: Bearer <token>` (from its auth store),
  `X-CSRF-Token` (read from the `ui_csrf` cookie), and `credentials: "include"`,
  with auto-refresh on 401 via `POST /ui/session/refresh`
  (`src/api/client.ts`). The renderer MUST NOT assume an auth/session context or
  read cookies/CSRF — those belong to the Android core-network interceptors
  (AND-011/012/013).
- Screenshots / `FLAG_SECURE`: an app-shell decision, not owned here; flagged as
  open question §13.

## 9. Accessibility & i18n

- Every control has a content description / semantics label derived from
  `label`; required state is announced (`stateDescription` "required").
- Choice options (`select`/`radio`) expose `Role.RadioButton`; `multiselect`
  exposes `Role.Checkbox`; `slider` exposes slider value semantics ("4 of 10").
- Minimum 48dp touch targets for radio/checkbox/slider thumb/segments.
- `error` text is associated via `semantics { error(it) }` for TalkBack.
- All renderer-owned literal strings ("No options available", required marker,
  slider/timezone/address labels) come from `strings.xml`; no hardcoded
  user-facing English. Question `label`/`hint`/option labels are
  backend-provided and rendered as-is (server is the localization authority).
- Date/time formatting uses the device locale for display; the *stored* value is
  always ISO-8601 (locale-independent) for `SessionSaveReq`.
- RTL: layouts use start/end (not left/right); verified with `LayoutDirection.Rtl`.

## 10. Telemetry & Logging

- Lightweight, debug-only structured logs via the app's logger (Timber or
  core logging wrapper). Events: `field_rendered{type}` (sampled/once-per-type),
  `unsupported_field_type{rawType}` (warn, once per distinct type),
  `field_capture_error{questionId,type,reason}`.
- **PII rule:** never log answer values, option labels, or config contents.
  Log only `questionId`, `QuestionType`, and error reason codes.
- No analytics SDK calls in this ticket; if a product analytics event for
  "questionnaire field interacted" is needed it belongs to AND-351's ViewModel
  layer, which already observes answer changes.

## 11. Testing Strategy

Compose UI + unit tests (this ticket; broader suite AND-352):

- **Per-type render tests** (`createComposeRule`): for each `QuestionType`,
  assert the expected node exists and the label/hint/required marker show.
- **Capture tests:** drive input (type text, pick select/radio option, toggle
  multiselect checkboxes, drag slider, pick date/time/timezone, fill address) and
  assert `onAnswerChanged` is invoked with the exact `AnswerValue` (use a
  recording lambda). This is the literal acceptance criterion "render + capture
  input".
- **Rehydration tests:** pass a non-empty `value` and assert the control shows
  it (selected option, filled text, chosen date, slider position).
- **Clear test:** clearing a control emits `AnswerValue.Empty`.
- **Unknown type test:** `UNKNOWN`/garbage `rawType` renders the placeholder and
  does not throw.
- **Malformed config tests:** choice w/ empty `options`, slider w/ null/invalid
  `min`/`max`/`step` (defaults to `0..10 step 1`).
- **`toJsonValue` unit tests:** each `AnswerValue` variant maps to the correct
  JSON scalar/array/object; `Empty` → null/omitted.
- **Slider parsing unit tests:** valid bounds, clamping, default-on-malformed.
- **Rotation/state-restore test:** in-progress text/slider state survives recreate.
- **Accessibility assertions:** roles + required semantics present.
- Reuse fixtures from the MockWebServer harness (AND-046) only for realistic
  `Question` JSON → model inputs (decoding owned by AND-346); renderer tests
  feed domain models directly.

## 12. Dependencies & Sequencing

- **Depends on AND-346** (Questionnaire API + DTOs): supplies `Question`,
  `QuestionType` (the nine verified values), `QuestionConfig`, `Section`, and the
  `type`/`config_json` normalization the renderer dispatches on. Hard blocker —
  the renderer cannot be built against untyped maps.
- **Depends on AND-020** (Core input composables): reuses `TlTextField`
  (error/helper), keyboard options, and patterns for password/OTP; the renderer
  must not duplicate these primitives.
- **Indirectly relies on** core-ui Material 3 theme (AND-019) for styling and
  core-model module (AND-003) for placing `AnswerValue`.
- **Blocks AND-348** (respondent session save/resume — needs the answer map +
  `toJsonValue`), **AND-349** (submit/PDF — needs captured answers), and
  **AND-350** (conditional logic/validation — renders the `error` slot and
  respects an externally controlled visibility filter).
- **Consumed by AND-351** (ViewModel/form state machine) and exercised by
  **AND-352** (renderer + validation test suite).
- Sequencing: land after AND-346 model is merged; AND-351 wires it; AND-350 layers
  validation/branching on top without modifying renderer signatures.

## 13. Risks & Open Questions

- **Type taxonomy — RESOLVED in review:** backend `type` is a free-form string
  (`maxLength 32`, verified in `QuestionCreateReq`), but the web client constrains
  it to nine values (`text, select, multiselect, radio, slider, date, time,
  timezone, address` — `src/api/types.ts: QuestionnaireQuestionType`). The
  renderer dispatches on those nine; any future/unknown `type` is absorbed by the
  `UNKNOWN` fallback. AND-346 must normalize to the same nine.
- **config_json shape per type — RESOLVED in review:** keys verified against
  `src/pages/questionnaires/questionConfig.ts` and `QuestionTypeConfigEditor.tsx`
  (`options` as `string[]`, `slider` `min/max/step`, `text` `minLength/maxLength/
  pattern`, `multiselect` `minSelections/maxSelections`, `date` `minDate/maxDate`,
  `time` `minTime/maxTime`, `timezone` `allowedTimezones`, `address`
  `requiredFields`). Remaining risk: AND-346's parser must use these exact names.
- **FLAG_SECURE on PII screens** — decide at app-shell level; not owned here.
  Open question.
- **`slider` render style** — the web models it as a numeric slider
  (`min/max/step`); whether to render as a Material 3 `Slider` vs a discrete
  segmented control is a UX choice. Either emits the same numeric `AnswerValue`.
- **`address` / `timezone` UX depth** — the web stores address as an object keyed
  by `requiredFields` and timezone as a string from `allowedTimezones`; the first
  Android pass may use simple text/grouped fields and a timezone dropdown.

## 14. Acceptance Criteria

1. For every supported `QuestionType` in §3, `QuestionField` renders the correct
   control with label, optional hint, and required marker.
2. Each control captures user input and emits the correct `AnswerValue` through
   `onAnswerChanged(questionId, value)` — verified by recording-lambda UI tests
   (the backlog acceptance: "All field types render + capture input").
3. Passing an existing `value` rehydrates the control (selected option, filled
   text, chosen date, slider position).
4. Clearing a control emits `AnswerValue.Empty`; cleared keys serialize as
   omitted/null via `toJsonValue`.
5. An unknown/unsupported `type` renders `UnsupportedFieldPlaceholder` and never
   throws; malformed configs degrade gracefully (no crash).
6. `error: String?` and `enabled: Boolean` are honored: error text shows with
   correct semantics; disabled controls are non-interactive.
7. `AnswerValue.toJsonValue()` produces JSON-serializable values matching the
   `answers_by_question_id` shape consumable by AND-348's `SessionSaveReq`.
8. All renderer-owned strings are in `strings.xml`; controls expose accessibility
   roles, required state, and error semantics; 48dp targets; RTL-safe.
9. Renderer holds no authoritative answer state and makes no network calls.

## 15. Definition of Done

- `QuestionField`, `QuestionList`, the `AnswerValue` sealed interface, per-type
  composables, `UnsupportedFieldPlaceholder`, and `AnswerValue.toJsonValue()` are
  implemented in `feature-questionnaire` (+ `AnswerValue` in `core-model`),
  using only `com.testlogon.android.*` packages.
- All per-type composables have `@Preview`s covering empty/filled/disabled/error.
- Compose UI + unit tests from §11 pass in CI (AND-050 unit-test job); coverage
  includes every `QuestionType`, the unsupported-type fallback, rehydration,
  clear, and `toJsonValue`.
- Lint/detekt/ktlint clean (AND-005); no hardcoded user-facing strings; no PII in
  logs.
- Public API reviewed with AND-351 owner so the ViewModel can host `QuestionList`
  without renderer changes; AND-348/AND-350 owners sign off that the answer map +
  `error` slot meet their needs.
- Merged to `android-port`; no new dependencies beyond core-ui/core-model and the
  AndroidX Material 3 DatePicker/TimePicker APIs already on the stack.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **`Question.type` is a string with `maxLength 32`** — VERIFIED.
   Source: OpenAPI `POST /questionnaires/drafts/{questionnaire_id}/questions`,
   schema `QuestionCreateReq.type` (`type: string, maxLength: 32, minLength: 1`).
2. **`config_json` is an open object on the question** — VERIFIED.
   Source: `QuestionCreateReq.config_json` (`type: object, additionalProperties:
   true`); `src/api/types.ts: QuestionnaireQuestion.config_json:
   Record<string, unknown>`.
3. **Canonical field `type` strings are the nine: `text, select, multiselect,
   radio, slider, date, time, timezone, address`** — CORRECTED (draft listed an
   invented superset incl. `number/email/phone/single_choice/multiple_choice/
   dropdown/scale/rating/boolean/datetime/upload/signature`).
   Source: `src/api/types.ts: QuestionnaireQuestionType`;
   `src/pages/questionnaires/questionConfig.ts: BuilderQuestionType`.
4. **`config.options` is a `List<String>`, not `{id,label}` objects** — CORRECTED.
   Source: `src/pages/questionnaires/questionConfig.ts: defaultConfigForType`
   (`{ options: ["Option 1","Option 2"] }`) and `validateQuestionConfig`;
   `QuestionTypeConfigEditor.tsx` (options edited as CSV → `string[]`).
5. **`slider` config keys are `min`/`max`/`step` (no `minLabel`/`maxLabel`)** —
   CORRECTED (draft used `scale` with `minLabel`/`maxLabel`).
   Source: `questionConfig.ts: defaultConfigForType` (`{min:0,max:10,step:1}`) +
   `validateQuestionConfig` slider branch; `QuestionTypeConfigEditor.tsx`
   (`Slider min`/`Slider max`/`Slider step`).
6. **`text` config keys are `minLength`/`maxLength`/`pattern`** — VERIFIED/added.
   Source: `questionConfig.ts` (`{minLength:0,maxLength:200}`);
   `QuestionTypeConfigEditor.tsx` (Min length / Max length / Regex pattern).
7. **`multiselect` adds `minSelections`/`maxSelections`** — VERIFIED.
   Source: `questionConfig.ts: validateQuestionConfig` multiselect branch;
   `QuestionTypeConfigEditor.tsx`.
8. **`date`=`minDate/maxDate`, `time`=`minTime/maxTime`, `timezone`=
   `allowedTimezones`, `address`=`requiredFields`** — VERIFIED.
   Source: `questionConfig.ts: defaultConfigForType`; `QuestionTypeConfigEditor.tsx`.
9. **Published questions live at `version.schema_json.sections[].questions[]`,
   not directly on `PublishedQuestionnaireEnvelope.version`** — CORRECTED.
   Source: `src/api/types.ts: PublishedQuestionnaireVersion.schema_json`;
   `src/pages/questionnaires/QuestionnaireRespondentPage.tsx` (`version.schema_json
   .sections` → `section.questions`).
10. **Fetch endpoint: `GET /questionnaires/published/{published_slug}` →
    `PublishedQuestionnaireEnvelope`** — VERIFIED.
    Source: OpenAPI index line `GET /questionnaires/published/{published_slug}`;
    `src/api/endpoints/questionnaires.ts: getPublishedQuestionnaireBySlug`.
11. **Save endpoint is `PUT /questionnaires/published/{published_slug}/sessions/
    {response_session_id}` with body `SessionSaveReq`** — VERIFIED.
    Source: OpenAPI index line for that PUT (`req=SessionSaveReq`);
    `src/api/endpoints/questionnaires.ts: savePublishedResponseSessionState`.
12. **`SessionSaveReq.answers_by_question_id` is an open object (raw scalars/
    arrays/objects keyed by question_id)** — VERIFIED.
    Source: OpenAPI `SessionSaveReq` (props `answers_by_question_id` object,
    `current_question_id`, `current_section_index`);
    `QuestionnaireRespondentPage.tsx` (answers map of string/string[]/number).
13. **Answer values are plain strings / string-arrays / numbers / objects, not a
    `Choice(optionId)`/`Bool`/`Files` taxonomy** — CORRECTED (`AnswerValue`
    reshaped: `Text`, `Number`, `Choice(option:String)`, `MultiChoice(List<String>)`,
    `AddressValue(Map)`).
    Source: `QuestionnaireRespondentPage.tsx` (`stringifyAnswer`, array join,
    raw `<Input>` value) and `questionConfig.ts` option/value shapes.
14. **No `upload`/`file`/`signature`/`number`/`email`/`phone` types exist in the
    contract; upload/signature scope is dropped** — CORRECTED (draft §3/§4/§7/§8
    described file pickers, `GetMultipleContents`, draw surface,
    `takePersistableUriPermission`).
    Source: absence from `QuestionnaireQuestionType` / `questionConfig.ts` (only
    the nine types).
15. **Web transport uses `Authorization: Bearer`, `X-CSRF-Token` from the
    `ui_csrf` cookie, `credentials: include`, and 401 auto-refresh via
    `POST /ui/session/refresh`** — VERIFIED (renderer correctly delegates this to
    core-network, owns none of it).
    Source: `src/api/client.ts` (`getCookie("ui_csrf")` → header `X-CSRF-Token`;
    `Authorization` Bearer from `useAuthStore`; refresh fetch to
    `/ui/session/refresh`).
16. **Validation error shape is `errors: { [questionId|group:*|form:*]:
    Array<{message, blocking?}> }` plus `can_submit`** — VERIFIED (informs the
    `error: String?` slot and test error fixtures).
    Source: `QuestionnaireRespondentPage.tsx` (`errorMap`, `fieldErrors`,
    `groupOrFormErrors`, `can_submit`); validate body adds `final_submit`.
17. **HTTP 422 validation errors use `HTTPValidationError { detail:
    ValidationError[] }`** — VERIFIED (the generic transport error shape; not
    surfaced by the renderer, but used by contract tests upstream).
    Source: OpenAPI `components.schemas.HTTPValidationError` →
    `#/components/schemas/ValidationError`.
18. **Compose stateless renderer / `rememberSaveable` for transient UI; Material 3
    `DatePicker`/`TimePicker`; `Role.RadioButton`/`Role.Checkbox`;
    `semantics { error() }`; 48dp targets** — UNVERIFIED-ASSUMPTION (Android
    framework design choices, not derivable from backend/web sources).
    Source: framework ref — Jetpack Compose state
    (https://developer.android.com/develop/ui/compose/state),
    Material 3 date/time pickers
    (https://developer.android.com/develop/ui/compose/components/datepickers),
    accessibility semantics
    (https://developer.android.com/develop/ui/compose/accessibility).

### Corrections made

- §2/§3/§4/§13: Replaced the speculative field-type list with the nine
  contract-verified types (`text, select, multiselect, radio, slider, date, time,
  timezone, address`); rewrote the `QuestionType` enum accordingly (citations 3).
- §3/§4/§6: `config.options` is `List<String>`; dropped `ChoiceOption(id,label)`
  identity (citation 4).
- §3/§4/§5/§7: `slider` uses `min/max/step`; removed `scale`/`rating` and
  `minLabel`/`maxLabel`; default `0..10 step 1` on malformed config (citation 5).
- §4: `QuestionConfig` keys rewritten to the verified per-type keys (citations
  4–8).
- §4: `AnswerValue` reshaped to string/number/choice-string/list/address-object
  variants; removed `Bool`, `Choice(optionId)`, `Scalar`, `DateValue`, `Files`
  (citation 13).
- §3/§4/§7/§8: Removed upload/signature/file-picker/`takePersistableUriPermission`
  scope and number/email/phone types (citation 14).
- §2/§5: Source of questions corrected to
  `version.schema_json.sections[].questions[]` (citation 9).
- §8: Replaced vague CSRF/cookie wording with the verified transport mechanism
  and confirmed the renderer owns none of it (citation 15).
- §9/§11/§14/§DoD: Updated control/role/test references to the real types and
  Material 3 pickers (no ActivityResult dependency).

### Open assumptions

- Compose/Material 3 implementation details (citation 18) cannot be verified from
  backend/web sources; they are standard Android framework choices and are
  labeled as framework refs.
- The exact normalization AND-346 performs (string `type` → enum; `config_json` →
  typed `QuestionConfig`) is owned by AND-346 and assumed to use the key names in
  citations 3–8. If AND-346 lands different names, the renderer's `when` and config
  reads must be updated.
- `address` answer object key set and `timezone` value source: assumed to mirror
  `config.requiredFields` / `config.allowedTimezones`; the backend stores these in
  the open `answers_by_question_id` object, so exact internal address keying is an
  AND-348/AND-349 serialization detail not pinned by the sources.
- The web respondent page renders every type as a generic text `<Input>` (it does
  not branch per type); per-type Android controls are an intentional richer
  implementation, so the *visual* mapping per type is an Android-side decision
  (the value shapes, however, are pinned by citations 12–13).

## 17. Test Plan

Test-target legend: JVM = local JVM/Robolectric unit; MWS = MockWebServer
contract; Compose-UI = `createComposeRule` on emulator AVD `test35` (API 35,
x86_64); instrumented = on-device; physical = Samsung Galaxy A15 5G (SM-A156U,
API 34, arm64-v8a). Acceptance-criteria references point at §14.

- **TC-AND-347-01** — Type: Compose-UI. Target: emulator `test35`.
  Preconditions: a `Question` of each of the nine types with label/hint/required.
  Steps: render `QuestionField` for each type. Expected: the correct control
  exists (text field / dropdown / checkbox group / radio group / slider /
  DatePicker / TimePicker / timezone dropdown / address group); label shown, hint
  shown when present, required marker shown when `required=true`.
  Traces: AC-1.

- **TC-AND-347-02** — Type: Compose-UI. Target: emulator `test35`.
  Preconditions: recording `onAnswerChanged` lambda; one question per type.
  Steps: enter text; pick a `select`/`radio` option; toggle two `multiselect`
  boxes; drag `slider`; pick a date and a time; choose a timezone; fill address
  fields. Expected: each emits the exact `AnswerValue` — `Text`, `Choice(option
  string)`, `MultiChoice(List<String>)`, `Number`, `Text("yyyy-MM-dd")`,
  `Text("HH:mm")`, `Text(tz)`, `AddressValue(map)`. Traces: AC-2.

- **TC-AND-347-03** — Type: Compose-UI. Target: emulator `test35`.
  Preconditions: non-empty `value` supplied for each type.
  Steps: render and inspect. Expected: control reflects the value (filled text,
  selected option(s), slider at position, chosen date/time/timezone, populated
  address). Traces: AC-3.

- **TC-AND-347-04** — Type: Compose-UI. Target: emulator `test35`.
  Preconditions: a control with an existing value + recording lambda.
  Steps: clear the control (delete text / deselect). Expected: emits
  `AnswerValue.Empty`. Traces: AC-4.

- **TC-AND-347-05** — Type: JVM unit. Target: JVM/Robolectric.
  Preconditions: each `AnswerValue` variant constructed.
  Steps: call `toJsonValue()`. Expected: `Text`→String, `Number`→Double/JSON
  number, `Choice`→String, `MultiChoice`→`List<String>`, `AddressValue`→Map,
  `Empty`→null (key omitted). Output is JSON-serializable into
  `answers_by_question_id`. Traces: AC-4, AC-7.

- **TC-AND-347-06** — Type: Compose-UI. Target: emulator `test35`.
  Preconditions: a `Question` with `type=UNKNOWN` and a garbage `rawType`
  (e.g. `"hologram"`).
  Steps: render `QuestionField`. Expected: `UnsupportedFieldPlaceholder` shows the
  raw type + label, is non-interactive, and no exception is thrown. Traces: AC-5.

- **TC-AND-347-07** — Type: JVM unit + Compose-UI. Target: JVM + emulator
  `test35`. Preconditions: `select`/`radio` with empty `options`; `slider` with
  null/invalid `min`/`max`/`step`. Steps: render. Expected: choice shows label +
  "No options available" (no crash); slider falls back to `0..10 step 1` and emits
  a clamped value. Traces: AC-5.

- **TC-AND-347-08** — Type: JVM unit. Target: JVM/Robolectric.
  Preconditions: slider config edge values. Steps: parse and clamp `min/max/step`
  with valid, inverted (`max<min`), zero-step, and non-numeric inputs. Expected:
  valid passes through; invalid falls back to the web default; emitted value
  always within effective `min..max`. Traces: AC-5.

- **TC-AND-347-09** — Type: Compose-UI (state restore). Target: emulator `test35`.
  Preconditions: a text/slider control mid-edit. Steps: trigger recreate
  (rotation / `StateRestorationTester`). Expected: in-progress text and slider
  position survive via `rememberSaveable`; authoritative answer unchanged.
  Traces: AC-9.

- **TC-AND-347-10** — Type: Compose-UI. Target: emulator `test35`.
  Preconditions: `QuestionField` with `error="This field is required"` and
  `enabled=false`. Steps: render; attempt interaction. Expected: error text shown
  and associated via error semantics; control is non-interactive and emits nothing
  while disabled. Traces: AC-6.

- **TC-AND-347-11** — Type: MWS contract. Target: JVM + MockWebServer
  (fixtures from AND-046). Preconditions: a `GET /questionnaires/published/
  {published_slug}` response whose `version.schema_json.sections[].questions[]`
  uses each real `type` + verified `config_json` keys; AND-346 decoder in the
  loop. Steps: decode → domain `Question` list → feed renderer. Expected: every
  question maps to a non-`UNKNOWN` type and renders; an injected unknown `type`
  string maps to `UNKNOWN` and renders the placeholder. Also assert a malformed
  options array does not crash decode→render. Traces: AC-1, AC-5, AC-7.

- **TC-AND-347-12** — Type: Compose-UI (accessibility). Target: emulator `test35`.
  Preconditions: one question per type, with TalkBack semantics assertions.
  Steps: assert roles (`Role.RadioButton` for `select`/`radio`, `Role.Checkbox`
  for `multiselect`, slider value semantics), required state announced, error
  semantics present, and touch targets ≥48dp; verify with
  `LayoutDirection.Rtl`. Expected: all semantics/roles present; RTL layout uses
  start/end. Traces: AC-8.

- **TC-AND-347-13** — Type: JVM unit. Target: JVM/Robolectric.
  Preconditions: a logger spy. Steps: render/capture across types incl. an
  unsupported type and a capture error. Expected: logs contain only `questionId`,
  `QuestionType`, and reason codes — never answer values, option strings, or
  `config_json` content. Traces: AC-8 (PII), supports §8/§10.

- **TC-AND-347-14** — Type: instrumented (physical). Target: physical Galaxy A15
  5G (API 34, arm64-v8a). Preconditions: full nine-type form rendered on real
  hardware. Steps: exercise the Material 3 `DatePicker`/`TimePicker` and IME
  keyboards with the real on-device locale; confirm date/time emit ISO/`HH:mm`
  strings regardless of device locale display. Expected: pickers behave on
  API 34/arm64 (catches API-34-vs-35 and ABI differences vs the emulator);
  stored values stay locale-independent. MUST run on the physical device because
  it validates real-hardware IME/picker + ABI/API-level behavior the x86_64
  API-35 emulator does not represent. Traces: AC-1, AC-2, AC-3.

### Coverage matrix

| §14 AC | Covered by |
|--------|-----------|
| AC-1 (renders correct control + label/hint/required) | TC-01, TC-11, TC-14 |
| AC-2 (captures + emits correct AnswerValue) | TC-02, TC-14 |
| AC-3 (rehydrates from existing value) | TC-03, TC-14 |
| AC-4 (clear → Empty; cleared serializes omitted/null) | TC-04, TC-05 |
| AC-5 (unknown type placeholder; malformed config no crash) | TC-06, TC-07, TC-08, TC-11 |
| AC-6 (error + enabled honored) | TC-10 |
| AC-7 (toJsonValue matches answers_by_question_id) | TC-05, TC-11 |
| AC-8 (strings.xml, a11y roles/required/error, 48dp, RTL; no PII logs) | TC-12, TC-13 |
| AC-9 (no authoritative state; no network) | TC-09 |
