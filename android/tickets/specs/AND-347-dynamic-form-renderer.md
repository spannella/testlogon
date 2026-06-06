---
id: AND-347
title: Dynamic form renderer
milestone: M7
epic: E45
priority: P1
size: L
status: draft
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
  `hint`, and an open `config_json` object (verified against
  `QuestionCreateReq`/`PublishedQuestionnaireEnvelope` in dev `/openapi.json`).
  AND-346 normalizes `type` into the `QuestionType` enum and parses `config_json`
  into a typed `QuestionConfig`. This renderer consumes those typed models.
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

The renderer MUST support these field types. The canonical `type` string (left)
matches the backend `Question.type` value normalized by AND-346.

- `text` / `short_text` → single-line text input.
- `paragraph` / `long_text` → multi-line text input (min 3 visible lines).
- `number` → numeric input, decimal keyboard, parses to `Double`/`Long`.
- `email` → text input with email keyboard + email IME action.
- `phone` → text input with phone keyboard.
- `single_choice` → radio group (one selectable) from `config.options`.
- `multiple_choice` → checkbox group (zero-or-more) from `config.options`.
- `dropdown` → exposed dropdown menu (Material 3 `ExposedDropdownMenuBox`).
- `scale` → discrete segmented selector across `config.min..config.max`
  (e.g. 1–5 / 1–10) with optional `minLabel`/`maxLabel` endpoints.
- `rating` → star row (count = `config.max`, default 5).
- `boolean` / `yes_no` → labeled switch or two-option toggle.
- `date` → date picker (Material 3 `DatePicker`), ISO-8601 `yyyy-MM-dd` value.
- `datetime` → date + time pickers, ISO-8601 value.
- `upload` / `file` → file/photo picker launcher producing a local content URI
  list (upload bytes are NOT transferred here; that is AND-349's submit path).
- `signature` → opens a draw-to-sign surface, captures a bitmap URI.

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
- Choice options preserve backend order; option identity is `option.id`, display
  is `option.label`.
- The renderer does NOT own scroll/section paging — it renders a flat list of
  questions for one section; the section container (AND-348/AND-351) supplies the
  list and `LazyColumn` host.

## 4. Technical Design

Domain types (owned by AND-346, referenced here):

```kotlin
package com.testlogon.android.core.model.questionnaire

enum class QuestionType {
    TEXT, LONG_TEXT, NUMBER, EMAIL, PHONE,
    SINGLE_CHOICE, MULTIPLE_CHOICE, DROPDOWN,
    SCALE, RATING, BOOLEAN, DATE, DATETIME,
    UPLOAD, SIGNATURE, UNKNOWN
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

data class QuestionConfig(
    val options: List<ChoiceOption> = emptyList(),
    val min: Int? = null,
    val max: Int? = null,
    val minLabel: String? = null,
    val maxLabel: String? = null,
    val multiline: Boolean = false,
    val accept: List<String> = emptyList(), // upload mime hints
)

data class ChoiceOption(val id: String, val label: String)
```

Answer value model (owned by this ticket, in `core-model` so AND-348 can
serialize it):

```kotlin
sealed interface AnswerValue {
    data object Empty : AnswerValue
    data class Text(val value: String) : AnswerValue
    data class Number(val value: Double) : AnswerValue
    data class Bool(val value: Boolean) : AnswerValue
    data class Choice(val optionId: String) : AnswerValue
    data class MultiChoice(val optionIds: List<String>) : AnswerValue
    data class Scalar(val value: Int) : AnswerValue          // scale / rating
    data class DateValue(val iso: String) : AnswerValue       // yyyy-MM-dd[THH:mm]
    data class Files(val uris: List<String>) : AnswerValue    // content:// uris
}
```

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
composables (`TextFieldQuestion`, `ChoiceQuestion`, `ScaleQuestion`,
`RatingQuestion`, `DatePickerQuestion`, `UploadQuestion`, `SignatureQuestion`,
etc.). Each per-type composable is independently previewable and testable.
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

File/signature launchers use `rememberLauncherForActivityResult` with
`ActivityResultContracts.GetMultipleContents` (upload) and a draw surface backed
by a `Canvas`/`PointerInput` capture (signature). Captured URIs are persisted via
`takePersistableUriPermission` so they survive process death until submit.

## 5. API Contract

No direct network calls in this ticket — the renderer is a pure UI layer.
Network ownership: questionnaire fetch + DTOs (AND-346); session
start/save/validate (AND-348); submit/PDF (AND-349).

For traceability, the upstream/downstream shapes this renderer is wired against:

- Source question (from `GET /questionnaires/published/{published_slug}`,
  `PublishedQuestionnaireEnvelope.version`), per-question fields normalized by
  AND-346:

```json
{
  "question_id": "q_age",
  "type": "scale",
  "label": "Rate your experience",
  "required": true,
  "hint": "1 = poor, 5 = excellent",
  "config_json": { "min": 1, "max": 5, "minLabel": "Poor", "maxLabel": "Great" }
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
- **Stability:** `Question`, `AnswerValue`, and `ChoiceOption` are immutable data
  classes (Compose-stable). `onAnswerChanged` should be a stable lambda (caller
  uses a remembered reference) to avoid recomposing the whole list on each edit.
- **Keys:** list items keyed by `questionId`; choice items keyed by `optionId`.
- **Empty vs unanswered:** unanswered = key absent from `answers` (renderer
  receives `AnswerValue.Empty`); explicitly cleared = caller stores
  `AnswerValue.Empty`. Downstream validation (AND-350) distinguishes required
  failures from these.

## 7. Error Handling & Resilience

- **Unknown type:** `UNKNOWN`/unrecognized `rawType` renders
  `UnsupportedFieldPlaceholder(label, rawType)` — visible, non-interactive,
  never throws. Logged once per type (see §10).
- **Malformed config:** a choice/scale/rating with missing `options`/`min`/`max`
  degrades gracefully: choice with no options renders the label + an inline
  "No options available" note; scale/rating default to `1..5`. No crash.
- **Number parsing:** invalid numeric input keeps the raw string locally, emits
  `AnswerValue.Empty`, and shows a local "Enter a number" helper; it does not
  corrupt the answer map.
- **File/signature capture failure:** a cancelled or failed picker leaves the
  prior value intact; a `SecurityException` on `takePersistableUriPermission` is
  caught and surfaced as an inline "Couldn't attach file" message.
- **No network here:** timeouts/backoff/offline/401-refresh are owned by
  core-network (AND-009/016/013) and the fetch/session tickets (AND-346/348).
  The renderer must remain fully functional with stale/offline-loaded schema
  (it operates purely on in-memory models).
- **Validation errors:** the renderer only *displays* `error: String?`; it never
  computes validation (AND-350 owns rules).

## 8. Security & Privacy

- Respondent answers are PII. The renderer never logs answer values or
  `config_json` content (see §10); logs reference `questionId` and `type` only.
- File/signature URIs are held as `content://` references with persisted
  read permission; no file bytes are copied or cached by the renderer. Byte
  upload (and any encryption-in-transit concerns) is AND-349's responsibility.
- No clipboard auto-read; paste is user-initiated via standard IME.
- The public respond flow (AND-349) may be unauthenticated; the renderer must
  not assume an auth/session context or read cookies/CSRF (those live in
  core-network interceptors AND-011/012/013).
- Screenshots: signature capture surface should be usable but the renderer adds
  no `FLAG_SECURE` itself (that's an app-shell decision); flagged as open
  question §13.

## 9. Accessibility & i18n

- Every control has a content description / semantics label derived from
  `label`; required state is announced (`stateDescription` "required").
- Choice options expose `Role.RadioButton` / `Role.Checkbox`; scale/rating
  expose `Role.RadioButton` with value semantics ("4 of 5").
- Minimum 48dp touch targets for radio/checkbox/star/scale segments.
- `error` text is associated via `semantics { error(it) }` for TalkBack.
- All renderer-owned literal strings ("No options available", "Enter a number",
  "Couldn't attach file", required marker) come from `strings.xml`; no hardcoded
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
- **Capture tests:** drive input (type text, click option, pick scale value,
  toggle switch, set rating) and assert `onAnswerChanged` is invoked with the
  exact `AnswerValue` (use a recording lambda). This is the literal acceptance
  criterion "render + capture input".
- **Rehydration tests:** pass a non-empty `value` and assert the control shows
  it (selected radio, filled text, chosen date).
- **Clear test:** clearing a control emits `AnswerValue.Empty`.
- **Unknown type test:** `UNKNOWN`/garbage `rawType` renders the placeholder and
  does not throw.
- **Malformed config tests:** choice w/ empty options, scale w/ null min/max.
- **`toJsonValue` unit tests:** each `AnswerValue` variant maps to the correct
  JSON scalar/array; `Empty` → null/omitted.
- **Number parsing unit tests:** `"1.5"`→Number, `"-"`/`""`→Empty, locale digits.
- **Rotation/state-restore test:** in-progress numeric text survives recreate.
- **Accessibility assertions:** roles + required semantics present.
- Reuse fixtures from the MockWebServer harness (AND-046) only for realistic
  `Question` JSON → model inputs (decoding owned by AND-346); renderer tests
  feed domain models directly.

## 12. Dependencies & Sequencing

- **Depends on AND-346** (Questionnaire API + DTOs): supplies `Question`,
  `QuestionType`, `QuestionConfig`, `ChoiceOption`, `Section`, and the
  `type`/`config_json` normalization the renderer dispatches on. Hard blocker —
  the renderer cannot be built against untyped maps.
- **Depends on AND-020** (Core input composables): reuses `TlTextField`
  (error/helper), keyboard options, and patterns for password/OTP; the renderer
  must not duplicate these primitives.
- **Indirectly relies on** core-ui Material 3 theme (AND-019) for styling and
  core-model module (AND-003) for placing `AnswerValue`.
- **Blocks AND-348** (respondent session save/resume — needs the answer map +
  `toJsonValue`), **AND-349** (submit/PDF — needs captured answers incl. file
  URIs), and **AND-350** (conditional logic/validation — renders the `error`
  slot and respects an externally controlled visibility filter).
- **Consumed by AND-351** (ViewModel/form state machine) and exercised by
  **AND-352** (renderer + validation test suite).
- Sequencing: land after AND-346 model is merged; AND-351 wires it; AND-350 layers
  validation/branching on top without modifying renderer signatures.

## 13. Risks & Open Questions

- **Open type taxonomy:** backend `type` is a free-form string (`maxLength 32`),
  not an enum, in `/openapi.json`. The exact set of `type` strings and
  `config_json` keys must be confirmed against
  `frontend/src/api/endpoints/questionnaires.ts` and the web respondent renderer;
  any mismatch is absorbed by `UNKNOWN` fallback but should be reconciled with
  AND-346. **Action:** confirm the canonical type strings with the web app.
- **config_json shape per type** (e.g. is it `options`/`choices`, `min`/`max`
  vs `scale_min`/`scale_max`) is owned by AND-346's parser; renderer assumes the
  typed `QuestionConfig` above. Risk if AND-346 lands different field names.
- **Signature & upload** add ActivityResult + draw-surface complexity and may be
  scoped to a thin first pass (capture URI only) if M7 timeline is tight; submit
  wiring is AND-349 regardless.
- **FLAG_SECURE on signature/PII screens** — decide at app-shell level; not owned
  here. Open question.
- **Scale vs rating ambiguity** — some backends model star-rating as `scale`;
  confirm whether `rating` is a distinct type or a `scale` render hint.
- **Decimal/locale numeric entry** for `number` — confirm whether server expects
  `.`-decimal only; renderer normalizes to `Double` regardless of locale grouping.

## 14. Acceptance Criteria

1. For every supported `QuestionType` in §3, `QuestionField` renders the correct
   control with label, optional hint, and required marker.
2. Each control captures user input and emits the correct `AnswerValue` through
   `onAnswerChanged(questionId, value)` — verified by recording-lambda UI tests
   (the backlog acceptance: "All field types render + capture input").
3. Passing an existing `value` rehydrates the control (selected option, filled
   text, chosen date, set rating).
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
  AndroidX ActivityResult/DatePicker APIs already on the stack.
