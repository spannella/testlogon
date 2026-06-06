---
id: AND-346
title: Questionnaire API + DTOs
milestone: M7
epic: E45
priority: P1
size: M
status: draft
depends_on: [AND-027]
blocks: [AND-347, AND-348, AND-349, AND-350]
---

# AND-346 — Questionnaire API + DTOs

## 1. Overview & Goal

This ticket delivers the Kotlin networking surface and Moshi-backed data-transfer
objects for the TestLogon **questionnaires** domain — the Android port of the web
reference module `frontend/src/api/endpoints/questionnaires.ts` plus the
**published respondent sessions** types from `frontend/src/api/types.ts`. It is a
data/transport-only ticket: it produces a Retrofit `QuestionnaireApi` interface,
the request/response DTOs it exchanges, custom Moshi adapters for the
polymorphic questionnaire **field schema**, and round-trip unit tests. It produces
no UI, no ViewModel, no repository, and no persistence.

The primary M7 use case is an anonymous or authenticated **respondent** who loads
a *published* questionnaire by `slug`, opens or resumes a session, saves partial
answers, and submits. Each questionnaire is described by a tree of heterogeneous
**field** objects (text, choice, scale, date, file upload, etc.); correctly
modeling that polymorphic schema so it `maps (tested)` is the core deliverable and
the hardest part of this ticket.

Goal: ship `core-model` DTOs for the questionnaire schema and respondent session,
plus a `core-network` Retrofit `QuestionnaireApi` whose paths/verbs/bodies match
the live FastAPI contract, such that (a) every documented payload round-trips
against captured samples, (b) every documented field `type` deserializes into the
correct sealed subtype, and (c) the API is callable and contract-verified with
MockWebServer. Downstream tickets (renderer AND-347, session repository AND-348,
submit/PDF AND-349, conditional logic AND-350) compile against these types.

## 2. Context & References

- **Module placement.** DTOs live in `core-model` under package
  `com.testlogon.android.core.model.questionnaire`. The Retrofit
  `QuestionnaireApi`, the polymorphic `QuestionnaireField` adapter factory, and
  the Hilt module providing the typed API live in `core-network` under
  `com.testlogon.android.core.network.questionnaire`.
- **Stack.** Kotlin 2.0.21, Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15 with
  `moshi-kotlin-codegen` (KSP), Coroutines. minSdk 24 / compileSdk 35, JDK 17.
- **Layering.** `app → feature-* → core-*`. This ticket touches only
  `core-model` and `core-network`. Calls return `ApiResult<T>` (AND-018) via the
  shared error-mapping (AND-015 — FastAPI `detail` union string | [{msg}] |
  {code,...}).
- **Dependency (AND-027).** Establishes the Retrofit/OkHttp client stack, the
  persistent cookie jar (AND-011), CSRF interceptor (AND-012), 401-refresh
  authenticator (AND-013), and the pattern for declaring a typed `*Api`
  interface and providing it through Hilt. AND-346 follows that exact pattern.
- **Backend.** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. The authoritative
  field names are snake_case; mirror the web app's
  `frontend/src/api/endpoints/questionnaires.ts` and `types.ts` — do not invent
  camelCase wire keys.
- **Endpoint family.** Authenticated reads under `/questionnaires/...`; the
  public respondent surface under `/questionnaires/published/{slug}/...` and
  `/questionnaires/published/{slug}/sessions/*`. The published-session DTOs here
  are exactly what AND-348 (`start/save/validate session`) and AND-349
  (`submit, PDF export`) consume.
- **Downstream.** AND-347 renders fields from `QuestionnaireField`; AND-348 owns
  session lifecycle calls; AND-349 owns submit + PDF; AND-350 owns
  conditional/visibility logic that reads the `logic`/`condition` fields modeled
  here but evaluates them in the feature layer.

## 3. Functional Requirements

FR-1. Provide a Retrofit `QuestionnaireApi` with suspend functions for: fetch a
published questionnaire by slug; create/open a respondent session; fetch an
existing session; save (PATCH) partial answers; validate a session; submit a
session. (Submit/PDF *bodies* are modeled here; the submit call itself may be
invoked by AND-349 — see §5/§12.)

FR-2. Define the questionnaire schema DTOs: `QuestionnaireDto` (metadata + ordered
`pages`/`sections`), `QuestionnaireSection`, and the sealed `QuestionnaireField`
hierarchy keyed on a string `type` discriminator.

FR-3. Model **every documented field type** as a sealed subtype:
`text`, `textarea`, `number`, `choice` (single), `multichoice`, `dropdown`,
`scale`/`rating`, `date`, `datetime`, `boolean`, `upload` (file), and a
`Unknown` fallback for unrecognized/future types. Each subtype carries only the
properties relevant to it (e.g. `choice` carries `options`, `scale` carries
`min`/`max`/`step`/`labels`, `upload` carries `accept`/`maxSizeBytes`).

FR-4. Model the respondent session DTOs: `RespondentSessionDto`,
`SessionStartReq`, `SessionStartResp`, `SaveAnswersReq`, `ValidateResp`
(with a `ValidationError` list), `SubmitReq`, `SubmitResp`, and an `AnswerValue`
representation that can hold the union of answer shapes (string, number, boolean,
list of strings, date string, uploaded-file reference).

FR-5. Every wire field maps to the backend snake_case name via `@Json(name=…)`.
Unknown/extra JSON keys must be tolerated (additive backend evolution is safe);
unknown field `type` values must deserialize to `QuestionnaireField.Unknown`,
never throw.

FR-6. Nullability matches the contract: optional fields are Kotlin-nullable with
`null` defaults; required structural fields (`id`, `type`, `slug`,
`session_id`) are non-null and their absence is a fail-fast `JsonDataException`.

FR-7. All DTOs are immutable `data class`/`sealed` types exposing read-only
`List<T>`/`Map<…>` collections. Schema `id`/`slug` ordering of pages, sections,
fields, and options is preserved (ordered `List`).

FR-8. Provide captured JSON sample fixtures under `core-model` test resources for
the questionnaire schema (including one of every field type) and for each session
payload, used by round-trip and MockWebServer tests.

## 4. Technical Design

### 4.1 Field schema (polymorphic)

The schema is a sealed hierarchy. Because Moshi codegen does not handle sealed
polymorphism by discriminator out of the box, a `PolymorphicJsonAdapterFactory`
(from `moshi-adapters`) keyed on `type` is registered, with `Unknown` as the
default fallback.

```kotlin
package com.testlogon.android.core.model.questionnaire

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
data class QuestionnaireDto(
    val id: String,
    val slug: String,
    val title: String,
    val description: String? = null,
    val status: String,                                   // e.g. "published"
    @Json(name = "sections") val sections: List<QuestionnaireSection> = emptyList(),
    @Json(name = "updated_at") val updatedAt: String? = null,
)

@JsonClass(generateAdapter = true)
data class QuestionnaireSection(
    val id: String,
    val title: String? = null,
    val description: String? = null,
    val fields: List<QuestionnaireField> = emptyList(),
)

@JsonClass(generateAdapter = true, generator = "sealed:type")
sealed class QuestionnaireField {
    abstract val id: String
    abstract val label: String?
    abstract val required: Boolean
    abstract val condition: FieldCondition?               // evaluated in AND-350

    @TypeLabel("text") @JsonClass(generateAdapter = true)
    data class Text(
        override val id: String,
        override val label: String? = null,
        override val required: Boolean = false,
        override val condition: FieldCondition? = null,
        val placeholder: String? = null,
        @Json(name = "max_length") val maxLength: Int? = null,
        val multiline: Boolean = false,                   // "textarea" sets true
    ) : QuestionnaireField()

    @TypeLabel("number") @JsonClass(generateAdapter = true)
    data class Number(
        override val id: String, override val label: String? = null,
        override val required: Boolean = false, override val condition: FieldCondition? = null,
        val min: Double? = null, val max: Double? = null, val step: Double? = null,
    ) : QuestionnaireField()

    @TypeLabel("choice") @JsonClass(generateAdapter = true)
    data class Choice(
        override val id: String, override val label: String? = null,
        override val required: Boolean = false, override val condition: FieldCondition? = null,
        val options: List<FieldOption> = emptyList(),
        val multiple: Boolean = false,                    // covers "multichoice"
        @Json(name = "display") val display: String? = null, // "radio" | "dropdown"
    ) : QuestionnaireField()

    @TypeLabel("scale") @JsonClass(generateAdapter = true)
    data class Scale(
        override val id: String, override val label: String? = null,
        override val required: Boolean = false, override val condition: FieldCondition? = null,
        val min: Int = 1, val max: Int = 5, val step: Int = 1,
        @Json(name = "min_label") val minLabel: String? = null,
        @Json(name = "max_label") val maxLabel: String? = null,
    ) : QuestionnaireField()

    @TypeLabel("date") @JsonClass(generateAdapter = true)
    data class DateField(
        override val id: String, override val label: String? = null,
        override val required: Boolean = false, override val condition: FieldCondition? = null,
        @Json(name = "include_time") val includeTime: Boolean = false,
        val min: String? = null, val max: String? = null, // ISO-8601 bounds
    ) : QuestionnaireField()

    @TypeLabel("boolean") @JsonClass(generateAdapter = true)
    data class BooleanField(
        override val id: String, override val label: String? = null,
        override val required: Boolean = false, override val condition: FieldCondition? = null,
    ) : QuestionnaireField()

    @TypeLabel("upload") @JsonClass(generateAdapter = true)
    data class Upload(
        override val id: String, override val label: String? = null,
        override val required: Boolean = false, override val condition: FieldCondition? = null,
        val accept: List<String> = emptyList(),           // mime/ext hints
        @Json(name = "max_size_bytes") val maxSizeBytes: Long? = null,
        @Json(name = "max_files") val maxFiles: Int = 1,
    ) : QuestionnaireField()

    /** Forward-compatibility fallback; preserves unknown type + raw body. */
    @JsonClass(generateAdapter = true)
    data class Unknown(
        override val id: String = "",
        override val label: String? = null,
        override val required: Boolean = false,
        override val condition: FieldCondition? = null,
        val type: String? = null,
    ) : QuestionnaireField()
}

@JsonClass(generateAdapter = true)
data class FieldOption(
    val value: String,
    val label: String? = null,
)

@JsonClass(generateAdapter = true)
data class FieldCondition(
    @Json(name = "field_id") val fieldId: String,
    val op: String,                                       // eq|neq|in|gt|lt|...
    val value: AnswerValue? = null,
)
```

> Note on `generator = "sealed:type"` / `@TypeLabel`: these are illustrative of
> the `dev.zacsweers.moshix` sealed-codegen style. If the project pins plain
> Moshi 1.15 without moshix, use `PolymorphicJsonAdapterFactory.of(
> QuestionnaireField::class.java, "type").withSubtype(Text::class.java, "text")
> …withDefaultValue(Unknown())`. The chosen mechanism must be one of these two
> and is registered in `core-network` (§4.3). `textarea`/`multichoice`/`dropdown`
> map onto `Text(multiline=true)` / `Choice(multiple=true)` / `Choice(display=
> "dropdown")` via subtype labels (one `withSubtype` per documented `type` token).

### 4.2 Respondent session + answers

```kotlin
@JsonClass(generateAdapter = true)
data class RespondentSessionDto(
    @Json(name = "session_id") val sessionId: String,
    @Json(name = "questionnaire_slug") val questionnaireSlug: String,
    val status: String,                                   // "in_progress"|"submitted"
    val answers: Map<String, AnswerValue> = emptyMap(),   // keyed by field id
    @Json(name = "created_at") val createdAt: String? = null,
    @Json(name = "updated_at") val updatedAt: String? = null,
)

@JsonClass(generateAdapter = true)
data class SessionStartReq(
    @Json(name = "resume_token") val resumeToken: String? = null,
)

@JsonClass(generateAdapter = true)
data class SessionStartResp(
    @Json(name = "session_id") val sessionId: String,
    val questionnaire: QuestionnaireDto,
    val session: RespondentSessionDto? = null,           // present on resume
)

@JsonClass(generateAdapter = true)
data class SaveAnswersReq(
    val answers: Map<String, AnswerValue>,
)

@JsonClass(generateAdapter = true)
data class ValidateResp(
    val valid: Boolean,
    val errors: List<ValidationError> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class ValidationError(
    @Json(name = "field_id") val fieldId: String,
    val message: String,
    val code: String? = null,
)

@JsonClass(generateAdapter = true)
data class SubmitReq(
    val answers: Map<String, AnswerValue>? = null,        // optional final delta
)

@JsonClass(generateAdapter = true)
data class SubmitResp(
    @Json(name = "session_id") val sessionId: String,
    val status: String,                                   // "submitted"
    @Json(name = "pdf_url") val pdfUrl: String? = null,   // consumed by AND-349
    @Json(name = "submitted_at") val submittedAt: String? = null,
)
```

`AnswerValue` is the answer union. It is modeled as a sealed wrapper with a
custom adapter, so callers get a typed value rather than `Any?`:

```kotlin
sealed interface AnswerValue {
    data class Text(val value: String) : AnswerValue
    data class Num(val value: Double) : AnswerValue
    data class Bool(val value: Boolean) : AnswerValue
    data class Choices(val values: List<String>) : AnswerValue
    data class FileRef(val fileIds: List<String>) : AnswerValue
    data object Empty : AnswerValue
}
```

### 4.3 Retrofit interface + Hilt wiring

```kotlin
package com.testlogon.android.core.network.questionnaire

import com.testlogon.android.core.model.questionnaire.*
import retrofit2.http.*

interface QuestionnaireApi {

    @GET("questionnaires/published/{slug}")
    suspend fun getPublished(@Path("slug") slug: String): QuestionnaireDto

    @POST("questionnaires/published/{slug}/sessions")
    suspend fun startSession(
        @Path("slug") slug: String,
        @Body body: SessionStartReq,
    ): SessionStartResp

    @GET("questionnaires/published/{slug}/sessions/{sessionId}")
    suspend fun getSession(
        @Path("slug") slug: String,
        @Path("sessionId") sessionId: String,
    ): RespondentSessionDto

    @PATCH("questionnaires/published/{slug}/sessions/{sessionId}")
    suspend fun saveAnswers(
        @Path("slug") slug: String,
        @Path("sessionId") sessionId: String,
        @Body body: SaveAnswersReq,
    ): RespondentSessionDto

    @POST("questionnaires/published/{slug}/sessions/{sessionId}/validate")
    suspend fun validate(
        @Path("slug") slug: String,
        @Path("sessionId") sessionId: String,
    ): ValidateResp

    @POST("questionnaires/published/{slug}/sessions/{sessionId}/submit")
    suspend fun submit(
        @Path("slug") slug: String,
        @Path("sessionId") sessionId: String,
        @Body body: SubmitReq,
    ): SubmitResp
}
```

```kotlin
@Module
@InstallIn(SingletonComponent::class)
object QuestionnaireNetworkModule {
    @Provides @Singleton
    fun questionnaireApi(retrofit: Retrofit): QuestionnaireApi =
        retrofit.create(QuestionnaireApi::class.java)

    // Contributes the polymorphic field factory + AnswerValue adapter
    // into the shared Moshi adapter set established by AND-027/AND-010.
    @Provides @IntoSet @AppMoshiAdapter
    fun questionnaireFieldFactory(): Any =
        QuestionnaireFieldAdapterFactory.create()        // PolymorphicJsonAdapterFactory
}
```

Return-type policy: the interface declares the **success** type. Wrapping into
`ApiResult<T>` (AND-018) and FastAPI `detail` mapping (AND-015) happen in the
repository/CallAdapter layer per the AND-027 pattern; this ticket does not add a
new error model.

## 5. API Contract

Base URL is the flavored `BuildConfig` host (AND-006); dev =
`http://18.222.237.167:8000`. All session-mutating verbs (`POST`/`PATCH`) carry
the `X-CSRF-Token` header echoed from the `ui_csrf` cookie via the AND-012
intercept; cookies ride via the AND-011 jar. Authoritative key names follow
`/openapi.json` of the running host.

`GET /questionnaires/published/{slug}` → `QuestionnaireDto`:
```json
{ "id": "qn_01", "slug": "intake-2026", "title": "Intake",
  "status": "published", "updated_at": "2026-06-01T10:00:00Z",
  "sections": [ { "id": "s1", "title": "About you", "fields": [
    { "type": "text", "id": "f_name", "label": "Full name", "required": true,
      "max_length": 120 },
    { "type": "choice", "id": "f_color", "label": "Favorite color",
      "options": [ {"value":"r","label":"Red"}, {"value":"b","label":"Blue"} ] },
    { "type": "scale", "id": "f_nps", "label": "Rate us", "min": 0, "max": 10,
      "min_label": "Hate", "max_label": "Love" },
    { "type": "upload", "id": "f_doc", "accept": ["application/pdf"],
      "max_size_bytes": 10485760, "max_files": 1 } ] } ] }
```

`POST /questionnaires/published/{slug}/sessions` request / response:
```json
{ "resume_token": null }
```
```json
{ "session_id": "sess_abc", "questionnaire": { "...": "QuestionnaireDto" },
  "session": null }
```

`PATCH /questionnaires/published/{slug}/sessions/{session_id}` request / response:
```json
{ "answers": { "f_name": "Ada", "f_nps": 9, "f_color": ["b"] } }
```
```json
{ "session_id": "sess_abc", "questionnaire_slug": "intake-2026",
  "status": "in_progress",
  "answers": { "f_name": "Ada", "f_nps": 9, "f_color": ["b"] },
  "updated_at": "2026-06-05T12:00:00Z" }
```

`POST .../{session_id}/validate` → `ValidateResp`:
```json
{ "valid": false,
  "errors": [ { "field_id": "f_doc", "message": "Required", "code": "required" } ] }
```

`POST .../{session_id}/submit` request / response:
```json
{ "answers": null }
```
```json
{ "session_id": "sess_abc", "status": "submitted",
  "pdf_url": "/questionnaires/published/intake-2026/sessions/sess_abc/pdf",
  "submitted_at": "2026-06-05T12:05:00Z" }
```

Ownership note: the *call sites* for `startSession`/`saveAnswers`/`validate` are
exercised by AND-348 and `submit`/PDF by AND-349. AND-346 freezes the
interface + bodies and proves each method is callable with MockWebServer; the
public App Link (`/questionnaires/published/:slug/respond`) is AND-349's concern,
not a DTO/endpoint added here.

## 6. Data & State Management

No app state, Room rows, or DataStore keys are introduced. DTOs are transient wire
types and must not be stored directly; mapping to domain models, caching of
in-progress sessions for offline resume, and `StateFlow<UiState>` exposure are
owned by AND-348 (session repository) and AND-347 (renderer state). DTOs carry no
Compose `@Stable`/`@Immutable` annotations — they never enter composition; the
renderer maps them to a UI model. ISO-8601 timestamps stay `String` at this layer.
The only stateful behavioral choices are total-deserialization fallbacks
(`QuestionnaireField.Unknown`, `AnswerValue.Empty`) that keep parsing
non-throwing. Answer `Map<String, AnswerValue>` ordering is not significant (keyed
by field id); page/section/field/option `List` ordering is significant and
preserved.

## 7. Error Handling & Resilience

Two layers:

- **Deserialization (owned here).** Missing required structural field
  (`id`/`type`/`session_id`/`slug`) → `JsonDataException` (fail fast, asserted in
  tests). Unknown JSON keys → skipped. Unknown field `type` →
  `QuestionnaireField.Unknown` (never throws); the renderer (AND-347) must show a
  graceful "unsupported field" placeholder and the validator must not block
  submit on an `Unknown` non-required field. Malformed `AnswerValue` →
  `AnswerValue.Empty` rather than crash.
- **Network (owned by AND-015/016/027, constrained here).** `getPublished` and
  `getSession` are idempotent GETs and are eligible for the bounded backoff retry
  (AND-016) under the ~20s timeout budget against the unreliable dev host.
  `startSession`/`saveAnswers`/`validate`/`submit` are **non-idempotent** and must
  **not** be auto-retried by the GET-retry interceptor; resume/save-conflict and
  offline UX are AND-348's responsibility. On 401 the AND-013 authenticator
  performs one `POST /ui/session/refresh` then retries (only relevant for the
  authenticated-respondent path; anonymous published sessions may legitimately
  return 200 without a session cookie). FastAPI `detail` union mapping is reused
  unchanged from AND-015 — no questionnaire-specific error model is added.

## 8. Security & Privacy

- Respondent answers can contain PII (names, free text, uploaded documents).
  `SaveAnswersReq`, `SubmitReq`, `RespondentSessionDto`, and `AnswerValue`
  subtypes must **not** be logged. Override `toString()` on answer-bearing DTOs to
  redact: `override fun toString() = "SaveAnswersReq(answers=<${answers.size} redacted>)"`.
- The OkHttp body-logging interceptor (core-network) must redact request/response
  bodies for all `.../sessions/*` paths — documented here as a constraint,
  implemented in the logging-interceptor ticket.
- File uploads are referenced by id only (`AnswerValue.FileRef`); the actual
  presigned upload pipeline (if any) is a separate files ticket — no file bytes
  flow through these DTOs.
- Plaintext HTTP on the dev host means answers traverse the network unencrypted;
  this is a dev-only constraint (noted as a risk) — production base URL must be
  HTTPS. No credentials or tokens are placed in DTO fields; auth rides on
  HttpOnly cookies invisible to this layer.
- Committed JSON fixtures must use synthetic answers only (no real PII).

## 9. Accessibility & i18n

Not applicable as a UI surface — this ticket introduces no composables and no
`strings.xml` entries. However, it carries i18n-relevant *data*: field `label`,
`description`, `min_label`/`max_label`, and `ValidationError.message` are
server-supplied, server-localized strings and are passed through verbatim (no
client transformation, no truncation). The renderer (AND-347) is responsible for
content descriptions, focus order, and touch-target sizing when it consumes these
labels. No locale negotiation is added here; server-locale sync is AND-113.

## 10. Telemetry & Logging

No analytics events are emitted by this layer. Logging is prohibited beyond
redacted `toString()` overrides (§8). A single non-PII structured debug log is
permitted on deserialization fallback — `QuestionnaireField.Unknown` encountered —
emitting only the unknown `type` token and field `id` (no answer/label content),
to aid diagnosing schema drift against the dev backend. This log must be gated
behind the debug build flavor and must never include answer values. Telemetry for
respondent funnel events (started/saved/submitted) is owned by AND-348/AND-349.

## 11. Testing Strategy

All tests are JVM unit tests (`core-model` round-trip) plus a MockWebServer
contract test (`core-network`); no instrumentation required. Reuse the core-testing
(AND-046 pattern) MockWebServer harness once available; until then a local
`MockWebServer` is fine.

- **Field-type round-trip.** A fixture
  `core-model/src/test/resources/questionnaire/all_field_types.json` contains one
  of every documented `type`. Test asserts each deserializes to the correct
  `QuestionnaireField` subtype with expected properties, and re-serializing yields
  a parsed tree equal to the input (key-order/whitespace-insensitive). This is the
  acceptance-defining "schema maps (tested)" test.
- **Unknown type.** A field with `"type":"signature"` deserializes to
  `QuestionnaireField.Unknown(type="signature")`, never throws.
- **Field-name mapping.** Serialized output uses snake_case
  (`max_size_bytes`, `field_id`, `session_id`) — assert keys present, camelCase
  absent.
- **Required-field failure.** Removing `id`/`type` from a field, or `session_id`
  from a session, throws `JsonDataException`.
- **Unknown-key tolerance.** Extra `"server_time"` key on `QuestionnaireDto`
  deserializes cleanly.
- **AnswerValue union.** String/number/boolean/list/file-ref/empty all round-trip
  to the correct `AnswerValue` subtype; a `SaveAnswersReq` with a mixed answer map
  re-serializes to the documented JSON.
- **API contract (MockWebServer).** For each `QuestionnaireApi` method: enqueue
  the §5 sample response, invoke the suspend fn, assert (a) recorded request path
  + HTTP verb match exactly, (b) request body (where applicable) serializes as
  documented, (c) the response deserializes to the expected DTO. Test class:
  `com.testlogon.android.core.network.questionnaire.QuestionnaireApiContractTest`.
- **Redaction.** `SaveAnswersReq(...).toString()` / `SubmitReq(...).toString()`
  do not contain answer values.
- **Coverage target.** Every DTO in §4 has ≥1 round-trip test + committed
  fixture; every `QuestionnaireApi` method has a contract test. Round-trip class:
  `com.testlogon.android.core.model.questionnaire.QuestionnaireDtoRoundTripTest`.

## 12. Dependencies & Sequencing

- **Depends on AND-027** (AuthApi session endpoints): provides the configured
  Retrofit/OkHttp stack, cookie jar, CSRF + 401-refresh interceptors, shared
  `Moshi` adapter-set hook, and the typed-`*Api`-via-Hilt pattern this ticket
  mirrors. (Transitively depends on AND-010 Retrofit/Moshi, AND-026's adapter-set
  multibinding, AND-015 error mapping, AND-018 `ApiResult`, AND-006 base URL.)
- **Blocks AND-347** (dynamic form renderer): renders `QuestionnaireField`
  subtypes — cannot compile without them.
- **Blocks AND-348** (respondent session start/save/validate): consumes
  `QuestionnaireApi` session methods + session DTOs.
- **Blocks AND-349** (submit + PDF, public respond App Link): consumes `submit`
  and `SubmitResp.pdfUrl`.
- **Blocks AND-350** (conditional logic / validation): consumes `FieldCondition`
  and `ValidationError` modeled here; evaluation logic lives there.
- Sequence after AND-027 merges so the shared adapter-set hook exists.

## 13. Risks & Open Questions

- **R1 — Field type catalog drift.** The exact set of `type` tokens and their
  property names is inferred from the web reference; the live `/openapi.json` is
  authoritative. *Open:* enumerate every `type` the backend emits (esp. whether
  `textarea`/`multichoice`/`dropdown` are distinct types or modifier flags as
  modeled) and capture a real schema fixture. The `Unknown` fallback de-risks
  missing one, but the renderer would skip it.
- **R2 — Session URL shape.** Whether sessions are nested under
  `.../sessions/{id}` or addressed via a resume token / cookie only. *Open:*
  confirm path params and whether `startSession` returns the questionnaire inline
  (modeled) or requires a separate `getPublished`.
- **R3 — Anonymous vs authenticated respondent.** Whether the public path sets a
  session cookie and whether CSRF is required for anonymous PATCH/POST. *Open:*
  confirm against backend; affects which interceptors apply.
- **R4 — `AnswerValue` shape per field.** Whether choice answers are always
  arrays (modeled `Choices`) or scalar for single-choice. *Open:* confirm; the
  union tolerates both but the renderer/validator need a firm rule.
- **R5 — Polymorphic adapter mechanism.** moshix sealed-codegen vs
  `PolymorphicJsonAdapterFactory`. *Open:* confirm which is already on the
  classpath from AND-010/027; pick one and document.
- **R6 — Plaintext PII.** Dev host is HTTP; answers travel unencrypted. Mitigation:
  flag for production HTTPS; do not test with real PII.

## 14. Acceptance Criteria

1. All DTOs in §4 exist in `com.testlogon.android.core.model.questionnaire` as
   immutable data/sealed types; the polymorphic `QuestionnaireField` factory and
   `AnswerValue` adapter are registered on the shared `Moshi`.
2. **Questionnaire schema maps (tested):** `all_field_types.json` deserializes
   every documented field `type` to the correct `QuestionnaireField` subtype and
   round-trips to an equal parsed tree, proven by `QuestionnaireDtoRoundTripTest`.
3. Unknown field `type` → `QuestionnaireField.Unknown` (no throw); unknown JSON
   keys tolerated; missing required structural fields throw `JsonDataException`.
4. `QuestionnaireApi` exposes all §4.3 methods; each is callable and its
   path/verb/body matches §5, proven by `QuestionnaireApiContractTest`
   (MockWebServer).
5. Serialized payloads use snake_case keys; `AnswerValue` union round-trips for
   all six variants.
6. Answer-bearing DTO `toString()` redact answers; no committed fixture contains
   real PII.
7. Module compiles via KSP codegen against the shared `Moshi`; AND-027's existing
   tests stay green; AND-347/348/349/350 can reference all types and compile.

## 15. Definition of Done

- Code merged to `android-port`: DTOs under `core-model`, `QuestionnaireApi` +
  adapter factory + Hilt module under `core-network`, package base
  `com.testlogon.android`.
- `QuestionnaireDtoRoundTripTest` and `QuestionnaireApiContractTest` pass in CI;
  captured JSON fixtures committed under
  `core-model/src/test/resources/questionnaire/` (including `all_field_types.json`).
- `./gradlew :core-model:test :core-network:test` green on JDK 17; no new
  lint/detekt violations.
- Redaction verified by test; debug-only unknown-type log gated and PII-free.
- Open questions R1–R5 resolved against the running `/openapi.json` (or explicitly
  ticketed) before AND-347/AND-348 begin consuming the types; R6 (plaintext PII)
  noted for production HTTPS.
- Spec reviewed; no UI, ViewModel, repository, or persistence code introduced
  (those are AND-347/348/349/350).
