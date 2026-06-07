---
id: AND-346
title: Questionnaire API + DTOs
milestone: M7
epic: E45
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
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
- **Endpoint family.** Authenticated draft-authoring reads/writes under
  `/questionnaires/drafts/...`; the public respondent surface under
  `/questionnaires/published/{published_slug}/...` and
  `/questionnaires/published/{published_slug}/sessions/*`. The published-session
  DTOs here are exactly what AND-348 (`start/save/validate session`) and AND-349
  (`submit, PDF export`) consume. **[Corrected]** The OpenAPI path parameter is
  `published_slug` (not `slug`) and `response_session_id` (not `session_id`);
  Retrofit `@Path` keys must match the declared `{published_slug}` /
  `{response_session_id}` tokens. Source: OpenAPI
  `GET /questionnaires/published/{published_slug}` and
  `GET /questionnaires/published/{published_slug}/sessions/{response_session_id}`.
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

FR-3. Model **every documented field/question type** as a sealed subtype, plus a
`Unknown` fallback for unrecognized/future types.
**[Corrected]** The authoritative type catalog from the frontend reference
(`src/api/types.ts: QuestionnaireQuestionType`) is exactly:
`text`, `select`, `multiselect`, `radio`, `slider`, `date`, `time`, `timezone`,
`address`. There is **no** `textarea`, `number`, `choice`, `multichoice`,
`dropdown`, `scale`/`rating`, `datetime`, `boolean`, or `upload` type in the
contract; the original list in this spec was inferred and is wrong. Note also
that the per-type configuration is **not** modeled as typed sibling fields on
the wire — every question carries an opaque `config_json: Record<string,
unknown>` (`src/api/types.ts: QuestionnaireQuestion`), so subtype-specific
properties (options, slider min/max, etc.) live inside `config_json` rather than
as first-class JSON keys. Each Kotlin subtype may surface a typed view of its
slice of `config_json`, but must tolerate the opaque map. Source:
`src/api/types.ts: QuestionnaireQuestionType` and `QuestionnaireQuestion`.

FR-4. Model the respondent session DTOs and an `AnswerValue` representation that
can hold the union of answer shapes (string, number, boolean, list of strings,
date string). **[Corrected]** The wire schema names and shapes differ from the
original draft; mirror the backend exactly:
- Start request `ResponseSessionStartReq` `{ questionnaire_id?: string }` (the
  frontend posts `{}`); response is the envelope `ResponseSessionEnvelope`
  `{ session: object }`. There is **no** `resume_token` field and the start
  response does **not** inline the questionnaire.
- Session state response is `SessionStateEnvelope`
  `{ session: object, answers_by_question_id: object }`.
- Save is `PUT` with `SessionSaveReq`
  `{ answers_by_question_id: object, current_section_index?: int,
  current_question_id?: string }` — **not** `PATCH` and **not** a flat
  `{ answers }` body.
- Validate request is `QuestionnaireValidationRequest`
  `{ answers_by_question_id, contract_version="2026-03-validation-v1",
  final_submit=false, form_rules:[], group_rules:[] }`; response is
  `QuestionnaireValidationResponse`
  `{ is_valid, can_submit, has_blocking_form_error,
  errors: Map<questionId, List<ValidationIssue>>, contract_version }`.
- `ValidationIssue` is `{ code, message, blocking?: bool, rule_id?: string }` —
  there is no flat `ValidationError` list and no `field_id` on the issue (the
  question id is the map key in `errors`).
- Submit request is `QuestionnaireValidationRequest` (same shape, typically
  `final_submit=true`); response is `SessionSubmitEnvelope`
  `{ session: object, result: QuestionnaireValidationResponse }` — **no**
  `pdf_url`/`submitted_at`.
- PDF is a **separate** pair of endpoints
  (`POST .../pdf` → `SessionPdfEnvelope { artifact: object }` to generate,
  `GET .../pdf` to download) owned by AND-349; it is not a field on submit.
Sources: OpenAPI schemas `ResponseSessionStartReq`, `ResponseSessionEnvelope`,
`SessionStateEnvelope`, `SessionSaveReq`, `QuestionnaireValidationRequest`,
`QuestionnaireValidationResponse`, `ValidationIssue`, `SessionSubmitEnvelope`,
`SessionPdfEnvelope`; frontend `src/api/endpoints/questionnaires.ts`.

FR-5. Every wire field maps to the backend snake_case name via `@Json(name=…)`.
Unknown/extra JSON keys must be tolerated (additive backend evolution is safe);
unknown field `type` values must deserialize to `QuestionnaireField.Unknown`,
never throw.

FR-6. Nullability matches the contract: optional fields are Kotlin-nullable with
`null` defaults; required structural fields are non-null and their absence is a
fail-fast `JsonDataException`. **[Corrected]** The required structural keys per
the contract are: question `type`, `question_id`, `section_id`, `label`,
`required` on `QuestionnaireQuestion`; `published_slug`, `questionnaire_id`,
`version_id`, `schema_json` on `PublishedQuestionnaireVersion`;
`response_session_id`, `questionnaire_id`, `version_id`, `status` on the session
state; and `is_valid`, `can_submit`, `has_blocking_form_error`, `errors` on
`QuestionnaireValidationResponse`. Note the envelope wrappers (`version`,
`session`, `answers_by_question_id`, `result`, `artifact`) are themselves
required at the top level. Source: OpenAPI `required` arrays of the named
schemas; `src/api/types.ts: QuestionnaireQuestion`,
`PublishedQuestionnaireVersion`, `QuestionnaireSessionState`.

FR-7. All DTOs are immutable `data class`/`sealed` types exposing read-only
`List<T>`/`Map<…>` collections. Schema `id`/`slug` ordering of pages, sections,
fields, and options is preserved (ordered `List`).

FR-8. Provide captured JSON sample fixtures under `core-model` test resources for
the questionnaire schema (including one of every field type) and for each session
payload, used by round-trip and MockWebServer tests.

## 4. Technical Design

### 4.1 Field schema (polymorphic)

> **[Corrected — read before the code below]** The Kotlin sketch in this
> subsection predates verification and uses the wrong `@TypeLabel` tokens and
> wrong per-type fields (it invents `textarea`/`choice`/`scale`/`upload`/
> `boolean`/`number` and typed sibling props). The authoritative catalog is
> `text|select|multiselect|radio|slider|date|time|timezone|address` and per-type
> config rides in an opaque `config_json` map (see FR-3). Treat the structural
> spine below (sealed discriminator + `Unknown` fallback + adapter mechanism) as
> the design; replace the subtype set and field shapes with the corrected
> catalog when implementing. The discriminator key is `type` and the field id
> key is `question_id` (not `id`), section key is `section_id`. Source:
> `src/api/types.ts: QuestionnaireQuestionType`, `QuestionnaireQuestion`.

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

> **[Corrected — the interface below has several contract errors; corrected
> signatures follow.]** Against OpenAPI the verified surface is:
> - `GET questionnaires/published/{published_slug}` →
>   `PublishedQuestionnaireEnvelope` (`{ version: object }`), **not** a bare
>   `QuestionnaireDto`.
> - `POST questionnaires/published/{published_slug}/sessions` with body
>   `ResponseSessionStartReq` → `ResponseSessionEnvelope` (`{ session: object }`).
> - `GET questionnaires/published/{published_slug}/sessions/{response_session_id}`
>   → `SessionStateEnvelope`.
> - **`PUT`** (not `PATCH`)
>   `questionnaires/published/{published_slug}/sessions/{response_session_id}`
>   with body `SessionSaveReq` → `SessionStateEnvelope`.
> - `POST .../{response_session_id}/validate` with body
>   `QuestionnaireValidationRequest` → `QuestionnaireValidationResponse`.
> - `POST .../{response_session_id}/submit` with body
>   `QuestionnaireValidationRequest` → `SessionSubmitEnvelope`.
> - PDF (owned by AND-349, optional here):
>   `POST .../{response_session_id}/pdf` → `SessionPdfEnvelope` (generate) and
>   `GET .../{response_session_id}/pdf` (download bytes).
>
> `@Path` keys must be `published_slug` and `responseSessionId` bound to
> `{response_session_id}`. Source: OpenAPI index lines for
> `op=get_published_by_slug_*`, `start_response_session_*`,
> `get_response_session_state_*`, `save_response_session_state_*`,
> `validate_response_session_state_*`, `submit_response_session_*`,
> `generate_response_session_pdf_*`, `download_response_session_pdf_*`; frontend
> `src/api/endpoints/questionnaires.ts`.

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
`http://18.222.237.167:8000`. All session-mutating verbs (`POST`/`PUT`) carry
the `X-CSRF-Token` header echoed from the `ui_csrf` cookie via the AND-012
intercept; cookies ride via the AND-011 jar. **[Verified]** the web client sets
`X-CSRF-Token` from the `ui_csrf` cookie and sends `credentials: "include"` on
every request (`src/api/client.ts` lines 167-171, 183). Authoritative key names
follow `/openapi.json` of the running host.

> **[Corrected]** The sample payloads below were written against the wrong shapes
> (`PATCH` save, bare top-level DTOs, flat `errors` list, `pdf_url` on submit).
> The verified shapes are: every published read/session response is **enveloped**
> (`{ "version": {...} }`, `{ "session": {...} }`,
> `{ "session": {...}, "answers_by_question_id": {...} }`,
> `{ "session": {...}, "result": {...} }`); save is **`PUT`** with body
> `{ "answers_by_question_id": {...}, "current_section_index": 0,
> "current_question_id": "q1" }`; validate/submit bodies are
> `QuestionnaireValidationRequest`
> (`{ "answers_by_question_id": {...}, "contract_version":
> "2026-03-validation-v1", "final_submit": false, "form_rules": [],
> "group_rules": [] }`); validate/submit `result` is
> `{ "is_valid": false, "can_submit": false, "has_blocking_form_error": true,
> "errors": { "q_doc": [ { "code": "required", "message": "Required",
> "blocking": true, "rule_id": null } ] }, "contract_version":
> "2026-03-validation-v1" }`. The published `version` / session `session` /
> `schema_json` objects are opaque `additionalProperties:true` maps in OpenAPI —
> the questionnaire schema tree is **not** typed in the backend OpenAPI; the
> typed Kotlin model is reconstructed from the frontend `schema_json` usage and
> must tolerate unknown keys. Sources: OpenAPI `PublishedQuestionnaireEnvelope`,
> `SessionStateEnvelope`, `SessionSaveReq`, `QuestionnaireValidationRequest`,
> `QuestionnaireValidationResponse`, `ValidationIssue`, `SessionSubmitEnvelope`;
> `src/api/types.ts: PublishedQuestionnaireVersion`,
> `QuestionnaireSessionStateResp`.

`GET /questionnaires/published/{published_slug}` →
`PublishedQuestionnaireEnvelope` (corrected — the questionnaire is nested under
`version.schema_json`, not a bare top-level `QuestionnaireDto`). The schema tree
below is illustrative of the decoded `schema_json` content; the real wire keys
inside `schema_json` are opaque per OpenAPI and the `type` tokens shown here
predate verification (see FR-3 for the real catalog):
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

`POST /questionnaires/published/{published_slug}/sessions` request / response
(corrected — request is `ResponseSessionStartReq` `{ questionnaire_id? }`, the web
client posts `{}`; response is `ResponseSessionEnvelope`; no `resume_token`, the
questionnaire is **not** inlined):
```json
{}
```
```json
{ "session": { "response_session_id": "sess_abc", "questionnaire_id": "qn_01",
  "version_id": "v1", "status": "in_progress" } }
```

`PUT /questionnaires/published/{published_slug}/sessions/{response_session_id}`
request / response (corrected — `PUT`, `answers_by_question_id`, enveloped):
```json
{ "answers_by_question_id": { "q_name": "Ada", "q_nps": 9, "q_color": ["b"] },
  "current_section_index": 0, "current_question_id": "q_color" }
```
```json
{ "session": { "response_session_id": "sess_abc",
    "questionnaire_id": "qn_01", "version_id": "v1", "status": "in_progress",
    "current_section_index": 0 },
  "answers_by_question_id": { "q_name": "Ada", "q_nps": 9, "q_color": ["b"] } }
```

`POST .../{response_session_id}/validate` → `QuestionnaireValidationResponse`
(corrected — request is `QuestionnaireValidationRequest`; `errors` is a map):
```json
{ "answers_by_question_id": { "q_name": "Ada" },
  "contract_version": "2026-03-validation-v1", "final_submit": false,
  "form_rules": [], "group_rules": [] }
```
```json
{ "is_valid": false, "can_submit": false, "has_blocking_form_error": true,
  "errors": { "q_doc": [ { "code": "required", "message": "Required",
    "blocking": true, "rule_id": null } ] },
  "contract_version": "2026-03-validation-v1" }
```

`POST .../{response_session_id}/submit` request / response (corrected — request
is `QuestionnaireValidationRequest` with `final_submit:true`; response is
`SessionSubmitEnvelope`; no `pdf_url`):
```json
{ "answers_by_question_id": { "q_name": "Ada" },
  "contract_version": "2026-03-validation-v1", "final_submit": true,
  "form_rules": [], "group_rules": [] }
```
```json
{ "session": { "response_session_id": "sess_abc", "status": "submitted" },
  "result": { "is_valid": true, "can_submit": true,
    "has_blocking_form_error": false, "errors": {},
    "contract_version": "2026-03-validation-v1" } }
```

PDF is a separate endpoint pair (owned by AND-349):
`POST .../{response_session_id}/pdf` → `SessionPdfEnvelope` `{ "artifact": {...} }`
to generate; `GET .../{response_session_id}/pdf` to download.

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
  `startSession`/`saveAnswers`/`validate`/`submit` are **mutating** and must
  **not** be auto-retried by the GET-retry interceptor; resume/save-conflict and
  offline UX are AND-348's responsibility. (Note: `saveAnswers` is **`PUT`**, so
  it is technically idempotent at the HTTP level, but it is still excluded from
  the GET-only retry path.) On 401 the AND-013 authenticator performs one
  `POST /ui/session/refresh` then retries (verified: OpenAPI
  `POST /ui/session/refresh`, `op=ui_session_refresh_*`) (only relevant for the
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
- **Field-name mapping.** Serialized output uses snake_case — assert keys
  present, camelCase absent. **[Corrected]** Use the verified wire keys for
  assertions: `answers_by_question_id`, `question_id`, `section_id`,
  `response_session_id`, `current_section_index`, `published_slug`, `schema_json`,
  `is_valid`, `can_submit`, `has_blocking_form_error`, `contract_version`,
  `rule_id` (not the invented `max_size_bytes`/`field_id`/`session_id`).
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **Published read path is `GET /questionnaires/published/{published_slug}`.**
   VERDICT: Corrected (was `{slug}`). SOURCE: OpenAPI
   `GET /questionnaires/published/{published_slug}` (op=get_published_by_slug_…);
   `src/api/endpoints/questionnaires.ts: getPublishedQuestionnaireBySlug`.
2. **Published read returns an envelope `PublishedQuestionnaireEnvelope`
   `{ version: object }`, not a bare `QuestionnaireDto`.** VERDICT: Corrected.
   SOURCE: OpenAPI schema `PublishedQuestionnaireEnvelope`;
   `src/api/endpoints/questionnaires.ts` (`api.get<{ version: ... }>`).
3. **The published questionnaire schema is opaque (`version` /
   `schema_json` are `additionalProperties:true` objects) in the backend
   OpenAPI.** VERDICT: Verified. SOURCE: OpenAPI `PublishedQuestionnaireEnvelope`;
   `src/api/types.ts: PublishedQuestionnaireVersion.schema_json:
   Record<string, unknown>`.
4. **Question type catalog is
   `text|select|multiselect|radio|slider|date|time|timezone|address`.**
   VERDICT: Corrected (spec listed
   text/textarea/number/choice/multichoice/dropdown/scale/rating/datetime/boolean/upload).
   SOURCE: `src/api/types.ts: QuestionnaireQuestionType`.
5. **Per-question config is an opaque `config_json` map, not typed sibling
   fields; structural keys are `question_id`, `section_id`, `type`, `label`,
   `required`, `hint`, `position`.** VERDICT: Corrected. SOURCE:
   `src/api/types.ts: QuestionnaireQuestion`.
6. **Start session: `POST .../sessions` body `ResponseSessionStartReq`
   `{ questionnaire_id? }` (web posts `{}`); response `ResponseSessionEnvelope`
   `{ session: object }`; no `resume_token`; questionnaire not inlined.**
   VERDICT: Corrected. SOURCE: OpenAPI `ResponseSessionStartReq`,
   `ResponseSessionEnvelope`; `src/api/endpoints/questionnaires.ts:
   startPublishedResponseSession` (posts `{}`).
7. **Get session state: `GET .../sessions/{response_session_id}` →
   `SessionStateEnvelope { session, answers_by_question_id }`.** VERDICT:
   Corrected (was `{session_id}` → bare `RespondentSessionDto`). SOURCE: OpenAPI
   `SessionStateEnvelope`; `src/api/types.ts: QuestionnaireSessionStateResp`.
8. **Save is `PUT` with `SessionSaveReq`
   `{ answers_by_question_id, current_section_index?, current_question_id? }`.**
   VERDICT: Corrected (spec said `PATCH` with flat `{answers}`). SOURCE: OpenAPI
   `PUT /questionnaires/published/{published_slug}/sessions/{response_session_id}`
   + schema `SessionSaveReq`; `src/api/endpoints/questionnaires.ts:
   savePublishedResponseSessionState` (`api.put`, body
   `answers_by_question_id`).
9. **Validate: `POST .../validate` body `QuestionnaireValidationRequest`
   `{ answers_by_question_id, contract_version="2026-03-validation-v1",
   final_submit, form_rules, group_rules }` → `QuestionnaireValidationResponse`.**
   VERDICT: Corrected (spec had no request body and wrong response). SOURCE:
   OpenAPI `validate_response_session_state_…`, schemas
   `QuestionnaireValidationRequest` / `QuestionnaireValidationResponse`.
10. **Validation response is
    `{ is_valid, can_submit, has_blocking_form_error,
    errors: Map<questionId, List<ValidationIssue>>, contract_version }` — errors
    keyed by question id, not a flat list.** VERDICT: Corrected (spec had
    `{ valid, errors:[{field_id,message,code}] }`). SOURCE: OpenAPI
    `QuestionnaireValidationResponse` (errors `additionalProperties: array of
    ValidationIssue`).
11. **`ValidationIssue` is `{ code, message, blocking?, rule_id? }` (no
    `field_id`).** VERDICT: Corrected. SOURCE: OpenAPI schema `ValidationIssue`.
12. **Submit: `POST .../submit` body `QuestionnaireValidationRequest` →
    `SessionSubmitEnvelope { session, result: QuestionnaireValidationResponse }`;
    no `pdf_url`/`submitted_at`.** VERDICT: Corrected. SOURCE: OpenAPI
    `submit_response_session_…`, schema `SessionSubmitEnvelope`;
    `src/api/endpoints/questionnaires.ts: submitPublishedResponseSession`
    (`{ session, result }`).
13. **PDF is a separate endpoint pair (POST generate → `SessionPdfEnvelope
    { artifact }`, GET download); not a field on submit.** VERDICT: Corrected
    (spec implied `pdf_url` on submit). SOURCE: OpenAPI
    `generate_response_session_pdf_…` (`SessionPdfEnvelope`) and
    `download_response_session_pdf_…`.
14. **Mutating verbs carry `X-CSRF-Token` from the `ui_csrf` cookie;
    `credentials: include` (cookies) on all requests.** VERDICT: Verified.
    SOURCE: `src/api/client.ts` lines 167-171 (CSRF) and 183 (`credentials:
    "include"`).
15. **401 triggers a single `POST /ui/session/refresh` then retry.** VERDICT:
    Verified (endpoint exists). SOURCE: OpenAPI `POST /ui/session/refresh`
    (op=ui_session_refresh_…). The refresh-then-retry orchestration is AND-013's
    behavior (not re-verified here).
16. **422 validation errors use FastAPI `HTTPValidationError`.** VERDICT:
    Verified. SOURCE: OpenAPI — every questionnaire op lists
    `422:HTTPValidationError`.
17. **Polymorphic adapter via `PolymorphicJsonAdapterFactory` (moshi-adapters)
    or moshix sealed-codegen, keyed on `type` with `Unknown` default.** VERDICT:
    Unverified-assumption (framework choice; not derivable from backend/frontend).
    SOURCE: framework ref — Moshi
    `https://github.com/square/moshi#polymorphic-types`; moshix
    `https://github.com/ZacSweers/MoshiX/tree/main/moshi-sealed`.
18. **Stack: Kotlin 2.0.21, Retrofit 2.11, OkHttp 4.12, Moshi 1.15 + KSP, Hilt;
    minSdk 24 / compileSdk 35, JDK 17.** VERDICT: Unverified-assumption (inherited
    from AND-027/AND-010; not in the reviewed sources). SOURCE: framework refs —
    Retrofit `https://square.github.io/retrofit/`, Moshi
    `https://github.com/square/moshi`.

### Corrections made

- Path params: `{slug}`→`{published_slug}`, `{session_id}`→`{response_session_id}`
  (§2, §4.3, §5).
- All published/session responses are **enveloped**, not bare DTOs (§4.3, §5):
  `version` / `session` / `answers_by_question_id` / `result` / `artifact`.
- Save endpoint: `PATCH {answers}` → `PUT` `SessionSaveReq`
  `{answers_by_question_id, current_section_index?, current_question_id?}`
  (§4.3, §5, §7).
- Start session: removed non-existent `resume_token`; request is
  `ResponseSessionStartReq` (web posts `{}`); response no longer inlines the
  questionnaire (§4.4/§5, FR-4).
- Validate/submit: added the real `QuestionnaireValidationRequest` body and
  corrected the response to `QuestionnaireValidationResponse` with map-shaped
  `errors` of `ValidationIssue`; submit returns `SessionSubmitEnvelope`
  (§4.3, §5, FR-4).
- Removed `pdf_url`/`submitted_at` from submit; PDF is a separate endpoint pair
  (§4.3, §5, FR-1).
- Field/question type catalog corrected to the nine real types; per-type config
  noted as opaque `config_json` (FR-3, §4.1).
- Required structural key names corrected (FR-6).
- §11 snake_case key examples corrected to verified wire keys.

### Open assumptions

- **Polymorphic adapter mechanism (R5).** Whether moshix sealed-codegen or
  `PolymorphicJsonAdapterFactory` is on the classpath cannot be confirmed from
  the backend/frontend sources; depends on the AND-010/027 build setup. Pick at
  implementation time.
- **Internal shape of `schema_json` / `config_json` / `session` objects.** The
  backend OpenAPI declares these as opaque `additionalProperties:true`, so the
  exact nested keys (e.g. how `select` options or `slider` bounds are encoded
  inside `config_json`) are **not** verifiable from OpenAPI. The typed Kotlin
  model must be reconstructed from a captured real fixture (R1) and tolerate
  unknown keys until then.
- **Answer value union per question type (R4).** Whether single-select answers
  are scalar or single-element arrays is not pinned by the sources;
  `answers_by_question_id` is an opaque map. Confirm against a real session
  capture; the `AnswerValue` union tolerates both.
- **Anonymous vs authenticated respondent / CSRF on anonymous POST (R3).**
  `PublishedQuestionnaireVersion.allow_anonymous` exists, but whether anonymous
  POST/PUT requires `X-CSRF-Token`/a session cookie is not specified in the
  sources. Confirm against the running backend.
- **Stack/version pins.** Library versions are inherited assumptions from
  upstream tickets, not verified here.

## 17. Test Plan

Test target legend (CI/dev): **JVM** = local JVM/Robolectric unit (no device);
**MWS** = MockWebServer contract test on JVM; **emu test35** = headless AVD
x86_64 API 35; **A15** = physical Samsung Galaxy A15 5G (SM-A156U, API 34,
arm64-v8a). This is a transport/DTO-only ticket with **no UI**, so the bulk runs
on JVM/MWS; the physical device is used only to prove the ABI/API-34 build and
the real-network/cookie+CSRF path against the live dev host.

- **TC-AND-346-01** — Type: contract/MockWebServer. Target: MWS.
  Preconditions: `QuestionnaireApi` built on a Retrofit pointed at MWS.
  Steps: enqueue a `PublishedQuestionnaireEnvelope` body, call `getPublished`.
  Expected: recorded request is `GET /questionnaires/published/{published_slug}`;
  response deserializes to the envelope and `version.schema_json` decodes to the
  questionnaire tree. Traces: AC-4.
- **TC-AND-346-02** — Type: unit (round-trip). Target: JVM.
  Preconditions: `all_field_types.json` fixture with one of each of the nine real
  types (`text, select, multiselect, radio, slider, date, time, timezone,
  address`), each with a representative `config_json`.
  Steps: deserialize, assert each maps to the correct `QuestionnaireField`
  subtype with expected `config_json`; re-serialize and compare parsed trees.
  Expected: all nine map correctly and round-trip equal. Traces: AC-2.
- **TC-AND-346-03** — Type: unit. Target: JVM.
  Preconditions: fixture with `"type":"signature"` (unknown).
  Steps: deserialize.
  Expected: yields `QuestionnaireField.Unknown(type="signature")`, no throw.
  Traces: AC-3.
- **TC-AND-346-04** — Type: unit. Target: JVM.
  Preconditions: question JSON with `question_id`/`type`/`section_id` removed
  (one per case); session JSON with `response_session_id` removed.
  Steps: deserialize each.
  Expected: each throws `JsonDataException` (fail-fast on missing required
  structural key). Traces: AC-3.
- **TC-AND-346-05** — Type: unit. Target: JVM.
  Preconditions: `QuestionnaireDto`/session JSON with extra unknown keys
  (`server_time`, future field).
  Steps: deserialize.
  Expected: unknown keys skipped, parse succeeds. Traces: AC-3.
- **TC-AND-346-06** — Type: unit. Target: JVM.
  Preconditions: none.
  Steps: serialize representative DTOs; inspect keys.
  Expected: output uses verified snake_case (`answers_by_question_id`,
  `question_id`, `section_id`, `response_session_id`, `current_section_index`,
  `is_valid`, `can_submit`, `has_blocking_form_error`, `rule_id`); no camelCase
  wire keys present. Traces: AC-5.
- **TC-AND-346-07** — Type: unit. Target: JVM.
  Preconditions: `answers_by_question_id` samples covering string, number,
  boolean, list-of-strings, date-string, and empty/null.
  Steps: deserialize to `AnswerValue` then re-serialize.
  Expected: each maps to the correct `AnswerValue` subtype and round-trips;
  malformed value → `AnswerValue.Empty` (no throw). Traces: AC-5, AC-3.
- **TC-AND-346-08** — Type: contract/MockWebServer. Target: MWS.
  Preconditions: API on MWS.
  Steps: call `startSession` with `ResponseSessionStartReq()`; assert request is
  `POST .../sessions` with body `{}` (or `{questionnaire_id:...}`); enqueue
  `ResponseSessionEnvelope`. Then call `saveAnswers`; assert verb is **`PUT`**,
  body has `answers_by_question_id`/`current_section_index`/`current_question_id`,
  response deserializes to `SessionStateEnvelope`.
  Expected: paths, verbs (incl. PUT not PATCH), bodies, and decoded envelopes all
  match §5. Traces: AC-4.
- **TC-AND-346-09** — Type: contract/MockWebServer. Target: MWS.
  Preconditions: API on MWS.
  Steps: call `validate` and `submit`; assert each is `POST`, body is
  `QuestionnaireValidationRequest` (with `contract_version`,
  `final_submit=false`/`true`, `form_rules`/`group_rules`); enqueue a failing
  `QuestionnaireValidationResponse` for validate (map-shaped `errors` with a
  `ValidationIssue`) and a `SessionSubmitEnvelope` for submit.
  Expected: requests/bodies match; validate decodes `errors` as
  `Map<String,List<ValidationIssue>>`; submit decodes `{session,result}`.
  Traces: AC-4.
- **TC-AND-346-10** — Type: contract/MockWebServer. Target: MWS.
  Preconditions: API on MWS.
  Steps: enqueue a `422` with a FastAPI `HTTPValidationError` body for
  `saveAnswers`.
  Expected: the call surfaces the error to the AND-015 `detail` mapper unchanged
  (no questionnaire-specific error model); no crash. Traces: AC-4, AC-7.
- **TC-AND-346-11** — Type: unit (security). Target: JVM.
  Preconditions: populated `SaveAnswersReq`/`SubmitReq` equivalents
  (answer-bearing DTOs).
  Steps: call `toString()`.
  Expected: no answer values present (redacted, e.g. `<N redacted>`).
  Traces: AC-6.
- **TC-AND-346-12** — Type: unit (security/fixtures). Target: JVM.
  Preconditions: committed JSON fixtures.
  Steps: scan fixtures for PII patterns.
  Expected: only synthetic answers; no real PII. Traces: AC-6.
- **TC-AND-346-13** — Type: contract/MockWebServer (CSRF/cookie). Target: MWS.
  Preconditions: OkHttp stack with the AND-011 cookie jar + AND-012 CSRF
  interceptor; a `ui_csrf` cookie present.
  Steps: invoke `saveAnswers` (PUT) and `submit` (POST) against MWS.
  Expected: recorded requests carry `X-CSRF-Token` equal to the `ui_csrf` value
  and the session cookie; idempotent GETs (`getPublished`/`getSession`) need no
  CSRF. Traces: AC-4, AC-7.
- **TC-AND-346-14** — Type: instrumented/e2e (real network). Target: **A15
  (physical device — required)**. MUST run on the physical device to exercise the
  arm64-v8a API-34 build and the real flaky plaintext-HTTP dev host
  (`http://18.222.237.167:8000`); the x86_64 emulator does not represent the
  shipping ABI/API level.
  Preconditions: a published questionnaire slug exists on the dev host; debug
  build installed via adb on serial R5CX821TA9R.
  Steps: run an instrumented test that calls `getPublished` then `startSession`
  against the live host, with the GET-retry/backoff (AND-016) active; force one
  transient failure (toggle airplane mode mid-GET) to hit the offline path.
  Expected: GET retries within the ~20s budget and ultimately decodes the
  envelope; `startSession` (mutating) is **not** auto-retried; module loads and
  Moshi codegen runs correctly on arm64-v8a/API 34. Traces: AC-4, AC-7.

Accessibility: not applicable — this ticket introduces no composables/UI
(§9); a11y checks are deferred to AND-347. Noted here so reviewers see the
omission is intentional.

### Coverage matrix

| AC (§14) | Covered by |
| --- | --- |
| AC-1 (DTOs exist, factory + AnswerValue adapter registered) | TC-02, TC-07, TC-13 (adapters exercised via parse/serialize through the registered Moshi) |
| AC-2 (schema maps; round-trip equal) | TC-02 |
| AC-3 (Unknown type; unknown keys tolerated; missing required throws) | TC-03, TC-04, TC-05, TC-07 |
| AC-4 (all API methods callable; path/verb/body match §5) | TC-01, TC-08, TC-09, TC-10, TC-13, TC-14 |
| AC-5 (snake_case keys; AnswerValue union round-trips) | TC-06, TC-07 |
| AC-6 (toString redaction; no real PII in fixtures) | TC-11, TC-12 |
| AC-7 (compiles via KSP; retries/CSRF constraints; downstream can reference) | TC-10, TC-13, TC-14 |
