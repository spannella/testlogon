package com.testlogon.android.core.model.questionnaire

/**
 * AND-346 - questionnaire SCHEMA container DTOs (the decoded `schema_json` tree + its published-version
 * envelope). The QUESTIONNAIRES domain, epic E45. Data/transport only.
 *
 * RECONCILIATION NOTE (core-model has no Moshi): like the rest of core-model these carry NO `@Json` /
 * `@JsonClass` annotations (core-model has no moshi dependency - AND-319 KYC precedent). The production
 * Moshi decodes them via the reflective KotlinJsonAdapterFactory, so each property name IS the
 * snake_case wire key (questionnaire_id, schema_json, ...). The polymorphic `questions` list decodes via
 * the custom core-network QuestionnaireFieldAdapter (registered before the reflective factory).
 *
 * Wire shape (frontend src/api/types.ts + QuestionnaireRespondentPage):
 *   version.schema_json = { questionnaire_id, sections: [ { section_id, title?, questions: [...] } ] }
 * The published read is ENVELOPED: GET .../published/{published_slug} -> { version: {...} } (FR-6: the
 * `version` wrapper and `schema_json` are required at the top level). The backend OpenAPI declares
 * `schema_json` as an opaque additionalProperties:true object, so the typed tree below is reconstructed
 * from frontend usage and tolerates unknown keys.
 *
 * Ordering of sections / questions is significant and preserved (ordered List - FR-7). Required
 * structural keys have NO default (absence -> JsonDataException). Optional fields are nullable with null
 * defaults; the questions/sections lists default to empty so partial bodies decode.
 */

/** One section of a questionnaire schema; `questions` are ordered and decoded polymorphically. */
data class QuestionnaireSection(
    val section_id: String,
    val title: String? = null,
    val description: String? = null,
    val position: Int? = null,
    val questions: List<QuestionnaireField> = emptyList(),
)

/**
 * The decoded questionnaire schema tree (the content of `schema_json`). `questionnaire_id` identifies
 * the questionnaire; `sections` are ordered. Tolerates unknown keys (additive backend evolution).
 */
data class QuestionnaireDto(
    val questionnaire_id: String,
    val title: String? = null,
    val version_id: String? = null,
    val sections: List<QuestionnaireSection> = emptyList(),
)

/**
 * A published questionnaire version (frontend PublishedQuestionnaireVersion). `schema_json` carries the
 * questionnaire schema tree and is REQUIRED (FR-6); published_slug / questionnaire_id / version_id are
 * required structural keys. schema_json is typed as [QuestionnaireDto] here (the reflective adapter +
 * the custom field adapter decode it); unknown keys inside it are tolerated.
 */
data class PublishedQuestionnaireVersion(
    val published_slug: String,
    val questionnaire_id: String,
    val version_id: String,
    val schema_json: QuestionnaireDto,
    val version_number: Int? = null,
    val visibility: String? = null,
    val allow_anonymous: Boolean? = null,
    val published_at: String? = null,
)

/**
 * Top-level envelope for GET /questionnaires/published/{published_slug}. The `version` wrapper is
 * required at the top level (FR-6); the questionnaire is nested under `version.schema_json`, NOT a bare
 * top-level DTO. ASSUMPTION: the envelope key is `version` (frontend posts `api.get<{ version: ... }>`).
 */
data class PublishedQuestionnaireEnvelope(
    val version: PublishedQuestionnaireVersion,
)
