package com.testlogon.android.core.network.questionnaire

import com.squareup.moshi.Json

/**
 * Questionnaire BUILDER (creator-authoring) transport DTOs - the draft/section/question management
 * surface that the web `QuestionnaireBuilderPage` consumes. The respondent surface lives in
 * [QuestionnaireApi]; this file adds only the authenticated owner-side builder shapes.
 *
 * CODEGEN NOTE (identical to the apikeys/webhooks pattern): core-network does NOT apply the Moshi KSP
 * codegen plugin, so these DTOs decode via the reflective KotlinJsonAdapterFactory registered on the
 * shared Moshi in NetworkModule.provideMoshi. The reflective factory maps Kotlin property names to JSON
 * keys VERBATIM (Moshi does NOT auto snake_case), so every wire key is pinned with an explicit
 * @Json(name = ...). @JsonClass(generateAdapter = true) is intentionally OMITTED.
 *
 * WIRE CONTRACT (verified against app/routers/questionnaires.py; relative paths, NO leading slash):
 *   GET    questionnaires/drafts?include_archived=  -> { items: [DraftDto] }
 *   POST   questionnaires/drafts                    -> { draft: DraftDto }   body = DraftCreateReq
 *   GET    questionnaires/drafts/{id}               -> { draft: DraftDto }
 *   PATCH  questionnaires/drafts/{id}               -> { draft: DraftDto }   body = DraftUpdateReq
 *   DELETE questionnaires/drafts/{id}               -> { draft: DraftDto }   (archive)
 *   GET    .../{id}/sections                        -> { items: [SectionDto] }
 *   POST   .../{id}/sections                        -> { section: SectionDto } body = SectionCreateReq
 *   PATCH  .../{id}/sections/{sid}                  -> { section: SectionDto } body = SectionUpdateReq
 *   DELETE .../{id}/sections/{sid}                  -> { section: SectionDto }
 *   GET    .../{id}/sections/{sid}/questions        -> { items: [QuestionDto] }
 *   POST   .../{id}/questions                       -> { question: QuestionDto } body = QuestionCreateReq
 *   PATCH  .../{id}/questions/{qid}?section_id=      -> { question: QuestionDto } body = QuestionUpdateReq
 *   DELETE .../{id}/questions/{qid}?section_id=      -> { question: QuestionDto }
 *   POST   .../{id}/publish                         -> { version: VersionDto }   body = PublishReq
 *
 * TIME: created_at / updated_at / published_at are EPOCH-SECOND STRINGS (the backend stores str(now_ts()))
 * - typed as String? here and formatted at the UI. `position` is an int. `config_json` is an opaque
 * additionalProperties object decoded to a Map (the typed per-type config lives only in the builder UI).
 */

/** One questionnaire draft (the META row) as returned by the drafts list / draft envelopes. */
data class QnrDraftDto(
    @Json(name = "questionnaire_id") val questionnaireId: String,
    @Json(name = "title") val title: String? = null,
    @Json(name = "description") val description: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "visibility") val visibility: String? = null,
    @Json(name = "published_version_id") val publishedVersionId: String? = null,
    @Json(name = "created_at") val createdAt: String? = null,
    @Json(name = "updated_at") val updatedAt: String? = null,
)

/** One section row. */
data class QnrSectionDto(
    @Json(name = "section_id") val sectionId: String,
    @Json(name = "title") val title: String? = null,
    @Json(name = "description") val description: String? = null,
    @Json(name = "position") val position: Int = 0,
)

/** One question row. `config_json` is the opaque per-type config object. */
data class QnrQuestionDto(
    @Json(name = "question_id") val questionId: String,
    @Json(name = "section_id") val sectionId: String,
    @Json(name = "type") val type: String,
    @Json(name = "label") val label: String? = null,
    @Json(name = "required") val required: Boolean = false,
    @Json(name = "hint") val hint: String? = null,
    @Json(name = "config_json") val configJson: Map<String, @JvmSuppressWildcards Any?> = emptyMap(),
    @Json(name = "position") val position: Int = 0,
)

/** A published immutable version (returned by publish). */
data class QnrVersionDto(
    @Json(name = "version_id") val versionId: String,
    @Json(name = "questionnaire_id") val questionnaireId: String? = null,
    @Json(name = "version_number") val versionNumber: Int? = null,
    @Json(name = "published_slug") val publishedSlug: String? = null,
    @Json(name = "published_at") val publishedAt: String? = null,
)

// ---- Envelopes ----

data class QnrDraftEnvelope(@Json(name = "draft") val draft: QnrDraftDto)
data class QnrDraftListEnvelope(@Json(name = "items") val items: List<QnrDraftDto> = emptyList())
data class QnrSectionEnvelope(@Json(name = "section") val section: QnrSectionDto)
data class QnrSectionListEnvelope(@Json(name = "items") val items: List<QnrSectionDto> = emptyList())
data class QnrQuestionEnvelope(@Json(name = "question") val question: QnrQuestionDto)
data class QnrQuestionListEnvelope(@Json(name = "items") val items: List<QnrQuestionDto> = emptyList())
data class QnrVersionEnvelope(@Json(name = "version") val version: QnrVersionDto)

// ---- Request bodies ----

data class QnrDraftCreateReq(
    @Json(name = "questionnaire_id") val questionnaireId: String,
    @Json(name = "title") val title: String,
    @Json(name = "description") val description: String = "",
    @Json(name = "visibility") val visibility: String = "private",
)

data class QnrDraftUpdateReq(
    @Json(name = "title") val title: String? = null,
    @Json(name = "description") val description: String? = null,
    @Json(name = "visibility") val visibility: String? = null,
)

data class QnrSectionCreateReq(
    @Json(name = "section_id") val sectionId: String,
    @Json(name = "title") val title: String,
    @Json(name = "description") val description: String = "",
)

data class QnrSectionUpdateReq(
    @Json(name = "title") val title: String? = null,
    @Json(name = "description") val description: String? = null,
)

data class QnrQuestionCreateReq(
    @Json(name = "section_id") val sectionId: String,
    @Json(name = "question_id") val questionId: String,
    @Json(name = "type") val type: String,
    @Json(name = "label") val label: String,
    @Json(name = "required") val required: Boolean = false,
    @Json(name = "hint") val hint: String = "",
    @Json(name = "config_json") val configJson: Map<String, @JvmSuppressWildcards Any?> = emptyMap(),
)

data class QnrQuestionUpdateReq(
    @Json(name = "label") val label: String? = null,
    @Json(name = "required") val required: Boolean? = null,
    @Json(name = "hint") val hint: String? = null,
    @Json(name = "config_json") val configJson: Map<String, @JvmSuppressWildcards Any?>? = null,
)

data class QnrPublishReq(
    @Json(name = "published_slug") val publishedSlug: String? = null,
)
