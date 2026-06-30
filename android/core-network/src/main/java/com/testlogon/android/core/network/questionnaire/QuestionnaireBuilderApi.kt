package com.testlogon.android.core.network.questionnaire

import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.HTTP
import retrofit2.http.Headers
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * Retrofit interface for the questionnaire BUILDER (creator-authoring) surface - the draft / section /
 * question management + publish endpoints under `questionnaires/drafts` (web `QuestionnaireBuilderPage`
 * parity). Distinct from the respondent [QuestionnaireApi].
 *
 * Transport only; no repo / VM / UI. Paths have NO leading slash (relative to the shared Retrofit base
 * URL). All calls are suspend and return the RAW enveloped DTO directly; the ApiResult wrapping + FastAPI
 * detail mapping is the downstream repository's job. Mutating verbs that send a JSON body carry an
 * explicit JSON Content-Type. Session cookies / Authorization Bearer / X-CSRF-Token are attached globally
 * by the core-network interceptors (these are AUTHENTICATED owner-side calls - NOT [Anonymous]).
 *
 * DELETE-with-body is avoided; the delete-question/delete-section calls pass `section_id` as a query param
 * (matching the web client). The PATCH-question call also carries `section_id` as a query param exactly as
 * the backend's `update_question(section_id: str = Query(...))` requires.
 */
interface QuestionnaireBuilderApi {

    // ---- Drafts ----

    @GET("questionnaires/drafts")
    suspend fun listDrafts(
        @Query("include_archived") includeArchived: Boolean = false,
    ): QnrDraftListEnvelope

    @Headers("Content-Type: application/json")
    @POST("questionnaires/drafts")
    suspend fun createDraft(@Body body: QnrDraftCreateReq): QnrDraftEnvelope

    @GET("questionnaires/drafts/{id}")
    suspend fun getDraft(@Path("id") questionnaireId: String): QnrDraftEnvelope

    @Headers("Content-Type: application/json")
    @PATCH("questionnaires/drafts/{id}")
    suspend fun updateDraft(
        @Path("id") questionnaireId: String,
        @Body body: QnrDraftUpdateReq,
    ): QnrDraftEnvelope

    @DELETE("questionnaires/drafts/{id}")
    suspend fun archiveDraft(@Path("id") questionnaireId: String): QnrDraftEnvelope

    // ---- Sections ----

    @GET("questionnaires/drafts/{id}/sections")
    suspend fun listSections(@Path("id") questionnaireId: String): QnrSectionListEnvelope

    @Headers("Content-Type: application/json")
    @POST("questionnaires/drafts/{id}/sections")
    suspend fun createSection(
        @Path("id") questionnaireId: String,
        @Body body: QnrSectionCreateReq,
    ): QnrSectionEnvelope

    @Headers("Content-Type: application/json")
    @PATCH("questionnaires/drafts/{id}/sections/{sid}")
    suspend fun updateSection(
        @Path("id") questionnaireId: String,
        @Path("sid") sectionId: String,
        @Body body: QnrSectionUpdateReq,
    ): QnrSectionEnvelope

    @DELETE("questionnaires/drafts/{id}/sections/{sid}")
    suspend fun deleteSection(
        @Path("id") questionnaireId: String,
        @Path("sid") sectionId: String,
    ): QnrSectionEnvelope

    // ---- Questions ----

    @GET("questionnaires/drafts/{id}/sections/{sid}/questions")
    suspend fun listQuestions(
        @Path("id") questionnaireId: String,
        @Path("sid") sectionId: String,
    ): QnrQuestionListEnvelope

    @Headers("Content-Type: application/json")
    @POST("questionnaires/drafts/{id}/questions")
    suspend fun createQuestion(
        @Path("id") questionnaireId: String,
        @Body body: QnrQuestionCreateReq,
    ): QnrQuestionEnvelope

    @Headers("Content-Type: application/json")
    @PATCH("questionnaires/drafts/{id}/questions/{qid}")
    suspend fun updateQuestion(
        @Path("id") questionnaireId: String,
        @Path("qid") questionId: String,
        @Query("section_id") sectionId: String,
        @Body body: QnrQuestionUpdateReq,
    ): QnrQuestionEnvelope

    @HTTP(method = "DELETE", path = "questionnaires/drafts/{id}/questions/{qid}", hasBody = false)
    suspend fun deleteQuestion(
        @Path("id") questionnaireId: String,
        @Path("qid") questionId: String,
        @Query("section_id") sectionId: String,
    ): QnrQuestionEnvelope

    // ---- Publish ----

    @Headers("Content-Type: application/json")
    @POST("questionnaires/drafts/{id}/publish")
    suspend fun publish(
        @Path("id") questionnaireId: String,
        @Body body: QnrPublishReq,
    ): QnrVersionEnvelope
}
