package com.testlogon.android.core.network.questionnaire

import com.testlogon.android.core.model.questionnaire.PublishedQuestionnaireEnvelope
import com.testlogon.android.core.model.questionnaire.QuestionnaireValidationRequest
import com.testlogon.android.core.model.questionnaire.QuestionnaireValidationResponse
import com.testlogon.android.core.model.questionnaire.ResponseSessionEnvelope
import com.testlogon.android.core.model.questionnaire.ResponseSessionStartReq
import com.testlogon.android.core.model.questionnaire.SessionPdfEnvelope
import com.testlogon.android.core.model.questionnaire.SessionSaveReq
import com.testlogon.android.core.model.questionnaire.SessionStateEnvelope
import com.testlogon.android.core.model.questionnaire.SessionSubmitEnvelope
import okhttp3.ResponseBody
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.PUT
import retrofit2.http.Path
import retrofit2.http.Streaming

/**
 * AND-346 - Retrofit interface for the published-questionnaire RESPONDENT surface (epic E45).
 * Transport only; no repo / VM / UI.
 *
 * Paths have NO leading slash (relative to the shared Retrofit base URL, matching the rest of the
 * codebase). All calls are suspend and return the RAW DTO directly (mirroring AND-339 SigningApi):
 * the ApiResult wrapping + FastAPI detail mapping is the downstream repository's job (AND-348), NOT
 * this layer's. Mutating verbs that send a JSON body carry an explicit JSON Content-Type. Session
 * cookies, Authorization Bearer and X-CSRF-Token are attached globally by the core-network
 * interceptors.
 *
 * Path tokens are EXACTLY {published_slug} and {response_session_id} per the corrected OpenAPI
 * contract. All published reads/sessions responses are ENVELOPED (version / session /
 * answers_by_question_id / result / artifact wrappers).
 *
 * PDF endpoints (generate + download) are owned by AND-349; they are included here (returning
 * SessionPdfEnvelope for generate, a @Streaming raw Response of ResponseBody for download) so the
 * full surface is modeled, but their call sites are AND-349's concern.
 */
interface QuestionnaireApi {

    /** GET a published questionnaire by slug. Returns the enveloped published version (version.schema_json). */
    @GET("questionnaires/published/{published_slug}")
    suspend fun getPublished(
        @Path("published_slug") publishedSlug: String,
    ): PublishedQuestionnaireEnvelope

    /** POST create/open a respondent session. The web client posts an empty body. */
    @Headers("Content-Type: application/json")
    @POST("questionnaires/published/{published_slug}/sessions")
    suspend fun startSession(
        @Path("published_slug") publishedSlug: String,
        @Body body: ResponseSessionStartReq,
    ): ResponseSessionEnvelope

    /** GET the current state of a respondent session (session + answers_by_question_id). */
    @GET("questionnaires/published/{published_slug}/sessions/{response_session_id}")
    suspend fun getSession(
        @Path("published_slug") publishedSlug: String,
        @Path("response_session_id") responseSessionId: String,
    ): SessionStateEnvelope

    /** PUT (NOT PATCH) partial answers + cursor. Returns the updated session state envelope. */
    @Headers("Content-Type: application/json")
    @PUT("questionnaires/published/{published_slug}/sessions/{response_session_id}")
    suspend fun saveAnswers(
        @Path("published_slug") publishedSlug: String,
        @Path("response_session_id") responseSessionId: String,
        @Body body: SessionSaveReq,
    ): SessionStateEnvelope

    /** POST validate a session's answers. Returns the validation response (errors keyed by question id). */
    @Headers("Content-Type: application/json")
    @POST("questionnaires/published/{published_slug}/sessions/{response_session_id}/validate")
    suspend fun validate(
        @Path("published_slug") publishedSlug: String,
        @Path("response_session_id") responseSessionId: String,
        @Body body: QuestionnaireValidationRequest,
    ): QuestionnaireValidationResponse

    /** POST submit a session (typically final_submit=true). Returns the submit envelope (session + result). */
    @Headers("Content-Type: application/json")
    @POST("questionnaires/published/{published_slug}/sessions/{response_session_id}/submit")
    suspend fun submit(
        @Path("published_slug") publishedSlug: String,
        @Path("response_session_id") responseSessionId: String,
        @Body body: QuestionnaireValidationRequest,
    ): SessionSubmitEnvelope

    // ---- PDF (owned by AND-349; modeled here for completeness) ----

    /** POST generate the response PDF artifact (owned by AND-349). */
    @POST("questionnaires/published/{published_slug}/sessions/{response_session_id}/pdf")
    suspend fun generatePdf(
        @Path("published_slug") publishedSlug: String,
        @Path("response_session_id") responseSessionId: String,
    ): SessionPdfEnvelope

    /** GET download the response PDF bytes (streamed; opaque PDF, not JSON). Owned by AND-349. */
    @Streaming
    @GET("questionnaires/published/{published_slug}/sessions/{response_session_id}/pdf")
    suspend fun downloadPdf(
        @Path("published_slug") publishedSlug: String,
        @Path("response_session_id") responseSessionId: String,
    ): Response<ResponseBody>
}
