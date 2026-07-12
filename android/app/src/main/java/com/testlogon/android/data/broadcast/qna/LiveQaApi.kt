package com.testlogon.android.data.broadcast.qna

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-284 — dedicated Retrofit interface for live Q&A.
 *
 * VERIFIED against reference/openapi.index.txt lines 1625-1637 + src/api/endpoints/liveQa.ts +
 * src/api/types.ts (LiveQaQuestion / LiveQaQueueResponse / LiveQaModeResponse):
 *  - GET    ui/live-qa/sessions/{id}/questions?status=&limit= -> { questions, has_more }
 *  - GET    ui/live-qa/sessions/{id}/featured                 -> LiveQaQuestion | null
 *  - GET    ui/live-qa/sessions/{id}/mode                     -> { ok, session_id, qa_mode_enabled }
 *  - POST   ui/live-qa/sessions/{id}/questions (LiveQaQuestionSubmitIn) -> 200 LiveQaQuestion
 *  - POST   ui/live-qa/sessions/{id}/questions/{qid}/vote     -> 200 LiveQaQuestion
 *  - DELETE ui/live-qa/sessions/{id}/questions/{qid}/vote     -> 200 LiveQaQuestion
 *
 * The viewer panel requests viewer-visible statuses (`featured` / `answered`) — NOT `pending` (which is
 * host/moderator-only per the OpenAPI list description). Vote uses POST/DELETE on the SAME .../vote path
 * (no /upvote or /downvote verb). created_at/featured_at are epoch numbers; per-viewer voted state has
 * no server field and is tracked locally. Distinct from MessagingApi (its FakeApi is untouched).
 */
interface LiveQaApi {

    @GET("ui/live-qa/sessions/{id}/questions")
    suspend fun getQuestions(
        @Path("id") sessionId: String,
        @Query("status") status: String = STATUS_FEATURED,
        @Query("limit") limit: Int = DEFAULT_LIMIT,
    ): Response<QaQuestionsDto>

    @GET("ui/live-qa/sessions/{id}/featured")
    suspend fun getFeatured(
        @Path("id") sessionId: String,
    ): Response<QaQuestionDto?>

    @GET("ui/live-qa/sessions/{id}/mode")
    suspend fun getMode(
        @Path("id") sessionId: String,
    ): Response<QaModeDto>

    @POST("ui/live-qa/sessions/{id}/questions")
    suspend fun ask(
        @Path("id") sessionId: String,
        @Body body: AskQuestionDto,
    ): Response<QaQuestionDto>

    @POST("ui/live-qa/sessions/{id}/questions/{questionId}/vote")
    suspend fun upvote(
        @Path("id") sessionId: String,
        @Path("questionId") questionId: String,
    ): Response<QaQuestionDto>

    @DELETE("ui/live-qa/sessions/{id}/questions/{questionId}/vote")
    suspend fun removeUpvote(
        @Path("id") sessionId: String,
        @Path("questionId") questionId: String,
    ): Response<QaQuestionDto>

    // ---- HOST CONSOLE (web LiveQaPage) — host/moderator-only ui/live-qa endpoints. ----

    /** Enable / disable Q&A mode for the session (host only). Body { enabled }. */
    @POST("ui/live-qa/sessions/{id}/mode")
    suspend fun setMode(
        @Path("id") sessionId: String,
        @Body body: SetModeDto,
    ): Response<QaModeDto>

    /** Q&A engagement stats (host/moderator only). */
    @GET("ui/live-qa/sessions/{id}/stats")
    suspend fun getStats(@Path("id") sessionId: String): Response<QaStatsDto>

    /** Feature a question on the broadcast overlay (host/moderator). Returns the updated question. */
    @POST("ui/live-qa/sessions/{id}/questions/{questionId}/feature")
    suspend fun feature(
        @Path("id") sessionId: String,
        @Path("questionId") questionId: String,
    ): Response<QaQuestionDto>

    /** Mark a question answered (host/moderator). Returns the updated question. */
    @POST("ui/live-qa/sessions/{id}/questions/{questionId}/answer")
    suspend fun answer(
        @Path("id") sessionId: String,
        @Path("questionId") questionId: String,
    ): Response<QaQuestionDto>

    /** Dismiss a question (host/moderator). Returns the updated question. */
    @POST("ui/live-qa/sessions/{id}/questions/{questionId}/dismiss")
    suspend fun dismiss(
        @Path("id") sessionId: String,
        @Path("questionId") questionId: String,
    ): Response<QaQuestionDto>

    /** Pin / unpin a question to the top of the queue (host/moderator). Body { pinned }. */
    @POST("ui/live-qa/sessions/{id}/questions/{questionId}/pin")
    suspend fun pin(
        @Path("id") sessionId: String,
        @Path("questionId") questionId: String,
        @Body body: PinQuestionDto,
    ): Response<QaQuestionDto>

    /** Soft-delete (remove) a question (host/moderator). Returns { ok, question_id }. */
    @POST("ui/live-qa/sessions/{id}/questions/{questionId}/remove")
    suspend fun remove(
        @Path("id") sessionId: String,
        @Path("questionId") questionId: String,
    ): Response<QaRemoveResultDto>

    companion object {
        const val STATUS_FEATURED = "featured"
        const val STATUS_ANSWERED = "answered"
        const val STATUS_PENDING = "pending"
        const val DEFAULT_LIMIT = 50
    }
}

/** LiveQaQuestion — created_at/featured_at/answered_at are epoch NUMBERS (Long). */
@JsonClass(generateAdapter = true)
data class QaQuestionDto(
    @Json(name = "question_id") val questionId: String,
    @Json(name = "session_id") val sessionId: String = "",
    @Json(name = "submitter_id") val submitterId: String = "",
    @Json(name = "submitter_display_name") val submitterDisplayName: String = "",
    @Json(name = "text") val text: String = "",
    @Json(name = "status") val status: String = "pending",
    @Json(name = "vote_count") val voteCount: Int = 0,
    @Json(name = "pinned") val pinned: Boolean = false,
    @Json(name = "featured_at") val featuredAt: Long? = null,
    @Json(name = "answered_at") val answeredAt: Long? = null,
    @Json(name = "created_at") val createdAt: Long = 0L,
    @Json(name = "featured_by") val featuredBy: String? = null,
)

/** LiveQaQueueResponse — { questions, has_more }. */
@JsonClass(generateAdapter = true)
data class QaQuestionsDto(
    @Json(name = "questions") val questions: List<QaQuestionDto> = emptyList(),
    @Json(name = "has_more") val hasMore: Boolean = false,
)

/** LiveQaModeResponse — { ok, session_id, qa_mode_enabled }. */
@JsonClass(generateAdapter = true)
data class QaModeDto(
    @Json(name = "ok") val ok: Boolean = true,
    @Json(name = "session_id") val sessionId: String = "",
    @Json(name = "qa_mode_enabled") val qaModeEnabled: Boolean = false,
)

/** LiveQaQuestionSubmitIn — { text } (server enforces 1..500). */
@JsonClass(generateAdapter = true)
data class AskQuestionDto(
    @Json(name = "text") val text: String,
)

/** LiveQaModeToggleIn — { enabled }. */
@JsonClass(generateAdapter = true)
data class SetModeDto(
    @Json(name = "enabled") val enabled: Boolean,
)

/** LiveQaPinIn — { pinned }. */
@JsonClass(generateAdapter = true)
data class PinQuestionDto(
    @Json(name = "pinned") val pinned: Boolean,
)

/** LiveQaStats — host engagement summary. */
@JsonClass(generateAdapter = true)
data class QaStatsDto(
    @Json(name = "total_questions") val totalQuestions: Int = 0,
    @Json(name = "answered") val answered: Int = 0,
    @Json(name = "dismissed") val dismissed: Int = 0,
    @Json(name = "featured") val featured: Int = 0,
    @Json(name = "pending") val pending: Int = 0,
    @Json(name = "total_upvotes") val totalUpvotes: Int = 0,
    @Json(name = "avg_upvotes") val avgUpvotes: Double = 0.0,
    @Json(name = "answer_rate") val answerRate: Double = 0.0,
)

/** remove response — { ok, question_id }. */
@JsonClass(generateAdapter = true)
data class QaRemoveResultDto(
    @Json(name = "ok") val ok: Boolean = true,
    @Json(name = "question_id") val questionId: String = "",
)
