package com.testlogon.android.data.pmideas

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * Retrofit interface + Moshi DTOs for the PM-agent feature-idea TRIAGE surface (web /agents/pm/ideas).
 *
 * Mirrors frontend/src/api/endpoints/productAgent.ts (BASE /ui/agents/pm): list ideas by status,
 * approve / reject / archive, and a manual "trigger review". Distinct from the member idea-SUBMIT flow
 * (feature/ideas -> /ui/agents/ideas). All endpoints are backend `require_ui_session` (agent_pm.py) ->
 * NOT admin-gated (usable by the test user), though the web places it in the operator/agents area.
 * Idea `created_at` / `reviewed_at` are epoch-SECONDS (Long). Session cookies / Bearer / X-CSRF-Token
 * attached by interceptors; paths relative (base URL carries the trailing slash).
 */
interface PmIdeasApi {

    @GET("ui/agents/pm/ideas")
    suspend fun listIdeas(
        @Query("status") status: String? = null,
        @Query("cursor") cursor: String? = null,
    ): FeatureIdeaListDto

    @GET("ui/agents/pm/ideas/{ideaId}")
    suspend fun getIdea(@Path("ideaId") ideaId: String): FeatureIdeaDto

    @POST("ui/agents/pm/ideas/{ideaId}/approve")
    suspend fun approveIdea(@Path("ideaId") ideaId: String, @Body body: Map<String, String> = emptyMap()): FeatureIdeaDto

    @POST("ui/agents/pm/ideas/{ideaId}/reject")
    suspend fun rejectIdea(@Path("ideaId") ideaId: String, @Body body: RejectIdeaReqDto): FeatureIdeaDto

    @POST("ui/agents/pm/ideas/{ideaId}/archive")
    suspend fun archiveIdea(@Path("ideaId") ideaId: String, @Body body: Map<String, String> = emptyMap()): FeatureIdeaDto

    @POST("ui/agents/pm/trigger-review")
    suspend fun triggerReview(@Body body: TriggerReviewReqDto): TriggerReviewResultDto
}

// ---- DTOs ----

@JsonClass(generateAdapter = true)
data class FeatureIdeaDto(
    @Json(name = "idea_id") val ideaId: String = "",
    @Json(name = "user_id") val userId: String = "",
    @Json(name = "agent_id") val agentId: String = "",
    val title: String = "",
    val description: String = "",
    val category: String = "",
    @Json(name = "priority_suggestion") val prioritySuggestion: String = "",
    @Json(name = "user_impact") val userImpact: String = "",
    @Json(name = "mockup_description") val mockupDescription: String? = null,
    val status: String = "",
    @Json(name = "rejection_reason") val rejectionReason: String? = null,
    @Json(name = "created_ticket_id") val createdTicketId: String? = null,
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "reviewed_at") val reviewedAt: Long? = null,
)

@JsonClass(generateAdapter = true)
data class FeatureIdeaListDto(
    val ideas: List<FeatureIdeaDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class RejectIdeaReqDto(
    val reason: String,
)

@JsonClass(generateAdapter = true)
data class TriggerReviewReqDto(
    @Json(name = "agent_id") val agentId: String = "pm-agent",
    val count: Int = 3,
)

@JsonClass(generateAdapter = true)
data class TriggerReviewResultDto(
    val ok: Boolean = false,
)
