package com.testlogon.android.data.ideas

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Query

/**
 * Retrofit interface + Moshi DTOs for the user-facing product-ideas feature.
 *
 * Mirrors the web ideas/submit page (frontend/src/pages/agents/IdeaSubmissionPage.tsx ->
 * frontend/src/api/endpoints/pmAgent.ts): submit a new idea (POST ui/agents/ideas {title, description})
 * and list the signed-in member's ideas (GET ui/agents/ideas, cursor-paged). Response shapes verified
 * against the ProductIdea / IdeaListResult interfaces in frontend/src/api/types.ts. The admin-only
 * triage endpoints (getIdea / updateIdeaStatus / pm-operation) are deliberately omitted -- this is the
 * member-facing submit surface only. Session cookies / Bearer / X-CSRF-Token are attached by
 * interceptors. The base URL carries the trailing slash, so every path here is relative and WITHOUT a
 * leading slash.
 */
interface IdeasApi {

    /** The signed-in member's submitted ideas; [status] filters, [cursor] pages forward. */
    @GET("ui/agents/ideas")
    suspend fun listIdeas(
        @Query("status") status: String? = null,
        @Query("limit") limit: Int? = null,
        @Query("cursor") cursor: String? = null,
    ): IdeaListDto

    /** Submits a new product idea for PM-agent triage. */
    @POST("ui/agents/ideas")
    suspend fun submitIdea(@Body body: IdeaCreateReqDto): IdeaDto
}

// ---- DTOs ----

@JsonClass(generateAdapter = true)
data class IdeaListDto(
    val ideas: List<IdeaDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class IdeaDto(
    @Json(name = "idea_id") val ideaId: String,
    @Json(name = "submitted_by") val submittedBy: String = "",
    val title: String = "",
    val description: String = "",
    val status: String = "",
    @Json(name = "priority_suggestion") val prioritySuggestion: String? = null,
    @Json(name = "impact_score") val impactScore: Double? = null,
    @Json(name = "effort_score") val effortScore: Double? = null,
    @Json(name = "priority_rationale") val priorityRationale: String? = null,
    @Json(name = "feature_ticket_id") val featureTicketId: String? = null,
    @Json(name = "agent_run_id") val agentRunId: String? = null,
    @Json(name = "rejection_reason") val rejectionReason: String? = null,
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class IdeaCreateReqDto(
    val title: String,
    val description: String,
)
