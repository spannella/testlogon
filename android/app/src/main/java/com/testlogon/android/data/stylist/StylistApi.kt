package com.testlogon.android.data.stylist

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.PUT
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * Retrofit interface + Moshi DTOs for the Stylist / UI-design agent (web /agents/stylist area).
 *
 * Mirrors frontend/src/api/endpoints/stylistAgent.ts (BASE /ui/agents/stylist): design overview
 * (page + overall scores), design rules CRUD, review detail + create-ticket-from-issue, and
 * trigger-review. All endpoints are backend `require_ui_session` (agent_stylist.py) -> usable by any
 * authenticated user (no operator gate). Timestamps are epoch-SECONDS (Long). Session cookies / Bearer /
 * X-CSRF-Token are attached by interceptors. The base URL carries a trailing slash, so every path is
 * relative and WITHOUT a leading slash.
 */
interface StylistApi {

    @GET("ui/agents/stylist/scores")
    suspend fun getPageScores(): List<PageDesignScoreDto>

    @GET("ui/agents/stylist/scores/overall")
    suspend fun getOverallScore(): OverallDesignScoreDto

    @GET("ui/agents/stylist/reviews")
    suspend fun listReviews(
        @Query("page_url") pageUrl: String? = null,
        @Query("review_type") reviewType: String? = null,
        @Query("limit") limit: Int? = null,
    ): UIReviewListDto

    @GET("ui/agents/stylist/reviews/{reviewId}")
    suspend fun getReview(@Path("reviewId") reviewId: String): UIReviewDto

    @POST("ui/agents/stylist/reviews/{reviewId}/issues/{issueId}/ticket")
    suspend fun createIssueTicket(
        @Path("reviewId") reviewId: String,
        @Path("issueId") issueId: String,
        @Body body: Map<String, String> = emptyMap(),
    ): CreateIssueTicketResultDto

    @POST("ui/agents/stylist/trigger-review")
    suspend fun triggerReview(@Body body: TriggerUIReviewReqDto): TriggerUIReviewResultDto

    @GET("ui/agents/stylist/rules")
    suspend fun listRules(@Query("category") category: String? = null): List<DesignRuleDto>

    @POST("ui/agents/stylist/rules")
    suspend fun createRule(@Body body: CreateDesignRuleReqDto): DesignRuleDto

    @PUT("ui/agents/stylist/rules/{ruleId}")
    suspend fun updateRule(
        @Path("ruleId") ruleId: String,
        @Body body: UpdateDesignRuleReqDto,
    ): DesignRuleDto

    @DELETE("ui/agents/stylist/rules/{ruleId}")
    suspend fun deleteRule(@Path("ruleId") ruleId: String): DeleteRuleResultDto
}

// ---- DTOs ----

@JsonClass(generateAdapter = true)
data class PageDesignScoreDto(
    @Json(name = "page_url") val pageUrl: String = "",
    @Json(name = "page_name") val pageName: String = "",
    @Json(name = "design_score") val designScore: Double = 0.0,
    @Json(name = "accessibility_score") val accessibilityScore: Double? = null,
    @Json(name = "issues_found") val issuesFound: Int = 0,
    @Json(name = "last_reviewed") val lastReviewed: Long = 0,
)

@JsonClass(generateAdapter = true)
data class OverallDesignScoreDto(
    @Json(name = "overall_design_score") val overallDesignScore: Double = 0.0,
    @Json(name = "overall_accessibility_score") val overallAccessibilityScore: Double = 0.0,
    @Json(name = "pages_reviewed") val pagesReviewed: Int = 0,
    @Json(name = "total_issues") val totalIssues: Int = 0,
)

@JsonClass(generateAdapter = true)
data class UIReviewListDto(
    val reviews: List<UIReviewDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class UIReviewScreenshotDto(
    val url: String = "",
    val viewport: String = "",
    val label: String = "",
)

@JsonClass(generateAdapter = true)
data class UIReviewIssueDto(
    @Json(name = "issue_id") val issueId: String = "",
    val category: String = "",
    val severity: String = "",
    val title: String = "",
    val description: String = "",
    val suggestion: String = "",
    @Json(name = "created_ticket_id") val createdTicketId: String? = null,
)

@JsonClass(generateAdapter = true)
data class UIReviewDto(
    @Json(name = "review_id") val reviewId: String = "",
    @Json(name = "page_url") val pageUrl: String = "",
    @Json(name = "page_name") val pageName: String = "",
    @Json(name = "review_type") val reviewType: String = "",
    val screenshots: List<UIReviewScreenshotDto> = emptyList(),
    @Json(name = "design_score") val designScore: Double = 0.0,
    @Json(name = "accessibility_score") val accessibilityScore: Double? = null,
    @Json(name = "issues_found") val issuesFound: Int = 0,
    val issues: List<UIReviewIssueDto> = emptyList(),
    val status: String = "",
    @Json(name = "created_at") val createdAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class CreateIssueTicketResultDto(
    val ok: Boolean = false,
    @Json(name = "ticket_id") val ticketId: String = "",
    @Json(name = "review_id") val reviewId: String = "",
    @Json(name = "issue_id") val issueId: String = "",
)

@JsonClass(generateAdapter = true)
data class TriggerUIReviewReqDto(
    val pages: List<String>,
    @Json(name = "review_type") val reviewType: String = "full_page",
)

@JsonClass(generateAdapter = true)
data class TriggerUIReviewResultDto(
    val ok: Boolean = false,
    val reviews: List<UIReviewDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class DesignRuleDto(
    @Json(name = "rule_id") val ruleId: String = "",
    val name: String = "",
    val category: String = "",
    val description: String = "",
    val severity: String = "",
    val enabled: Boolean = true,
    @Json(name = "created_at") val createdAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class CreateDesignRuleReqDto(
    val name: String,
    val category: String,
    val description: String,
    val severity: String,
)

@JsonClass(generateAdapter = true)
data class UpdateDesignRuleReqDto(
    val name: String? = null,
    val category: String? = null,
    val description: String? = null,
    val severity: String? = null,
    val enabled: Boolean? = null,
)

@JsonClass(generateAdapter = true)
data class DeleteRuleResultDto(
    val ok: Boolean = false,
    @Json(name = "rule_id") val ruleId: String = "",
)
