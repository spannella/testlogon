package com.testlogon.android.data.marketing

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
 * Retrofit interface + Moshi DTOs for the Marketing content agent (web /agents/marketing area).
 *
 * Mirrors frontend/src/api/endpoints/marketingAgent.ts (BASE /ui/agents/marketing): content list +
 * CRUD, lifecycle actions (approve/schedule/publish/archive), calendar (month), and engagement
 * summary. All endpoints are backend `require_ui_session` (agent_marketing.py) -> usable by any
 * authenticated user (no operator gate). Timestamps are epoch-SECONDS (Long). Session cookies / Bearer /
 * X-CSRF-Token attached by interceptors; paths relative (base URL carries the trailing slash).
 */
interface MarketingApi {

    @GET("ui/agents/marketing/content")
    suspend fun listContent(
        @Query("type") type: String? = null,
        @Query("status") status: String? = null,
        @Query("limit") limit: Int? = null,
        @Query("cursor") cursor: String? = null,
    ): MarketingContentListDto

    @POST("ui/agents/marketing/content")
    suspend fun createContent(@Body body: CreateMarketingContentReqDto): MarketingContentDto

    @GET("ui/agents/marketing/content/{contentId}")
    suspend fun getContent(@Path("contentId") contentId: String): MarketingContentDto

    @PUT("ui/agents/marketing/content/{contentId}")
    suspend fun updateContent(
        @Path("contentId") contentId: String,
        @Body body: UpdateMarketingContentReqDto,
    ): MarketingContentDto

    @POST("ui/agents/marketing/content/{contentId}/approve")
    suspend fun approveContent(@Path("contentId") contentId: String): MarketingContentDto

    @POST("ui/agents/marketing/content/{contentId}/schedule")
    suspend fun scheduleContent(
        @Path("contentId") contentId: String,
        @Body body: ScheduleReqDto,
    ): MarketingContentDto

    @POST("ui/agents/marketing/content/{contentId}/publish")
    suspend fun publishContent(@Path("contentId") contentId: String): MarketingContentDto

    @POST("ui/agents/marketing/content/{contentId}/archive")
    suspend fun archiveContent(@Path("contentId") contentId: String): MarketingContentDto

    @DELETE("ui/agents/marketing/content/{contentId}")
    suspend fun deleteContent(@Path("contentId") contentId: String): DeleteContentResultDto

    @GET("ui/agents/marketing/calendar")
    suspend fun getCalendar(@Query("month") month: String): List<ContentCalendarEntryDto>

    @GET("ui/agents/marketing/engagement/summary")
    suspend fun getEngagementSummary(@Query("days") days: Int = 30): MarketingEngagementSummaryDto
}

// ---- DTOs ----

@JsonClass(generateAdapter = true)
data class MarketingContentDto(
    @Json(name = "content_id") val contentId: String = "",
    @Json(name = "content_type") val contentType: String = "",
    val title: String = "",
    val body: String = "",
    val summary: String? = null,
    @Json(name = "feature_refs") val featureRefs: List<String>? = null,
    val tags: List<String>? = null,
    @Json(name = "seo_meta") val seoMeta: SeoMetaDto? = null,
    val status: String = "",
    @Json(name = "scheduled_publish_at") val scheduledPublishAt: Long? = null,
    @Json(name = "published_at") val publishedAt: Long? = null,
    @Json(name = "target_platform") val targetPlatform: String? = null,
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class SeoMetaDto(
    val title: String? = null,
    val description: String? = null,
    val keywords: List<String>? = null,
)

@JsonClass(generateAdapter = true)
data class MarketingContentListDto(
    val items: List<MarketingContentDto> = emptyList(),
    val cursor: String? = null,
    val count: Int = 0,
)

@JsonClass(generateAdapter = true)
data class CreateMarketingContentReqDto(
    @Json(name = "content_type") val contentType: String,
    val title: String,
    val body: String,
    val summary: String? = null,
    val tags: List<String>? = null,
    @Json(name = "seo_meta") val seoMeta: Map<String, Any?>? = null,
)

@JsonClass(generateAdapter = true)
data class UpdateMarketingContentReqDto(
    val title: String? = null,
    val body: String? = null,
    val summary: String? = null,
    val tags: List<String>? = null,
    @Json(name = "seo_meta") val seoMeta: Map<String, Any?>? = null,
)

@JsonClass(generateAdapter = true)
data class ScheduleReqDto(
    @Json(name = "publish_at") val publishAt: Long,
)

@JsonClass(generateAdapter = true)
data class DeleteContentResultDto(
    val ok: Boolean = false,
    @Json(name = "content_id") val contentId: String = "",
    val deleted: Boolean = false,
)

@JsonClass(generateAdapter = true)
data class ContentCalendarEntryDto(
    @Json(name = "content_id") val contentId: String = "",
    val title: String = "",
    @Json(name = "content_type") val contentType: String = "",
    val status: String = "",
    val date: Long = 0,
)

@JsonClass(generateAdapter = true)
data class TopPerformingDto(
    @Json(name = "content_id") val contentId: String = "",
    val title: String = "",
    val clicks: Int = 0,
)

@JsonClass(generateAdapter = true)
data class MarketingEngagementSummaryDto(
    @Json(name = "total_content") val totalContent: Int = 0,
    @Json(name = "total_views") val totalViews: Int = 0,
    @Json(name = "total_clicks") val totalClicks: Int = 0,
    @Json(name = "total_signups") val totalSignups: Int = 0,
    @Json(name = "avg_click_rate") val avgClickRate: Double = 0.0,
    @Json(name = "avg_signup_rate") val avgSignupRate: Double = 0.0,
    @Json(name = "top_performing") val topPerforming: List<TopPerformingDto> = emptyList(),
)
