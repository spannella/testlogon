package com.testlogon.android.data.analytics

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Query

/**
 * AND-399 - Retrofit interface + Moshi DTOs for the account-wide analytics DASHBOARDS surface (the
 * native port of the web reference src/api/endpoints/analytics.ts). This is the general analytics read
 * surface under /ui/analytics, NOT the ads-campaign analytics owned by AND-368 (under /ui/ads).
 *
 * CORRECTED contract (see spec AND-399 sections 5 and 16): there is NO single /ui/analytics/dashboard
 * or /ui/analytics/breakdown endpoint. The real surface is a set of per-metric GETs taking
 * from_date / to_date (NOT start / end) plus a POST /ui/analytics/refresh recompute. The repository
 * fans out across these GETs and assembles the dashboard domain model client-side.
 *
 * Verified against reference/openapi.index.txt (lines 1144-1158) and components.schemas.Analytics*Out /
 * EngagementRateOut in reference/openapi.pretty.json.
 *
 * Session cookies / Authorization Bearer / X-CSRF-Token ride the core-network interceptors (AND-027);
 * this interface adds no auth logic and no headers.
 */
interface AnalyticsDashboardApi {

    /** KPI summary (views / revenue_cents / new+total subscribers) plus an embedded top_content list. */
    @GET("ui/analytics/overview")
    suspend fun getOverview(
        @Query("from_date") fromDate: String,
        @Query("to_date") toDate: String,
    ): AnalyticsOverviewDto

    /** Views / watch-time daily series. */
    @GET("ui/analytics/views")
    suspend fun getViews(
        @Query("from_date") fromDate: String,
        @Query("to_date") toDate: String,
        @Query("granularity") granularity: String = GRANULARITY_DAY,
    ): AnalyticsViewsDto

    /** Subscriber-growth series (new / churned / net / total). */
    @GET("ui/analytics/subscribers")
    suspend fun getSubscribers(
        @Query("from_date") fromDate: String,
        @Query("to_date") toDate: String,
        @Query("granularity") granularity: String = GRANULARITY_DAY,
    ): AnalyticsSubscribersDto

    /** Top content rows. sort_by is `views` (engagement_rate is server-computed and not sortable). */
    @GET("ui/analytics/top-content")
    suspend fun getTopContent(
        @Query("from_date") fromDate: String,
        @Query("to_date") toDate: String,
        @Query("sort_by") sortBy: String = SORT_BY_VIEWS,
        @Query("limit") limit: Int = DEFAULT_TOP_CONTENT_LIMIT,
    ): AnalyticsTopContentDto

    /** Audience by country / device (percentage fields are already 0-100 numbers). */
    @GET("ui/analytics/audience")
    suspend fun getAudience(
        @Query("from_date") fromDate: String,
        @Query("to_date") toDate: String,
    ): AnalyticsAudienceDto

    /**
     * Pull-to-refresh recompute trigger; the dashboard GETs are re-issued afterwards. This is the only
     * non-GET on the screen and is an idempotent recompute (NOT an analytics write).
     */
    @POST("ui/analytics/refresh")
    suspend fun refresh(): AnalyticsRefreshDto

    companion object {
        const val GRANULARITY_DAY = "day"
        const val SORT_BY_VIEWS = "views"
        const val DEFAULT_TOP_CONTENT_LIMIT = 10
    }
}

// ---- DTOs (AND-399). All fields default per the backend schema so a partial / `200 {}` decodes safely. ----

/** Mirrors AnalyticsOverviewOut (KPI tiles + embedded top_content). Revenue is integer cents. */
@JsonClass(generateAdapter = true)
data class AnalyticsOverviewDto(
    @Json(name = "period_views") val periodViews: Long = 0L,
    @Json(name = "period_revenue_cents") val periodRevenueCents: Long = 0L,
    @Json(name = "period_new_subscribers") val periodNewSubscribers: Long = 0L,
    @Json(name = "total_subscribers") val totalSubscribers: Long = 0L,
    val currency: String = "USD",
    @Json(name = "top_content") val topContent: List<AnalyticsTopContentItemDto> = emptyList(),
)

/** Mirrors AnalyticsViewsOut. watch_time is integer SECONDS. */
@JsonClass(generateAdapter = true)
data class AnalyticsViewsDto(
    @Json(name = "time_series") val timeSeries: List<AnalyticsViewsPointDto> = emptyList(),
    @Json(name = "total_views") val totalViews: Long = 0L,
    @Json(name = "total_watch_time_seconds") val totalWatchTimeSeconds: Long = 0L,
)

@JsonClass(generateAdapter = true)
data class AnalyticsViewsPointDto(
    val date: String = "",
    val views: Long = 0L,
    @Json(name = "unique_viewers") val uniqueViewers: Long = 0L,
    @Json(name = "watch_time_seconds") val watchTimeSeconds: Long = 0L,
)

/** Mirrors AnalyticsSubscribersOut. */
@JsonClass(generateAdapter = true)
data class AnalyticsSubscribersDto(
    @Json(name = "time_series") val timeSeries: List<AnalyticsSubscribersPointDto> = emptyList(),
    @Json(name = "current_total") val currentTotal: Long = 0L,
    @Json(name = "net_change") val netChange: Long = 0L,
)

@JsonClass(generateAdapter = true)
data class AnalyticsSubscribersPointDto(
    val date: String = "",
    val new: Long = 0L,
    val churned: Long = 0L,
    val net: Long = 0L,
    val total: Long = 0L,
)

/** Mirrors AnalyticsTopContentOut. engagement_rate is a 0-1 fraction; revenue is integer cents. */
@JsonClass(generateAdapter = true)
data class AnalyticsTopContentDto(
    val items: List<AnalyticsTopContentItemDto> = emptyList(),
    @Json(name = "total_items") val totalItems: Long = 0L,
)

@JsonClass(generateAdapter = true)
data class AnalyticsTopContentItemDto(
    @Json(name = "content_id") val contentId: String = "",
    @Json(name = "content_type") val contentType: String = "",
    val title: String = "",
    val views: Long = 0L,
    @Json(name = "revenue_cents") val revenueCents: Long = 0L,
    @Json(name = "engagement_rate") val engagementRate: Double = 0.0,
)

/** Mirrors AnalyticsAudienceOut. percentage fields are already 0-100 numbers (no client scaling). */
@JsonClass(generateAdapter = true)
data class AnalyticsAudienceDto(
    val countries: List<AnalyticsCountryDto> = emptyList(),
    val devices: List<AnalyticsDeviceDto> = emptyList(),
    @Json(name = "total_unique_viewers") val totalUniqueViewers: Long = 0L,
)

@JsonClass(generateAdapter = true)
data class AnalyticsCountryDto(
    val code: String = "",
    val name: String = "",
    val viewers: Long = 0L,
    val percentage: Double = 0.0,
)

@JsonClass(generateAdapter = true)
data class AnalyticsDeviceDto(
    val type: String = "",
    val viewers: Long = 0L,
    val percentage: Double = 0.0,
)

/** Mirrors AnalyticsRefreshOut (the recompute acknowledgement). Fields are tolerated, not required. */
@JsonClass(generateAdapter = true)
data class AnalyticsRefreshDto(
    val status: String = "",
    @Json(name = "recomputed_at") val recomputedAt: String? = null,
)
