package com.testlogon.android.data.analytics

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.GET
import retrofit2.http.Query

/**
 * AND-254 — Retrofit interface + Moshi DTOs for the creator engagement-rate surface.
 *
 * Verified against reference/openapi.index.txt and components.schemas in reference/openapi.pretty.json
 * (EngagementRateOut L31437, EngagementTimeSeriesItem L31615, EngagementTimeSeriesOut L31648) plus
 * reference/src/api/endpoints/engagementRate.ts and reference/src/api/types.ts (EngagementRate,
 * EngagementTimeSeriesItem, EngagementTimeSeries).
 *
 * The engagement RATE is computed SERVER-SIDE and returned verbatim (engagement_rate percentage +
 * engagement_rate_bps). There is NO client formula and NO reach/impressions/saves/views/previous/series
 * on the rate endpoint; the denominator is follower_count. The TREND chart is fed by the separate
 * /ui/analytics/engagement/history endpoint (EngagementTimeSeriesOut { items: [...] }).
 *
 * Endpoint citations (reference/openapi.index.txt):
 *  - GET ui/analytics/engagement         (EngagementRateOut; params period_days,...)
 *  - GET ui/analytics/engagement/history (EngagementTimeSeriesOut; params from_date,to_date,...)
 *
 * Session cookies / Authorization Bearer / X-CSRF-Token ride core-network interceptors; the
 * operator-only user_sub / X-SESSION-ID / X-IMPERSONATION-TOKEN params are deliberately NOT sent.
 */
interface EngagementApi {

    /** Server-computed engagement summary for the period (rate + breakdown counts + server trend). */
    @GET("ui/analytics/engagement")
    suspend fun getEngagement(
        @Query("period_days") periodDays: Int = DEFAULT_PERIOD_DAYS,
    ): EngagementRateDto

    /** The engagement-rate time series (for the trend chart). Dates default to the server window. */
    @GET("ui/analytics/engagement/history")
    suspend fun getEngagementHistory(
        @Query("from_date") fromDate: String? = null,
        @Query("to_date") toDate: String? = null,
    ): EngagementTimeSeriesDto

    companion object {
        const val DEFAULT_PERIOD_DAYS = 30
    }
}

// ---- DTOs (AND-254) ----

/** Mirrors EngagementRateOut exactly. All fields have server defaults so a partial 200 decodes safely. */
@JsonClass(generateAdapter = true)
data class EngagementRateDto(
    @Json(name = "engagement_rate") val engagementRate: Double = 0.0,
    @Json(name = "engagement_rate_bps") val engagementRateBps: Int = 0,
    @Json(name = "period_days") val periodDays: Int = 0,
    @Json(name = "total_interactions") val totalInteractions: Int = 0,
    @Json(name = "follower_count") val followerCount: Int = 0,
    @Json(name = "posts_in_period") val postsInPeriod: Int = 0,
    val likes: Int = 0,
    val comments: Int = 0,
    val shares: Int = 0,
    val tips: Int = 0,
    val trend: String = "",
    @Json(name = "trend_delta") val trendDelta: Double = 0.0,
)

/** Mirrors EngagementTimeSeriesOut { items: EngagementTimeSeriesItem[] }. */
@JsonClass(generateAdapter = true)
data class EngagementTimeSeriesDto(
    // `items` defaults empty defensively for the flaky dev host occasionally returning `200 {}`.
    val items: List<EngagementTimeSeriesItemDto> = emptyList(),
)

/** Mirrors EngagementTimeSeriesItem (`date` required; the rest default per the schema). */
@JsonClass(generateAdapter = true)
data class EngagementTimeSeriesItemDto(
    val date: String,
    @Json(name = "engagement_rate") val engagementRate: Double = 0.0,
    @Json(name = "engagement_rate_bps") val engagementRateBps: Int = 0,
    val interactions: Int = 0,
    @Json(name = "post_count") val postCount: Int = 0,
)
