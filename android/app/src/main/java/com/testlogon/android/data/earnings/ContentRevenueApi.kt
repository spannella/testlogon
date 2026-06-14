package com.testlogon.android.data.earnings

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.GET
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-253 — Retrofit interface + Moshi DTOs for per-content revenue.
 *
 * Verified against reference/openapi.index.txt (lines 1145..1148) and
 * reference/src/api/endpoints/perContentRevenue.ts + components.schemas
 * (ContentRevenueListOut, ContentRevenueItem, ContentRevenueDetailOut, ContentRevenueTimeSeriesPoint).
 * Money is integer cents; `published_at` is epoch SECONDS (0 == unknown). Auth rides the shared cookie/
 * CSRF interceptors; the operator-only `user_sub`/`X-SESSION-ID`/`X-IMPERSONATION-TOKEN` are NOT sent.
 * The non-slash path is used (the trailing-slash variant could 307 and drop headers).
 *
 * Endpoint citations:
 *  - GET ui/analytics/content-revenue              L1145  (ContentRevenueListOut)
 *  - GET ui/analytics/content-revenue/{content_id} L1148  (ContentRevenueDetailOut)
 */
interface ContentRevenueApi {

    @GET("ui/analytics/content-revenue")
    suspend fun list(
        @Query("from_date") fromDate: String? = null,
        @Query("to_date") toDate: String? = null,
        @Query("sort_by") sortBy: String = DEFAULT_SORT_BY,
        @Query("sort_order") sortOrder: String = DEFAULT_SORT_ORDER,
        @Query("content_type") contentType: String? = null,
        @Query("limit") limit: Int = DEFAULT_LIMIT,
        @Query("cursor") cursor: String? = null,
    ): ContentRevenueListDto

    @GET("ui/analytics/content-revenue/{content_id}")
    suspend fun detail(
        @Path("content_id") contentId: String,
        @Query("from_date") fromDate: String? = null,
        @Query("to_date") toDate: String? = null,
    ): ContentRevenueDetailDto

    companion object {
        const val DEFAULT_SORT_BY = "total_cents"
        const val DEFAULT_SORT_ORDER = "desc"
        const val DEFAULT_LIMIT = 50
        const val MAX_LIMIT = 200
    }
}

// ---- DTOs (AND-253) ----

@JsonClass(generateAdapter = true)
data class ContentRevenueItemDto(
    @Json(name = "content_id") val contentId: String,
    @Json(name = "content_type") val contentType: String = "post",
    val title: String = "",
    @Json(name = "published_at") val publishedAt: Long = 0,
    @Json(name = "tips_cents") val tipsCents: Long = 0,
    @Json(name = "unlocks_cents") val unlocksCents: Long = 0,
    @Json(name = "subscriptions_cents") val subscriptionsCents: Long = 0,
    @Json(name = "ads_cents") val adsCents: Long = 0,
    @Json(name = "vod_cents") val vodCents: Long = 0,
    @Json(name = "total_cents") val totalCents: Long = 0,
)

@JsonClass(generateAdapter = true)
data class ContentRevenueListDto(
    val items: List<ContentRevenueItemDto> = emptyList(),
    @Json(name = "total_items") val totalItems: Int = 0,
    @Json(name = "total_revenue_cents") val totalRevenueCents: Long = 0,
    @Json(name = "next_cursor") val nextCursor: String? = null,
    val currency: String = DEFAULT_CURRENCY,
)

@JsonClass(generateAdapter = true)
data class ContentRevenueTimeSeriesPointDto(
    val date: String,
    @Json(name = "tips_cents") val tipsCents: Long = 0,
    @Json(name = "unlocks_cents") val unlocksCents: Long = 0,
    @Json(name = "subscriptions_cents") val subscriptionsCents: Long = 0,
    @Json(name = "ads_cents") val adsCents: Long = 0,
    @Json(name = "vod_cents") val vodCents: Long = 0,
    @Json(name = "total_cents") val totalCents: Long = 0,
)

@JsonClass(generateAdapter = true)
data class ContentRevenueDetailDto(
    @Json(name = "content_id") val contentId: String,
    @Json(name = "content_type") val contentType: String = "post",
    val title: String = "",
    @Json(name = "published_at") val publishedAt: Long = 0,
    @Json(name = "tips_cents") val tipsCents: Long = 0,
    @Json(name = "unlocks_cents") val unlocksCents: Long = 0,
    @Json(name = "subscriptions_cents") val subscriptionsCents: Long = 0,
    @Json(name = "ads_cents") val adsCents: Long = 0,
    @Json(name = "vod_cents") val vodCents: Long = 0,
    @Json(name = "total_cents") val totalCents: Long = 0,
    val currency: String = DEFAULT_CURRENCY,
    @Json(name = "time_series") val timeSeries: List<ContentRevenueTimeSeriesPointDto> = emptyList(),
)
