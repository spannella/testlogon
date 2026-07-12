package com.testlogon.android.core.network.ads

import com.squareup.moshi.Json

/**
 * Transport DTOs for the CONTENT AD-CONTROLS surface (ui/ads/content-controls). Mirrors the backend
 * pydantic models ContentAdOverrideIn/Out, RevenueShareIn, AdRevenueBreakdownOut, AdvertiserTransparencyOut.
 *
 * CODEGEN NOTE (identical to the rest of core-network/ads): core-network does NOT apply the Moshi KSP
 * codegen plugin, so these DTOs decode via the reflective KotlinJsonAdapterFactory on the shared Moshi
 * (NetworkModule.provideMoshi). The reflective factory maps Kotlin property names VERBATIM, so every wire
 * key is pinned with an explicit @Json(name = ...). @JsonClass(generateAdapter = true) is OMITTED. No new
 * Moshi adapter is needed (all fields are primitives / String / List).
 *
 * MONEY is a flat *_cents Long; revenue share is an integer basis-points; updated_at is an epoch Long.
 */

/** A per-content ad override request. ad_density is one of low|standard|high; content_type video|post|broadcast. */
data class ContentAdOverrideIn(
    @Json(name = "content_type") val contentType: String = "video",
    @Json(name = "ad_enabled") val adEnabled: Boolean? = null,
    @Json(name = "ad_density") val adDensity: String? = null,
    @Json(name = "pre_roll_enabled") val preRollEnabled: Boolean? = null,
    @Json(name = "mid_roll_enabled") val midRollEnabled: Boolean? = null,
    @Json(name = "ads_free_for_subscribers") val adsFreeForSubscribers: Boolean? = null,
)

/** A saved per-content override as returned by list/get/upsert. */
data class ContentAdOverrideDto(
    @Json(name = "content_id") val contentId: String,
    @Json(name = "content_type") val contentType: String = "video",
    @Json(name = "owner_sub") val ownerSub: String? = null,
    @Json(name = "ad_enabled") val adEnabled: Boolean = true,
    @Json(name = "ad_density") val adDensity: String = "standard",
    @Json(name = "pre_roll_enabled") val preRollEnabled: Boolean = true,
    @Json(name = "mid_roll_enabled") val midRollEnabled: Boolean = true,
    @Json(name = "ads_free_for_subscribers") val adsFreeForSubscribers: Boolean = false,
    @Json(name = "updated_at") val updatedAt: Long? = null,
)

/** A generic {ok} response (e.g. delete-override). */
data class OkResponseDto(
    @Json(name = "ok") val ok: Boolean = true,
)

/** Revenue-share set request (basis points, server-capped 0-7000). */
data class RevenueShareIn(
    @Json(name = "revenue_share_bps") val revenueShareBps: Int,
)

/** Revenue-share response. The PUT response may also carry {ok}; only the bps is read downstream. */
data class RevenueShareDto(
    @Json(name = "revenue_share_bps") val revenueShareBps: Int = 7000,
    @Json(name = "ok") val ok: Boolean? = null,
)

/** One by-content row of the ad-revenue breakdown. */
data class AdRevenueBreakdownContentDto(
    @Json(name = "content_id") val contentId: String,
    @Json(name = "revenue_cents") val revenueCents: Long = 0L,
)

/** The ad-revenue breakdown (total + window + share + per-content top list). */
data class AdRevenueBreakdownDto(
    @Json(name = "total_ad_revenue_cents") val totalAdRevenueCents: Long = 0L,
    @Json(name = "entry_count") val entryCount: Int = 0,
    @Json(name = "days") val days: Int = 30,
    @Json(name = "revenue_share_bps") val revenueShareBps: Int = 7000,
    @Json(name = "top_content") val topContent: List<AdRevenueBreakdownContentDto> = emptyList(),
)

/** One advertiser-transparency row (an advertiser whose ads ran on the caller content). */
data class AdvertiserTransparencyDto(
    @Json(name = "account_id") val accountId: String,
    @Json(name = "company_name") val companyName: String = "Unknown",
    @Json(name = "total_impressions") val totalImpressions: Long = 0L,
    @Json(name = "total_clicks") val totalClicks: Long = 0L,
    @Json(name = "total_revenue_cents") val totalRevenueCents: Long = 0L,
)
