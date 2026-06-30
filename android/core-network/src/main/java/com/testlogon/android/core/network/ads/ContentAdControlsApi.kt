package com.testlogon.android.core.network.ads

import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.PUT
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * Retrofit interface for the CONTENT AD-CONTROLS surface (web parity: content_ad_controls.py, prefix
 * /ui/ads/content-controls). Per-content ad overrides, the creator revenue share, and the ad-revenue
 * transparency / breakdown layer.
 *
 * Paths have NO leading slash (relative to the shared Retrofit base URL); session cookie / CSRF are attached
 * globally by the core-network interceptors. The override LIST returns a BARE ARRAY; get/upsert return a
 * single override; delete returns {ok}; revenue-share GET/PUT return {revenue_share_bps,...}; the breakdown
 * returns an object; transparency returns a BARE ARRAY. Mirrors the web contentAdControls.ts functions.
 * RAW DTOs; the feature repo maps to domain.
 */
interface ContentAdControlsApi {

    /** GET all per-content overrides for the caller (BARE ARRAY). */
    @GET("ui/ads/content-controls/overrides")
    suspend fun listOverrides(): List<ContentAdOverrideDto>

    /** GET one override by content id. */
    @GET("ui/ads/content-controls/overrides/{contentId}")
    suspend fun getOverride(@Path("contentId") contentId: String): ContentAdOverrideDto

    /** PUT (upsert) one override. Returns the saved override. */
    @PUT("ui/ads/content-controls/overrides/{contentId}")
    suspend fun upsertOverride(
        @Path("contentId") contentId: String,
        @Body body: ContentAdOverrideIn,
    ): ContentAdOverrideDto

    /** DELETE one override. Returns {ok:Boolean}. */
    @DELETE("ui/ads/content-controls/overrides/{contentId}")
    suspend fun deleteOverride(@Path("contentId") contentId: String): OkResponseDto

    /** GET the creator revenue share in basis points. */
    @GET("ui/ads/content-controls/revenue-share")
    suspend fun getRevenueShare(): RevenueShareDto

    /** PUT (set) the creator revenue share in basis points (0-7000). */
    @PUT("ui/ads/content-controls/revenue-share")
    suspend fun setRevenueShare(@Body body: RevenueShareIn): RevenueShareDto

    /** GET the ad-revenue breakdown over the given day window (default 30, 1-365). */
    @GET("ui/ads/content-controls/revenue-breakdown")
    suspend fun getRevenueBreakdown(@Query("days") days: Int): AdRevenueBreakdownDto

    /** GET the advertiser transparency list (optionally for a YYYY-MM month). BARE ARRAY. */
    @GET("ui/ads/content-controls/transparency")
    suspend fun getTransparency(@Query("month") month: String? = null): List<AdvertiserTransparencyDto>
}
