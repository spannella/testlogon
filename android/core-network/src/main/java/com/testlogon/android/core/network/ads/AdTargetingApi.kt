package com.testlogon.android.core.network.ads

import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.PUT
import retrofit2.http.Path

/**
 * Retrofit interface for the ad TARGETING control plane (web parity: ads_targeting.py, prefix /ui/ads).
 *
 * Paths have NO leading slash (relative to the shared Retrofit base URL). Session cookie / CSRF are attached
 * globally by the core-network interceptors. The list endpoint returns a BARE ARRAY of targeting sets;
 * create/get/update return a single set; estimate returns an audience estimate. Mirrors the web ads.ts
 * targeting functions (createTargeting / listTargeting / getTargeting / updateTargeting / deleteTargeting /
 * estimateAudience). RAW DTOs; the feature repo maps to domain.
 */
interface AdTargetingApi {

    /** GET all targeting sets for a campaign (BARE ARRAY). */
    @GET("ui/ads/campaigns/{campaignId}/targeting")
    suspend fun listTargeting(@Path("campaignId") campaignId: String): List<AdTargetingDto>

    /** POST a new targeting set (returns the created set; backend status 201). */
    @POST("ui/ads/campaigns/{campaignId}/targeting")
    suspend fun createTargeting(
        @Path("campaignId") campaignId: String,
        @Body body: AdTargetingCreateIn,
    ): AdTargetingDto

    /** GET one targeting set by id. */
    @GET("ui/ads/campaigns/{campaignId}/targeting/{targetSetId}")
    suspend fun getTargeting(
        @Path("campaignId") campaignId: String,
        @Path("targetSetId") targetSetId: String,
    ): AdTargetingDto

    /** PUT (full replace) one targeting set. */
    @PUT("ui/ads/campaigns/{campaignId}/targeting/{targetSetId}")
    suspend fun updateTargeting(
        @Path("campaignId") campaignId: String,
        @Path("targetSetId") targetSetId: String,
        @Body body: AdTargetingCreateIn,
    ): AdTargetingDto

    /** DELETE one targeting set. */
    @DELETE("ui/ads/campaigns/{campaignId}/targeting/{targetSetId}")
    suspend fun deleteTargeting(
        @Path("campaignId") campaignId: String,
        @Path("targetSetId") targetSetId: String,
    )

    /** POST an audience estimate for an unsaved targeting spec (does not persist). */
    @POST("ui/ads/campaigns/{campaignId}/targeting/estimate")
    suspend fun estimateAudience(
        @Path("campaignId") campaignId: String,
        @Body body: AdTargetingCreateIn,
    ): AudienceEstimateDto
}
