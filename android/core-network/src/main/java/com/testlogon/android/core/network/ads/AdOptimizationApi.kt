package com.testlogon.android.core.network.ads

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * Retrofit interface for the ad OPTIMIZATION control plane (web parity: ad_optimization.py, prefix
 * /ui/ads/optimization). Mirrors the web adOptimization.ts functions (generateRecommendations /
 * listRecommendations / applyRecommendation / dismissRecommendation / getSuggestedBid /
 * getBudgetRecommendation / updateOptimizationConfig).
 *
 * Paths have NO leading slash. Session cookie / CSRF attached globally. RAW DTOs; the feature repo maps.
 * generate / apply / dismiss are NON-idempotent POSTs (never auto-retried).
 */
interface AdOptimizationApi {

    /** POST a deterministic optimization pass; persists + returns recommendations. */
    @POST("ui/ads/optimization/campaigns/{campaignId}/generate")
    suspend fun generate(
        @Path("campaignId") campaignId: String,
        @Query("days") days: Int? = null,
    ): GenerateResultDto

    /** GET recommendation history (newest first), optional status filter. */
    @GET("ui/ads/optimization/campaigns/{campaignId}/recommendations")
    suspend fun listRecommendations(
        @Path("campaignId") campaignId: String,
        @Query("status") status: String? = null,
    ): RecommendationListDto

    /** POST apply a recommendation (mutates the campaign/creative). */
    @POST("ui/ads/optimization/campaigns/{campaignId}/recommendations/{recommendationId}/apply")
    suspend fun applyRecommendation(
        @Path("campaignId") campaignId: String,
        @Path("recommendationId") recommendationId: String,
    ): OptimizationActionResultDto

    /** POST dismiss a recommendation without applying it. */
    @POST("ui/ads/optimization/campaigns/{campaignId}/recommendations/{recommendationId}/dismiss")
    suspend fun dismissRecommendation(
        @Path("campaignId") campaignId: String,
        @Path("recommendationId") recommendationId: String,
    ): OptimizationActionResultDto

    /** GET suggested bid range based on targeting specificity. */
    @GET("ui/ads/optimization/campaigns/{campaignId}/suggested-bid")
    suspend fun getSuggestedBid(@Path("campaignId") campaignId: String): SuggestedBidDto

    /** GET recommended daily budget for a desired reach. */
    @GET("ui/ads/optimization/campaigns/{campaignId}/budget-recommendation")
    suspend fun getBudgetRecommendation(
        @Path("campaignId") campaignId: String,
        @Query("desired_daily_reach") desiredDailyReach: Int,
    ): BudgetRecommendationDto

    /** PATCH auto-optimize toggle + thresholds on the campaign. */
    @PATCH("ui/ads/optimization/campaigns/{campaignId}/optimization-config")
    suspend fun updateConfig(
        @Path("campaignId") campaignId: String,
        @Body body: OptimizationConfigUpdateIn,
    ): OptimizationConfigResultDto
}
