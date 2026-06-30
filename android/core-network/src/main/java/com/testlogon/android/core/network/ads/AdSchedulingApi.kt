package com.testlogon.android.core.network.ads

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.PATCH
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * Retrofit interface for the ad SCHEDULING control plane (web parity: ad_dayparting.py, prefix
 * /ui/ads/scheduling). Mirrors the web adDayparting.ts functions (getScheduleTemplates /
 * getCampaignSchedule / updateCampaignSchedule / getScheduleEligibility / getBudgetPacing).
 *
 * Paths have NO leading slash. Session cookie / CSRF attached globally. RAW DTOs; the feature repo maps.
 */
interface AdSchedulingApi {

    /** GET predefined dayparting schedule templates. */
    @GET("ui/ads/scheduling/templates")
    suspend fun getTemplates(): ScheduleTemplatesDto

    /** GET the current dayparting / flight schedule for a campaign. */
    @GET("ui/ads/scheduling/campaigns/{campaignId}/schedule")
    suspend fun getSchedule(@Path("campaignId") campaignId: String): CampaignScheduleDto

    /** PATCH dayparting and/or flights and/or timezone on a campaign. */
    @PATCH("ui/ads/scheduling/campaigns/{campaignId}/schedule")
    suspend fun updateSchedule(
        @Path("campaignId") campaignId: String,
        @Body body: CampaignScheduleUpdateIn,
    ): CampaignScheduleDto

    /** GET whether the campaign is eligible to serve right now (optional `now` override). */
    @GET("ui/ads/scheduling/campaigns/{campaignId}/schedule/eligibility")
    suspend fun getEligibility(
        @Path("campaignId") campaignId: String,
        @Query("now") now: Long? = null,
    ): ScheduleEligibilityDto

    /** GET dayparting-aware budget pacing for the campaign. */
    @GET("ui/ads/scheduling/campaigns/{campaignId}/schedule/pacing")
    suspend fun getPacing(
        @Path("campaignId") campaignId: String,
        @Query("now") now: Long? = null,
    ): BudgetPacingDto
}
