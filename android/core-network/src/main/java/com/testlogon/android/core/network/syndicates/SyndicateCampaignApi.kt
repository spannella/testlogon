package com.testlogon.android.core.network.syndicates

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * Retrofit interface for the syndicate-advertising campaign DETAIL surface (web parity:
 * /syndicates/:syndicateId/campaigns/:campaignId). Transport only; the :app repository folds the RAW DTO
 * returns into ApiResult. Paths are relative; the shared authenticated client attaches auth globally.
 *
 * Read = members-only (server-side). Mutations (status / add-budget) = admin-only (a non-admin gets a 403,
 * surfaced as Failure and gated in the UI by the viewer's admin flag).
 */
interface SyndicateCampaignApi {

    /** GET one campaign's details (members only). */
    @GET("ui/syndicates/advertising/{syndicateId}/campaigns/{campaignId}")
    suspend fun getCampaign(
        @Path("syndicateId") syndicateId: String,
        @Path("campaignId") campaignId: String,
    ): SyndicateCampaignOut

    /** GET the campaign's daily analytics + totals (members only). */
    @GET("ui/syndicates/advertising/{syndicateId}/campaigns/{campaignId}/analytics")
    suspend fun getAnalytics(
        @Path("syndicateId") syndicateId: String,
        @Path("campaignId") campaignId: String,
    ): SyndicateCampaignAnalyticsOut

    /** POST pause / resume / cancel (admin only). Returns the updated campaign. */
    @Headers("Content-Type: application/json")
    @POST("ui/syndicates/advertising/{syndicateId}/campaigns/{campaignId}/status")
    suspend fun updateStatus(
        @Path("syndicateId") syndicateId: String,
        @Path("campaignId") campaignId: String,
        @Body body: SyndicateCampaignStatusUpdateIn,
    ): SyndicateCampaignOut

    /** POST add budget from the treasury (admin only). Returns the updated campaign. */
    @Headers("Content-Type: application/json")
    @POST("ui/syndicates/advertising/{syndicateId}/campaigns/{campaignId}/add-budget")
    suspend fun addBudget(
        @Path("syndicateId") syndicateId: String,
        @Path("campaignId") campaignId: String,
        @Body body: SyndicateCampaignBudgetAddIn,
    ): SyndicateCampaignOut
}
