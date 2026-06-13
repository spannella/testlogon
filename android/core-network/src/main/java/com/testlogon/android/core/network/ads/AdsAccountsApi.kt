package com.testlogon.android.core.network.ads

import retrofit2.http.GET
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-363 - Retrofit interface for the platform ads accounts control plane (ui/ads/accounts). Transport
 * only; no repo / VM / UI / domain mapping (downstream E47). This is the platform's OWN REST ads surface,
 * NOT a third-party ad-network SDK.
 *
 * Paths have NO leading slash (relative to the shared Retrofit base URL, matching the rest of the
 * codebase). All four operations are idempotent suspend GETs returning RAW DTOs (bare List<> for the three
 * array endpoints). Session cookie / Authorization Bearer are attached globally by the core-network
 * interceptors. The @Path token is EXACTLY {accountId}. The ONLY query param in the ticket is the optional
 * billing `limit` (default 50); there is NO page / offset / cursor. Mutation is out of scope.
 */
interface AdsAccountsApi {

    /** GET all ad accounts the caller can see (BARE ARRAY). No params, no envelope. */
    @GET("ui/ads/accounts")
    suspend fun listAdsAccounts(): List<AdAccountDto>

    /** GET one ad account (same shape as a list row). */
    @GET("ui/ads/accounts/{accountId}")
    suspend fun getAdsAccount(@Path("accountId") accountId: String): AdAccountDto

    /**
     * GET the account billing ledger (BARE ARRAY). `limit` is the only query param (optional, default 50);
     * no page / offset / cursor.
     */
    @GET("ui/ads/accounts/{accountId}/billing")
    suspend fun getAdsAccountBilling(
        @Path("accountId") accountId: String,
        @Query("limit") limit: Int = 50,
    ): List<AdBillingEntryDto>

    /** GET the campaigns under an account (BARE ARRAY). No params. */
    @GET("ui/ads/accounts/{accountId}/campaigns")
    suspend fun listAdsAccountCampaigns(
        @Path("accountId") accountId: String,
    ): List<AdCampaignDto>
}
