package com.testlogon.android.core.network.ads

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
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
 * billing `limit` (default 50); there is NO page / offset / cursor.
 *
 * AND-367 EXTENSION (NOT a fork): the SAME interface gains the monthly-invoice GET and the DEPOSIT
 * (add-funds) POST - the first MUTATING ads operation here. The deposit body carries an integer
 * `amount_cents` + an OPTIONAL `payment_method_id`; there is NO vendor payment SDK (the server charges the
 * wallet / an existing saved method). The invoice @Path tokens are EXACTLY {accountId} and {month}.
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

    /**
     * AND-367 - GET one monthly invoice for an account. [month] is the period label (assumed "YYYY-MM"; the
     * wire format is UNVERIFIED). The @Path tokens are EXACTLY {accountId} and {month}. Idempotent GET.
     */
    @GET("ui/ads/accounts/{accountId}/invoices/{month}")
    suspend fun getInvoice(
        @Path("accountId") accountId: String,
        @Path("month") month: String,
    ): AdInvoiceDto

    /**
     * AND-367 - POST a deposit (add funds) to an account. Body is {amount_cents, payment_method_id?}; the
     * server charges the wallet / an existing saved payment method (NO vendor payment SDK) and returns the
     * updated balance. NON-idempotent (the repo / VM never auto-retry it).
     */
    @POST("ui/ads/accounts/{accountId}/deposit")
    suspend fun deposit(
        @Path("accountId") accountId: String,
        @Body body: AdDepositIn,
    ): AdDepositOut
}
