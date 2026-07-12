package com.testlogon.android.core.network.ads

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query
import okhttp3.MultipartBody
import okhttp3.RequestBody
import retrofit2.http.Multipart
import retrofit2.http.Part

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

    /**
     * AND-368 - GET the READ-ONLY KPI analytics summary for an account over a date range. account_id is a
     * QUERY param (mirrors the verified web ads.ts getAnalyticsSummary); [from] / [to] are YYYY-MM-DD
     * strings. Idempotent GET; returns a single raw DTO.
     */
    @GET("ui/ads/analytics/summary")
    suspend fun getAnalyticsSummary(
        @Query("account_id") accountId: String,
        @Query("from") from: String,
        @Query("to") to: String,
    ): AdAnalyticsSummaryDto

    /**
     * AND-368 - GET the READ-ONLY daily-bucketed time series (BARE ARRAY) for an account over a date range.
     * account_id / from / to are QUERY params. Idempotent GET; no paging.
     */
    @GET("ui/ads/analytics/timeseries")
    suspend fun getAnalyticsTimeseries(
        @Query("account_id") accountId: String,
        @Query("from") from: String,
        @Query("to") to: String,
    ): List<AdTimeSeriesPointDto>

    /**
     * AND-368 - GET the READ-ONLY breakdown rows (BARE ARRAY) for a [dimension] (creative / surface /
     * targeting) over a date range. account_id / dimension / from / to are QUERY params. Idempotent GET; the
     * caller caps the row count client-side (no paging).
     */
    @GET("ui/ads/analytics/breakdown")
    suspend fun getAnalyticsBreakdown(
        @Query("account_id") accountId: String,
        @Query("dimension") dimension: String,
        @Query("from") from: String,
        @Query("to") to: String,
    ): List<AdBreakdownEntryDto>
    // ── ADV-107/108/109 : MUTATING create flow (account -> campaign -> creative + upload -> submit) ──

    /** ADV-107 - POST create a new advertiser account (company_name, billing_email) -> 201 pending_review. */
    @POST("ui/ads/accounts")
    suspend fun createAdsAccount(@Body body: AdAccountCreateIn): AdAccountMutationDto

    /** ADV-108 - POST create a draft campaign under [accountId] (account must be active) -> 201 draft. */
    @POST("ui/ads/accounts/{accountId}/campaigns")
    suspend fun createCampaign(
        @Path("accountId") accountId: String,
        @Body body: AdCampaignCreateIn,
    ): AdCampaignDto

    /** ADV-108 - POST submit a draft campaign for admin review (draft -> pending_review). */
    @POST("ui/ads/accounts/{accountId}/campaigns/{campaignId}/submit")
    suspend fun submitCampaign(
        @Path("accountId") accountId: String,
        @Path("campaignId") campaignId: String,
    ): AdSubmitAckDto

    /** ADV-109 - POST create a draft creative under [campaignId] -> 201 draft. */
    @POST("ui/ads/campaigns/{campaignId}/creatives")
    suspend fun createCreative(
        @Path("campaignId") campaignId: String,
        @Body body: AdCreativeCreateIn,
    ): AdCreativeDto

    /**
     * ADV-109 - POST the creative image/video asset (multipart). `file` is the binary part; `asset_type`
     * is the backend Form field (default "image"). Server enforces the mime whitelist + size/magic bytes.
     */
    @Multipart
    @POST("ui/ads/campaigns/{campaignId}/creatives/{creativeId}/upload")
    suspend fun uploadCreativeAsset(
        @Path("campaignId") campaignId: String,
        @Path("creativeId") creativeId: String,
        @Part file: MultipartBody.Part,
        @Part("asset_type") assetType: RequestBody,
    ): AdAssetUploadDto

    /** ADV-109 - POST submit a draft creative for admin review (draft -> pending_review). */
    @POST("ui/ads/campaigns/{campaignId}/creatives/{creativeId}/submit")
    suspend fun submitCreative(
        @Path("campaignId") campaignId: String,
        @Path("creativeId") creativeId: String,
    ): AdSubmitAckDto

    /**
     * ADV-501/503 - GET the ROAS report for an account (optionally scoped to one [campaignId]) over the last
     * [days] days: per-account totals + per-campaign spend/impressions/clicks/CTR/conversions/CPA/ROAS.
     * account_id is a QUERY param (mirrors the analytics reads). Idempotent GET.
     */
    @GET("ui/ads/roas")
    suspend fun getRoas(
        @Query("account_id") accountId: String,
        @Query("campaign_id") campaignId: String? = null,
        @Query("days") days: Int = 30,
    ): AdRoasReportDto
}
