package com.testlogon.android.core.network.ads

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.PUT
import retrofit2.http.Path

/**
 * ADV2-709/710/711 (F7) — Retrofit interface for the SYNDICATE-owned advertiser control plane
 * (ui/ads/syndicates/{syndicateId}/...). Transport only; no repo / VM / UI / domain mapping.
 *
 * Paths have NO leading slash (relative to the shared Retrofit base URL, matching the rest of the ads
 * surface). Session cookie / Authorization Bearer are attached globally by the core-network interceptors.
 * Every endpoint is ADMIN-GATED server-side (syndicates._require_admin -> 403 for a plain member).
 *
 * The @Path token is EXACTLY {syndicateId}. Campaign / creative / deposit / analytics for a syndicate
 * account REUSE the existing owner-scoped [AdsAccountsApi] endpoints (the syndicate account's owner_sub is
 * the admin), so this interface adds ONLY the two syndicate-scoped surfaces the owner-scoped api can't
 * express: the syndicate account create/list and the per-syndicate placement split config get/set.
 */
interface SyndicateAdsApi {

    /**
     * ADV2-709 — POST create a syndicate-owned advertiser account (owner_type=syndicate) -> 201
     * pending_review. Body REUSES [AdAccountCreateIn] (company_name, billing_email). Admin-gated.
     */
    @POST("ui/ads/syndicates/{syndicateId}/accounts")
    suspend fun createSyndicateAdAccount(
        @Path("syndicateId") syndicateId: String,
        @Body body: AdAccountCreateIn,
    ): SyndicateAdAccountDto

    /** ADV2-709 — GET the syndicate's ad accounts (BARE ARRAY). Admin-gated. Idempotent GET. */
    @GET("ui/ads/syndicates/{syndicateId}/accounts")
    suspend fun listSyndicateAdAccounts(
        @Path("syndicateId") syndicateId: String,
    ): List<SyndicateAdAccountDto>

    /** ADV2-710 — GET the per-syndicate ad-placement split config. Admin-gated. Idempotent GET. */
    @GET("ui/ads/syndicates/{syndicateId}/ad-placement-config")
    suspend fun getSyndicateAdPlacementConfig(
        @Path("syndicateId") syndicateId: String,
    ): SyndicateAdPlacementConfigDto

    /**
     * ADV2-710 — PUT the member's share (bps) of the content-owner split (0..10000). Returns the updated
     * config. Admin-gated; NON-idempotent write in effect (last-writer-wins), so no auto-retry.
     */
    @PUT("ui/ads/syndicates/{syndicateId}/ad-placement-config")
    suspend fun setSyndicateAdPlacementConfig(
        @Path("syndicateId") syndicateId: String,
        @Body body: SyndicateAdPlacementConfigIn,
    ): SyndicateAdPlacementConfigDto
}
