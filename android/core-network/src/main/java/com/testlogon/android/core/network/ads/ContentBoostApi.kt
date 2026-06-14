package com.testlogon.android.core.network.ads

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * AND-364 - Retrofit interface for the platform CONTENT BOOST surface (ui/ads/boost). Transport only; the
 * repo / VM / UI / domain mapping live downstream in the :app feature. This is the platform's OWN REST ads
 * surface, NOT a third-party ad-network SDK and NOT a payment SDK.
 *
 * Paths have NO leading slash (relative to the shared Retrofit base URL, matching the rest of the
 * codebase). Session cookie / Authorization Bearer are attached globally by the core-network interceptors.
 * The @Path token is EXACTLY {boostId}. All operations return RAW DTOs; the repo wraps them in ApiResult.
 *
 * NO ads-account / payment-method selection is involved on create (the server charges the wallet up-front).
 * Cancel is only meaningful while the boost status is "active" (the server enforces this; the client gates
 * the affordance accordingly), and yields the refunded amount.
 */
interface ContentBoostApi {

    /**
     * Create (and pay for, wallet-charged server-side) a boost. Body is EXACTLY
     * {content_type, content_id, budget_cents, duration_seconds} - no payment / account fields.
     */
    @POST("ui/ads/boost")
    suspend fun createBoost(@Body body: ContentBoostCreateIn): ContentBoostOut

    /** GET one boost's current state (status + budget / spent / remaining / ends_at). Idempotent GET. */
    @GET("ui/ads/boost/{boostId}")
    suspend fun getBoost(@Path("boostId") boostId: String): ContentBoostOut

    /** GET a lightweight spend snapshot for a boost. Idempotent GET. */
    @GET("ui/ads/boost/{boostId}/spend")
    suspend fun getBoostSpend(@Path("boostId") boostId: String): ContentBoostSpendOut

    /** POST a cancel of an ACTIVE boost; returns the refunded amount. */
    @POST("ui/ads/boost/{boostId}/cancel")
    suspend fun cancelBoost(@Path("boostId") boostId: String): ContentBoostCancelOut

    /** GET the caller's boosts (optional convenience; NOT part of the exercised flow). Idempotent GET. */
    @GET("ui/ads/boost")
    suspend fun listBoosts(): ContentBoostListResponse
}
