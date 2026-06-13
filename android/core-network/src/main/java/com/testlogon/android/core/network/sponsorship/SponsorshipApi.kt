package com.testlogon.android.core.network.sponsorship

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * AND-365 / AND-366 - Retrofit interface for the sponsorship surface (inbound brand deals). Transport only; no
 * repo / VM / UI / domain mapping (those live in the :app feature). This is the platform's OWN REST surface,
 * NOT a third-party SDK.
 *
 * Paths have NO leading slash (relative to the shared Retrofit base URL, matching the rest of the codebase).
 * Session cookie / Authorization Bearer are attached globally by the core-network interceptors. The @Path
 * token is EXACTLY {dealId}. All operations return RAW DTOs; the repo wraps them in ApiResult.
 *
 * AND-365 (READ-ONLY inbox): a single idempotent GET returning a RAW BARE ARRAY of [SponsorshipDealDto]; the
 * inbox filters + sorts CLIENT-SIDE so NO query params are sent.
 *
 * AND-366 (DEAL DETAIL + MANAGE) extends this with the full-deal GET, the negotiation/lifecycle history GET,
 * and the three management mutations. WIRE CONTRACT (OpenAPI / frontend-verified, paths under
 * ui/ads/sponsorships/{deal_id}):
 *   GET  ui/ads/sponsorships/{dealId}          -> the FULL deal ([SponsorshipDealDetailDto]; no offers[])
 *   GET  ui/ads/sponsorships/{dealId}/history  -> bare array of [SponsorshipDealEventDto]
 *   POST ui/ads/sponsorships/{dealId}/accept   (NO body) -> the deal (accepted)
 *   POST ui/ads/sponsorships/{dealId}/reject   body [SponsorshipRejectReq] -> the deal (rejected)
 *   POST ui/ads/sponsorships/{dealId}/counter  body [SponsorshipCounterReq] -> the deal (negotiating)
 *
 * The mutations are NON-idempotent (the repo / VM NEVER auto-retries them); the GET load / refresh is
 * idempotent (bounded retry is fine at the shared client). accept / reject / counter all return the updated
 * detail DTO so the screen can re-render the new status without a second read (the VM still re-reads history).
 */
interface SponsorshipApi {

    /** GET the caller's sponsorship deals (BARE ARRAY). No params, no envelope, no paging. (AND-365) */
    @GET("ui/ads/sponsorships")
    suspend fun listDeals(): List<SponsorshipDealDto>

    /** GET the FULL deal by id. Idempotent. (AND-366) */
    @GET("ui/ads/sponsorships/{dealId}")
    suspend fun getDeal(@Path("dealId") dealId: String): SponsorshipDealDetailDto

    /** GET the deal's negotiation / lifecycle history (BARE ARRAY). Idempotent; tolerated to fail. (AND-366) */
    @GET("ui/ads/sponsorships/{dealId}/history")
    suspend fun getHistory(@Path("dealId") dealId: String): List<SponsorshipDealEventDto>

    /** POST accept (NO body). Returns the updated deal. NON-idempotent. (AND-366) */
    @POST("ui/ads/sponsorships/{dealId}/accept")
    suspend fun accept(@Path("dealId") dealId: String): SponsorshipDealDetailDto

    /** POST reject with an optional reason. Returns the updated deal. NON-idempotent. (AND-366) */
    @POST("ui/ads/sponsorships/{dealId}/reject")
    suspend fun reject(
        @Path("dealId") dealId: String,
        @Body body: SponsorshipRejectReq,
    ): SponsorshipDealDetailDto

    /** POST a counter-offer. Returns the updated deal (negotiating). NON-idempotent. (AND-366) */
    @POST("ui/ads/sponsorships/{dealId}/counter")
    suspend fun counter(
        @Path("dealId") dealId: String,
        @Body body: SponsorshipCounterReq,
    ): SponsorshipDealDetailDto
}
