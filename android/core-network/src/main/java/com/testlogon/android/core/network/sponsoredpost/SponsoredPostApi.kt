package com.testlogon.android.core.network.sponsoredpost

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * ADV2-E4 (F4) / ADV2-407..409 — Retrofit interface for the sponsored-as-creator (paid partnership) surface.
 * Transport only; the repo/VM/UI live in the :app feature. Paths have NO leading slash (relative to the
 * shared Retrofit base URL); the session cookie / Bearer / CSRF are attached globally by the core-network
 * interceptors. All ops return RAW DTOs; the repo folds them into ApiResult.
 *
 * WIRE CONTRACT (backend ADV2-401..406, verified on prod):
 *   POST ui/ads/sponsored-posts/proposals                    body [SponsoredPostProposalReq] -> row (201)
 *   GET  ui/ads/sponsored-posts/proposals/inbox              -> { proposals: [...] } (the creator's queue)
 *   GET  ui/ads/sponsored-posts/proposals/outbox             -> { proposals: [...] } (the advertiser's)
 *   POST ui/ads/sponsored-posts/proposals/{id}/approve       (NO body) -> { proposal_id, status, post_id }
 *   POST ui/ads/sponsored-posts/proposals/{id}/reject        body [SponsoredPostRejectReq] -> { ..., status }
 *   GET  ui/ads/sponsored-posts/{postId}/placement           -> the per-viewer billing handle
 *
 * approve / reject are NON-idempotent (the repo/VM never auto-retry); the queue GETs + placement GET are
 * idempotent. Only the TARGETED creator may approve/reject (server enforces 403); a double-approve is 409.
 */
interface SponsoredPostApi {

    /** POST an advertiser-drafted proposal to a target creator. Does NOT publish. (ADV2-401) */
    @POST("ui/ads/sponsored-posts/proposals")
    suspend fun createProposal(@Body body: SponsoredPostProposalReq): SponsoredPostProposalDto

    /** GET the targeted creator's review queue (pending proposals only). (ADV2-403) */
    @GET("ui/ads/sponsored-posts/proposals/inbox")
    suspend fun inbox(): SponsoredPostListDto

    /** GET the advertiser's own outbox (all statuses). (ADV2-403) */
    @GET("ui/ads/sponsored-posts/proposals/outbox")
    suspend fun outbox(): SponsoredPostListDto

    /** POST approve (NO body) -> publishes the creator-authored paid_partnership post. NON-idempotent. */
    @POST("ui/ads/sponsored-posts/proposals/{id}/approve")
    suspend fun approve(@Path("id") proposalId: String): SponsoredPostApproveDto

    /** POST reject with an optional reason -> terminal, no post. NON-idempotent. */
    @POST("ui/ads/sponsored-posts/proposals/{id}/reject")
    suspend fun reject(
        @Path("id") proposalId: String,
        @Body body: SponsoredPostRejectReq,
    ): SponsoredPostRejectResultDto

    /** GET the per-viewer billing mint for a published paid_partnership post. Idempotent. (ADV2-404) */
    @GET("ui/ads/sponsored-posts/{postId}/placement")
    suspend fun placement(@Path("postId") postId: String): SponsoredPostPlacementDto
}
