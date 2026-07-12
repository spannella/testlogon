package com.testlogon.android.data.livecommerce

import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * LIVECOM L5 — Retrofit interface for live-stream commerce (host pin/unpin + shop-this-stream list +
 * seller affiliate-commission). Backed by the backend router app/routers/live_commerce.py. All paths
 * are relative to the shared Retrofit base URL. Host-only writes (pin/unpin) are enforced server-side
 * (session.created_by / admin); the affiliate-commission set is owner-scoped server-side.
 */
interface LiveCommerceApi {

    // ─── L1: pin / unpin / shop-this-stream ────────────────────────────────────

    @POST("ui/live-commerce/sessions/{sessionId}/products")
    suspend fun pinProduct(
        @Path("sessionId") sessionId: String,
        @Body body: PinProductDto,
    ): PinnedProductDto

    @DELETE("ui/live-commerce/sessions/{sessionId}/products/{productId}")
    suspend fun unpinProduct(
        @Path("sessionId") sessionId: String,
        @Path("productId") productId: String,
    ): LiveCommerceOkDto

    @GET("ui/live-commerce/sessions/{sessionId}/products")
    suspend fun streamProducts(
        @Path("sessionId") sessionId: String,
    ): StreamProductsDto

    // ─── L2: seller-set per-listing affiliate commission (owner-scoped) ─────────

    @POST("ui/live-commerce/listings/{categoryId}/{itemId}/affiliate-commission")
    suspend fun setAffiliateCommission(
        @Path("categoryId") categoryId: String,
        @Path("itemId") itemId: String,
        @Body body: AffiliateCommissionDto,
    ): AffiliateCommissionDto

    @GET("ui/live-commerce/listings/{categoryId}/{itemId}/affiliate-commission")
    suspend fun getAffiliateCommission(
        @Path("categoryId") categoryId: String,
        @Path("itemId") itemId: String,
    ): AffiliateCommissionDto
}
