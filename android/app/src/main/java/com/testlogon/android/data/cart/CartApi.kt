package com.testlogon.android.data.cart

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * AND-206 — Retrofit interface for the shopping-cart endpoints used by product-detail add-to-cart.
 *
 * Paths are relative (no leading slash) so they resolve against the shared Retrofit base URL; session
 * cookies, Authorization: Bearer and X-CSRF-Token are attached by the core-network interceptor chain.
 * Add-to-cart is non-idempotent and must NOT be auto-retried.
 *
 * Verified contract (reference/src/api/endpoints/cart.ts; OpenAPI index lines 1859/1860/1865):
 *  - GET  ui/shoppingcart/carts                       -> List of ShoppingCartSummary
 *  - POST ui/shoppingcart/carts                       -> ShoppingCartSummary
 *  - POST ui/shoppingcart/carts/{cart_id}/items       -> ShoppingCartItemOut  (body ShoppingCartItemIn)
 */
interface CartApi {

    @GET("ui/shoppingcart/carts")
    suspend fun listCarts(): List<CartSummaryDto>

    @POST("ui/shoppingcart/carts")
    suspend fun createCart(): CartSummaryDto

    @POST("ui/shoppingcart/carts/{cartId}/items")
    suspend fun addItem(
        @Path("cartId") cartId: String,
        @Body body: CartItemInDto,
    ): CartItemOutDto

    companion object {
        /** Web client cart status for "the cart we add into". */
        const val STATUS_ACTIVE = "active"
    }
}
