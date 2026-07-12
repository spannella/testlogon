package com.testlogon.android.data.cart

import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.Header
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-206 — Retrofit interface for the shopping-cart endpoints used by product-detail add-to-cart.
 *
 * Paths are relative (no leading slash) so they resolve against the shared Retrofit base URL; session
 * cookies, Authorization: Bearer and X-CSRF-Token are attached by the core-network interceptor chain.
 * Add-to-cart is non-idempotent and must NOT be auto-retried.
 *
 * Verified contract (reference/src/api/endpoints/cart.ts; OpenAPI index lines 1861/1864/1865/1867/1868/1870):
 *  - GET    ui/shoppingcart/carts                          -> List of ShoppingCartSummary
 *  - POST   ui/shoppingcart/carts                          -> ShoppingCartSummary
 *  - GET    ui/shoppingcart/carts/{cart_id}/items          -> ShoppingCartItemsOut
 *  - GET    ui/shoppingcart/carts/{cart_id}/total          -> ShoppingCartTotalOut
 *  - POST   ui/shoppingcart/carts/{cart_id}/items          -> ShoppingCartItemOut  (body ShoppingCartItemIn)
 *  - PATCH  ui/shoppingcart/carts/{cart_id}/items/{sku}    -> 200 (untyped; re-fetch after)  (body ShoppingCartUpdateQtyIn)
 *  - DELETE ui/shoppingcart/carts/{cart_id}/items/{sku}    -> OkResp  (optional ?decrement=true)
 *  - DELETE ui/shoppingcart/carts/{cart_id}                -> OkResp
 *
 * AND-210 — extends the AND-206 add-to-cart seam to the FULL cart surface (read items + total,
 * update qty, remove line, delete cart). Mutations return an affected item / OkResp — NOT the whole
 * cart — so the repository re-fetches items + total to reconcile (web parity: invalidateQueries).
 */
interface CartApi {

    @GET("ui/shoppingcart/carts")
    suspend fun listCarts(): List<CartSummaryDto>

    @POST("ui/shoppingcart/carts")
    suspend fun createCart(): CartSummaryDto

    @GET("ui/shoppingcart/carts/{cartId}/items")
    suspend fun getCartItems(@Path("cartId") cartId: String): CartItemsRespDto

    @GET("ui/shoppingcart/carts/{cartId}/total")
    suspend fun getCartTotal(@Path("cartId") cartId: String): CartTotalDto

    @POST("ui/shoppingcart/carts/{cartId}/items")
    suspend fun addItem(
        @Path("cartId") cartId: String,
        @Body body: CartItemInDto,
    ): CartItemOutDto

    @PATCH("ui/shoppingcart/carts/{cartId}/items/{sku}")
    suspend fun updateItemQty(
        @Path("cartId") cartId: String,
        @Path("sku") sku: String,
        @Body body: UpdateCartItemQtyRequest,
    ): OkRespDto

    @DELETE("ui/shoppingcart/carts/{cartId}/items/{sku}")
    suspend fun removeItem(
        @Path("cartId") cartId: String,
        @Path("sku") sku: String,
        @Query("decrement") decrement: Boolean? = null,
    ): OkRespDto

    @DELETE("ui/shoppingcart/carts/{cartId}")
    suspend fun deleteCart(@Path("cartId") cartId: String): OkRespDto

    /**
     * FIX (ecom residual #1) — the one-shot complete-purchase endpoint. Requires X-Idempotency-Key;
     * body carries an optional promo. Returns the created order + purchase txn.
     */
    @POST("ui/shoppingcart/carts/{cartId}/purchase")
    suspend fun purchaseCart(
        @Path("cartId") cartId: String,
        @Header("X-Idempotency-Key") idempotencyKey: String,
        @Body body: CartPurchaseInDto,
    ): CartPurchaseOutDto

    companion object {
        /**
         * The web client is inconsistent about the "active cart" status string:
         * ProductDetail.tsx matches "active" while Cart.tsx matches "OPEN". We accept either so a
         * cart created by add-to-cart is also resolvable by the cart screen.
         */
        const val STATUS_ACTIVE = "active"
        const val STATUS_OPEN = "OPEN"

        /** Statuses that denote a usable, addable/editable cart. */
        val ACTIVE_STATUSES = setOf(STATUS_ACTIVE, STATUS_OPEN)
    }
}
