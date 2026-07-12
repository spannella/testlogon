package com.testlogon.android.data.wishlist

import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * ECOM — Retrofit interface for the per-user wishlist / favourites surface (new backend router,
 * `app/routers/wishlist.py`). Storage reuses the shopping-cart DDB table keyed by user + category +
 * item; the client treats it as an opaque saved-items list.
 *
 * Paths are relative (no leading slash) so they resolve against the shared Retrofit base URL; session
 * cookies, Authorization: Bearer and X-CSRF-Token are attached by the core-network interceptor chain
 * (POST/DELETE echo the ui_csrf cookie). Add is an idempotent upsert; delete is idempotent (always 200).
 *
 * Verified contract:
 *  - GET    ui/wishlist                              -> WishlistListDto { items, count }
 *  - POST   ui/wishlist   (body WishlistAddDto)      -> WishlistItemDto  (404 if the catalog item is gone)
 *  - DELETE ui/wishlist/{category_id}/{item_id}      -> WishlistDeleteDto { deleted:true }
 */
interface WishlistApi {

    @GET("ui/wishlist")
    suspend fun list(): WishlistListDto

    @POST("ui/wishlist")
    suspend fun add(@Body body: WishlistAddDto): WishlistItemDto

    @DELETE("ui/wishlist/{categoryId}/{itemId}")
    suspend fun remove(
        @Path("categoryId") categoryId: String,
        @Path("itemId") itemId: String,
    ): WishlistDeleteDto
}
