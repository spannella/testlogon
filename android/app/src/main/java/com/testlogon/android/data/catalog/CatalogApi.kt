package com.testlogon.android.data.catalog

import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-204 — dedicated Retrofit interface for the storefront catalog (shop) surface.
 *
 * Paths are relative (no leading slash) so they resolve against the shared Retrofit base URL; session
 * cookies, Authorization: Bearer and X-CSRF-Token are attached by the core-network interceptor chain.
 * All three calls are idempotent GETs (bounded-backoff eligible). Token-based paging: page_size +
 * nullable next_token (Retrofit omits a null query param). There is no single-category / single-item
 * GET — detail is derived from the list payload downstream (AND-206).
 *
 * Verified contract (reference/src/api/endpoints/cart.ts; OpenAPI index lines 1308/1311/1321):
 *  - GET ui/catalog/categories                       -> CatalogCategoryListOut
 *  - GET ui/catalog/categories/{category_id}/items   -> CatalogItemListOut
 *  - GET ui/catalog/items/search?q=                  -> CatalogItemListOut (same envelope as items)
 */
interface CatalogApi {

    @GET("ui/catalog/categories")
    suspend fun listCategories(
        @Query("page_size") pageSize: Int = PAGE_SIZE,
        @Query("next_token") nextToken: String? = null,
    ): CatalogCategoryListDto

    @GET("ui/catalog/categories/{categoryId}/items")
    suspend fun listItems(
        @Path("categoryId") categoryId: String,
        @Query("page_size") pageSize: Int = PAGE_SIZE,
        @Query("next_token") nextToken: String? = null,
    ): CatalogItemListDto

    @GET("ui/catalog/items/search")
    suspend fun searchCatalog(
        @Query("q") query: String,
        @Query("page_size") pageSize: Int = PAGE_SIZE,
        @Query("next_token") nextToken: String? = null,
    ): CatalogItemListDto

    /**
     * ECOM (reviews) — the item-review sub-resource. Reviews are keyed by item_id alone (no category in
     * the path). List is an idempotent GET; add is a non-idempotent POST; delete removes by review_id.
     * X-CSRF-Token / session cookies are attached by the interceptor chain.
     *
     *  - GET    ui/catalog/items/{item_id}/reviews              -> CatalogReviewListOut
     *  - POST   ui/catalog/items/{item_id}/reviews              -> CatalogReviewOut (body CatalogReviewCreateIn)
     *  - DELETE ui/catalog/items/{item_id}/reviews/{review_id}  -> { ok: true }
     */
    @GET("ui/catalog/items/{itemId}/reviews")
    suspend fun listReviews(
        @Path("itemId") itemId: String,
        @Query("page_size") pageSize: Int = REVIEW_PAGE_SIZE,
        @Query("next_token") nextToken: String? = null,
    ): CatalogReviewListDto

    @POST("ui/catalog/items/{itemId}/reviews")
    suspend fun addReview(
        @Path("itemId") itemId: String,
        @Body body: CatalogReviewCreateDto,
    ): CatalogReviewDto

    @DELETE("ui/catalog/items/{itemId}/reviews/{reviewId}")
    suspend fun deleteReview(
        @Path("itemId") itemId: String,
        @Path("reviewId") reviewId: String,
    ): OkRespCatalogDto

    companion object {
        /** Web client default (cart.ts getCategories / getCategoryItems). */
        const val PAGE_SIZE = 50

        /** Reviews page size (backend caps at 200). */
        const val REVIEW_PAGE_SIZE = 50
    }
}
