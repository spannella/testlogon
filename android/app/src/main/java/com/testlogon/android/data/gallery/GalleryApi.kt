package com.testlogon.android.data.gallery

import retrofit2.http.GET
import retrofit2.http.Query

/**
 * AND-201 — dedicated Retrofit interface for the published video gallery.
 *
 * Paths are relative (no leading slash) so they resolve against the shared Retrofit base URL; cookies,
 * Authorization: Bearer and X-CSRF-Token are attached by the core-network interceptor chain. All calls
 * are idempotent GETs (bounded-backoff eligible).
 *
 * Verified contract (reference/src/api/endpoints/gallery.ts; OpenAPI /ui/videos/gallery*):
 *  - GET ui/videos/gallery?category=&limit=&cursor=  -> GalleryListOut { videos, categories, cursor }
 *  - GET ui/videos/gallery/search?q=&limit=&cursor=  -> GallerySearchOut { videos, cursor } (q required)
 *  - GET ui/videos/gallery/categories                -> CategoriesOut { categories }
 */
interface GalleryApi {

    @GET("ui/videos/gallery")
    suspend fun browseGallery(
        @Query("category") category: String?,
        @Query("cursor") cursor: String?,
        @Query("limit") limit: Int = PAGE_SIZE,
    ): GalleryListDto

    @GET("ui/videos/gallery/search")
    suspend fun searchGallery(
        @Query("q") query: String,
        @Query("cursor") cursor: String?,
        @Query("limit") limit: Int = PAGE_SIZE,
    ): GallerySearchDto

    @GET("ui/videos/gallery/categories")
    suspend fun categories(): CategoriesDto

    companion object {
        /** Web uses limit:48; the Paging source follows `cursor` but tolerates a single-page gallery. */
        const val PAGE_SIZE = 48
    }
}
