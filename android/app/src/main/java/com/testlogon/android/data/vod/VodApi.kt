package com.testlogon.android.data.vod

import retrofit2.http.GET
import retrofit2.http.Query

/**
 * AND-191 — Retrofit interface for the VOD catalog (browse on-demand titles).
 *
 * Dedicated to this feature. Paths are relative (shared base URL); auth headers (cookie jar +
 * Authorization: Bearer + X-CSRF-Token) are attached by the core-network interceptor chain. All reads
 * are idempotent GETs. VOD detail reuses the videos detail endpoint via the shared VideosApi/Repository
 * (GET ui/videos/{video_id} -> VideoDetailOut), so it is not re-declared here.
 *
 * Verified contract (reference/src/api/endpoints/gallery.ts + videos.ts; openapi.index.txt):
 *  - GET ui/videos/public          (limit, cursor?)              -> VideoListOut { items, cursor? }
 *      op=list_public_videos... — the default public catalog page.
 *  - GET ui/videos/gallery         (category?, limit, cursor?)   -> GalleryListOut { videos, categories, cursor? }
 *      op=browse_gallery_endpoint... — the category browse the web GalleryPage renders.
 *  - GET ui/videos/gallery/search  (q, limit, cursor?)           -> GallerySearchOut { videos, cursor? }
 *      op=search_gallery_endpoint...
 *  - GET ui/videos/gallery/categories                            -> CategoriesOut { categories }
 *      op=list_gallery_categories...
 */
interface VodApi {

    @GET("ui/videos/public")
    suspend fun getPublicCatalog(
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = CATALOG_PAGE_SIZE,
    ): VideoListResponseDto

    @GET("ui/videos/gallery")
    suspend fun browseGallery(
        @Query("category") category: String? = null,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = CATALOG_PAGE_SIZE,
    ): GalleryListResponseDto

    @GET("ui/videos/gallery/search")
    suspend fun searchGallery(
        @Query("q") query: String,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = CATALOG_PAGE_SIZE,
    ): GallerySearchResponseDto

    @GET("ui/videos/gallery/categories")
    suspend fun getCategories(): CategoriesResponseDto

    companion object {
        const val CATALOG_PAGE_SIZE = 30
    }
}
