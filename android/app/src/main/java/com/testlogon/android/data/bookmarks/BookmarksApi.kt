package com.testlogon.android.data.bookmarks

import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-092 — Retrofit interface for the Saved / bookmarks surface.
 *
 * Paths are relative (no leading slash); cookies, Authorization and X-CSRF-Token are attached by the
 * core-network interceptor chain (so no per-method auth headers beyond Content-Type on the POST).
 * All methods are suspend; non-2xx surfaces as retrofit2.HttpException.
 *
 * Verified against reference/src/api/endpoints/bookmarks.ts and OpenAPI:
 *  - list   -> GET    ui/bookmarks                              (params limit,cursor,content_type,collection_id)
 *  - delete -> DELETE ui/bookmarks/{content_type}/{content_id} (200 { ok: true })
 *  - create -> POST   ui/bookmarks                             (201 body; used only for Undo)
 *
 * DELETE/POST parse a tiny [OkDto] rather than Unit so the JSON body is consumed.
 */
interface BookmarksApi {

    /** Paginated, most-recently-saved-first list. Idempotent GET. */
    @GET("ui/bookmarks")
    suspend fun listBookmarks(
        @Query("limit") limit: Int? = null,
        @Query("cursor") cursor: String? = null,
        @Query("content_type") contentType: String? = null,
        @Query("collection_id") collectionId: String? = null,
    ): BookmarkPageDto

    /** Remove a bookmark by its composite key. Mutating (CSRF injected by the interceptor chain). */
    @DELETE("ui/bookmarks/{content_type}/{content_id}")
    suspend fun deleteBookmark(
        @Path("content_type") contentType: String,
        @Path("content_id") contentId: String,
    ): OkDto

    /** Re-create a bookmark (Undo / feed save). Mutating POST. */
    @Headers("Content-Type: application/json")
    @POST("ui/bookmarks")
    suspend fun createBookmark(@Body body: CreateBookmarkDto): OkDto

    /**
     * AND-176 — batch presence check used to seed the feed's per-post saved icon cheaply.
     * `ids` is a comma-joined list of content ids. Idempotent GET.
     */
    @GET("ui/bookmarks/status")
    suspend fun bookmarkStatus(@Query("ids") ids: String): BookmarkStatusDto
}
