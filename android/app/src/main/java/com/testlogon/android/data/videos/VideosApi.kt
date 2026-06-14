package com.testlogon.android.data.videos

import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-189 / AND-190 — Retrofit interface for the Videos library + video detail surfaces.
 *
 * Dedicated to this feature (separate from DiscoverApi / MessagingApi) so the videos work never
 * touches other features' API contracts. Paths are relative (no leading slash) so they resolve
 * against the shared Retrofit base URL; cookies, Authorization: Bearer and X-CSRF-Token are attached
 * by the core-network interceptor chain. All reads are idempotent GETs.
 *
 * Verified contract (reference/src/api/endpoints/videos.ts + gallery.ts; openapi.index.txt):
 *  - GET  ui/videos              (limit, cursor?, status?, visibility?)  -> VideoListOut
 *      op=list_own_videos_ui_videos_get — "List the caller's own videos (paginated, filterable)."
 *  - GET  ui/videos/{video_id}                                          -> VideoDetailOut
 *      op=get_video_detail_ui_videos__video_id__get
 *  - GET  ui/videos/{video_id}/similar  (limit)                         -> SimilarVideosResponse
 *      op=similar_videos_endpoint... — drives the detail "up next" rail.
 *  - GET  ui/videos/{video_id}/like                                     -> LikeCheckOut { liked }
 *  - POST ui/videos/{video_id}/like                                     -> LikeToggleOut { liked, like_count }
 */
interface VideosApi {

    @GET("ui/videos")
    suspend fun listVideos(
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = LIBRARY_PAGE_SIZE,
        @Query("status") status: String? = null,
        @Query("visibility") visibility: String? = null,
    ): VideoListResponseDto

    @GET("ui/videos/{video_id}")
    suspend fun getVideoDetail(@Path("video_id") videoId: String): VideoDetailDto

    @GET("ui/videos/{video_id}/similar")
    suspend fun getSimilar(
        @Path("video_id") videoId: String,
        @Query("limit") limit: Int = SIMILAR_LIMIT,
    ): SimilarVideosResponseDto

    @GET("ui/videos/{video_id}/like")
    suspend fun checkLike(@Path("video_id") videoId: String): LikeCheckDto

    @POST("ui/videos/{video_id}/like")
    suspend fun toggleLike(@Path("video_id") videoId: String): LikeToggleDto

    /**
     * AND-197 — the authoritative per-video access check.
     * op=check_video_access_ui_videos__video_id__access_get -> VodAccessOut. `user_sub` is intentionally
     * omitted so the server derives identity from the session (prevents client identity spoofing).
     */
    @GET("ui/videos/{video_id}/access")
    suspend fun checkAccess(@Path("video_id") videoId: String): VodAccessDto

    companion object {
        // Server `limit` default is 50, min 1, max 200; the app page size stays small for fast paint.
        const val LIBRARY_PAGE_SIZE = 24
        const val SIMILAR_LIMIT = 12
    }
}
