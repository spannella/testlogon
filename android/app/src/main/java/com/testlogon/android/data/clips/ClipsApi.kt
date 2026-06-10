package com.testlogon.android.data.clips

import retrofit2.http.GET
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-196 — Retrofit interface for the Clips feature (short shareable segments of a VOD).
 *
 * Dedicated to this feature (separate from VideosApi / VodApi). Paths are relative (no leading slash)
 * so they resolve against the shared Retrofit base URL; cookies, Authorization: Bearer and
 * X-CSRF-Token are attached by the core-network interceptor chain. The public endpoint takes NO auth
 * params server-side (it is genuinely unauthenticated); the client may still attach headers harmlessly.
 * All reads are idempotent GETs.
 *
 * Verified contract (reference/src/api/endpoints/clips.ts + types.ts; openapi.index.txt). KEY FACTS:
 *  - GET ui/clips                         (sort?, limit, cursor?) -> ClipListOut { clips, next_cursor? }
 *      op=gallery_route_ui_clips_get — authed gallery feed (sort = "popular" | "recent").
 *      NOTE the pagination field is `next_cursor` here (NOT `cursor` like the videos list).
 *  - GET ui/clips/mine                    (no paging params)      -> ClipListOut
 *      op=my_clips_route_ui_clips_mine_get — the caller's own clips.
 *  - GET broadcast/clips/{clip_id}                                -> ClipOut  (one clip, authed)
 *      op=get_clip_route_broadcast_clips__clip_id__get
 *  - GET broadcast/public/clips/{clip_id}                         -> PublicClipOut (public, no auth)
 *      op=public_clip_route_broadcast_public_clips__clip_id__get — adds broadcaster attribution.
 *
 * A clip carries `video_id` + `thumbnail_url` only; there is NO hls_url / stream URL and NO
 * visibility/locked/entitlement field on the clip schema. The web reference renders the thumbnail and
 * does not itself play HLS. We REUSE the videos detail endpoint (VideosApi.getVideoDetail) to resolve a
 * playable tokenized HLS URL from `video_id`; see ClipsRepository. A 4xx on a public clip is "unavailable".
 */
interface ClipsApi {

    @GET("ui/clips")
    suspend fun getFeed(
        @Query("sort") sort: String? = SORT_RECENT,
        @Query("limit") limit: Int = FEED_PAGE_SIZE,
        @Query("cursor") cursor: String? = null,
    ): ClipListResponseDto

    @GET("ui/clips/mine")
    suspend fun getMyClips(): ClipListResponseDto

    @GET("broadcast/clips/{clip_id}")
    suspend fun getClip(@Path("clip_id") clipId: String): ClipDto

    @GET("broadcast/public/clips/{clip_id}")
    suspend fun getPublicClip(@Path("clip_id") clipId: String): PublicClipDto

    companion object {
        // Server `limit` supports a small page; the app keeps it small for fast paint.
        const val FEED_PAGE_SIZE = 10

        // Verified `sort` values for GET ui/clips.
        const val SORT_RECENT = "recent"
        const val SORT_POPULAR = "popular"
    }
}
