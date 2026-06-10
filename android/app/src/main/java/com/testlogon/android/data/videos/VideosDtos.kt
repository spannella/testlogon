package com.testlogon.android.data.videos

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * AND-189 / AND-190 — wire DTOs for the Videos library + detail.
 *
 * Field shapes verified against OpenAPI components.schemas (VideoListOut / VideoListItem /
 * VideoDetailOut / SimilarVideosResponse / LikeCheckOut / LikeToggleOut) and
 * reference/src/api/endpoints/videos.ts. Key facts that have bitten ports before:
 *  - item id field is `video_id` (NOT `id`).
 *  - pagination field is `cursor` (NOT `next_cursor`); absent/null on the terminal page.
 *  - `duration_seconds` is a NUMBER/float (e.g. 372.0), not an Int.
 *  - `created_at` / `updated_at` / `published_at` are epoch-SECOND integers, not ISO strings.
 *  - there is NO `view_count` / `tags` / `is_locked` on VideoListItem or VideoDetailOut.
 *  - the playable URL is `hls_manifest_url` paired with `playback_token` (no `playback_url`).
 */

/** VideoListOut = { items: VideoListItem[], cursor?: string|null }. */
@JsonClass(generateAdapter = true)
data class VideoListResponseDto(
    @Json(name = "items") val items: List<VideoListItemDto> = emptyList(),
    @Json(name = "cursor") val cursor: String? = null,
)

/** VideoListItem — one row in the library grid. */
@JsonClass(generateAdapter = true)
data class VideoListItemDto(
    @Json(name = "video_id") val videoId: String,
    @Json(name = "title") val title: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "visibility") val visibility: String = "",
    @Json(name = "created_at") val createdAt: Long = 0L,
    @Json(name = "updated_at") val updatedAt: Long = 0L,
    @Json(name = "thumbnail_url") val thumbnailUrl: String? = null,
    @Json(name = "duration_seconds") val durationSeconds: Double? = null,
    @Json(name = "width") val width: Int? = null,
    @Json(name = "height") val height: Int? = null,
    @Json(name = "file_size_bytes") val fileSizeBytes: Long? = null,
    @Json(name = "review_status") val reviewStatus: String? = null,
    @Json(name = "owner_user_id") val ownerUserId: String? = null,
)

/** VideoDetailOut (subset relevant to playback + display; monetization/DRM fields omitted as oos). */
@JsonClass(generateAdapter = true)
data class VideoDetailDto(
    @Json(name = "video_id") val videoId: String,
    @Json(name = "owner_user_id") val ownerUserId: String = "",
    @Json(name = "title") val title: String = "",
    @Json(name = "description") val description: String? = null,
    @Json(name = "status") val status: String = "",
    @Json(name = "visibility") val visibility: String = "",
    @Json(name = "created_at") val createdAt: Long = 0L,
    @Json(name = "updated_at") val updatedAt: Long = 0L,
    @Json(name = "published_at") val publishedAt: Long? = null,
    @Json(name = "duration_seconds") val durationSeconds: Double? = null,
    @Json(name = "width") val width: Int? = null,
    @Json(name = "height") val height: Int? = null,
    @Json(name = "thumbnail_url") val thumbnailUrl: String? = null,
    @Json(name = "hls_manifest_url") val hlsManifestUrl: String? = null,
    @Json(name = "playback_token") val playbackToken: String? = null,
    @Json(name = "playback_expires_at") val playbackExpiresAt: Long? = null,
    @Json(name = "review_status") val reviewStatus: String? = null,
    @Json(name = "is_entitled") val isEntitled: Boolean? = null,
    @Json(name = "access_mode") val accessMode: String? = null,
    @Json(name = "access_reason") val accessReason: String? = null,
)

/** SimilarVideosResponse = { videos: VideoListItem[]-ish }. Modelled defensively as a list. */
@JsonClass(generateAdapter = true)
data class SimilarVideosResponseDto(
    @Json(name = "videos") val videos: List<VideoListItemDto> = emptyList(),
)

/** LikeCheckOut = { liked }. */
@JsonClass(generateAdapter = true)
data class LikeCheckDto(
    @Json(name = "liked") val liked: Boolean = false,
)

/** LikeToggleOut = { liked, like_count }. */
@JsonClass(generateAdapter = true)
data class LikeToggleDto(
    @Json(name = "liked") val liked: Boolean = false,
    @Json(name = "like_count") val likeCount: Int = 0,
)
