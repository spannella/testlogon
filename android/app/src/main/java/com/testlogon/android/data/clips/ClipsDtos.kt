package com.testlogon.android.data.clips

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * AND-196 — wire DTOs for the Clips feature.
 *
 * Field shapes verified against OpenAPI (ClipOut / PublicClipOut / ClipListOut) and
 * reference/src/api/types.ts (BroadcastClip / PublicBroadcastClip / ClipListResponse). KEY FACTS that
 * have bitten ports before:
 *  - id field is `clip_id` (NOT `id`); the source VOD is `video_id`.
 *  - the list pagination field is `next_cursor` (NOT `cursor` like the videos list).
 *  - `start_seconds` / `end_seconds` / `duration_seconds` are NUMBERS/floats (seconds, not ms).
 *  - `created_at` is an epoch-SECOND integer, not an ISO string.
 *  - the caption field is `title` (NOT `caption`); the poster is `thumbnail_url`.
 *  - there is NO `hls_url` / stream URL field, and NO `visibility` / `locked` / entitlement field.
 *  - PublicClipOut extends ClipOut with `broadcaster_display_name` + `profile_id` for attribution.
 */

/** ClipListOut = { clips: ClipOut[], next_cursor?: string }. */
@JsonClass(generateAdapter = true)
data class ClipListResponseDto(
    @Json(name = "clips") val clips: List<ClipDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

/** ClipOut — one clip (authed gallery row or single fetch). */
@JsonClass(generateAdapter = true)
data class ClipDto(
    @Json(name = "clip_id") val clipId: String,
    @Json(name = "session_id") val sessionId: String = "",
    @Json(name = "broadcaster_user_id") val broadcasterUserId: String = "",
    @Json(name = "creator_user_id") val creatorUserId: String = "",
    @Json(name = "creator_display_name") val creatorDisplayName: String = "",
    @Json(name = "video_id") val videoId: String = "",
    @Json(name = "title") val title: String = "",
    @Json(name = "start_seconds") val startSeconds: Double = 0.0,
    @Json(name = "end_seconds") val endSeconds: Double = 0.0,
    @Json(name = "duration_seconds") val durationSeconds: Double = 0.0,
    @Json(name = "status") val status: String = "",
    @Json(name = "view_count") val viewCount: Int = 0,
    @Json(name = "share_count") val shareCount: Int = 0,
    @Json(name = "thumbnail_url") val thumbnailUrl: String? = null,
    @Json(name = "created_at") val createdAt: Long = 0L,
)

/** PublicClipOut — a public clip; extends ClipOut with broadcaster attribution. */
@JsonClass(generateAdapter = true)
data class PublicClipDto(
    @Json(name = "clip_id") val clipId: String,
    @Json(name = "session_id") val sessionId: String = "",
    @Json(name = "broadcaster_user_id") val broadcasterUserId: String = "",
    @Json(name = "creator_user_id") val creatorUserId: String = "",
    @Json(name = "creator_display_name") val creatorDisplayName: String = "",
    @Json(name = "video_id") val videoId: String = "",
    @Json(name = "title") val title: String = "",
    @Json(name = "start_seconds") val startSeconds: Double = 0.0,
    @Json(name = "end_seconds") val endSeconds: Double = 0.0,
    @Json(name = "duration_seconds") val durationSeconds: Double = 0.0,
    @Json(name = "status") val status: String = "",
    @Json(name = "view_count") val viewCount: Int = 0,
    @Json(name = "share_count") val shareCount: Int = 0,
    @Json(name = "thumbnail_url") val thumbnailUrl: String? = null,
    @Json(name = "created_at") val createdAt: Long = 0L,
    @Json(name = "broadcaster_display_name") val broadcasterDisplayName: String = "",
    @Json(name = "profile_id") val profileId: String = "",
)
