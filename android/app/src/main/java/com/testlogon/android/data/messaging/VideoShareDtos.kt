package com.testlogon.android.data.messaging

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * AND-131 — wire DTOs for the video-share flow.
 *
 * The primary flow shares an EXISTING published library video by opaque video_id — there is no
 * upload step (verified reference/src/api/endpoints/messaging.ts: sendVideoShareMessage,
 * src/pages/messages/VideoPickerDialog.tsx: listMyVideos). The post body carries ONLY
 * {video_id, text?, send_at?}; the server returns the resolved video_share object (thumbnail,
 * hls_manifest_url, playback_token, ...).
 */

/** CreateVideoShareMessageIn = { video_id (required), text?, send_at? }. */
@JsonClass(generateAdapter = true)
data class CreateVideoShareReq(
    @Json(name = "video_id") val videoId: String,
    val text: String? = null,
    @Json(name = "send_at") val sendAt: Long? = null,
)

/** GET /ui/videos -> VideoListResponse { items, cursor? }. */
@JsonClass(generateAdapter = true)
data class VideoListRespDto(
    val items: List<VideoListItemDto> = emptyList(),
    val cursor: String? = null,
)

/** VideoListItem — a row in the share picker. */
@JsonClass(generateAdapter = true)
data class VideoListItemDto(
    @Json(name = "video_id") val videoId: String,
    val title: String = "",
    val status: String = "",
    val visibility: String = "",
    @Json(name = "duration_seconds") val durationSeconds: Int? = null,
    @Json(name = "thumbnail_url") val thumbnailUrl: String? = null,
)
