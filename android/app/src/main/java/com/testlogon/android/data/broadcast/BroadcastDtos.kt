package com.testlogon.android.data.broadcast

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * AND-278 — wire DTOs for the broadcast domain.
 *
 * Shapes verified against reference/src/api/endpoints/broadcast.ts (BroadcastSession /
 * SessionListResponse / BroadcastPlaybackUrl), broadcastSchedule.ts (ScheduledListResponse), and
 * openapi.index.txt (BroadcastSessionOut / BroadcastSessionListOut / BroadcastScheduledListOut /
 * BroadcastPlaybackUrlOut). Field names are snake_case via [Json]; absent optionals fall back to Kotlin
 * defaults (lenient decode). ISO timestamps stay as strings on the wire and are parsed to Instant in
 * [toDomain] (no shared Instant Moshi adapter — the network Moshi uses the reflective Kotlin factory);
 * `scheduled_at` / `expires_at` are epoch-SECOND integers parsed via Instant.ofEpochSecond in the mapper.
 *
 * NOTE: the verified wire has NO nested `host` object, NO nested `playback` object, and NO
 * `hls_url`/`title`/`scheduled_start_at`/`ended_at`/`viewer_count`/`remind_me`/`next_page` fields.
 */

/** BroadcastSessionOut — the SAME shape for a list element and the getSession detail response. */
@JsonClass(generateAdapter = true)
data class BroadcastSessionDto(
    @Json(name = "id") val id: String,
    @Json(name = "profile_id") val profileId: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "created_by") val createdBy: String = "",
    @Json(name = "created_at") val createdAt: String? = null,
    @Json(name = "updated_at") val updatedAt: String? = null,
    @Json(name = "name") val name: String? = null,
    @Json(name = "description") val description: String? = null,
    @Json(name = "cloudfront_playback_url") val cloudfrontPlaybackUrl: String? = null,
    @Json(name = "mediapackage_endpoint") val mediapackageEndpoint: String? = null,
    @Json(name = "ingest_url") val ingestUrl: String? = null,
    @Json(name = "thumbnail_url") val thumbnailUrl: String? = null,
    @Json(name = "scheduled_at") val scheduledAt: Long? = null,
    @Json(name = "schedule_status") val scheduleStatus: String? = null,
    @Json(name = "started_at") val startedAt: String? = null,
    @Json(name = "stopped_at") val stoppedAt: String? = null,
    @Json(name = "cancelled_at") val cancelledAt: String? = null,
    @Json(name = "tip_total_cents") val tipTotalCents: Long? = null,
    @Json(name = "tip_count") val tipCount: Int? = null,
)

/** BroadcastSessionListOut = { items, has_more } (NOT a cursor). */
@JsonClass(generateAdapter = true)
data class BroadcastSessionListRespDto(
    @Json(name = "items") val items: List<BroadcastSessionDto> = emptyList(),
    @Json(name = "has_more") val hasMore: Boolean = false,
)

/** BroadcastScheduledListOut = { items, count } (the scheduled & upcoming routes). */
@JsonClass(generateAdapter = true)
data class BroadcastScheduledListRespDto(
    @Json(name = "items") val items: List<BroadcastSessionDto> = emptyList(),
    @Json(name = "count") val count: Int = 0,
)

/** BroadcastPlaybackUrlOut = { session_id, playback_url, expires_at } (epoch-second expiry). */
@JsonClass(generateAdapter = true)
data class BroadcastPlaybackUrlDto(
    @Json(name = "session_id") val sessionId: String,
    @Json(name = "playback_url") val playbackUrl: String,
    @Json(name = "expires_at") val expiresAt: Long,
)
