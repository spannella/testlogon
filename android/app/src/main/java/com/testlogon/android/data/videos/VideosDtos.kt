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
    // AND-197 — flat pay-per-view / subscription gating fields (no nested pricing object).
    @Json(name = "price_cents") val priceCents: Int? = null,
    @Json(name = "purchase_available") val purchaseAvailable: Boolean? = null,
    @Json(name = "subscription_available") val subscriptionAvailable: Boolean? = null,
    @Json(name = "subscription_upsell") val subscriptionUpsell: Boolean? = null,
    // B-VIDSOCIAL2 — video-level reactions + running tip total (feed-post parity).
    @Json(name = "reactions_counts") val reactionsCounts: Map<String, Int> = emptyMap(),
    @Json(name = "my_reactions") val myReactions: List<String> = emptyList(),
    @Json(name = "tip_total_cents") val tipTotalCents: Int = 0,
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

/**
 * AND-197 — VodAccessOut (the per-video access check). Required: `entitled`, `reason`. The rest carry
 * server defaults. `reason`/`access_mode` are FREE-FORM strings (no fixed enum); the resolver keys off
 * the typed booleans + `access_mode` literals, never `reason`. There is NO `granted`/`status`/`video_id`
 * and NO nested pricing/currency on this DTO (verified openapi.pretty.json lines 82127-82212).
 */
@JsonClass(generateAdapter = true)
data class VodAccessDto(
    @Json(name = "entitled") val entitled: Boolean = false,
    @Json(name = "reason") val reason: String = "none",
    @Json(name = "access_mode") val accessMode: String? = null,
    @Json(name = "price_cents") val priceCents: Int? = null,
    @Json(name = "purchase_type") val purchaseType: String = "permanent",
    @Json(name = "purchase_available") val purchaseAvailable: Boolean = false,
    @Json(name = "subscription_available") val subscriptionAvailable: Boolean = false,
    @Json(name = "subscription_upsell") val subscriptionUpsell: Boolean = false,
    @Json(name = "expires_at") val expiresAt: Long? = null,
    @Json(name = "views_remaining") val viewsRemaining: Int = -1,
)

/** LikeToggleOut = { liked, like_count }. */
@JsonClass(generateAdapter = true)
data class LikeToggleDto(
    @Json(name = "liked") val liked: Boolean = false,
    @Json(name = "like_count") val likeCount: Int = 0,
)

/** B-VIDSOCIAL2 — request body for a video reaction add/remove. */
@JsonClass(generateAdapter = true)
data class VideoReactionReq(
    @Json(name = "emoji") val emoji: String,
)

/** B-VIDSOCIAL2 — VideoReactionOut = { video_id, reactions_counts, my_reactions }. */
@JsonClass(generateAdapter = true)
data class VideoReactionDto(
    @Json(name = "video_id") val videoId: String = "",
    @Json(name = "reactions_counts") val reactionsCounts: Map<String, Int> = emptyMap(),
    @Json(name = "my_reactions") val myReactions: List<String> = emptyList(),
)

/** B-VIDSOCIAL2 — request body for tipping a video's creator. */
@JsonClass(generateAdapter = true)
data class VideoTipReq(
    @Json(name = "amount_cents") val amountCents: Int,
    @Json(name = "currency") val currency: String = "usd",
    @Json(name = "payment_method_id") val paymentMethodId: String? = null,
)

/** B-VIDSOCIAL2 — VideoTipOut = { ok, video_id, amount_cents, currency, tip_total_cents }. */
@JsonClass(generateAdapter = true)
data class VideoTipDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "video_id") val videoId: String = "",
    @Json(name = "amount_cents") val amountCents: Int = 0,
    @Json(name = "currency") val currency: String = "usd",
    @Json(name = "tip_total_cents") val tipTotalCents: Int = 0,
)
