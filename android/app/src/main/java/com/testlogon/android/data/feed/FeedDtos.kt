package com.testlogon.android.data.feed

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * AND-097 — wire DTOs for the consumer newsfeed.
 *
 * Verified against reference/src/api/types.ts (FeedPost), reference/src/api/endpoints/newsfeed.ts
 * (getFeed -> GET /feed, getPost -> GET /posts/{post_id}), and reference/src/pages/feed/PostCard.tsx.
 *
 * Key field facts (review-corrected contract):
 *  - id is "post_id" (NOT "id"); author is a flat "author_id" (NO nested author object).
 *  - text is "body" / "body_plain" (NOT "text"); plain projection is body_plain ?? body.
 *  - media is "image_urls": string[] + a SINGLE "video" object (NO "media[]" array).
 *  - lock state is FLAT: locked, unlocked, lock_type ("fixed_price"|"tip_lottery"),
 *    unlock_price_cents, unlock_limit/_count/_limit_reached, lock_expired.
 *    Web rule: isLocked = !!post.locked && !post.unlocked. There is NO currency field (USD assumed).
 *  - envelope is { items, next_cursor } — NO has_more; end-of-feed == next_cursor null/absent.
 *
 * Only post_id/author_id/created_at are server-required for our read; everything else is defaulted so
 * unknown/missing fields never crash the page (Moshi codegen ignores unknown JSON keys by default).
 */
@JsonClass(generateAdapter = true)
data class FeedPageDto(
    @Json(name = "items") val items: List<PostDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class PostDto(
    @Json(name = "post_id") val postId: String,
    @Json(name = "author_id") val authorId: String = "",
    @Json(name = "created_at") val createdAt: String = "",
    @Json(name = "body") val body: String? = null,
    @Json(name = "body_plain") val bodyPlain: String? = null,
    @Json(name = "image_urls") val imageUrls: List<String>? = null,
    @Json(name = "video") val video: VideoDto? = null,
    @Json(name = "tags") val tags: List<String>? = null,
    @Json(name = "like_count") val likeCount: Int = 0,
    @Json(name = "comment_count") val commentCount: Int = 0,
    @Json(name = "liked_by_me") val likedByMe: Boolean = false,
    // --- flat lock / paywall fields (mirror FeedPost) ---
    @Json(name = "locked") val locked: Boolean = false,
    @Json(name = "unlocked") val unlocked: Boolean = false,
    @Json(name = "lock_type") val lockType: String? = null,
    @Json(name = "unlock_price_cents") val unlockPriceCents: Int? = null,
    @Json(name = "unlock_limit") val unlockLimit: Int? = null,
    @Json(name = "unlock_count") val unlockCount: Int? = null,
    @Json(name = "unlock_limit_reached") val unlockLimitReached: Boolean? = null,
    @Json(name = "lock_expired") val lockExpired: Boolean? = null,
)

@JsonClass(generateAdapter = true)
data class VideoDto(
    @Json(name = "video_id") val videoId: String,
    @Json(name = "title") val title: String? = null,
    @Json(name = "thumbnail_url") val thumbnailUrl: String? = null,
    @Json(name = "duration_seconds") val durationSeconds: Long? = null,
    @Json(name = "hls_manifest_url") val hlsManifestUrl: String? = null,
)
