package com.testlogon.android.core.network.groups

import com.squareup.moshi.Json
import com.testlogon.android.core.network.poll.PollInputDto
import com.testlogon.android.core.network.poll.PollSnapshotDto

/**
 * Batch-8 (#11) - transport DTOs for the GROUP FEED surface (GROUP-002 group_feed router).
 *
 * CODEGEN NOTE: core-network does NOT apply Moshi KSP codegen, so these decode via the reflective
 * KotlinJsonAdapterFactory on the shared Moshi - every snake_case wire key is pinned with @Json.
 *
 * CONTRACT (verified live on prod):
 *   POST ui/groups/{groupId}/posts  { text(1..10000), body_format, image_url?, audience, unlock_price_cents? }
 *        -> 201 GroupFeedPostDto
 *   GET  ui/groups/{groupId}/feed?cursor=&limit=  -> GroupFeedResponse { posts[], cursor, has_more }
 */

/** Request body for POST ui/groups/{groupId}/posts. `text` is required (server-validated 1..10000). */
data class GroupPostCreateIn(
    @Json(name = "text") val text: String,
    @Json(name = "body_format") val bodyFormat: String = "plain",
    @Json(name = "image_url") val imageUrl: String? = null,
    // Batch-9 (#11): full-newsfeed media parity - multiple images + a single VOD video.
    @Json(name = "image_urls") val imageUrls: List<String>? = null,
    @Json(name = "video_id") val videoId: String? = null,
    @Json(name = "audience") val audience: String = "public",
    @Json(name = "unlock_price_cents") val unlockPriceCents: Int? = null,
    // Arbitrary text-option poll attached to the post (question + 2..N text options, single/multi).
    @Json(name = "poll") val poll: PollInputDto? = null,
)

/**
 * One group feed post. `post_id` + `user_id` are required; `text` may be null (a locked post the viewer has
 * not unlocked); the rest is optional / defaulted. `created_at` is INTEGER epoch.
 */
data class GroupFeedPostDto(
    @Json(name = "post_id") val postId: String,
    @Json(name = "user_id") val userId: String,
    @Json(name = "user_display_name") val userDisplayName: String? = null,
    @Json(name = "user_avatar_url") val userAvatarUrl: String? = null,
    @Json(name = "text") val text: String? = null,
    @Json(name = "body_format") val bodyFormat: String? = null,
    @Json(name = "image_url") val imageUrl: String? = null,
    @Json(name = "image_urls") val imageUrls: List<String>? = null,
    @Json(name = "video_id") val videoId: String? = null,
    @Json(name = "group_id") val groupId: String? = null,
    @Json(name = "audience") val audience: String? = null,
    @Json(name = "pinned") val pinned: Boolean? = false,
    @Json(name = "unlock_price_cents") val unlockPriceCents: Int? = null,
    @Json(name = "unlocked") val unlocked: Boolean? = true,
    @Json(name = "tip_total_cents") val tipTotalCents: Int? = 0,
    @Json(name = "comment_count") val commentCount: Int? = 0,
    @Json(name = "created_at") val createdAt: Long? = 0,
    @Json(name = "poll") val poll: PollSnapshotDto? = null,
)

/** The feed page envelope { posts, cursor, has_more }. A null/blank cursor terminates pagination. */
data class GroupFeedResponse(
    @Json(name = "posts") val posts: List<GroupFeedPostDto> = emptyList(),
    @Json(name = "cursor") val cursor: String? = null,
    @Json(name = "has_more") val hasMore: Boolean? = false,
)
