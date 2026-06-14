package com.testlogon.android.data.discover

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.testlogon.android.data.feed.PostDto

/**
 * AND-182 / AND-183 / AND-184 — wire DTOs for the discover / tag / recommendations / global-search
 * surfaces.
 *
 * Verified against the staged web reference (authoritative, since the OpenAPI 200 schemas for these
 * routes are empty):
 *  - reference/src/api/endpoints/discovery.ts: DiscoveryUser / DiscoverySearchResponse /
 *    TrendingTag / TrendingTagsResponse / TagDiscoverResponse (posts: FeedPost[]).
 *  - reference/src/api/endpoints/recommendations.ts: RecommendedVideo / ForYouResponse /
 *    CreatorSuggestion / CreatorSuggestionsResponse.
 *  - reference/src/api/endpoints/search.ts: SearchResultItem / SearchResultSection /
 *    GlobalSearchResponse.
 *
 * Only the server-required ids are mandatory; everything else is defaulted so a missing/unknown field
 * never crashes decoding (Moshi ignores unknown keys). Tag-page posts reuse the AND-097 [PostDto] and
 * its redaction-safe mapper rather than re-modelling FeedPost.
 */

// ---- Discover: suggested / trending / discover-search (DiscoverySearchResponse) ----

@JsonClass(generateAdapter = true)
data class DiscoverySearchResponseDto(
    @Json(name = "items") val items: List<DiscoveryUserDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
    @Json(name = "total_estimate") val totalEstimate: Int = 0,
)

@JsonClass(generateAdapter = true)
data class DiscoveryUserDto(
    @Json(name = "user_id") val userId: String,
    @Json(name = "display_name") val displayName: String = "",
    @Json(name = "profile_photo_url") val profilePhotoUrl: String? = null,
    @Json(name = "description") val description: String? = null,
    @Json(name = "follower_count") val followerCount: Int = 0,
    @Json(name = "is_following") val isFollowing: Boolean = false,
    @Json(name = "is_followed_by") val isFollowedBy: Boolean = false,
    @Json(name = "is_mutual") val isMutual: Boolean = false,
)

// ---- Discover: trending tags (TrendingTagsResponse) ----

@JsonClass(generateAdapter = true)
data class TrendingTagsResponseDto(
    @Json(name = "tags") val tags: List<TrendingTagDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class TrendingTagDto(
    @Json(name = "tag") val tag: String,
    @Json(name = "count") val count: Int = 0,
    @Json(name = "last_used_at") val lastUsedAt: String? = null,
)

// ---- Tag pages (TagDiscoverResponse) — posts reuse AND-097 PostDto ----

@JsonClass(generateAdapter = true)
data class TagDiscoverResponseDto(
    @Json(name = "tag") val tag: String = "",
    @Json(name = "posts") val posts: List<PostDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

// ---- Recommendations: For-You feed (ForYouResponse) ----

@JsonClass(generateAdapter = true)
data class ForYouResponseDto(
    @Json(name = "videos") val videos: List<RecommendedVideoDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
    @Json(name = "source") val source: String = "for_you",
)

@JsonClass(generateAdapter = true)
data class RecommendedVideoDto(
    @Json(name = "video_id") val videoId: String,
    @Json(name = "title") val title: String = "",
    @Json(name = "description") val description: String? = null,
    @Json(name = "thumbnail_url") val thumbnailUrl: String? = null,
    @Json(name = "duration_seconds") val durationSeconds: Double? = null,
    @Json(name = "creator_id") val creatorId: String = "",
    @Json(name = "creator_name") val creatorName: String = "",
    @Json(name = "view_count") val viewCount: Long = 0,
    @Json(name = "like_count") val likeCount: Long = 0,
    @Json(name = "category") val category: String? = null,
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "recommendation_reason") val recommendationReason: String? = null,
)

// ---- Recommendations: creator suggestions (CreatorSuggestionsResponse, /ui/discover/creators) ----

@JsonClass(generateAdapter = true)
data class CreatorSuggestionsResponseDto(
    @Json(name = "creators") val creators: List<CreatorSuggestionDto> = emptyList(),
    @Json(name = "source") val source: String = "",
)

@JsonClass(generateAdapter = true)
data class CreatorSuggestionDto(
    @Json(name = "user_id") val userId: String,
    @Json(name = "display_name") val displayName: String = "",
    @Json(name = "avatar_url") val avatarUrl: String? = null,
    @Json(name = "subscriber_count") val subscriberCount: Long = 0,
    @Json(name = "video_count") val videoCount: Long = 0,
    @Json(name = "overlap_reason") val overlapReason: String? = null,
)
