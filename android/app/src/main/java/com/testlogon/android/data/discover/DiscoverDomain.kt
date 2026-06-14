package com.testlogon.android.data.discover

import com.testlogon.android.data.feed.FeedPost
import com.testlogon.android.data.feed.toDomain

/**
 * AND-182 / AND-183 / AND-184 — pure, framework-free domain models + mappers for discover, tag pages,
 * and recommendations. No android.* / java.time here so the mappers are minSdk24-safe and
 * JVM-unit-testable.
 */

// ---- Discover screen (AND-182) ----

/** A creator card on the discover grid (mapped from DiscoveryUser). */
data class DiscoverCreator(
    val userId: String,
    val displayName: String,
    val profilePhotoUrl: String?,
    val description: String?,
    val followerCount: Int,
    val isFollowing: Boolean,
)

/** A trending hashtag chip (mapped from TrendingTag). */
data class DiscoverTag(
    val tag: String,
    val count: Int,
)

/**
 * The aggregated, client-composed discover payload (AND-182 §4.3). The repository fans out to the
 * per-section endpoints and assembles this; the UI renders each non-empty section.
 */
data class DiscoverContent(
    val suggested: List<DiscoverCreator>,
    val trendingCreators: List<DiscoverCreator>,
    val trendingTags: List<DiscoverTag>,
) {
    val isEmpty: Boolean
        get() = suggested.isEmpty() && trendingCreators.isEmpty() && trendingTags.isEmpty()
}

internal fun DiscoveryUserDto.toCreator(): DiscoverCreator = DiscoverCreator(
    userId = userId,
    displayName = displayName,
    profilePhotoUrl = profilePhotoUrl?.takeIf { it.isNotBlank() },
    description = description?.takeIf { it.isNotBlank() },
    followerCount = followerCount,
    isFollowing = isFollowing,
)

internal fun List<DiscoveryUserDto>.toCreators(): List<DiscoverCreator> =
    asSequence().filter { it.userId.isNotBlank() }.map { it.toCreator() }.toList()

internal fun TrendingTagDto.toTag(): DiscoverTag = DiscoverTag(tag = tag, count = count)

internal fun List<TrendingTagDto>.toTags(): List<DiscoverTag> =
    asSequence().filter { it.tag.isNotBlank() }.map { it.toTag() }.toList()

// ---- Tag pages (AND-183) — reuse the redaction-safe FeedPost mapper ----

/** One page of tag-filtered posts + the opaque cursor for the next page (null = terminal). */
data class TagPostPage(
    val posts: List<FeedPost>,
    val nextCursor: String?,
)

internal fun TagDiscoverResponseDto.toDomain(): TagPostPage = TagPostPage(
    posts = posts.map { it.toDomain() },
    nextCursor = nextCursor,
)

// ---- Recommendations (AND-184) ----

/** One recommended item ("for you" video). `id` == video_id; used for navigation. */
data class RecommendationItem(
    val id: String,
    val title: String,
    val posterUrl: String?,
    val reason: String?,
)

/**
 * The recommendations payload: a flat list of items + the server `source` ("for_you" |
 * "trending_fallback") which drives the cold-start notice.
 */
data class Recommendations(
    val items: List<RecommendationItem>,
    val source: String,
) {
    val isTrendingFallback: Boolean get() = source == SOURCE_TRENDING_FALLBACK

    companion object {
        const val SOURCE_FOR_YOU = "for_you"
        const val SOURCE_TRENDING_FALLBACK = "trending_fallback"
    }
}

internal fun RecommendedVideoDto.toRecommendationItem(): RecommendationItem = RecommendationItem(
    id = videoId,
    title = title,
    posterUrl = thumbnailUrl?.takeIf { it.isNotBlank() },
    reason = recommendationReason?.takeIf { it.isNotBlank() },
)

internal fun ForYouResponseDto.toDomain(): Recommendations = Recommendations(
    // Drop malformed items (blank video_id) defensively rather than failing the whole feed.
    items = videos.asSequence().filter { it.videoId.isNotBlank() }.map { it.toRecommendationItem() }.toList(),
    source = source,
)
