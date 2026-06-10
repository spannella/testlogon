package com.testlogon.android.data.stories

/**
 * AND-199 / AND-200 — immutable domain models for the Stories surface.
 *
 * Per the verified contract a backend `Story` is a single media item; an author's "segments" are the
 * author's list of `Story` objects (GET /ui/stories/user/{user_id}), and a tray entry is one
 * `StoryBarEntry` (GET /ui/stories/bar). Mapping rules live here (the single point of DTO->domain
 * adaptation); repositories return these types, never raw DTOs.
 */

/** One image|video story media item. */
enum class SegmentKind { IMAGE, VIDEO }

/**
 * One tray entry == one author with active stories. The bar API returns NO display name or avatar URL
 * (StoryBarEntry has only user_id); a label is derived from [userId] for accessibility, mirroring the
 * web placeholder.
 */
data class StoryBarItem(
    val userId: String,
    val latestStoryId: String,
    val latestMediaUrl: String?,
    val storyCount: Int,
    val hasUnseen: Boolean,
    val isOwn: Boolean,
) {
    /** Human-friendly label derived from the opaque user id (local-part before '@'), web parity. */
    val displayLabel: String get() = userId.substringBefore('@').ifBlank { userId }
}

/** One segment == one backend Story. [durationMs] is the auto-advance ceiling for the segment. */
data class StorySegment(
    val storyId: String,
    val authorId: String,
    val kind: SegmentKind,
    val mediaUrl: String,
    val durationMs: Long,
    val textOverlay: String?,
    val linkUrl: String?,
    val expiresAt: Long,
    val viewCount: Int,
    val highlighted: Boolean,
)

/** Default per-image display duration (web SLIDE_DURATION_MS), also the ceiling fallback for video. */
const val DEFAULT_STORY_DURATION_MS: Long = 5_000L

// ---- Mappers (DTO -> domain) ----

internal fun StoryBarEntryDto.toDomain(): StoryBarItem = StoryBarItem(
    userId = userId,
    latestStoryId = latestStoryId,
    latestMediaUrl = latestMediaUrl,
    storyCount = storyCount,
    hasUnseen = hasUnseen,
    isOwn = isOwn,
)

internal fun StoryDto.toDomain(): StorySegment {
    val kind = when (mediaType?.lowercase()) {
        "video" -> SegmentKind.VIDEO
        "image" -> SegmentKind.IMAGE
        else -> SegmentKind.IMAGE // unknown/null -> IMAGE fallback (web parity); logged by caller.
    }
    // Web rule: duration_seconds applies ONLY to video; images always use the 5000 ms default.
    val durationMs = if (kind == SegmentKind.VIDEO && durationSeconds != null && durationSeconds > 0) {
        (durationSeconds * 1000).toLong()
    } else {
        DEFAULT_STORY_DURATION_MS
    }
    return StorySegment(
        storyId = storyId,
        authorId = authorId,
        kind = kind,
        mediaUrl = mediaUrl,
        durationMs = durationMs,
        textOverlay = textOverlay,
        linkUrl = linkUrl,
        expiresAt = expiresAt,
        viewCount = viewCount,
        highlighted = highlighted,
    )
}
