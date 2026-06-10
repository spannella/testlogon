package com.testlogon.android.data.gallery

/**
 * AND-201 — immutable domain models for the video gallery. Every gallery item is a video (there is no
 * image/video discriminator). Mapping lives here; the paging source / repository never expose raw DTOs.
 */
data class GalleryVideoItem(
    val videoId: String,
    val title: String,
    val ownerUserId: String,
    val description: String? = null,
    val thumbnailUrl: String? = null,
    val durationSeconds: Double? = null,
    val category: String? = null,
    val tags: List<String> = emptyList(),
    val viewCount: Int = 0,
    val likeCount: Int = 0,
    val commentCount: Int = 0,
    val priceCents: Int? = null,
    val accessMode: String? = null,
    val createdAt: Long = 0,
    val publishedAt: Long? = null,
) {
    /** PPV badge shows only when a positive price is set. */
    val isPpv: Boolean get() = (priceCents ?: 0) > 0
}

data class GalleryCategory(val slug: String, val label: String)

/** One mapped page of gallery videos plus the next-page cursor (null/absent = last page). */
data class GalleryPage(
    val videos: List<GalleryVideoItem>,
    val categories: List<GalleryCategory>,
    val cursor: String?,
)

// ---- Mappers (DTO -> domain) ----

/** Maps a wire item to domain; returns null if a required field is blank (dropped, never rendered broken). */
internal fun GalleryVideoItemDto.toDomainOrNull(): GalleryVideoItem? {
    if (videoId.isBlank() || title.isBlank() || ownerUserId.isBlank()) return null
    return GalleryVideoItem(
        videoId = videoId,
        title = title,
        ownerUserId = ownerUserId,
        description = description,
        thumbnailUrl = thumbnailUrl,
        durationSeconds = durationSeconds,
        category = category,
        tags = tags,
        viewCount = viewCount,
        likeCount = likeCount,
        commentCount = commentCount,
        priceCents = priceCents,
        accessMode = accessMode,
        createdAt = createdAt,
        publishedAt = publishedAt,
    )
}

internal fun GalleryCategoryDto.toDomain(): GalleryCategory = GalleryCategory(slug = slug, label = label)

internal fun GalleryListDto.toDomain(): GalleryPage = GalleryPage(
    videos = videos.mapNotNull { it.toDomainOrNull() },
    categories = categories.map { it.toDomain() },
    cursor = cursor,
)

internal fun GallerySearchDto.toDomain(): GalleryPage = GalleryPage(
    videos = videos.mapNotNull { it.toDomainOrNull() },
    categories = emptyList(),
    cursor = cursor,
)
