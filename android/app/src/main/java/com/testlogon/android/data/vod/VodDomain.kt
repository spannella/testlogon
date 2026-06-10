package com.testlogon.android.data.vod

import kotlin.math.roundToInt

/**
 * AND-191 — domain models + DTO mappers for the VOD catalog. Pure (no Android types), JVM-testable.
 *
 * Both catalog envelopes (public VideoListOut and gallery GalleryListOut/Search) collapse onto the same
 * [VodSummary]/[VodPage] so the UI and PagingSource are envelope-agnostic. VOD detail reuses the
 * videos [com.testlogon.android.data.videos.VideoDetail] model (same VideoDetailOut contract).
 */

/** A tile in the VOD catalog grid. `durationSec` is rounded for the H:MM badge. */
data class VodSummary(
    val id: String,
    val title: String,
    val thumbnailUrl: String?,
    val durationSec: Int?,
)

/** One cursor-paged catalog page. `cursor` is null/absent on the terminal page. */
data class VodPage(
    val items: List<VodSummary>,
    val cursor: String?,
)

/** A browsable VOD category ({ slug, label }). */
data class VodCategory(
    val slug: String,
    val label: String,
)

// ---- Mappers ----

fun VideoListItemDto.toSummary(): VodSummary = VodSummary(
    id = videoId,
    title = title,
    thumbnailUrl = thumbnailUrl?.takeIf { it.isNotBlank() },
    durationSec = durationSeconds?.takeIf { it > 0 }?.roundToInt(),
)

fun GalleryVideoItemDto.toSummary(): VodSummary = VodSummary(
    id = videoId,
    title = title,
    thumbnailUrl = thumbnailUrl?.takeIf { it.isNotBlank() },
    durationSec = durationSeconds?.takeIf { it > 0 }?.roundToInt(),
)

fun GalleryCategoryDto.toDomain(): VodCategory = VodCategory(slug = slug, label = label)

fun VideoListResponseDto.toDomain(): VodPage = VodPage(
    items = items.asSequence().filter { it.videoId.isNotBlank() }.map { it.toSummary() }.toList(),
    cursor = cursor,
)

fun GalleryListResponseDto.toDomain(): VodPage = VodPage(
    items = videos.asSequence().filter { it.videoId.isNotBlank() }.map { it.toSummary() }.toList(),
    cursor = cursor,
)

fun GallerySearchResponseDto.toDomain(): VodPage = VodPage(
    items = videos.asSequence().filter { it.videoId.isNotBlank() }.map { it.toSummary() }.toList(),
    cursor = cursor,
)
