package com.testlogon.android.data.vod

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * AND-191 — wire DTOs for the VOD catalog.
 *
 * Field shapes verified against OpenAPI (VideoListOut / GalleryListOut / GallerySearchOut /
 * GalleryVideoItem / CategoriesOut) and reference/src/api/endpoints/gallery.ts. The public catalog
 * uses the VideoListOut envelope ({ items, cursor? }); the gallery browse/search use the
 * { videos, categories?, cursor? } envelope with the richer GalleryVideoItem. Pagination field is
 * `cursor` (NOT next_cursor); `duration_seconds` is a NUMBER (float); ids are `video_id`.
 */

/** VideoListOut envelope (public catalog). Reuses the verified VideoListItem row shape. */
@JsonClass(generateAdapter = true)
data class VideoListResponseDto(
    @Json(name = "items") val items: List<VideoListItemDto> = emptyList(),
    @Json(name = "cursor") val cursor: String? = null,
)

/** VideoListItem — public-catalog row. */
@JsonClass(generateAdapter = true)
data class VideoListItemDto(
    @Json(name = "video_id") val videoId: String,
    @Json(name = "title") val title: String = "",
    @Json(name = "thumbnail_url") val thumbnailUrl: String? = null,
    @Json(name = "duration_seconds") val durationSeconds: Double? = null,
)

/** GalleryListOut = { videos: GalleryVideoItem[], categories: object[], cursor? }. */
@JsonClass(generateAdapter = true)
data class GalleryListResponseDto(
    @Json(name = "videos") val videos: List<GalleryVideoItemDto> = emptyList(),
    @Json(name = "categories") val categories: List<GalleryCategoryDto> = emptyList(),
    @Json(name = "cursor") val cursor: String? = null,
)

/** GallerySearchOut = { videos: GalleryVideoItem[], cursor? }. */
@JsonClass(generateAdapter = true)
data class GallerySearchResponseDto(
    @Json(name = "videos") val videos: List<GalleryVideoItemDto> = emptyList(),
    @Json(name = "cursor") val cursor: String? = null,
)

/** GalleryVideoItem — gallery row (richer than VideoListItem). */
@JsonClass(generateAdapter = true)
data class GalleryVideoItemDto(
    @Json(name = "video_id") val videoId: String,
    @Json(name = "title") val title: String = "",
    @Json(name = "description") val description: String? = null,
    @Json(name = "thumbnail_url") val thumbnailUrl: String? = null,
    @Json(name = "duration_seconds") val durationSeconds: Double? = null,
    @Json(name = "category") val category: String? = null,
    @Json(name = "view_count") val viewCount: Int? = null,
    @Json(name = "like_count") val likeCount: Int? = null,
)

/** GalleryCategory = { slug, label }. */
@JsonClass(generateAdapter = true)
data class GalleryCategoryDto(
    @Json(name = "slug") val slug: String = "",
    @Json(name = "label") val label: String = "",
)

/** CategoriesOut = { categories: GalleryCategory[] }. */
@JsonClass(generateAdapter = true)
data class CategoriesResponseDto(
    @Json(name = "categories") val categories: List<GalleryCategoryDto> = emptyList(),
)
