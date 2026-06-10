package com.testlogon.android.data.gallery

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * AND-201 — wire DTOs for the video gallery browse/search/categories surfaces.
 *
 * Verified against reference/src/api/endpoints/gallery.ts and OpenAPI `GET /ui/videos/gallery`
 * (-> GalleryListOut), `/search` (-> GallerySearchOut), `/categories` (-> CategoriesOut), item schema
 * `GalleryVideoItem`. Required item fields: video_id, title, owner_user_id; everything else is
 * optional/defaulted. created_at/published_at are Unix epoch integers (seconds). The next-page field is
 * `cursor` (null/absent on the last page) — NOT `next_cursor` (that belongs to the messaging gallery).
 */

@JsonClass(generateAdapter = true)
data class GalleryListDto(
    @Json(name = "videos") val videos: List<GalleryVideoItemDto> = emptyList(),
    @Json(name = "categories") val categories: List<GalleryCategoryDto> = emptyList(),
    @Json(name = "cursor") val cursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class GallerySearchDto(
    @Json(name = "videos") val videos: List<GalleryVideoItemDto> = emptyList(),
    @Json(name = "cursor") val cursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class CategoriesDto(
    @Json(name = "categories") val categories: List<GalleryCategoryDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class GalleryCategoryDto(
    @Json(name = "slug") val slug: String,
    @Json(name = "label") val label: String = "",
)

@JsonClass(generateAdapter = true)
data class GalleryVideoItemDto(
    @Json(name = "video_id") val videoId: String,
    @Json(name = "title") val title: String,
    @Json(name = "owner_user_id") val ownerUserId: String,
    @Json(name = "description") val description: String? = null,
    @Json(name = "thumbnail_url") val thumbnailUrl: String? = null,
    @Json(name = "duration_seconds") val durationSeconds: Double? = null,
    @Json(name = "category") val category: String? = null,
    @Json(name = "tags") val tags: List<String> = emptyList(),
    @Json(name = "view_count") val viewCount: Int = 0,
    @Json(name = "like_count") val likeCount: Int = 0,
    @Json(name = "comment_count") val commentCount: Int = 0,
    @Json(name = "price_cents") val priceCents: Int? = null,
    @Json(name = "access_mode") val accessMode: String? = null,
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "published_at") val publishedAt: Long? = null,
)
