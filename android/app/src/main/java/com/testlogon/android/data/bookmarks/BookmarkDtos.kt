package com.testlogon.android.data.bookmarks

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * AND-092 — wire DTOs for the Saved / bookmarks surface.
 *
 * Verified contract (reference/src/api/endpoints/bookmarks.ts: BookmarkItem / BookmarkListResponse,
 * and OpenAPI /ui/bookmarks):
 *  - the list envelope key is "bookmarks" (NOT "items"); it also carries "total_count".
 *  - pagination key is nullable "next_cursor".
 *  - an item is keyed by the composite (content_type, content_id); there is NO single "id".
 *  - the saved timestamp is "created_at" (an ISO-8601 STRING here, NOT "saved_at", NOT epoch).
 *  - display metadata is nested under "content_preview" (NOT flat title/thumbnail_url).
 *  - DELETE returns 200 with a JSON body { "ok": true } (NOT 204); POST returns 201 with a body.
 */
@JsonClass(generateAdapter = true)
data class BookmarkPageDto(
    @Json(name = "bookmarks") val bookmarks: List<BookmarkDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
    @Json(name = "total_count") val totalCount: Int = 0,
)

@JsonClass(generateAdapter = true)
data class BookmarkDto(
    @Json(name = "content_type") val contentType: String = "",
    @Json(name = "content_id") val contentId: String,
    @Json(name = "collection_id") val collectionId: String? = null,
    @Json(name = "created_at") val createdAt: String? = null,
    @Json(name = "content_preview") val contentPreview: ContentPreviewDto? = null,
)

@JsonClass(generateAdapter = true)
data class ContentPreviewDto(
    @Json(name = "author_id") val authorId: String? = null,
    @Json(name = "author_display_name") val authorDisplayName: String? = null,
    @Json(name = "body_snippet") val bodySnippet: String? = null,
    @Json(name = "image_url") val imageUrl: String? = null,
    @Json(name = "like_count") val likeCount: Int? = null,
)

@JsonClass(generateAdapter = true)
data class CreateBookmarkDto(
    @Json(name = "content_type") val contentType: String? = null,
    @Json(name = "content_id") val contentId: String,
    @Json(name = "collection_id") val collectionId: String? = null,
)

/** Both DELETE (200) and POST (201) return at least `{ "ok": true }`. */
@JsonClass(generateAdapter = true)
data class OkDto(
    @Json(name = "ok") val ok: Boolean = true,
)
