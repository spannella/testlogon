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
 *
 * P0-consumer/bookmarks: content_preview is polymorphic by content_type — a post preview carries
 * author/body/image fields; a video preview carries video_id/title/thumbnail_url/creator/duration/view
 * fields. Both variants are folded into one [ContentPreviewDto] (all-nullable) and disambiguated by
 * content_type in the domain mapper.
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
    // --- post preview ---
    @Json(name = "author_id") val authorId: String? = null,
    @Json(name = "author_display_name") val authorDisplayName: String? = null,
    @Json(name = "body_snippet") val bodySnippet: String? = null,
    @Json(name = "image_url") val imageUrl: String? = null,
    @Json(name = "like_count") val likeCount: Int? = null,
    // --- video preview (P0-consumer/bookmarks) ---
    @Json(name = "video_id") val videoId: String? = null,
    @Json(name = "title") val title: String? = null,
    @Json(name = "thumbnail_url") val thumbnailUrl: String? = null,
    @Json(name = "creator_id") val creatorId: String? = null,
    @Json(name = "creator_display_name") val creatorDisplayName: String? = null,
    @Json(name = "duration_seconds") val durationSeconds: Double? = null,
    @Json(name = "view_count") val viewCount: Int? = null,
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

/**
 * AND-176 — `GET /ui/bookmarks/status?ids=` response: a map of "type:id" -> saved boolean.
 * Verified: OpenAPI `bookmark_status_ui_bookmarks_status_get`; reference bookmarks.ts getBookmarkStatus.
 * The server ONLY honours composite "type:id" keys (bare ids are skipped) and echoes them back the same.
 */
@JsonClass(generateAdapter = true)
data class BookmarkStatusDto(
    @Json(name = "statuses") val statuses: Map<String, Boolean> = emptyMap(),
)

// ── Bookmark collections (P0-consumer/bookmarks) ──────────────────────────────

/** GET /ui/bookmark-collections envelope. */
@JsonClass(generateAdapter = true)
data class CollectionListDto(
    @Json(name = "collections") val collections: List<CollectionDto> = emptyList(),
)

/** A single collection; POST/GET return the same shape (POST also carries an `ok`). */
@JsonClass(generateAdapter = true)
data class CollectionDto(
    @Json(name = "collection_id") val collectionId: String = "",
    @Json(name = "name") val name: String = "",
    @Json(name = "item_count") val itemCount: Int = 0,
    @Json(name = "created_at") val createdAt: String? = null,
)

/** Body for POST /ui/bookmark-collections and PATCH /ui/bookmark-collections/{id}. */
@JsonClass(generateAdapter = true)
data class CollectionNameBody(
    @Json(name = "name") val name: String,
)

/** Body for PATCH /ui/bookmarks/{type}/{id} — moves a bookmark to another collection. */
@JsonClass(generateAdapter = true)
data class MoveBookmarkBody(
    @Json(name = "collection_id") val collectionId: String,
)
