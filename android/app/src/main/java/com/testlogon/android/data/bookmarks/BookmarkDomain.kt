package com.testlogon.android.data.bookmarks

/**
 * AND-092 — domain model + mapping for saved bookmarks (framework-free, JVM-unit-test safe).
 *
 * A bookmark is identified by the composite (contentType, contentId); [key] is the stable
 * "type/id" string used for Paging keys, optimistic-removal sets, and the DELETE path. Display
 * labels are derived from the nested content_preview, degrading gracefully when it is absent.
 *
 * The saved timestamp arrives as an ISO-8601 STRING (server "created_at"); it is kept as the raw
 * string in the domain so no java.time is needed at this layer (formatting is a UI concern, and the
 * string is tolerated/dropped if unparseable downstream).
 */
data class Bookmark(
    val contentType: String,
    val contentId: String,
    val collectionId: String?,
    val title: String?,
    val subtitle: String?,
    val thumbnailUrl: String?,
    /** Raw ISO-8601 saved timestamp, or null when absent. */
    val savedAtIso: String?,
) {
    /** Stable composite key "contentType/contentId". */
    val key: String get() = "$contentType/$contentId"
}

/** One page of bookmarks + the opaque cursor for the next page (null = terminal). */
data class BookmarkPage(
    val items: List<Bookmark>,
    val nextCursor: String?,
    val totalCount: Int,
)

internal fun BookmarkDto.toDomain(): Bookmark {
    val preview = contentPreview
    return Bookmark(
        contentType = contentType,
        contentId = contentId,
        collectionId = collectionId,
        title = preview?.authorDisplayName?.takeIf { it.isNotBlank() }
            ?: preview?.authorId?.takeIf { it.isNotBlank() },
        subtitle = preview?.bodySnippet?.takeIf { it.isNotBlank() },
        thumbnailUrl = preview?.imageUrl?.takeIf { it.isNotBlank() },
        savedAtIso = createdAt?.takeIf { it.isNotBlank() },
    )
}
