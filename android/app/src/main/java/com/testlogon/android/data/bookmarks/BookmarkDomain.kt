package com.testlogon.android.data.bookmarks

/**
 * AND-092 — domain model + mapping for saved bookmarks (framework-free, JVM-unit-test safe).
 *
 * A bookmark is identified by the composite (contentType, contentId); [key] is the stable
 * "type/id" string used for Paging keys, optimistic-removal sets, and the DELETE path. Display
 * labels are derived from the nested content_preview, degrading gracefully when it is absent, and
 * are chosen per content_type (post vs video — P0-consumer/bookmarks).
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

    val isVideo: Boolean get() = contentType.equals(CONTENT_TYPE_VIDEO, ignoreCase = true)

    companion object {
        const val CONTENT_TYPE_POST = "post"
        const val CONTENT_TYPE_VIDEO = "video"
    }
}

/** One page of bookmarks + the opaque cursor for the next page (null = terminal). */
data class BookmarkPage(
    val items: List<Bookmark>,
    val nextCursor: String?,
    val totalCount: Int,
)

/**
 * A user-defined bookmark collection (P0-consumer/bookmarks). [id] "default" is the implicit
 * "all / uncategorised" bucket the backend assigns when no collection is chosen.
 */
data class BookmarkCollection(
    val id: String,
    val name: String,
    val itemCount: Int,
    val createdAtIso: String?,
) {
    companion object {
        const val DEFAULT_ID = "default"
    }
}

internal fun BookmarkDto.toDomain(): Bookmark {
    val preview = contentPreview
    val isVideo = contentType.equals(Bookmark.CONTENT_TYPE_VIDEO, ignoreCase = true)
    return if (isVideo) {
        Bookmark(
            contentType = contentType,
            contentId = contentId,
            collectionId = collectionId,
            title = preview?.title?.takeIf { it.isNotBlank() } ?: contentId,
            subtitle = preview?.creatorDisplayName?.takeIf { it.isNotBlank() }
                ?: preview?.creatorId?.takeIf { it.isNotBlank() },
            thumbnailUrl = preview?.thumbnailUrl?.takeIf { it.isNotBlank() },
            savedAtIso = createdAt?.takeIf { it.isNotBlank() },
        )
    } else {
        Bookmark(
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
}

internal fun CollectionDto.toDomain(): BookmarkCollection = BookmarkCollection(
    id = collectionId,
    name = name,
    itemCount = itemCount,
    createdAtIso = createdAt?.takeIf { it.isNotBlank() },
)
