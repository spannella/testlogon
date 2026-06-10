package com.testlogon.android.data.discover

/**
 * AND-185 — pure domain models + mapper for global multi-entity search.
 *
 * The backend returns a keyed object of (up to) nine sections, each with a uniform item shape. The
 * domain model mirrors that: one [SearchCategory] per non-empty section, in a fixed display order,
 * each holding uniform [SearchResult] rows. Everything here is framework-free and JVM-testable.
 */

/** The nine real entity types + an OTHER forward-compat fallback for an unrecognized server `type`. */
enum class SearchEntityType(val wire: String) {
    USER("user"),
    POST("post"),
    CATALOG("catalog"),
    FILE("file"),
    MESSAGE("message"),
    TICKET("ticket"),
    CONTACT("contact"),
    VIDEO("video"),
    CALENDAR("calendar"),
    OTHER("");

    companion object {
        /** Maps a wire `type` string to its enum, defaulting unknown values to [OTHER]. */
        fun fromWire(value: String?): SearchEntityType =
            entries.firstOrNull { it != OTHER && it.wire == value?.trim()?.lowercase() } ?: OTHER
    }
}

/** One uniform search result row (every entity type shares this shape). */
data class SearchResult(
    val id: String,
    val type: SearchEntityType,
    val title: String,
    /** Web suppresses snippet when it equals title; null/blank => no subtitle. */
    val snippet: String?,
    val thumbnailUrl: String?,
    /** Server-provided deep-link target; nav resolves this to an in-app destination. */
    val url: String,
)

/** One per-entity section (drives a result tab). [count] is the rendered item count. */
data class SearchCategory(
    val type: SearchEntityType,
    val items: List<SearchResult>,
    /** Backend's estimate of the full count; >= items.size when [hasMore]. */
    val totalEstimate: Int,
    val hasMore: Boolean,
) {
    val count: Int get() = items.size
}

/** The full multi-entity search payload. */
data class SearchResults(
    val query: String,
    val categories: List<SearchCategory>,
) {
    /** "All"-tab total == sum of rendered item counts across sections (web parity). */
    val totalCount: Int get() = categories.sumOf { it.count }
    val isEmpty: Boolean get() = categories.all { it.items.isEmpty() }
}

/** AND-185 — pure DTO -> domain mapper, isolated for unit testing. */
object SearchMapper {

    /** Fixed display order for the result tabs (matches the web SEARCH_TABS ordering). */
    private val SECTION_ORDER: List<SearchEntityType> = listOf(
        SearchEntityType.USER,
        SearchEntityType.POST,
        SearchEntityType.VIDEO,
        SearchEntityType.CATALOG,
        SearchEntityType.FILE,
        SearchEntityType.MESSAGE,
        SearchEntityType.TICKET,
        SearchEntityType.CONTACT,
        SearchEntityType.CALENDAR,
    )

    fun toDomain(dto: SearchResponseDto): SearchResults {
        val r = dto.results
        val sections: List<Pair<SearchEntityType, SearchSectionDto?>> = listOf(
            SearchEntityType.USER to r.users,
            SearchEntityType.POST to r.posts,
            SearchEntityType.VIDEO to r.videos,
            SearchEntityType.CATALOG to r.catalog,
            SearchEntityType.FILE to r.files,
            SearchEntityType.MESSAGE to r.messages,
            SearchEntityType.TICKET to r.tickets,
            SearchEntityType.CONTACT to r.contacts,
            SearchEntityType.CALENDAR to r.calendar,
        )
        val byType = sections.toMap()
        val categories = SECTION_ORDER.mapNotNull { type ->
            val section = byType[type] ?: return@mapNotNull null
            val items = section.items.mapNotNull { it.toResult() }
            if (items.isEmpty()) null
            else SearchCategory(
                type = type,
                items = items,
                totalEstimate = section.totalEstimate.coerceAtLeast(items.size),
                hasMore = section.hasMore,
            )
        }
        return SearchResults(query = dto.query, categories = categories)
    }

    private fun SearchItemDto.toResult(): SearchResult? {
        if (id.isBlank()) return null
        val cleanSnippet = snippet?.takeIf { it.isNotBlank() && it != title }
        return SearchResult(
            id = id,
            type = SearchEntityType.fromWire(type),
            title = title,
            snippet = cleanSnippet,
            thumbnailUrl = thumbnailUrl?.takeIf { it.isNotBlank() },
            url = url,
        )
    }
}
