package com.testlogon.android.feature.search

/**
 * Pure, side-effect-free filter + ranking for the global search list. Extracted from the ViewModel so
 * it can be unit-tested in isolation (no Android, no coroutines).
 *
 * Matching is a case-insensitive substring over an item's [SearchItem.title], [SearchItem.subtitle],
 * and [SearchItem.keywords]. A blank query matches nothing (the ViewModel shows recents instead).
 *
 * Ranking (lower [score] = better) is a small fuzzy score computed per item:
 *   0  exact title match
 *   1  title starts with the query
 *   2  a title WORD starts with the query
 *   3  title contains the query (mid-word)
 *   4  a keyword/subtitle match only
 * Ties break by kind order (Symbols, then Destinations, then Actions) and then by title A→Z, so the
 * output is deterministic across identical inputs.
 */
object SearchMatching {

    /** Result of scoring one item against a query; only produced for matches. */
    data class Scored(val item: SearchItem, val score: Int)

    /**
     * Filter [items] by [rawQuery] and return the surviving items grouped by kind (in kind order), each
     * group internally ranked best-first. A blank query yields an empty list.
     */
    fun filterGrouped(items: List<SearchItem>, rawQuery: String): List<SearchGroup> {
        val ranked = rank(items, rawQuery)
        return SearchResultKind.entries
            .map { kind -> kind to ranked.filter { it.kind == kind } }
            .filter { (_, its) -> its.isNotEmpty() }
            .map { (kind, its) -> SearchGroup(kind, its) }
    }

    /** Filter + rank [items] by [rawQuery] into a single best-first list (kind order breaks score ties). */
    fun rank(items: List<SearchItem>, rawQuery: String): List<SearchItem> {
        val q = rawQuery.trim().lowercase()
        if (q.isEmpty()) return emptyList()
        return items
            .mapNotNull { item -> score(item, q)?.let { Scored(item, it) } }
            .sortedWith(
                compareBy(
                    { it.score },
                    { it.item.kind.ordinal },
                    { it.item.title.lowercase() },
                ),
            )
            .map { it.item }
    }

    /** Score a single item against an already-normalised (trimmed, lowercased) query, or null if no match. */
    fun score(item: SearchItem, normalizedQuery: String): Int? {
        val q = normalizedQuery
        if (q.isEmpty()) return null
        val title = item.title.lowercase()
        return when {
            title == q -> 0
            title.startsWith(q) -> 1
            wordStartsWith(title, q) -> 2
            title.contains(q) -> 3
            item.subtitle?.lowercase()?.contains(q) == true -> 4
            item.keywords.any { it.lowercase().contains(q) } -> 4
            else -> null
        }
    }

    /** True when any whitespace-delimited word in [text] starts with [prefix]. */
    private fun wordStartsWith(text: String, prefix: String): Boolean =
        text.split(' ', '/', '-').any { it.startsWith(prefix) }
}
