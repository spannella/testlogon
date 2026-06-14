package com.testlogon.android.feature.files.presentation

/**
 * AND-332 - pure, JVM-testable helpers for the path-based folder navigation.
 *
 * Nodes are addressed by a path String; there are NO node ids. The canonical browse path always starts
 * and is anchored at the root, written as a single forward slash. Breadcrumbs are derived by splitting
 * the path on the slash separator. Kept free of Android types so the navigation math is unit-testable.
 */

/** One breadcrumb segment: its display [name] and the absolute [path] it navigates to when tapped. */
data class Breadcrumb(val name: String, val path: String)

object FilePath {

    /** The browse root path. */
    const val ROOT: String = "/"

    private const val SEPARATOR: Char = '/'

    /** Collapses repeated separators and trailing separators to a single canonical absolute path. */
    fun normalize(path: String): String {
        val segments = segments(path)
        return if (segments.isEmpty()) ROOT else ROOT + segments.joinToString(separator = "$SEPARATOR")
    }

    /** The non-empty path segments (root yields an empty list). */
    fun segments(path: String): List<String> =
        path.split(SEPARATOR).filter { it.isNotEmpty() }

    /** True when [path] is the browse root. */
    fun isRoot(path: String): Boolean = segments(path).isEmpty()

    /** Appends [name] (a single child segment) to [parent], returning the canonical child path. */
    fun child(parent: String, name: String): String {
        val childSegment = name.trim(SEPARATOR)
        if (childSegment.isEmpty()) return normalize(parent)
        return normalize(segments(parent) + childSegment)
    }

    /** The parent of [path] (root is its own parent). */
    fun parent(path: String): String {
        val segments = segments(path)
        return if (segments.isEmpty()) ROOT else normalize(segments.dropLast(1))
    }

    /**
     * The path truncated to the breadcrumb at [index] (0-based, into [breadcrumbs] - the root crumb is
     * index 0). Out-of-range indices clamp to the root.
     */
    fun truncateTo(path: String, index: Int): String {
        if (index <= 0) return ROOT
        val segments = segments(path)
        // breadcrumb index 0 == root, index N == the Nth path segment.
        return normalize(segments.take(index.coerceAtMost(segments.size)))
    }

    /**
     * Derives the breadcrumb trail for [path]: always a leading root crumb, then one crumb per segment
     * carrying the cumulative path. [rootName] is the localized label for the root crumb.
     */
    fun breadcrumbs(path: String, rootName: String): List<Breadcrumb> {
        val crumbs = mutableListOf(Breadcrumb(name = rootName, path = ROOT))
        var accumulated = ""
        for (segment in segments(path)) {
            accumulated = if (accumulated.isEmpty()) segment else "$accumulated$SEPARATOR$segment"
            crumbs += Breadcrumb(name = segment, path = normalize(accumulated))
        }
        return crumbs
    }

    private fun normalize(segments: List<String>): String =
        if (segments.isEmpty()) ROOT else ROOT + segments.joinToString(separator = "$SEPARATOR")
}
