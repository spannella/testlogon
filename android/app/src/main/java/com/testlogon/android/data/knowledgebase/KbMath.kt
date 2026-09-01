package com.testlogon.android.data.knowledgebase

import com.testlogon.android.core.model.kb.KbArticleSummary
import com.testlogon.android.core.network.kb.KbConstants

/**
 * KB-AND-1 - PURE, framework-free logic for the Knowledge Base surface. No Android / java.time types, so every
 * function here is JVM-unit-testable (mirrors the PurchaseHistoryMath idiom).
 *
 * Responsibilities:
 *  - htmlToPlainText: turn raw server body_html into a Compose-safe plain-text body (no WebView / no HTML
 *    renderer). Degrade, never throw: unknown / malformed markup passes through as text.
 *  - snippet: build a bounded excerpt for a list row (prefer the server excerpt, else derive from the body).
 *  - client-side search filter + relevance ranking (used when the caller wants to filter a already-loaded
 *    page locally, and by the search screen's query pre-validation).
 *  - status / helpfulness formatting helpers.
 *
 * Degrade-on-404: the repository maps a 404 (KB flag off) to an EMPTY list; these helpers all treat empty /
 * null inputs as "nothing to show" rather than throwing, so the empty state renders cleanly.
 */
object KbMath {

    /** Max characters in a derived list snippet before an ellipsis is appended. */
    const val SNIPPET_MAX_LENGTH: Int = 160

    /** The minimum trimmed query length the search screen will actually dispatch (shorter -> no-op). */
    const val MIN_QUERY_LENGTH: Int = 2

    private val TAG_REGEX = Regex("<[^>]*>")
    private val WHITESPACE_REGEX = Regex("\\s+")

    /** A small map of the common named/numeric HTML entities the KB body uses; unknown entities pass through. */
    private val ENTITIES: Map<String, String> = mapOf(
        "&amp;" to "&",
        "&lt;" to "<",
        "&gt;" to ">",
        "&quot;" to "\"",
        "&#39;" to "'",
        "&apos;" to "'",
        "&nbsp;" to " ",
    )

    /**
     * Strips HTML tags from raw body_html and returns collapsed plain text. Block-level tags (</p>, <br>, <li>
     * ...) are converted to a single newline BEFORE tag removal so paragraphs don't run together; remaining
     * tags are dropped; a small entity table is decoded; runs of spaces/tabs collapse to one space while
     * paragraph newlines are preserved. Null / blank -> "". Never throws (malformed markup degrades to text).
     */
    fun htmlToPlainText(html: String?): String {
        val raw = html?.takeIf { it.isNotBlank() } ?: return ""
        // Normalise block boundaries to newlines so structure survives tag stripping.
        var s = raw
            .replace(Regex("(?i)<\\s*br\\s*/?>"), "\n")
            .replace(Regex("(?i)</\\s*(p|div|li|h[1-6]|tr|ul|ol|blockquote)\\s*>"), "\n")
            .replace(Regex("(?i)<\\s*li[^>]*>"), "\n• ")
        s = TAG_REGEX.replace(s, "")
        s = decodeEntities(s)
        // Collapse horizontal whitespace per line, drop empty lines, trim.
        val lines = s.split('\n')
            .map { WHITESPACE_REGEX.replace(it, " ").trim() }
            .filter { it.isNotEmpty() }
        return lines.joinToString("\n")
    }

    /** Decodes the known entity set; leaves unknown entities as-is (forward-compatible, never throws). */
    internal fun decodeEntities(text: String): String {
        var out = text
        for ((entity, replacement) in ENTITIES) {
            out = out.replace(entity, replacement)
        }
        return out
    }

    /**
     * A bounded one-line snippet for a list row. Prefers a non-blank server [excerpt]; otherwise derives one
     * from the plain-text [body]. The result is single-line (newlines -> spaces), trimmed, and truncated to
     * [SNIPPET_MAX_LENGTH] with an ellipsis on a word boundary. Empty inputs -> "".
     */
    fun snippet(excerpt: String?, body: String?, maxLength: Int = SNIPPET_MAX_LENGTH): String {
        val source = excerpt?.takeIf { it.isNotBlank() } ?: body.orEmpty()
        val flat = WHITESPACE_REGEX.replace(source.replace('\n', ' '), " ").trim()
        if (flat.length <= maxLength) return flat
        val cut = flat.substring(0, maxLength)
        val lastSpace = cut.lastIndexOf(' ')
        val base = if (lastSpace >= maxLength / 2) cut.substring(0, lastSpace) else cut
        return base.trimEnd().trimEnd('.', ',', ';', ':') + "…"
    }

    /** True when [query] is worth dispatching to the server search (trimmed length >= [MIN_QUERY_LENGTH]). */
    fun isSearchable(query: String?): Boolean =
        (query?.trim()?.length ?: 0) >= MIN_QUERY_LENGTH

    /** Human label for a raw article status token. Unknown / blank -> a Title-Cased fallback or "". */
    fun statusLabel(status: String?): String = when (status?.trim()?.lowercase()) {
        KbConstants.ArticleStatus.DRAFT -> "Draft"
        KbConstants.ArticleStatus.PUBLISHED -> "Published"
        KbConstants.ArticleStatus.EXPIRED -> "Expired"
        null, "" -> ""
        else -> status.trim().replaceFirstChar { it.uppercase() }
    }

    /**
     * Helpfulness ratio 0f..1f (helpful / (helpful + notHelpful)), or null when there are NO votes (so the UI
     * hides the meter rather than showing a misleading 0%). Negative inputs are clamped to 0.
     */
    fun helpfulnessRatio(helpful: Long, notHelpful: Long): Float? {
        val up = helpful.coerceAtLeast(0L)
        val down = notHelpful.coerceAtLeast(0L)
        val total = up + down
        if (total <= 0L) return null
        return up.toFloat() / total.toFloat()
    }

    /** Formats [helpfulnessRatio] as a whole-percent string ("83%"); null ratio -> "". */
    fun helpfulnessPercent(helpful: Long, notHelpful: Long): String {
        val ratio = helpfulnessRatio(helpful, notHelpful) ?: return ""
        return "${Math.round(ratio * 100f)}%"
    }

    /**
     * CLIENT-SIDE relevance filter + ranking over an already-loaded page (used to refine a loaded list without
     * a round-trip). Case-insensitive substring match over title + excerpt + tags. A blank query returns the
     * input unchanged (server order preserved). Ranking: title-prefix > title-contains > tag-match >
     * excerpt-contains; ties keep the incoming order (stable sort).
     */
    fun filterAndRank(items: List<KbArticleSummary>, query: String?): List<KbArticleSummary> {
        val q = query?.trim()?.lowercase().orEmpty()
        if (q.isEmpty()) return items
        return items
            .mapNotNull { item ->
                val score = relevanceScore(item, q)
                if (score <= 0) null else item to score
            }
            .sortedByDescending { it.second }
            .map { it.first }
    }

    /** Higher is more relevant; 0 means no match. Pure integer scoring so ties are deterministic. */
    internal fun relevanceScore(item: KbArticleSummary, lowerQuery: String): Int {
        if (lowerQuery.isEmpty()) return 0
        val title = item.title?.lowercase().orEmpty()
        val excerpt = item.excerpt?.lowercase().orEmpty()
        val tags = item.tags.map { it.lowercase() }
        var score = 0
        if (title.startsWith(lowerQuery)) score += 100
        if (title.contains(lowerQuery)) score += 40
        if (tags.any { it == lowerQuery }) score += 30
        if (tags.any { it.contains(lowerQuery) }) score += 15
        if (excerpt.contains(lowerQuery)) score += 10
        return score
    }
}
