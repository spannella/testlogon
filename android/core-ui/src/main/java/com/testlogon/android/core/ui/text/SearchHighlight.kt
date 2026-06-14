package com.testlogon.android.core.ui.text

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.withStyle
import java.text.Normalizer

/**
 * AND-151 / AND-152 — shared, pure search-highlight logic.
 *
 * Authored for in-conversation search (AND-151) and reused verbatim by global search (AND-152).
 * Matching is case-insensitive, LITERAL (not regex — no ReDoS from user input), and Unicode-NFC
 * normalized to align with backend behaviour. The range finder is a pure function (no Android types)
 * and is JVM-unit-tested; [highlightMatches] builds a Compose [AnnotatedString] (also a JVM type).
 */

/**
 * Returns every non-overlapping occurrence of [query] in [body] as a [start, end) range indexing the
 * ORIGINAL [body] (so callers can highlight/scroll against the raw text). Case-insensitive, literal,
 * NFC. Returns empty when [query] is blank or there is no match.
 *
 * NFC offsets are only trusted when normalization preserves length (the common case for already-
 * composed text); otherwise we fall back to scanning the raw text so offsets never go out of bounds.
 */
fun searchMatchRanges(body: String, query: String): List<IntRange> {
    val q = query.trim()
    if (q.isEmpty() || body.isEmpty()) return emptyList()

    val nfcBody = Normalizer.normalize(body, Normalizer.Form.NFC)
    val haystack = if (nfcBody.length == body.length) nfcBody else body
    val nfcNeedle = Normalizer.normalize(q, Normalizer.Form.NFC)
    val needle = if (nfcNeedle.length == q.length) nfcNeedle else q

    val ranges = ArrayList<IntRange>()
    var from = 0
    while (from <= haystack.length - needle.length) {
        val idx = haystack.indexOf(needle, startIndex = from, ignoreCase = true)
        if (idx < 0) break
        ranges += idx until (idx + needle.length)
        from = idx + needle.length
    }
    return ranges
}

/**
 * Builds an [AnnotatedString] for [body] with every occurrence of [query] highlighted. The occurrence
 * at [activeOccurrence] (when non-null and in range) gets the stronger [activeBg] + bold weight so the
 * active match is distinguishable WITHOUT relying on color alone (AA / color-blind safe); all other
 * matches use [matchBg]. A blank query or no match returns [body] unchanged.
 *
 * @param activeOccurrence index (into this message's occurrence list) of the active match, or null.
 */
fun highlightMatches(
    body: String,
    query: String,
    activeOccurrence: Int? = null,
    matchBg: Color = Color.Unspecified,
    activeBg: Color = Color.Unspecified,
): AnnotatedString {
    val ranges = searchMatchRanges(body, query)
    if (ranges.isEmpty()) return AnnotatedString(body)

    return buildAnnotatedString {
        var cursor = 0
        ranges.forEachIndexed { occurrence, range ->
            val start = range.first
            val end = range.last + 1
            if (start > cursor) append(body.substring(cursor, start))
            val isActive = activeOccurrence != null && occurrence == activeOccurrence
            withStyle(
                SpanStyle(
                    background = if (isActive) activeBg else matchBg,
                    fontWeight = if (isActive) FontWeight.Bold else null,
                ),
            ) {
                append(body.substring(start, end))
            }
            cursor = end
        }
        if (cursor < body.length) append(body.substring(cursor))
    }
}
