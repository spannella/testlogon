package com.testlogon.android.feature.feed

import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.LinkAnnotation
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.withLink

/**
 * AND-099 — pure body-text helpers. URL detection is an Android-only enhancement (the web client does
 * NOT linkify @mentions/#hashtags; hashtags live in a separate tags[] field). Detection is a pure
 * function so it is JVM-unit-testable with no Compose/Android dependency.
 *
 * NOTE on KDoc: never write the comment-terminator sequence inside a comment.
 */

/** A detected URL span in a body string: [start, end) over the original text. */
data class UrlSpan(val start: Int, val end: Int, val url: String)

private val URL_REGEX = Regex("""https?://[^\s<>"']+""")
// Trailing punctuation that is almost never part of the intended URL.
private const val TRAILING_PUNCT = ").,;:!?]}>\"'"

/**
 * Finds http(s) URL spans, excluding trailing punctuation (so "see https://x.com." links "https://x.com").
 * Returns spans in source order; plain text yields an empty list.
 */
fun detectUrls(text: String): List<UrlSpan> {
    if (text.isBlank()) return emptyList()
    return URL_REGEX.findAll(text).mapNotNull { m ->
        var end = m.range.last + 1
        while (end > m.range.first && text[end - 1] in TRAILING_PUNCT) end--
        val url = text.substring(m.range.first, end)
        if (url.length <= "https://".length) null else UrlSpan(m.range.first, end, url)
    }.toList()
}

/**
 * Builds an [AnnotatedString] for [text] with each detected URL wrapped in a clickable [LinkAnnotation]
 * that invokes [onLinkClick] with the raw URL string (scheme validation is the consumer's duty).
 */
fun buildPostAnnotatedString(
    text: String,
    linkColor: androidx.compose.ui.graphics.Color,
    onLinkClick: (String) -> Unit,
): AnnotatedString {
    val spans = detectUrls(text)
    if (spans.isEmpty()) return AnnotatedString(text)
    return buildAnnotatedString {
        var cursor = 0
        for (span in spans) {
            if (span.start > cursor) append(text.substring(cursor, span.start))
            withLink(
                LinkAnnotation.Clickable(
                    tag = "url",
                    styles = androidx.compose.ui.text.TextLinkStyles(
                        style = SpanStyle(color = linkColor),
                    ),
                    linkInteractionListener = { onLinkClick(span.url) },
                ),
            ) {
                append(text.substring(span.start, span.end))
            }
            cursor = span.end
        }
        if (cursor < text.length) append(text.substring(cursor))
    }
}
