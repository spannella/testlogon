package com.testlogon.android.feature.messaging

/**
 * AND-135 — pure, JVM-testable splitter for inline custom-emoji rendering.
 *
 * Matches the web reference (`src/utils/emoji.ts`): the custom-shortcode regex is
 * `:([a-z0-9_]{2,32}):` (case-insensitive). A shortcode is rendered inline as an image only when it
 * is present in the catalog map; unknown shortcodes, single-char tokens, and tokens longer than 32
 * chars are left as literal text.
 */

/** A piece of a message body after splitting: literal text, or a resolved custom-emoji image. */
sealed interface EmojiSpan {
    data class Literal(val text: String) : EmojiSpan

    /** A known shortcode (without colons) mapped to its [imageUrl]. */
    data class Emoji(val shortcode: String, val imageUrl: String) : EmojiSpan
}

private val CUSTOM_SHORTCODE_RE = Regex("(?i):([a-z0-9_]{2,32}):")

/**
 * Splits [text] into literal + emoji spans. [catalog] maps a shortcode (without colons) to its image
 * url; an unknown shortcode is emitted as a [EmojiSpan.Literal] (`:shortcode:`). Adjacent tokens both
 * resolve; malformed colons are untouched. Pure — safe for unit tests.
 */
fun splitCustomEmoji(text: String, catalog: Map<String, String>): List<EmojiSpan> {
    if (text.isEmpty()) return emptyList()
    val spans = mutableListOf<EmojiSpan>()
    var cursor = 0
    for (match in CUSTOM_SHORTCODE_RE.findAll(text)) {
        if (match.range.first > cursor) {
            spans += EmojiSpan.Literal(text.substring(cursor, match.range.first))
        }
        val shortcode = match.groupValues[1]
        val url = catalog[shortcode] ?: catalog[shortcode.lowercase()]
        spans += if (url != null) {
            EmojiSpan.Emoji(shortcode, url)
        } else {
            // Unknown shortcode -> keep the literal token (including colons).
            EmojiSpan.Literal(match.value)
        }
        cursor = match.range.last + 1
    }
    if (cursor < text.length) spans += EmojiSpan.Literal(text.substring(cursor))
    return spans
}

/** True if [text] contains at least one resolvable custom-emoji shortcode in [catalog]. */
fun hasCustomEmoji(text: String, catalog: Map<String, String>): Boolean =
    CUSTOM_SHORTCODE_RE.findAll(text).any { catalog.containsKey(it.groupValues[1]) }
