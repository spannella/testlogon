package com.testlogon.android.feature.messaging

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-135 — inline custom-emoji shortcode splitter (regex :([a-z0-9_]{2,32}):). */
class EmojiTextTest {

    private val catalog = mapOf("partyparrot" to "https://e/pp.gif")

    @Test
    fun knownShortcode_becomesEmojiSpan() {
        val spans = splitCustomEmoji("hi :partyparrot:", catalog)
        assertEquals(EmojiSpan.Literal("hi "), spans[0])
        assertEquals(EmojiSpan.Emoji("partyparrot", "https://e/pp.gif"), spans[1])
    }

    @Test
    fun unknownShortcode_staysLiteral() {
        val spans = splitCustomEmoji(":unknown:", catalog)
        assertEquals(listOf(EmojiSpan.Literal(":unknown:")), spans)
    }

    @Test
    fun singleCharAndOver32_doNotMatch() {
        val long = "a".repeat(40)
        val spans = splitCustomEmoji(":x: :$long:", catalog)
        // Neither token matches the 2..32 length rule, so both remain literal.
        assertTrue(spans.all { it is EmojiSpan.Literal })
        assertEquals(":x: :$long:", spans.joinToString("") { (it as EmojiSpan.Literal).text })
    }

    @Test
    fun adjacentTokensBothResolve() {
        val spans = splitCustomEmoji(":partyparrot::partyparrot:", catalog)
        assertEquals(2, spans.size)
        assertTrue(spans.all { it is EmojiSpan.Emoji })
    }

    @Test
    fun caseInsensitiveMatch() {
        val spans = splitCustomEmoji(":PartyParrot:", catalog)
        assertTrue(spans.single() is EmojiSpan.Emoji)
    }

    @Test
    fun malformedColonsUntouched() {
        val spans = splitCustomEmoji("a : b :", catalog)
        assertEquals(listOf(EmojiSpan.Literal("a : b :")), spans)
    }

    @Test
    fun hasCustomEmoji_detectsKnownOnly() {
        assertTrue(hasCustomEmoji("yo :partyparrot:", catalog))
        assertFalse(hasCustomEmoji("yo :unknown:", catalog))
    }
}
