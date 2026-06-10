package com.testlogon.android.core.ui.text

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-151 / AND-152 — pure JVM tests for the shared highlight logic. */
class SearchHighlightTest {

    @Test
    fun ranges_findsMultipleCaseInsensitiveOccurrences() {
        val body = "we Deploy to prod after the deploy freeze"
        val ranges = searchMatchRanges(body, "deploy")
        assertEquals(2, ranges.size)
        assertEquals(body.indexOf("Deploy") until body.indexOf("Deploy") + 6, ranges[0])
        assertEquals(body.lastIndexOf("deploy"), ranges[1].first)
    }

    @Test
    fun ranges_blankQueryReturnsEmpty() {
        assertTrue(searchMatchRanges("hello world", "   ").isEmpty())
        assertTrue(searchMatchRanges("hello world", "").isEmpty())
    }

    @Test
    fun ranges_noMatchReturnsEmpty() {
        assertTrue(searchMatchRanges("hello world", "xyz").isEmpty())
    }

    @Test
    fun ranges_nonOverlapping() {
        // "aa" in "aaaa" yields 2 non-overlapping matches, not 3.
        val ranges = searchMatchRanges("aaaa", "aa")
        assertEquals(2, ranges.size)
        assertEquals(0 until 2, ranges[0])
        assertEquals(2 until 4, ranges[1])
    }

    @Test
    fun ranges_literalNotRegex() {
        // Regex metacharacters are matched literally (no ReDoS / no pattern semantics).
        val ranges = searchMatchRanges("price is .* dollars", ".*")
        assertEquals(1, ranges.size)
        assertEquals(9 until 11, ranges[0])
    }

    @Test
    fun ranges_unicodeNfcEquivalence() {
        // Composed "é" (U+00E9) body vs composed query — single match, length-preserving NFC.
        val ranges = searchMatchRanges("café menu", "café")
        assertEquals(1, ranges.size)
        assertEquals(0 until 4, ranges[0])
    }

    @Test
    fun highlight_noMatchReturnsPlainBody() {
        val s = highlightMatches("hello world", "xyz")
        assertEquals("hello world", s.text)
        assertTrue(s.spanStyles.isEmpty())
    }

    @Test
    fun highlight_blankQueryReturnsPlainBody() {
        val s = highlightMatches("hello world", "")
        assertTrue(s.spanStyles.isEmpty())
    }

    @Test
    fun highlight_activeOccurrenceUsesBoldAndActiveBg() {
        val matchBg = Color.Yellow
        val activeBg = Color.Cyan
        val s = highlightMatches(
            body = "deploy and deploy",
            query = "deploy",
            activeOccurrence = 1,
            matchBg = matchBg,
            activeBg = activeBg,
        )
        assertEquals(2, s.spanStyles.size)
        val first = s.spanStyles[0].item
        val second = s.spanStyles[1].item
        assertEquals(matchBg, first.background)
        assertNull(first.fontWeight)
        assertEquals(activeBg, second.background)
        assertEquals(FontWeight.Bold, second.fontWeight)
    }
}
