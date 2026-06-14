package com.testlogon.android.feature.feed

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Locale

/** AND-099 / AND-101 / AND-103 — pure (JVM) helper tests: URL detection, price, duration, monogram. */
class FeedHelpersTest {

    @Test
    fun detectUrls_plainText_none() {
        assertTrue(detectUrls("just some text with no links").isEmpty())
    }

    @Test
    fun detectUrls_findsSingleUrl() {
        val text = "see https://testlogon.dev/blog now"
        val spans = detectUrls(text)
        assertEquals(1, spans.size)
        assertEquals("https://testlogon.dev/blog", spans[0].url)
        assertEquals("https://testlogon.dev/blog", text.substring(spans[0].start, spans[0].end))
    }

    @Test
    fun detectUrls_excludesTrailingPunctuation() {
        val spans = detectUrls("read https://x.com/page. ok")
        assertEquals("https://x.com/page", spans[0].url)
    }

    @Test
    fun detectUrls_doesNotLinkifyMentionsOrHashtags() {
        val spans = detectUrls("hello @ada and #android")
        assertTrue(spans.isEmpty())
    }

    @Test
    fun detectUrls_multiple_inOrder() {
        val spans = detectUrls("http://a.com and https://b.com")
        assertEquals(2, spans.size)
        assertEquals("http://a.com", spans[0].url)
        assertEquals("https://b.com", spans[1].url)
    }

    @Test
    fun priceFormatter_usd() {
        assertEquals("$4.99", PriceFormatter.format(499, "USD", Locale.US))
        assertEquals("$0.00", PriceFormatter.format(0, "USD", Locale.US))
    }

    @Test
    fun priceFormatter_nullAmount_returnsNull() {
        assertNull(PriceFormatter.format(null))
    }

    @Test
    fun priceFormatter_invalidCurrency_returnsNull() {
        assertNull(PriceFormatter.format(499, "ZZZ", Locale.US))
    }

    @Test
    fun formatDuration_secondsToMinuteSecond() {
        assertEquals("0:42", formatDuration(42))
        assertEquals("1:35", formatDuration(95))
        assertEquals("0:00", formatDuration(0))
        assertEquals("0:00", formatDuration(-5))
    }

    @Test
    fun monogram_takesFirstTwoUpper() {
        assertEquals("U_", monogram("u_42"))
        assertEquals("AD", monogram("ada"))
        assertEquals("?", monogram(""))
        assertEquals("?", monogram("   "))
    }
}
