package com.testlogon.android.data.knowledgebase

import com.testlogon.android.core.model.kb.KbArticleSummary
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * KB-AND-1 - JVM unit tests for the pure Knowledge Base logic (HTML-to-text, snippet, search predicates,
 * relevance ranking, status + helpfulness formatting). No Android types; degrade-on-empty / degrade-on-bad
 * input is asserted so the UI never crashes on dev-host drift or a 404 (KB flag off).
 */
class KbMathTest {

    private fun summary(
        id: String = "a",
        title: String? = null,
        excerpt: String? = null,
        tags: List<String> = emptyList(),
    ) = KbArticleSummary(articleId = id, title = title, excerpt = excerpt, tags = tags)

    // ---- htmlToPlainText ----

    @Test
    fun htmlToPlainText_nullOrBlank_returnsEmpty() {
        assertEquals("", KbMath.htmlToPlainText(null))
        assertEquals("", KbMath.htmlToPlainText("   "))
    }

    @Test
    fun htmlToPlainText_stripsTags_andDecodesEntities() {
        val html = "<p>Hello &amp; <b>welcome</b></p>"
        assertEquals("Hello & welcome", KbMath.htmlToPlainText(html))
    }

    @Test
    fun htmlToPlainText_blockTags_becomeNewlines_notRunTogether() {
        val html = "<p>First para</p><p>Second para</p>"
        assertEquals("First para\nSecond para", KbMath.htmlToPlainText(html))
    }

    @Test
    fun htmlToPlainText_listItems_getBullets() {
        val html = "<ul><li>One</li><li>Two</li></ul>"
        val out = KbMath.htmlToPlainText(html)
        assertTrue(out.contains("• One"))
        assertTrue(out.contains("• Two"))
    }

    @Test
    fun htmlToPlainText_malformedMarkup_degradesToText_neverThrows() {
        // Closed tags are stripped; the unknown entity is passed through verbatim (forward-compatible).
        val out = KbMath.htmlToPlainText("<div>text <span>inner</span> &unknownentity;</div>")
        assertFalse("closed tags must be stripped", out.contains("<span>"))
        assertTrue(out.contains("text"))
        assertTrue(out.contains("inner"))
        assertTrue(out.contains("&unknownentity;"))
    }

    @Test
    fun htmlToPlainText_collapsesWhitespace() {
        assertEquals("a b c", KbMath.htmlToPlainText("a   b\t\t c"))
    }

    // ---- snippet ----

    @Test
    fun snippet_prefersExcerpt_overBody() {
        assertEquals("The excerpt", KbMath.snippet("The excerpt", "the body text"))
    }

    @Test
    fun snippet_fallsBackToBody_whenExcerptBlank() {
        assertEquals("the body", KbMath.snippet("   ", "the body"))
    }

    @Test
    fun snippet_truncatesOnWordBoundary_withEllipsis() {
        val long = (1..40).joinToString(" ") { "word$it" }
        val out = KbMath.snippet(null, long, maxLength = 20)
        assertTrue("expected ellipsis, got: $out", out.endsWith("…"))
        assertTrue("expected <= 21 chars, got ${out.length}", out.length <= 21)
        assertFalse("should not cut mid-word", out.dropLast(1).endsWith("wor"))
    }

    @Test
    fun snippet_emptyInputs_returnEmpty() {
        assertEquals("", KbMath.snippet(null, null))
        assertEquals("", KbMath.snippet("", ""))
    }

    // ---- isSearchable ----

    @Test
    fun isSearchable_requiresMinLength_afterTrim() {
        assertFalse(KbMath.isSearchable(null))
        assertFalse(KbMath.isSearchable(" a "))
        assertTrue(KbMath.isSearchable("ab"))
        assertTrue(KbMath.isSearchable("  refund "))
    }

    // ---- statusLabel ----

    @Test
    fun statusLabel_knownAndUnknown() {
        assertEquals("Published", KbMath.statusLabel("published"))
        assertEquals("Draft", KbMath.statusLabel("DRAFT"))
        assertEquals("Expired", KbMath.statusLabel("expired"))
        assertEquals("", KbMath.statusLabel(null))
        assertEquals("", KbMath.statusLabel(""))
        // Unknown token -> Title-Cased fallback (forward-compatible).
        assertEquals("Archived", KbMath.statusLabel("archived"))
    }

    // ---- helpfulness ----

    @Test
    fun helpfulnessRatio_noVotes_isNull() {
        assertNull(KbMath.helpfulnessRatio(0, 0))
        // Negative inputs clamp to 0 -> still no votes.
        assertNull(KbMath.helpfulnessRatio(-3, -1))
    }

    @Test
    fun helpfulnessRatio_andPercent_compute() {
        assertEquals(0.8f, KbMath.helpfulnessRatio(8, 2)!!, 0.0001f)
        assertEquals("80%", KbMath.helpfulnessPercent(8, 2))
        assertEquals("100%", KbMath.helpfulnessPercent(5, 0))
        assertEquals("", KbMath.helpfulnessPercent(0, 0))
    }

    // ---- filterAndRank ----

    @Test
    fun filterAndRank_blankQuery_returnsInputUnchanged() {
        val items = listOf(summary("a", title = "Alpha"), summary("b", title = "Beta"))
        assertEquals(items, KbMath.filterAndRank(items, "   "))
    }

    @Test
    fun filterAndRank_titlePrefix_outranksExcerptContains() {
        val prefix = summary("p", title = "Refund policy")
        val excerptOnly = summary("e", title = "Shipping", excerpt = "how to get a refund")
        val ranked = KbMath.filterAndRank(listOf(excerptOnly, prefix), "refund")
        assertEquals(listOf("p", "e"), ranked.map { it.articleId })
    }

    @Test
    fun filterAndRank_dropsNonMatches() {
        val items = listOf(
            summary("a", title = "Billing help"),
            summary("b", title = "Password reset"),
        )
        val ranked = KbMath.filterAndRank(items, "billing")
        assertEquals(listOf("a"), ranked.map { it.articleId })
    }

    @Test
    fun filterAndRank_tagExactMatch_scoresHigherThanExcerpt() {
        val tagged = summary("t", title = "Guide", tags = listOf("refund"))
        val excerpt = summary("e", title = "Guide2", excerpt = "mentions refund inline")
        val ranked = KbMath.filterAndRank(listOf(excerpt, tagged), "refund")
        assertEquals(listOf("t", "e"), ranked.map { it.articleId })
    }
}
