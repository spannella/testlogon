package com.testlogon.android.data.alerts

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Pure-logic tests for [AlertsPrefsMath] (webhook URL/event-type + push merge). */
class AlertsPrefsMathTest {

    // --- normalizeUrls ---

    @Test
    fun normalizeUrls_trimsDropsBlanksAndDedupes_preservingOrder() {
        val out = AlertsPrefsMath.normalizeUrls(
            listOf(" https://a.com/hook ", "", "https://b.com/x", "https://a.com/hook", "   "),
        )
        assertEquals(listOf("https://a.com/hook", "https://b.com/x"), out)
    }

    @Test
    fun normalizeUrls_empty_returnsEmpty() {
        assertTrue(AlertsPrefsMath.normalizeUrls(emptyList()).isEmpty())
    }

    // --- isValidWebhookUrl ---

    @Test
    fun isValidWebhookUrl_acceptsHttpAndHttps() {
        assertTrue(AlertsPrefsMath.isValidWebhookUrl("https://hooks.example.com/abc"))
        assertTrue(AlertsPrefsMath.isValidWebhookUrl(" http://example.io/y "))
    }

    @Test
    fun isValidWebhookUrl_rejectsBlankSchemelessAndHostless() {
        assertFalse(AlertsPrefsMath.isValidWebhookUrl(""))
        assertFalse(AlertsPrefsMath.isValidWebhookUrl("   "))
        assertFalse(AlertsPrefsMath.isValidWebhookUrl("ftp://example.com"))
        assertFalse(AlertsPrefsMath.isValidWebhookUrl("example.com/no-scheme"))
        assertFalse(AlertsPrefsMath.isValidWebhookUrl("https://"))
        assertFalse(AlertsPrefsMath.isValidWebhookUrl("https://localhost/x")) // no dot in host
    }

    // --- addUrl ---

    @Test
    fun addUrl_appendsValidUnique() {
        val out = AlertsPrefsMath.addUrl(listOf("https://a.com/x"), " https://b.com/y ")
        assertEquals(listOf("https://a.com/x", "https://b.com/y"), out)
    }

    @Test
    fun addUrl_ignoresInvalid_returnsNormalizedCurrent() {
        val out = AlertsPrefsMath.addUrl(listOf(" https://a.com/x ", "https://a.com/x"), "not-a-url")
        assertEquals(listOf("https://a.com/x"), out)
    }

    @Test
    fun addUrl_doesNotDuplicateExisting() {
        val out = AlertsPrefsMath.addUrl(listOf("https://a.com/x"), "https://a.com/x")
        assertEquals(listOf("https://a.com/x"), out)
    }

    // --- removeUrl ---

    @Test
    fun removeUrl_dropsExactMatchAfterTrim() {
        val out = AlertsPrefsMath.removeUrl(listOf("https://a.com/x", "https://b.com/y"), " https://a.com/x ")
        assertEquals(listOf("https://b.com/y"), out)
    }

    @Test
    fun removeUrl_missing_isNoOp() {
        val out = AlertsPrefsMath.removeUrl(listOf("https://a.com/x"), "https://z.com/none")
        assertEquals(listOf("https://a.com/x"), out)
    }

    // --- toggleEventType ---

    @Test
    fun toggleEventType_addsWhenEnabled() {
        val out = AlertsPrefsMath.toggleEventType(listOf("tip_received"), "order_shipped", true)
        assertEquals(listOf("tip_received", "order_shipped"), out)
    }

    @Test
    fun toggleEventType_removesWhenDisabled() {
        val out = AlertsPrefsMath.toggleEventType(listOf("tip_received", "order_shipped"), "tip_received", false)
        assertEquals(listOf("order_shipped"), out)
    }

    @Test
    fun toggleEventType_enableExisting_isIdempotent() {
        val out = AlertsPrefsMath.toggleEventType(listOf("tip_received"), " tip_received ", true)
        assertEquals(listOf("tip_received"), out)
    }

    // --- isEventSelected ---

    @Test
    fun isEventSelected_emptyMeansAll() {
        assertTrue(AlertsPrefsMath.isEventSelected(emptyList(), "anything"))
    }

    @Test
    fun isEventSelected_matchesMembership() {
        assertTrue(AlertsPrefsMath.isEventSelected(listOf("a", "b"), " b "))
        assertFalse(AlertsPrefsMath.isEventSelected(listOf("a", "b"), "c"))
    }

    // --- push merge ---

    @Test
    fun mergePushEnabled_defaultsMinusOptOutPlusOptIn() {
        val out = AlertsPrefsMath.mergePushEnabled(
            defaults = setOf("tip", "sold", "delivered"),
            optOut = setOf("sold"),
            explicitOptIn = setOf("marketing"),
        )
        assertEquals(setOf("tip", "delivered", "marketing"), out)
    }

    @Test
    fun isPushEnabled_defaultOnRespectsOptOut() {
        assertTrue(AlertsPrefsMath.isPushEnabled("tip", setOf("tip"), emptySet(), emptySet()))
        assertFalse(AlertsPrefsMath.isPushEnabled("tip", setOf("tip"), setOf("tip"), emptySet()))
    }

    @Test
    fun isPushEnabled_defaultOffRespectsOptIn() {
        assertFalse(AlertsPrefsMath.isPushEnabled("marketing", emptySet(), emptySet(), emptySet()))
        assertTrue(AlertsPrefsMath.isPushEnabled("marketing", emptySet(), emptySet(), setOf("marketing")))
    }
}
