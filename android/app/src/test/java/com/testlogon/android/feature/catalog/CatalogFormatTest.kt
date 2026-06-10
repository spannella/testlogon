package com.testlogon.android.feature.catalog

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Locale

/** AND-205 — pure price-formatting tests across currencies/locales (no Android). */
class CatalogFormatTest {

    @Test
    fun usd_enUs() {
        assertEquals("$19.99", formatPrice(1999, "USD", Locale.US))
    }

    @Test
    fun eur_deDe() {
        // de-DE formats EUR as "19,99 €" (NBSP before the symbol).
        val out = formatPrice(1999, "EUR", Locale.GERMANY)
        assertTrue(out, out.contains("19,99"))
        assertTrue(out, out.contains("€"))
    }

    @Test
    fun zeroPrice() {
        assertEquals("$0.00", formatPrice(0, "USD", Locale.US))
    }

    @Test
    fun unknownCurrency_fallsBack_noCrash() {
        val out = formatPrice(1234, "XYZ", Locale.US)
        assertTrue(out, out.contains("12.34"))
        assertTrue(out, out.contains("XYZ"))
    }
}
