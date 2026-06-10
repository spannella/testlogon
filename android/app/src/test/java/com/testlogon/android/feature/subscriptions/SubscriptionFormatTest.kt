package com.testlogon.android.feature.subscriptions

import com.testlogon.android.data.subscriptions.BillingInterval
import org.junit.Assert.assertEquals
import org.junit.Test
import java.util.Locale

/** AND-235 — pure price/interval formatting: currency, Free special-case, locale, unknown currency. */
class SubscriptionFormatTest {

    @Test
    fun formatsUsdUnderEnUs() {
        assertEquals("$4.99", formatTierPrice(499, "USD", "Free", Locale.US))
    }

    @Test
    fun zeroCents_rendersFreeLabel() {
        assertEquals("Free", formatTierPrice(0, "USD", "Free", Locale.US))
    }

    @Test
    fun unknownCurrency_doesNotCrash() {
        // "ZZZ" is not a valid ISO-4217 code -> graceful plain fallback, never an exception.
        val out = formatTierPrice(1000, "ZZZ", "Free", Locale.US)
        assertEquals("10.00 ZZZ", out)
    }

    @Test
    fun eurUnderDeDe_formatsLocaleCorrect() {
        // de-DE EUR formatting uses a comma decimal + trailing symbol; assert the digits are present.
        val out = formatTierPrice(1000, "EUR", "Free", Locale.GERMANY)
        assertEquals(true, out.contains("10,00"))
    }

    @Test
    fun intervalSuffix_mapsKnownIntervals() {
        assertEquals("/month", intervalSuffix(BillingInterval.MONTH, "/month", "/year", "/week"))
        assertEquals("/year", intervalSuffix(BillingInterval.YEAR, "/month", "/year", "/week"))
        assertEquals("/week", intervalSuffix(BillingInterval.WEEK, "/month", "/year", "/week"))
        assertEquals("", intervalSuffix(BillingInterval.UNKNOWN, "/month", "/year", "/week"))
    }
}
