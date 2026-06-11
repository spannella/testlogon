package com.testlogon.android.feature.payouts

import com.testlogon.android.data.payouts.PayoutMoney
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Locale

/** AND-260 — pure money/date formatting: locale currency, unknown-currency fallback, epoch date guard. */
class PayoutFormatTest {

    @Test
    fun money_formatsUsdInUsLocale() {
        assertEquals("$45.00", formatPayoutMoney(PayoutMoney(4500, "USD"), Locale.US))
    }

    @Test
    fun money_unknownCurrency_fallsBackToPlainForm() {
        val out = formatPayoutMoney(PayoutMoney(4500, "ZZZ"), Locale.US)
        assertTrue(out.contains("45.00"))
        assertTrue(out.contains("ZZZ"))
    }

    @Test
    fun date_nullOrZero_isNull() {
        assertNull(formatPayoutDate(null))
        assertNull(formatPayoutDate(0L))
    }

    @Test
    fun date_validEpoch_isNonNull() {
        assertTrue(formatPayoutDate(1_748_800_800L, Locale.US)?.isNotBlank() == true)
    }
}
