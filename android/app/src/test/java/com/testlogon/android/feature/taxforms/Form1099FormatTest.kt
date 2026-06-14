package com.testlogon.android.feature.taxforms

import com.testlogon.android.data.taxforms.Form1099Money
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Locale

/**
 * AND-247/250 — pure formatter tests: the filename builder (FR-6: TestLogon_1099-NEC_<year>.pdf), USD
 * money formatting (cents/100), unknown-currency fallback, and epoch->date null handling.
 */
class Form1099FormatTest {

    @Test
    fun fileName_isTypeAndYearOnly() {
        assertEquals("TestLogon_1099-NEC_2025.pdf", form1099FileName(2025))
        assertEquals("TestLogon_1099-NEC_2023.pdf", form1099FileName(2023))
    }

    @Test
    fun money_formatsUsdMinorUnits() {
        val text = formatForm1099Money(Form1099Money(1_284_500), Locale.US)
        assertEquals("$12,845.00", text)
    }

    @Test
    fun money_unknownCurrency_fallsBackGracefully() {
        val text = formatForm1099Money(Form1099Money(1000, "zzz"), Locale.US)
        assertTrue(text.contains("ZZZ"))
        assertTrue(text.contains("10.00"))
    }

    @Test
    fun date_nullEpoch_isNull() {
        assertNull(formatForm1099Date(null))
    }

    @Test
    fun date_nonNullEpoch_isNonNull() {
        // We don't assert the exact locale string; only that a non-null epoch yields a value.
        val text = formatForm1099Date(1_738_310_400L, Locale.US)
        assertTrue(text != null && text.isNotBlank())
    }
}
