package com.testlogon.android.core.model.syndicates

import org.junit.Assert.assertEquals
import org.junit.Test
import java.util.Locale

/**
 * AND-370 - the GENUINE-GAP coverage for the overflow-proof [formatCents] [Long] overload. The AND-364..369
 * ads surface ships every monetary field as a flat *_cents [Long] specifically to survive values beyond
 * Int.MAX (the whole reason the [Long] overload exists), yet the existing helper tests
 * (SyndicateMappersTest / CollaborationMappersTest) only ever assert small Int-range amounts (1999 / 150000 /
 * 6000 / 1234) and NEVER exercise a value greater than Int.MAX_VALUE nor a plain zero.
 *
 * This pins those two edges: a cents value larger than Int.MAX_VALUE formats WITHOUT overflow (the Int
 * overload would have truncated), and zero cents formats to the currency zero label. Locale is fixed to
 * [Locale.US] so the grouping / symbol output is deterministic on any host.
 *
 * NOTE: distinct class + method names from the existing helper tests so this is purely additive (no
 * duplication). KDoc here deliberately avoids the comment-terminator character pair.
 */
class MoneyFormatOverflowTest {

    @Test
    fun formatCents_long_aboveIntMax_formatsWithoutOverflow() {
        // 2_147_483_648 cents == Int.MAX_VALUE + 1 cents == $21,474,836.48 (the Int overload would truncate).
        val aboveIntMax = Int.MAX_VALUE.toLong() + 1L
        assertEquals("$21,474,836.48", formatCents(aboveIntMax, "USD", Locale.US))
    }

    @Test
    fun formatCents_long_farAboveIntMax_formatsWholeMagnitude() {
        // A value far beyond Int range: 1_234_567_890_123 cents == $12,345,678,901.23.
        assertEquals("$12,345,678,901.23", formatCents(1_234_567_890_123L, "USD", Locale.US))
    }

    @Test
    fun formatCents_long_zero_formatsCurrencyZero() {
        assertEquals("$0.00", formatCents(0L, "USD", Locale.US))
    }
}
