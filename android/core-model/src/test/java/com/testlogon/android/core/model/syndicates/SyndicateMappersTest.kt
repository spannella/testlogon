package com.testlogon.android.core.model.syndicates

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Locale

/**
 * AND-356 - unit tests for the core-model syndicate types: [SplitMode.from] (UNKNOWN fallback), the
 * weighted-only [RevenueSplitPolicy.weightSumOk] check (within 1bp of 10000 ok; off-by-2bp not ok; equal /
 * performance never checked), and the [formatCents] money helper (currency upper-cased, cents -> string,
 * exotic-currency fallback). Pure JVM; no Android, no Moshi.
 */
class SyndicateMappersTest {

    // ---- SplitMode.from ----

    @Test
    fun splitMode_parsesKnownTokens_caseAndWhitespaceInsensitive() {
        assertEquals(SplitMode.EQUAL, SplitMode.from("equal"))
        assertEquals(SplitMode.WEIGHTED, SplitMode.from("WEIGHTED"))
        assertEquals(SplitMode.PERFORMANCE, SplitMode.from(" performance "))
    }

    @Test
    fun splitMode_unknownOrNull_isUnknown_neverThrows() {
        assertEquals(SplitMode.UNKNOWN, SplitMode.from(null))
        assertEquals(SplitMode.UNKNOWN, SplitMode.from(""))
        // "tiered" is NOT a supported mode -> UNKNOWN
        assertEquals(SplitMode.UNKNOWN, SplitMode.from("tiered"))
    }

    // ---- weightSumOk (weighted only) ----

    @Test
    fun weightSumOk_weighted_sumsToFullShare_isOk() {
        val policy = RevenueSplitPolicy(
            mode = SplitMode.WEIGHTED,
            weightsBps = mapOf("a" to 6000, "b" to 4000),
        )
        assertEquals(10_000, policy.weightSumBps)
        assertTrue(policy.weightSumOk)
    }

    @Test
    fun weightSumOk_weighted_withinOneBp_isOk() {
        val policy = RevenueSplitPolicy(
            mode = SplitMode.WEIGHTED,
            weightsBps = mapOf("a" to 6000, "b" to 4001),
        )
        assertTrue(policy.weightSumOk)
    }

    @Test
    fun weightSumOk_weighted_offByTwoBp_isNotOk() {
        val policy = RevenueSplitPolicy(
            mode = SplitMode.WEIGHTED,
            weightsBps = mapOf("a" to 6000, "b" to 3998),
        )
        assertEquals(9_998, policy.weightSumBps)
        assertFalse(policy.weightSumOk)
    }

    @Test
    fun weightSumOk_equalMode_isNotChecked_alwaysOk() {
        // equal mode with stray (or empty) weights is never flagged
        val equal = RevenueSplitPolicy(mode = SplitMode.EQUAL, weightsBps = mapOf("a" to 1))
        val performance = RevenueSplitPolicy(mode = SplitMode.PERFORMANCE, weightsBps = emptyMap())
        assertTrue(equal.weightSumOk)
        assertTrue(performance.weightSumOk)
    }

    @Test
    fun weightSumOk_weighted_emptyWeights_isNotChecked() {
        val policy = RevenueSplitPolicy(mode = SplitMode.WEIGHTED, weightsBps = emptyMap())
        assertTrue(policy.weightSumOk)
    }

    // ---- formatCents ----

    @Test
    fun formatCents_usd_enUs_formatsMajorMinor() {
        assertEquals("$19.99", formatCents(1999, "usd", Locale.US))
        assertEquals("$1,500.00", formatCents(150000, "USD", Locale.US))
    }

    @Test
    fun formatCents_exoticCurrency_fallsBackToPlainForm() {
        // an unrecognized ISO code must not crash; it falls back to "<major>.<minor> CODE"
        assertEquals("12.34 ZZZ", formatCents(1234, "zzz", Locale.US))
    }
}
