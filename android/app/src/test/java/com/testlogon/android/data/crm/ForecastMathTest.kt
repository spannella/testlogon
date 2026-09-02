package com.testlogon.android.data.crm

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * CRM-AND-OPP — JVM unit tests for the pure forecast / quota / pipeline-report maths. No Android types;
 * degrade-on-bad-input (negative / zero-quota) is asserted so the UI never crashes on a 404 or drift.
 */
class ForecastMathTest {

    private data class Row(
        override val stage: String?,
        override val count: Int,
        override val totalAmountCents: Long,
        override val weightedAmountCents: Long,
    ) : ForecastMath.StageMetricLike

    // ── attainmentPct ────────────────────────────────────────────────────────

    @Test
    fun attainment_basicPercent() {
        assertEquals(50, ForecastMath.attainmentPct(5_000, 10_000))
        assertEquals(100, ForecastMath.attainmentPct(10_000, 10_000))
    }

    @Test
    fun attainment_roundsHalfUp() {
        // 3333 / 10000 = 33.33% -> 33
        assertEquals(33, ForecastMath.attainmentPct(3_333, 10_000))
        // 3335 / 10000 = 33.35 -> 33
        assertEquals(33, ForecastMath.attainmentPct(3_335, 10_000))
        // 3355 / 10000 = 33.55 -> 34
        assertEquals(34, ForecastMath.attainmentPct(3_355, 10_000))
    }

    @Test
    fun attainment_canExceed100() {
        assertEquals(150, ForecastMath.attainmentPct(15_000, 10_000))
    }

    @Test
    fun attainment_zeroQuotaDegradesToZero() {
        assertEquals(0, ForecastMath.attainmentPct(5_000, 0))
        assertEquals(0, ForecastMath.attainmentPct(5_000, -100))
    }

    @Test
    fun attainment_negativeClosedDegradesToZero() {
        assertEquals(0, ForecastMath.attainmentPct(-5_000, 10_000))
    }

    // ── gapToQuota ─────────────────────────────────────────────────────────

    @Test
    fun gap_remainingToQuota() {
        assertEquals(4_000L, ForecastMath.gapToQuotaCents(6_000, 10_000))
    }

    @Test
    fun gap_zeroOnceMet() {
        assertEquals(0L, ForecastMath.gapToQuotaCents(10_000, 10_000))
        assertEquals(0L, ForecastMath.gapToQuotaCents(12_000, 10_000))
    }

    @Test
    fun gap_zeroQuotaDegradesToZero() {
        assertEquals(0L, ForecastMath.gapToQuotaCents(5_000, 0))
    }

    // ── pipelineCoverage ───────────────────────────────────────────────────

    @Test
    fun coverage_multipleOfGap() {
        // gap 10k, pipeline 30k -> 300%
        assertEquals(300, ForecastMath.pipelineCoveragePct(30_000, 0, 10_000))
    }

    @Test
    fun coverage_zeroGapDegradesToZero() {
        // quota already met -> no gap -> 0
        assertEquals(0, ForecastMath.pipelineCoveragePct(30_000, 10_000, 10_000))
    }

    // ── rollup ─────────────────────────────────────────────────────────────

    @Test
    fun rollup_derivedTotals() {
        val r = ForecastMath.rollup(
            committedCents = 4_000,
            bestCaseCents = 8_000,
            pipelineCents = 20_000,
            closedCents = 3_000,
            quotaCents = 10_000,
        )
        assertEquals(7_000L, r.commitTotalCents)
        assertEquals(11_000L, r.bestCaseTotalCents)
        assertEquals(30, r.attainmentPct)       // 3000/10000
        assertEquals(7_000L, r.gapToQuotaCents) // 10000-3000
        assertFalse(r.committedMeetsQuota)      // commitTotal 7000 < 10000
    }

    @Test
    fun rollup_committedMeetsQuota() {
        val r = ForecastMath.rollup(8_000, 9_000, 5_000, 3_000, 10_000)
        // commitTotal = 3000 + 8000 = 11000 >= 10000
        assertTrue(r.committedMeetsQuota)
    }

    @Test
    fun rollup_clampsNegativeInputs() {
        val r = ForecastMath.rollup(-1, -1, -1, -1, -1)
        assertEquals(0L, r.committedCents)
        assertEquals(0L, r.closedCents)
        assertEquals(0L, r.quotaCents)
        assertEquals(0, r.attainmentPct)
    }

    // ── pipeline-report roll-ups ─────────────────────────────────────────────

    private fun sampleRows() = listOf(
        Row("prospecting", 3, 30_000, 3_000),
        Row("negotiation_review", 2, 20_000, 16_000),
        Row("closed_won", 1, 50_000, 50_000),
        Row("closed_lost", 4, 40_000, 0),
    )

    @Test
    fun report_openTotalsExcludeClosed() {
        val rows = sampleRows()
        assertEquals(50_000L, ForecastMath.openTotalAmountCents(rows))    // 30k + 20k
        assertEquals(19_000L, ForecastMath.openWeightedAmountCents(rows)) // 3k + 16k
    }

    @Test
    fun report_wonAmount() {
        assertEquals(50_000L, ForecastMath.wonAmountCents(sampleRows()))
    }

    @Test
    fun report_openCount() {
        assertEquals(5, ForecastMath.openCount(sampleRows())) // 3 + 2
    }

    @Test
    fun report_stageSharePct() {
        assertEquals(30, ForecastMath.stageSharePct(3, 10))
        assertEquals(0, ForecastMath.stageSharePct(3, 0)) // divide-by-zero degrade
    }

    @Test
    fun report_emptyRowsDegradeToZero() {
        val empty = emptyList<Row>()
        assertEquals(0L, ForecastMath.openTotalAmountCents(empty))
        assertEquals(0L, ForecastMath.wonAmountCents(empty))
        assertEquals(0, ForecastMath.openCount(empty))
    }
}
