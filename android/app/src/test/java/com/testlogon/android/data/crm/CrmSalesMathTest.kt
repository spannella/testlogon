package com.testlogon.android.data.crm

import com.testlogon.android.data.crm.CrmSalesMath.LeadScoreBand
import com.testlogon.android.data.crm.CrmSalesMath.PipelineOpp
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * CRM-AND-1 — JVM unit tests for the pure CRM Sales logic (lead-score bucketing, stage classification,
 * weighted-forecast maths, cents formatting). No Android types; degrade-on-empty / degrade-on-bad-input
 * is asserted so the UI never crashes on a 404 (module disabled) or dev-host drift.
 */
class CrmSalesMathTest {

    // ── scoreBand ────────────────────────────────────────────────────────────

    @Test
    fun scoreBand_bucketsAcrossThirds() {
        assertEquals(LeadScoreBand.COLD, CrmSalesMath.scoreBand(0))
        assertEquals(LeadScoreBand.COLD, CrmSalesMath.scoreBand(32))
        assertEquals(LeadScoreBand.WARM, CrmSalesMath.scoreBand(34))
        assertEquals(LeadScoreBand.WARM, CrmSalesMath.scoreBand(60))
        assertEquals(LeadScoreBand.HOT, CrmSalesMath.scoreBand(67))
        assertEquals(LeadScoreBand.HOT, CrmSalesMath.scoreBand(100))
    }

    @Test
    fun scoreBand_clampsOutOfRange() {
        assertEquals(LeadScoreBand.COLD, CrmSalesMath.scoreBand(-50))
        assertEquals(LeadScoreBand.HOT, CrmSalesMath.scoreBand(9999))
    }

    @Test
    fun scoreBand_customMaxScore() {
        // max 10 -> 3 is cold(<3.33), 4 warm(<6.66), 8 hot
        assertEquals(LeadScoreBand.COLD, CrmSalesMath.scoreBand(3, maxScore = 10))
        assertEquals(LeadScoreBand.WARM, CrmSalesMath.scoreBand(4, maxScore = 10))
        assertEquals(LeadScoreBand.HOT, CrmSalesMath.scoreBand(8, maxScore = 10))
    }

    @Test
    fun scoreBand_nonPositiveMax_degradesToCold() {
        assertEquals(LeadScoreBand.COLD, CrmSalesMath.scoreBand(50, maxScore = 0))
        assertEquals(LeadScoreBand.COLD, CrmSalesMath.scoreBand(50, maxScore = -1))
    }

    // ── stage classification ──────────────────────────────────────────────────

    @Test
    fun stageClassification_wonLostClosedOpen() {
        assertTrue(CrmSalesMath.isWonStage("closed_won"))
        assertFalse(CrmSalesMath.isWonStage("closed_lost"))
        assertTrue(CrmSalesMath.isLostStage("closed_lost"))
        assertTrue(CrmSalesMath.isClosedStage("closed_won"))
        assertTrue(CrmSalesMath.isClosedStage("closed_lost"))
        assertFalse(CrmSalesMath.isClosedStage("prospecting"))
        assertTrue(CrmSalesMath.isOpenStage("qualification"))
        assertFalse(CrmSalesMath.isOpenStage("closed_won"))
    }

    @Test
    fun stageLabel_curatedAndFallback() {
        assertEquals("Prospecting", CrmSalesMath.stageLabel("prospecting"))
        assertEquals("Closed Won", CrmSalesMath.stageLabel("closed_won"))
        // unknown server stage -> title-cased de-underscored
        assertEquals("Some New Stage", CrmSalesMath.stageLabel("some_new_stage"))
        assertEquals("—", CrmSalesMath.stageLabel(null))
        assertEquals("—", CrmSalesMath.stageLabel("  "))
    }

    @Test
    fun defaultProbability_monotonicIshAndBounds() {
        assertEquals(10, CrmSalesMath.defaultProbabilityFor("prospecting"))
        assertEquals(100, CrmSalesMath.defaultProbabilityFor("closed_won"))
        assertEquals(0, CrmSalesMath.defaultProbabilityFor("closed_lost"))
        assertEquals(10, CrmSalesMath.defaultProbabilityFor("mystery"))
    }

    // ── weightedAmountCents ────────────────────────────────────────────────────

    @Test
    fun weightedAmount_appliesProbability() {
        assertEquals(5000L, CrmSalesMath.weightedAmountCents(10000L, 50, "qualification"))
        // round half up: 10000 * 33 = 330000 -> /100 = 3300 (exact); 12345*33=407385 +50 /100 = 4074
        assertEquals(4074L, CrmSalesMath.weightedAmountCents(12345L, 33, "qualification"))
    }

    @Test
    fun weightedAmount_wonIsFull_lostIsZero() {
        assertEquals(10000L, CrmSalesMath.weightedAmountCents(10000L, 10, "closed_won"))
        assertEquals(0L, CrmSalesMath.weightedAmountCents(10000L, 90, "closed_lost"))
    }

    @Test
    fun weightedAmount_clampsProbabilityAndNonPositiveAmount() {
        assertEquals(10000L, CrmSalesMath.weightedAmountCents(10000L, 150, "qualification"))
        assertEquals(0L, CrmSalesMath.weightedAmountCents(10000L, -20, "qualification"))
        assertEquals(0L, CrmSalesMath.weightedAmountCents(0L, 50, "qualification"))
        assertEquals(0L, CrmSalesMath.weightedAmountCents(-100L, 50, "qualification"))
    }

    // ── pipeline roll-ups ──────────────────────────────────────────────────────

    private val sample = listOf(
        PipelineOpp("prospecting", 100_00L, 10),
        PipelineOpp("negotiation_review", 200_00L, 80),
        PipelineOpp("closed_won", 500_00L, 100),
        PipelineOpp("closed_lost", 999_00L, 90),
    )

    @Test
    fun openPipeline_excludesClosed() {
        // open weighted: 10000*10% =1000 ; 20000*80% =16000 => 17000
        assertEquals(170_00L, CrmSalesMath.openPipelineWeightedCents(sample))
        assertEquals(300_00L, CrmSalesMath.openPipelineAmountCents(sample))
        assertEquals(500_00L, CrmSalesMath.wonAmountCents(sample))
    }

    @Test
    fun openPipeline_emptyIsZero() {
        assertEquals(0L, CrmSalesMath.openPipelineWeightedCents(emptyList()))
        assertEquals(0L, CrmSalesMath.wonAmountCents(emptyList()))
        assertEquals(0, CrmSalesMath.winRatePct(emptyList()))
    }

    @Test
    fun winRate_overClosedOnly() {
        // 1 won, 1 lost -> 50%
        assertEquals(50, CrmSalesMath.winRatePct(sample))
        val allWon = listOf(PipelineOpp("closed_won", 1L, 100), PipelineOpp("closed_won", 1L, 100))
        assertEquals(100, CrmSalesMath.winRatePct(allWon))
    }

    @Test
    fun groupByStage_ordersByCanonicalThenExtras() {
        val opps = listOf(
            PipelineOpp("closed_won", 1L, 100),
            PipelineOpp("prospecting", 1L, 10),
            PipelineOpp("zzz_custom", 1L, 10),
        )
        val grouped = CrmSalesMath.groupByStage(opps)
        assertEquals(listOf("prospecting", "closed_won", "zzz_custom"), grouped.map { it.first })
    }

    // ── formatCents ────────────────────────────────────────────────────────────

    @Test
    fun formatCents_groupsAndPads() {
        assertEquals("$0.00", CrmSalesMath.formatCents(0L))
        assertEquals("$1.05", CrmSalesMath.formatCents(105L))
        assertEquals("$12.34", CrmSalesMath.formatCents(1234L))
        assertEquals("$1,234.56", CrmSalesMath.formatCents(123456L))
        assertEquals("$1,234,567.89", CrmSalesMath.formatCents(123456789L))
        assertEquals("-$1.00", CrmSalesMath.formatCents(-100L))
    }
}
