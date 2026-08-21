package com.testlogon.android.feature.bailout

import com.testlogon.android.data.bailout.HealthZone
import com.testlogon.android.feature.bailout.BailoutMath.BailoutBid
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class BailoutMathTest {

    // ---- healthZone ----

    @Test
    fun healthZone_insolvent_isLiquidation_regardlessOfBuffer() {
        assertEquals(HealthZone.LIQUIDATION, BailoutMath.healthZone(bufferBps = 9000, dangerBps = 100, solvent = false))
    }

    @Test
    fun healthZone_solventInsideBand_isDistress() {
        // buffer <= danger and solvent -> distressed but still solvent (bailout possible).
        assertEquals(HealthZone.DISTRESS, BailoutMath.healthZone(bufferBps = 120, dangerBps = 300, solvent = true))
    }

    @Test
    fun healthZone_solventAtBandEdge_isDistress() {
        assertEquals(HealthZone.DISTRESS, BailoutMath.healthZone(bufferBps = 300, dangerBps = 300, solvent = true))
    }

    @Test
    fun healthZone_solventOutsideBand_isHealthy() {
        assertEquals(HealthZone.HEALTHY, BailoutMath.healthZone(bufferBps = 5000, dangerBps = 300, solvent = true))
    }

    @Test
    fun healthZone_negativeInputsClampToZero_distress() {
        assertEquals(HealthZone.DISTRESS, BailoutMath.healthZone(bufferBps = -5, dangerBps = -5, solvent = true))
    }

    // ---- dangerBps ----

    @Test
    fun dangerBps_scalesWithVolatility_kIs1point5() {
        // 1000 bps vol * 1.5 = 1500 bps.
        assertEquals(1500, BailoutMath.dangerBps(volatilityBps = 1000))
    }

    @Test
    fun dangerBps_clampsToFloor() {
        assertEquals(100, BailoutMath.dangerBps(volatilityBps = 10)) // 15 -> floor 100
    }

    @Test
    fun dangerBps_clampsToCeil() {
        assertEquals(3000, BailoutMath.dangerBps(volatilityBps = 100000)) // huge -> ceil 3000
    }

    // ---- bufferBps ----

    @Test
    fun bufferBps_distanceToLiquidation() {
        // mark 10000, liq 9500 -> 500/10000 = 500 bps.
        assertEquals(500, BailoutMath.bufferBps(markPrice = 10000, liqPrice = 9500))
    }

    @Test
    fun bufferBps_zeroMark_isZero() {
        assertEquals(0, BailoutMath.bufferBps(markPrice = 0, liqPrice = 100))
    }

    // ---- clearingSummary ----

    @Test
    fun clearing_empty_nothingClears() {
        val s = BailoutMath.clearingSummary(emptyList(), capitalNeededCents = 100_00)
        assertNull(s.clearingShareBps)
        assertEquals(0L, s.raisedCents)
        assertTrue(!s.fullyFunded)
    }

    @Test
    fun clearing_leastDilutiveFirst_singlePrice() {
        // Need $200. Bid A: $100 for 500bps (5bps/$). Bid B: $100 for 1000bps (10bps/$).
        // A is cheaper -> filled first fully (500bps), then B fully (1000bps). Total 1500bps, raised $200.
        val bids = listOf(
            BailoutBid(capitalCents = 100_00, shareBps = 1000), // pricier
            BailoutBid(capitalCents = 100_00, shareBps = 500),  // cheaper
        )
        val s = BailoutMath.clearingSummary(bids, capitalNeededCents = 200_00)
        assertEquals(200_00L, s.raisedCents)
        assertEquals(2, s.filledRescuers)
        assertTrue(s.fullyFunded)
        assertEquals(1500, s.clearingShareBps)
    }

    @Test
    fun clearing_marginalBidProRated() {
        // Need $150. Cheap bid: $100 for 500bps. Pricier: $100 for 1000bps.
        // Cheap fills fully (500bps, $100). Pricier fills $50 of $100 -> 500bps share. Total 1000bps.
        val bids = listOf(
            BailoutBid(capitalCents = 100_00, shareBps = 500),
            BailoutBid(capitalCents = 100_00, shareBps = 1000),
        )
        val s = BailoutMath.clearingSummary(bids, capitalNeededCents = 150_00)
        assertEquals(150_00L, s.raisedCents)
        assertEquals(2, s.filledRescuers)
        assertTrue(s.fullyFunded)
        assertEquals(1000, s.clearingShareBps) // 500 + (1000 * 5000/10000)
    }

    @Test
    fun clearing_underfunded_partialRaise_notFullyFunded() {
        val bids = listOf(BailoutBid(capitalCents = 50_00, shareBps = 500))
        val s = BailoutMath.clearingSummary(bids, capitalNeededCents = 200_00)
        assertEquals(50_00L, s.raisedCents)
        assertTrue(!s.fullyFunded)
        assertEquals(500, s.clearingShareBps)
    }

    @Test
    fun clearing_zeroNeeded_fullyFundedNoShare() {
        val s = BailoutMath.clearingSummary(
            listOf(BailoutBid(capitalCents = 100_00, shareBps = 500)),
            capitalNeededCents = 0,
        )
        assertEquals(0, s.clearingShareBps)
        assertTrue(s.fullyFunded)
    }

    @Test
    fun clearing_ignoresInvalidBids() {
        val bids = listOf(
            BailoutBid(capitalCents = 0, shareBps = 500),      // no capital
            BailoutBid(capitalCents = 100_00, shareBps = 0),   // no share offered
            BailoutBid(capitalCents = 100_00, shareBps = 400), // valid
        )
        val s = BailoutMath.clearingSummary(bids, capitalNeededCents = 100_00)
        assertEquals(100_00L, s.raisedCents)
        assertEquals(1, s.filledRescuers)
        assertEquals(400, s.clearingShareBps)
    }

    // ---- helpers ----

    @Test
    fun shareForCapital_proRataOfClearing() {
        // Rescuer put in $100 of $200 raised at 1500bps clearing -> 750bps.
        assertEquals(750, BailoutMath.shareForCapital(capitalCents = 100_00, clearingShareBps = 1500, raisedCents = 200_00))
    }

    @Test
    fun formatHelpers() {
        assertEquals("25.00%", BailoutMath.formatBps(2500))
        assertEquals("$100.00", BailoutMath.formatCents(100_00))
        assertEquals("-$1.50", BailoutMath.formatCents(-150))
    }
}
