package com.testlogon.android.feature.tokens

import com.testlogon.android.data.tokens.TokenBid
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Unit tests for [TokenMath] — the pure math backing the creator revenue-share token surface:
 * shortfall upkeep, pro-rata upkeep share, pct_bps <-> qty, and the single-clearing-price summary.
 */
class TokenMathTest {

    // ---- upkeepAmountDue (shortfall model) ----

    @Test
    fun upkeep_shortfall_whenNoFees_isFullThreshold() {
        assertEquals(100_00L, TokenMath.upkeepAmountDue(feesGeneratedCents = 0L))
    }

    @Test
    fun upkeep_shortfall_isThresholdMinusFees() {
        assertEquals(40_00L, TokenMath.upkeepAmountDue(feesGeneratedCents = 60_00L))
    }

    @Test
    fun upkeep_shortfall_isZero_whenFeesMeetOrExceedThreshold() {
        assertEquals(0L, TokenMath.upkeepAmountDue(feesGeneratedCents = 100_00L))
        assertEquals(0L, TokenMath.upkeepAmountDue(feesGeneratedCents = 250_00L))
    }

    @Test
    fun upkeep_negativeFees_clampToFullThreshold() {
        assertEquals(100_00L, TokenMath.upkeepAmountDue(feesGeneratedCents = -5_00L))
    }

    // ---- proRataShare ----

    @Test
    fun proRata_halfHolding_isHalfCharge() {
        assertEquals(50_00L, TokenMath.proRataShare(amountDueCents = 100_00L, myQty = 500L, totalSupply = 1000L))
    }

    @Test
    fun proRata_roundsHalfUp() {
        // 100_00 * 1 / 3 = 3333.33 -> 3333
        assertEquals(3333L, TokenMath.proRataShare(amountDueCents = 100_00L, myQty = 1L, totalSupply = 3L))
    }

    @Test
    fun proRata_zeroSupplyOrQty_isZero() {
        assertEquals(0L, TokenMath.proRataShare(100_00L, myQty = 0L, totalSupply = 1000L))
        assertEquals(0L, TokenMath.proRataShare(100_00L, myQty = 100L, totalSupply = 0L))
    }

    @Test
    fun proRata_neverExceedsAmountDue() {
        assertEquals(100_00L, TokenMath.proRataShare(100_00L, myQty = 5000L, totalSupply = 1000L))
    }

    // ---- pct_bps <-> qty ----

    @Test
    fun qtyToBps_quarterHolding_is2500bps() {
        assertEquals(2500, TokenMath.qtyToBps(qty = 250L, totalSupply = 1000L))
    }

    @Test
    fun bpsToQty_roundtripsCleanPercents() {
        assertEquals(200L, TokenMath.bpsToQty(pctBps = 2000, totalSupply = 1000L))
        assertEquals(1000L, TokenMath.bpsToQty(pctBps = 10_000, totalSupply = 1000L))
        assertEquals(0L, TokenMath.bpsToQty(pctBps = 0, totalSupply = 1000L))
    }

    // ---- clearingSummary (single clearing price) ----

    @Test
    fun clearing_singlePrice_isLowestAcceptedBid() {
        val bids = listOf(
            TokenBid(sub = "a", qty = 100L, limitPrice = 300L),
            TokenBid(sub = "b", qty = 100L, limitPrice = 200L),
            TokenBid(sub = "c", qty = 100L, limitPrice = 150L), // marginal filled
        )
        val s = TokenMath.clearingSummary(bids, offeredQty = 300L, reservePrice = 100L)
        assertEquals(150L, s.clearingPrice)
        assertEquals(300L, s.filledQty)
        assertEquals(3, s.clearedBids)
    }

    @Test
    fun clearing_excessDemand_fillsHighestBidsOnly() {
        val bids = listOf(
            TokenBid(sub = "a", qty = 100L, limitPrice = 500L),
            TokenBid(sub = "b", qty = 100L, limitPrice = 400L),
            TokenBid(sub = "c", qty = 100L, limitPrice = 300L), // not reached
        )
        val s = TokenMath.clearingSummary(bids, offeredQty = 200L, reservePrice = 100L)
        assertEquals(400L, s.clearingPrice) // lowest of the two filled
        assertEquals(200L, s.filledQty)
        assertEquals(2, s.clearedBids)
    }

    @Test
    fun clearing_belowReserve_isExcluded() {
        val bids = listOf(
            TokenBid(sub = "a", qty = 100L, limitPrice = 90L), // below reserve
            TokenBid(sub = "b", qty = 100L, limitPrice = 250L),
        )
        val s = TokenMath.clearingSummary(bids, offeredQty = 300L, reservePrice = 100L)
        assertEquals(250L, s.clearingPrice)
        assertEquals(100L, s.filledQty)
        assertEquals(1, s.clearedBids)
    }

    @Test
    fun clearing_noEligibleBids_clearsNothing() {
        val bids = listOf(TokenBid(sub = "a", qty = 100L, limitPrice = 50L))
        val s = TokenMath.clearingSummary(bids, offeredQty = 100L, reservePrice = 100L)
        assertNull(s.clearingPrice)
        assertEquals(0L, s.filledQty)
        assertEquals(0, s.clearedBids)
    }

    @Test
    fun clearing_partialLastBid_countsAndCaps() {
        val bids = listOf(
            TokenBid(sub = "a", qty = 100L, limitPrice = 300L),
            TokenBid(sub = "b", qty = 100L, limitPrice = 200L), // only 50 of 100 taken
        )
        val s = TokenMath.clearingSummary(bids, offeredQty = 150L, reservePrice = 100L)
        assertEquals(200L, s.clearingPrice)
        assertEquals(150L, s.filledQty)
        assertEquals(2, s.clearedBids)
    }

    @Test
    fun formatting_centsAndBps() {
        assertEquals("$100.00", TokenMath.formatCents(100_00L))
        assertEquals("$1,234.56", TokenMath.formatCents(123456L))
        assertEquals("10.00%", TokenMath.formatBps(1000))
        assertEquals("100.00%", TokenMath.formatBps(10_000))
    }
}
