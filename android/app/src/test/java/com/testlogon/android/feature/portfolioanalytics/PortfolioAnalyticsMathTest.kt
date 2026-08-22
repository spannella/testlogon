package com.testlogon.android.feature.portfolioanalytics

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-math coverage for [PortfolioAnalyticsMath]: allocation/concentration/exposure plus the risk
 * combinators (portfolio vol, parametric + historical VaR, diversification). Every edge case
 * (empty / single / zero-equity / hedged / degenerate matrix) is pinned so the ViewModel can lean on
 * these without re-guarding.
 */
class PortfolioAnalyticsMathTest {

    private fun pos(
        key: String,
        valueCents: Long,
        group: String = "Spot",
        assetClass: String = "Crypto",
        side: PositionSide = PositionSide.LONG,
    ) = NormalizedPosition(key = key, label = key, group = group, assetClass = assetClass, valueCents = valueCents, side = side)

    // ---------------- allocation ----------------

    @Test
    fun allocation_byAsset_weightsSumTo10000() {
        val positions = listOf(pos("BTC", 6_000), pos("ETH", 4_000))
        val slices = PortfolioAnalyticsMath.allocation(positions, AllocationBy.ASSET)
        assertEquals(2, slices.size)
        assertEquals("BTC", slices.first().key)
        assertEquals(6_000, slices.first().weightBps)
        assertEquals(4_000, slices[1].weightBps)
        assertEquals(10_000, slices.sumOf { it.weightBps })
    }

    @Test
    fun allocation_byClass_bucketsAcrossKeys() {
        val positions = listOf(
            pos("BTC", 5_000, assetClass = "Crypto"),
            pos("ETH", 3_000, assetClass = "Crypto"),
            pos("USD", 2_000, assetClass = "Cash"),
        )
        val slices = PortfolioAnalyticsMath.allocation(positions, AllocationBy.CLASS)
        assertEquals(2, slices.size)
        val crypto = slices.single { it.key == "Crypto" }
        assertEquals(8_000, crypto.valueCents)
        assertEquals(8_000, crypto.weightBps)
    }

    @Test
    fun allocation_byProduct_buckets() {
        val positions = listOf(
            pos("BTC", 5_000, group = "Spot"),
            pos("BTC", 5_000, group = "Custody"),
        )
        val slices = PortfolioAnalyticsMath.allocation(positions, AllocationBy.PRODUCT)
        assertEquals(2, slices.size)
        assertEquals(5_000, slices.first().weightBps)
    }

    @Test
    fun allocation_empty_isEmpty() {
        assertTrue(PortfolioAnalyticsMath.allocation(emptyList(), AllocationBy.ASSET).isEmpty())
    }

    @Test
    fun allocation_zeroTotal_noDivideByZero() {
        val slices = PortfolioAnalyticsMath.allocation(listOf(pos("BTC", 0)), AllocationBy.ASSET)
        assertEquals(1, slices.size)
        assertEquals(0, slices.first().weightBps)
    }

    // ---------------- concentration ----------------

    @Test
    fun concentration_singleHolding_maxHhi() {
        val slices = PortfolioAnalyticsMath.allocation(listOf(pos("BTC", 1_000)), AllocationBy.ASSET)
        val c = PortfolioAnalyticsMath.concentration(slices)
        assertEquals(10_000, c.hhi)
        assertEquals(10_000, c.topWeightBps)
        assertEquals("BTC", c.topKey)
    }

    @Test
    fun concentration_equalHoldings_lowHhi() {
        val positions = (1..10).map { pos("A$it", 1_000) }
        val slices = PortfolioAnalyticsMath.allocation(positions, AllocationBy.ASSET)
        val c = PortfolioAnalyticsMath.concentration(slices, topN = 3)
        // 10 equal 1000-bps holdings -> HHI = 10 * 0.1^2 = 0.1 -> 1000 index.
        assertEquals(1_000, c.hhi)
        assertEquals(3_000, c.topNCumulativeBps)
        assertTrue(c.effectiveBets > 9.0)
    }

    @Test
    fun concentration_empty_zeroed() {
        val c = PortfolioAnalyticsMath.concentration(emptyList())
        assertEquals(0, c.hhi)
        assertNull(c.topKey)
        assertEquals(0.0, c.effectiveBets, 0.0)
    }

    // ---------------- exposure ----------------

    @Test
    fun exposure_longOnly() {
        val e = PortfolioAnalyticsMath.exposure(listOf(pos("BTC", 6_000), pos("ETH", 4_000)))
        assertEquals(10_000, e.grossCents)
        assertEquals(10_000, e.netCents)
        assertEquals(10_000, e.longCents)
        assertEquals(0, e.shortCents)
        assertEquals(10_000, e.leverageBps) // gross/|net| = 1.0x
    }

    @Test
    fun exposure_longShort_netAndLeverage() {
        val e = PortfolioAnalyticsMath.exposure(
            listOf(pos("BTC", 8_000, side = PositionSide.LONG), pos("ETH", 2_000, side = PositionSide.SHORT)),
        )
        assertEquals(10_000, e.grossCents)
        assertEquals(6_000, e.netCents)
        assertEquals(8_000, e.longCents)
        assertEquals(2_000, e.shortCents)
        // gross 10000 / net 6000 = 1.6667x -> ~16667 bps
        assertTrue(e.leverageBps in 16_600..16_700)
    }

    @Test
    fun exposure_perfectlyHedged_zeroLeverage() {
        val e = PortfolioAnalyticsMath.exposure(
            listOf(pos("BTC", 5_000, side = PositionSide.LONG), pos("BTC", 5_000, side = PositionSide.SHORT)),
        )
        assertEquals(0, e.netCents)
        assertEquals(0, e.leverageBps)
    }

    @Test
    fun exposure_empty_allZero() {
        val e = PortfolioAnalyticsMath.exposure(emptyList())
        assertEquals(0, e.grossCents)
        assertEquals(0, e.leverageBps)
    }

    // ---------------- portfolio volatility ----------------

    @Test
    fun portfolioVol_singleAsset_returnsOwnVol() {
        val v = PortfolioAnalyticsMath.portfolioVolatilityBps(listOf(10_000), listOf(5_000))
        assertEquals(5_000, v)
    }

    @Test
    fun portfolioVol_independent_lessThanWeightedSum() {
        // Two 50/50 assets, each 40% vol, uncorrelated (no matrix -> rho=0).
        val v = PortfolioAnalyticsMath.portfolioVolatilityBps(listOf(5_000, 5_000), listOf(4_000, 4_000))
        assertNotNull(v)
        // sqrt(0.5^2*0.4^2 + 0.5^2*0.4^2) = 0.2828 -> ~2828 bps, well under 4000.
        assertTrue(v!! in 2_700..2_900)
    }

    @Test
    fun portfolioVol_perfectlyCorrelated_equalsWeightedSum() {
        val corr = listOf(listOf(1.0, 1.0), listOf(1.0, 1.0))
        val v = PortfolioAnalyticsMath.portfolioVolatilityBps(listOf(5_000, 5_000), listOf(4_000, 4_000), corr)
        // rho=1 -> vol = 0.5*0.4 + 0.5*0.4 = 0.4 -> 4000 bps.
        assertEquals(4_000, v)
    }

    @Test
    fun portfolioVol_empty_null() {
        assertNull(PortfolioAnalyticsMath.portfolioVolatilityBps(emptyList(), emptyList()))
    }

    // ---------------- VaR ----------------

    @Test
    fun parametricVar_computesLoss() {
        // $10,000 (1_000_000 cents) at 20% vol, z=1.645 -> ~329,000 cents.
        val v = PortfolioAnalyticsMath.parametricVarCents(1_000_000, 2_000, 1.645)
        assertEquals(329_000, v)
    }

    @Test
    fun parametricVar_zeroInputs_zero() {
        assertEquals(0L, PortfolioAnalyticsMath.parametricVarCents(0, 2_000, 1.645))
        assertEquals(0L, PortfolioAnalyticsMath.parametricVarCents(1_000_000, 0, 1.645))
    }

    @Test
    fun historicalVar_quantileLoss() {
        // 20 returns; worst is -0.10. At 95% the (1-.95)*20 = index 1 -> -0.08.
        val returns = listOf(-0.10, -0.08) + List(18) { 0.01 }
        val v = PortfolioAnalyticsMath.historicalVarCents(1_000_000, returns, 0.95)
        assertEquals(80_000, v)
    }

    @Test
    fun historicalVar_tooFewReturns_zero() {
        assertEquals(0L, PortfolioAnalyticsMath.historicalVarCents(1_000_000, listOf(-0.05), 0.95))
    }

    @Test
    fun historicalVar_allPositive_zero() {
        val v = PortfolioAnalyticsMath.historicalVarCents(1_000_000, listOf(0.01, 0.02, 0.03, 0.04), 0.95)
        assertEquals(0L, v)
    }

    // ---------------- diversification ----------------

    @Test
    fun diversification_singleHolding_zero() {
        assertEquals(0, PortfolioAnalyticsMath.diversificationScore(listOf(10_000)))
    }

    @Test
    fun diversification_manyEqualUncorrelated_high() {
        val weights = List(5) { 2_000 }
        val score = PortfolioAnalyticsMath.diversificationScore(weights)
        assertTrue("expected high score, got $score", score >= 90)
    }

    @Test
    fun diversification_correlatedPair_lowerThanUncorrelated() {
        val weights = listOf(5_000, 5_000)
        val uncorr = PortfolioAnalyticsMath.diversificationScore(weights)
        val corr = PortfolioAnalyticsMath.diversificationScore(
            weights, listOf(listOf(1.0, 0.95), listOf(0.95, 1.0)),
        )
        assertTrue("corr $corr should be < uncorr $uncorr", corr < uncorr)
    }

    @Test
    fun diversification_empty_zero() {
        assertEquals(0, PortfolioAnalyticsMath.diversificationScore(emptyList()))
    }
}
