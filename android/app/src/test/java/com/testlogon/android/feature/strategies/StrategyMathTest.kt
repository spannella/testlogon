package com.testlogon.android.feature.strategies

import com.testlogon.android.data.strategies.StrategyLeg
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure JVM tests for [StrategyMath] — NAV unit math, dual-fee accrual with a high-water mark, weight
 * validation, min-size + capacity checks, and the basket backtest helper. No Android runtime.
 */
class StrategyMathTest {

    private fun legs(vararg pairs: Pair<Int, Int>): List<StrategyLeg> =
        pairs.map { StrategyLeg(symbolId = it.first, weightBps = it.second) }

    // ---- weight validation ----

    @Test
    fun weightsValid_true_whenLegsSumTo10000() {
        assertTrue(StrategyMath.weightsValid(legs(1 to 6000, 2 to 4000)))
        assertEquals(10000, StrategyMath.totalWeightBps(legs(1 to 6000, 2 to 4000)))
    }

    @Test
    fun weightsValid_false_whenSumOff_orEmpty_orBadLeg() {
        assertFalse(StrategyMath.weightsValid(legs(1 to 6000, 2 to 3000))) // 90%
        assertFalse(StrategyMath.weightsValid(legs(1 to 6000, 2 to 5000))) // 110%
        assertFalse(StrategyMath.weightsValid(emptyList()))
        assertFalse(StrategyMath.weightsValid(legs(1 to 10000, 0 to 0))) // bad symbol/weight
    }

    // ---- NAV unit math ----

    @Test
    fun unitsForInvestment_atPar_issuesProportionalMicroUnits() {
        // $100.00 at par NAV $1.00 -> 100 units == 100_000_000 micro-units.
        assertEquals(100_000_000L, StrategyMath.unitsForInvestment(10_000L, StrategyMath.PAR_NAV_CENTS))
    }

    @Test
    fun unitsForInvestment_guardsNonPositive() {
        assertEquals(0L, StrategyMath.unitsForInvestment(0L, 100L))
        assertEquals(0L, StrategyMath.unitsForInvestment(10_000L, 0L))
    }

    @Test
    fun proceedsForUnits_roundTripsAtPar() {
        val units = StrategyMath.unitsForInvestment(50_000L, StrategyMath.PAR_NAV_CENTS)
        assertEquals(50_000L, StrategyMath.proceedsForUnits(units, StrategyMath.PAR_NAV_CENTS))
    }

    @Test
    fun proceedsForUnits_appreciatedNav_returnsMore() {
        val units = StrategyMath.unitsForInvestment(10_000L, 100L) // 100 units
        // NAV doubled to $2.00 -> redeeming the same units yields ~$200.
        assertEquals(20_000L, StrategyMath.proceedsForUnits(units, 200L))
    }

    @Test
    fun navPerUnit_freshFundPricesAtPar_thenTracksAum() {
        assertEquals(StrategyMath.PAR_NAV_CENTS, StrategyMath.navPerUnit(0L, 0L))
        val units = StrategyMath.unitsForInvestment(10_000L, StrategyMath.PAR_NAV_CENTS)
        // AUM grows to $150 on the same units -> NAV $1.50.
        assertEquals(150L, StrategyMath.navPerUnit(15_000L, units))
    }

    // ---- fee accrual ----

    @Test
    fun mgmtFeeAccrual_annualBps_proRataByDays() {
        // 2% (200 bps) annual on $10,000 AUM for a full year == $200.00 (20000 cents).
        assertEquals(20_000L, StrategyMath.mgmtFeeAccrual(1_000_000L, 200, 365.0))
        // Half a year -> ~half.
        assertEquals(10_000L, StrategyMath.mgmtFeeAccrual(1_000_000L, 200, 182.5))
        assertEquals(0L, StrategyMath.mgmtFeeAccrual(1_000_000L, 0, 365.0))
    }

    @Test
    fun perfFee_onlyAboveHighWaterMark() {
        val units = StrategyMath.unitsForInvestment(10_000L, 100L) // 100 units of $100 at par
        // NAV $1.20, HWM $1.00, 20% (2000 bps) perf fee -> profit $20 -> fee $4.00 (400 cents).
        assertEquals(400L, StrategyMath.perfFee(120L, 100L, units, 2000))
        // NAV below the HWM -> no fee.
        assertEquals(0L, StrategyMath.perfFee(90L, 100L, units, 2000))
        // NAV equal to the HWM -> no fee.
        assertEquals(0L, StrategyMath.perfFee(100L, 100L, units, 2000))
    }

    @Test
    fun highWaterMark_onlyRatchetsUp() {
        assertEquals(120L, StrategyMath.updatedHighWaterMark(100L, 120L))
        assertEquals(120L, StrategyMath.updatedHighWaterMark(120L, 110L))
    }

    // ---- size + capacity ----

    @Test
    fun meetsMinInvestment_enforcesFloor() {
        assertTrue(StrategyMath.meetsMinInvestment(10_000L, 10_000L))
        assertFalse(StrategyMath.meetsMinInvestment(9_999L, 10_000L))
        assertTrue(StrategyMath.meetsMinInvestment(500L, 0L)) // uncapped floor
        assertFalse(StrategyMath.meetsMinInvestment(0L, 0L))
    }

    @Test
    fun capacityAndWithinCapacity() {
        assertEquals(null, StrategyMath.capacityRemaining(0L, 5_000L)) // uncapped
        assertEquals(4_000L, StrategyMath.capacityRemaining(10_000L, 6_000L))
        assertEquals(0L, StrategyMath.capacityRemaining(10_000L, 12_000L)) // over cap clamps to 0
        assertTrue(StrategyMath.withinCapacity(4_000L, 10_000L, 6_000L))
        assertFalse(StrategyMath.withinCapacity(4_001L, 10_000L, 6_000L))
        assertTrue(StrategyMath.withinCapacity(1_000_000L, 0L, 0L)) // uncapped always fits
    }

    // ---- basket backtest ----

    @Test
    fun basketEquityCurve_singleLeg_tracksItsReturn() {
        val leg = StrategyMath.BacktestLeg(weightBps = 10000, closes = listOf(100.0, 110.0, 121.0))
        val curve = StrategyMath.basketEquityCurve(listOf(leg))
        assertEquals(3, curve.size)
        assertEquals(1.0, curve.first(), 1e-9)
        assertEquals(1.21, curve.last(), 1e-9)
        assertEquals(0.21, StrategyMath.totalReturn(curve), 1e-9)
    }

    @Test
    fun basketEquityCurve_twoLegs_blendsByWeight_andTruncatesToCommonLength() {
        val a = StrategyMath.BacktestLeg(weightBps = 5000, closes = listOf(100.0, 200.0, 300.0)) // +100% then +200%
        val b = StrategyMath.BacktestLeg(weightBps = 5000, closes = listOf(100.0, 100.0))        // flat, shorter
        val curve = StrategyMath.basketEquityCurve(listOf(a, b))
        // Common length is 2. Step 2: 0.5*2.0 + 0.5*1.0 = 1.5.
        assertEquals(2, curve.size)
        assertEquals(1.0, curve.first(), 1e-9)
        assertEquals(1.5, curve.last(), 1e-9)
    }

    @Test
    fun basketEquityCurve_degenerateInputs_returnsFlatCurve() {
        assertEquals(listOf(1.0), StrategyMath.basketEquityCurve(emptyList()))
        val tooShort = StrategyMath.BacktestLeg(weightBps = 10000, closes = listOf(100.0))
        assertEquals(listOf(1.0), StrategyMath.basketEquityCurve(listOf(tooShort)))
        assertEquals(0.0, StrategyMath.totalReturn(listOf(1.0)), 1e-9)
    }
}
