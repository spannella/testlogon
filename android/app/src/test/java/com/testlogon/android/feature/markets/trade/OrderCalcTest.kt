package com.testlogon.android.feature.markets.trade

import com.testlogon.android.data.exchange.OrderSide
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for [OrderCalc] — the pure order-entry depth math (position sizing, risk:reward, break-even,
 * est. liquidation, TWAP schedule + Iceberg clips). All values are raw int64 ticks (scaler = 1).
 */
class OrderCalcTest {

    // ---- positionSizeQty ----

    @Test fun positionSize_basic() {
        // equity 100_000, risk 2% = 2_000; stop distance 100 -> 20 units
        assertEquals(20L, OrderCalc.positionSizeQty(100_000L, 2, 1_000L, 900L))
    }

    @Test fun positionSize_floorsToWhole() {
        // risk 2_000 / distance 150 = 13.33 -> 13
        assertEquals(13L, OrderCalc.positionSizeQty(100_000L, 2, 1_000L, 850L))
    }

    @Test fun positionSize_zeroWhenEntryEqualsStop() =
        assertEquals(0L, OrderCalc.positionSizeQty(100_000L, 2, 1_000L, 1_000L))

    @Test fun positionSize_guardsNullsAndNonPositive() {
        assertEquals(0L, OrderCalc.positionSizeQty(null, 2, 1_000L, 900L))
        assertEquals(0L, OrderCalc.positionSizeQty(100_000L, 2, null, 900L))
        assertEquals(0L, OrderCalc.positionSizeQty(100_000L, 2, 1_000L, null))
        assertEquals(0L, OrderCalc.positionSizeQty(0L, 2, 1_000L, 900L))
        assertEquals(0L, OrderCalc.positionSizeQty(100_000L, 0, 1_000L, 900L))
        assertEquals(0L, OrderCalc.positionSizeQty(100_000L, -5, 1_000L, 900L))
    }

    @Test fun positionSize_tinyRiskRoundsToZero() =
        // equity 100, 1% = 1; distance 100 -> 0 units (floors)
        assertEquals(0L, OrderCalc.positionSizeQty(100L, 1, 1_000L, 900L))

    // ---- riskReward ----

    @Test fun riskReward_twoToOne() {
        val rr = OrderCalc.riskReward(entry = 1_000L, stop = 900L, takeProfit = 1_200L)!!
        assertEquals(100L, rr.risk)
        assertEquals(200L, rr.reward)
        assertEquals(2.0, rr.ratio, 1e-9)
    }

    @Test fun riskReward_shortSide() {
        // short: entry 1000, stop 1100 (risk 100), tp 800 (reward 200)
        val rr = OrderCalc.riskReward(entry = 1_000L, stop = 1_100L, takeProfit = 800L)!!
        assertEquals(100L, rr.risk)
        assertEquals(200L, rr.reward)
        assertEquals(2.0, rr.ratio, 1e-9)
    }

    @Test fun riskReward_nullWhenLegMissing() {
        assertNull(OrderCalc.riskReward(null, 900L, 1_200L))
        assertNull(OrderCalc.riskReward(1_000L, null, 1_200L))
        assertNull(OrderCalc.riskReward(1_000L, 900L, null))
    }

    @Test fun riskReward_nullWhenRiskZero() =
        assertNull(OrderCalc.riskReward(1_000L, 1_000L, 1_200L))

    // ---- liquidationPreview ----

    @Test fun liquidation_longBelowEntry() {
        // 5% mmr -> long liquidates at 1000 * 0.95 = 950
        assertEquals(950L, OrderCalc.liquidationPreview(1_000L, OrderSide.BUY, 500L))
    }

    @Test fun liquidation_shortAboveEntry() {
        // 5% mmr -> short liquidates at 1000 * 1.05 = 1050
        assertEquals(1_050L, OrderCalc.liquidationPreview(1_000L, OrderSide.SELL, 500L))
    }

    @Test fun liquidation_nullWhenEntryNonPositive() {
        assertNull(OrderCalc.liquidationPreview(0L, OrderSide.BUY, 500L))
        assertNull(OrderCalc.liquidationPreview(null, OrderSide.BUY, 500L))
    }

    // ---- breakevenPrice ----

    @Test fun breakeven_longAboveEntry() {
        // 10 bps -> drag 2*10/10000 = 0.002 ; 1000 * 1.002 = 1002
        assertEquals(1_002L, OrderCalc.breakevenPrice(1_000L, OrderSide.BUY, 10L))
    }

    @Test fun breakeven_shortBelowEntry() {
        // 1000 * 0.998 = 998
        assertEquals(998L, OrderCalc.breakevenPrice(1_000L, OrderSide.SELL, 10L))
    }

    @Test fun breakeven_zeroFeeIsEntry() =
        assertEquals(1_000L, OrderCalc.breakevenPrice(1_000L, OrderSide.BUY, 0L))

    @Test fun breakeven_nullWhenEntryNonPositive() {
        assertNull(OrderCalc.breakevenPrice(0L, OrderSide.BUY, 10L))
        assertNull(OrderCalc.breakevenPrice(null, OrderSide.SELL, 10L))
    }

    // ---- twapSchedule ----

    @Test fun twap_evenSplitSumsToTotal() {
        val s = OrderCalc.twapSchedule(100L, 4, 60_000L)
        assertEquals(4, s.size)
        assertEquals(100L, s.sumOf { it.qty })
        s.forEach { assertEquals(25L, it.qty) }
    }

    @Test fun twap_remainderOnEarliestSlices() {
        // 10 over 3 -> base 3, remainder 1 -> [4,3,3]
        val s = OrderCalc.twapSchedule(10L, 3, 30_000L)
        assertEquals(listOf(4L, 3L, 3L), s.map { it.qty })
        assertEquals(10L, s.sumOf { it.qty })
    }

    @Test fun twap_offsetsAreEvenlySpacedFromZero() {
        val s = OrderCalc.twapSchedule(4L, 4, 40_000L)
        assertEquals(listOf(0L, 10_000L, 20_000L, 30_000L), s.map { it.offsetMs })
    }

    @Test fun twap_emptyForDegenerate() {
        assertTrue(OrderCalc.twapSchedule(0L, 4, 1000L).isEmpty())
        assertTrue(OrderCalc.twapSchedule(100L, 0, 1000L).isEmpty())
        assertTrue(OrderCalc.twapSchedule(-5L, 4, 1000L).isEmpty())
        // more slices than qty would create zero-qty children -> empty
        assertTrue(OrderCalc.twapSchedule(3L, 4, 1000L).isEmpty())
    }

    @Test fun twap_negativeDurationClampsToImmediate() {
        val s = OrderCalc.twapSchedule(4L, 2, -100L)
        assertEquals(2, s.size)
        s.forEach { assertEquals(0L, it.offsetMs) }
        assertEquals(4L, s.sumOf { it.qty })
    }

    @Test fun twap_singleSliceIsWholeQty() {
        val s = OrderCalc.twapSchedule(50L, 1, 10_000L)
        assertEquals(1, s.size)
        assertEquals(50L, s.single().qty)
        assertEquals(0L, s.single().offsetMs)
    }

    // ---- icebergClips ----

    @Test fun iceberg_splitsWithRemainderLast() {
        assertEquals(listOf(30L, 30L, 30L, 10L), OrderCalc.icebergClips(100L, 30L))
    }

    @Test fun iceberg_exactMultiple() {
        assertEquals(listOf(25L, 25L, 25L, 25L), OrderCalc.icebergClips(100L, 25L))
    }

    @Test fun iceberg_visibleExceedsTotalIsSingleClip() =
        assertEquals(listOf(50L), OrderCalc.icebergClips(50L, 200L))

    @Test fun iceberg_emptyForDegenerate() {
        assertTrue(OrderCalc.icebergClips(0L, 30L).isEmpty())
        assertTrue(OrderCalc.icebergClips(100L, 0L).isEmpty())
        assertTrue(OrderCalc.icebergClips(-5L, 30L).isEmpty())
    }

    @Test fun iceberg_sumEqualsTotal() {
        val clips = OrderCalc.icebergClips(97L, 20L)
        assertEquals(97L, clips.sum())
    }
}
