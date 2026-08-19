package com.testlogon.android.feature.markets.trade

import com.testlogon.android.data.exchange.OrderSide
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Unit tests for [OrderMath] — the pure order-entry math behind the ticket preview, buying-power sizing,
 * and the risk calculator. All values are raw int64 ticks (scaler = 1).
 */
class OrderMathTest {

    // ---- notional ----

    @Test fun notional_multiplies() = assertEquals(200L, OrderMath.notional(100L, 2L))

    @Test fun notional_nullWhenAnyMissing() {
        assertNull(OrderMath.notional(null, 2L))
        assertNull(OrderMath.notional(100L, null))
    }

    @Test fun notional_zeroQtyIsZero() = assertEquals(0L, OrderMath.notional(100L, 0L))

    // ---- maxQtyForBalance ----

    @Test fun maxQty_floorsToWholeUnits() {
        // 1050 / 100 = 10 (floors the .5)
        assertEquals(10L, OrderMath.maxQtyForBalance(1050L, 100L))
    }

    @Test fun maxQty_exactDivision() = assertEquals(5L, OrderMath.maxQtyForBalance(500L, 100L))

    @Test fun maxQty_zeroWhenUnaffordable() = assertEquals(0L, OrderMath.maxQtyForBalance(50L, 100L))

    @Test fun maxQty_guardsNonPositiveAndNull() {
        assertEquals(0L, OrderMath.maxQtyForBalance(1000L, 0L))
        assertEquals(0L, OrderMath.maxQtyForBalance(0L, 100L))
        assertEquals(0L, OrderMath.maxQtyForBalance(null, 100L))
        assertEquals(0L, OrderMath.maxQtyForBalance(1000L, null))
        assertEquals(0L, OrderMath.maxQtyForBalance(-10L, 100L))
    }

    // ---- qtyForPercent ----

    @Test fun qtyPercent_fractionsOfMax() {
        // max = 1000/100 = 10
        assertEquals(2L, OrderMath.qtyForPercent(1000L, 100L, 25))  // 2.5 -> floor 2
        assertEquals(5L, OrderMath.qtyForPercent(1000L, 100L, 50))
        assertEquals(10L, OrderMath.qtyForPercent(1000L, 100L, 100))
    }

    @Test fun qtyPercent_positivePctFloorsToOne() {
        // max = 3, 25% = 0.75 -> floors to 0 -> bumped to 1 because pct > 0
        assertEquals(1L, OrderMath.qtyForPercent(300L, 100L, 25))
    }

    @Test fun qtyPercent_zeroPctStaysZero() = assertEquals(0L, OrderMath.qtyForPercent(1000L, 100L, 0))

    @Test fun qtyPercent_zeroWhenNoBuyingPower() = assertEquals(0L, OrderMath.qtyForPercent(50L, 100L, 100))

    // ---- riskSizedQty ----

    @Test fun riskSized_dividesRiskByStopDistance() {
        // risk 1000, entry 100, stop 90 -> dist 10 -> 100 units
        assertEquals(100L, OrderMath.riskSizedQty(1000L, 100L, 90L))
    }

    @Test fun riskSized_stopAboveEntry_usesAbsDistance() {
        // short case: entry 100, stop 105 -> dist 5 -> 1000/5 = 200
        assertEquals(200L, OrderMath.riskSizedQty(1000L, 100L, 105L))
    }

    @Test fun riskSized_floorsPartialUnit() {
        // risk 1000, dist 30 -> 33.3 -> floor 33
        assertEquals(33L, OrderMath.riskSizedQty(1000L, 100L, 130L))
    }

    @Test fun riskSized_zeroWhenEntryEqualsStop() = assertEquals(0L, OrderMath.riskSizedQty(1000L, 100L, 100L))

    @Test fun riskSized_guardsNonPositiveAndNull() {
        assertEquals(0L, OrderMath.riskSizedQty(0L, 100L, 90L))
        assertEquals(0L, OrderMath.riskSizedQty(-5L, 100L, 90L))
        assertEquals(0L, OrderMath.riskSizedQty(null, 100L, 90L))
        assertEquals(0L, OrderMath.riskSizedQty(1000L, null, 90L))
        assertEquals(0L, OrderMath.riskSizedQty(1000L, 100L, null))
    }

    // ---- marginRequired ----

    @Test fun margin_appliesBps() {
        // notional 10000 at 1000 bps (10%) = 1000
        assertEquals(1000L, OrderMath.marginRequired(10000L, 1000L))
    }

    @Test fun margin_roundsToNearestTick() {
        // 10005 * 500 / 10000 = 500.25 -> 500
        assertEquals(500L, OrderMath.marginRequired(10005L, 500L))
    }

    @Test fun margin_zeroGuards() {
        assertEquals(0L, OrderMath.marginRequired(null, 1000L))
        assertEquals(0L, OrderMath.marginRequired(0L, 1000L))
        assertEquals(0L, OrderMath.marginRequired(10000L, 0L))
    }

    // ---- estLiquidationPrice ----

    @Test fun liq_long_belowEntry() {
        // entry 100, mmr 500 bps (5%) -> 100 * 0.95 = 95
        assertEquals(95L, OrderMath.estLiquidationPrice(100L, OrderSide.BUY, 500L))
    }

    @Test fun liq_short_aboveEntry() {
        // entry 100, mmr 500 bps -> 100 * 1.05 = 105
        assertEquals(105L, OrderMath.estLiquidationPrice(100L, OrderSide.SELL, 500L))
    }

    @Test fun liq_nullWhenEntryNonPositive() {
        assertNull(OrderMath.estLiquidationPrice(null, OrderSide.BUY, 500L))
        assertNull(OrderMath.estLiquidationPrice(0L, OrderSide.BUY, 500L))
    }

    @Test fun liq_nullWhenNoMaintenanceBps() {
        assertNull(OrderMath.estLiquidationPrice(100L, OrderSide.BUY, 0L))
    }

    @Test fun liq_defaultsAreSane() {
        assertEquals(1000L, OrderMath.DEFAULT_INITIAL_MARGIN_BPS)
        assertEquals(500L, OrderMath.DEFAULT_MAINTENANCE_MARGIN_BPS)
    }
}
