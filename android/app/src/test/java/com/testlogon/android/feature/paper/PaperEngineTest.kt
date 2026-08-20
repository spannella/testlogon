package com.testlogon.android.feature.paper

import com.testlogon.android.data.exchange.OrderSide
import com.testlogon.android.feature.paper.PaperEngine.PaperOrder
import com.testlogon.android.feature.paper.PaperEngine.PaperOrderStatus
import com.testlogon.android.feature.paper.PaperEngine.PaperOrderType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Thorough unit tests for the PURE [PaperEngine]: market fills (buy & sell), limit fills (working ->
 * triggered, buy & sell), average-cost realized PnL, weighted-average entry, short-selling, position
 * flip, cash legs, equity/unrealized marks, and cancel.
 */
class PaperEngineTest {

    private val BTC = 1
    private val ETH = 2

    private fun order(
        id: String,
        side: OrderSide,
        type: PaperOrderType,
        qty: Long,
        limitPrice: Long? = null,
        symbolId: Int = BTC,
    ) = PaperOrder(id = id, symbolId = symbolId, side = side, type = type, qty = qty, limitPrice = limitPrice)

    // ---- market fills ----

    @Test
    fun marketBuy_fillsImmediately_debitsCash_opensLong() {
        val acct = PaperEngine.newAccount(1_000_000)
        val after = PaperEngine.placeOrder(acct, order("o1", OrderSide.BUY, PaperOrderType.MARKET, 3), 100)
        val pos = after.positions.getValue(BTC)
        assertEquals(3L, pos.qty)
        assertEquals(100L, pos.avgEntry)
        assertEquals(1_000_000 - 300, after.cash)
        assertEquals(1, after.fills.size)
        assertEquals(PaperOrderStatus.FILLED, after.orders.single().status)
    }

    @Test
    fun marketSell_fromFlat_opensShort_creditsCash() {
        val acct = PaperEngine.newAccount(1_000_000)
        val after = PaperEngine.placeOrder(acct, order("s1", OrderSide.SELL, PaperOrderType.MARKET, 2), 100)
        val pos = after.positions.getValue(BTC)
        assertEquals(-2L, pos.qty)
        assertEquals(100L, pos.avgEntry)
        assertEquals(1_000_000 + 200, after.cash)
    }

    // ---- average-cost realized (round trip) ----

    @Test
    fun buyThenSellHigher_realizesProfit_flatClosesPosition() {
        var acct = PaperEngine.newAccount(1_000_000)
        acct = PaperEngine.placeOrder(acct, order("b", OrderSide.BUY, PaperOrderType.MARKET, 10), 100)
        acct = PaperEngine.placeOrder(acct, order("s", OrderSide.SELL, PaperOrderType.MARKET, 10), 130)
        // realized = (130-100)*10 = 300
        assertEquals(300L, acct.realizedPnl)
        assertNull(acct.positions[BTC])
        // cash: -1000 (buy) + 1300 (sell) = +300 over start
        assertEquals(1_000_000 + 300, acct.cash)
    }

    @Test
    fun weightedAverageEntry_acrossTwoBuys() {
        var acct = PaperEngine.newAccount(1_000_000)
        acct = PaperEngine.placeOrder(acct, order("b1", OrderSide.BUY, PaperOrderType.MARKET, 10), 100)
        acct = PaperEngine.placeOrder(acct, order("b2", OrderSide.BUY, PaperOrderType.MARKET, 30), 200)
        // avg = (10*100 + 30*200) / 40 = 7000/40 = 175
        assertEquals(175L, acct.positions.getValue(BTC).avgEntry)
        assertEquals(40L, acct.positions.getValue(BTC).qty)
    }

    @Test
    fun partialClose_realizesOnClosedQtyOnly_keepsRemainingAtSameAvg() {
        var acct = PaperEngine.newAccount(1_000_000)
        acct = PaperEngine.placeOrder(acct, order("b", OrderSide.BUY, PaperOrderType.MARKET, 10), 100)
        acct = PaperEngine.placeOrder(acct, order("s", OrderSide.SELL, PaperOrderType.MARKET, 4), 150)
        // realized on 4: (150-100)*4 = 200; remaining 6 @ avg 100
        assertEquals(200L, acct.realizedPnl)
        assertEquals(6L, acct.positions.getValue(BTC).qty)
        assertEquals(100L, acct.positions.getValue(BTC).avgEntry)
    }

    // ---- short realized ----

    @Test
    fun shortThenCoverLower_realizesProfit() {
        var acct = PaperEngine.newAccount(1_000_000)
        acct = PaperEngine.placeOrder(acct, order("s", OrderSide.SELL, PaperOrderType.MARKET, 5), 200)
        acct = PaperEngine.placeOrder(acct, order("b", OrderSide.BUY, PaperOrderType.MARKET, 5), 120)
        // short realized = (120-200)*5*(-1) = 400
        assertEquals(400L, acct.realizedPnl)
        assertNull(acct.positions[BTC])
    }

    // ---- flip ----

    @Test
    fun sellThroughLong_flipsToShort_reseedsAvgAtFill() {
        var acct = PaperEngine.newAccount(1_000_000)
        acct = PaperEngine.placeOrder(acct, order("b", OrderSide.BUY, PaperOrderType.MARKET, 10), 100)
        acct = PaperEngine.placeOrder(acct, order("s", OrderSide.SELL, PaperOrderType.MARKET, 15), 130)
        // close 10 long @ (130-100)*10 = 300 realized; residual 5 opens short @ 130
        assertEquals(300L, acct.realizedPnl)
        val pos = acct.positions.getValue(BTC)
        assertEquals(-5L, pos.qty)
        assertEquals(130L, pos.avgEntry)
    }

    // ---- limit fills via onTick ----

    @Test
    fun limitBuy_belowMarket_rests_thenFillsWhenPriceDrops() {
        var acct = PaperEngine.newAccount(1_000_000)
        // market is 100, buy limit 90 is not marketable -> works
        acct = PaperEngine.placeOrder(acct, order("lb", OrderSide.BUY, PaperOrderType.LIMIT, 5, 90), 100)
        assertTrue(acct.positions.isEmpty())
        assertEquals(PaperOrderStatus.WORKING, acct.orders.single().status)
        // price ticks down to 90 -> fills at limit 90
        acct = PaperEngine.onTick(acct, BTC, 90)
        assertEquals(5L, acct.positions.getValue(BTC).qty)
        assertEquals(90L, acct.positions.getValue(BTC).avgEntry)
        assertEquals(PaperOrderStatus.FILLED, acct.orders.single().status)
        assertEquals(1_000_000 - 450, acct.cash)
    }

    @Test
    fun limitSell_aboveMarket_rests_thenFillsWhenPriceRises() {
        var acct = PaperEngine.newAccount(1_000_000)
        acct = PaperEngine.placeOrder(acct, order("ls", OrderSide.SELL, PaperOrderType.LIMIT, 5, 110), 100)
        assertEquals(PaperOrderStatus.WORKING, acct.orders.single().status)
        acct = PaperEngine.onTick(acct, BTC, 111) // >= 110 triggers
        assertEquals(-5L, acct.positions.getValue(BTC).qty)
        assertEquals(110L, acct.positions.getValue(BTC).avgEntry) // fills at limit, not the tick
    }

    @Test
    fun marketableLimit_fillsImmediatelyAtLimit() {
        val acct = PaperEngine.newAccount(1_000_000)
        // buy limit 120 with market at 100 -> already marketable -> fills at 120
        val after = PaperEngine.placeOrder(acct, order("mb", OrderSide.BUY, PaperOrderType.LIMIT, 2, 120), 100)
        assertEquals(2L, after.positions.getValue(BTC).qty)
        assertEquals(120L, after.positions.getValue(BTC).avgEntry)
        assertEquals(PaperOrderStatus.FILLED, after.orders.single().status)
    }

    @Test
    fun onTick_onlyFillsMatchingSymbol() {
        var acct = PaperEngine.newAccount(1_000_000)
        acct = PaperEngine.placeOrder(acct, order("lb", OrderSide.BUY, PaperOrderType.LIMIT, 5, 90, symbolId = BTC), 100)
        // a tick for ETH should not touch the BTC working order
        acct = PaperEngine.onTick(acct, ETH, 50)
        assertEquals(PaperOrderStatus.WORKING, acct.orders.single().status)
        assertTrue(acct.positions.isEmpty())
    }

    // ---- cancel ----

    @Test
    fun cancel_marksWorkingOrderCancelled_leavesNoPosition() {
        var acct = PaperEngine.newAccount(1_000_000)
        acct = PaperEngine.placeOrder(acct, order("lb", OrderSide.BUY, PaperOrderType.LIMIT, 5, 90), 100)
        acct = PaperEngine.cancelOrder(acct, "lb")
        assertEquals(PaperOrderStatus.CANCELLED, acct.orders.single().status)
        // a later tick to the limit must NOT fill a cancelled order
        acct = PaperEngine.onTick(acct, BTC, 80)
        assertTrue(acct.positions.isEmpty())
    }

    @Test
    fun cancel_unknownOrFilled_isNoOp() {
        var acct = PaperEngine.newAccount(1_000_000)
        acct = PaperEngine.placeOrder(acct, order("b", OrderSide.BUY, PaperOrderType.MARKET, 1), 100)
        val same = PaperEngine.cancelOrder(acct, "b")     // already filled
        assertEquals(acct, same)
        val same2 = PaperEngine.cancelOrder(acct, "nope") // unknown
        assertEquals(acct, same2)
    }

    // ---- equity / unrealized ----

    @Test
    fun equityAndUnrealized_markLong() {
        var acct = PaperEngine.newAccount(1_000_000)
        acct = PaperEngine.placeOrder(acct, order("b", OrderSide.BUY, PaperOrderType.MARKET, 10), 100)
        // cash 999_000, position 10 @ 100. Mark 150 -> unrealized (150-100)*10 = 500
        val marks = mapOf(BTC to 150L)
        assertEquals(500L, PaperEngine.unrealized(acct, marks))
        // equity = cash + qty*mark = 999_000 + 10*150 = 1_000_500
        assertEquals(1_000_500L, PaperEngine.equity(acct, marks))
    }

    @Test
    fun unrealized_short_profitsAsMarkFalls() {
        var acct = PaperEngine.newAccount(1_000_000)
        acct = PaperEngine.placeOrder(acct, order("s", OrderSide.SELL, PaperOrderType.MARKET, 4), 200)
        // short 4 @ 200. Mark 150 -> unrealized (150-200)*(-4) = 200
        assertEquals(200L, PaperEngine.unrealized(acct, mapOf(BTC to 150L)))
    }

    @Test
    fun equity_missingMark_usesCostBasis_noJump() {
        var acct = PaperEngine.newAccount(1_000_000)
        acct = PaperEngine.placeOrder(acct, order("b", OrderSide.BUY, PaperOrderType.MARKET, 10), 100)
        // no mark provided -> position valued at cost basis; equity == startingCash
        assertEquals(1_000_000L, PaperEngine.equity(acct, emptyMap()))
        assertEquals(0L, PaperEngine.unrealized(acct, emptyMap()))
    }

    @Test
    fun zeroQtyOrder_ignored() {
        val acct = PaperEngine.newAccount(1_000_000)
        val after = PaperEngine.placeOrder(acct, order("z", OrderSide.BUY, PaperOrderType.MARKET, 0), 100)
        assertEquals(acct, after)
    }
}
