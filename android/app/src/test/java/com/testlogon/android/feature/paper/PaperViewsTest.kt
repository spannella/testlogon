package com.testlogon.android.feature.paper

import com.testlogon.android.data.exchange.OrderSide
import com.testlogon.android.feature.blotter.BlotterSide
import com.testlogon.android.feature.blotter.BlotterStatus
import com.testlogon.android.feature.paper.PaperEngine.PaperOrder
import com.testlogon.android.feature.paper.PaperEngine.PaperOrderType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for the PURE [PaperViews] adapters that project a shared [PaperEngine.PaperAccount] into
 * the read-only Blotter / PnL / Portfolio render shapes when paper mode is ON. Builds a small account
 * by driving the engine, then asserts the projected rows/stats.
 */
class PaperViewsTest {

    private val BTC = 1
    private val ETH = 2
    private val names = mapOf(BTC to "BTCUSDC", ETH to "ETHUSDC")

    private fun order(
        id: String,
        side: OrderSide,
        type: PaperOrderType,
        qty: Long,
        limitPrice: Long? = null,
        symbolId: Int = BTC,
    ) = PaperOrder(id = id, symbolId = symbolId, side = side, type = type, qty = qty, limitPrice = limitPrice)

    /** Buy 2 @100 (market fill), sell 1 @150 (realizes +50 on the closed unit), leaving 1 long @100. */
    private fun sampleAccount(): PaperEngine.PaperAccount {
        var acct = PaperEngine.newAccount(1_000_000)
        acct = PaperEngine.placeOrder(acct, order("o1", OrderSide.BUY, PaperOrderType.MARKET, 2), 100)
        acct = PaperEngine.placeOrder(acct, order("o2", OrderSide.SELL, PaperOrderType.MARKET, 1), 150)
        return acct
    }

    // ---- Blotter -----------------------------------------------------------

    @Test
    fun blotterOrders_projectsFilledMarketOrders_withLiveMarkAsPx() {
        val acct = sampleAccount()
        val marks = mapOf(BTC to 120L)
        val rows = PaperViews.blotterOrders(acct, marks, names)
        assertEquals(2, rows.size)
        val buy = rows.first { it.clord == "o1" }
        assertEquals("BTCUSDC", buy.sym)
        assertEquals(BlotterSide.BUY, buy.side)
        assertEquals(BlotterStatus.FILLED, buy.status)
        assertEquals(2.0, buy.qty, 1e-9)
        assertEquals(2.0, buy.cumQty, 1e-9)   // fully executed
        assertEquals(0.0, buy.leaves, 1e-9)
        assertEquals(100.0, buy.avgPx, 1e-9)  // true fill basis
        assertEquals(120.0, buy.px, 1e-9)     // live mark drives px
    }

    @Test
    fun blotterOrders_workingLimit_isLiveWithFullLeaves() {
        var acct = PaperEngine.newAccount(1_000_000)
        // Non-marketable buy limit (limit 90 < market 100) rests as WORKING.
        acct = PaperEngine.placeOrder(acct, order("w1", OrderSide.BUY, PaperOrderType.LIMIT, 5, limitPrice = 90), 100)
        val rows = PaperViews.blotterOrders(acct, emptyMap(), names)
        val w = rows.single()
        assertEquals(BlotterStatus.LIVE, w.status)
        assertEquals(5.0, w.leaves, 1e-9)
        assertEquals(0.0, w.cumQty, 1e-9)
        // No live mark -> px falls back to the limit price.
        assertEquals(90.0, w.px, 1e-9)
    }

    // ---- PnL ---------------------------------------------------------------

    @Test
    fun pnlStats_realizedUnrealizedAndCounts() {
        val acct = sampleAccount()
        val marks = mapOf(BTC to 130L)
        val stats = PaperViews.pnlStats(acct, marks)
        assertEquals(50L, stats.netRealized)          // closed 1 unit @ +50
        assertEquals(30L, stats.unrealized)           // 1 long @100 marked 130
        assertEquals(0L, stats.totalFees)
        assertEquals(2, stats.tradeCount)             // two fills
        assertEquals(1, stats.closingTradeCount)      // the sell closed
        assertTrue(stats.winRate > 0.99f)             // the one closing trade won
        // volume = |2|*100 + |1|*150 = 350
        assertEquals(350L, stats.volume)
    }

    @Test
    fun pnlBySymbol_splitsPerSymbol() {
        var acct = sampleAccount()
        // Add an ETH round-trip: buy 3 @50, sell 3 @40 -> realized -30.
        acct = PaperEngine.placeOrder(acct, order("e1", OrderSide.BUY, PaperOrderType.MARKET, 3, symbolId = ETH), 50)
        acct = PaperEngine.placeOrder(acct, order("e2", OrderSide.SELL, PaperOrderType.MARKET, 3, symbolId = ETH), 40)
        val rows = PaperViews.pnlBySymbol(acct, names)
        val btc = rows.first { it.symbol == "BTCUSDC" }
        val eth = rows.first { it.symbol == "ETHUSDC" }
        assertEquals(50L, btc.realized)
        assertEquals(-30L, eth.realized)
        assertEquals(0L, btc.fees)
    }

    // ---- Portfolio ---------------------------------------------------------

    @Test
    fun portfolioPositions_openPositionMarkedToMarket() {
        val acct = sampleAccount()
        val marks = mapOf(BTC to 200L)
        val pos = PaperViews.portfolioPositions(acct, marks, names).single()
        assertEquals("BTCUSDC", pos.symbol)
        assertEquals(1L, pos.qty)            // 1 long remains
        assertEquals(100L, pos.entryPrice)
        assertEquals(0L, pos.liquidationPrice)
        assertEquals(100L, pos.unrealizedPnl) // (200-100)*1
        assertTrue(pos.isLong)
        assertTrue(pos.isProfit)
    }

    @Test
    fun portfolioPositions_noMark_zeroUpl() {
        val acct = sampleAccount()
        val pos = PaperViews.portfolioPositions(acct, emptyMap(), names).single()
        assertEquals(0L, pos.unrealizedPnl)  // no mark -> not fabricated
    }
}
