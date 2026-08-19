package com.testlogon.android.feature.pnl

import com.testlogon.android.data.exchange.FillFee
import com.testlogon.android.data.exchange.FillsFees
import com.testlogon.android.data.exchange.FundingPayment
import com.testlogon.android.data.exchange.FundingPayments
import com.testlogon.android.data.exchange.Liquidation
import com.testlogon.android.data.exchange.Liquidations
import com.testlogon.android.data.exchange.Liquidity
import com.testlogon.android.data.exchange.OrderSide
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for the PURE [PnlAnalytics]. Covers the average-cost realized walk (a simple round-trip
 * close, a weighted-average entry across two buys, a position flip), the win-rate denominator (closing
 * trades only), the net roll-up folding fees/funding/liquidations, and the cumulative equity curve.
 */
class PnlAnalyticsTest {

    private fun fill(
        symbolId: Int,
        side: OrderSide,
        price: Long,
        qty: Long,
        fee: Long = 0L,
        tsNs: Long,
    ) = FillFee(
        symbolId = symbolId,
        price = price,
        qty = qty,
        side = side,
        liquidity = Liquidity.TAKER,
        fee = fee,
        feeAsset = 0,
        tsNs = tsNs,
    )

    private fun fills(vararg f: FillFee) = FillsFees(f.toList(), f.size)

    // ---- average-cost realized ----

    @Test
    fun `simple round-trip close realizes price difference`() {
        // Buy 10 @ 100, sell 10 @ 120 -> (120-100)*10 = 200 realized, one closing (winning) trade.
        val report = PnlAnalytics.analyze(
            fills(
                fill(1, OrderSide.BUY, 100, 10, tsNs = 1),
                fill(1, OrderSide.SELL, 120, 10, tsNs = 2),
            ),
            Liquidations(emptyList(), 0),
            FundingPayments(emptyList(), 0),
            unrealizedPnl = 0,
        )
        val sym = report.bySymbol.single()
        assertEquals(200L, sym.realized)
        assertEquals(1, sym.closingTrades)
        assertEquals(1, sym.winningTrades)
        assertEquals(200L, report.netRealized)
        assertEquals(1f, report.winRate, 0.0001f)
    }

    @Test
    fun `weighted average entry across two buys before a close`() {
        // Buy 10 @ 100, buy 10 @ 200 -> avg entry 150; sell 20 @ 160 -> (160-150)*20 = 200.
        val rows = PnlAnalytics.realizedBySymbol(
            listOf(
                fill(1, OrderSide.BUY, 100, 10, tsNs = 1),
                fill(1, OrderSide.BUY, 200, 10, tsNs = 2),
                fill(1, OrderSide.SELL, 160, 20, tsNs = 3),
            ),
        )
        assertEquals(200L, rows.single().realized)
        assertEquals(1, rows.single().closingTrades)
    }

    @Test
    fun `short round-trip realizes when covering below entry`() {
        // Sell 5 @ 100 (open short), buy 5 @ 90 (cover) -> (90-100)*5*(-1) = 50 profit.
        val rows = PnlAnalytics.realizedBySymbol(
            listOf(
                fill(1, OrderSide.SELL, 100, 5, tsNs = 1),
                fill(1, OrderSide.BUY, 90, 5, tsNs = 2),
            ),
        )
        assertEquals(50L, rows.single().realized)
        assertEquals(1, rows.single().winningTrades)
    }

    @Test
    fun `position flip closes then re-seeds entry at fill price`() {
        // Buy 10 @ 100, sell 15 @ 120: closes 10 (+200), flips to short 5 @ 120 (no further realize).
        val rows = PnlAnalytics.realizedBySymbol(
            listOf(
                fill(1, OrderSide.BUY, 100, 10, tsNs = 1),
                fill(1, OrderSide.SELL, 120, 15, tsNs = 2),
            ),
        )
        assertEquals(200L, rows.single().realized)
        assertEquals(1, rows.single().closingTrades)
    }

    // ---- win rate ----

    @Test
    fun `win rate counts only closing trades`() {
        // sym1: one winning close. sym2: one losing close. Opening buys are not closing trades.
        val report = PnlAnalytics.analyze(
            fills(
                fill(1, OrderSide.BUY, 100, 10, tsNs = 1),
                fill(1, OrderSide.SELL, 110, 10, tsNs = 2), // +100 win
                fill(2, OrderSide.BUY, 100, 10, tsNs = 3),
                fill(2, OrderSide.SELL, 90, 10, tsNs = 4), // -100 loss
            ),
            Liquidations(emptyList(), 0),
            FundingPayments(emptyList(), 0),
            unrealizedPnl = 0,
        )
        assertEquals(2, report.closingTradeCount)
        assertEquals(0.5f, report.winRate, 0.0001f)
    }

    // ---- net roll-up ----

    @Test
    fun `net realized folds fees funding and liquidations`() {
        // realized 200, fees 5+5=10, funding +30, liq realized -40 with fee 3.
        val report = PnlAnalytics.analyze(
            fills(
                fill(1, OrderSide.BUY, 100, 10, fee = 5, tsNs = 1),
                fill(1, OrderSide.SELL, 120, 10, fee = 5, tsNs = 2),
            ),
            Liquidations(listOf(Liquidation(1, 2, 118, -40, 3, 3)), 1),
            FundingPayments(listOf(FundingPayment(1, 5, 118, 10, 30, true, 2)), 1),
            unrealizedPnl = 7,
        )
        // 200 - 10 + 30 + (-40) - 3 = 177
        assertEquals(177L, report.netRealized)
        assertEquals(10L, report.totalFees)
        assertEquals(30L, report.fundingTotal)
        assertEquals(-40L, report.liquidationPnl)
        assertEquals(7L, report.unrealized)
    }

    // ---- equity curve ----

    @Test
    fun `equity curve is time-ordered cumulative and ends at net minus uPnL`() {
        val report = PnlAnalytics.analyze(
            fills(
                fill(1, OrderSide.BUY, 100, 10, fee = 5, tsNs = 1),
                fill(1, OrderSide.SELL, 120, 10, fee = 5, tsNs = 2),
            ),
            Liquidations(emptyList(), 0),
            FundingPayments(listOf(FundingPayment(1, 5, 118, 10, 30, true, 3)), 1),
            unrealizedPnl = 999,
        )
        val curve = report.equityCurve
        // Three cash events: fill1 (-5), fill2 (+200-5=195), funding (+30). Cumulative: -5, 190, 220.
        assertEquals(3, curve.size)
        assertEquals(-5L, curve[0].cumulative)
        assertEquals(190L, curve[1].cumulative)
        assertEquals(220L, curve[2].cumulative)
        // Curve final reconciles with netRealized (independent of uPnL).
        assertEquals(report.netRealized, curve.last().cumulative)
        assertTrue(curve[0].tsNs <= curve[1].tsNs && curve[1].tsNs <= curve[2].tsNs)
    }

    @Test
    fun `empty inputs produce an empty report`() {
        val report = PnlAnalytics.analyze(
            FillsFees(emptyList(), 0),
            Liquidations(emptyList(), 0),
            FundingPayments(emptyList(), 0),
            unrealizedPnl = 0,
        )
        assertTrue(report.isEmpty)
        assertEquals(0L, report.netRealized)
        assertTrue(report.equityCurve.isEmpty())
    }
}
