package com.testlogon.android.feature.reports

import com.testlogon.android.data.exchange.FillFee
import com.testlogon.android.data.exchange.FillsFees
import com.testlogon.android.data.exchange.FundingPayments
import com.testlogon.android.data.exchange.Liquidity
import com.testlogon.android.data.exchange.Liquidations
import com.testlogon.android.data.exchange.MarginAccount
import com.testlogon.android.data.exchange.OrderSide
import com.testlogon.android.data.exchange.PositionSnapshot
import com.testlogon.android.feature.pnl.PnlAnalytics
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for the PURE reporting helpers: [ReportCsv] (headers, RFC 4180 comma/quote escaping,
 * per-fill rows, the PnL-summary total roll-up, the account statement) and [ReportPeriod] period
 * scoping (24h/7d/30d/All window boundaries against a deterministic 'now').
 */
class ReportCsvTest {

    private val ns = 1_000_000_000L // 1 second in nanoseconds

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

    private val names = mapOf(1 to "BTCUSDC", 2 to "ETHUSDC")

    // ---- CSV field escaping (RFC 4180) ----

    @Test
    fun `plain field is not quoted`() {
        assertEquals("BTCUSDC", ReportCsv.csvField("BTCUSDC"))
    }

    @Test
    fun `field with comma is quoted`() {
        assertEquals("\"a,b\"", ReportCsv.csvField("a,b"))
    }

    @Test
    fun `embedded quote is doubled and wrapped`() {
        // a"b -> "a""b"
        assertEquals("\"a\"\"b\"", ReportCsv.csvField("a\"b"))
    }

    @Test
    fun `field with newline is quoted`() {
        assertEquals("\"a\nb\"", ReportCsv.csvField("a\nb"))
    }

    // ---- trade history ----

    @Test
    fun `trade history has header and one row per fill oldest first`() {
        val csv = ReportCsv.tradeHistory(
            listOf(
                fill(1, OrderSide.SELL, 120, 10, fee = 2, tsNs = 2 * ns),
                fill(1, OrderSide.BUY, 100, 10, fee = 1, tsNs = 1 * ns),
            ),
            names,
        )
        val lines = csv.split("\r\n")
        assertEquals("Time,Symbol,Side,Price,Qty,Fee,Notional", lines[0])
        assertEquals(3, lines.size) // header + 2 rows
        // Oldest (BUY @ 100, ts=1) sorts first; notional = |10|*100 = 1000.
        assertTrue(lines[1].contains(",BTCUSDC,BUY,100,10,1,1000"))
        // Then SELL @ 120; notional = 1200.
        assertTrue(lines[2].contains(",BTCUSDC,SELL,120,10,2,1200"))
    }

    @Test
    fun `trade history emits header only when there are no fills`() {
        val csv = ReportCsv.tradeHistory(emptyList(), names)
        assertEquals("Time,Symbol,Side,Price,Qty,Fee,Notional", csv)
    }

    @Test
    fun `unknown symbol id falls back to hash id`() {
        val csv = ReportCsv.tradeHistory(
            listOf(fill(99, OrderSide.BUY, 5, 1, tsNs = ns)),
            names,
        )
        assertTrue(csv.contains(",#99,BUY,5,1,"))
    }

    // ---- PnL summary ----

    @Test
    fun `pnl summary has per-symbol rows plus a TOTAL row`() {
        // Round-trip on symbol 1: buy 10@100, sell 10@120 -> realized 200.
        val report = PnlAnalytics.analyze(
            FillsFees(
                listOf(
                    fill(1, OrderSide.BUY, 100, 10, fee = 1, tsNs = 1 * ns),
                    fill(1, OrderSide.SELL, 120, 10, fee = 1, tsNs = 2 * ns),
                ),
                2,
            ),
            Liquidations(emptyList(), 0),
            FundingPayments(emptyList(), 0),
            unrealizedPnl = 0,
        )
        val csv = ReportCsv.pnlSummary(report, names)
        val lines = csv.split("\r\n")
        assertEquals("Symbol,Realized,Fees,Volume,Trades", lines[0])
        assertTrue(lines.any { it.startsWith("BTCUSDC,200,") })
        assertTrue(lines.any { it.startsWith("TOTAL,200,") })
        assertTrue(lines.any { it.startsWith("Net realized,198,") }) // 200 - 2 fees
    }

    // ---- account statement ----

    @Test
    fun `account statement includes period balances and open position`() {
        val report = PnlAnalytics.analyze(
            FillsFees(emptyList(), 0),
            Liquidations(emptyList(), 0),
            FundingPayments(emptyList(), 0),
            unrealizedPnl = 50,
        )
        val margin = MarginAccount(
            balance = 10_000,
            availableBalance = 9_000,
            reservedMargin = 1_000,
            numPositions = 1,
            position = PositionSnapshot(
                symbolId = 1,
                qty = 5,
                entryPrice = 100,
                liquidationPrice = 80,
                unrealizedPnl = 50,
            ),
            distressLevel = 0,
            isLiquidating = false,
            mpid = "MP1",
        )
        val csv = ReportCsv.accountStatement(
            report = report,
            margin = margin,
            symbolNames = names,
            periodLabel = "7d",
            fromTsNs = 0,
            toTsNs = 0,
        )
        assertTrue(csv.contains("Field,Value"))
        assertTrue(csv.contains("Period,7d"))
        assertTrue(csv.contains("Balance,10000"))
        assertTrue(csv.contains("Available balance,9000"))
        assertTrue(csv.contains("Position symbol,BTCUSDC"))
        assertTrue(csv.contains("Position qty,5"))
    }

    @Test
    fun `account statement renders dashes and flat when margin is null`() {
        val report = PnlAnalytics.analyze(
            FillsFees(emptyList(), 0),
            Liquidations(emptyList(), 0),
            FundingPayments(emptyList(), 0),
            unrealizedPnl = 0,
        )
        val csv = ReportCsv.accountStatement(report, null, names, "All", 0, 0)
        assertTrue(csv.contains("Balance,--"))
        assertTrue(csv.contains("Position,flat"))
    }

    // ---- period scoping ----

    @Test
    fun `period cutoff drops events older than the window`() {
        val now = 100L * 24 * 60 * 60 * ns // day 100
        val oldFill = fill(1, OrderSide.BUY, 1, 1, tsNs = now - 40L * 24 * 60 * 60 * ns) // 40 days ago
        val recentFill = fill(1, OrderSide.BUY, 1, 1, tsNs = now - 3L * 24 * 60 * 60 * ns) // 3 days ago
        val all = listOf(oldFill, recentFill)

        // 7d keeps only the 3-day-old fill.
        val week = filterFills(all, ReportPeriod.WEEK, now)
        assertEquals(1, week.size)
        assertEquals(recentFill.tsNs, week.single().tsNs)

        // 30d still drops the 40-day-old fill.
        assertEquals(1, filterFills(all, ReportPeriod.MONTH, now).size)

        // ALL keeps everything.
        assertEquals(2, filterFills(all, ReportPeriod.ALL, now).size)
    }

    @Test
    fun `period contains is inclusive at the boundary`() {
        val now = 10L * 24 * 60 * 60 * ns
        val cutoff = ReportPeriod.DAY.cutoffNs(now)
        assertTrue(ReportPeriod.DAY.contains(cutoff, now)) // exactly at the boundary is kept
        assertFalse(ReportPeriod.DAY.contains(cutoff - 1, now)) // one tick before is dropped
    }
}
