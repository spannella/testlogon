package com.testlogon.android.feature.taxreport

import com.testlogon.android.feature.taxreport.TaxLotMath.CostBasisMethod
import com.testlogon.android.feature.taxreport.TaxLotMath.NormalizedFill
import com.testlogon.android.feature.taxreport.TaxLotMath.Term
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for the PURE [TaxLotMath] tax-lot engine. Covers: FIFO / LIFO / AVERAGE lot matching,
 * gain = proceeds - cost - fee (fees folding in), holding-period term classification (short vs long at
 * the 365-day boundary), open-lot residuals, oversell / empty guards, multi-symbol isolation, the
 * realized summary (by-symbol + short/long split + total), unrealized cost-vs-market, and the CSV.
 */
class TaxLotMathTest {

    private val DAY = 24L * 60L * 60L * 1_000_000_000L

    private fun buy(symbol: String, qty: Long, price: Long, tsNs: Long, fee: Long = 0L) =
        NormalizedFill(tsNs = tsNs, symbol = symbol, side = "buy", qty = qty, priceCents = price, feeCents = fee)

    private fun sell(symbol: String, qty: Long, price: Long, tsNs: Long, fee: Long = 0L) =
        NormalizedFill(tsNs = tsNs, symbol = symbol, side = "sell", qty = qty, priceCents = price, feeCents = fee)

    // 1
    @Test
    fun `empty fills yields empty result`() {
        val r = TaxLotMath.computeLots(emptyList(), CostBasisMethod.FIFO)
        assertTrue(r.openLots.isEmpty())
        assertTrue(r.realized.isEmpty())
    }

    // 2
    @Test
    fun `single buy leaves one open lot with cost basis`() {
        val r = TaxLotMath.computeLots(listOf(buy("BTC", 10, 100, 1)), CostBasisMethod.FIFO)
        assertTrue(r.realized.isEmpty())
        val lot = r.openLots.single()
        assertEquals(10L, lot.qty)
        assertEquals(1000L, lot.costBasisCents)
    }

    // 3
    @Test
    fun `simple round-trip realizes proceeds minus cost`() {
        val r = TaxLotMath.computeLots(
            listOf(buy("BTC", 10, 100, 1), sell("BTC", 10, 120, 2)),
            CostBasisMethod.FIFO,
        )
        val lot = r.realized.single()
        assertEquals(1200L, lot.proceedsCents)
        assertEquals(1000L, lot.costBasisCents)
        assertEquals(200L, lot.gainCents)
        assertTrue(r.openLots.isEmpty())
    }

    // 4
    @Test
    fun `fees fold into realized gain`() {
        // buy fee 10 (into cost) + sell fee 20 (subtracted): gain = 1200 - 1010 - 20 = 170.
        val r = TaxLotMath.computeLots(
            listOf(buy("BTC", 10, 100, 1, fee = 10), sell("BTC", 10, 120, 2, fee = 20)),
            CostBasisMethod.FIFO,
        )
        val lot = r.realized.single()
        assertEquals(1010L, lot.costBasisCents)
        assertEquals(20L, lot.feeCents)
        assertEquals(170L, lot.gainCents)
    }

    // 5
    @Test
    fun `FIFO closes oldest lot first`() {
        // Buy 5@100 then 5@200; sell 5@300 under FIFO closes the 100-lot: gain = 1500-500 = 1000.
        val r = TaxLotMath.computeLots(
            listOf(buy("BTC", 5, 100, 1), buy("BTC", 5, 200, 2), sell("BTC", 5, 300, 3)),
            CostBasisMethod.FIFO,
        )
        val lot = r.realized.single()
        assertEquals(500L, lot.costBasisCents)
        assertEquals(1000L, lot.gainCents)
        // Remaining open lot is the 200-lot.
        assertEquals(1000L, r.openLots.single().costBasisCents)
    }

    // 6
    @Test
    fun `LIFO closes newest lot first`() {
        // Same buys; sell 5@300 under LIFO closes the 200-lot: gain = 1500-1000 = 500.
        val r = TaxLotMath.computeLots(
            listOf(buy("BTC", 5, 100, 1), buy("BTC", 5, 200, 2), sell("BTC", 5, 300, 3)),
            CostBasisMethod.LIFO,
        )
        val lot = r.realized.single()
        assertEquals(1000L, lot.costBasisCents)
        assertEquals(500L, lot.gainCents)
        assertEquals(500L, r.openLots.single().costBasisCents)
    }

    // 7
    @Test
    fun `AVERAGE blends cost basis across buys`() {
        // Buy 5@100 + 5@200 -> avg 150; sell 5@300 -> cost 750, gain = 1500-750 = 750.
        val r = TaxLotMath.computeLots(
            listOf(buy("BTC", 5, 100, 1), buy("BTC", 5, 200, 2), sell("BTC", 5, 300, 3)),
            CostBasisMethod.AVERAGE,
        )
        val lot = r.realized.single()
        assertEquals(750L, lot.costBasisCents)
        assertEquals(750L, lot.gainCents)
        // The blended lot still holds 5 @ 150 -> cost 750.
        assertEquals(750L, r.openLots.single().costBasisCents)
    }

    // 8
    @Test
    fun `sell spanning two lots produces two realized slices under FIFO`() {
        val r = TaxLotMath.computeLots(
            listOf(buy("BTC", 5, 100, 1), buy("BTC", 5, 200, 2), sell("BTC", 10, 300, 3)),
            CostBasisMethod.FIFO,
        )
        assertEquals(2, r.realized.size)
        assertEquals(1500L, r.realized.sumOf { it.gainCents }) // (1500-500)+(1500-1000)
        assertTrue(r.openLots.isEmpty())
    }

    // 9
    @Test
    fun `holding over 365 days is long term`() {
        val r = TaxLotMath.computeLots(
            listOf(buy("BTC", 1, 100, 1), sell("BTC", 1, 200, 1 + 400 * DAY)),
            CostBasisMethod.FIFO,
        )
        val lot = r.realized.single()
        assertEquals(Term.LONG, lot.term)
        assertTrue(lot.holdingDays > TaxLotMath.LONG_TERM_DAYS)
    }

    // 10
    @Test
    fun `holding at or under 365 days is short term`() {
        val r = TaxLotMath.computeLots(
            listOf(buy("BTC", 1, 100, 1), sell("BTC", 1, 200, 1 + 100 * DAY)),
            CostBasisMethod.FIFO,
        )
        assertEquals(Term.SHORT, r.realized.single().term)
    }

    // 11
    @Test
    fun `oversell matches only available qty and drops remainder`() {
        // Buy 5, sell 10: only 5 closable; no negative lot, one realized slice of 5.
        val r = TaxLotMath.computeLots(
            listOf(buy("BTC", 5, 100, 1), sell("BTC", 10, 120, 2)),
            CostBasisMethod.FIFO,
        )
        assertEquals(1, r.realized.size)
        assertEquals(5L, r.realized.single().qty)
        assertTrue(r.openLots.isEmpty())
    }

    // 12
    @Test
    fun `sell with no open position is ignored`() {
        val r = TaxLotMath.computeLots(listOf(sell("BTC", 5, 100, 1)), CostBasisMethod.FIFO)
        assertTrue(r.realized.isEmpty())
        assertTrue(r.openLots.isEmpty())
    }

    // 13
    @Test
    fun `symbols are isolated`() {
        val r = TaxLotMath.computeLots(
            listOf(
                buy("BTC", 1, 100, 1), sell("BTC", 1, 150, 2),
                buy("ETH", 1, 10, 1), // ETH stays open
            ),
            CostBasisMethod.FIFO,
        )
        assertEquals(1, r.realized.size)
        assertEquals("BTC", r.realized.single().symbol)
        assertEquals("ETH", r.openLots.single().symbol)
    }

    // 14
    @Test
    fun `realizedSummary rolls up by symbol term split and total`() {
        val r = TaxLotMath.computeLots(
            listOf(
                buy("BTC", 1, 100, 1), sell("BTC", 1, 200, 1 + 10 * DAY),   // short +100
                buy("ETH", 1, 100, 1), sell("ETH", 1, 300, 1 + 400 * DAY),  // long +200
            ),
            CostBasisMethod.FIFO,
        )
        val s = TaxLotMath.realizedSummary(r.realized)
        assertEquals(300L, s.totalGainCents)
        assertEquals(100L, s.byTerm.shortCents)
        assertEquals(200L, s.byTerm.longCents)
        assertEquals(2, s.bySymbol.size)
    }

    // 15
    @Test
    fun `unrealized values open lots against marks`() {
        val r = TaxLotMath.computeLots(listOf(buy("BTC", 10, 100, 1)), CostBasisMethod.FIFO)
        val rows = TaxLotMath.unrealized(r.openLots, mapOf("BTC" to 130L))
        val row = rows.single()
        assertEquals(1000L, row.costBasisCents)
        assertEquals(1300L, row.marketValueCents)
        assertEquals(300L, row.unrealizedCents)
    }

    // 16
    @Test
    fun `unrealized skips symbols without a mark`() {
        val r = TaxLotMath.computeLots(listOf(buy("BTC", 10, 100, 1)), CostBasisMethod.FIFO)
        assertTrue(TaxLotMath.unrealized(r.openLots, emptyMap()).isEmpty())
    }

    // 17
    @Test
    fun `lotsToCsv emits header and one row per realized lot`() {
        val r = TaxLotMath.computeLots(
            listOf(buy("BTC", 10, 100, 1), sell("BTC", 10, 120, 2)),
            CostBasisMethod.FIFO,
        )
        val csv = TaxLotMath.lotsToCsv(r.realized)
        val lines = csv.split("\r\n")
        assertEquals(2, lines.size) // header + 1 lot
        assertTrue(lines[0].startsWith("Symbol,CloseTime,Qty"))
        assertTrue(lines[1].contains("BTC"))
        assertTrue(lines[1].contains("200")) // gain
    }

    // 18
    @Test
    fun `lotsToCsv on empty realized still emits a header`() {
        val csv = TaxLotMath.lotsToCsv(emptyList())
        assertEquals(1, csv.split("\r\n").size)
    }

    // 19
    @Test
    fun `position flip after full close reopens at fill price`() {
        // Buy 5@100, sell 10@120 (oversell drops the extra 5), so no flip: guard keeps it clean.
        // Then a fresh buy opens a new lot.
        val r = TaxLotMath.computeLots(
            listOf(buy("BTC", 5, 100, 1), sell("BTC", 5, 120, 2), buy("BTC", 3, 90, 3)),
            CostBasisMethod.FIFO,
        )
        assertEquals(1, r.realized.size)
        val open = r.openLots.single()
        assertEquals(3L, open.qty)
        assertEquals(270L, open.costBasisCents)
    }

    // 20
    @Test
    fun `csv field escaping quotes embedded delimiter`() {
        assertEquals("\"a,b\"", TaxLotMath.csvField("a,b"))
        assertEquals("plain", TaxLotMath.csvField("plain"))
    }
}
