package com.testlogon.android.feature.markets.chart

import com.testlogon.android.data.exchange.OrderBook
import com.testlogon.android.data.exchange.OrderBookLevel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for the pure cumulative-depth math in [DepthMath] that backs the [DepthChart] Canvas.
 * No Compose / Android here — this is the extracted, framework-free layer.
 */
class DepthMathTest {

    private fun lvl(price: Long, qty: Long) = OrderBookLevel(price, qty)

    private fun book(
        bids: List<OrderBookLevel>,
        asks: List<OrderBookLevel>,
        bestBid: Long? = bids.firstOrNull()?.price,
        bestAsk: Long? = asks.firstOrNull()?.price,
    ) = OrderBook(symbolId = 1, bids = bids, asks = asks, bestBid = bestBid, bestAsk = bestAsk)

    @Test
    fun cumulativeBids_accumulateFromBestOutward() {
        // best bid highest price first
        val out = DepthMath.cumulativeBids(listOf(lvl(100, 5), lvl(99, 3), lvl(98, 2)))
        assertEquals(listOf(5L, 8L, 10L), out.map { it.cumQty })
        assertEquals(listOf(100L, 99L, 98L), out.map { it.price })
    }

    @Test
    fun cumulativeAsks_accumulateFromBestOutward() {
        val out = DepthMath.cumulativeAsks(listOf(lvl(101, 4), lvl(102, 1), lvl(103, 5)))
        assertEquals(listOf(4L, 5L, 10L), out.map { it.cumQty })
        assertEquals(listOf(101L, 102L, 103L), out.map { it.price })
    }

    @Test
    fun cumulative_tolerateUnsortedInput_andSkipZeroQty() {
        // deliberately scrambled + a zero-qty level that must be dropped
        val bids = DepthMath.cumulativeBids(listOf(lvl(98, 2), lvl(100, 5), lvl(99, 0), lvl(97, 1)))
        assertEquals(listOf(100L, 98L, 97L), bids.map { it.price })
        assertEquals(listOf(5L, 7L, 8L), bids.map { it.cumQty })

        val asks = DepthMath.cumulativeAsks(listOf(lvl(103, 5), lvl(101, 4), lvl(102, 0)))
        assertEquals(listOf(101L, 103L), asks.map { it.price })
        assertEquals(listOf(4L, 9L), asks.map { it.cumQty })
    }

    @Test
    fun model_computesAxisMidSpreadAndMaxCum() {
        val m = DepthMath.model(
            book(
                bids = listOf(lvl(100, 5), lvl(99, 3)),
                asks = listOf(lvl(101, 4), lvl(102, 6)),
            ),
        )
        assertFalse(m.isEmpty)
        assertEquals(99L, m.minPrice)
        assertEquals(102L, m.maxPrice)
        assertEquals(100L, m.bestBid)
        assertEquals(101L, m.bestAsk)
        assertEquals(100.5, m.mid!!, 1e-9)
        assertEquals(1L, m.spread)
        // bid total 8, ask total 10 -> maxCum 10
        assertEquals(10L, m.maxCum)
    }

    @Test
    fun model_maxCumNeverZero_evenForEmptyOrTinyBook() {
        assertTrue(DepthMath.model(null).isEmpty)
        assertEquals(1L, DepthMath.model(null).maxCum)
        val emptyBook = DepthMath.model(book(emptyList(), emptyList(), null, null))
        assertTrue(emptyBook.isEmpty)
    }

    @Test
    fun model_capsEachSideToMaxLevels() {
        val bids = (1..10).map { lvl(100L - it, 1L) }        // 99..90
        val asks = (1..10).map { lvl(100L + it, 1L) }        // 101..110
        val m = DepthMath.model(book(bids, asks, 99, 101), maxLevels = 3)
        assertEquals(3, m.bids.size)
        assertEquals(3, m.asks.size)
        // capped cumulative maxima are 3 each
        assertEquals(3L, m.maxCum)
    }

    @Test
    fun model_oneSidedBook_stillProducesModel() {
        val m = DepthMath.model(book(bids = listOf(lvl(100, 5), lvl(99, 2)), asks = emptyList(), bestAsk = null))
        assertFalse(m.isEmpty)
        assertNull(m.mid)      // no ask -> no mid
        assertNull(m.spread)
        assertEquals(7L, m.maxCum)
        assertTrue(m.asks.isEmpty())
    }

    @Test
    fun crosshair_onBidSide_reportsCumAtOrAbovePrice() {
        val m = DepthMath.model(
            book(
                bids = listOf(lvl(100, 5), lvl(99, 3), lvl(98, 2)), // cum 5,8,10
                asks = listOf(lvl(101, 4), lvl(102, 6)),            // cum 4,10
            ),
        )
        // axis 98..102, span 4. price 99 -> fracX = (99-98)/4 = 0.25
        val c = DepthMath.crosshairAt(m, 0.25f)
        assertNotNull(c)
        assertTrue(c!!.isBid)
        assertEquals(99L, c.price)
        // cumulative bid depth at/above 99 = 5 + 3 = 8
        assertEquals(8L, c.cumQty)
    }

    @Test
    fun crosshair_onAskSide_reportsCumAtOrBelowPrice() {
        val m = DepthMath.model(
            book(
                bids = listOf(lvl(100, 5), lvl(99, 3), lvl(98, 2)),
                asks = listOf(lvl(101, 4), lvl(102, 6)),            // cum 4,10
            ),
        )
        // price 102 -> fracX = (102-98)/4 = 1.0, right of mid 100.5 -> ask side
        val c = DepthMath.crosshairAt(m, 1.0f)!!
        assertFalse(c.isBid)
        assertEquals(102L, c.price)
        assertEquals(10L, c.cumQty)
    }

    @Test
    fun crosshair_farLeft_reportsBestBidOnly() {
        val m = DepthMath.model(
            book(
                bids = listOf(lvl(100, 5), lvl(99, 3), lvl(98, 2)),
                asks = listOf(lvl(101, 4), lvl(102, 6)),
            ),
        )
        // fracX 0 -> price 98, at/above 98 = full bid stack 10
        val c = DepthMath.crosshairAt(m, 0f)!!
        assertTrue(c.isBid)
        assertEquals(98L, c.price)
        assertEquals(10L, c.cumQty)
    }

    @Test
    fun crosshair_emptyModel_isNull() {
        assertNull(DepthMath.crosshairAt(DepthMath.EMPTY, 0.5f))
    }

    @Test
    fun crosshair_clampsFractionOutOfRange() {
        val m = DepthMath.model(
            book(
                bids = listOf(lvl(100, 5)),
                asks = listOf(lvl(101, 4)),
            ),
        )
        // out-of-range fractions clamp into [0,1] rather than throwing
        assertNotNull(DepthMath.crosshairAt(m, -3f))
        assertNotNull(DepthMath.crosshairAt(m, 5f))
    }
}
