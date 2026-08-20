package com.testlogon.android.feature.paper

import com.testlogon.android.data.exchange.OrderSide
import com.testlogon.android.feature.markets.trade.OrderType
import com.testlogon.android.feature.paper.PaperEngine.PaperOrderType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for the PURE [PaperTicketSupport] helpers backing the trade-ticket paper-mode toggle:
 * marketPrice selection (buy lifts ask / sell hits bid, with fallbacks) + paper order-type gating.
 */
class PaperTicketSupportTest {

    // ---- marketPriceFor ----

    @Test
    fun buy_takesBestAsk() {
        assertEquals(101L, PaperTicketSupport.marketPriceFor(OrderSide.BUY, bestBid = 99, bestAsk = 101, last = 100))
    }

    @Test
    fun sell_takesBestBid() {
        assertEquals(99L, PaperTicketSupport.marketPriceFor(OrderSide.SELL, bestBid = 99, bestAsk = 101, last = 100))
    }

    @Test
    fun buy_missingAsk_fallsBackToLast() {
        assertEquals(100L, PaperTicketSupport.marketPriceFor(OrderSide.BUY, bestBid = 99, bestAsk = null, last = 100))
    }

    @Test
    fun missingLast_fallsBackToMid() {
        assertEquals(150L, PaperTicketSupport.marketPriceFor(OrderSide.BUY, bestBid = null, bestAsk = null, last = null, mid = 150))
    }

    @Test
    fun buy_missingAskAndLast_fallsBackToOppositeSide() {
        // No ask, no last, no mid -> use the bid (the only known price) rather than fabricate.
        assertEquals(99L, PaperTicketSupport.marketPriceFor(OrderSide.BUY, bestBid = 99, bestAsk = null, last = null))
    }

    @Test
    fun nothingKnown_returnsNull() {
        assertNull(PaperTicketSupport.marketPriceFor(OrderSide.BUY, bestBid = null, bestAsk = null, last = null, mid = null))
    }

    @Test
    fun nonPositivePricesAreIgnored() {
        // A zero/negative ask is skipped in favour of the next positive candidate (last).
        assertEquals(100L, PaperTicketSupport.marketPriceFor(OrderSide.BUY, bestBid = 0, bestAsk = 0, last = 100))
    }

    // ---- paper order-type gating ----

    @Test
    fun onlyMarketAndLimitAreSimulatable() {
        assertTrue(PaperTicketSupport.isPaperSimulatable(OrderType.MARKET))
        assertTrue(PaperTicketSupport.isPaperSimulatable(OrderType.LIMIT))
        assertFalse(PaperTicketSupport.isPaperSimulatable(OrderType.STOP))
        assertFalse(PaperTicketSupport.isPaperSimulatable(OrderType.OCO))
        assertFalse(PaperTicketSupport.isPaperSimulatable(OrderType.FUNDING))
    }

    @Test
    fun snapToPaper_keepsMarketAndLimit_snapsRestToLimit() {
        assertEquals(OrderType.MARKET, PaperTicketSupport.snapToPaper(OrderType.MARKET))
        assertEquals(OrderType.LIMIT, PaperTicketSupport.snapToPaper(OrderType.LIMIT))
        assertEquals(OrderType.LIMIT, PaperTicketSupport.snapToPaper(OrderType.STOP_LIMIT))
        assertEquals(OrderType.LIMIT, PaperTicketSupport.snapToPaper(OrderType.QUOTE))
    }

    @Test
    fun toPaperType_mapsMarketElseLimit() {
        assertEquals(PaperOrderType.MARKET, PaperTicketSupport.toPaperType(OrderType.MARKET))
        assertEquals(PaperOrderType.LIMIT, PaperTicketSupport.toPaperType(OrderType.LIMIT))
        assertEquals(PaperOrderType.LIMIT, PaperTicketSupport.toPaperType(OrderType.STOP))
    }
}
