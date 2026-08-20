package com.testlogon.android.feature.paper

import com.testlogon.android.data.exchange.OrderSide
import com.testlogon.android.feature.markets.trade.OrderType
import com.testlogon.android.feature.paper.PaperEngine.PaperOrderType

/**
 * PURE, framework-free helpers backing the trade-ticket PAPER-MODE toggle. No Android / coroutine /
 * Compose / network dependencies so every function is unit-testable in isolation.
 *
 * Two concerns:
 *  - [marketPriceFor]  — pick the simulated marketPrice fed into [PaperEngine.placeOrder].
 *  - paper order-type gating ([isPaperSimulatable] / [toPaperType] / [snapToPaper]) — in paper mode ONLY
 *    Market & Limit are simulated; every other type snaps back to Limit.
 */
object PaperTicketSupport {

    /**
     * The marketPrice used to fill a paper order for [side]: a BUY lifts the best ASK, a SELL hits the
     * best BID (crossing the spread, like a real taker). Falls back to [last] then [mid] then the
     * opposite side of the book when a side is missing, so a one-sided book still produces a price.
     * Returns null only when NOTHING is known (no book, no last, no mid) — the caller must then refuse
     * the fill rather than fabricate a price.
     */
    fun marketPriceFor(
        side: OrderSide,
        bestBid: Long?,
        bestAsk: Long?,
        last: Long?,
        mid: Long? = null,
    ): Long? {
        val primary = if (side == OrderSide.BUY) bestAsk else bestBid
        val secondary = if (side == OrderSide.BUY) bestBid else bestAsk
        return firstPositive(primary, last, mid, secondary)
    }

    private fun firstPositive(vararg candidates: Long?): Long? =
        candidates.firstOrNull { it != null && it > 0L }

    /** In paper mode only MARKET & LIMIT are simulated by [PaperEngine]. */
    fun isPaperSimulatable(type: OrderType): Boolean =
        type == OrderType.MARKET || type == OrderType.LIMIT

    /** Snap a non-simulatable order-type back to LIMIT (used when paper mode turns on). */
    fun snapToPaper(type: OrderType): OrderType =
        if (isPaperSimulatable(type)) type else OrderType.LIMIT

    /** Map the (already-gated) ticket order-type to the engine paper type. Non-market -> LIMIT. */
    fun toPaperType(type: OrderType): PaperOrderType =
        if (type == OrderType.MARKET) PaperOrderType.MARKET else PaperOrderType.LIMIT
}
