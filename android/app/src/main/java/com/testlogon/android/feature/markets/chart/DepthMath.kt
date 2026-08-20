package com.testlogon.android.feature.markets.chart

import com.testlogon.android.data.exchange.OrderBook
import com.testlogon.android.data.exchange.OrderBookLevel

/**
 * Pure, framework-free math backing the [DepthChart] Canvas. Kept UI-free so it can be unit-tested
 * in isolation (no Compose, no Android). All prices/quantities are raw integer ticks; scaling for
 * display happens in the Canvas layer.
 *
 * The depth model is the classic cumulative "market depth" curve:
 *  - bids are summed from the BEST bid (highest price) outward to worse prices,
 *  - asks are summed from the BEST ask (lowest price) outward to worse prices,
 * so the two cumulative curves both grow as you move AWAY from the mid, mirrored about it.
 */
object DepthMath {

    /** One point on a cumulative-depth curve: a [price] tick and the running [cumQty] to that level. */
    data class DepthPoint(val price: Long, val cumQty: Long)

    /**
     * A render-ready depth model: the two cumulative curves plus the shared axis extents used to map
     * price to x and cumQty to y in the Canvas. [maxCum] is the larger of the two curves' totals
     * (>=1 so callers can divide safely); [minPrice]/[maxPrice] bound the visible price axis.
     */
    data class DepthModel(
        val bids: List<DepthPoint>,
        val asks: List<DepthPoint>,
        val minPrice: Long,
        val maxPrice: Long,
        val maxCum: Long,
        val bestBid: Long?,
        val bestAsk: Long?,
    ) {
        val isEmpty: Boolean get() = bids.isEmpty() && asks.isEmpty()

        /** Mid price (average of best bid/ask), or null when either side is empty. */
        val mid: Double?
            get() = if (bestBid != null && bestAsk != null) (bestBid + bestAsk) / 2.0 else null

        /** Ask minus bid, or null when either side is empty. */
        val spread: Long?
            get() = if (bestBid != null && bestAsk != null) bestAsk - bestBid else null
    }

    /**
     * Accumulate bid levels from the best bid outward. Input [bids] are expected sorted descending by
     * price (best first), matching [OrderBook.bids]; unsorted input is tolerated by sorting a copy so
     * the "from the top of book" invariant always holds. Zero/negative-qty levels are skipped.
     */
    fun cumulativeBids(bids: List<OrderBookLevel>): List<DepthPoint> {
        val ordered = bids.filter { it.qty > 0 }.sortedByDescending { it.price }
        var run = 0L
        return ordered.map { run += it.qty; DepthPoint(it.price, run) }
    }

    /**
     * Accumulate ask levels from the best ask outward. Input [asks] are expected sorted ascending by
     * price (best first), matching [OrderBook.asks]; unsorted input is tolerated by sorting a copy.
     * Zero/negative-qty levels are skipped.
     */
    fun cumulativeAsks(asks: List<OrderBookLevel>): List<DepthPoint> {
        val ordered = asks.filter { it.qty > 0 }.sortedBy { it.price }
        var run = 0L
        return ordered.map { run += it.qty; DepthPoint(it.price, run) }
    }

    /**
     * Build the full [DepthModel] from an [OrderBook], optionally capping each side to [maxLevels]
     * levels outward from the mid (a null/<=0 cap keeps all levels). Returns an empty model when the
     * book is null or both sides are empty.
     */
    fun model(book: OrderBook?, maxLevels: Int? = null): DepthModel {
        if (book == null) return EMPTY
        var bids = cumulativeBids(book.bids)
        var asks = cumulativeAsks(book.asks)
        if (maxLevels != null && maxLevels > 0) {
            bids = bids.take(maxLevels)
            asks = asks.take(maxLevels)
        }
        if (bids.isEmpty() && asks.isEmpty()) return EMPTY

        val bestBid = book.bestBid ?: bids.firstOrNull()?.price
        val bestAsk = book.bestAsk ?: asks.firstOrNull()?.price
        // Price axis spans the outermost visible bid to the outermost visible ask; fall back to the
        // populated side alone when one side is empty.
        val lowCandidates = listOfNotNull(bids.lastOrNull()?.price, asks.firstOrNull()?.price, bestBid, bestAsk)
        val highCandidates = listOfNotNull(asks.lastOrNull()?.price, bids.firstOrNull()?.price, bestAsk, bestBid)
        val minPrice = lowCandidates.minOrNull() ?: 0L
        val maxPrice = highCandidates.maxOrNull() ?: 0L
        val maxCum = maxOf(bids.lastOrNull()?.cumQty ?: 0L, asks.lastOrNull()?.cumQty ?: 0L).coerceAtLeast(1L)
        return DepthModel(
            bids = bids,
            asks = asks,
            minPrice = minPrice,
            maxPrice = maxPrice,
            maxCum = maxCum,
            bestBid = bestBid,
            bestAsk = bestAsk,
        )
    }

    /**
     * Map a horizontal fraction [fracX] in [0,1] across the price axis to the nearest depth point,
     * used by the touch crosshair. Returns the cumulative depth AT that price on whichever side the
     * price falls (bid side left of mid, ask side right). Null when the model is empty or the axis is
     * degenerate.
     */
    fun crosshairAt(model: DepthModel, fracX: Float): Crosshair? {
        if (model.isEmpty) return null
        if (model.maxPrice <= model.minPrice) {
            // Degenerate axis (single price level): report that level directly if present.
            val only = (model.bids + model.asks).minByOrNull { it.price } ?: return null
            return Crosshair(only.price, only.cumQty, isBid = model.asks.isEmpty())
        }
        val span = (model.maxPrice - model.minPrice).toDouble()
        val price = model.minPrice + (fracX.coerceIn(0f, 1f) * span).toLong()
        val mid = model.mid ?: ((model.minPrice + model.maxPrice) / 2.0)
        val isBid = price <= mid
        val cum = if (isBid) cumAtBid(model.bids, price) else cumAtAsk(model.asks, price)
        return Crosshair(price = price, cumQty = cum, isBid = isBid)
    }

    /** Crosshair readout: the [price] under the finger and cumulative [cumQty] on that [isBid] side. */
    data class Crosshair(val price: Long, val cumQty: Long, val isBid: Boolean)

    /**
     * Cumulative bid depth available at or above [price] (i.e. everything that would fill a sell down
     * to [price]). Points are best-first (descending price). Zero when [price] is above the best bid.
     */
    private fun cumAtBid(bids: List<DepthPoint>, price: Long): Long {
        var last = 0L
        for (p in bids) {
            if (p.price >= price) last = p.cumQty else break
        }
        return last
    }

    /**
     * Cumulative ask depth available at or below [price] (everything that would fill a buy up to
     * [price]). Points are best-first (ascending price). Zero when [price] is below the best ask.
     */
    private fun cumAtAsk(asks: List<DepthPoint>, price: Long): Long {
        var last = 0L
        for (p in asks) {
            if (p.price <= price) last = p.cumQty else break
        }
        return last
    }

    val EMPTY = DepthModel(emptyList(), emptyList(), 0L, 0L, 1L, null, null)
}
