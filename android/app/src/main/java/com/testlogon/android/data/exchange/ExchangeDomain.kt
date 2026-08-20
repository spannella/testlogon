package com.testlogon.android.data.exchange

/**
 * Markets (VIEW-ONLY) domain models — the render-ready shapes the feature layer consumes.
 *
 * Raw integer prices/quantities are kept as-is; call [Instrument.display] to scale a raw price for
 * presentation (all scalers are 1 today, so this is identity, but the seam is honoured).
 */
data class Instrument(
    val symbol: String,
    val symbolId: Int,
    val priceScaler: Long,
    val lotSize: Long,
    val referencePrice: Long,
    val isPerpetual: Boolean,
    /** Funding interval in seconds for perpetuals (0 for spot / when unknown). */
    val fundingIntervalS: Long = 0,
) {
    /** Scale a raw integer price/qty into a display double (divides by a >=1 scaler). */
    fun display(raw: Long): Double = raw.toDouble() / priceScaler.coerceAtLeast(1)
}

/** One price level of the order book: an integer [price] and aggregate [qty]. */
data class OrderBookLevel(
    val price: Long,
    val qty: Long,
)

/**
 * A market-data order book snapshot. [bids] are sorted descending by price, [asks] ascending.
 * [bestBid]/[bestAsk] are the server-provided top-of-book prices (nullable when a side is empty).
 */
data class OrderBook(
    val symbolId: Int,
    val bids: List<OrderBookLevel>,
    val asks: List<OrderBookLevel>,
    val bestBid: Long?,
    val bestAsk: Long?,
) {
    /** Ask minus bid, or null when either side is empty. */
    val spread: Long?
        get() {
            val b = bestBid ?: bids.firstOrNull()?.price
            val a = bestAsk ?: asks.firstOrNull()?.price
            return if (b != null && a != null) a - b else null
        }

    /** Mid price (average of best bid/ask), or null when either side is empty. */
    val mid: Double?
        get() {
            val b = bestBid ?: bids.firstOrNull()?.price
            val a = bestAsk ?: asks.firstOrNull()?.price
            return if (b != null && a != null) (b + a) / 2.0 else null
        }
}

/** A single OHLCV candle. Timestamp is the bar-start in nanoseconds since epoch. */
data class Candle(
    val tsStartNs: Long,
    val open: Long,
    val high: Long,
    val low: Long,
    val close: Long,
    val volume: Long,
    val trades: Long,
)

/** Which side crossed the spread on a print. */
enum class Aggressor { BUY, SELL, UNKNOWN }

/** A single trade print on the tape. */
data class Trade(
    val price: Long,
    val qty: Long,
    val aggressor: Aggressor,
    val tsNs: Long,
)

/**
 * One historical OHLCV bar for the Analysis workbench. [ts] is the bar-start in epoch SECONDS (the
 * long-range history endpoint keys by seconds, unlike [Candle.tsStartNs]). Prices/volume are raw
 * integers; scale for display via the owning [Instrument].
 */
data class HistoryBar(
    val ts: Long,
    val open: Long,
    val high: Long,
    val low: Long,
    val close: Long,
    val volume: Long,
)

/**
 * A page of [HistoryBar]s for one symbol+interval. [nextCursor] paginates a large range (null when
 * the page is terminal). [stub] is true when this was DEGRADED from the recent-window candles read
 * because the long-range `md/history` endpoint was absent (404) — the UI shows a "recent window
 * only" banner in that case.
 */
data class HistoryBars(
    val symbolId: Int,
    val interval: String,
    val bars: List<HistoryBar>,
    val nextCursor: String? = null,
    val stub: Boolean = false,
)
