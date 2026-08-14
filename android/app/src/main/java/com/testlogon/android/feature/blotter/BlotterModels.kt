package com.testlogon.android.feature.blotter

/**
 * Trading Blotter — the mobile-native counterpart of the web trading blotter (parity).
 *
 * A [BlotterOrder] is one working/terminal order row. Fills are derived as the subset with
 * cumQty > 0; positions are derived by aggregating signed executed quantity per symbol.
 */

/** Buy / Sell. Rendered as a color-coded B / S badge. */
enum class BlotterSide(val code: String) {
    BUY("B"),
    SELL("S"),
}

/** Order lifecycle status. Rendered as a color-coded badge. */
enum class BlotterStatus(val label: String) {
    LIVE("live"),
    PARTIAL("partial"),
    FILLED("filled"),
    CANCELLED("cancelled"),
}

/** Time-in-force. */
enum class BlotterTif(val label: String) {
    DAY("DAY"),
    GTC("GTC"),
    IOC("IOC"),
    FOK("FOK"),
}

/**
 * A single order row on the blotter.
 *
 * @param clord client order id (stable row key).
 * @param sym instrument symbol (e.g. BTC-USD).
 * @param side buy or sell.
 * @param px limit price.
 * @param qty original order quantity.
 * @param cumQty cumulative executed quantity (0..qty).
 * @param leaves remaining open quantity (qty - cumQty).
 * @param avgPx average fill price over the executed quantity (0 when nothing executed).
 * @param status current lifecycle status.
 * @param tif time-in-force.
 */
data class BlotterOrder(
    val clord: String,
    val sym: String,
    val side: BlotterSide,
    val px: Double,
    val qty: Double,
    val cumQty: Double,
    val leaves: Double,
    val avgPx: Double,
    val status: BlotterStatus,
    val tif: BlotterTif,
)

/** A per-symbol aggregated net position derived from executed order quantity. */
data class BlotterPosition(
    val sym: String,
    /** Signed net executed quantity (buys positive, sells negative). */
    val net: Double,
    /** Volume-weighted average cost of the open net position (0 when flat). */
    val avgCost: Double,
    /** Current mark (last drifted reference price for the symbol). */
    val mark: Double,
    /** Unrealized P&L: (mark - avgCost) * net. */
    val uPnl: Double,
)

/** Which blotter tab is selected. */
enum class BlotterTab(val label: String) {
    ORDERS("Orders"),
    FILLS("Fills"),
    POSITIONS("Positions"),
}

/** Sortable columns for the Orders / Fills table (positions use a fixed order). */
enum class BlotterSortColumn {
    SYM,
    SIDE,
    PX,
    QTY,
    CUM,
    AVG_PX,
    STATUS,
}

/** Sort direction for the active column. */
enum class BlotterSortDir { ASC, DESC }
