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
    LEAVES,
    AVG_PX,
    TIF,
    STATUS,
    CLORD,
}

/** Sort direction for the active column. */
enum class BlotterSortDir { ASC, DESC }

// ---- Parity additions: columns / grouping / filtering ----------------------

/**
 * A stable descriptor for one Orders/Fills column. The Orders and Fills tables share this single
 * column set; the Positions table stays fixed. Rendering iterates the VISIBLE descriptors instead
 * of hardcoding each cell, so the column chooser can show/hide columns generically.
 *
 * @param header short header label.
 * @param weight relative Row weight for layout.
 * @param defaultVisible whether the column is shown before the user customizes the layout.
 * @param sortColumn the [BlotterSortColumn] this maps to, or null if the column is not sortable.
 * @param numeric right-aligned numeric rendering when true.
 */
enum class BlotterColumn(
    val header: String,
    val weight: Float,
    val defaultVisible: Boolean,
    val sortColumn: BlotterSortColumn?,
    val numeric: Boolean,
) {
    SYM("Sym", 2.2f, true, BlotterSortColumn.SYM, false),
    SIDE("Side", 1f, true, BlotterSortColumn.SIDE, false),
    PX("Px", 2f, true, BlotterSortColumn.PX, true),
    QTY("Qty", 1.8f, true, BlotterSortColumn.QTY, true),
    CUM("Cum", 1.8f, true, BlotterSortColumn.CUM, true),
    LEAVES("Leaves", 1.8f, false, BlotterSortColumn.LEAVES, true),
    AVG_PX("AvgPx", 2f, false, BlotterSortColumn.AVG_PX, true),
    TIF("TIF", 1.4f, false, BlotterSortColumn.TIF, false),
    STATUS("Status", 2f, true, BlotterSortColumn.STATUS, false),
    CLORD("ClOrd", 2.2f, false, BlotterSortColumn.CLORD, false),
}

/** A column the user can group Orders/Fills rows by (collapsible groups). */
enum class BlotterGroupKey(val label: String) {
    SYMBOL("Symbol"),
    SIDE("Side"),
    STATUS("Status"),
}

/**
 * View-derived filter set for Orders/Fills. Applied to a display copy only (never mutates the
 * stored orders) so the ticker keeps updating the source of truth. Empty selections mean "no
 * constraint"; null numeric bounds mean "unbounded".
 */
data class BlotterFilters(
    val search: String = "",
    val symbols: Set<String> = emptySet(),
    val sides: Set<BlotterSide> = emptySet(),
    val statuses: Set<BlotterStatus> = emptySet(),
    val tifs: Set<BlotterTif> = emptySet(),
    val pxMin: Double? = null,
    val pxMax: Double? = null,
    val qtyMin: Double? = null,
    val qtyMax: Double? = null,
) {
    /** How many distinct filter facets are active (drives the toolbar badge). */
    val activeCount: Int
        get() = (if (search.isNotBlank()) 1 else 0) +
            (if (symbols.isNotEmpty()) 1 else 0) +
            (if (sides.isNotEmpty()) 1 else 0) +
            (if (statuses.isNotEmpty()) 1 else 0) +
            (if (tifs.isNotEmpty()) 1 else 0) +
            (if (pxMin != null || pxMax != null) 1 else 0) +
            (if (qtyMin != null || qtyMax != null) 1 else 0)

    val isActive: Boolean get() = activeCount > 0
}

// ---- Column ordering (drag-to-reorder) -------------------------------------

/** The default Orders/Fills column order before the user reorders them. */
val DEFAULT_COLUMN_ORDER: List<BlotterColumn> = BlotterColumn.entries.toList()

/**
 * Return a COMPLETE, de-duplicated column order derived from a (possibly partial or stale) saved
 * order: the saved columns first (in saved order, duplicates dropped), then any columns missing
 * from the save appended in canonical [BlotterColumn.entries] order. This guarantees no column can
 * silently vanish from the header/cells if a persisted order pre-dates a newly added column.
 */
fun normalizeColumnOrder(saved: List<BlotterColumn>): List<BlotterColumn> {
    val seen = saved.distinct()
    val missing = BlotterColumn.entries.filter { it !in seen }
    return seen + missing
}
