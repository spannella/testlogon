package com.testlogon.android.feature.pnl

/**
 * UI state for the read-only PnL & performance screen. The ViewModel fetches the four exchange reads,
 * runs the pure [PnlAnalytics.analyze], resolves symbol ids to names, and projects the result into this
 * render-ready shape. Nothing here moves money — it is a derived analytics view.
 *
 * [loading] gates the initial spinner; [unavailable] is set when EVERY underlying read was undeployed
 * (404) so the whole surface is unsupported on this deployment; [error] carries a transient failure the
 * user can retry. When a report is present, [isEmpty] drives the "no trading activity yet" empty state.
 */
data class PnlUiState(
    val loading: Boolean = true,
    val unavailable: Boolean = false,
    val error: String? = null,
    val stats: PnlStats? = null,
    val bySymbol: List<SymbolRow> = emptyList(),
    val equityCurve: List<EquityCurvePoint> = emptyList(),
    /** True when the report is derived from the shared PAPER account (drives the PAPER badge). */
    val paper: Boolean = false,
) {
    /** True once loaded, readable, and there was genuinely no trading activity to analyze. */
    val isEmpty: Boolean
        get() = !loading && !unavailable && error == null &&
            (stats == null || (stats.tradeCount == 0 && bySymbol.isEmpty() && equityCurve.isEmpty()))
}

/** The top-of-screen stat cards, all raw integer engine units except [winRate] (0..1 fraction). */
data class PnlStats(
    val netRealized: Long,
    val unrealized: Long,
    val totalFees: Long,
    val winRate: Float,
    val closingTradeCount: Int,
    val tradeCount: Int,
    val volume: Long,
    val fundingTotal: Long,
    val liquidationPnl: Long,
) {
    val isRealizedProfit: Boolean get() = netRealized >= 0
    val isUnrealizedProfit: Boolean get() = unrealized >= 0
    /** Win rate as a whole-number percent for compact display. */
    val winRatePercent: Int get() = Math.round(winRate * 100f)
}

/** One per-symbol breakdown row (symbol name / realized / volume / fees / #trades). */
data class SymbolRow(
    val symbol: String,
    val realized: Long,
    val volume: Long,
    val fees: Long,
    val tradeCount: Int,
) {
    val isProfit: Boolean get() = realized >= 0
}

/** One equity-curve point projected for the Canvas: a running cumulative net total (raw units). */
data class EquityCurvePoint(val tsNs: Long, val cumulative: Long)
