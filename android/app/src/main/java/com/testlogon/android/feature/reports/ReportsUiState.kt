package com.testlogon.android.feature.reports

/**
 * UI state for the Export & Reporting screen. The ViewModel fetches the exchange reads once, then
 * re-derives [stats] + the CSV export payloads whenever the selected [period] changes (period scoping
 * is a pure local filter — no re-fetch). Nothing here moves money; it is a read-only reporting view.
 *
 * [loading] gates the initial spinner; [unavailable] mirrors the PnL screen's whole-surface-degraded
 * state (every read undeployed); [error] carries a retryable transient failure. When loaded, [isEmpty]
 * drives the 'no activity in this period' empty state for the CURRENT period.
 */
data class ReportsUiState(
    val loading: Boolean = true,
    val unavailable: Boolean = false,
    val error: String? = null,
    val period: ReportPeriod = ReportPeriod.MONTH,
    val stats: ReportStats? = null,
    /** Prepared CSV payloads for the current period, ready to hand to the share sheet. */
    val exports: ReportExports? = null,
) {
    /** True once loaded/readable and there was genuinely no fill activity in the selected window. */
    val isEmpty: Boolean
        get() = !loading && !unavailable && error == null &&
            (stats == null || (stats.tradeCount == 0 && stats.fillCount == 0))
}

/** Headline stats for the selected period (raw integer engine units, [winRate] a 0..1 fraction). */
data class ReportStats(
    val netRealized: Long,
    val totalFees: Long,
    val volume: Long,
    val tradeCount: Int,
    val fillCount: Int,
    val winRate: Float,
    val closingTradeCount: Int,
) {
    val isProfit: Boolean get() = netRealized >= 0
    val winRatePercent: Int get() = Math.round(winRate * 100f)
}

/** The three built CSV documents + their file base-names, one export action each. */
data class ReportExports(
    val tradeHistoryCsv: String,
    val pnlSummaryCsv: String,
    val accountStatementCsv: String,
    val tradeHistoryName: String,
    val pnlSummaryName: String,
    val accountStatementName: String,
)
