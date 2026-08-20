package com.testlogon.android.feature.analysis

import com.testlogon.android.data.exchange.HistoryBar
import com.testlogon.android.data.exchange.Instrument
import com.testlogon.android.feature.markets.MarketClassTab

/** Time-range presets the workbench requests over the history/candles feed. */
enum class AnalysisRange(val label: String, val interval: String, val lookbackSeconds: Long) {
    D1("1D", "5m", 86_400L),
    W1("1W", "1h", 604_800L),
    M1("1M", "1h", 2_592_000L),
    M3("3M", "1d", 7_776_000L),
    Y1("1Y", "1d", 31_536_000L),
}

/**
 * Render-ready computed statistics for a single symbol's loaded bars. All values are display-scaled
 * fractions/prices; a null field means "not enough data" and the panel shows a dash.
 */
data class SymbolStats(
    val periodReturnPct: Double?,
    val cumulativeReturnPct: Double?,
    val annualizedVolPct: Double?,
    val maxDrawdownPct: Double?,
    val high: Double?,
    val low: Double?,
    val avgVolume: Double?,
    val totalVolume: Double,
)

/** One symbol's loaded history plus its derived close series (display-scaled) for charts + stats. */
data class SymbolSeries(
    val instrument: Instrument,
    val bars: List<HistoryBar>,
    val closes: List<Double>,
    val stats: SymbolStats?,
)

/** A backtest run's inputs + result for the summary card + equity curve. */
data class BacktestState(
    val fast: Int = 5,
    val slow: Int = 20,
    val result: BacktestResult? = null,
)

/** One cell of the compact correlation grid (i,j -> pearson r over aligned closes). */
data class CorrelationCell(
    val rowSymbol: String,
    val colSymbol: String,
    val r: Double?,
)

/**
 * Single immutable Analysis-workbench state. [phase] drives the top-level surface; [degraded] is true
 * when the long-range history endpoint was absent and we fell back to the recent-window candles read
 * (the UI shows the "recent window only" banner then).
 */
data class MarketAnalysisUiState(
    val phase: Phase = Phase.Loading,
    val instruments: List<Instrument> = emptyList(),
    val classTab: MarketClassTab = MarketClassTab.All,
    val selectedSymbolId: Int? = null,
    val compareSymbolIds: Set<Int> = emptySet(),
    val range: AnalysisRange = AnalysisRange.W1,
    val primary: SymbolSeries? = null,
    val compareSeries: List<SymbolSeries> = emptyList(),
    val correlation: List<CorrelationCell> = emptyList(),
    val backtest: BacktestState = BacktestState(),
    val degraded: Boolean = false,
    val hasMore: Boolean = false,
    val errorMessage: String? = null,
) {
    enum class Phase { Loading, Content, Empty, Error }

    /** The selected instrument, resolved from the loaded catalogue. */
    val selectedInstrument: Instrument?
        get() = instruments.firstOrNull { it.symbolId == selectedSymbolId }
}
