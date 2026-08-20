package com.testlogon.android.feature.analysis

import com.testlogon.android.core.model.ApiResult
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.data.exchange.ExchangeRepository
import com.testlogon.android.data.exchange.HistoryBar
import com.testlogon.android.data.exchange.HistoryBars
import com.testlogon.android.data.exchange.Instrument
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Drives [MarketAnalysisUiState] from [ExchangeRepository]. Loads the instrument catalogue, then for
 * the selected symbol + range loads long-range history (degrading to the recent-window candles read
 * when `md/history` is absent, surfaced via [MarketAnalysisUiState.degraded]). Computes the stats
 * panel ([MarketStats]), a multi-symbol normalized overlay + a compact correlation grid, and runs the
 * fast/slow MA-cross backtest. All heavy math is delegated to the pure [MarketStats] helpers.
 */
@HiltViewModel
class MarketAnalysisViewModel @Inject constructor(
    private val repository: ExchangeRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(MarketAnalysisUiState())
    val uiState: StateFlow<MarketAnalysisUiState> = _uiState.asStateFlow()

    /** Per (symbolId,interval) history cache for this VM instance (avoids re-fetching on re-select). */
    private val historyCache = HashMap<String, HistoryBars>()

    init { load() }

    fun onRetry() = load()

    private fun load() {
        _uiState.update { it.copy(phase = MarketAnalysisUiState.Phase.Loading, errorMessage = null) }
        viewModelScope.launch {
            when (val result = repository.symbols()) {
                is ApiResult.Success -> {
                    val instruments = result.data
                    if (instruments.isEmpty()) {
                        _uiState.update { it.copy(phase = MarketAnalysisUiState.Phase.Empty) }
                    } else {
                        val defaultId = instruments.first().symbolId
                        _uiState.update {
                            it.copy(
                                phase = MarketAnalysisUiState.Phase.Content,
                                instruments = instruments,
                                selectedSymbolId = it.selectedSymbolId ?: defaultId,
                            )
                        }
                        refreshAll()
                    }
                }
                is ApiResult.Failure -> reduceError(result.error.message)
                is ApiResult.NetworkError -> reduceError(OFFLINE_FALLBACK)
            }
        }
    }

    fun onSelectSymbol(symbolId: Int) {
        if (_uiState.value.selectedSymbolId == symbolId) return
        _uiState.update {
            // Never compare a symbol against itself in the overlay/grid.
            it.copy(selectedSymbolId = symbolId, compareSymbolIds = it.compareSymbolIds - symbolId)
        }
        viewModelScope.launch { refreshAll() }
    }

    fun onSelectRange(range: AnalysisRange) {
        if (_uiState.value.range == range) return
        _uiState.update { it.copy(range = range) }
        viewModelScope.launch { refreshAll() }
    }

    fun onSelectClassTab(tab: com.testlogon.android.feature.markets.MarketClassTab) {
        _uiState.update { it.copy(classTab = tab) }
    }

    fun onToggleCompare(symbolId: Int) {
        val state = _uiState.value
        if (symbolId == state.selectedSymbolId) return
        val next = state.compareSymbolIds.toMutableSet().apply {
            if (!add(symbolId)) remove(symbolId)
        }
        _uiState.update { it.copy(compareSymbolIds = next) }
        viewModelScope.launch { refreshAll() }
    }

    fun onBacktestParams(fast: Int, slow: Int) {
        _uiState.update { it.copy(backtest = it.backtest.copy(fast = fast, slow = slow)) }
        recomputeBacktest()
    }

    /** Reload primary + compare series for the current selection/range, then recompute all derived data. */
    private suspend fun refreshAll() {
        val state = _uiState.value
        val primaryId = state.selectedSymbolId ?: return
        val range = state.range

        val primaryInstrument = state.instruments.firstOrNull { it.symbolId == primaryId } ?: return
        val primaryBars = loadBars(primaryInstrument, range)
        val primarySeries = primaryInstrument.toSeries(primaryBars.bars)

        val compareSeries = state.compareSymbolIds
            .mapNotNull { id -> state.instruments.firstOrNull { it.symbolId == id } }
            .map { inst -> inst.toSeries(loadBars(inst, range).bars) }

        val correlation = buildCorrelation(primarySeries, compareSeries)

        _uiState.update {
            it.copy(
                primary = primarySeries,
                compareSeries = compareSeries,
                correlation = correlation,
                degraded = primaryBars.stub,
                hasMore = primaryBars.nextCursor != null,
            )
        }
        recomputeBacktest()
    }

    private fun recomputeBacktest() {
        _uiState.update { state ->
            val closes = state.primary?.closes.orEmpty()
            val bt = state.backtest
            val result = MarketStats.backtestMaCross(closes, bt.fast, bt.slow)
            state.copy(backtest = bt.copy(result = result))
        }
    }

    /** Load (and cache) a symbol's bars for a range; degrade-on-404 handled inside the repository. */
    private suspend fun loadBars(instrument: Instrument, range: AnalysisRange): HistoryBars {
        val key = "${instrument.symbolId}:${range.interval}:${range.name}"
        historyCache[key]?.let { return it }
        val nowSec = System.currentTimeMillis() / 1000L
        val from = nowSec - range.lookbackSeconds
        val bars = when (
            val r = repository.getHistory(
                symbolId = instrument.symbolId,
                interval = range.interval,
                from = from,
                to = nowSec,
            )
        ) {
            is ApiResult.Success -> r.data
            // On a hard failure (offline etc.), return an empty non-stub page; the panel shows dashes.
            else -> HistoryBars(instrument.symbolId, range.interval, emptyList())
        }
        historyCache[key] = bars
        return bars
    }

    private fun Instrument.toSeries(bars: List<HistoryBar>): SymbolSeries {
        val closes = bars.map { display(it.close) }
        val volumes = bars.map { it.volume.toDouble() }
        val stats = if (closes.isEmpty()) null else SymbolStats(
            periodReturnPct = MarketStats.cumulativeReturnPct(closes),
            cumulativeReturnPct = MarketStats.cumulativeReturnPct(closes),
            annualizedVolPct = MarketStats.annualizedVolatility(closes)?.let { it * 100.0 },
            maxDrawdownPct = MarketStats.maxDrawdown(closes)?.let { it * 100.0 },
            high = MarketStats.high(closes),
            low = MarketStats.low(closes),
            avgVolume = MarketStats.average(volumes),
            totalVolume = MarketStats.total(volumes),
        )
        return SymbolSeries(instrument = this, bars = bars, closes = closes, stats = stats)
    }

    /** Build the compact NxN correlation grid over the primary + compare series (aligned closes). */
    private fun buildCorrelation(
        primary: SymbolSeries,
        compare: List<SymbolSeries>,
    ): List<CorrelationCell> {
        val all = listOf(primary) + compare
        if (all.size < 2) return emptyList()
        val cells = ArrayList<CorrelationCell>(all.size * all.size)
        for (row in all) {
            for (col in all) {
                val r = if (row.instrument.symbolId == col.instrument.symbolId) {
                    1.0
                } else {
                    MarketStats.correlation(row.closes, col.closes)
                }
                cells.add(CorrelationCell(row.instrument.symbol, col.instrument.symbol, r))
            }
        }
        return cells
    }

    private fun reduceError(message: String) {
        _uiState.update {
            if (it.instruments.isNotEmpty()) {
                it.copy(phase = MarketAnalysisUiState.Phase.Content)
            } else {
                it.copy(phase = MarketAnalysisUiState.Phase.Error, errorMessage = message)
            }
        }
    }

    private companion object {
        const val OFFLINE_FALLBACK = "Couldn't reach the market-data service. Tap retry."
    }
}
