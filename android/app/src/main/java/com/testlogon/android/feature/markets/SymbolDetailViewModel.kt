package com.testlogon.android.feature.markets

import android.content.Context
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.exchange.Candle
import com.testlogon.android.data.exchange.ExchangeRepository
import com.testlogon.android.data.exchange.ExchangeStream
import com.testlogon.android.feature.markets.chart.Anchor
import com.testlogon.android.feature.markets.chart.ChartDrawing
import com.testlogon.android.feature.markets.chart.DrawingTool
import com.testlogon.android.navigation.SymbolDetailDest
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Drives [SymbolDetailUiState] for one instrument.
 *
 * On start it resolves the symbol name, does a one-shot REST fetch of the order book + candle
 * history + trades for the first paint, then goes LIVE: [ExchangeStream.marketData] pushes an
 * order-book + latest-candle frame on every book change (server-sent events). The order book is
 * therefore no longer polled — SSE drives it, and [SymbolDetailUiState.live] flips true once the
 * first frame lands. Trades are NOT carried on the stream, so they keep a (relaxed) REST poll.
 *
 * User chart drawings (trendlines / fib / etc.) are persisted per symbol in SharedPreferences.
 */
@HiltViewModel
class SymbolDetailViewModel @Inject constructor(
    private val repository: ExchangeRepository,
    private val exchangeStream: ExchangeStream,
    @ApplicationContext appContext: Context,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val symbolId: Int = savedStateHandle.get<Int>(SymbolDetailDest.ARG_SYMBOL_ID) ?: 0
    private val drawingPrefs = appContext.getSharedPreferences(DRAW_PREFS, Context.MODE_PRIVATE)

    private val _uiState = MutableStateFlow(
        SymbolDetailUiState(symbolId = symbolId, drawings = loadDrawings()),
    )
    val uiState: StateFlow<SymbolDetailUiState> = _uiState.asStateFlow()

    /** The current live-stream collector; cancelled + restarted when the timeframe changes. */
    private var streamJob: Job? = null

    init {
        resolveName()
        initialFetch()
        streamMarketData()
        pollTrades()
    }

    fun onRetry() {
        _uiState.update { it.copy(phase = SymbolDetailUiState.Phase.Loading, errorMessage = null) }
        initialFetch()
    }

    /** Select the active drawing tool (or NONE to return to normal pan/zoom). */
    fun setTool(tool: DrawingTool) {
        _uiState.update { it.copy(activeTool = if (it.activeTool == tool) DrawingTool.NONE else tool) }
    }

    /** Append a committed drawing and persist. */
    fun addDrawing(drawing: ChartDrawing) {
        val next = _uiState.value.drawings + drawing
        _uiState.update { it.copy(drawings = next) }
        saveDrawings(next)
    }

    /** Remove all drawings for this symbol. */
    fun clearDrawings() {
        _uiState.update { it.copy(drawings = emptyList()) }
        saveDrawings(emptyList())
    }

    /**
     * Switch the chart timeframe: re-fetch candle history at [intervalSec] and restart the live SSE
     * stream at the same interval so live bars align with the selected grid. No-op if unchanged.
     */
    fun setInterval(intervalSec: Int) {
        if (intervalSec == _uiState.value.intervalSec) return
        _uiState.update { it.copy(intervalSec = intervalSec, candles = emptyList()) }
        refetchCandles(intervalSec)
        streamMarketData()
    }

    private fun refetchCandles(intervalSec: Int) {
        viewModelScope.launch {
            when (val candles = repository.candles(symbolId, intervalSec)) {
                is ApiResult.Success -> _uiState.update { it.copy(candles = candles.data) }
                else -> Unit
            }
        }
    }

    private fun resolveName() {
        viewModelScope.launch {
            val symbols = (repository.symbols() as? ApiResult.Success)?.data.orEmpty()
            val name = symbols.firstOrNull { it.symbolId == symbolId }?.symbol
                ?: "Symbol #$symbolId"
            _uiState.update { it.copy(symbolName = name) }
        }
    }

    /** One-shot REST fetch for the first paint (order book snapshot + candle history + trades). */
    private fun initialFetch() {
        viewModelScope.launch {
            val intervalSec = _uiState.value.intervalSec
            val candles = repository.candles(symbolId, intervalSec)
            // Publish candle history immediately so a slow book/trades fetch (or the concurrent SSE
            // stream seeding a single bar from empty) can't leave the chart stuck on one candle.
            if (candles is ApiResult.Success && candles.data.isNotEmpty()) {
                _uiState.update { it.copy(candles = candles.data, phase = SymbolDetailUiState.Phase.Content) }
            }
            val book = repository.orderBook(symbolId, depth = 50)
            val trades = repository.trades(symbolId)

            val anyOk = candles is ApiResult.Success ||
                book is ApiResult.Success ||
                trades is ApiResult.Success

            _uiState.update { state ->
                state.copy(
                    phase = when {
                        anyOk -> SymbolDetailUiState.Phase.Content
                        state.phase == SymbolDetailUiState.Phase.Loading ->
                            SymbolDetailUiState.Phase.Error
                        else -> state.phase
                    },
                    candles = (candles as? ApiResult.Success)?.data ?: state.candles,
                    orderBook = (book as? ApiResult.Success)?.data ?: state.orderBook,
                    trades = (trades as? ApiResult.Success)?.data ?: state.trades,
                    errorMessage = if (anyOk) null else "Couldn't load market data.",
                )
            }
        }
    }

    /** LIVE order book + latest candle via SSE. Cancelled automatically when the scope clears. */
    private fun streamMarketData() {
        streamJob?.cancel()
        val intervalSec = _uiState.value.intervalSec
        streamJob = viewModelScope.launch {
            exchangeStream.marketData(symbolId, intervalSec).collect { frame ->
                _uiState.update { state ->
                    state.copy(
                        phase = SymbolDetailUiState.Phase.Content,
                        orderBook = frame.orderBook,
                        candles = frame.candle?.let { mergeCandle(state.candles, it) } ?: state.candles,
                        live = true,
                        errorMessage = null,
                    )
                }
            }
        }
    }

    /** Trades are not carried on the stream, so poll them (relaxed cadence). */
    private fun pollTrades() {
        viewModelScope.launch {
            while (isActive) {
                when (val trades = repository.trades(symbolId)) {
                    is ApiResult.Success -> _uiState.update { it.copy(trades = trades.data) }
                    else -> Unit
                }
                delay(TRADES_POLL_MS)
            }
        }
    }

    private fun mergeCandle(existing: List<Candle>, latest: Candle): List<Candle> {
        if (existing.isEmpty()) return listOf(latest)
        val last = existing.last()
        return if (last.tsStartNs == latest.tsStartNs) {
            // Same bar still forming -> replace the last candle in place.
            existing.dropLast(1) + latest
        } else {
            // A new bar started -> append it.
            existing + latest
        }
    }

    // ---- drawing persistence (SharedPreferences, one CSV-ish blob per symbol) ----

    private fun loadDrawings(): List<ChartDrawing> {
        val blob = drawingPrefs.getString(key(), null).orEmpty()
        if (blob.isBlank()) return emptyList()
        return blob.split(";").mapNotNull { part ->
            val f = part.split("|")
            if (f.size < 5) return@mapNotNull null
            val tool = runCatching { DrawingTool.valueOf(f[0]) }.getOrNull() ?: return@mapNotNull null
            val aTs = f[1].toLongOrNull() ?: return@mapNotNull null
            val aPrice = f[2].toDoubleOrNull() ?: return@mapNotNull null
            val bTs = f[3].toLongOrNull()
            val bPrice = f[4].toDoubleOrNull()
            val b = if (bTs != null && bPrice != null) Anchor(bTs, bPrice) else null
            ChartDrawing(id = aTs, tool = tool, a = Anchor(aTs, aPrice), b = b)
        }
    }

    private fun saveDrawings(list: List<ChartDrawing>) {
        val blob = list.joinToString(";") { d ->
            val b = d.b
            "${d.tool.name}|${d.a.tsNs}|${d.a.price}|${b?.tsNs ?: ""}|${b?.price ?: ""}"
        }
        drawingPrefs.edit().putString(key(), blob).apply()
    }

    private fun key() = "sym_$symbolId"

    private companion object {
        const val TRADES_POLL_MS = 4_000L
        const val DRAW_PREFS = "chart_drawings"
    }
}
