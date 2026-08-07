package com.testlogon.android.feature.markets

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.exchange.Candle
import com.testlogon.android.data.exchange.ExchangeRepository
import com.testlogon.android.data.exchange.ExchangeStream
import com.testlogon.android.navigation.SymbolDetailDest
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
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
 */
@HiltViewModel
class SymbolDetailViewModel @Inject constructor(
    private val repository: ExchangeRepository,
    private val exchangeStream: ExchangeStream,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val symbolId: Int = savedStateHandle.get<Int>(SymbolDetailDest.ARG_SYMBOL_ID) ?: 0

    private val _uiState = MutableStateFlow(SymbolDetailUiState(symbolId = symbolId))
    val uiState: StateFlow<SymbolDetailUiState> = _uiState.asStateFlow()

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
            val candles = repository.candles(symbolId)
            val book = repository.orderBook(symbolId)
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
        viewModelScope.launch {
            exchangeStream.marketData(symbolId).collect { frame ->
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

    private companion object {
        const val TRADES_POLL_MS = 4_000L
    }
}
