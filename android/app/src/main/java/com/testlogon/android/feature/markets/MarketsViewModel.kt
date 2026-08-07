package com.testlogon.android.feature.markets

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.exchange.ExchangeRepository
import com.testlogon.android.data.exchange.Instrument
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
 * Drives [MarketsUiState] from [ExchangeRepository]. Loads the instrument catalogue, then polls each
 * instrument's top-of-book (order-book best bid/ask + last trade) every [POLL_MS] so the list shows
 * live-ish quotes. The `md/stream` WS is a later milestone; polling is the interim.
 */
@HiltViewModel
class MarketsViewModel @Inject constructor(
    private val repository: ExchangeRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(MarketsUiState())
    val uiState: StateFlow<MarketsUiState> = _uiState.asStateFlow()

    init {
        load()
    }

    fun onRetry() = load()

    private fun load() {
        _uiState.update { it.copy(phase = MarketsUiState.Phase.Loading, errorMessage = null) }
        viewModelScope.launch {
            when (val result = repository.symbols()) {
                is ApiResult.Success -> {
                    val instruments = result.data
                    if (instruments.isEmpty()) {
                        _uiState.update { it.copy(phase = MarketsUiState.Phase.Empty, rows = emptyList()) }
                    } else {
                        _uiState.update {
                            it.copy(
                                phase = MarketsUiState.Phase.Content,
                                rows = instruments.map { i -> MarketRow(instrument = i) },
                            )
                        }
                        pollQuotes(instruments)
                    }
                }
                is ApiResult.Failure -> reduceError(result.error.message)
                is ApiResult.NetworkError -> reduceError(OFFLINE_FALLBACK)
            }
        }
    }

    /** Continuously refresh each instrument's top-of-book while the ViewModel is alive. */
    private suspend fun pollQuotes(instruments: List<Instrument>) {
        while (viewModelScope.isActive) {
            for (instrument in instruments) {
                val book = (repository.orderBook(instrument.symbolId) as? ApiResult.Success)?.data
                val last = (repository.trades(instrument.symbolId) as? ApiResult.Success)
                    ?.data?.firstOrNull()?.price
                val lastPrice = last?.let { instrument.display(it) } ?: book?.mid
                _uiState.update { state ->
                    state.copy(
                        rows = state.rows.map { row ->
                            if (row.instrument.symbolId == instrument.symbolId) {
                                row.copy(
                                    lastPrice = lastPrice,
                                    bestBid = book?.bestBid ?: book?.bids?.firstOrNull()?.price,
                                    bestAsk = book?.bestAsk ?: book?.asks?.firstOrNull()?.price,
                                )
                            } else {
                                row
                            }
                        },
                    )
                }
            }
            delay(POLL_MS)
        }
    }

    private fun reduceError(message: String) {
        _uiState.update {
            if (it.rows.isNotEmpty()) {
                it.copy(phase = MarketsUiState.Phase.Content)
            } else {
                it.copy(phase = MarketsUiState.Phase.Error, errorMessage = message)
            }
        }
    }

    private companion object {
        const val POLL_MS = 2_000L
        const val OFFLINE_FALLBACK = "Couldn't reach the market-data service. Tap retry."
    }
}
