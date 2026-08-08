package com.testlogon.android.feature.markets

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.exchange.ExchangeRepository
import com.testlogon.android.data.exchange.Instrument
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
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
 * live-ish quotes, plus a periodic candle fetch that feeds each row's sparkline + % change. Starred
 * instruments (the watchlist) are persisted in SharedPreferences and surfaced via [MarketsUiState].
 */
@HiltViewModel
class MarketsViewModel @Inject constructor(
    private val repository: ExchangeRepository,
    @ApplicationContext appContext: Context,
) : ViewModel() {

    private val prefs = appContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    private val _uiState = MutableStateFlow(MarketsUiState(favorites = readFavorites()))
    val uiState: StateFlow<MarketsUiState> = _uiState.asStateFlow()

    init {
        load()
    }

    fun onRetry() = load()

    /** Toggle an instrument in the persisted watchlist. */
    fun toggleFavorite(symbolId: Int) {
        val next = _uiState.value.favorites.toMutableSet().apply {
            if (!add(symbolId)) remove(symbolId)
        }
        prefs.edit().putStringSet(KEY_FAV, next.map { it.toString() }.toSet()).apply()
        _uiState.update { it.copy(favorites = next) }
    }

    private fun readFavorites(): Set<Int> =
        prefs.getStringSet(KEY_FAV, emptySet()).orEmpty().mapNotNull { it.toIntOrNull() }.toSet()

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

    /** Continuously refresh each instrument's top-of-book + sparkline while the VM is alive. */
    private suspend fun pollQuotes(instruments: List<Instrument>) {
        var tick = 0
        while (viewModelScope.isActive) {
            for (instrument in instruments) {
                val book = (repository.orderBook(instrument.symbolId) as? ApiResult.Success)?.data
                val last = (repository.trades(instrument.symbolId) as? ApiResult.Success)
                    ?.data?.firstOrNull()?.price
                val lastPrice = last?.let { instrument.display(it) } ?: book?.mid

                // Candle-derived sparkline + % change; refreshed less often than the quote poll.
                var spark: List<Float>? = null
                var changePct: Double? = null
                if (tick % SPARK_EVERY == 0) {
                    val candles = (repository.candles(instrument.symbolId, SPARK_INTERVAL_SEC)
                        as? ApiResult.Success)?.data
                    if (!candles.isNullOrEmpty()) {
                        val window = candles.takeLast(SPARK_POINTS)
                        spark = window.map { instrument.display(it.close).toFloat() }
                        val firstOpen = instrument.display(window.first().open)
                        val lastClose = instrument.display(window.last().close)
                        if (firstOpen != 0.0) changePct = (lastClose - firstOpen) / firstOpen * 100.0
                    }
                }

                _uiState.update { state ->
                    state.copy(
                        rows = state.rows.map { row ->
                            if (row.instrument.symbolId == instrument.symbolId) {
                                row.copy(
                                    lastPrice = lastPrice,
                                    bestBid = book?.bestBid ?: book?.bids?.firstOrNull()?.price,
                                    bestAsk = book?.bestAsk ?: book?.asks?.firstOrNull()?.price,
                                    spark = spark ?: row.spark,
                                    changePct = changePct ?: row.changePct,
                                )
                            } else {
                                row
                            }
                        },
                    )
                }
            }
            tick++
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
        const val SPARK_EVERY = 5          // refresh sparkline/change every ~10s
        const val SPARK_INTERVAL_SEC = 60
        const val SPARK_POINTS = 30
        const val OFFLINE_FALLBACK = "Couldn't reach the market-data service. Tap retry."
        const val PREFS = "markets_prefs"
        const val KEY_FAV = "favorites"
    }
}
