package com.testlogon.android.feature.markets

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.exchange.ExchangeRepository
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
 * Drives [SymbolDetailUiState] for one instrument. On start it resolves the symbol name from the
 * catalogue, then polls candles + order book + recent trades every [POLL_MS] while alive. The first
 * successful tick flips [SymbolDetailUiState.Phase] to Content; later ticks update content in place.
 */
@HiltViewModel
class SymbolDetailViewModel @Inject constructor(
    private val repository: ExchangeRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val symbolId: Int = savedStateHandle.get<Int>(SymbolDetailDest.ARG_SYMBOL_ID) ?: 0

    private val _uiState = MutableStateFlow(SymbolDetailUiState(symbolId = symbolId))
    val uiState: StateFlow<SymbolDetailUiState> = _uiState.asStateFlow()

    init {
        resolveName()
        poll()
    }

    fun onRetry() {
        _uiState.update { it.copy(phase = SymbolDetailUiState.Phase.Loading, errorMessage = null) }
        poll()
    }

    private fun resolveName() {
        viewModelScope.launch {
            val symbols = (repository.symbols() as? ApiResult.Success)?.data.orEmpty()
            val name = symbols.firstOrNull { it.symbolId == symbolId }?.symbol
                ?: "Symbol #$symbolId"
            _uiState.update { it.copy(symbolName = name) }
        }
    }

    private fun poll() {
        viewModelScope.launch {
            while (isActive) {
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
                delay(POLL_MS)
            }
        }
    }

    private companion object {
        const val POLL_MS = 2_000L
    }
}
