package com.testlogon.android.feature.strategies

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.strategies.Strategy
import com.testlogon.android.data.strategies.StrategiesRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** Which slice of the strategy list is shown. */
enum class StrategyListTab { MARKET, MINE }

data class StrategyMarketUiState(
    val phase: Phase = Phase.Loading,
    val tab: StrategyListTab = StrategyListTab.MARKET,
    val market: List<Strategy> = emptyList(),
    val mine: List<Strategy> = emptyList(),
    val errorMessage: String? = null,
) {
    enum class Phase { Loading, Content, Error }

    val rows: List<Strategy> get() = if (tab == StrategyListTab.MARKET) market else mine
}

/**
 * Drives the strategy MARKETPLACE + "My strategies" list. Loads both the PUBLISHED marketplace and the
 * caller's AUTHORED strategies; both degrade to empty on 404 so the screen shows an honest "pending
 * backend" empty state rather than an error when the endpoints are undeployed. A transport failure
 * (offline) on either read surfaces as a retryable error.
 */
@HiltViewModel
class StrategyMarketViewModel @Inject constructor(
    private val repository: StrategiesRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(StrategyMarketUiState())
    val uiState: StateFlow<StrategyMarketUiState> = _uiState.asStateFlow()

    init { load() }

    fun onRetry() = load()

    fun selectTab(tab: StrategyListTab) = _uiState.update { it.copy(tab = tab) }

    fun load() {
        _uiState.update { it.copy(phase = StrategyMarketUiState.Phase.Loading, errorMessage = null) }
        viewModelScope.launch {
            val market = repository.market()
            val mine = repository.mine()
            val netError = (market as? ApiResult.NetworkError) ?: (mine as? ApiResult.NetworkError)
            if (netError != null) {
                _uiState.update {
                    it.copy(
                        phase = StrategyMarketUiState.Phase.Error,
                        errorMessage = "No connection. Check your network and retry.",
                    )
                }
                return@launch
            }
            _uiState.update {
                it.copy(
                    phase = StrategyMarketUiState.Phase.Content,
                    market = (market as? ApiResult.Success)?.data.orEmpty(),
                    mine = (mine as? ApiResult.Success)?.data.orEmpty(),
                    errorMessage = null,
                )
            }
        }
    }
}
