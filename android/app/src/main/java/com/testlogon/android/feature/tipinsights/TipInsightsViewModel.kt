package com.testlogon.android.feature.tipinsights

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.tipinsights.TipInsights
import com.testlogon.android.data.tipinsights.TipInsightsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** TIPX-D3/D4 — the period filter for the tips measurement screen. */
enum class TipInsightsPeriod(val apiValue: String) {
    D7("7d"),
    D30("30d"),
    ALL("all"),
}

data class TipInsightsUiState(
    val phase: Phase = Phase.Loading,
    val period: TipInsightsPeriod = TipInsightsPeriod.D30,
    val insights: TipInsights? = null,
    val isRefreshing: Boolean = false,
    val errorMessage: String? = null,
    val isOffline: Boolean = false,
) {
    enum class Phase { Loading, Content, Error }
}

/**
 * TIPX-D3/D4 — drives [TipInsightsUiState] from [TipInsightsRepository].
 *
 * A load pulls the creator's ledger-backed tips-received summary (NET, all surfaces,
 * reversed-excluded — reconciles to earnings/leaderboard) plus the tipper's sent receipts, in one
 * shot. Period changes re-query the RECEIVED summary window (sent history is all-time).
 */
@HiltViewModel
class TipInsightsViewModel @Inject constructor(
    private val repository: TipInsightsRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(TipInsightsUiState())
    val uiState: StateFlow<TipInsightsUiState> = _uiState.asStateFlow()

    init {
        load(_uiState.value.period, fromUser = false)
    }

    fun onPeriodSelected(period: TipInsightsPeriod) {
        if (period == _uiState.value.period && _uiState.value.insights != null) return
        _uiState.update { it.copy(period = period) }
        load(period, fromUser = false)
    }

    fun onRefresh() = load(_uiState.value.period, fromUser = true)

    fun onRetry() = load(_uiState.value.period, fromUser = true)

    private fun load(period: TipInsightsPeriod, fromUser: Boolean) {
        val hasContent = _uiState.value.insights != null
        _uiState.update {
            it.copy(
                phase = if (hasContent) it.phase else TipInsightsUiState.Phase.Loading,
                isRefreshing = fromUser && hasContent,
                errorMessage = if (hasContent) it.errorMessage else null,
            )
        }
        viewModelScope.launch {
            when (val result = repository.load(period.apiValue)) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(
                        phase = TipInsightsUiState.Phase.Content,
                        insights = result.data,
                        isRefreshing = false,
                        errorMessage = null,
                        isOffline = false,
                    )
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(
                        phase = if (it.insights != null) TipInsightsUiState.Phase.Content else TipInsightsUiState.Phase.Error,
                        isRefreshing = false,
                        errorMessage = result.error.message,
                        isOffline = false,
                    )
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(
                        phase = if (it.insights != null) TipInsightsUiState.Phase.Content else TipInsightsUiState.Phase.Error,
                        isRefreshing = false,
                        errorMessage = "You're offline. Try again.",
                        isOffline = true,
                    )
                }
            }
        }
    }
}
