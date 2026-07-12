package com.testlogon.android.feature.costs

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.costs.CostsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** Drives [CostAlertsUiState]. Mirrors the web CostAlertsPage (list + unack/all filter + acknowledge). */
@HiltViewModel
class CostAlertsViewModel @Inject constructor(
    private val repository: CostsRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(CostAlertsUiState())
    val uiState: StateFlow<CostAlertsUiState> = _uiState.asStateFlow()

    private val _effects = Channel<CostsEffect>(Channel.BUFFERED)
    val effects: Flow<CostsEffect> = _effects.receiveAsFlow()

    init {
        load(fromUser = false)
    }

    fun onRefresh() = load(fromUser = true)
    fun onRetry() = load(fromUser = true)

    fun onFilterChange(unacknowledgedOnly: Boolean) {
        if (unacknowledgedOnly == _uiState.value.unacknowledgedOnly) return
        _uiState.update { it.copy(unacknowledgedOnly = unacknowledgedOnly) }
        load(fromUser = true)
    }

    fun onAcknowledge(alertId: String) = viewModelScope.launch {
        when (repository.acknowledgeAlert(alertId)) {
            is ApiResult.Success -> {
                _effects.send(CostsEffect.ShowMessage(R.string.costs_alert_acknowledged))
                load(fromUser = true)
            }
            else -> _effects.send(CostsEffect.ShowMessage(R.string.costs_action_failed))
        }
    }

    private fun load(fromUser: Boolean) {
        val state = _uiState.value
        if (state.isRefreshing) return
        val hasContent = state.phase == CostsPhase.Content || state.phase == CostsPhase.Empty
        _uiState.update {
            it.copy(
                phase = if (hasContent) it.phase else CostsPhase.Loading,
                isRefreshing = fromUser && hasContent,
            )
        }
        viewModelScope.launch {
            when (val result = repository.loadAlerts(_uiState.value.unacknowledgedOnly)) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(
                        phase = if (result.data.isEmpty()) CostsPhase.Empty else CostsPhase.Content,
                        alerts = result.data,
                        isRefreshing = false,
                        errorMessage = null,
                    )
                }
                is ApiResult.Failure ->
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _uiState.update { it.copy(phase = CostsPhase.SessionExpired, isRefreshing = false) }
                    } else {
                        _uiState.update {
                            it.copy(phase = CostsPhase.Error, isRefreshing = false, errorMessage = result.error.message)
                        }
                    }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(phase = CostsPhase.Offline, isRefreshing = false, errorMessage = OFFLINE_FALLBACK)
                }
            }
        }
    }

    private companion object {
        private const val HTTP_UNAUTHORIZED = 401
        private const val OFFLINE_FALLBACK = "Could not reach the server. Pull down to retry."
    }
}
