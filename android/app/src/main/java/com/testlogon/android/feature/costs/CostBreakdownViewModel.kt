package com.testlogon.android.feature.costs

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.costs.CostsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** Drives [CostBreakdownUiState]. Mirrors the web CostBreakdownPage (date-scoped 3-tab table). */
@HiltViewModel
class CostBreakdownViewModel @Inject constructor(
    private val repository: CostsRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(CostBreakdownUiState(date = repository.today()))
    val uiState: StateFlow<CostBreakdownUiState> = _uiState.asStateFlow()

    init {
        load(fromUser = false)
    }

    fun onRefresh() = load(fromUser = true)
    fun onRetry() = load(fromUser = true)

    fun onDateChange(date: String) {
        if (date.isBlank() || date == _uiState.value.date) return
        _uiState.update { it.copy(date = date) }
        load(fromUser = true)
    }

    private fun load(fromUser: Boolean) {
        val state = _uiState.value
        if (state.isRefreshing) return
        val hasContent = state.summary != null
        _uiState.update {
            it.copy(
                phase = if (hasContent) it.phase else CostsPhase.Loading,
                isRefreshing = fromUser && hasContent,
            )
        }
        viewModelScope.launch {
            val date = _uiState.value.date
            val summaryResult = repository.loadDailySummary(date)
            val ticketsResult = repository.loadTicketCosts()
            when (summaryResult) {
                is ApiResult.Success -> {
                    val tickets = (ticketsResult as? ApiResult.Success)?.data.orEmpty()
                    val summary = summaryResult.data
                    val empty = summary.byAgentType.isEmpty() && summary.byWorker.isEmpty() && tickets.isEmpty()
                    _uiState.update {
                        it.copy(
                            phase = if (empty) CostsPhase.Empty else CostsPhase.Content,
                            summary = summary,
                            tickets = tickets,
                            isRefreshing = false,
                            errorMessage = null,
                        )
                    }
                }
                is ApiResult.Failure ->
                    if (summaryResult.error.status == HTTP_UNAUTHORIZED) {
                        _uiState.update { it.copy(phase = CostsPhase.SessionExpired, isRefreshing = false) }
                    } else {
                        reduceFailure(summaryResult.error.message, offline = false)
                    }
                is ApiResult.NetworkError -> reduceFailure(OFFLINE_FALLBACK, offline = true)
            }
        }
    }

    private fun reduceFailure(message: String, offline: Boolean) {
        _uiState.update {
            it.copy(
                phase = if (offline) CostsPhase.Offline else CostsPhase.Error,
                isRefreshing = false,
                errorMessage = message,
            )
        }
    }

    private companion object {
        private const val HTTP_UNAUTHORIZED = 401
        private const val OFFLINE_FALLBACK = "Could not reach the server. Pull down to retry."
    }
}
