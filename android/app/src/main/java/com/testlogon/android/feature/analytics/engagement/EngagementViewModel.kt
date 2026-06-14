package com.testlogon.android.feature.analytics.engagement

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.analytics.Engagement
import com.testlogon.android.data.analytics.EngagementRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-254 — drives [EngagementUiState] from [EngagementRepository].
 *
 * The initial period resolves a deep-link arg -> default D30. Period changes re-query and reset the
 * point selection. A new period selection or refresh cancels the in-flight load so a slow earlier
 * response cannot overwrite newer state (last-write-wins by [loadJob] cancellation + request
 * generation). The ViewModel surfaces only domain types and label resources; no formatting here.
 */
@HiltViewModel
class EngagementViewModel @Inject constructor(
    private val repository: EngagementRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val deepLinkPeriod: EngagementPeriod? =
        savedStateHandle.get<String>(ARG_PERIOD)?.let { key ->
            EngagementPeriod.entries.firstOrNull { it.days.toString() == key }
        }

    private val _uiState = MutableStateFlow(EngagementUiState())
    val uiState: StateFlow<EngagementUiState> = _uiState.asStateFlow()

    private var loadJob: Job? = null
    private var requestGen = 0L

    init {
        val initial = deepLinkPeriod ?: EngagementPeriod.DEFAULT
        _uiState.update { it.copy(period = initial) }
        load(initial, fromUser = false)
    }

    fun onPeriodSelected(period: EngagementPeriod) {
        if (period == _uiState.value.period && _uiState.value.engagement != null) return
        _uiState.update { it.copy(period = period, selectedPoint = null) }
        load(period, fromUser = false)
    }

    fun onRefresh() = load(_uiState.value.period, fromUser = true)

    fun onRetry() = load(_uiState.value.period, fromUser = true)

    fun onChartTypeToggled() {
        _uiState.update {
            val next = if (it.chartType == EngagementChartType.LINE) {
                EngagementChartType.BAR
            } else {
                EngagementChartType.LINE
            }
            it.copy(chartType = next, selectedPoint = null)
        }
    }

    fun onPointSelected(index: Int?) {
        _uiState.update { it.copy(selectedPoint = index) }
    }

    private fun load(period: EngagementPeriod, fromUser: Boolean) {
        val gen = ++requestGen
        loadJob?.cancel()
        // Retain visible content only on a user refresh/retry of the SAME period; a period change (or
        // initial load) shows a full Loading surface because the prior content belongs to another window.
        val keepContent = fromUser && _uiState.value.engagement != null
        _uiState.update {
            it.copy(
                phase = if (keepContent) it.phase else EngagementUiState.Phase.Loading,
                engagement = if (keepContent) it.engagement else null,
                isRefreshing = keepContent,
                errorMessage = if (keepContent) it.errorMessage else null,
            )
        }
        loadJob = viewModelScope.launch {
            val result = repository.load(period.days)
            if (gen != requestGen) return@launch // superseded; drop the stale result
            when (result) {
                is ApiResult.Success -> reduceSuccess(period, result.data)
                is ApiResult.Failure ->
                    reduceFailure(period, result.error.message, offline = false)
                is ApiResult.NetworkError ->
                    reduceFailure(period, OFFLINE_FALLBACK, offline = true)
            }
        }
    }

    private fun reduceSuccess(period: EngagementPeriod, data: Engagement) {
        _uiState.update {
            it.copy(
                period = period,
                phase = if (data.isEmpty) EngagementUiState.Phase.Empty else EngagementUiState.Phase.Content,
                engagement = if (data.isEmpty) null else data,
                isRefreshing = false,
                errorMessage = null,
            )
        }
    }

    private fun reduceFailure(period: EngagementPeriod, message: String, offline: Boolean) {
        _uiState.update {
            it.copy(
                period = period,
                phase = if (offline) EngagementUiState.Phase.Offline else EngagementUiState.Phase.Error,
                engagement = if (it.engagement != null && it.period == period) it.engagement else null,
                isRefreshing = false,
                errorMessage = message,
            )
        }
    }

    companion object {
        const val ARG_PERIOD = "period"
        private const val OFFLINE_FALLBACK = "Couldn't reach the server. Pull down to retry."
    }
}
