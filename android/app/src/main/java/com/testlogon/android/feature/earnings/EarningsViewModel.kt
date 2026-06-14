package com.testlogon.android.feature.earnings

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.earnings.EarningsDashboard
import com.testlogon.android.data.earnings.EarningsPrefs
import com.testlogon.android.data.earnings.EarningsRange
import com.testlogon.android.data.earnings.EarningsRepository
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

/**
 * AND-252 — drives [EarningsUiState] from [EarningsRepository] + [EarningsPrefs].
 *
 * The initial range resolves deep-link arg -> persisted pref -> default D30. Range changes re-query
 * (quick-stats + summary combined in the repo) and persist the new range; on a failed refresh a cached
 * snapshot is served behind a stale banner (Offline-with-cache), else Error/Offline. One-shot messages
 * use a [Channel]-backed [effects] flow (not a StateFlow) so they are not replayed on rotation.
 */
@HiltViewModel
class EarningsViewModel @Inject constructor(
    private val repository: EarningsRepository,
    private val prefs: EarningsPrefs,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val deepLinkRange: EarningsRange? =
        savedStateHandle.get<String>(ARG_RANGE)?.let { EarningsRange.fromKey(it) }

    private val _uiState = MutableStateFlow(EarningsUiState())
    val uiState: StateFlow<EarningsUiState> = _uiState.asStateFlow()

    private val _effects = Channel<EarningsEffect>(Channel.BUFFERED)
    val effects: Flow<EarningsEffect> = _effects.receiveAsFlow()

    init {
        viewModelScope.launch {
            val initial = deepLinkRange ?: prefs.selectedRange()
            _uiState.update { it.copy(range = initial) }
            load(initial, fromUser = false)
        }
    }

    fun onRangeSelected(range: EarningsRange) {
        if (range == _uiState.value.range && _uiState.value.dashboard != null) return
        // Selecting a range resets the point selection and persists the choice.
        _uiState.update { it.copy(range = range, selectedPoint = null) }
        viewModelScope.launch { prefs.setSelectedRange(range) }
        load(range, fromUser = false)
    }

    fun onRefresh() = load(_uiState.value.range, fromUser = true)

    fun onRetry() = load(_uiState.value.range, fromUser = true)

    fun onChartTypeToggled() {
        _uiState.update {
            val next = if (it.chartType == ChartType.LINE) ChartType.BAR else ChartType.LINE
            it.copy(chartType = next, selectedPoint = null)
        }
    }

    fun onPointSelected(index: Int?) {
        _uiState.update { it.copy(selectedPoint = index) }
    }

    private fun load(range: EarningsRange, fromUser: Boolean) {
        val state = _uiState.value
        if (state.isRefreshing) return
        val hasContent = state.dashboard != null && state.dashboard.range == range
        _uiState.update {
            it.copy(
                phase = if (hasContent) it.phase else EarningsUiState.Phase.Loading,
                isRefreshing = fromUser && hasContent,
                errorMessage = if (hasContent) it.errorMessage else null,
            )
        }
        viewModelScope.launch {
            when (val result = repository.loadDashboard(range)) {
                is ApiResult.Success -> reduceSuccess(result.data)
                is ApiResult.Failure -> reduceFailure(range, result.error.message, offline = false)
                is ApiResult.NetworkError -> reduceFailure(range, OFFLINE_FALLBACK, offline = true)
            }
        }
    }

    private fun reduceSuccess(data: EarningsDashboard) {
        _uiState.update {
            it.copy(
                range = data.range,
                phase = if (data.isEmpty) EarningsUiState.Phase.Empty else EarningsUiState.Phase.Content,
                dashboard = if (data.isEmpty) null else data,
                isRefreshing = false,
                isStale = false,
                lastUpdated = data.fetchedAtEpochMs,
                errorMessage = null,
            )
        }
    }

    private suspend fun reduceFailure(range: EarningsRange, message: String, offline: Boolean) {
        val cached = repository.cached(range)
        if (cached != null) {
            _uiState.update {
                it.copy(
                    range = range,
                    phase = EarningsUiState.Phase.Content,
                    dashboard = cached.asStale(),
                    isRefreshing = false,
                    isStale = true,
                    lastUpdated = cached.fetchedAtEpochMs,
                    errorMessage = null,
                )
            }
            _effects.send(EarningsEffect.ShowMessage(R.string.earnings_refresh_failed_stale))
        } else {
            _uiState.update {
                it.copy(
                    range = range,
                    phase = if (offline) EarningsUiState.Phase.Offline else EarningsUiState.Phase.Error,
                    dashboard = null,
                    isRefreshing = false,
                    isStale = false,
                    errorMessage = message,
                )
            }
        }
    }

    companion object {
        const val ARG_RANGE = "range"
        private const val OFFLINE_FALLBACK = "Couldn't reach the server. Pull down to retry."
    }
}
