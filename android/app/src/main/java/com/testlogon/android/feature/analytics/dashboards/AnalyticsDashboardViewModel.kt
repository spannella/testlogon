package com.testlogon.android.feature.analytics.dashboards

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.analytics.AnalyticsDashboard
import com.testlogon.android.data.analytics.AnalyticsDashboardRange
import com.testlogon.android.data.analytics.AnalyticsDashboardRepository
import com.testlogon.android.data.analytics.AnalyticsRangePrefs
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-399 - drives [AnalyticsDashboardUiState] from [AnalyticsDashboardRepository].
 *
 * The initial range resolves a deep-link arg -> the persisted preference -> the default (LAST_30). A
 * range change re-queries the whole fan-out and persists the preset (FR-8). A new range selection or
 * refresh cancels the in-flight load so a slow earlier response cannot overwrite newer state
 * (last-write-wins by [loadJob] cancellation + request generation, mirroring EngagementViewModel).
 *
 * On a network failure WITH a cached snapshot for the range, the prior dashboard is re-served with
 * isStale=true and a "showing saved data" banner instead of a blocking error (FR-6 / AC-4). With no
 * cache it falls to Error (HTTP) / Offline (transport).
 */
@HiltViewModel
class AnalyticsDashboardViewModel @Inject constructor(
    private val repository: AnalyticsDashboardRepository,
    private val rangePrefs: AnalyticsRangePrefs,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val deepLinkRange: AnalyticsDashboardRange? =
        savedStateHandle.get<String>(ARG_RANGE)?.let { key ->
            AnalyticsDashboardRange.entries.firstOrNull { it.apiKey.equals(key, ignoreCase = true) }
        }

    private val _uiState = MutableStateFlow(AnalyticsDashboardUiState())
    val uiState: StateFlow<AnalyticsDashboardUiState> = _uiState.asStateFlow()

    private var loadJob: Job? = null
    private var requestGen = 0L

    init {
        // Resolve the start range OFF the synchronous init path (the persisted pref read is suspend):
        // seed the deep-link/default immediately, then settle the persisted value inside the coroutine.
        val seed = deepLinkRange?.let { DashboardRangeOption.of(it) } ?: DashboardRangeOption.DEFAULT
        _uiState.update { it.copy(range = seed) }
        viewModelScope.launch {
            val resolved = deepLinkRange?.let { DashboardRangeOption.of(it) }
                ?: DashboardRangeOption.of(rangePrefs.selectedRange())
            _uiState.update { it.copy(range = resolved) }
            load(resolved, fromUser = false, refresh = false)
        }
    }

    fun onRangeSelected(option: DashboardRangeOption) {
        if (option == _uiState.value.range && _uiState.value.dashboard != null) return
        _uiState.update { it.copy(range = option) }
        viewModelScope.launch { rangePrefs.setSelectedRange(option.range) }
        load(option, fromUser = false, refresh = false)
    }

    fun onRefresh() = load(_uiState.value.range, fromUser = true, refresh = true)

    fun onRetry() = load(_uiState.value.range, fromUser = true, refresh = false)

    private fun load(option: DashboardRangeOption, fromUser: Boolean, refresh: Boolean) {
        val gen = ++requestGen
        loadJob?.cancel()
        // Keep visible content only on a user refresh/retry of the SAME range; a range change (or the
        // initial load) shows a full Loading surface because the prior content is for another window.
        val keepContent = fromUser && _uiState.value.dashboard != null && _uiState.value.range == option
        _uiState.update {
            it.copy(
                phase = if (keepContent) it.phase else AnalyticsDashboardUiState.Phase.Loading,
                dashboard = if (keepContent) it.dashboard else null,
                isStale = if (keepContent) it.isStale else false,
                isRefreshing = keepContent,
                errorMessage = if (keepContent) it.errorMessage else null,
            )
        }
        loadJob = viewModelScope.launch {
            val result = if (refresh) repository.refresh(option.range) else repository.loadDashboard(option.range)
            if (gen != requestGen) return@launch // superseded; drop the stale result
            when (result) {
                is ApiResult.Success -> reduceSuccess(option, result.data)
                is ApiResult.Failure -> reduceFailure(option, result.error.message, offline = false)
                is ApiResult.NetworkError -> reduceFailure(option, OFFLINE_FALLBACK, offline = true)
            }
        }
    }

    private fun reduceSuccess(option: DashboardRangeOption, data: AnalyticsDashboard) {
        _uiState.update {
            it.copy(
                range = option,
                phase = if (data.isEmpty) {
                    AnalyticsDashboardUiState.Phase.Empty
                } else {
                    AnalyticsDashboardUiState.Phase.Content
                },
                dashboard = if (data.isEmpty) null else data,
                isStale = false,
                isRefreshing = false,
                errorMessage = null,
            )
        }
    }

    private fun reduceFailure(option: DashboardRangeOption, message: String, offline: Boolean) {
        // Prefer serving a cached snapshot (stale) over a blocking error (FR-6 / AC-4).
        val cached = repository.cached(option.range)
        if (cached != null && !cached.isEmpty) {
            _uiState.update {
                it.copy(
                    range = option,
                    phase = AnalyticsDashboardUiState.Phase.Content,
                    dashboard = cached,
                    isStale = true,
                    isRefreshing = false,
                    errorMessage = null,
                )
            }
            return
        }
        _uiState.update {
            it.copy(
                range = option,
                phase = if (offline) {
                    AnalyticsDashboardUiState.Phase.Offline
                } else {
                    AnalyticsDashboardUiState.Phase.Error
                },
                dashboard = null,
                isStale = false,
                isRefreshing = false,
                errorMessage = message,
            )
        }
    }

    companion object {
        const val ARG_RANGE = "range"
        private const val OFFLINE_FALLBACK = "Couldn't reach the server. Pull down to retry."
    }
}
