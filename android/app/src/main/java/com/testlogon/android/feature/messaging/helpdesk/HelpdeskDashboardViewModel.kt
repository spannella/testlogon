package com.testlogon.android.feature.messaging.helpdesk

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.messaging.helpdesk.HelpdeskMetricsRepository
import com.testlogon.android.data.messaging.helpdesk.HelpdeskQueueItem
import com.testlogon.android.data.messaging.helpdesk.HelpdeskRepositoryImpl
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-377 — presentation logic for the helpdesk agent dashboard.
 *
 * Role resolution mirrors the web queue-403 probe (spec §1 / FR-1): there is NO readable role on
 * `/ui/me`, so the gate IS the agent-scoped queue fetch. [HelpdeskMetricsRepository.refreshMetrics]
 * reuses that fetch — a 403 ⇒ [HelpdeskDashboardUiState.AccessDenied] (no further request), a 200 ⇒
 * derive metrics + queue preview. On a transport failure the ViewModel falls back to the in-memory
 * cache ([HelpdeskDashboardUiState.Content] with `isStale = true`) when present, else a retryable
 * [HelpdeskDashboardUiState.Error]. An all-zero/no-data success ⇒ [HelpdeskDashboardUiState.Empty].
 *
 * The queue preview is exposed alongside the metrics (FR-3) so the dashboard renders both from a
 * single request — no separate Paging source / second queue fetch. `load()`/`refresh()` cancel any
 * in-flight job (single [Job] ref) to avoid stale emissions (§7).
 */
@HiltViewModel
class HelpdeskDashboardViewModel @Inject constructor(
    private val metricsRepository: HelpdeskMetricsRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<HelpdeskDashboardUiState>(HelpdeskDashboardUiState.Loading)
    val uiState: StateFlow<HelpdeskDashboardUiState> = _uiState.asStateFlow()

    private val _isRefreshing = MutableStateFlow(false)
    val isRefreshing: StateFlow<Boolean> = _isRefreshing.asStateFlow()

    private val _queuePreview = MutableStateFlow<List<HelpdeskQueueItem>>(emptyList())
    val queuePreview: StateFlow<List<HelpdeskQueueItem>> = _queuePreview.asStateFlow()

    private var loadJob: Job? = null

    init {
        load(isRefresh = false)
    }

    fun load(isRefresh: Boolean) {
        loadJob?.cancel()
        if (!isRefresh) _uiState.value = HelpdeskDashboardUiState.Loading
        loadJob = viewModelScope.launch {
            if (isRefresh) _isRefreshing.value = true
            try {
                _uiState.value = reduce(metricsRepository.refreshMetrics())
            } finally {
                if (isRefresh) _isRefreshing.value = false
            }
        }
    }

    fun refresh() = load(isRefresh = true)

    fun retry() = load(isRefresh = false)

    private fun reduce(result: ApiResult<com.testlogon.android.data.messaging.helpdesk.HelpdeskDashboardData>): HelpdeskDashboardUiState =
        when (result) {
            is ApiResult.Success -> {
                _queuePreview.value = result.data.queuePreview
                if (result.data.metrics.isEmpty && result.data.queuePreview.isEmpty()) {
                    HelpdeskDashboardUiState.Empty
                } else {
                    HelpdeskDashboardUiState.Content(
                        metrics = result.data.metrics,
                        isStale = false,
                        cachedAtEpochSeconds = null,
                    )
                }
            }
            is ApiResult.Failure ->
                if (result.error.status == HelpdeskRepositoryImpl.HTTP_FORBIDDEN) {
                    HelpdeskDashboardUiState.AccessDenied
                } else {
                    fallbackToCacheOrError(result.error.message)
                }
            is ApiResult.NetworkError ->
                fallbackToCacheOrError(OFFLINE_MESSAGE)
        }

    /** Offline/failure WITH cache -> stale Content + banner (FR-6); WITHOUT cache -> retryable Error. */
    private fun fallbackToCacheOrError(message: String): HelpdeskDashboardUiState {
        val cached = metricsRepository.cachedMetrics().value
        return if (cached != null) {
            _queuePreview.value = cached.data.queuePreview
            HelpdeskDashboardUiState.Content(
                metrics = cached.data.metrics,
                isStale = true,
                cachedAtEpochSeconds = cached.cachedAtEpochSeconds,
            )
        } else {
            HelpdeskDashboardUiState.Error(message = message, retryable = true)
        }
    }

    companion object {
        const val OFFLINE_MESSAGE = "You're offline. Try again when you're back online."
    }
}
