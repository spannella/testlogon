package com.testlogon.android.feature.dashboard

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.Dashboard
import com.testlogon.android.data.dashboard.DashboardRepository
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
 * AND-068 — drives [DashboardUiState] from [DashboardRepository].
 *
 * Loads on init, supports pull-to-refresh and retry, and serves a last-known-good snapshot behind a
 * stale indicator when a refresh fails (offline state). One-shot messages are emitted on a
 * [Channel]-backed [effects] flow (not a StateFlow) so they are not replayed on rotation — and the
 * init-time emission is safely buffered.
 */
@HiltViewModel
class DashboardViewModel @Inject constructor(
    private val repository: DashboardRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(DashboardUiState())
    val uiState: StateFlow<DashboardUiState> = _uiState.asStateFlow()

    private val _effects = Channel<DashboardEffect>(Channel.BUFFERED)
    val effects: Flow<DashboardEffect> = _effects.receiveAsFlow()

    init {
        load(fromUser = false)
    }

    /** Pull-to-refresh: forces a server-side refresh trigger before re-reading the summary. */
    fun onRefresh() = load(fromUser = true)

    /** Retry from an Error/Empty surface: behaves like a fresh load. */
    fun onRetry() = load(fromUser = true)

    private fun load(fromUser: Boolean) {
        val state = _uiState.value
        // FR-5 de-dup: ignore overlapping loads while one is already in flight.
        if (state.isRefreshing || (state.phase == DashboardUiState.Phase.Loading && state.dashboard == null && fromUser)) {
            return
        }
        _uiState.update { it.startLoad(fromUser = fromUser) }
        viewModelScope.launch {
            when (val result = repository.getDashboard(forceRefresh = fromUser)) {
                is ApiResult.Success -> _uiState.update { it.toContentOrEmpty(result.data) }
                is ApiResult.Failure -> reduceFailure(result.error.message)
                is ApiResult.NetworkError -> reduceFailure(OFFLINE_MESSAGE_FALLBACK)
            }
        }
    }

    private suspend fun reduceFailure(message: String) {
        val cached = repository.cachedDashboard()
        if (cached != null) {
            // Keep content visible behind a stale indicator; surface a one-shot banner.
            _uiState.update { it.toStaleContent(cached) }
            _effects.send(DashboardEffect.ShowMessage(R.string.dashboard_refresh_failed_stale))
        } else {
            _uiState.update { it.toError(message) }
        }
    }

    private companion object {
        const val OFFLINE_MESSAGE_FALLBACK =
            "Couldn't reach the server. Pull down to retry."
    }
}

// ---- Pure reducers (dispatcher-free, unit-testable in isolation) ----

internal fun DashboardUiState.startLoad(fromUser: Boolean): DashboardUiState {
    val hasContent = dashboard != null
    return copy(
        phase = if (hasContent) phase else DashboardUiState.Phase.Loading,
        isRefreshing = fromUser && hasContent,
        errorMessage = if (hasContent) errorMessage else null,
    )
}

internal fun DashboardUiState.toContentOrEmpty(data: Dashboard): DashboardUiState = copy(
    phase = if (data.isEmpty) DashboardUiState.Phase.Empty else DashboardUiState.Phase.Content,
    dashboard = if (data.isEmpty) null else data,
    isRefreshing = false,
    isStale = false,
    errorMessage = null,
)

internal fun DashboardUiState.toStaleContent(cached: Dashboard): DashboardUiState = copy(
    phase = DashboardUiState.Phase.Content,
    dashboard = cached,
    isRefreshing = false,
    isStale = true,
    errorMessage = null,
)

internal fun DashboardUiState.toError(message: String): DashboardUiState = copy(
    phase = DashboardUiState.Phase.Error,
    dashboard = null,
    isRefreshing = false,
    isStale = false,
    errorMessage = message,
)
