package com.testlogon.android.feature.kyc.cases

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.kyc.cases.data.KycCaseRepository
import com.testlogon.android.feature.kyc.cases.model.KycCaseSummary
import com.testlogon.android.feature.kyc.cases.model.MonitoringState
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-329 - presentation logic for the READ-ONLY KYC case-list + monitoring-banner screen.
 *
 * READ-ONLY REST (NO writes / SDK / flagged seam): [load] / [refresh] read the case list AND the
 * ongoing-monitoring banner state ONCE each (single, non-looping). There is NO poll loop — refresh is manual
 * (pull-to-refresh / retry). Cases are sorted newest-first by createdAt; the derived [MonitoringState] is
 * surfaced alongside the list (and on the Empty state, so a banner can still show when there are no cases).
 *
 * STALE DISPLAY: on a refresh failure while a prior [KycCaseListUiState.Content] is showing, the prior content
 * is kept with isStale=true instead of being replaced by an Error. The monitoring read failing on its own does
 * NOT fail the screen: the list still renders with an INACTIVE banner.
 */
@HiltViewModel
class KycCaseListViewModel @Inject constructor(
    private val repository: KycCaseRepository,
    @Suppress("UNUSED_PARAMETER") savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val _uiState = MutableStateFlow<KycCaseListUiState>(KycCaseListUiState.Loading)
    val uiState: StateFlow<KycCaseListUiState> = _uiState.asStateFlow()

    /** Single in-flight read guard. */
    private var loadJob: Job? = null

    init {
        load()
    }

    /** Initial read: flashes the spinner, then lands on Content / Empty / Error. */
    fun load() = read(showSpinner = true)

    /** Pull-to-refresh: re-reads without flashing the spinner; keeps prior content stale on failure. */
    fun refresh() = read(showSpinner = false)

    /** Re-runs the initial load after a terminal error. */
    fun retry() = load()

    private fun read(showSpinner: Boolean) {
        val prior = _uiState.value as? KycCaseListUiState.Content
        if (showSpinner) {
            _uiState.value = KycCaseListUiState.Loading
        } else if (prior != null) {
            _uiState.value = prior.copy(refreshing = true)
        }

        loadJob?.cancel()
        loadJob = viewModelScope.launch {
            // Monitoring is best-effort: a failure here yields an INACTIVE banner, never a screen error.
            val monitoring = when (val m = repository.monitoring()) {
                is ApiResult.Success -> m.data
                else -> MonitoringState.INACTIVE
            }
            when (val result = repository.cases()) {
                is ApiResult.Success -> emitContent(result.data, monitoring)
                is ApiResult.Failure -> emitFailure(prior, result.error.message, retryable = true)
                is ApiResult.NetworkError -> emitFailure(prior, OFFLINE, retryable = true)
            }
        }
    }

    private fun emitContent(cases: List<KycCaseSummary>, monitoring: MonitoringState) {
        if (cases.isEmpty()) {
            _uiState.value = KycCaseListUiState.Empty(monitoring = monitoring)
            return
        }
        _uiState.value = KycCaseListUiState.Content(
            cases = cases.sortedByDescending { it.createdAt },
            monitoring = monitoring,
            isStale = false,
            refreshing = false,
        )
    }

    /** On a refresh failure with prior content, KEEP it stale; otherwise surface a terminal Error. */
    private fun emitFailure(prior: KycCaseListUiState.Content?, message: String, retryable: Boolean) {
        _uiState.value = prior?.copy(isStale = true, refreshing = false)
            ?: KycCaseListUiState.Error(message, retryable)
    }

    companion object {
        private const val OFFLINE = "Couldn't reach the server. Try again."
    }
}
