package com.testlogon.android.feature.kyc.cases

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.kyc.cases.data.KycCaseRepository
import com.testlogon.android.feature.kyc.cases.model.KycCaseDetail
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-329 - presentation logic for the READ-ONLY KYC case-detail (status + synthesized timeline) screen.
 *
 * READ-ONLY REST (NO writes / SDK / flagged seam): [load] / [refresh] read the case ONCE (single, non-looping)
 * and the repository SYNTHESIZES the timeline. There is NO poll loop — refresh is manual (pull-to-refresh /
 * retry). The [caseId] is sourced from the [SavedStateHandle] nav arg ([ARG_CASE_ID]).
 *
 * STALE DISPLAY: on a refresh failure while a prior [KycCaseDetailUiState.Content] is showing, the prior
 * content is kept with isStale=true instead of being replaced by an Error.
 */
@HiltViewModel
class KycCaseDetailViewModel @Inject constructor(
    private val repository: KycCaseRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val caseId: String =
        savedStateHandle.get<String>(ARG_CASE_ID)?.takeIf { it.isNotBlank() }.orEmpty()

    private val _uiState = MutableStateFlow<KycCaseDetailUiState>(KycCaseDetailUiState.Loading)
    val uiState: StateFlow<KycCaseDetailUiState> = _uiState.asStateFlow()

    /** Single in-flight read guard. */
    private var loadJob: Job? = null

    init {
        load()
    }

    /** Initial read: flashes the spinner, then lands on Content or Error. */
    fun load() = read(showSpinner = true)

    /** Pull-to-refresh: re-reads without flashing the spinner; keeps prior content stale on failure. */
    fun refresh() = read(showSpinner = false)

    /** Re-runs the initial load after a terminal error. */
    fun retry() = load()

    private fun read(showSpinner: Boolean) {
        if (caseId.isEmpty()) {
            _uiState.value = KycCaseDetailUiState.Error(MISSING_CASE, retryable = false)
            return
        }

        val prior = _uiState.value as? KycCaseDetailUiState.Content
        if (showSpinner) {
            _uiState.value = KycCaseDetailUiState.Loading
        } else if (prior != null) {
            _uiState.value = prior.copy(refreshing = true)
        }

        loadJob?.cancel()
        loadJob = viewModelScope.launch {
            when (val result = repository.caseDetail(caseId)) {
                is ApiResult.Success -> emitContent(result.data)
                is ApiResult.Failure -> emitFailure(prior, result.error.message, retryable = true)
                is ApiResult.NetworkError -> emitFailure(prior, OFFLINE, retryable = true)
            }
        }
    }

    private fun emitContent(detail: KycCaseDetail) {
        _uiState.value = KycCaseDetailUiState.Content(
            case = detail.case,
            timeline = detail.timeline,
            reasonCodes = detail.reasonCodes,
            isStale = false,
            refreshing = false,
        )
    }

    /** On a refresh failure with prior content, KEEP it stale; otherwise surface a terminal Error. */
    private fun emitFailure(prior: KycCaseDetailUiState.Content?, message: String, retryable: Boolean) {
        _uiState.value = prior?.copy(isStale = true, refreshing = false)
            ?: KycCaseDetailUiState.Error(message, retryable)
    }

    companion object {
        const val ARG_CASE_ID = "caseId"

        private const val OFFLINE = "Couldn't reach the server. Try again."
        private const val MISSING_CASE = "Case not found."
    }
}
