package com.testlogon.android.feature.kyc.screening

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.kyc.screening.data.ScreeningRepository
import com.testlogon.android.feature.kyc.screening.model.KycScreeningResult
import com.testlogon.android.feature.kyc.screening.model.ScreeningStatus
import com.testlogon.android.feature.kyc.screening.model.aggregate
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-328 - presentation logic for the READ-ONLY KYC screening status screen.
 *
 * READ-ONLY REST (NO writes / SDK / flagged seam): [load] / [refresh] read the per-screen screening results
 * ONCE (single, non-looping) and aggregate them into one [ScreeningStatus] via the pure
 * [com.testlogon.android.feature.kyc.screening.model.aggregate] reducer. case_id is sourced inside the
 * repository from KycApi.listCases (latest case) OR taken from the optional [ARG_CASE_ID] nav arg here.
 *
 * STALE DISPLAY: on a refresh failure while a prior [ScreeningUiState.Content] is showing, the prior content
 * is kept with isStale=true (a snapshot of the last-known results) instead of replacing it with an Error.
 *
 * FR-8 AUTO-REFRESH (BOUNDED ONE-SHOT, NOT A LOOP): when the loaded status is transient (NOT_STARTED while a
 * case nonetheless exists is indistinguishable here from "no case", so the trigger is REVIEW or an
 * empty-but-loaded set), a SINGLE delayed re-poll is scheduled. It is one coroutine with ONE [delay] —
 * cancellable, guarded by [rePollScheduled] so it can never spin, and cancelled on [onCleared]. There is NO
 * unbounded loop, so tests never hang (they use runCurrent + a tiny bounded advanceTimeBy, never
 * advanceUntilIdle).
 */
@HiltViewModel
class ScreeningViewModel @Inject constructor(
    private val repository: ScreeningRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val caseId: String? =
        savedStateHandle.get<String>(ARG_CASE_ID)?.takeIf { it.isNotBlank() }

    private val _uiState = MutableStateFlow<ScreeningUiState>(ScreeningUiState.Loading)
    val uiState: StateFlow<ScreeningUiState> = _uiState.asStateFlow()

    /** Single in-flight read guard. */
    private var loadJob: Job? = null

    /** The single bounded one-shot re-poll coroutine (cancellable; never a loop). */
    private var rePollJob: Job? = null

    /** True once the one-shot re-poll has been scheduled, so it can never be scheduled twice (no spin). */
    private var rePollScheduled: Boolean = false

    /**
     * Delay before the single FR-8 re-poll. Settable so tests can keep it tiny / deterministic; production
     * uses [DEFAULT_REPOLL_DELAY_MS].
     */
    var rePollDelayMs: Long = DEFAULT_REPOLL_DELAY_MS

    init {
        load()
    }

    /** Initial read: flashes the spinner, then lands on Content or Error. */
    fun load() = read(showSpinner = true)

    /** Pull-to-refresh: re-reads without flashing the spinner; keeps prior content stale on failure. */
    fun refresh() = read(showSpinner = false)

    private fun read(showSpinner: Boolean) {
        val prior = _uiState.value as? ScreeningUiState.Content
        if (showSpinner) {
            _uiState.value = ScreeningUiState.Loading
        } else if (prior != null) {
            _uiState.value = prior.copy(refreshing = true)
        }

        loadJob?.cancel()
        loadJob = viewModelScope.launch {
            when (val result = repository.screening(caseId)) {
                is ApiResult.Success -> emitContent(result.data)
                is ApiResult.Failure -> emitFailure(prior, result.error.message, retryable = true)
                is ApiResult.NetworkError -> emitFailure(prior, OFFLINE, retryable = true)
            }
        }
    }

    private fun emitContent(results: List<KycScreeningResult>) {
        val status = aggregate(results)
        _uiState.value = ScreeningUiState.Content(
            status = status,
            results = results,
            isStale = false,
            lastUpdated = results.mapNotNull { it.screenedAt }.maxOrNull(),
            refreshing = false,
        )
        maybeScheduleRePoll(status, results)
    }

    /** On a refresh failure with prior content, KEEP it stale; otherwise surface a terminal Error. */
    private fun emitFailure(prior: ScreeningUiState.Content?, message: String, retryable: Boolean) {
        _uiState.value = prior?.copy(isStale = true, refreshing = false)
            ?: ScreeningUiState.Error(message, retryable)
    }

    /**
     * Schedules the SINGLE bounded one-shot re-poll when the status is transient (REVIEW, or an
     * empty-but-loaded set that may still be screening). Guarded by [rePollScheduled] so it never fires more
     * than once -> no loop, no test hang.
     */
    private fun maybeScheduleRePoll(status: ScreeningStatus, results: List<KycScreeningResult>) {
        if (rePollScheduled) return
        val transient = status == ScreeningStatus.REVIEW ||
            (results.isEmpty() && caseId != null)
        if (!transient) return

        rePollScheduled = true
        rePollJob = viewModelScope.launch {
            delay(rePollDelayMs)
            refresh()
        }
    }

    /** Re-runs the initial load after a terminal error. */
    fun retry() = load()

    override fun onCleared() {
        rePollJob?.cancel()
        super.onCleared()
    }

    companion object {
        const val ARG_CASE_ID = "caseId"

        /** Production delay for the single FR-8 re-poll. */
        const val DEFAULT_REPOLL_DELAY_MS = 8_000L

        private const val OFFLINE = "Couldn't reach the server. Try again."
    }
}
