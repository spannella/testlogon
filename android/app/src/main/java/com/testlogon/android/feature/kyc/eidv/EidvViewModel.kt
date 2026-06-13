package com.testlogon.android.feature.kyc.eidv

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.kyc.eidv.data.EidvRepository
import com.testlogon.android.feature.kyc.eidv.model.EidScheme
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-325 - presentation logic for the KYC electronic ID verification (eIDV) redirect flow.
 *
 * REAL REST REDIRECT eIDV (NO PII submitted, NO vendor / ML / CameraX SDK, NO flagged seam): the VM lists
 * schemes, ensures a draft KYC case (REUSING AND-319 KycApi.createCase via the repo), starts a session for
 * the chosen scheme (only the {scheme} token leaves the device), exposes the returned redirect_url for the
 * SCREEN to open EXTERNALLY (ACTION_VIEW), then polls status until an eid_verification assertion appears or
 * the session expires. The VM never opens a URL itself.
 *
 * STATUS POLL ANTI-HANG: the poll is a cancellable [Job] that is NOT auto-started in [init]. It is started
 * only when entering [EidvUiState.AwaitingProvider] (via [start] / [onProviderReturned]); it loops while the
 * scope is active, the session has not expired, and a poll budget remains, calling status() each iteration
 * and stopping on the first assertion ([EidvUiState.Result]) or at expiry ([EidvUiState.Expired]). The
 * interval is the settable property [pollIntervalMillis] (NOT a ctor param - Hilt cannot provide a bare
 * Long). The job is cancelled on Result / Expired / restart / onCleared. Tests set [pollIntervalMillis],
 * drive a SINGLE iteration with runCurrent, then stop - NEVER advanceUntilIdle.
 *
 * case_id is sourced from [SavedStateHandle] (the optional nav arg [ARG_CASE_ID]); if absent it is created
 * lazily via ensureDraftCase on [start]. On [init], if a case id is already in context, status() is checked
 * first and the flow skips straight to [EidvUiState.Result] when a verification already exists (FR-6).
 * SavedStateHandle persists caseId / sessionId / the selected scheme across process death (FR-7).
 */
@HiltViewModel
class EidvViewModel @Inject constructor(
    private val repository: EidvRepository,
    private val savedStateHandle: SavedStateHandle,
) : ViewModel() {

    /**
     * Poll interval (ms). NOT a constructor param - Hilt cannot provide a bare [Long] and ignores Kotlin
     * defaults. Tests set this directly after construction to drive fast single iterations.
     */
    internal var pollIntervalMillis: Long = DEFAULT_POLL_INTERVAL_MILLIS

    private val _uiState = MutableStateFlow<EidvUiState>(EidvUiState.Loading)
    val uiState: StateFlow<EidvUiState> = _uiState.asStateFlow()

    private var pollJob: Job? = null

    init {
        // No poll loop is started here (an unbounded delay loop in init would spin runTest forever). A
        // resume case id, if present, is status-checked once; otherwise the scheme list is loaded once.
        val resumeCaseId = savedStateHandle.get<String>(SAVED_CASE_ID)
            ?: savedStateHandle.get<String>(ARG_CASE_ID)
        if (resumeCaseId != null && resumeCaseId.isNotBlank()) {
            savedStateHandle[SAVED_CASE_ID] = resumeCaseId
            resumeFrom(resumeCaseId)
        } else {
            loadSchemes()
        }
    }

    /** Single non-looping load of the available schemes. */
    fun loadSchemes() {
        _uiState.value = EidvUiState.Loading
        viewModelScope.launch {
            when (val result = repository.listSchemes()) {
                is ApiResult.Success -> _uiState.value = EidvUiState.SchemeSelection(
                    schemes = result.data,
                    selected = savedStateHandle.get<String>(SAVED_SCHEME)?.let { EidScheme.fromToken(it) },
                )
                is ApiResult.Failure -> _uiState.value =
                    EidvUiState.Error(result.error.message, EidvUiState.Retry.LOAD)
                is ApiResult.NetworkError -> _uiState.value =
                    EidvUiState.Error(OFFLINE, EidvUiState.Retry.LOAD)
            }
        }
    }

    /**
     * Resume path (FR-6): a case id is already known, so check status once. If a verification already
     * exists, skip straight to [EidvUiState.Result]; otherwise fall back to scheme selection so the user
     * can start (a fresh) verification.
     */
    private fun resumeFrom(caseId: String) {
        _uiState.value = EidvUiState.Loading
        viewModelScope.launch {
            when (val result = repository.status(caseId)) {
                is ApiResult.Success -> {
                    val verification = result.data.verification
                    if (verification != null) {
                        _uiState.value = EidvUiState.Result(
                            caseId = caseId,
                            verification = verification,
                            hasCriticalDiscrepancy = verification.hasCriticalDiscrepancy,
                            autoTierUpgrade = result.data.autoTierUpgrade,
                        )
                    } else {
                        loadSchemes()
                    }
                }
                // A status failure on resume is non-fatal: fall back to letting the user start fresh.
                is ApiResult.Failure -> loadSchemes()
                is ApiResult.NetworkError -> loadSchemes()
            }
        }
    }

    /** Selects [scheme] in the scheme-selection state and persists it across process death (FR-7). */
    fun onSchemeSelected(scheme: EidScheme) {
        val current = _uiState.value as? EidvUiState.SchemeSelection ?: return
        savedStateHandle[SAVED_SCHEME] = scheme.wire
        _uiState.value = current.copy(selected = scheme)
    }

    /**
     * Starts an eID session for the selected scheme. DEBOUNCED via [EidvUiState.SchemeSelection.starting]
     * (the start POST is non-idempotent and NOT auto-retried). Ensures a draft case first when no case id
     * is known yet (REUSING AND-319 createCase), then starts the session, enters [AwaitingProvider] (the
     * screen opens redirect_url externally), and begins the bounded status poll.
     */
    fun start() {
        val current = _uiState.value as? EidvUiState.SchemeSelection ?: return
        val scheme = current.selected ?: return
        if (current.starting) return // debounce: a start is already in flight.

        _uiState.value = current.copy(starting = true)
        viewModelScope.launch {
            val caseId = when (val ensured = ensureCaseId()) {
                is ApiResult.Success -> ensured.data
                is ApiResult.Failure -> {
                    _uiState.value = EidvUiState.Error(ensured.error.message, EidvUiState.Retry.START)
                    return@launch
                }
                is ApiResult.NetworkError -> {
                    _uiState.value = EidvUiState.Error(OFFLINE, EidvUiState.Retry.START)
                    return@launch
                }
            }

            when (val result = repository.start(caseId, scheme.wire)) {
                is ApiResult.Success -> {
                    savedStateHandle[SAVED_SESSION_ID] = result.data.sessionId
                    enterAwaiting(
                        caseId = caseId,
                        scheme = scheme,
                        sessionId = result.data.sessionId,
                        redirectUrl = result.data.redirectUrl,
                        expiresAtEpochSec = result.data.expiresAt.epochSecond,
                    )
                }
                is ApiResult.Failure ->
                    _uiState.value = EidvUiState.Error(result.error.message, EidvUiState.Retry.START)
                is ApiResult.NetworkError ->
                    _uiState.value = EidvUiState.Error(OFFLINE, EidvUiState.Retry.START)
            }
        }
    }

    /** Returns the existing case id (from saved state) or creates a draft one (REUSING AND-319 createCase). */
    private suspend fun ensureCaseId(): ApiResult<String> {
        savedStateHandle.get<String>(SAVED_CASE_ID)?.takeIf { it.isNotBlank() }?.let {
            return ApiResult.Success(it)
        }
        return when (val created = repository.ensureDraftCase()) {
            is ApiResult.Success -> {
                savedStateHandle[SAVED_CASE_ID] = created.data
                created
            }
            is ApiResult.Failure -> created
            is ApiResult.NetworkError -> created
        }
    }

    /** Moves to [AwaitingProvider] and (re)starts the bounded status poll. */
    private fun enterAwaiting(
        caseId: String,
        scheme: EidScheme,
        sessionId: String,
        redirectUrl: String,
        expiresAtEpochSec: Long,
    ) {
        _uiState.value = EidvUiState.AwaitingProvider(
            caseId = caseId,
            sessionId = sessionId,
            scheme = scheme,
            redirectUrl = redirectUrl,
            expiresAt = expiresAtEpochSec,
            polling = true,
        )
        startPolling()
    }

    /**
     * Begins the bounded status poll. ANTI-HANG: a cancellable [Job] (NOT started in init) that loops while
     * the scope is active, the session has not expired, and the poll budget remains. Each iteration calls
     * status(); the first assertion -> [Result] (stop); expiry with a null assertion -> [Expired] (stop).
     * Safe to call repeatedly. Tests set [pollIntervalMillis], drive ONE iteration with runCurrent, then
     * call [stopPolling].
     */
    fun startPolling() {
        val awaiting = _uiState.value as? EidvUiState.AwaitingProvider ?: return
        if (pollJob != null) return
        pollJob = viewModelScope.launch {
            var budget = MAX_POLL_ITERATIONS
            while (isActive && budget > 0) {
                if (nowEpochSec() >= awaiting.expiresAt) {
                    _uiState.value = EidvUiState.Expired
                    break
                }
                when (val result = repository.status(awaiting.caseId)) {
                    is ApiResult.Success -> {
                        val verification = result.data.verification
                        if (verification != null) {
                            _uiState.value = EidvUiState.Result(
                                caseId = awaiting.caseId,
                                verification = verification,
                                hasCriticalDiscrepancy = verification.hasCriticalDiscrepancy,
                                autoTierUpgrade = result.data.autoTierUpgrade,
                            )
                            break
                        }
                    }
                    // A transient poll failure does not abort the loop; we retry next iteration until expiry.
                    is ApiResult.Failure -> Unit
                    is ApiResult.NetworkError -> Unit
                }
                budget--
                if (budget <= 0) break
                delay(pollIntervalMillis)
            }
        }
        pollJob?.invokeOnCompletion { pollJob = null }
    }

    /** Cancels the poll loop. Idempotent. */
    fun stopPolling() {
        pollJob?.cancel()
        pollJob = null
    }

    /**
     * Called when the user returns from the external provider (or taps "I've finished, check status"). Runs
     * a single immediate status check; if no assertion yet, ensures the bounded poll is running.
     */
    fun refreshStatus() {
        val awaiting = _uiState.value as? EidvUiState.AwaitingProvider ?: return
        viewModelScope.launch {
            when (val result = repository.status(awaiting.caseId)) {
                is ApiResult.Success -> {
                    val verification = result.data.verification
                    if (verification != null) {
                        stopPolling()
                        _uiState.value = EidvUiState.Result(
                            caseId = awaiting.caseId,
                            verification = verification,
                            hasCriticalDiscrepancy = verification.hasCriticalDiscrepancy,
                            autoTierUpgrade = result.data.autoTierUpgrade,
                        )
                    } else if (nowEpochSec() >= awaiting.expiresAt) {
                        stopPolling()
                        _uiState.value = EidvUiState.Expired
                    } else {
                        startPolling()
                    }
                }
                // A manual check failure keeps the awaiting screen; the poll continues.
                is ApiResult.Failure -> startPolling()
                is ApiResult.NetworkError -> startPolling()
            }
        }
    }

    /** Alias for [refreshStatus] used by the screen's "I've finished" / return-from-provider affordance. */
    fun onProviderReturned() = refreshStatus()

    /** Returns to scheme selection (from Expired / Result / Error), cancelling any poll and reloading. */
    fun restart() {
        stopPolling()
        savedStateHandle.remove<String>(SAVED_SESSION_ID)
        loadSchemes()
    }

    /** Re-runs the action that failed, per [EidvUiState.Error.retry]. */
    fun retry(kind: EidvUiState.Retry) {
        when (kind) {
            EidvUiState.Retry.LOAD -> loadSchemes()
            EidvUiState.Retry.START -> {
                // Return to scheme selection so the user can re-pick + start (a fresh, non-idempotent POST).
                loadSchemes()
            }
            EidvUiState.Retry.STATUS -> {
                val caseId = savedStateHandle.get<String>(SAVED_CASE_ID)
                if (caseId != null) resumeFrom(caseId) else loadSchemes()
            }
        }
    }

    override fun onCleared() {
        stopPolling()
        super.onCleared()
    }

    /** Overridable wall clock (epoch seconds) so tests can simulate expiry. */
    internal var nowProvider: () -> Long = { System.currentTimeMillis() / 1000 }

    private fun nowEpochSec(): Long = nowProvider()

    companion object {
        const val ARG_CASE_ID = "caseId"

        private const val SAVED_CASE_ID = "eidv_case_id"
        private const val SAVED_SESSION_ID = "eidv_session_id"
        private const val SAVED_SCHEME = "eidv_scheme"

        private const val OFFLINE = "Couldn't reach the server. Try again."

        /** Default poll interval (ms). Override via [pollIntervalMillis] in tests. */
        private const val DEFAULT_POLL_INTERVAL_MILLIS = 3_000L

        /** Hard upper bound on poll iterations (belt-and-braces alongside the expires_at guard). */
        private const val MAX_POLL_ITERATIONS = 200
    }
}
