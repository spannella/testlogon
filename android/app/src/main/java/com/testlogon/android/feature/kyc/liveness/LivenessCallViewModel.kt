package com.testlogon.android.feature.kyc.liveness

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.kyc.liveness.data.LivenessCallRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-324 - presentation logic for the KYC scheduled liveness (video-verification) call flow.
 *
 * REAL REST SCHEDULING (NOT in-app WebRTC): [schedule] books an appointment against the KYC [caseId],
 * a human verifier conducts it later, and the resulting opaque join_url is opened EXTERNALLY by the
 * screen. [onJoinClicked] simply returns the join_url for the screen's ACTION_VIEW; this VM never opens
 * a URL itself and there is NO WebRTC / camera / vendor SDK and NO flagged seam.
 *
 * STATUS REFRESH: [uiState] is a plain MutableStateFlow refreshed by a SINGLE non-looping list fetch in
 * [init] and again on explicit [refresh] (manual / pull-to-refresh) and after a successful schedule /
 * cancel. There is NO poll / delay loop.
 *
 * DEBOUNCE: [schedule] and [cancel] are NON-IDEMPOTENT POSTs. [schedule] is debounced (ignored while a
 * schedule is already in flight) to avoid double-booking; neither is auto-retried.
 *
 * case_id is sourced from [SavedStateHandle] (the nav arg [ARG_CASE_ID]); a blank/absent case id lands
 * the VM in a non-recoverable [LivenessUiState.Error] so the form is disabled and the flow cannot
 * proceed without a real case.
 */
@HiltViewModel
class LivenessCallViewModel @Inject constructor(
    private val repository: LivenessCallRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val caseId: String = savedStateHandle.get<String>(ARG_CASE_ID).orEmpty()

    private val _uiState = MutableStateFlow<LivenessUiState>(
        if (caseId.isBlank()) {
            LivenessUiState.Error(message = ERROR_NO_CASE, recoverable = false)
        } else {
            LivenessUiState.Loading
        },
    )
    val uiState: StateFlow<LivenessUiState> = _uiState.asStateFlow()

    init {
        if (caseId.isNotBlank()) refresh()
    }

    /** Single non-looping fetch of the user's calls. Preserves the in-flight scheduling/form sub-state. */
    fun refresh() {
        if (caseId.isBlank()) return
        viewModelScope.launch {
            val prior = _uiState.value as? LivenessUiState.Ready
            when (val result = repository.list()) {
                is ApiResult.Success -> _uiState.value = LivenessUiState.Ready(
                    calls = result.data,
                    scheduling = prior?.scheduling ?: false,
                    formError = prior?.formError,
                )
                is ApiResult.Failure ->
                    if (prior != null) {
                        // Keep the existing list; a refresh failure should not blow away a usable screen.
                        Unit
                    } else {
                        _uiState.value = LivenessUiState.Error(result.error.message, recoverable = true)
                    }
                is ApiResult.NetworkError ->
                    if (prior != null) {
                        Unit
                    } else {
                        _uiState.value = LivenessUiState.Error(OFFLINE, recoverable = true)
                    }
            }
        }
    }

    /**
     * Schedules a video-verification call. DEBOUNCED: ignored while a schedule is already in flight. On
     * success refreshes the list (and clears the form error); a 422 / validation failure surfaces as
     * [LivenessUiState.Ready.formError].
     */
    fun schedule(scheduledAtEpochSec: Long, durationMinutes: Int, note: String? = null) {
        if (caseId.isBlank()) return
        val current = _uiState.value as? LivenessUiState.Ready ?: return
        if (current.scheduling) return // debounce: a schedule is already in flight.

        _uiState.value = current.copy(scheduling = true, formError = null)
        viewModelScope.launch {
            when (val result = repository.schedule(caseId, scheduledAtEpochSec, durationMinutes, note)) {
                is ApiResult.Success -> {
                    // Clear the in-flight flag then refresh to pick up the new call.
                    setScheduling(false, formError = null)
                    refresh()
                }
                is ApiResult.Failure -> setScheduling(false, formError = result.error.message)
                is ApiResult.NetworkError -> setScheduling(false, formError = OFFLINE)
            }
        }
    }

    /**
     * Cancels a still-cancellable call (NON-IDEMPOTENT POST, not auto-retried). On success refreshes the
     * list; a failure surfaces as the form error (the list view's only inline error channel).
     */
    fun cancel(callId: String) {
        if (caseId.isBlank()) return
        viewModelScope.launch {
            when (val result = repository.cancel(callId)) {
                is ApiResult.Success -> refresh()
                is ApiResult.Failure -> setScheduling(scheduling = currentScheduling(), formError = result.error.message)
                is ApiResult.NetworkError -> setScheduling(scheduling = currentScheduling(), formError = OFFLINE)
            }
        }
    }

    /**
     * Returns the join_url for [callId] so the SCREEN can open it EXTERNALLY (ACTION_VIEW). Returns null
     * when the call has no join_url yet (e.g. not started). The VM never opens the URL itself.
     */
    fun onJoinClicked(callId: String): String? =
        (_uiState.value as? LivenessUiState.Ready)
            ?.calls
            ?.firstOrNull { it.callId == callId }
            ?.joinUrl

    /** Dismisses the inline form error. */
    fun dismissFormError() {
        val current = _uiState.value as? LivenessUiState.Ready ?: return
        _uiState.value = current.copy(formError = null)
    }

    private fun currentScheduling(): Boolean =
        (_uiState.value as? LivenessUiState.Ready)?.scheduling ?: false

    private fun setScheduling(scheduling: Boolean, formError: String?) {
        val current = _uiState.value as? LivenessUiState.Ready ?: return
        _uiState.value = current.copy(scheduling = scheduling, formError = formError)
    }

    companion object {
        const val ARG_CASE_ID = "caseId"
        private const val ERROR_NO_CASE = "No KYC case to schedule a verification call against."
        private const val OFFLINE = "Couldn't reach the server. Try again."
    }
}
