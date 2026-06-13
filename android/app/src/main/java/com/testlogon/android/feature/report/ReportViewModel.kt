package com.testlogon.android.feature.report

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.messaging.report.ReportReason
import com.testlogon.android.data.report.ReportFlowRepository
import com.testlogon.android.data.report.ReportKind
import com.testlogon.android.data.report.ReportOutcome
import com.testlogon.android.data.report.ReportResult
import com.testlogon.android.data.report.ReportTarget
import com.testlogon.android.data.report.ReportTopics
import com.testlogon.android.data.report.kind
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-383 - UI state for the cross-cutting report sheet. The form is a multi-select topic set + a REQUIRED
 * `reason_text` (5..2000 after trim). [canSubmit] is true only when at least one topic is selected, the
 * trimmed reason length is in range, AND the phase is Editing (so it disables while a submit is in flight,
 * giving the no-double-submit guard).
 */
data class ReportUiState(
    val kind: ReportKind = ReportKind.USER,
    val topics: List<ReportReason> = emptyList(),
    val selectedTopics: Set<ReportReason> = emptySet(),
    val reasonText: String = "",
    val reasonMin: Int = REASON_MIN,
    val reasonMax: Int = REASON_MAX,
    val phase: Phase = Phase.Editing,
) {
    val reasonLength: Int get() = reasonText.trim().length

    val canSubmit: Boolean
        get() = selectedTopics.isNotEmpty() &&
            reasonText.trim().length in reasonMin..reasonMax &&
            phase == Phase.Editing

    /** The terminal/working phase of the flow. */
    sealed interface Phase {
        data object Editing : Phase
        data object Submitting : Phase
        data class Success(val alreadyReported: Boolean) : Phase
        data class Error(val message: String, val retryable: Boolean) : Phase
    }

    companion object {
        const val REASON_MIN = 5
        const val REASON_MAX = 2000
    }
}

/**
 * AND-383 - presentation logic for the reusable report flow. Reused from profile / feed / message-thread
 * call sites via [ReportSheet]; routing by [ReportKind] is owned by [ReportFlowRepository].
 *
 * The submit POST is non-idempotent and is NEVER auto-retried; [retry] re-issues the SAME request only on
 * user action and preserves [ReportUiState.selectedTopics] / [ReportUiState.reasonText]. A re-entrant
 * [submit] while Submitting is a no-op (single repo invocation). A terminal 401 (after the core-network
 * single refresh) maps to a non-retryable "Sign in to report" error; 403/404/validation are
 * non-retryable; 5xx/timeout/IO/429 are retryable. The reporter's free-text reason is NEVER logged.
 *
 * Draft fields (reason text) survive config changes via [SavedStateHandle]; the target is supplied via
 * [start] (a non-primitive schema, so not a ctor arg per the Hilt gotcha).
 */
@HiltViewModel
class ReportViewModel @Inject constructor(
    private val repository: ReportFlowRepository,
    private val savedState: SavedStateHandle,
) : ViewModel() {

    private val _state = MutableStateFlow(restoreDraft())
    val state: StateFlow<ReportUiState> = _state.asStateFlow()

    private var target: ReportTarget? = null

    /** Loads the topic options for the target kind, restoring any saved draft text. */
    fun start(target: ReportTarget) {
        this.target = target
        val kind = target.kind
        _state.update {
            it.copy(
                kind = kind,
                topics = ReportTopics.forKind(kind),
                reasonText = savedState[KEY_REASON] ?: it.reasonText,
                phase = ReportUiState.Phase.Editing,
            )
        }
    }

    fun onTopicToggled(topic: ReportReason, checked: Boolean) = _state.update {
        val next = if (checked) it.selectedTopics + topic else it.selectedTopics - topic
        it.copy(selectedTopics = next, phase = ReportUiState.Phase.Editing)
    }

    fun onReasonTextChanged(text: String) {
        val capped = text.take(ReportUiState.REASON_MAX)
        savedState[KEY_REASON] = capped
        _state.update { it.copy(reasonText = capped, phase = ReportUiState.Phase.Editing) }
    }

    /** Idempotent re-entry safe: ignored while Submitting; requires a valid form. */
    fun submit() {
        val s = _state.value
        if (s.phase == ReportUiState.Phase.Submitting) return
        if (!s.canSubmit) return
        runSubmit()
    }

    /** User-initiated retry of the same request (only meaningful from a retryable Error). */
    fun retry() {
        if (_state.value.phase == ReportUiState.Phase.Submitting) return
        runSubmit()
    }

    private fun runSubmit() {
        val s = _state.value
        val t = target ?: return
        _state.update { it.copy(phase = ReportUiState.Phase.Submitting) }
        viewModelScope.launch {
            try {
                when (val r = repository.submit(t, s.selectedTopics, s.reasonText.trim())) {
                    is ApiResult.Success -> onSuccess(r.data)
                    is ApiResult.Failure -> onFailure(r.error)
                    is ApiResult.NetworkError -> _state.update {
                        it.copy(phase = ReportUiState.Phase.Error(OFFLINE_MESSAGE, retryable = true))
                    }
                }
            } catch (e: CancellationException) {
                throw e
            }
        }
    }

    private fun onSuccess(result: ReportResult) = _state.update {
        it.copy(phase = ReportUiState.Phase.Success(alreadyReported = result.alreadyReported))
    }

    private fun onFailure(error: ApiError) {
        val (message, retryable) = when (error.status) {
            401 -> SIGN_IN_MESSAGE to false
            403, 404 -> error.message to false
            422, ApiError.STATUS_PARSE -> error.message to false
            429 -> error.message to true
            in 500..599 -> error.message to true
            else -> error.message to false
        }
        _state.update {
            it.copy(phase = ReportUiState.Phase.Error(message, retryable = retryable))
        }
    }

    /** The outcome to hand back to the call site, derived from the current phase. */
    fun outcome(): ReportOutcome = when (val p = _state.value.phase) {
        is ReportUiState.Phase.Success ->
            if (p.alreadyReported) ReportOutcome.ALREADY_REPORTED else ReportOutcome.SUBMITTED
        else -> ReportOutcome.CANCELLED
    }

    private fun restoreDraft(): ReportUiState =
        ReportUiState(reasonText = savedState[KEY_REASON] ?: "")

    companion object {
        const val OFFLINE_MESSAGE = "No connection - try again"
        const val SIGN_IN_MESSAGE = "Sign in to report"
        private const val KEY_REASON = "report_reason_text"
    }
}
