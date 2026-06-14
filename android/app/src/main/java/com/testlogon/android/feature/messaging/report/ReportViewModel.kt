package com.testlogon.android.feature.messaging.report

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.messaging.report.ReportReason
import com.testlogon.android.data.messaging.report.ReportRepository
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
 * AND-163 — UI state for the report sheet. The sheet is launched per-target (a transient host inside the
 * thread), not a navigation destination, so the target is provided via [open] rather than SavedStateHandle.
 *
 * Submit is gated on a selected reason AND a statement >= [STATEMENT_MIN] chars; the counter is shown
 * against [STATEMENT_MAX]. There is no `OTHER`-requires-details branch (the reason set is the fixed
 * lowercase topic list; statement is always required).
 */
data class ReportUiState(
    val visible: Boolean = false,
    val conversationId: String = "",
    val messageId: String = "",
    val availableReasons: List<ReportReason> = ReportReason.SELECTABLE,
    val selectedReason: ReportReason? = null,
    val statement: String = "",
    val isSubmitting: Boolean = false,
    val error: String? = null,
) {
    val statementLength: Int get() = statement.length
    val canSubmit: Boolean
        get() = !isSubmitting && selectedReason != null && statement.length in STATEMENT_MIN..STATEMENT_MAX

    companion object {
        const val STATEMENT_MIN = 5
        const val STATEMENT_MAX = 2000
    }
}

/** AND-163 — one-shot effects for the report sheet (confirmation Snackbar). */
sealed interface ReportEvent {
    data object Submitted : ReportEvent
}

/**
 * AND-163 — report-sheet presentation logic.
 *
 * Reuses the dedicated [ReportRepository] (a separate api/repo, so MessagingApi's FakeApi is untouched).
 * On submit: optimistic PENDING is owned by the repo; the VM flips `isSubmitting`, issues the POST, and
 * on success dismisses the sheet and emits [ReportEvent.Submitted] for the confirmation Snackbar. The
 * reporter's free-text statement is never logged.
 */
@HiltViewModel
class ReportViewModel @Inject constructor(
    private val repository: ReportRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(ReportUiState())
    val uiState: StateFlow<ReportUiState> = _uiState.asStateFlow()

    private val _events = Channel<ReportEvent>(Channel.BUFFERED)
    val events: Flow<ReportEvent> = _events.receiveAsFlow()

    /** Open the sheet for a specific message target, resetting any prior draft. */
    fun open(conversationId: String, messageId: String) {
        _uiState.value = ReportUiState(
            visible = true,
            conversationId = conversationId,
            messageId = messageId,
            availableReasons = repository.reasonCatalog(),
        )
    }

    /** Cancel/dismiss discards the draft (no autosave). */
    fun dismiss() {
        _uiState.value = ReportUiState()
    }

    fun onReasonSelected(reason: ReportReason) =
        _uiState.update { it.copy(selectedReason = reason, error = null) }

    fun onStatementChanged(text: String) =
        _uiState.update {
            it.copy(statement = text.take(ReportUiState.STATEMENT_MAX), error = null)
        }

    fun dismissError() = _uiState.update { it.copy(error = null) }

    fun submit() {
        val s = _uiState.value
        val reason = s.selectedReason ?: return
        if (!s.canSubmit) return
        _uiState.update { it.copy(isSubmitting = true, error = null) }
        viewModelScope.launch {
            when (
                val r = repository.reportMessage(
                    conversationId = s.conversationId,
                    messageId = s.messageId,
                    reason = reason,
                    statement = s.statement,
                )
            ) {
                is ApiResult.Success -> {
                    _uiState.value = ReportUiState() // dismiss
                    _events.send(ReportEvent.Submitted)
                }
                is ApiResult.Failure ->
                    _uiState.update { it.copy(isSubmitting = false, error = r.error.message) }
                is ApiResult.NetworkError ->
                    _uiState.update { it.copy(isSubmitting = false, error = OFFLINE_MESSAGE) }
            }
        }
    }

    companion object {
        const val OFFLINE_MESSAGE = "No connection - try again"
    }
}
