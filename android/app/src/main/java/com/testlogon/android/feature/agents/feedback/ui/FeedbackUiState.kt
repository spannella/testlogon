package com.testlogon.android.feature.agents.feedback.ui

import com.testlogon.android.feature.agents.feedback.data.FeedbackRequest
import com.testlogon.android.feature.agents.feedback.data.TerminalOutput

/** AGENTS-BASICS (web-parity) - UI state + effect for the FEEDBACK list screen (web /agents/feedback). */
sealed interface FeedbackUiState {
    data object Loading : FeedbackUiState
    data class Content(
        val items: List<FeedbackRequest>,
        val isRefreshing: Boolean = false,
        val actioningId: String? = null,
        val actionError: String? = null,
    ) : FeedbackUiState
    data object Empty : FeedbackUiState
    data class Error(val message: String) : FeedbackUiState
}

/**
 * Dialog state hoisted OUTSIDE the list state so create / terminal-log work from the empty state too
 * (the empty list is precisely where you would raise the first request). Both dialogs are closed when null.
 */
data class FeedbackDialogState(
    val create: CreateFeedbackState? = null,
    val terminal: TerminalLogState? = null,
)

/** Transient state for the create-feedback dialog (web createFeedbackRequest). */
data class CreateFeedbackState(
    val submitting: Boolean = false,
    val error: String? = null,
)

/** Transient state for the per-worker terminal-log viewer (web getTerminalLog). */
data class TerminalLogState(
    val workerId: String,
    val loading: Boolean = false,
    val output: TerminalOutput? = null,
    val error: String? = null,
)

/** One-shot effects for the feedback ViewModel. */
sealed interface FeedbackEffect {
    data object NavigateToLogin : FeedbackEffect
}
