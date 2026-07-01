package com.testlogon.android.feature.agents.feedback.ui

import com.testlogon.android.feature.agents.feedback.data.FeedbackRequest

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

/** One-shot effects for the feedback ViewModel. */
sealed interface FeedbackEffect {
    data object NavigateToLogin : FeedbackEffect
}
