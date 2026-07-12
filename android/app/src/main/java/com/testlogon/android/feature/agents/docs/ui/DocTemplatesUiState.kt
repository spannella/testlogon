package com.testlogon.android.feature.agents.docs.ui

import com.testlogon.android.feature.agents.docs.data.DocTemplate

/**
 * AGENTS-BASICS (web-parity) - UI state for the doc-templates screen (web /agents/docs/templates). Content is
 * shown even when the list is empty (the create form must stay reachable), with an inline empty hint.
 */
sealed interface DocTemplatesUiState {
    data object Loading : DocTemplatesUiState
    data class Content(
        val templates: List<DocTemplate>,
        val isRefreshing: Boolean = false,
        val busy: Boolean = false,
        val actionError: String? = null,
    ) : DocTemplatesUiState
    data class Error(val message: String) : DocTemplatesUiState
}
