package com.testlogon.android.feature.agents.docs.ui

import com.testlogon.android.feature.agents.docs.data.DocCoverage
import com.testlogon.android.feature.agents.docs.data.DocCoverageSummary

/** AGENTS-BASICS (web-parity) - UI state + effect for the DOC-COVERAGE dashboard (web /agents/docs). */
sealed interface DocCoverageUiState {
    data object Loading : DocCoverageUiState
    data class Content(
        val summary: DocCoverageSummary,
        val docs: List<DocCoverage>,
        val isRefreshing: Boolean = false,
        val checkingFreshness: Boolean = false,
        val actionMessage: String? = null,
    ) : DocCoverageUiState
    data class Error(val message: String) : DocCoverageUiState
}

sealed interface DocsEffect {
    data object NavigateToLogin : DocsEffect
}
