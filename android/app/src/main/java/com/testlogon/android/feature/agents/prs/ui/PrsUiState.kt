package com.testlogon.android.feature.agents.prs.ui

import com.testlogon.android.feature.agents.prs.data.AgentPr

/** AGENTS-BASICS (web-parity) - UI state + effect for the agent-PR list & detail (web /agents/prs). */
sealed interface PrsListUiState {
    data object Loading : PrsListUiState
    data class Content(val items: List<AgentPr>, val isRefreshing: Boolean = false) : PrsListUiState
    data object Empty : PrsListUiState
    data class Error(val message: String) : PrsListUiState
}

sealed interface PrDetailUiState {
    data object Loading : PrDetailUiState
    data class Content(val pr: AgentPr) : PrDetailUiState
    data class Error(val message: String) : PrDetailUiState
}

sealed interface PrsEffect {
    data object NavigateToLogin : PrsEffect
}
