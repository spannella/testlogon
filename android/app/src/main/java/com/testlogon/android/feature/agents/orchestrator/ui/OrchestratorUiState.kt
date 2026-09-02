package com.testlogon.android.feature.agents.orchestrator.ui

import com.testlogon.android.feature.agents.orchestrator.data.AgentStatus
import com.testlogon.android.feature.agents.orchestrator.data.EligibleTicket
import com.testlogon.android.feature.agents.orchestrator.data.LoopAction

/**
 * AGENT-ORCHESTRATOR (web-parity) - UI state + one-shot effects for the orchestrator console.
 */
sealed interface OrchestratorUiState {
    data object Loading : OrchestratorUiState

    /**
     * The worker exists but has no orchestrator record yet (status 404, degrade-on-404). The console offers a
     * retry (the loop can still be reached once the worker record is orchestratable).
     */
    data object NoLoop : OrchestratorUiState

    data class Content(
        val status: AgentStatus,
        /** The set of loop actions currently offered (derived from [status] via OrchestratorMath). */
        val actions: Set<LoopAction>,
        val summary: String,
        val eligible: List<EligibleTicket> = emptyList(),
        val eligibleLoading: Boolean = false,
        val isRefreshing: Boolean = false,
        /** The action currently in flight (disables the button row); null when idle. */
        val actioning: LoopAction? = null,
        val actionError: String? = null,
        /** Transient success banner (e.g. "Heartbeat sent"); cleared on the next action. */
        val notice: String? = null,
    ) : OrchestratorUiState

    data class Error(val message: String) : OrchestratorUiState
}

/** One-shot effects. */
sealed interface OrchestratorEffect {
    data object NavigateToLogin : OrchestratorEffect
}
