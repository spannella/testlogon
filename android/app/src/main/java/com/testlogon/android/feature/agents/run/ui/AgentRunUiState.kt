package com.testlogon.android.feature.agents.run.ui

import com.testlogon.android.data.agentrun.AgentRunOutput
import com.testlogon.android.data.agentrun.AgentRunType
import com.testlogon.android.data.agentrun.DeploymentDecision
import com.testlogon.android.data.agentrun.EligibleTicket
import com.testlogon.android.data.agentrun.PmOperation
import com.testlogon.android.data.agentrun.RunMetrics
import com.testlogon.android.data.agentrun.RunReport
import com.testlogon.android.data.agentrun.RunState

/**
 * AGENT-RUN (web-parity) - UI state + effect for the generic agent-run console (mobile mirror of the web
 * *RunOutputPanel / DeploymentApprovalPanel family). One [Content] state carries the whole run lifecycle for
 * the chosen [type] + typeId.
 */
sealed interface AgentRunUiState {
    data object Loading : AgentRunUiState

    /** The backend 403'd every call (non-operator). Distinct so the console shows an operator-only notice. */
    data object Forbidden : AgentRunUiState

    data class Content(
        val type: AgentRunType,
        val typeId: String,
        val runState: RunState,
        val eligibleTickets: List<EligibleTicket> = emptyList(),
        val loadingTickets: Boolean = false,
        val selectedTicketId: String? = null,
        val pmOperation: PmOperation = PmOperation.IDEA_TRIAGE,
        val runId: String? = null,
        val output: AgentRunOutput? = null,
        val report: RunReport? = null,
        val metrics: RunMetrics? = null,
        val loadingMetrics: Boolean = false,
        val decision: DeploymentDecision? = null,
        val busy: Boolean = false,
        val message: String? = null,
    ) : AgentRunUiState

    data class Error(val message: String) : AgentRunUiState
}

sealed interface AgentRunEffect {
    data object NavigateToLogin : AgentRunEffect
}
