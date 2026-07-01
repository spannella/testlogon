package com.testlogon.android.feature.agents.fleet.ui

import com.testlogon.android.feature.agents.fleet.data.FleetCapacity
import com.testlogon.android.feature.agents.fleet.data.FleetStatus
import com.testlogon.android.feature.agents.fleet.data.WorkerTemplate

/** AGENTS-BASICS (web-parity) - UI state for the FLEET dashboard. */
sealed interface FleetUiState {
    data object Loading : FleetUiState
    data class Content(
        val status: FleetStatus,
        val capacity: FleetCapacity?,
        val templates: List<WorkerTemplate>,
        val isRefreshing: Boolean = false,
        val bulkBusy: Boolean = false,
        val busyTemplateId: String? = null,
        val actionMessage: String? = null,
        val actionError: String? = null,
    ) : FleetUiState
    data class Error(val message: String) : FleetUiState
}

sealed interface FleetEffect {
    data object NavigateToLogin : FleetEffect
}
