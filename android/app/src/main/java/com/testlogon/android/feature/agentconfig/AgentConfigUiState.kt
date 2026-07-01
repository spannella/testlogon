package com.testlogon.android.feature.agentconfig

import com.testlogon.android.data.agentconfig.AgentConfigType
import com.testlogon.android.data.agentconfig.ConfigForm

/**
 * Render state for the parametrized agent-type config screen. One immutable data class; [phase] is the
 * mutually-exclusive top-level surface. Forbidden is a first-class phase because these endpoints are
 * operator-gated - the signed-in member (test acct) is expected to get 403, which is NOT an error to retry.
 */
data class AgentConfigUiState(
    val type: AgentConfigType,
    val typeId: String,
    val phase: Phase = Phase.Loading,
    val form: ConfigForm? = null,
    val isSaving: Boolean = false,
    val errorMessage: String? = null,
    /** Server-side validation errors from validate / a rejected save. */
    val validationErrors: List<String> = emptyList(),
) {
    enum class Phase { Loading, Content, Forbidden, SessionExpired, Error, Offline }
}

/** One-shot effects (Channel-backed, not replayed on rotation). */
sealed interface AgentConfigEffect {
    data class ShowMessage(val text: String) : AgentConfigEffect
}
