package com.testlogon.android.feature.agents.memory.ui

import com.testlogon.android.feature.agents.memory.data.AgentIdentity
import com.testlogon.android.feature.agents.memory.data.MemoryEntry
import com.testlogon.android.feature.agents.memory.data.ProjectContext

/**
 * AGENTS-BASICS (web-parity) - UI state + effect for the per-worker MEMORY screen (web /agents/memory/:workerId).
 * Identity + project context + memory entries are loaded together into one Content state.
 */
sealed interface MemoryUiState {
    data object Loading : MemoryUiState
    data class Content(
        val identity: AgentIdentity,
        val project: ProjectContext,
        val entries: List<MemoryEntry>,
        val totalTokens: Int,
        val saving: Boolean = false,
        val actionError: String? = null,
    ) : MemoryUiState
    data class Error(val message: String) : MemoryUiState
}

sealed interface MemoryEffect {
    data object NavigateToLogin : MemoryEffect
    data class Toast(val message: String) : MemoryEffect
}
