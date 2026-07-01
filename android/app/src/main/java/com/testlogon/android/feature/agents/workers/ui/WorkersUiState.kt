package com.testlogon.android.feature.agents.workers.ui

import com.testlogon.android.feature.agents.workers.data.ComputeOption
import com.testlogon.android.feature.agents.workers.data.ToolInfo
import com.testlogon.android.feature.agents.workers.data.Worker

/**
 * AGENTS-BASICS (web-parity) - UI state for the WORKERS surfaces (list, detail, create) + the shared effect.
 */

/** Exhaustive state for the workers LIST screen. */
sealed interface WorkersListUiState {
    data object Loading : WorkersListUiState
    data class Content(
        val items: List<Worker>,
        val isRefreshing: Boolean = false,
        val actioningId: String? = null,
        val actionError: String? = null,
    ) : WorkersListUiState
    data object Empty : WorkersListUiState
    data class Error(val message: String) : WorkersListUiState
}

/** State for the worker DETAIL screen (worker + provision log). */
sealed interface WorkerDetailUiState {
    data object Loading : WorkerDetailUiState
    data class Content(
        val worker: Worker,
        val isRefreshing: Boolean = false,
        val actioning: Boolean = false,
        val actionError: String? = null,
    ) : WorkerDetailUiState
    data class Error(val message: String) : WorkerDetailUiState
}

/**
 * The create-worker form state. [canSubmit] is derived (non-blank label + an LLM key selected + a compute
 * option selected). [llmKeyOptions] pairs (keyId -> display label); [selectedLlmKeyId] is the chosen key.
 */
data class CreateWorkerForm(
    val label: String = "",
    val agentType: String = "coder",
    val tool: String = "",
    val computeType: String = "",
    val instanceType: String = "",
    val selectedLlmKeyId: String = "",
    val repoUrl: String = "",
    val tools: List<ToolInfo> = emptyList(),
    val computeOptions: List<ComputeOption> = emptyList(),
    val llmKeyOptions: List<Pair<String, String>> = emptyList(),
    val loadingOptions: Boolean = true,
    val submitting: Boolean = false,
    val submitError: String? = null,
) {
    val canSubmit: Boolean
        get() = label.isNotBlank() && selectedLlmKeyId.isNotBlank() &&
            tool.isNotBlank() && instanceType.isNotBlank() && !submitting
}

/** One-shot effects for the workers ViewModels. */
sealed interface WorkersEffect {
    data object NavigateToLogin : WorkersEffect
    data object CreateSucceeded : WorkersEffect
    data object TerminateSucceeded : WorkersEffect
}
