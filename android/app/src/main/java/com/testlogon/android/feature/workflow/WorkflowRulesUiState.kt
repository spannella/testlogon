package com.testlogon.android.feature.workflow

import com.testlogon.android.core.model.ApiError

/**
 * WFL — UI envelope + pure fold for the workflow-rules admin list. Android-free + JVM-testable.
 *
 * DEGRADE-ON-404: a 404 (flag off) OR 403 (not admin) folds to [Unavailable] — a calm message, not a
 * scary error/retry. Any other failure with no prior content -> [Error].
 */
sealed interface WorkflowRulesUiState {

    data object Loading : WorkflowRulesUiState

    data class Content(
        val rules: List<WorkflowRule>,
        val enabledCount: Int,
        val isRefreshing: Boolean = false,
    ) : WorkflowRulesUiState

    data object Empty : WorkflowRulesUiState

    /** Feature not enabled (404) or caller not an admin (403). */
    data object Unavailable : WorkflowRulesUiState

    data class Error(val error: ApiError) : WorkflowRulesUiState
}

/**
 * PURE fold of a list-load result. 404/403 -> [Unavailable]; other error -> [Error]; empty -> [Empty];
 * else [Content] (sorted, with the enabled-count badge).
 */
fun foldRulesResult(
    rules: List<WorkflowRule>?,
    error: ApiError?,
): WorkflowRulesUiState = when {
    error != null && (error.status == 404 || error.status == 403) -> WorkflowRulesUiState.Unavailable
    error != null -> WorkflowRulesUiState.Error(error)
    rules == null || rules.isEmpty() -> WorkflowRulesUiState.Empty
    else -> {
        val sorted = sortRules(rules)
        WorkflowRulesUiState.Content(rules = sorted, enabledCount = enabledCount(sorted))
    }
}
