package com.testlogon.android.feature.workflow

import com.testlogon.android.core.model.ApiError

/**
 * WFL — UI envelopes + pure folds for the workflow-rules admin surface. Android-free + JVM-testable.
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
        /** A rule id currently being toggled/deleted (disables its row actions). null == idle. */
        val busyRuleId: String? = null,
        /** Transient one-shot user message (e.g. "Rule enabled"), cleared by the ViewModel. */
        val message: String? = null,
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

// ---------------------------------------------------------------------------
// Run history
// ---------------------------------------------------------------------------

/** UI envelope for a rule's run-history list. */
sealed interface WorkflowRunsUiState {
    data object Loading : WorkflowRunsUiState
    data class Content(val runs: List<WorkflowRun>) : WorkflowRunsUiState
    data object Empty : WorkflowRunsUiState
    data object Unavailable : WorkflowRunsUiState
    data class Error(val error: ApiError) : WorkflowRunsUiState
}

/** PURE fold of a run-history load. 404/403 -> [Unavailable]; empty -> [Empty]; else [Content]. */
fun foldRunsResult(runs: List<WorkflowRun>?, error: ApiError?): WorkflowRunsUiState = when {
    error != null && (error.status == 404 || error.status == 403) -> WorkflowRunsUiState.Unavailable
    error != null -> WorkflowRunsUiState.Error(error)
    runs == null || runs.isEmpty() -> WorkflowRunsUiState.Empty
    else -> WorkflowRunsUiState.Content(runs.sortedByDescending { it.startedAt })
}

// ---------------------------------------------------------------------------
// Drip sequences
// ---------------------------------------------------------------------------

/** UI envelope for the drip-sequence list. */
sealed interface DripSequencesUiState {
    data object Loading : DripSequencesUiState
    data class Content(
        val sequences: List<DripSequence>,
        val isRefreshing: Boolean = false,
        val message: String? = null,
    ) : DripSequencesUiState
    data object Empty : DripSequencesUiState
    data object Unavailable : DripSequencesUiState
    data class Error(val error: ApiError) : DripSequencesUiState
}

/** PURE fold of a drip-sequence load. 404/403 -> [Unavailable]; empty -> [Empty]; else [Content]. */
fun foldDripResult(sequences: List<DripSequence>?, error: ApiError?): DripSequencesUiState = when {
    error != null && (error.status == 404 || error.status == 403) -> DripSequencesUiState.Unavailable
    error != null -> DripSequencesUiState.Error(error)
    sequences == null || sequences.isEmpty() -> DripSequencesUiState.Empty
    else -> DripSequencesUiState.Content(sequences.sortedBy { it.name.lowercase() })
}
