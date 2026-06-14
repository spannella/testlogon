package com.testlogon.android.feature.broadcast.inputs

import com.testlogon.android.data.broadcast.BroadcastInput

/**
 * AND-310 — UI state contract for the inputs-management surface.
 *
 * [InputsUiState] is the sealed render state; [InputRow] is a single list item carrying the input plus the
 * client-derived affordance gates ([canMakeLive] / [canDeactivate]). `isProgram` is NOT a wire field — the
 * ViewModel derives it by joining the input list against the layout's `primary_input_id` (the input whose
 * id == primaryInputId is the live program source) and writes it onto [BroadcastInput.isProgram].
 */
sealed interface InputsUiState {

    /** Initial / cold load before any cache or network result. */
    data object Loading : InputsUiState

    /**
     * Inputs are available. [isStale] is true when a refresh failed but cached rows are shown (warm cache).
     * [banner] carries a one-shot human-readable message (e.g. a rolled-back toggle failure). [pendingIds]
     * holds inputs with an in-flight optimistic toggle (rendered non-interactive with progress).
     */
    data class Content(
        val inputs: List<InputRow>,
        val isStale: Boolean = false,
        val banner: String? = null,
        val pendingIds: Set<String> = emptySet(),
    ) : InputsUiState

    /** No inputs exist for the session. [isStale] flags a failed refresh over an empty cache. */
    data class Empty(val isStale: Boolean = false) : InputsUiState

    /** Cold-cache failure: nothing to show. [retryable] gates the retry affordance. */
    data class Error(val message: String, val retryable: Boolean) : InputsUiState
}

/**
 * AND-310 — a single input row + derived affordance gates.
 *
 * [canMakeLive] — the input is live but is NOT already the program (you can promote it).
 * [canDeactivate] — the input is NOT the program (you cannot deactivate the live program source).
 */
data class InputRow(
    val input: BroadcastInput,
    val canMakeLive: Boolean,
    val canDeactivate: Boolean,
)
