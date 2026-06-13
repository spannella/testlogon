package com.testlogon.android.feature.signing.model

import com.testlogon.android.core.model.ApiError

/**
 * AND-344 - one-shot SIDE EFFECTS emitted by the cross-cutting signing orchestrator
 * (SigningFlowViewModel). These are FIRE-ONCE events (navigation / dismissal / a transient error
 * banner), so the orchestrator exposes them over a Channel + receiveAsFlow() and NEVER stores them in
 * the StateFlow (FR-6). Re-collecting the StateFlow must never replay a navigation - that is the whole
 * reason effects live off-state.
 *
 * REUSE: the error payload reuses the canonical core-model [ApiError] (the repository's failure type);
 * AND-344 does NOT introduce a parallel error model.
 *
 * NOTE on naming: the AND-344 spec refers to this carrier generically as "AppError"; the established
 * core-model type in this codebase is [ApiError], so that is what is reused verbatim here.
 */
sealed interface SigningEffect {

    /** Navigate to the document viewer (AND-341) for [packetId] as the journey enters reading. */
    data class NavigateToDocument(val packetId: String) : SigningEffect

    /** Navigate to the terminal submit/mark-done surface (AND-343) once placement is complete. */
    data object NavigateToSubmit : SigningEffect

    /** Surface a transient error (a load / step failure). Carries the reused [ApiError]. */
    data class ShowError(val error: ApiError) : SigningEffect

    /** Dismiss / close the signing flow (e.g. the packet is terminal or the user backed all the way out). */
    data object Dismiss : SigningEffect
}
