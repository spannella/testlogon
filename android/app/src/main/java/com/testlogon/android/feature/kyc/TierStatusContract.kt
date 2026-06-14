package com.testlogon.android.feature.kyc

import com.testlogon.android.feature.kyc.model.Requirement
import com.testlogon.android.feature.kyc.model.Tier
import com.testlogon.android.feature.kyc.model.TierHistory
import java.time.Instant

// AND-320 — UI state + one-shot events for the Tier Status screen.

/** The sealed UI state for the Tier Status screen. */
sealed interface TierUiState {

    /** First load, nothing cached yet. */
    data object Loading : TierUiState

    /**
     * Renderable tier status. [target] is null at the max tier (checklist + Evaluate hidden, terminal
     * message shown). [stale] + [inlineError] surface a refresh failure while keeping cached content.
     * [evaluating]/[refreshing] drive inline progress without dropping the content.
     */
    data class Content(
        val current: Tier,
        val updatedAt: Instant?,
        val target: Tier?,
        val requirements: List<Requirement>,
        val eligibleForTarget: Boolean,
        val history: List<TierHistory>,
        val evaluating: Boolean = false,
        val refreshing: Boolean = false,
        val stale: Boolean = false,
        val inlineError: String? = null,
    ) : TierUiState {
        /** True only at the highest tier (no target to advance to). */
        val isMaxTier: Boolean get() = target == null
    }

    /** Cold failure: nothing cached AND a load failed. */
    data class Error(val message: String, val canRetry: Boolean) : TierUiState
}

/** One-shot UI events (collected by the screen for snackbars / promotion celebration). */
sealed interface TierEvent {
    /** A transient message (e.g. an evaluate failure that kept content visible). */
    data class Snackbar(val message: String) : TierEvent

    /** The caller was promoted; [toTierLevel] is the new tier (UI resolves the name). */
    data class Promoted(val toTierLevel: Int) : TierEvent
}
