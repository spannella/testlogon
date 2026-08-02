package com.testlogon.android.feature.collaborations.ui

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.collaborations.CollabRevision
import com.testlogon.android.core.model.collaborations.Collaboration
import com.testlogon.android.core.model.collaborations.SplitDistribution

/**
 * AND-358 / PAR-04 - render-ready state for the collaboration DETAIL screen (two parties + status + the
 * revenue split + the negotiation revision history + the deal actions).
 *
 * Sealed so the screen renders mutually-exclusive surfaces; a new variant forces an exhaustive `when`.
 * [Content] holds the collaboration plus the OPTIONAL split-history distributions and revision history;
 * [isStale] is true when a refresh failed and the last-good content is being re-shown (IN-MEMORY stale - it
 * does NOT drop content). [busy] is true while a deal-action mutation is in flight (the actions disable).
 * [SessionExpired] is the SIGNAL for an unrecoverable 401 (after the one auth refresh); PAR-04 does NOT own
 * the routing, it only surfaces the signal.
 */
sealed interface CollaborationDetailUiState {

    /** Initial first-load surface (no content yet). */
    data object Loading : CollaborationDetailUiState

    /**
     * Loaded collaboration. [distributions] is the optional split history (empty when absent / tolerated
     * failure); [revisions] is the optional negotiation history (same tolerance). [isStale] is true when a
     * refresh failed and the last-good snapshot is being re-shown. [busy] is true while a deal action runs.
     */
    data class Content(
        val collab: Collaboration,
        val distributions: List<SplitDistribution> = emptyList(),
        val revisions: List<CollabRevision> = emptyList(),
        val isStale: Boolean = false,
        val busy: Boolean = false,
    ) : CollaborationDetailUiState

    /** Unrecoverable 401 (after the one auth refresh). A signal only - routing is owned elsewhere. */
    data object SessionExpired : CollaborationDetailUiState

    /** Terminal first-load failure (no content to show). */
    data class Error(val error: ApiError) : CollaborationDetailUiState
}

/**
 * PAR-04 - the deal actions a creator can take on the detail screen. Used to key the one-shot success message
 * (resolved to a localized string at the screen) and to disable the right affordance while busy.
 */
enum class CollabAction { ACCEPT, REJECT, COUNTER, CANCEL, TERMINATE }

/**
 * PAR-04 - one-shot side effects for the detail screen (Channel-backed so they are NOT replayed on rotation).
 * A deal action emits either an [ActionSucceeded] (the screen localizes it per [CollabAction]) or an
 * [ActionFailed] (carrying the RAW server / transport message, mirroring the Highlights convention).
 */
sealed interface CollaborationDetailEffect {
    /** A deal action succeeded; the screen shows a localized confirmation for [action]. */
    data class ActionSucceeded(val action: CollabAction) : CollaborationDetailEffect

    /** A deal action failed; [message] is the raw server / transport message. */
    data class ActionFailed(val message: String) : CollaborationDetailEffect
}
