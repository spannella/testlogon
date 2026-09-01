package com.testlogon.android.feature.collaborations.ui

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.collaborations.CollabDispute
import com.testlogon.android.core.model.collaborations.CollabRevision
import com.testlogon.android.core.model.collaborations.CollabSplitRecordModel
import com.testlogon.android.core.model.collaborations.Collaboration
import com.testlogon.android.core.model.collaborations.SplitDistribution

/**
 * AND-358 / PAR-04 / FIN-011 - render-ready state for the collaboration DETAIL screen (two parties + status +
 * the revenue split + the negotiation revision history + the deal actions + the FIN-011 revenue records +
 * disputes panel).
 *
 * Sealed so the screen renders mutually-exclusive surfaces; a new variant forces an exhaustive `when`.
 * [Content] holds the collaboration plus the OPTIONAL split-history distributions, revision history, executed
 * split records, and disputes; [isStale] is true when a refresh failed and the last-good content is being
 * re-shown (IN-MEMORY stale). [busy] is true while a deal-action / dispute mutation is in flight.
 * [SessionExpired] is the SIGNAL for an unrecoverable 401 (after the one auth refresh).
 */
sealed interface CollaborationDetailUiState {

    /** Initial first-load surface (no content yet). */
    data object Loading : CollaborationDetailUiState

    /**
     * Loaded collaboration. [distributions] is the optional split history; [revisions] is the optional
     * negotiation history; [splitRecords] is the FIN-011 executed-split revenue view; [disputes] is the
     * FIN-011 disputes panel. Each optional section folds to empty on a tolerated failure. [isStale] is true
     * when a refresh failed and the last-good snapshot is being re-shown. [busy] is true while an action runs.
     */
    data class Content(
        val collab: Collaboration,
        val distributions: List<SplitDistribution> = emptyList(),
        val revisions: List<CollabRevision> = emptyList(),
        val splitRecords: List<CollabSplitRecordModel> = emptyList(),
        val disputes: List<CollabDispute> = emptyList(),
        val isStale: Boolean = false,
        val busy: Boolean = false,
    ) : CollaborationDetailUiState

    /** Unrecoverable 401 (after the one auth refresh). A signal only - routing is owned elsewhere. */
    data object SessionExpired : CollaborationDetailUiState

    /** Terminal first-load failure (no content to show). */
    data class Error(val error: ApiError) : CollaborationDetailUiState
}

/**
 * PAR-04 / FIN-011 - the actions a creator can take on the detail screen. Used to key the one-shot success
 * message (resolved to a localized string at the screen) and to disable the right affordance while busy.
 */
enum class CollabAction { ACCEPT, REJECT, COUNTER, CANCEL, TERMINATE, FILE_DISPUTE, RESOLVE_DISPUTE }

/**
 * PAR-04 / FIN-011 - one-shot side effects for the detail screen (Channel-backed so they are NOT replayed on
 * rotation). An action emits either an [ActionSucceeded] (the screen localizes it per [CollabAction]) or an
 * [ActionFailed] (carrying the RAW server / transport message).
 */
sealed interface CollaborationDetailEffect {
    /** An action succeeded; the screen shows a localized confirmation for [action]. */
    data class ActionSucceeded(val action: CollabAction) : CollaborationDetailEffect

    /** An action failed; [message] is the raw server / transport message. */
    data class ActionFailed(val message: String) : CollaborationDetailEffect
}
