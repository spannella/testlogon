package com.testlogon.android.feature.collaborations.ui

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.collaborations.Collaboration
import com.testlogon.android.core.model.collaborations.SplitDistribution

/**
 * AND-358 - render-ready state for the READ-ONLY collaboration DETAIL screen (two parties + status + the
 * revenue split).
 *
 * Sealed so the screen renders mutually-exclusive surfaces; a new variant forces an exhaustive `when`.
 * [Content] holds the collaboration plus the OPTIONAL split-history distributions; [isStale] is true when a
 * refresh failed and the last-good content is being re-shown (IN-MEMORY stale - it does NOT drop content).
 * [SessionExpired] is the SIGNAL for an unrecoverable 401 (after the one auth refresh); AND-358 does NOT own
 * the routing, it only surfaces the signal.
 */
sealed interface CollaborationDetailUiState {

    /** Initial first-load surface (no content yet). */
    data object Loading : CollaborationDetailUiState

    /**
     * Loaded collaboration. [distributions] is the optional split history (empty when absent / tolerated
     * failure). [isStale] is true when a refresh failed and the last-good snapshot is being re-shown.
     */
    data class Content(
        val collab: Collaboration,
        val distributions: List<SplitDistribution> = emptyList(),
        val isStale: Boolean = false,
    ) : CollaborationDetailUiState

    /** Unrecoverable 401 (after the one auth refresh). A signal only - routing is owned elsewhere. */
    data object SessionExpired : CollaborationDetailUiState

    /** Terminal first-load failure (no content to show). */
    data class Error(val error: ApiError) : CollaborationDetailUiState
}
