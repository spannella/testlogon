package com.testlogon.android.feature.syndicates.ui

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.syndicates.RevenueSplitPolicy
import com.testlogon.android.core.model.syndicates.SyndicateOverview
import com.testlogon.android.core.model.syndicates.TreasurySummary

/**
 * AND-356 - render-ready state for the READ-ONLY syndicate overview screen (Feed / Treasury / Revenue-split).
 *
 * Sealed so the screen renders mutually-exclusive surfaces; a new variant forces an exhaustive `when`.
 * [NotMember] is the FR-7 empty-state (is_member == false OR a 403 on the overview). [Content] holds the
 * header plus the two non-paged tab snapshots (treasury summary + split policy) as independent [TabState]s;
 * the feed + ledger are paged separately via Flows on the ViewModel. A refresh failure keeps the last-good
 * [Content] and flips [Content.isStale] true (IN-MEMORY stale, FR-6) - it does NOT drop content.
 */
sealed interface SyndicateOverviewUiState {

    /** Initial first-load surface (no header yet). */
    data object Loading : SyndicateOverviewUiState

    /** The viewer is not a member (is_member == false) OR the overview returned 403 (FR-7). */
    data object NotMember : SyndicateOverviewUiState

    /** Terminal first-load failure of the overview (no header to show). */
    data class Error(val error: ApiError) : SyndicateOverviewUiState

    /**
     * Loaded header. The treasury + split tabs each carry an independent [TabState]; [isStale] is true when
     * a refresh failed and the last-good header/tab snapshots are being re-shown (in-memory stale).
     */
    data class Content(
        val overview: SyndicateOverview,
        val treasury: TabState<TreasurySummary>,
        val split: TabState<RevenueSplitPolicy>,
        val isStale: Boolean = false,
    ) : SyndicateOverviewUiState
}

/**
 * Per-tab load state for the two NON-paged tabs (treasury summary + split policy). The feed tab and the
 * treasury ledger are paged independently (their load/empty/error come from Paging's LoadState), so they do
 * NOT use this type.
 */
sealed interface TabState<out T> {
    data object Loading : TabState<Nothing>
    data class Content<out T>(val data: T) : TabState<T>
    data class Error(val error: ApiError) : TabState<Nothing>
}
