package com.testlogon.android.feature.syndicates.ads.ui

import com.testlogon.android.core.model.ads.SyndicateAdPlacementConfig

/**
 * ADV2-710 (F7) — render state for the syndicate ad-placement SPLIT config editor. [Content] carries the
 * loaded config plus the in-progress [draftMemberShareBps] the slider edits (0..10000). [saved] flips true
 * for a moment after a successful PUT so the screen can confirm. [Forbidden] is the non-admin surface.
 */
sealed interface SyndicateAdSplitUiState {
    data object Loading : SyndicateAdSplitUiState
    data class Content(
        val config: SyndicateAdPlacementConfig,
        val draftMemberShareBps: Int,
        val saving: Boolean = false,
        val saved: Boolean = false,
        val error: String? = null,
    ) : SyndicateAdSplitUiState {
        /** True when the draft differs from the saved value and is in range. */
        val dirty: Boolean get() = draftMemberShareBps != config.memberShareBps
    }
    data object Forbidden : SyndicateAdSplitUiState
    data class Error(val message: String) : SyndicateAdSplitUiState
}
