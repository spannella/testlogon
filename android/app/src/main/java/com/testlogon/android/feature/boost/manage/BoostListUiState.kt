package com.testlogon.android.feature.boost.manage

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ads.ContentBoost

/**
 * Hoisted UI state for the BOOST LIST screen (web parity: ContentBoostPage.tsx list section).
 *
 *  - [Loading] - the boosts list load is in flight.
 *  - [Error]   - a fatal load failure; retryable.
 *  - [Content] - the caller's boosts. [boosts] may be empty (rendered as an empty state).
 */
sealed interface BoostListUiState {

    data object Loading : BoostListUiState

    data class Error(val error: ApiError) : BoostListUiState

    data class Content(
        val boosts: List<ContentBoost> = emptyList(),
        val refreshing: Boolean = false,
    ) : BoostListUiState
}
