package com.testlogon.android.feature.ads.campaigns.ui

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ads.AdCampaign

/**
 * AND-369 - hoisted UI state for the READ-ONLY campaigns list under a single account.
 *
 *  - [Loading] - the initial read is in flight.
 *  - [Content] - the loaded campaigns. [isRefreshing] drives the pull-to-refresh affordance; [isStale] marks
 *    content kept after a refresh failure (in-memory ONLY - there is no Room cache this wave).
 *  - [Empty]   - the account has no campaigns.
 *  - [Error]   - a fatal first-load failure (no prior content); retryable.
 *
 * READ-ONLY: there are no mutation sub-states (the campaigns list is never written by this surface).
 */
sealed interface AdsCampaignsUiState {

    data object Loading : AdsCampaignsUiState

    /** The loaded campaigns. A refresh failure that has prior content keeps it here with [isStale] = true. */
    data class Content(
        val campaigns: List<AdCampaign>,
        val isRefreshing: Boolean = false,
        val isStale: Boolean = false,
    ) : AdsCampaignsUiState

    /** The account has no campaigns to show. */
    data object Empty : AdsCampaignsUiState

    /** A fatal, retryable load error (the first read failed with no content). */
    data class Error(val error: ApiError) : AdsCampaignsUiState
}
