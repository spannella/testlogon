package com.testlogon.android.feature.ads.accounts.ui

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ads.AdAccountSummary

/**
 * AND-369 - hoisted UI state for the advertiser-accounts LIST.
 *
 *  - [Loading] - the initial read is in flight.
 *  - [Content] - the loaded accounts, plus the [selectedAccountId] (set by onAccountSelected, NO network I/O).
 *    [isRefreshing] drives the pull-to-refresh affordance; [isStale] marks content kept after a refresh
 *    failure (in-memory ONLY - there is no Room cache this wave).
 *  - [Empty]   - the caller can see no ad accounts.
 *  - [Error]   - a fatal first-load failure (no prior content); retryable.
 *
 * The accounts list reuses the AND-367 [AdAccountSummary] domain row. READ-ONLY: there are no mutation
 * sub-states (selection is local state, not a server write).
 */
sealed interface AdsAccountsUiState {

    data object Loading : AdsAccountsUiState

    /**
     * The loaded accounts list. A refresh failure that has prior content keeps it here with [isStale] = true
     * and [isRefreshing] cleared. [selectedAccountId] records the user's selection locally.
     */
    data class Content(
        val accounts: List<AdAccountSummary>,
        val selectedAccountId: String? = null,
        val isRefreshing: Boolean = false,
        val isStale: Boolean = false,
    ) : AdsAccountsUiState

    /** The caller has no visible ad accounts. */
    data object Empty : AdsAccountsUiState

    /** A fatal, retryable load error (the first read failed with no content). */
    data class Error(val error: ApiError) : AdsAccountsUiState
}
