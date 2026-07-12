package com.testlogon.android.feature.syndicates.bundles

/** Exhaustive UI state for the My Bundles screen (web parity: /syndicates/my-bundles). */
sealed interface MyBundlesUiState {

    data object Loading : MyBundlesUiState

    data class Content(
        val items: List<BundleSubscription>,
        val isRefreshing: Boolean = false,
        val isStale: Boolean = false,
        val cancellingId: String? = null,
        val actionError: String? = null,
    ) : MyBundlesUiState

    /** Zero active bundles (the web shows a "Browse syndicates" empty state). */
    data object Empty : MyBundlesUiState

    data class Error(val message: String) : MyBundlesUiState
}
