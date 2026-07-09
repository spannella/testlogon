package com.testlogon.android.feature.syndicates.ads.ui

import com.testlogon.android.core.model.ads.AdAccountSummary
import com.testlogon.android.core.model.ads.SyndicateAdPlacementConfig

/**
 * ADV2-709/710 (F7) — render state for the syndicate-ads hub (list the syndicate's ad accounts + a create
 * form + the placement-split summary). [FORBIDDEN] is the non-admin surface (a 403 from the admin-gated
 * endpoints). The create form + submit state are kept OUT of [accountsState] so an in-flight/failed create
 * never clobbers the loaded list.
 */
sealed interface SyndicateAdsAccountsState {
    data object Loading : SyndicateAdsAccountsState
    data class Content(val accounts: List<AdAccountSummary>) : SyndicateAdsAccountsState
    data object Empty : SyndicateAdsAccountsState
    data object Forbidden : SyndicateAdsAccountsState
    data class Error(val message: String) : SyndicateAdsAccountsState
}

/** The create-account form submit lifecycle (separate from the typed input fields). */
sealed interface SyndicateAdCreateState {
    data object Idle : SyndicateAdCreateState
    data object Submitting : SyndicateAdCreateState
    /** Created + recorded as the studio selection; [accountId] is ready to campaign/fund against. */
    data class Success(val accountId: String, val status: String?) : SyndicateAdCreateState
    data class Error(val message: String) : SyndicateAdCreateState
}

/** The placement-split summary shown on the hub (edited on the dedicated split screen). */
sealed interface SyndicateAdConfigState {
    data object Loading : SyndicateAdConfigState
    data class Content(val config: SyndicateAdPlacementConfig) : SyndicateAdConfigState
    data object Hidden : SyndicateAdConfigState
}
