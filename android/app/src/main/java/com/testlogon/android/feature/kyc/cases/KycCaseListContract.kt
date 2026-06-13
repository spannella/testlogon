package com.testlogon.android.feature.kyc.cases

import com.testlogon.android.feature.kyc.cases.model.KycCaseSummary
import com.testlogon.android.feature.kyc.cases.model.MonitoringState

// AND-329 - UI state for the READ-ONLY KYC case-list screen.

/** The sealed UI state for the KYC case list. */
sealed interface KycCaseListUiState {

    /** Initial single read of the case list + monitoring. */
    data object Loading : KycCaseListUiState

    /**
     * The loaded case list ([cases], sorted newest-first by createdAt) plus the derived [monitoring] banner
     * state. [isStale] is true when a refresh failed and this is a retained last-known snapshot; [refreshing]
     * drives pull-to-refresh.
     */
    data class Content(
        val cases: List<KycCaseSummary>,
        val monitoring: MonitoringState,
        val isStale: Boolean = false,
        val refreshing: Boolean = false,
    ) : KycCaseListUiState

    /** The caller has no KYC cases yet (CTA to start verification). [monitoring] may still raise a banner. */
    data class Empty(
        val monitoring: MonitoringState,
    ) : KycCaseListUiState

    /** A terminal load error with no prior content to fall back to. [retryable] gates the Retry action. */
    data class Error(
        val message: String,
        val retryable: Boolean,
    ) : KycCaseListUiState
}
