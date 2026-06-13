package com.testlogon.android.feature.kyc.cases

import com.testlogon.android.feature.kyc.cases.model.KycCaseSummary
import com.testlogon.android.feature.kyc.cases.model.TimelineEvent

// AND-329 - UI state for the READ-ONLY KYC case-detail screen.

/** The sealed UI state for the KYC case detail. */
sealed interface KycCaseDetailUiState {

    /** Initial single read of the case + synthesized timeline. */
    data object Loading : KycCaseDetailUiState

    /**
     * The loaded [case] (carrying its current status), the synthesized [timeline] (oldest -> newest), and the
     * review [reasonCodes] (shown for rejected cases). [isStale] is true when a refresh failed and this is a
     * retained last-known snapshot; [refreshing] drives pull-to-refresh.
     */
    data class Content(
        val case: KycCaseSummary,
        val timeline: List<TimelineEvent>,
        val reasonCodes: List<String>,
        val isStale: Boolean = false,
        val refreshing: Boolean = false,
    ) : KycCaseDetailUiState

    /** A terminal load error with no prior content to fall back to. [retryable] gates the Retry action. */
    data class Error(
        val message: String,
        val retryable: Boolean,
    ) : KycCaseDetailUiState
}
