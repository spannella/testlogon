package com.testlogon.android.feature.kyc.screening

import com.testlogon.android.feature.kyc.screening.model.KycScreeningResult
import com.testlogon.android.feature.kyc.screening.model.ScreeningStatus
import java.time.Instant

// AND-328 - UI state for the READ-ONLY KYC screening status screen.

/** The sealed UI state for the screening flow. */
sealed interface ScreeningUiState {

    /** Initial single read of the screening results. */
    data object Loading : ScreeningUiState

    /**
     * The aggregated [status] plus the per-screen [results] breakdown. [isStale] is true when a refresh
     * failed and this is a retained last-known snapshot; [lastUpdated] is the newest screened_at across the
     * results (locale-aware time formatting happens in the screen). [refreshing] drives pull-to-refresh.
     */
    data class Content(
        val status: ScreeningStatus,
        val results: List<KycScreeningResult>,
        val isStale: Boolean = false,
        val lastUpdated: Instant? = null,
        val refreshing: Boolean = false,
    ) : ScreeningUiState

    /** A terminal load error with no prior content to fall back to. [retryable] gates the Retry action. */
    data class Error(
        val message: String,
        val retryable: Boolean,
    ) : ScreeningUiState
}
