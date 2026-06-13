package com.testlogon.android.feature.kyc.prooffunds

import com.testlogon.android.feature.kyc.prooffunds.model.PoFSource
import com.testlogon.android.feature.kyc.prooffunds.model.PoFSummary
import com.testlogon.android.feature.kyc.prooffunds.model.ProofOfFunds

// AND-327 - UI state + supporting types for the KYC proof-of-funds screen.

/**
 * Per-field validation flags for the submit form, surfaced inline so the screen can show field errors
 * without throwing. The submit button is gated separately by [ProofOfFundsUiState.Form.submitEnabled].
 */
data class PoFFieldErrors(
    val sourceMissing: Boolean = false,
    val amountMissing: Boolean = false,
    val amountInvalid: Boolean = false,
    val documentMissing: Boolean = false,
)

/** The sealed UI state for the proof-of-funds flow. */
sealed interface ProofOfFundsUiState {

    /** Initial single load of summary + submissions. */
    data object Loading : ProofOfFundsUiState

    /**
     * The latest submission's status plus the full [history]. [canResubmit] gates the Resubmit affordance
     * (true when the latest status invites more evidence). [refreshing] drives pull-to-refresh.
     */
    data class Status(
        val summary: PoFSummary,
        val latest: ProofOfFunds,
        val history: List<ProofOfFunds>,
        val canResubmit: Boolean,
        val refreshing: Boolean = false,
    ) : ProofOfFundsUiState

    /**
     * The editable submit form. The client UX requires a document + a source + an amount before
     * [submitEnabled] turns true (even though the wire treats every field as optional).
     */
    data class Form(
        val summary: PoFSummary,
        val source: PoFSource? = null,
        val sourceCategoryList: List<PoFSource> = PoFSource.selectable,
        val amountRaw: String = "",
        val currency: String = DEFAULT_CURRENCY,
        val note: String = "",
        val documentKey: String? = null,
        val documentLabel: String? = null,
        val fieldErrors: PoFFieldErrors = PoFFieldErrors(),
        val uploading: Boolean = false,
        val submitting: Boolean = false,
        val submitEnabled: Boolean = false,
        val inlineError: String? = null,
    ) : ProofOfFundsUiState

    /** A terminal-for-now error. [retryable] gates the retry affordance. */
    data class Error(val message: String, val retryable: Boolean) : ProofOfFundsUiState

    companion object {
        const val DEFAULT_CURRENCY = "USD"
    }
}
