package com.testlogon.android.feature.adsbilling.ui

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ads.AdAccountSummary
import com.testlogon.android.core.model.ads.AdBillingEntry
import com.testlogon.android.core.model.ads.AdInvoice

/**
 * AND-367 - hoisted UI state for the ads-account billing screen (the READ view).
 *
 *  - [Loading] - the initial read is in flight.
 *  - [Content] - the summary + ledger + (best-effort) invoice. [isStale] marks cached data shown after a
 *    refresh failure.
 *  - [Error]   - a fatal load problem (the account / ledger read failed with no cache); retryable.
 *
 * The DEPOSIT (add-funds) flow lives in a SEPARATE [DepositState] so a deposit in flight / success / error
 * NEVER clobbers the read state (the summary + ledger stay rendered behind the deposit sheet).
 */
sealed interface AdsBillingUiState {

    data object Loading : AdsBillingUiState

    /**
     * The loaded billing view. [invoice] is null when the (best-effort) monthly-invoice read failed -
     * a missing invoice is tolerated, NOT a fatal error. [isStale] is true when a refresh failed and the
     * previously-loaded content is being kept.
     */
    data class Content(
        val account: AdAccountSummary,
        val ledger: List<AdBillingEntry>,
        val invoice: AdInvoice? = null,
        val isStale: Boolean = false,
    ) : AdsBillingUiState

    /** A fatal, retryable load error. */
    data class Error(val error: ApiError) : AdsBillingUiState
}

/**
 * AND-367 - the SEPARATE deposit sub-state (kept off the read state). [Idle] is the resting state;
 * [Submitting] disables the confirm + guards against a double-submit; [Success] carries the new balance for
 * the confirmation; [Error] carries a friendly message (a 400 "Minimum deposit" is mapped to a friendly
 * string upstream). The deposit is NON-idempotent -> there is NO auto-retry from any of these.
 */
sealed interface DepositState {

    data object Idle : DepositState

    data object Submitting : DepositState

    data class Success(val newBalanceCents: Long?) : DepositState

    data class Error(val message: String) : DepositState
}
