package com.testlogon.android.feature.kyc.eidv

import com.testlogon.android.feature.kyc.eidv.model.EidScheme
import com.testlogon.android.feature.kyc.eidv.model.EidVerification
import com.testlogon.android.feature.kyc.eidv.model.SchemeInfo

// AND-325 - UI state for the KYC electronic ID verification (eIDV) redirect screen.

/**
 * The single immutable UI state for the eIDV flow.
 *
 * - [Loading]          the initial scheme list (or a resume-status check) is in flight.
 * - [SchemeSelection]  the user picks a government eID scheme; [canStart] gates the Start button;
 *                      [starting] guards the non-idempotent start POST debounce.
 * - [AwaitingProvider] the session is started; the screen opens [redirectUrl] EXTERNALLY and a bounded
 *                      status poll runs while [polling]. [expiresAt] is epoch seconds.
 * - [Result]           a completed verification assertion arrived.
 * - [Expired]          the session reached [expires_at] with no assertion.
 * - [Error]            a load / start / status failure, tagged with the [retry] kind.
 */
sealed interface EidvUiState {

    data object Loading : EidvUiState

    data class SchemeSelection(
        val schemes: List<SchemeInfo> = emptyList(),
        val selected: EidScheme? = null,
        val starting: Boolean = false,
    ) : EidvUiState {
        val canStart: Boolean
            get() = selected != null && !starting
    }

    data class AwaitingProvider(
        val caseId: String,
        val sessionId: String,
        val scheme: EidScheme,
        val redirectUrl: String,
        val expiresAt: Long,
        val polling: Boolean = true,
    ) : EidvUiState

    data class Result(
        val caseId: String,
        val verification: EidVerification,
        val hasCriticalDiscrepancy: Boolean,
        val autoTierUpgrade: Boolean,
    ) : EidvUiState

    data object Expired : EidvUiState

    data class Error(
        val message: String,
        val retry: Retry,
    ) : EidvUiState

    /** Which action a retry affordance should re-run. */
    enum class Retry { LOAD, START, STATUS }
}
