package com.testlogon.android.feature.call.billing

/**
 * AND-301 — pure (android-free, JVM-testable) UI contract for the 1:1 call BILLING layer that ATTACHES
 * to the existing call flow (AND-296/298). No android.*, no Compose. Money is Int CENTS, USD.
 *
 * The billing layer is purely additive: it observes the invite (paid/rate), the server heartbeat
 * (authoritative running cost/balance/warnings), and the terminal billing read — it does NOT drive the
 * call FSM. The pre-start confirm is a LOCAL affordance; the wallet-balance check routes through the
 * FLAGGED [com.testlogon.android.data.messaging.BillingAuthorizer] seam (AND-031), which returns
 * NotConfigured, so a null balance means "balance check unavailable" and start is still allowed.
 */

/** The pre-start paid-call confirm gate (LOCAL affordance; there is no server /authorize endpoint). */
sealed interface PaidCallConfirmState {
    /** Free call (paid==false / no rate): no confirm gate. */
    data object NotPaid : PaidCallConfirmState

    /**
     * Paid call awaiting the user's Start/Cancel decision. [balanceRemainingCents] is null when the
     * FLAGGED wallet check is unavailable (do NOT block start on an unknown balance).
     */
    data class AwaitingConfirm(
        val rateCentsPerMinute: Int,
        val balanceRemainingCents: Int?,
    ) : PaidCallConfirmState

    /** User confirmed: the gate is open, the call may proceed. */
    data object Confirmed : PaidCallConfirmState

    /** User cancelled the paid call before start. */
    data object Cancelled : PaidCallConfirmState
}

/** A billing warning/terminal condition surfaced to the UI (mapped from heartbeat warnings / end reason). */
enum class BillingCondition {
    None,
    LowBalance,
    MaxDurationWarning,
    BalanceDepleted,
    MaxDurationReached,
    HeartbeatTimeout,
}

/**
 * The immutable billing snapshot the running-cost overlay + confirm dialog render. [runningCostCents] is
 * authoritative (heartbeat) when [isEstimate] is false, otherwise a local estimate. [finalCostCents] is
 * set on Ended (authoritative from the billing read, or the last running value labelled [finalIsEstimate]).
 */
data class CallBillingUiState(
    val paid: Boolean,
    val rateCentsPerMinute: Int,
    val confirm: PaidCallConfirmState,
    val runningCostCents: Int,
    val isEstimate: Boolean,
    val balanceRemainingCents: Int?,
    val condition: BillingCondition,
    val finalCostCents: Int?,
    val finalIsEstimate: Boolean,
) {
    companion object {
        /** Default snapshot for a free (non-paid) call: nothing to bill, no confirm gate. */
        fun free(): CallBillingUiState = CallBillingUiState(
            paid = false,
            rateCentsPerMinute = 0,
            confirm = PaidCallConfirmState.NotPaid,
            runningCostCents = 0,
            isEstimate = false,
            balanceRemainingCents = null,
            condition = BillingCondition.None,
            finalCostCents = null,
            finalIsEstimate = false,
        )
    }
}
