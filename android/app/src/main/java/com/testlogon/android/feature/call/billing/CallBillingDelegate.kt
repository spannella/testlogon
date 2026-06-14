package com.testlogon.android.feature.call.billing

/**
 * AND-301 — the pure (android-free, coroutine-free) billing state machine for a 1:1 call. Takes
 * primitives / domain values and returns the next [CallBillingUiState]; the view models own the
 * coroutines + StateFlow and merely call these reducers, which keeps the logic trivially unit-testable.
 *
 * This delegate NEVER drives the call FSM (AND-296/298 owns it) and NEVER executes a charge — the pre-start
 * wallet check is the FLAGGED [com.testlogon.android.data.messaging.BillingAuthorizer] seam (AND-031).
 */
class CallBillingDelegate {

    /**
     * Seeds the billing state from the invite. paid && rate != null -> AwaitingConfirm (the pre-start
     * confirm gate); otherwise a free call (NotPaid). [balanceRemainingCents] is the FLAGGED wallet
     * balance (null = "balance check unavailable"; start is still allowed).
     */
    fun onInvite(
        paid: Boolean,
        rateCentsPerMinute: Int?,
        balanceRemainingCents: Int? = null,
    ): CallBillingUiState {
        if (!paid || rateCentsPerMinute == null) return CallBillingUiState.free()
        return CallBillingUiState.free().copy(
            paid = true,
            rateCentsPerMinute = rateCentsPerMinute,
            confirm = PaidCallConfirmState.AwaitingConfirm(
                rateCentsPerMinute = rateCentsPerMinute,
                balanceRemainingCents = balanceRemainingCents,
            ),
            balanceRemainingCents = balanceRemainingCents,
        )
    }

    /** User confirmed the paid call: the gate opens. */
    fun confirmPaidCall(state: CallBillingUiState): CallBillingUiState =
        state.copy(confirm = PaidCallConfirmState.Confirmed)

    /** User cancelled the paid call before start. */
    fun cancel(state: CallBillingUiState): CallBillingUiState =
        state.copy(confirm = PaidCallConfirmState.Cancelled)

    /**
     * Applies an authoritative server heartbeat: the running cost + balance come straight from the
     * server ([isEstimate] = false); warnings map to a [BillingCondition].
     */
    fun onHeartbeat(
        state: CallBillingUiState,
        totalCostCents: Int,
        balanceRemainingCents: Int,
        warnLowBalance: Boolean,
        maxDurationWarning: Boolean,
    ): CallBillingUiState = state.copy(
        runningCostCents = totalCostCents,
        isEstimate = false,
        balanceRemainingCents = balanceRemainingCents,
        condition = conditionFromWarnings(warnLowBalance, maxDurationWarning),
    )

    /**
     * Bridges between heartbeats with the LOCAL estimate (ceil(elapsed/60) * rate). Callers should only
     * apply this when no recent authoritative heartbeat exists; it always marks [isEstimate] = true.
     */
    fun onEstimateTick(state: CallBillingUiState, elapsedSeconds: Long): CallBillingUiState =
        state.copy(
            runningCostCents = BillingCalculator.estimateCents(elapsedSeconds, state.rateCentsPerMinute),
            isEstimate = true,
        )

    /**
     * Finalizes on Ended: [finalCostCents] from the billing read / server end when known
     * (finalIsEstimate = false); otherwise the last running value, labelled an estimate. The end reason
     * maps to a terminal [BillingCondition].
     */
    fun onEnded(
        state: CallBillingUiState,
        finalCostCents: Int?,
        endReason: String?,
    ): CallBillingUiState {
        val finalEstimate = finalCostCents == null
        val resolvedFinal = finalCostCents ?: state.runningCostCents
        return state.copy(
            finalCostCents = resolvedFinal,
            finalIsEstimate = finalEstimate,
            condition = conditionFromEndReason(endReason, state.condition),
        )
    }

    private fun conditionFromWarnings(
        warnLowBalance: Boolean,
        maxDurationWarning: Boolean,
    ): BillingCondition = when {
        maxDurationWarning -> BillingCondition.MaxDurationWarning
        warnLowBalance -> BillingCondition.LowBalance
        else -> BillingCondition.None
    }

    private fun conditionFromEndReason(
        endReason: String?,
        fallback: BillingCondition,
    ): BillingCondition = when (endReason?.lowercase()) {
        "balance_depleted", "insufficient_balance" -> BillingCondition.BalanceDepleted
        "max_duration_reached" -> BillingCondition.MaxDurationReached
        "heartbeat_timeout" -> BillingCondition.HeartbeatTimeout
        "ended", "hangup", null -> fallback
        else -> fallback
    }
}
