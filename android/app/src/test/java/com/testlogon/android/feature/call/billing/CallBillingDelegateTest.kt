package com.testlogon.android.feature.call.billing

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-301 — pure JUnit tests for the [CallBillingDelegate] reducers (no coroutines). */
class CallBillingDelegateTest {

    private val delegate = CallBillingDelegate()

    @Test
    fun onInvite_freeCall_isNotPaid() {
        val state = delegate.onInvite(paid = false, rateCentsPerMinute = null)
        assertFalse(state.paid)
        assertEquals(PaidCallConfirmState.NotPaid, state.confirm)
    }

    @Test
    fun onInvite_paidButNoRate_isNotPaid() {
        val state = delegate.onInvite(paid = true, rateCentsPerMinute = null)
        assertEquals(PaidCallConfirmState.NotPaid, state.confirm)
    }

    @Test
    fun onInvite_paidCall_awaitsConfirmWithRate() {
        val state = delegate.onInvite(paid = true, rateCentsPerMinute = 5)
        assertTrue(state.paid)
        assertEquals(5, state.rateCentsPerMinute)
        val confirm = state.confirm as PaidCallConfirmState.AwaitingConfirm
        assertEquals(5, confirm.rateCentsPerMinute)
        assertEquals(null, confirm.balanceRemainingCents)
    }

    @Test
    fun confirmPaidCall_opensGate() {
        val state = delegate.onInvite(paid = true, rateCentsPerMinute = 5)
        assertEquals(PaidCallConfirmState.Confirmed, delegate.confirmPaidCall(state).confirm)
    }

    @Test
    fun cancel_recordsCancelled() {
        val state = delegate.onInvite(paid = true, rateCentsPerMinute = 5)
        assertEquals(PaidCallConfirmState.Cancelled, delegate.cancel(state).confirm)
    }

    @Test
    fun onHeartbeat_setsAuthoritativeCostAndBalance() {
        val state = delegate.confirmPaidCall(delegate.onInvite(paid = true, rateCentsPerMinute = 5))
        val next = delegate.onHeartbeat(
            state = state,
            totalCostCents = 15,
            balanceRemainingCents = 200,
            warnLowBalance = false,
            maxDurationWarning = false,
        )
        assertEquals(15, next.runningCostCents)
        assertEquals(200, next.balanceRemainingCents)
        assertFalse(next.isEstimate)
        assertEquals(BillingCondition.None, next.condition)
    }

    @Test
    fun onHeartbeat_lowBalance_mapsLowBalanceCondition() {
        val state = delegate.onInvite(paid = true, rateCentsPerMinute = 5)
        val next = delegate.onHeartbeat(state, 10, 5, warnLowBalance = true, maxDurationWarning = false)
        assertEquals(BillingCondition.LowBalance, next.condition)
    }

    @Test
    fun onHeartbeat_maxDuration_mapsMaxDurationWarning() {
        val state = delegate.onInvite(paid = true, rateCentsPerMinute = 5)
        val next = delegate.onHeartbeat(state, 10, 50, warnLowBalance = false, maxDurationWarning = true)
        assertEquals(BillingCondition.MaxDurationWarning, next.condition)
    }

    @Test
    fun onEstimateTick_marksEstimate() {
        val state = delegate.onInvite(paid = true, rateCentsPerMinute = 5)
        val next = delegate.onEstimateTick(state, elapsedSeconds = 61L)
        assertEquals(10, next.runningCostCents)
        assertTrue(next.isEstimate)
    }

    @Test
    fun onEnded_withFinalCost_isAuthoritative() {
        val state = delegate.onHeartbeat(
            delegate.onInvite(paid = true, rateCentsPerMinute = 5),
            totalCostCents = 15,
            balanceRemainingCents = 200,
            warnLowBalance = false,
            maxDurationWarning = false,
        )
        val ended = delegate.onEnded(state, finalCostCents = 20, endReason = "ended")
        assertEquals(20, ended.finalCostCents)
        assertFalse(ended.finalIsEstimate)
    }

    @Test
    fun onEnded_withoutFinalCost_fallsBackToRunningEstimate() {
        val state = delegate.onHeartbeat(
            delegate.onInvite(paid = true, rateCentsPerMinute = 5),
            totalCostCents = 15,
            balanceRemainingCents = 200,
            warnLowBalance = false,
            maxDurationWarning = false,
        )
        val ended = delegate.onEnded(state, finalCostCents = null, endReason = "ended")
        assertEquals(15, ended.finalCostCents)
        assertTrue(ended.finalIsEstimate)
    }

    @Test
    fun onEnded_balanceDepleted_mapsCondition() {
        val state = delegate.onInvite(paid = true, rateCentsPerMinute = 5)
        assertEquals(
            BillingCondition.BalanceDepleted,
            delegate.onEnded(state, finalCostCents = 10, endReason = "balance_depleted").condition,
        )
    }

    @Test
    fun onEnded_maxDurationReached_mapsCondition() {
        val state = delegate.onInvite(paid = true, rateCentsPerMinute = 5)
        assertEquals(
            BillingCondition.MaxDurationReached,
            delegate.onEnded(state, finalCostCents = 10, endReason = "max_duration_reached").condition,
        )
    }

    @Test
    fun onEnded_heartbeatTimeout_mapsCondition() {
        val state = delegate.onInvite(paid = true, rateCentsPerMinute = 5)
        assertEquals(
            BillingCondition.HeartbeatTimeout,
            delegate.onEnded(state, finalCostCents = 10, endReason = "heartbeat_timeout").condition,
        )
    }
}
