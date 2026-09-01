package com.testlogon.android.feature.subscriptions

import com.testlogon.android.data.subscriptions.BillingInterval
import com.testlogon.android.data.subscriptions.CreatorSubscription
import com.testlogon.android.data.subscriptions.SubscriptionState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** SUBX-52 - JVM unit tests for the pure trial-convert self-service logic (no Android types). */
class TrialConvertMathTest {

    private fun sub(
        status: SubscriptionState = SubscriptionState.TRIALING,
        cancelAtPeriodEnd: Boolean = false,
        priceCents: Long? = 999L,
    ): CreatorSubscription = CreatorSubscription(
        subscriptionId = "sub_1",
        planId = "plan_1",
        creatorId = "usr_c",
        subscriberId = "usr_me",
        interval = BillingInterval.MONTH,
        provider = "ccbill",
        status = status,
        startAtEpochSeconds = 1_000L,
        currentPeriodEndEpochSeconds = 2_000L,
        cancelAtPeriodEnd = cancelAtPeriodEnd,
        priceCents = priceCents,
        currency = "USD",
        autoRenew = true,
        trialEndEpochSeconds = null,
    )

    // ---- canConvert ----

    @Test
    fun canConvert_trialing_notScheduled_true() {
        assertTrue(TrialConvertMath.canConvert(sub(status = SubscriptionState.TRIALING)))
    }

    @Test
    fun canConvert_trialing_scheduledToCancel_false() {
        assertFalse(TrialConvertMath.canConvert(sub(status = SubscriptionState.TRIALING, cancelAtPeriodEnd = true)))
    }

    @Test
    fun canConvert_active_false() {
        assertFalse(TrialConvertMath.canConvert(sub(status = SubscriptionState.ACTIVE)))
    }

    @Test
    fun canConvert_pastDue_false() {
        assertFalse(TrialConvertMath.canConvert(sub(status = SubscriptionState.PAST_DUE)))
    }

    @Test
    fun canConvert_canceled_false() {
        assertFalse(TrialConvertMath.canConvert(sub(status = SubscriptionState.CANCELED)))
    }

    @Test
    fun canConvert_expired_false() {
        assertFalse(TrialConvertMath.canConvert(sub(status = SubscriptionState.EXPIRED)))
    }

    // ---- trialDaysRemaining ----

    @Test
    fun daysRemaining_nullEnd_isNull() {
        assertNull(TrialConvertMath.trialDaysRemaining(null, 0L))
    }

    @Test
    fun daysRemaining_endInPast_isZero() {
        assertEquals(0L, TrialConvertMath.trialDaysRemaining(500L, 1_000L))
    }

    @Test
    fun daysRemaining_endEqualsNow_isZero() {
        assertEquals(0L, TrialConvertMath.trialDaysRemaining(1_000L, 1_000L))
    }

    @Test
    fun daysRemaining_exactlyOneDay_isOne() {
        assertEquals(1L, TrialConvertMath.trialDaysRemaining(TrialConvertMath.SECONDS_PER_DAY, 0L))
    }

    @Test
    fun daysRemaining_oneSecond_roundsUpToOne() {
        assertEquals(1L, TrialConvertMath.trialDaysRemaining(1L, 0L))
    }

    @Test
    fun daysRemaining_partialThirdDay_roundsUpToThree() {
        // 2 days + 1 second -> 3 days remaining (ceiling).
        val end = TrialConvertMath.SECONDS_PER_DAY * 2 + 1
        assertEquals(3L, TrialConvertMath.trialDaysRemaining(end, 0L))
    }

    @Test
    fun daysRemaining_wholeSevenDays_isSeven() {
        assertEquals(7L, TrialConvertMath.trialDaysRemaining(TrialConvertMath.SECONDS_PER_DAY * 7, 0L))
    }

    // ---- conversionChargeCents ----

    @Test
    fun charge_usesPlanPrice() {
        assertEquals(999L, TrialConvertMath.conversionChargeCents(sub(priceCents = 999L)))
    }

    @Test
    fun charge_nullPrice_isZero() {
        assertEquals(0L, TrialConvertMath.conversionChargeCents(sub(priceCents = null)))
    }

    @Test
    fun charge_negativePrice_clampedToZero() {
        assertEquals(0L, TrialConvertMath.conversionChargeCents(sub(priceCents = -50L)))
    }
}
