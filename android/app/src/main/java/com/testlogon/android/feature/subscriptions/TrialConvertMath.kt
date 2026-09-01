package com.testlogon.android.feature.subscriptions

import com.testlogon.android.data.subscriptions.CreatorSubscription
import com.testlogon.android.data.subscriptions.SubscriptionState

/**
 * SUBX-52 - pure, framework-free logic for the subscriber "Convert trial to paid now" self-service.
 *
 * The backend already auto-converts a trial at trial_end (the SUBX-01 sweeper rail); this surface lets a
 * TRIALING subscriber opt to be charged EARLY (POST api/subscriptions/{id}/trial/convert, same
 * funds-guarded rail). This object owns ONLY the deterministic decisions the ManageSubscription screen
 * needs: is the sub eligible to convert now, and how many trial days remain (for the "N days left" chip).
 * No clock, no Android types, no I/O - the current time is passed in (epoch seconds) so it is JVM-testable.
 *
 * Mirrors the backend gate in convert_trial (subscription_server.py:2645): a manual convert is allowed
 * ONLY while status == "trialing". A sub that is trialing but already scheduled to cancel at period end is
 * NOT offered a convert (converting an about-to-lapse trial would charge for access the subscriber has
 * chosen to give up); it must be un-scheduled (Keep) first.
 */
object TrialConvertMath {

    /** Seconds in one day (trial windows are stored as epoch seconds). */
    const val SECONDS_PER_DAY: Long = 86_400L

    /**
     * True when the subscription may be MANUALLY converted from trial to paid right now: it is in the
     * TRIALING state AND is not scheduled to cancel at period end. Mirrors the backend 400
     * "Subscription is not in trial" guard (only trialing subs convert) plus the Android product rule
     * (don't charge a trial the subscriber has already chosen to let lapse).
     */
    fun canConvert(subscription: CreatorSubscription): Boolean =
        subscription.status == SubscriptionState.TRIALING && !subscription.cancelAtPeriodEnd

    /**
     * Whole trial days remaining from [nowEpochSeconds] until [trialEndEpochSeconds], rounded UP so a
     * partial final day still reads as "1 day left" (never 0 while the trial is genuinely live). Returns
     * null when the trial end is unknown (the caller then hides the countdown) and 0 when the trial end is
     * at/before now (already elapsed - the sweeper is about to convert it). Negative inputs never produce
     * a negative result.
     */
    fun trialDaysRemaining(trialEndEpochSeconds: Long?, nowEpochSeconds: Long): Long? {
        val end = trialEndEpochSeconds ?: return null
        val remainingSeconds = end - nowEpochSeconds
        if (remainingSeconds <= 0L) return 0L
        // Ceiling division so any partial day counts as a full remaining day.
        return (remainingSeconds + SECONDS_PER_DAY - 1L) / SECONDS_PER_DAY
    }

    /**
     * The amount (integer USD cents) that converting the trial will charge: the plan's own price. Falls
     * back to 0 when the price is unknown (a $0 trial-convert is a no-op charge server-side). Never
     * negative.
     */
    fun conversionChargeCents(subscription: CreatorSubscription): Long {
        val cents = subscription.priceCents ?: 0L
        return if (cents < 0L) 0L else cents
    }
}
