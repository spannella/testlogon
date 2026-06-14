package com.testlogon.android.feature.subscriptions.entitlement

import com.testlogon.android.data.fanclub.FanClubTier
import com.testlogon.android.data.subscriptions.CreatorSubscription
import com.testlogon.android.data.subscriptions.SubscriptionState
import javax.inject.Inject

/**
 * AND-241 — pure (no I/O), deterministic entitlement derivation, shared by the subscription + fan-club
 * surfaces so the UI affordance can never disagree with the gate (FR-4/FR-8).
 *
 * Source of truth: the viewer's [CreatorSubscription] list (real `api/subscriptions`) plus the creator's
 * [FanClubTier] catalog (real `TierOut`, which carries the numeric `level` rank and the `plan_id` that
 * links a tier to a subscription plan). A fan-club tier is "owned" when the viewer holds an active
 * subscription to that tier's `plan_id`; the viewer's effective tier level is the max owned tier level.
 *
 * Fail-closed: when the inputs are `null` (data unavailable) the verdict is [Entitlement.Unknown], which
 * gates MUST treat as not-entitled (AND-241 §7/§8). An empty list is a known "nothing owned" answer
 * (Denied / RequiresUpgrade), distinct from `null` (Unknown).
 *
 * @Inject-constructable; no module needed.
 */
class EntitlementResolver @Inject constructor() {

    /**
     * Resolves [required] against the viewer's [subscriptions] + the creator's fan-club [tiers].
     * A `null` for the list needed by [required] yields [Entitlement.Unknown] (fail closed).
     */
    fun resolve(
        subscriptions: List<CreatorSubscription>?,
        tiers: List<FanClubTier>?,
        required: EntitlementKey,
    ): Entitlement = when (required) {
        is EntitlementKey.Plan -> resolvePlan(subscriptions, required.planId)
        is EntitlementKey.Content -> resolveLevel(subscriptions, tiers, required.minLevel)
        is EntitlementKey.FanClub -> resolveLevel(subscriptions, tiers, required.minLevel)
    }

    /** True only when an ACTIVE/TRIALING subscription references [planId] (drives TierRow.owned). */
    fun ownsTier(subscriptions: List<CreatorSubscription>?, planId: String): Boolean =
        subscriptions.orEmpty().any { it.planId == planId && it.isActiveLike() }

    /** The viewer's effective fan-club tier level (max owned tier level), or 0 when none/unknown. */
    fun activeTierLevel(
        subscriptions: List<CreatorSubscription>?,
        tiers: List<FanClubTier>?,
    ): Int {
        val activePlanIds = subscriptions.orEmpty()
            .filter { it.isActiveLike() }
            .map { it.planId }
            .toSet()
        return tiers.orEmpty()
            .filter { it.planId != null && it.planId in activePlanIds }
            .maxOfOrNull { it.level }
            ?: 0
    }

    private fun resolvePlan(subscriptions: List<CreatorSubscription>?, planId: String): Entitlement {
        if (subscriptions == null) return Entitlement.Unknown
        if (ownsTier(subscriptions, planId)) return Entitlement.Granted
        // A lapsed-only sub to this plan is Denied (re-subscribe), not an upgrade path.
        val hasLapsed = subscriptions.any { it.planId == planId && !it.isActiveLike() }
        return if (hasLapsed) Entitlement.Denied(REASON_LAPSED) else Entitlement.Denied(REASON_NOT_SUBSCRIBED)
    }

    private fun resolveLevel(
        subscriptions: List<CreatorSubscription>?,
        tiers: List<FanClubTier>?,
        minLevel: Int?,
    ): Entitlement {
        // Either input being absent means we cannot decide -> fail closed.
        if (subscriptions == null || tiers == null) return Entitlement.Unknown
        // No minimum required -> any active membership grants; otherwise being a member at all grants.
        val ownedLevel = activeTierLevel(subscriptions, tiers)
        val required = minLevel ?: MIN_MEMBER_LEVEL
        return when {
            ownedLevel >= required && ownedLevel > 0 -> Entitlement.Granted
            ownedLevel == 0 && hasOnlyLapsed(subscriptions) -> Entitlement.Denied(REASON_LAPSED)
            else -> Entitlement.RequiresUpgrade(required)
        }
    }

    private fun hasOnlyLapsed(subscriptions: List<CreatorSubscription>): Boolean =
        subscriptions.isNotEmpty() && subscriptions.none { it.isActiveLike() }

    private fun CreatorSubscription.isActiveLike(): Boolean =
        status == SubscriptionState.ACTIVE || status == SubscriptionState.TRIALING

    private companion object {
        const val MIN_MEMBER_LEVEL = 1
        const val REASON_LAPSED = "subscription_lapsed"
        const val REASON_NOT_SUBSCRIBED = "not_subscribed"
    }
}
