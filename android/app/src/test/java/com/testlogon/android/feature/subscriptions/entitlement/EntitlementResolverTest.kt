package com.testlogon.android.feature.subscriptions.entitlement

import com.testlogon.android.data.fanclub.FanClubTier
import com.testlogon.android.data.subscriptions.BillingInterval
import com.testlogon.android.data.subscriptions.CreatorSubscription
import com.testlogon.android.data.subscriptions.SubscriptionState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-241 / AND-242 — pure verdict matrix for [EntitlementResolver] (100% branch coverage backstop):
 * {no subs, active at tier, higher owned, lower owned, lapsed, multiple} x {Plan, Content, FanClub},
 * plus fail-closed Unknown when inputs are null. No I/O.
 */
class EntitlementResolverTest {

    private val resolver = EntitlementResolver()

    private fun sub(planId: String, status: SubscriptionState = SubscriptionState.ACTIVE) = CreatorSubscription(
        subscriptionId = "sub_$planId",
        planId = planId,
        creatorId = "cr_1",
        subscriberId = "u_1",
        interval = BillingInterval.MONTH,
        provider = "ccbill",
        status = status,
        startAtEpochSeconds = 0,
        currentPeriodEndEpochSeconds = 100,
        cancelAtPeriodEnd = false,
        priceCents = 999,
        currency = "USD",
        autoRenew = true,
    )

    private fun tier(id: String, level: Int, planId: String?) = FanClubTier(
        id = id, planId = planId, name = id, level = level, color = null, badgeEmoji = null,
        badgeImageUrl = null, description = null, memberCount = 0, sortOrder = level, active = true,
    )

    // ---- ownsTier ----

    @Test
    fun ownsTier_activeSubAtPlan_true_lapsed_false_null_false() {
        assertTrue(resolver.ownsTier(listOf(sub("plan_gold")), "plan_gold"))
        assertFalse(resolver.ownsTier(listOf(sub("plan_gold", SubscriptionState.CANCELED)), "plan_gold"))
        assertFalse(resolver.ownsTier(listOf(sub("plan_silver")), "plan_gold"))
        assertFalse(resolver.ownsTier(null, "plan_gold"))
    }

    @Test
    fun ownsTier_trialingCountsAsOwned() {
        assertTrue(resolver.ownsTier(listOf(sub("plan_gold", SubscriptionState.TRIALING)), "plan_gold"))
    }

    // ---- Plan key ----

    @Test
    fun resolvePlan_owned_granted() {
        assertEquals(Entitlement.Granted, resolver.resolve(listOf(sub("plan_gold")), null, EntitlementKey.Plan("plan_gold")))
    }

    @Test
    fun resolvePlan_noSubs_deniedNotSubscribed() {
        val v = resolver.resolve(emptyList(), null, EntitlementKey.Plan("plan_gold"))
        assertTrue(v is Entitlement.Denied)
    }

    @Test
    fun resolvePlan_lapsedSubToPlan_deniedLapsed() {
        val v = resolver.resolve(
            listOf(sub("plan_gold", SubscriptionState.CANCELED)), null, EntitlementKey.Plan("plan_gold"),
        )
        assertEquals(Entitlement.Denied("subscription_lapsed"), v)
    }

    @Test
    fun resolvePlan_nullSubs_unknown() {
        assertEquals(Entitlement.Unknown, resolver.resolve(null, null, EntitlementKey.Plan("plan_gold")))
    }

    // ---- activeTierLevel ----

    @Test
    fun activeTierLevel_maxOwnedLevel() {
        val tiers = listOf(tier("t1", 1, "plan_bronze"), tier("t2", 2, "plan_gold"), tier("t3", 3, "plan_plat"))
        val subs = listOf(sub("plan_bronze"), sub("plan_gold")) // owns level 1 + 2 -> 2
        assertEquals(2, resolver.activeTierLevel(subs, tiers))
    }

    @Test
    fun activeTierLevel_noMatch_zero() {
        assertEquals(0, resolver.activeTierLevel(listOf(sub("plan_x")), listOf(tier("t1", 1, "plan_gold"))))
        assertEquals(0, resolver.activeTierLevel(null, null))
    }

    // ---- Content / FanClub level keys ----

    private val ladder = listOf(tier("t1", 1, "plan_bronze"), tier("t2", 2, "plan_gold"), tier("t3", 3, "plan_plat"))

    @Test
    fun content_atOrAboveRequired_granted() {
        val subs = listOf(sub("plan_plat")) // level 3
        assertEquals(Entitlement.Granted, resolver.resolve(subs, ladder, EntitlementKey.Content("c", minLevel = 2)))
    }

    @Test
    fun content_belowRequired_requiresUpgrade() {
        val subs = listOf(sub("plan_bronze")) // level 1
        val v = resolver.resolve(subs, ladder, EntitlementKey.Content("c", minLevel = 3))
        assertEquals(Entitlement.RequiresUpgrade(3), v)
    }

    @Test
    fun content_noMembership_notLapsed_requiresUpgrade() {
        val v = resolver.resolve(emptyList(), ladder, EntitlementKey.Content("c", minLevel = 2))
        assertEquals(Entitlement.RequiresUpgrade(2), v)
    }

    @Test
    fun content_onlyLapsedMembership_denied() {
        val subs = listOf(sub("plan_gold", SubscriptionState.CANCELED))
        val v = resolver.resolve(subs, ladder, EntitlementKey.Content("c", minLevel = 2))
        assertEquals(Entitlement.Denied("subscription_lapsed"), v)
    }

    @Test
    fun fanClub_noMinLevel_anyMembershipGrants() {
        val subs = listOf(sub("plan_bronze")) // level 1 >= default member level 1
        assertEquals(Entitlement.Granted, resolver.resolve(subs, ladder, EntitlementKey.FanClub("cr_1")))
    }

    @Test
    fun fanClub_noMinLevel_noMembership_requiresUpgrade() {
        val v = resolver.resolve(emptyList(), ladder, EntitlementKey.FanClub("cr_1"))
        assertEquals(Entitlement.RequiresUpgrade(1), v)
    }

    @Test
    fun levelKey_nullEitherInput_failsClosedUnknown() {
        assertEquals(Entitlement.Unknown, resolver.resolve(null, ladder, EntitlementKey.Content("c", 2)))
        assertEquals(Entitlement.Unknown, resolver.resolve(emptyList(), null, EntitlementKey.FanClub("cr_1", 2)))
    }
}
