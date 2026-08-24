package com.testlogon.android.feature.rewards

import com.testlogon.android.data.rewards.CatalogReward
import com.testlogon.android.data.rewards.ReferralStatus
import com.testlogon.android.data.rewards.ReferredUser
import com.testlogon.android.data.rewards.RewardKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure math/rules for the REFERRALS + REWARDS surface: cents<->dollars + points formatting (exact, no
 * float drift), redemption affordability + points-after (floored), referral status counting + earned/
 * pending cents, and the shareable referral text. No Android / Compose / Hilt.
 */
class RewardsMathTest {

    private fun reward(
        id: String,
        cost: Long,
        valueCents: Long = 0,
        kind: RewardKind = RewardKind.PERK,
        stockLimit: Long? = null,
        redeemedCount: Long = 0L,
    ) = CatalogReward(
        id = id,
        name = id,
        description = "",
        costPoints = cost,
        valueCents = valueCents,
        kind = kind,
        stockLimit = stockLimit,
        redeemedCount = redeemedCount,
    )

    private fun ref(id: String, status: ReferralStatus, rewardCents: Long) =
        ReferredUser(id = id, maskedName = "A**", joinedTs = 0L, status = status, rewardCents = rewardCents)

    // ---- money / points formatting ----

    @Test
    fun formatCents_alwaysTwoDecimalsNoDrift() {
        assertEquals("10.99", RewardsMath.formatCents(1099L))
        assertEquals("0.00", RewardsMath.formatCents(0L))
        assertEquals("1234.56", RewardsMath.formatCents(123456L))
    }

    @Test
    fun formatCentsUsd_prependsSymbol() {
        assertEquals("$10.99", RewardsMath.formatCentsUsd(1099L))
        assertEquals("$0.00", RewardsMath.formatCentsUsd(0L))
    }

    @Test
    fun formatPoints_groupsAndPluralizes() {
        assertEquals("0 pts", RewardsMath.formatPoints(0L))
        assertEquals("1 pt", RewardsMath.formatPoints(1L))
        assertEquals("2 pts", RewardsMath.formatPoints(2L))
        assertEquals("1,250 pts", RewardsMath.formatPoints(1250L))
        assertEquals("1,000,000 pts", RewardsMath.formatPoints(1_000_000L))
    }

    @Test
    fun groupThousands_handlesBoundariesAndNegative() {
        assertEquals("999", RewardsMath.groupThousands(999L))
        assertEquals("1,000", RewardsMath.groupThousands(1000L))
        assertEquals("-1,000", RewardsMath.groupThousands(-1000L))
    }

    // ---- redemption ----

    @Test
    fun canRedeem_affordableAndZeroCost() {
        assertTrue(RewardsMath.canRedeem(reward("a", 500), 500))
        assertTrue(RewardsMath.canRedeem(reward("a", 500), 501))
        assertTrue(RewardsMath.canRedeem(reward("free", 0), 0))
        assertFalse(RewardsMath.canRedeem(reward("a", 500), 499))
    }

    @Test
    fun pointsAfterRedeem_flooredAtZero() {
        assertEquals(250L, RewardsMath.pointsAfterRedeem(750L, reward("a", 500)))
        assertEquals(0L, RewardsMath.pointsAfterRedeem(500L, reward("a", 500)))
        // Guard: even if called on an unaffordable reward, never goes negative.
        assertEquals(0L, RewardsMath.pointsAfterRedeem(100L, reward("a", 500)))
    }

    @Test
    fun redeemableAndLockedCatalog_partitionByAffordabilityPreservingOrder() {
        val catalog = listOf(reward("a", 100), reward("b", 500), reward("c", 1000))
        val affordable = RewardsMath.redeemableCatalog(catalog, 500)
        val locked = RewardsMath.lockedCatalog(catalog, 500)
        assertEquals(listOf("a", "b"), affordable.map { it.id })
        assertEquals(listOf("c"), locked.map { it.id })
    }

    @Test
    fun pointsNeeded_zeroWhenAffordableElsePositiveGap() {
        assertEquals(0L, RewardsMath.pointsNeeded(reward("a", 500), 500))
        assertEquals(0L, RewardsMath.pointsNeeded(reward("a", 500), 900))
        assertEquals(150L, RewardsMath.pointsNeeded(reward("a", 500), 350))
    }

    @Test
    fun isCashReward_onlyForCashKind() {
        assertTrue(RewardsMath.isCashReward(reward("c", 500, 500, RewardKind.CASH)))
        assertFalse(RewardsMath.isCashReward(reward("p", 500, 0, RewardKind.PERK)))
    }

    // ---- stock / inventory limits ----

    @Test
    fun remainingStock_nullWhenUnlimited() {
        assertNull(RewardsMath.remainingStock(reward("a", 100)))
    }

    @Test
    fun remainingStock_limitMinusRedeemedFlooredAtZero() {
        assertEquals(3L, RewardsMath.remainingStock(reward("a", 100, stockLimit = 5, redeemedCount = 2)))
        assertEquals(0L, RewardsMath.remainingStock(reward("a", 100, stockLimit = 5, redeemedCount = 5)))
        // Over-redeemed never goes negative.
        assertEquals(0L, RewardsMath.remainingStock(reward("a", 100, stockLimit = 5, redeemedCount = 9)))
    }

    @Test
    fun isOutOfStock_onlyWhenLimitedAndExhausted() {
        assertFalse(RewardsMath.isOutOfStock(reward("a", 100)))
        assertFalse(RewardsMath.isOutOfStock(reward("a", 100, stockLimit = 5, redeemedCount = 4)))
        assertTrue(RewardsMath.isOutOfStock(reward("a", 100, stockLimit = 5, redeemedCount = 5)))
    }

    @Test
    fun stockLabel_unlimitedLeftAndOut() {
        assertEquals("Unlimited", RewardsMath.stockLabel(reward("a", 100)))
        assertEquals("3 left", RewardsMath.stockLabel(reward("a", 100, stockLimit = 5, redeemedCount = 2)))
        assertEquals("Out of stock", RewardsMath.stockLabel(reward("a", 100, stockLimit = 5, redeemedCount = 5)))
    }

    @Test
    fun redeemableCatalog_requiresAffordableAndInStock() {
        val catalog = listOf(
            reward("aff_stock", 100),
            reward("aff_out", 100, stockLimit = 1, redeemedCount = 1),
            reward("expensive", 1000),
        )
        // 500 points: can afford aff_stock + aff_out, but aff_out is out of stock; expensive unaffordable.
        val redeemable = RewardsMath.redeemableCatalog(catalog, 500)
        assertEquals(listOf("aff_stock"), redeemable.map { it.id })
    }

    @Test
    fun redeemableCatalog_keepsAffordableLimitedButInStock() {
        val catalog = listOf(reward("a", 100, stockLimit = 5, redeemedCount = 4))
        assertEquals(listOf("a"), RewardsMath.redeemableCatalog(catalog, 500).map { it.id })
    }

    // ---- referral counting ----

    @Test
    fun statusCount_countsByStatus() {
        val list = listOf(
            ref("1", ReferralStatus.PENDING, 0),
            ref("2", ReferralStatus.QUALIFIED, 0),
            ref("3", ReferralStatus.REWARDED, 500),
            ref("4", ReferralStatus.REWARDED, 500),
        )
        assertEquals(1, RewardsMath.statusCount(list, ReferralStatus.PENDING))
        assertEquals(1, RewardsMath.statusCount(list, ReferralStatus.QUALIFIED))
        assertEquals(2, RewardsMath.statusCount(list, ReferralStatus.REWARDED))
    }

    @Test
    fun referralEarnedCents_sumsOnlyRewarded() {
        val list = listOf(
            ref("1", ReferralStatus.PENDING, 300),
            ref("2", ReferralStatus.QUALIFIED, 400),
            ref("3", ReferralStatus.REWARDED, 500),
            ref("4", ReferralStatus.REWARDED, 500),
        )
        assertEquals(1000L, RewardsMath.referralEarnedCents(list))
    }

    @Test
    fun referralPendingCents_sumsNonRewarded() {
        val list = listOf(
            ref("1", ReferralStatus.PENDING, 300),
            ref("2", ReferralStatus.QUALIFIED, 400),
            ref("3", ReferralStatus.REWARDED, 500),
        )
        assertEquals(700L, RewardsMath.referralPendingCents(list))
    }

    @Test
    fun referralCounts_emptyListIsZero() {
        assertEquals(0, RewardsMath.statusCount(emptyList(), ReferralStatus.REWARDED))
        assertEquals(0L, RewardsMath.referralEarnedCents(emptyList()))
        assertEquals(0L, RewardsMath.referralPendingCents(emptyList()))
    }

    // ---- share text ----

    @Test
    fun referralShareText_prefersLinkAndIncludesReward() {
        val text = RewardsMath.referralShareText(code = "ABC123", link = "https://x.io/?ref=ABC123", rewardPerReferralCents = 500)
        assertTrue(text.contains("https://x.io/?ref=ABC123"))
        assertTrue(text.contains("$5.00"))
    }

    @Test
    fun referralShareText_fallsBackToCodeWhenNoLink() {
        val text = RewardsMath.referralShareText(code = "ABC123", link = "", rewardPerReferralCents = 0)
        assertTrue(text.contains("ABC123"))
        assertFalse(text.contains("http"))
    }
}
