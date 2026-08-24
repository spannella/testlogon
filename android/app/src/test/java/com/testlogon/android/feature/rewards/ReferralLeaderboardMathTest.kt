package com.testlogon.android.feature.rewards

import com.testlogon.android.data.rewards.LeaderboardEntry
import com.testlogon.android.data.rewards.LeaderboardPeriod
import com.testlogon.android.data.rewards.LeaderboardYou
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure math/rules for the REFERRAL LEADERBOARD: medals, ranking repair, top-N slicing, and the
 * "your rank" resolution (already-in-slice vs synthetic out-of-slice row). No Android / Compose / Hilt.
 */
class ReferralLeaderboardMathTest {

    private fun entry(
        rank: Int,
        id: String,
        isYou: Boolean = false,
        referred: Int = 0,
        qualified: Int = 0,
        rewardCents: Long = 0L,
        name: String = "N**",
    ) = LeaderboardEntry(
        rank = rank,
        id = id,
        maskedName = name,
        isYou = isYou,
        referredCount = referred,
        qualifiedCount = qualified,
        rewardCents = rewardCents,
    )

    // ---- medals ----

    @Test
    fun rankMedal_topThreeGetMedals_restNone() {
        assertEquals(ReferralLeaderboardMath.Medal.GOLD, ReferralLeaderboardMath.rankMedal(1))
        assertEquals(ReferralLeaderboardMath.Medal.SILVER, ReferralLeaderboardMath.rankMedal(2))
        assertEquals(ReferralLeaderboardMath.Medal.BRONZE, ReferralLeaderboardMath.rankMedal(3))
        assertEquals(ReferralLeaderboardMath.Medal.NONE, ReferralLeaderboardMath.rankMedal(4))
        assertEquals(ReferralLeaderboardMath.Medal.NONE, ReferralLeaderboardMath.rankMedal(0))
        assertEquals(ReferralLeaderboardMath.Medal.NONE, ReferralLeaderboardMath.rankMedal(-1))
    }

    // ---- sortEntries ----

    @Test
    fun sortEntries_ordersByQualifiedThenReferredThenReward() {
        val a = entry(rank = 3, id = "a", qualified = 1, referred = 10, rewardCents = 100)
        val b = entry(rank = 1, id = "b", qualified = 5, referred = 5, rewardCents = 50)
        val c = entry(rank = 2, id = "c", qualified = 3, referred = 20, rewardCents = 999)
        val sorted = ReferralLeaderboardMath.sortEntries(listOf(a, b, c))
        assertEquals(listOf("b", "c", "a"), sorted.map { it.id })
    }

    @Test
    fun sortEntries_tieBreaksAreDeterministicAndStable() {
        val a = entry(rank = 1, id = "z", qualified = 5, referred = 5, rewardCents = 100, name = "Alpha")
        val b = entry(rank = 2, id = "y", qualified = 5, referred = 5, rewardCents = 100, name = "Alpha")
        // Identical metrics + name -> break by id asc ("y" before "z").
        val sorted = ReferralLeaderboardMath.sortEntries(listOf(a, b))
        assertEquals(listOf("y", "z"), sorted.map { it.id })
    }

    @Test
    fun sortEntries_preservesDisplayRank_doesNotRenumber() {
        val a = entry(rank = 7, id = "a", qualified = 9)
        val b = entry(rank = 9, id = "b", qualified = 1)
        val sorted = ReferralLeaderboardMath.sortEntries(listOf(b, a))
        assertEquals(7, sorted.first().rank) // rank field untouched
        assertEquals("a", sorted.first().id)
    }

    // ---- topN ----

    @Test
    fun topN_takesFirstNAfterSort() {
        val list = (1..30).map { entry(rank = it, id = "id$it", qualified = 100 - it) }
        val top = ReferralLeaderboardMath.topN(list, 20)
        assertEquals(20, top.size)
        assertEquals("id1", top.first().id)
        assertEquals("id20", top.last().id)
    }

    @Test
    fun topN_negativeOrZeroN_yieldsEmpty() {
        val list = listOf(entry(rank = 1, id = "a"))
        assertTrue(ReferralLeaderboardMath.topN(list, 0).isEmpty())
        assertTrue(ReferralLeaderboardMath.topN(list, -5).isEmpty())
    }

    // ---- youInSlice / resolveYouRow ----

    @Test
    fun youInSlice_detectsCallerRow() {
        val shown = listOf(entry(rank = 1, id = "a"), entry(rank = 2, id = "me", isYou = true))
        assertTrue(ReferralLeaderboardMath.youInSlice(shown))
        assertFalse(ReferralLeaderboardMath.youInSlice(listOf(entry(rank = 1, id = "a"))))
    }

    @Test
    fun resolveYouRow_nullWhenAlreadyInSlice() {
        val shown = listOf(entry(rank = 2, id = "me", isYou = true))
        val you = LeaderboardYou(rank = 2, referredCount = 4, qualifiedCount = 3, rewardCents = 500)
        assertNull(ReferralLeaderboardMath.resolveYouRow(shown, you))
    }

    @Test
    fun resolveYouRow_nullWhenNoServerYou() {
        val shown = listOf(entry(rank = 1, id = "a"))
        assertNull(ReferralLeaderboardMath.resolveYouRow(shown, null))
    }

    @Test
    fun resolveYouRow_buildsSyntheticRowWhenOutsideSlice() {
        val shown = listOf(entry(rank = 1, id = "a"), entry(rank = 2, id = "b"))
        val you = LeaderboardYou(rank = 42, referredCount = 7, qualifiedCount = 5, rewardCents = 1234)
        val row = ReferralLeaderboardMath.resolveYouRow(shown, you)
        assertNotNull(row)
        assertEquals(42, row!!.rank)
        assertTrue(row.isYou)
        assertEquals(7, row.referredCount)
        assertEquals(5, row.qualifiedCount)
        assertEquals(1234L, row.rewardCents)
    }

    // ---- format helpers ----

    @Test
    fun formatRank_prependsHash_emDashForNonPositive() {
        assertEquals("#12", ReferralLeaderboardMath.formatRank(12))
        assertEquals("—", ReferralLeaderboardMath.formatRank(0))
        assertEquals("—", ReferralLeaderboardMath.formatRank(-3))
    }

    @Test
    fun formatCount_groupsThousands() {
        assertEquals("1,250", ReferralLeaderboardMath.formatCount(1250))
        assertEquals("0", ReferralLeaderboardMath.formatCount(0))
    }

    @Test
    fun formatRewardCents_isUsd() {
        assertEquals("$12.34", ReferralLeaderboardMath.formatRewardCents(1234L))
    }

    @Test
    fun periodLabel_humanReadable() {
        assertEquals("All-time", ReferralLeaderboardMath.periodLabel(LeaderboardPeriod.ALL))
        assertEquals("This month", ReferralLeaderboardMath.periodLabel(LeaderboardPeriod.MONTH))
    }
}
