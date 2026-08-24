package com.testlogon.android.feature.rewards

import com.testlogon.android.data.rewards.LeaderboardEntry
import com.testlogon.android.data.rewards.LeaderboardYou

/**
 * Pure, Android-free math + formatting for the REFERRAL LEADERBOARD (feature/rewards). Kept out of the
 * ViewModel so ranking, medals, the "your rank" resolution and the shown-slice are unit-testable without
 * Compose/Hilt. Money is integer cents throughout (formatting delegates to [RewardsMath] for a single
 * source of truth, no float drift).
 *
 * DISTINCT from the social-achievements leaderboard: this ranks REFERRERS by referred/qualified count +
 * reward earned. Ranking is server-authoritative (entries carry a server `rank`); [sortEntries] only
 * repairs an out-of-order or rank-less slice so the UI never renders a scrambled list.
 */
object ReferralLeaderboardMath {

    /** Default number of top rows the board shows before falling back to the pinned "your rank" row. */
    const val DEFAULT_TOP_N: Int = 20

    /** A medal tier for the top three ranks; [NONE] for everyone else. */
    enum class Medal { GOLD, SILVER, BRONZE, NONE }

    /** rank 1/2/3 -> gold/silver/bronze, else none. Non-positive ranks are [Medal.NONE]. */
    fun rankMedal(rank: Int): Medal = when (rank) {
        1 -> Medal.GOLD
        2 -> Medal.SILVER
        3 -> Medal.BRONZE
        else -> Medal.NONE
    }

    /**
     * Deterministic ranking repair for a slice whose server ranks may be missing/scrambled: order by
     * qualified_count desc, then referred_count desc, then reward_cents desc, then masked_name asc, then
     * id asc (stable, total). Does NOT renumber — the row's own `rank` is preserved for display.
     */
    fun sortEntries(entries: List<LeaderboardEntry>): List<LeaderboardEntry> =
        entries.sortedWith(
            compareByDescending<LeaderboardEntry> { it.qualifiedCount }
                .thenByDescending { it.referredCount }
                .thenByDescending { it.rewardCents }
                .thenBy { it.maskedName.lowercase() }
                .thenBy { it.id },
        )

    /** The first [n] rows of the (repaired) slice; [n] is coerced to at least 0. */
    fun topN(entries: List<LeaderboardEntry>, n: Int = DEFAULT_TOP_N): List<LeaderboardEntry> =
        sortEntries(entries).take(n.coerceAtLeast(0))

    /** True when the caller already appears in the shown slice (so no pinned "your rank" row is needed). */
    fun youInSlice(shown: List<LeaderboardEntry>): Boolean = shown.any { it.isYou }

    /**
     * Resolve the pinned "Your rank" row. Returns null when the caller is already visible in [shown]
     * (no duplicate) or when the server gave us no out-of-slice [you] rank. Otherwise a synthetic row is
     * built from [you] so the caller always sees their standing even outside the top N. The synthetic row
     * is flagged [LeaderboardEntry.isYou] = true and carries a blank id/name (the UI labels it "You").
     */
    fun resolveYouRow(shown: List<LeaderboardEntry>, you: LeaderboardYou?): LeaderboardEntry? {
        if (youInSlice(shown)) return null
        val y = you ?: return null
        return LeaderboardEntry(
            rank = y.rank,
            id = "",
            maskedName = "You",
            isYou = true,
            referredCount = y.referredCount,
            qualifiedCount = y.qualifiedCount,
            rewardCents = y.rewardCents,
        )
    }

    // ---- Format helpers (delegate money to RewardsMath; single source of truth) ----

    /** "#12" rank label. Non-positive ranks render as an em dash. */
    fun formatRank(rank: Int): String = if (rank > 0) "#$rank" else "—"

    /** Integer count with thousands grouping (1250 -> "1,250"). */
    fun formatCount(count: Int): String = RewardsMath.groupThousands(count.toLong())

    /** Reward earned as USD ("$12.34"). */
    fun formatRewardCents(cents: Long): String = RewardsMath.formatCentsUsd(cents)

    /** Human label for a period toggle value. */
    fun periodLabel(period: com.testlogon.android.data.rewards.LeaderboardPeriod): String =
        when (period) {
            com.testlogon.android.data.rewards.LeaderboardPeriod.ALL -> "All-time"
            com.testlogon.android.data.rewards.LeaderboardPeriod.MONTH -> "This month"
        }
}
