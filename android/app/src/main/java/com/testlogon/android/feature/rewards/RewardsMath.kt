package com.testlogon.android.feature.rewards

import com.testlogon.android.data.rewards.CatalogReward
import com.testlogon.android.data.rewards.ReferralStatus
import com.testlogon.android.data.rewards.ReferredUser
import com.testlogon.android.data.rewards.RewardKind
import java.math.BigDecimal
import java.math.RoundingMode

/**
 * Pure, Android-free math + formatting for the REFERRALS + REWARDS surface. Kept out of the ViewModels
 * so the redemption/affordability rules, referral status counting and money/points formatting are unit
 * testable without Compose/Hilt. Money is integer cents and points are integer everywhere; cents->dollars
 * uses BigDecimal so 1099 -> "10.99" exactly (no binary-float drift).
 */
object RewardsMath {

    // ---- Money / points formatting ----

    /** Format integer cents as a plain dollar string with 2 decimals (1099 -> "10.99"). No symbol. */
    fun formatCents(cents: Long): String =
        BigDecimal(cents).movePointLeft(2).setScale(2, RoundingMode.UNNECESSARY).toPlainString()

    /** Format integer cents as a USD currency amount with symbol (1099 -> "$10.99"). */
    fun formatCentsUsd(cents: Long): String = "$" + formatCents(cents)

    /** Format integer points with grouping ("1,250 pts"); singular "1 pt". */
    fun formatPoints(points: Long): String {
        val grouped = groupThousands(points)
        val unit = if (points == 1L) "pt" else "pts"
        return "$grouped $unit"
    }

    /** Group a non-negative long into 3-digit comma groups (1250 -> "1,250"). Negatives keep the sign. */
    fun groupThousands(value: Long): String {
        val neg = value < 0
        val digits = kotlin.math.abs(value).toString()
        val sb = StringBuilder()
        val n = digits.length
        for (i in 0 until n) {
            if (i > 0 && (n - i) % 3 == 0) sb.append(',')
            sb.append(digits[i])
        }
        return (if (neg) "-" else "") + sb.toString()
    }

    // ---- Redemption rules ----

    /** True when the wallet has at least [reward.costPoints] points to spend. Zero-cost is always redeemable. */
    fun canRedeem(reward: CatalogReward, points: Long): Boolean = points >= reward.costPoints

    /**
     * Points left AFTER redeeming [reward], floored at 0 (the client never shows a negative balance; a
     * server rejection is still the source of truth). Callers gate on [canRedeem] first.
     */
    fun pointsAfterRedeem(points: Long, reward: CatalogReward): Long =
        (points - reward.costPoints).coerceAtLeast(0L)

    // ---- Stock / inventory limits ----

    /**
     * Remaining stock for [reward]: null when UNLIMITED (no stock_limit set), otherwise
     * max(0, stock_limit - redeemed_count) so it never shows negative.
     */
    fun remainingStock(reward: CatalogReward): Long? {
        val limit = reward.stockLimit ?: return null
        return (limit - reward.redeemedCount).coerceAtLeast(0L)
    }

    /** True only when the reward is stock-limited AND has zero remaining. Unlimited is never out of stock. */
    fun isOutOfStock(reward: CatalogReward): Boolean = remainingStock(reward) == 0L

    /** Stable stock label: "Unlimited" / "Out of stock" / "N left". */
    fun stockLabel(reward: CatalogReward): String {
        val remaining = remainingStock(reward) ?: return "Unlimited"
        return if (remaining <= 0L) "Out of stock" else "$remaining left"
    }

    /** The subset of [catalog] the user can currently afford AND that is in stock, preserving order. */
    fun redeemableCatalog(catalog: List<CatalogReward>, points: Long): List<CatalogReward> =
        catalog.filter { canRedeem(it, points) && !isOutOfStock(it) }

    /** The subset of [catalog] the user CANNOT yet afford (locked), preserving order. */
    fun lockedCatalog(catalog: List<CatalogReward>, points: Long): List<CatalogReward> =
        catalog.filter { !canRedeem(it, points) }

    // ---- Catalog ordering (featured-first) ----

    /**
     * Canonical display order for the redeemable catalog: FEATURED items first, then by [CatalogReward.sortOrder]
     * ascending (missing = 0), then by name (case-insensitive) ascending. STABLE + PURE (returns a new list,
     * never mutates the input). Back-compat: when nothing is featured and all sort_orders are 0 this degrades to
     * a plain name sort, which is a harmless re-order of the existing catalog.
     */
    fun sortCatalog(catalog: List<CatalogReward>): List<CatalogReward> =
        catalog.sortedWith(
            compareByDescending<CatalogReward> { it.featured }
                .thenBy { it.sortOrder }
                .thenBy { it.name.trim().lowercase() },
        )

    /** Points still needed to afford [reward] (0 when already affordable). */
    fun pointsNeeded(reward: CatalogReward, points: Long): Long =
        (reward.costPoints - points).coerceAtLeast(0L)

    // ---- Referral status counting ----

    /** Count referred users in a given [status]. */
    fun statusCount(referrals: List<ReferredUser>, status: ReferralStatus): Int =
        referrals.count { it.status == status }

    /**
     * Total reward cents actually EARNED from the referral list = the sum of reward_cents on entries that
     * have reached the terminal REWARDED state (pending/qualified are not yet paid).
     */
    fun referralEarnedCents(referrals: List<ReferredUser>): Long =
        referrals.filter { it.status == ReferralStatus.REWARDED }.sumOf { it.rewardCents }

    /** Reward cents still PENDING = sum of reward_cents on non-rewarded (pending + qualified) entries. */
    fun referralPendingCents(referrals: List<ReferredUser>): Long =
        referrals.filter { it.status != ReferralStatus.REWARDED }.sumOf { it.rewardCents }

    // ---- Share text ----

    /**
     * The message body shared via ACTION_SEND / copied to clipboard. Includes the code + link (link
     * preferred, code as fallback) and, when known, the per-referral reward as an incentive. Pure String
     * build so it is JVM-testable; never includes cookies/PII.
     */
    fun referralShareText(code: String, link: String, rewardPerReferralCents: Long): String {
        val target = link.trim().ifBlank { code.trim() }
        val base = if (rewardPerReferralCents > 0) {
            "Join me and we both earn ${formatCentsUsd(rewardPerReferralCents)}."
        } else {
            "Join me on TestLogon."
        }
        val ref = when {
            link.isNotBlank() -> "Sign up: $target"
            code.isNotBlank() -> "Use my code $target when you sign up."
            else -> ""
        }
        return listOf(base, ref).filter { it.isNotBlank() }.joinToString(" ")
    }

    // ---- Labels (stable keys; UI localizes) ----

    /** True when the reward credits the USD cash wallet (used to surface the "credited to your wallet" note). */
    fun isCashReward(reward: CatalogReward): Boolean = reward.kind == RewardKind.CASH
}
