package com.testlogon.android.feature.rewards

import com.testlogon.android.data.rewards.RewardsStatus

/**
 * Pure, dependency-free (Android/Compose/Hilt-free) math for the REWARDS STATUS / loyalty TIER LEVELS
 * surface: a loyalty membership ladder driven by LIFETIME reward points. This is DISTINCT from the
 * maker/taker FEE tiers (see [com.testlogon.android.feature.feetiers.FeeTierMath]): those key off
 * trading VOLUME and set trading fees; THESE key off LIFETIME reward points and set a points-earning
 * multiplier + membership perks.
 *
 * This is an EXACT mirror of the web client's frontend/src/lib/statusTiers.ts — same [STATUS_TIERS]
 * table (name / threshold / multiplier bps / perks), same current-tier / next-tier / progress rules,
 * same authoritative-preferred resolution. Do NOT change the table here without changing both.
 *
 * CONVENTIONS: points are WHOLE integers; [StatusTier.multiplierBps] is in BASIS POINTS where
 * 10000 = 1.0x. The table is ascending by [StatusTier.thresholdPoints]. Trivially unit-testable
 * (see StatusTierMathTest).
 */
object StatusTierMath {

    /** One rung of the loyalty status ladder. */
    data class StatusTier(
        /** Stable machine id. */
        val id: String,
        /** Display name. */
        val name: String,
        /** LIFETIME points required to reach this tier. */
        val thresholdPoints: Long,
        /** Points-earning multiplier in basis points (10000 = 1.0x). */
        val multiplierBps: Int,
        /** Membership perks unlocked at this tier. */
        val perks: List<String>,
    )

    /**
     * Canonical loyalty status ladder — MUST stay in sync with the web client
     * (frontend/src/lib/statusTiers.ts) and the optional authoritative GET me/rewards/status. Ascending
     * by threshold; the first entry (0 pts) is the floor every account is at.
     */
    val STATUS_TIERS: List<StatusTier> = listOf(
        StatusTier(
            id = "member",
            name = "Member",
            thresholdPoints = 0L,
            multiplierBps = 10000,
            perks = listOf("Base points earning"),
        ),
        StatusTier(
            id = "bronze",
            name = "Bronze",
            thresholdPoints = 1000L,
            multiplierBps = 10500,
            perks = listOf("5% bonus points", "Bronze badge"),
        ),
        StatusTier(
            id = "silver",
            name = "Silver",
            thresholdPoints = 5000L,
            multiplierBps = 11000,
            perks = listOf("10% bonus points", "Priority support"),
        ),
        StatusTier(
            id = "gold",
            name = "Gold",
            thresholdPoints = 25000L,
            multiplierBps = 12500,
            perks = listOf("25% bonus points", "+5% referral bonus", "Gold badge"),
        ),
        StatusTier(
            id = "platinum",
            name = "Platinum",
            thresholdPoints = 100000L,
            multiplierBps = 15000,
            perks = listOf("50% bonus points", "Reduced fees", "Priority withdrawals"),
        ),
        StatusTier(
            id = "diamond",
            name = "Diamond",
            thresholdPoints = 500000L,
            multiplierBps = 20000,
            perks = listOf("2x points", "All perks", "Concierge support"),
        ),
    )

    /** Coerce any input to a safe, whole, non-negative lifetime-points count. */
    private fun safePoints(lifetimePoints: Long): Long = lifetimePoints.coerceAtLeast(0L)

    /**
     * The current status tier for a lifetime-points balance: the highest tier whose threshold is <= the
     * balance. Always returns a tier (Member at the floor); guards 0 / negative input.
     */
    fun statusTierForPoints(lifetimePoints: Long): StatusTier {
        val pts = safePoints(lifetimePoints)
        var current = STATUS_TIERS.first()
        for (t in STATUS_TIERS) {
            if (pts >= t.thresholdPoints) current = t else break
        }
        return current
    }

    /** The next tier above the given one, or null when already at the top tier. */
    fun nextStatusTier(tier: StatusTier): StatusTier? = nextStatusTier(tier.id)

    /** The next tier above the tier with the given id, or null when already at (or past) the top tier. */
    fun nextStatusTier(tierId: String): StatusTier? {
        val idx = STATUS_TIERS.indexOfFirst { it.id == tierId }
        if (idx < 0 || idx >= STATUS_TIERS.size - 1) return null
        return STATUS_TIERS[idx + 1]
    }

    /**
     * Whole lifetime points still needed to reach the next tier, or 0 when already at the top tier
     * (or somehow past the last threshold). Never negative.
     */
    fun pointsToNextTier(lifetimePoints: Long): Long {
        val pts = safePoints(lifetimePoints)
        val next = nextStatusTier(statusTierForPoints(pts)) ?: return 0L
        return (next.thresholdPoints - pts).coerceAtLeast(0L)
    }

    /**
     * Progress from the CURRENT tier's threshold toward the NEXT tier's threshold, as a fraction in
     * [0, 1]. Returns 1.0 at (or above) the top tier. Never throws / never NaN.
     */
    fun progressToNextFraction(lifetimePoints: Long): Float {
        val pts = safePoints(lifetimePoints)
        val current = statusTierForPoints(pts)
        val next = nextStatusTier(current) ?: return 1f
        val span = next.thresholdPoints - current.thresholdPoints
        if (span <= 0L) return 1f
        val gained = pts - current.thresholdPoints
        val frac = gained.toDouble() / span.toDouble()
        return when {
            frac <= 0.0 -> 0f
            frac >= 1.0 -> 1f
            else -> frac.toFloat()
        }
    }

    /**
     * Human label for a basis-points multiplier, e.g. 12500 -> "1.25x", 10000 -> "1x", 20000 -> "2x".
     * Trims trailing zeros; guards non-positive input -> "1x".
     */
    fun multiplierLabel(bps: Int): String {
        val safe = if (bps > 0) bps else 10000
        // Whole and fractional parts of (bps / 10000) using integer math (no locale / float formatting).
        val whole = safe / 10000
        val frac = safe % 10000 // 0..9999, i.e. ten-thousandths
        if (frac == 0) return "${whole}x"
        // Two-decimal precision, then trim trailing zeros: 12500 -> "25" -> "1.25x"; 15000 -> "50" -> "1.5x".
        val hundredths = frac / 100 // 0..99
        val s = if (hundredths % 10 == 0) "${whole}.${hundredths / 10}" else "${whole}.${twoDigits(hundredths)}"
        return "${s}x"
    }

    private fun twoDigits(v: Int): String = if (v < 10) "0$v" else "$v"

    /** Where the resolved status view came from. */
    enum class Source { AUTHORITATIVE, ESTIMATED }

    /** A resolved status view for the screen, from either source. Points are whole; multiplier is bps. */
    data class ResolvedStatus(
        val tierId: String,
        val name: String,
        val lifetimePoints: Long,
        val multiplierBps: Int,
        val perks: List<String>,
        val nextName: String?,
        val nextThreshold: Long?,
        val pointsToNext: Long,
        val progressFraction: Float,
        val source: Source,
    ) {
        /** True when the numbers came from the authoritative backend read. */
        val isAuthoritative: Boolean get() = source == Source.AUTHORITATIVE

        /** True when the account is at the top of the ladder (no next tier). */
        val isTopTier: Boolean get() = nextName == null
    }

    /**
     * Resolve the status view. Prefers the AUTHORITATIVE me/rewards/status payload when present & sane
     * (available, a non-blank name, a positive multiplier); otherwise computes it CLIENT-SIDE from the
     * [lifetimePoints] balance against [STATUS_TIERS]. Never throws.
     */
    fun resolveStatus(
        lifetimePoints: Long,
        authoritative: RewardsStatus? = null,
    ): ResolvedStatus {
        if (authoritative != null &&
            authoritative.available &&
            authoritative.name.isNotBlank() &&
            authoritative.pointsMultiplierBps > 0
        ) {
            val lp = safePoints(authoritative.lifetimePoints)
            val nextThreshold = authoritative.nextThresholdPoints?.let { safePoints(it) }
            return ResolvedStatus(
                tierId = authoritative.tierId.ifBlank { statusTierForPoints(lp).id },
                name = authoritative.name,
                lifetimePoints = lp,
                multiplierBps = authoritative.pointsMultiplierBps,
                perks = authoritative.perks,
                nextName = authoritative.nextName,
                nextThreshold = nextThreshold,
                pointsToNext = nextThreshold?.let { (it - lp).coerceAtLeast(0L) } ?: 0L,
                progressFraction = progressToNextFraction(lp),
                source = Source.AUTHORITATIVE,
            )
        }

        val lp = safePoints(lifetimePoints)
        val current = statusTierForPoints(lp)
        val next = nextStatusTier(current)
        return ResolvedStatus(
            tierId = current.id,
            name = current.name,
            lifetimePoints = lp,
            multiplierBps = current.multiplierBps,
            perks = current.perks,
            nextName = next?.name,
            nextThreshold = next?.thresholdPoints,
            pointsToNext = pointsToNextTier(lp),
            progressFraction = progressToNextFraction(lp),
            source = Source.ESTIMATED,
        )
    }
}
