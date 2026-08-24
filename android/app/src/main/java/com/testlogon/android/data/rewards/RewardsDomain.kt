package com.testlogon.android.data.rewards

/**
 * Framework-free (Android/Compose-free) domain models for the REFERRALS + REWARDS surface, plus TOTAL
 * DTO -> domain mappers. Money is integer cents and points are integer everywhere. Absent optionals
 * default per the web contract, and enum-ish strings (referral status, reward kind, history type) are
 * normalized into sealed-ish Kotlin enums so the UI never branches on raw wire strings.
 *
 * [ReferralSummary.available] / [Rewards.available] are false when the read degraded (404 / undeployed),
 * so the screens can render an honest "coming soon" empty state rather than fabricating data.
 */

// ---- Referral ----

/** Referral status of a single referred user. Unknown/absent -> [PENDING] (most conservative). */
enum class ReferralStatus { PENDING, QUALIFIED, REWARDED }

data class ReferralSummary(
    val code: String,
    val link: String,
    val referredCount: Int,
    val qualifiedCount: Int,
    val pendingRewardCents: Long,
    val earnedRewardCents: Long,
    val rewardPerReferralCents: Long,
    val available: Boolean,
) {
    companion object {
        /** Honest "unavailable" summary for the degrade-on-404 empty state. */
        fun unavailable(): ReferralSummary = ReferralSummary(
            code = "",
            link = "",
            referredCount = 0,
            qualifiedCount = 0,
            pendingRewardCents = 0L,
            earnedRewardCents = 0L,
            rewardPerReferralCents = 0L,
            available = false,
        )
    }
}

data class ReferredUser(
    val id: String,
    val maskedName: String,
    val joinedTs: Long,
    val status: ReferralStatus,
    val rewardCents: Long,
)

// ---- Rewards ----

/** A catalog reward kind. Unknown/absent -> [PERK] (never mis-credits to cash). */
enum class RewardKind { CASH, PERK }

data class WayToEarn(
    val id: String,
    val title: String,
    val points: Long,
    val detail: String,
)

data class Rewards(
    val points: Long,
    val cashCents: Long,
    val lifetimePoints: Long,
    val waysToEarn: List<WayToEarn>,
    val available: Boolean,
) {
    companion object {
        fun unavailable(): Rewards = Rewards(
            points = 0L,
            cashCents = 0L,
            lifetimePoints = 0L,
            waysToEarn = emptyList(),
            available = false,
        )
    }
}

data class RewardsHistoryEntry(
    val ts: Long,
    val type: String,
    val description: String,
    val points: Long,
    val cashCents: Long,
    val status: String,
)

data class CatalogReward(
    val id: String,
    val name: String,
    val description: String,
    val costPoints: Long,
    val valueCents: Long,
    val kind: RewardKind,
)

/** Result of POST me/rewards/redeem (mutation). ok=true when the server accepted the redemption. */
data class RedeemResult(
    val ok: Boolean,
    val pointsRemaining: Long?,
    val reason: String?,
)

// ---- Mappers (DTO -> domain; TOTAL, absent optionals default) ----

private fun String?.toReferralStatus(): ReferralStatus = when (this?.trim()?.lowercase()) {
    "qualified" -> ReferralStatus.QUALIFIED
    "rewarded" -> ReferralStatus.REWARDED
    else -> ReferralStatus.PENDING
}

private fun String?.toRewardKind(): RewardKind = when (this?.trim()?.lowercase()) {
    "cash" -> RewardKind.CASH
    else -> RewardKind.PERK
}

internal fun ReferralSummaryDto.toDomain(): ReferralSummary = ReferralSummary(
    code = code?.trim().orEmpty(),
    link = link?.trim().orEmpty(),
    referredCount = referredCount ?: 0,
    qualifiedCount = qualifiedCount ?: 0,
    pendingRewardCents = pendingRewardCents ?: 0L,
    earnedRewardCents = earnedRewardCents ?: 0L,
    rewardPerReferralCents = rewardPerReferralCents ?: 0L,
    available = true,
)

internal fun ReferralEntryDto.toDomain(): ReferredUser? {
    val id = id?.trim()?.takeIf { it.isNotBlank() } ?: return null
    return ReferredUser(
        id = id,
        maskedName = maskedName?.trim()?.takeIf { it.isNotBlank() } ?: "Referred user",
        joinedTs = joinedTs ?: 0L,
        status = status.toReferralStatus(),
        rewardCents = rewardCents ?: 0L,
    )
}

internal fun ReferralListDto.toDomain(): List<ReferredUser> = referrals.mapNotNull { it.toDomain() }

internal fun RewardsSummaryDto.toDomain(): Rewards = Rewards(
    points = points ?: 0L,
    cashCents = cashCents ?: 0L,
    lifetimePoints = lifetimePoints ?: 0L,
    waysToEarn = waysToEarn.mapNotNull { it.toDomain() },
    available = true,
)

internal fun WayToEarnDto.toDomain(): WayToEarn? {
    val id = id?.trim()?.takeIf { it.isNotBlank() } ?: return null
    return WayToEarn(
        id = id,
        title = title?.trim()?.takeIf { it.isNotBlank() } ?: "Earn points",
        points = points ?: 0L,
        detail = detail?.trim().orEmpty(),
    )
}

internal fun RewardsHistoryDto.toDomain(): List<RewardsHistoryEntry> = entries.map { it.toDomain() }

internal fun RewardsHistoryEntryDto.toDomain(): RewardsHistoryEntry = RewardsHistoryEntry(
    ts = ts ?: 0L,
    type = type?.trim().orEmpty(),
    description = description?.trim()?.takeIf { it.isNotBlank() } ?: "Rewards activity",
    points = points ?: 0L,
    cashCents = cashCents ?: 0L,
    status = status?.trim().orEmpty(),
)

internal fun RewardsCatalogDto.toDomain(): List<CatalogReward> = rewards.mapNotNull { it.toDomain() }

internal fun CatalogRewardDto.toDomain(): CatalogReward? {
    val id = id?.trim()?.takeIf { it.isNotBlank() } ?: return null
    return CatalogReward(
        id = id,
        name = name?.trim()?.takeIf { it.isNotBlank() } ?: "Reward",
        description = description?.trim().orEmpty(),
        costPoints = costPoints ?: 0L,
        valueCents = valueCents ?: 0L,
        kind = kind.toRewardKind(),
    )
}

internal fun RedeemResultDto.toDomain(): RedeemResult = RedeemResult(
    ok = ok == true,
    pointsRemaining = pointsRemaining,
    reason = listOfNotNull(detail, error).firstOrNull { it.isNotBlank() },
)
