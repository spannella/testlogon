package com.testlogon.android.feature.syndicates.campaign

/**
 * Framework-free domain models for the syndicate-advertising campaign DETAIL surface (web parity:
 * /syndicates/:syndicateId/campaigns/:campaignId). Money is *_cents (Int); times are EPOCH SECONDS.
 */

/** Known campaign statuses (raw string kept for any server-side value not enumerated here). */
object CampaignStatus {
    const val ACTIVE = "active"
    const val PAUSED = "paused"
    const val CANCELLED = "cancelled"
    const val COMPLETED = "completed"
}

/** One syndicate ad campaign with its creative + budget. */
data class SyndicateCampaign(
    val campaignId: String,
    val syndicateId: String,
    val name: String,
    val description: String,
    val status: String,
    val budgetCents: Int,
    val spentCents: Int,
    val remainingCents: Int,
    val creativeHeadline: String?,
    val creativeBody: String?,
    val creativeCtaText: String?,
    val creativeCtaUrl: String?,
) {
    /** Spend progress 0f..1f (0 when there is no budget). */
    val spendFraction: Float
        get() = if (budgetCents > 0) (spentCents.toFloat() / budgetCents).coerceIn(0f, 1f) else 0f

    val isActive: Boolean get() = status.equals(CampaignStatus.ACTIVE, ignoreCase = true)
    val isPaused: Boolean get() = status.equals(CampaignStatus.PAUSED, ignoreCase = true)

    /** True when status-changing / budget controls should be offered at all (terminal states hide them). */
    val isMutable: Boolean
        get() = !status.equals(CampaignStatus.CANCELLED, ignoreCase = true) &&
            !status.equals(CampaignStatus.COMPLETED, ignoreCase = true)
}

/** One day of analytics. */
data class CampaignDailyStat(
    val date: String,
    val impressions: Int,
    val clicks: Int,
    val spendCents: Int,
)

/** Campaign analytics: daily series + summary totals. */
data class CampaignAnalytics(
    val daily: List<CampaignDailyStat>,
    val impressions: Int,
    val clicks: Int,
    val ctr: Double,
    val spendCents: Int,
)
