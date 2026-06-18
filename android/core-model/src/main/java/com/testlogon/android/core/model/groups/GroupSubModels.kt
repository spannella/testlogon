package com.testlogon.android.core.model.groups

/**
 * AND-355 (sub-pages) - plain domain models for the social-group SUB-PAGES: treasury, fundraising,
 * group advertising campaigns. core-model has NO Moshi dependency; the bridging DTO -> domain mappers
 * live in the feature module (which depends on both core-model and core-network).
 *
 * All money is in integer cents. Timestamps are epoch SECONDS (the wire uses numeric epoch seconds);
 * the UI formats them with SimpleDateFormat (NO java.time).
 */

/** The group treasury balance + roll-ups. */
data class TreasuryBalance(
    val balanceCents: Long,
    val currency: String,
    val totalContributedCents: Long,
    val totalDonatedCents: Long,
    val totalSpentCents: Long,
    val fundraisingGoalCents: Long?,
)

/** One credit/debit row in the treasury ledger. */
data class TreasuryLedgerEntry(
    val entryId: String,
    val amountCents: Long,
    val currency: String,
    val direction: String,
    val reason: String,
    val category: String,
    val actorUserId: String?,
    val actorDisplayName: String?,
    val referenceId: String?,
    val createdAt: Long?,
) {
    /** True when this row represents money leaving the treasury. */
    val isDebit: Boolean get() = direction.equals("debit", ignoreCase = true)
}

/** One contributor roll-up row. */
data class Contributor(
    val userId: String,
    val displayName: String?,
    val totalContributedCents: Long,
    val contributionCount: Int,
)

/** One group fundraiser. */
data class GroupFundraiser(
    val fundraiserId: String,
    val title: String,
    val description: String?,
    val goalCents: Long?,
    val raisedCents: Long,
    val donationCount: Int,
    val currency: String,
    val status: String,
    val coverImageUrl: String?,
    val createdAt: Long?,
    val endsAt: Long?,
) {
    /** Progress toward the goal in [0f,1f], or null when there is no goal. */
    val progress: Float?
        get() {
            val goal = goalCents ?: return null
            if (goal <= 0L) return null
            return (raisedCents.toFloat() / goal.toFloat()).coerceIn(0f, 1f)
        }
}

/** One group advertising campaign. */
data class GroupCampaign(
    val campaignId: String,
    val name: String,
    val status: String,
    val dailyBudgetCents: Long,
    val lifetimeBudgetCents: Long,
    val spentCents: Long,
    val impressions: Long,
    val clicks: Long,
    val creativeText: String?,
    val creativeImageUrl: String?,
    val createdAt: Long?,
)

/** Per-campaign performance stats. */
data class GroupCampaignStats(
    val campaignId: String,
    val impressions: Long,
    val clicks: Long,
    val ctr: Double,
    val spentCents: Long,
    val remainingCents: Long,
    val dailySpentCents: Long,
    val dailyBudgetCents: Long,
    val status: String,
)
