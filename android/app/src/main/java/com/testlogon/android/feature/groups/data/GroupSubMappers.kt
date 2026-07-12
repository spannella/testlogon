package com.testlogon.android.feature.groups.data

import com.testlogon.android.core.model.groups.Contributor
import com.testlogon.android.core.model.groups.GroupCampaign
import com.testlogon.android.core.model.groups.GroupCampaignStats
import com.testlogon.android.core.model.groups.GroupFundraiser
import com.testlogon.android.core.model.groups.TreasuryBalance
import com.testlogon.android.core.model.groups.TreasuryLedgerEntry
import com.testlogon.android.core.network.groups.ContributorDto
import com.testlogon.android.core.network.groups.GroupCampaignDto
import com.testlogon.android.core.network.groups.GroupCampaignStatsDto
import com.testlogon.android.core.network.groups.GroupFundraiserDto
import com.testlogon.android.core.network.groups.TreasuryBalanceDto
import com.testlogon.android.core.network.groups.TreasuryLedgerEntryDto

/**
 * AND-355 (sub-pages) - DTO -> domain mappers for the social-group SUB-PAGES (treasury / fundraising /
 * campaigns). Lives in the feature module which depends on BOTH core-network (DTOs) and core-model
 * (domain). Optional wire fields fall back to safe defaults so the UI never sees a null where it expects
 * a value.
 */

fun TreasuryBalanceDto.toDomain(): TreasuryBalance = TreasuryBalance(
    balanceCents = balanceCents,
    currency = currency.orEmpty(),
    totalContributedCents = totalContributedCents ?: 0L,
    totalDonatedCents = totalDonatedCents ?: 0L,
    totalSpentCents = totalSpentCents ?: 0L,
    fundraisingGoalCents = fundraisingGoalCents,
)

fun TreasuryLedgerEntryDto.toDomain(): TreasuryLedgerEntry = TreasuryLedgerEntry(
    entryId = entryId,
    amountCents = amountCents,
    currency = currency.orEmpty(),
    direction = direction.orEmpty(),
    reason = reason.orEmpty(),
    category = category.orEmpty(),
    actorUserId = actorUserId,
    actorDisplayName = actorDisplayName,
    referenceId = referenceId,
    createdAt = createdAt,
)

fun ContributorDto.toDomain(): Contributor = Contributor(
    userId = userId,
    displayName = displayName,
    totalContributedCents = totalContributedCents ?: 0L,
    contributionCount = contributionCount ?: 0,
)

fun GroupFundraiserDto.toDomain(): GroupFundraiser = GroupFundraiser(
    fundraiserId = fundraiserId,
    title = title,
    description = description,
    goalCents = goalCents,
    raisedCents = raisedCents ?: 0L,
    donationCount = donationCount ?: 0,
    currency = currency.orEmpty(),
    status = status.orEmpty(),
    coverImageUrl = coverImageUrl,
    createdAt = createdAt,
    endsAt = endsAt,
)

fun GroupCampaignDto.toDomain(): GroupCampaign = GroupCampaign(
    campaignId = campaignId,
    name = name,
    status = status.orEmpty(),
    dailyBudgetCents = dailyBudgetCents ?: 0L,
    lifetimeBudgetCents = lifetimeBudgetCents ?: 0L,
    spentCents = spentCents ?: 0L,
    impressions = impressions ?: 0L,
    clicks = clicks ?: 0L,
    creativeText = creativeText,
    creativeImageUrl = creativeImageUrl,
    createdAt = createdAt,
)

fun GroupCampaignStatsDto.toDomain(): GroupCampaignStats = GroupCampaignStats(
    campaignId = campaignId,
    impressions = impressions ?: 0L,
    clicks = clicks ?: 0L,
    ctr = ctr ?: 0.0,
    spentCents = spentCents ?: 0L,
    remainingCents = remainingCents ?: 0L,
    dailySpentCents = dailySpentCents ?: 0L,
    dailyBudgetCents = dailyBudgetCents ?: 0L,
    status = status.orEmpty(),
)
