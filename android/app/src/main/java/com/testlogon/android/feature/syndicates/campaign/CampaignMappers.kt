package com.testlogon.android.feature.syndicates.campaign

import com.testlogon.android.core.network.syndicates.SyndicateCampaignAnalyticsOut
import com.testlogon.android.core.network.syndicates.SyndicateCampaignDailyStatsOut
import com.testlogon.android.core.network.syndicates.SyndicateCampaignOut

/** DTO -> domain mappers for the syndicate-advertising campaign surface (in :app). */

fun SyndicateCampaignOut.toDomain(fallbackSyndicateId: String): SyndicateCampaign {
    val c = creative.orEmpty()
    return SyndicateCampaign(
        campaignId = campaignId,
        syndicateId = syndicateId?.takeIf { it.isNotBlank() } ?: fallbackSyndicateId,
        name = name.orEmpty(),
        description = description.orEmpty(),
        status = status?.takeIf { it.isNotBlank() } ?: "unknown",
        budgetCents = budgetCents,
        spentCents = spentCents,
        remainingCents = remainingCents,
        creativeHeadline = c["headline"],
        creativeBody = c["body"],
        creativeCtaText = c["cta_text"],
        creativeCtaUrl = c["cta_url"],
    )
}

fun SyndicateCampaignDailyStatsOut.toDomain(): CampaignDailyStat = CampaignDailyStat(
    date = date,
    impressions = impressions,
    clicks = clicks,
    spendCents = spendCents,
)

fun SyndicateCampaignAnalyticsOut.toDomain(): CampaignAnalytics {
    val t = totals.orEmpty()
    return CampaignAnalytics(
        daily = daily.map { it.toDomain() },
        impressions = (t["impressions"] ?: 0.0).toInt(),
        clicks = (t["clicks"] ?: 0.0).toInt(),
        ctr = t["ctr"] ?: 0.0,
        spendCents = (t["spend_cents"] ?: 0.0).toInt(),
    )
}
