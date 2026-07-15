package com.testlogon.android.feature.ads.analytics.data

import com.testlogon.android.core.model.ads.AdAnalyticsSummary
import com.testlogon.android.core.model.ads.AdBreakdownEntry
import com.testlogon.android.core.model.ads.AdTimeSeriesPoint
import com.testlogon.android.core.network.ads.AdAnalyticsSummaryDto
import com.testlogon.android.core.network.ads.AdBreakdownEntryDto
import com.testlogon.android.core.network.ads.AdTimeSeriesPointDto

/**
 * AND-368 - DTO to domain mappers for the READ-ONLY ad-analytics dashboard.
 *
 * PLACEMENT: core-model has no dependency on core-network DTOs (and core-network has no domain dep), so these
 * bridging mappers live in the feature, which depends on BOTH (mirrors AND-367 AdsBillingMappers). All
 * *_cents stay Long (overflow-proof); every *_pct is kept AS-IS (it is already a percentage - NEVER multiply
 * by 100); counts stay Long. The breakdown campaign-name join is applied in the repository, not here.
 */

/** Maps the KPI summary DTO to [AdAnalyticsSummary]. Every *_pct is carried through unchanged. */
fun AdAnalyticsSummaryDto.toDomain(): AdAnalyticsSummary = AdAnalyticsSummary(
    impressions = impressions,
    clicks = clicks,
    spendCents = spendCents,
    ctrPct = ctrPct,
    cpcCents = cpcCents,
    cpaCents = cpaCents,
    effectiveCpmCents = effectiveCpmCents,
    conversions = conversions,
    conversionRevenueCents = conversionRevenueCents,
    roas = roas,
    uniqueUsers = uniqueUsers,
    completes = completes,
    skips = skips,
    completionRatePct = completionRatePct,
    impressionsChangePct = impressionsChangePct,
    clicksChangePct = clicksChangePct,
    spendChangePct = spendChangePct,
    ctrChangePct = ctrChangePct,
    cpcChangePct = cpcChangePct,
    cpaChangePct = cpaChangePct,
    effectiveCpmChangePct = effectiveCpmChangePct,
    completionRateChangePct = completionRateChangePct,
)

/** Maps one time-series point DTO to [AdTimeSeriesPoint] (date or ts preserved as sent). */
fun AdTimeSeriesPointDto.toDomain(): AdTimeSeriesPoint = AdTimeSeriesPoint(
    date = date,
    ts = ts,
    impressions = impressions,
    clicks = clicks,
    spendCents = spendCents,
)

/**
 * Maps one breakdown DTO row to [AdBreakdownEntry]. The grouping key prefers `key` then falls back to
 * `dimension_value`. [campaignName] is left null here; the repository fills it from the campaign list.
 */
fun AdBreakdownEntryDto.toDomain(): AdBreakdownEntry = AdBreakdownEntry(
    key = key ?: dimensionValue,
    campaignName = null,
    impressions = impressions,
    clicks = clicks,
    spendCents = spendCents,
    ctrPct = ctrPct,
)

/** ADV-503 - maps the ROAS report DTO to [AdRoasReport] (totals + per-campaign rows). */
fun com.testlogon.android.core.network.ads.AdRoasReportDto.toDomain(): com.testlogon.android.core.model.ads.AdRoasReport =
    com.testlogon.android.core.model.ads.AdRoasReport(
        accountId = accountId,
        days = days,
        totals = totals.toDomain(),
        campaigns = campaigns.map { it.toDomain() },
    )

/** ADV-503 - maps one ROAS row DTO to [AdCampaignRoas]. Every *_cents stays Long; *Pct/roas kept as-is. */
fun com.testlogon.android.core.network.ads.AdCampaignRoasDto.toDomain(): com.testlogon.android.core.model.ads.AdCampaignRoas =
    com.testlogon.android.core.model.ads.AdCampaignRoas(
        campaignId = campaignId,
        impressions = impressions,
        clicks = clicks,
        conversions = conversions,
        spendCents = spendCents,
        conversionValueCents = conversionValueCents,
        ctrPct = ctrPct,
        cpaCents = cpaCents,
        roas = roas,
    )
