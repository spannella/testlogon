package com.testlogon.android.core.model.ads

import java.time.LocalDate
import java.time.format.DateTimeFormatter

/**
 * AND-368 - domain models for the READ-ONLY ad-analytics dashboard (KPI summary + daily time series +
 * dimension breakdown over a selectable date range).
 *
 * core-model has NO Moshi dependency: these are plain domain types. The transport DTOs (core-network
 * AdAnalyticsSummaryDto / AdTimeSeriesPointDto / AdBreakdownEntryDto) are mapped to these by the feature-layer
 * AdAnalyticsMappers (core-model cannot see core-network's DTOs).
 *
 * MONEY: every monetary field is a flat *_cents [Long] (overflow-proof). Display currency is fixed to USD
 * (no currency field on the wire) and formatted via core-model formatCents.
 * RATES: every *Pct is ALREADY a percentage [Double] (e.g. 1.23 == 1.23 percent) - the mapper keeps it
 * as-is and NEVER multiplies by 100.
 * COUNTS: impressions / clicks / completes / skips are [Long]. There is NO cpc and NO conversions field.
 */

/**
 * The KPI summary for an account over a date range. [impressions] / [clicks] / [spendCents] / [ctrPct] are
 * the headline figures (non-null); the rest are optional. Each `*ChangePct` is a period-over-period delta
 * percentage (kept as-is).
 */
data class AdAnalyticsSummary(
    val impressions: Long,
    val clicks: Long,
    val spendCents: Long,
    val ctrPct: Double,
    val cpaCents: Long? = null,
    val effectiveCpmCents: Long? = null,
    val completes: Long? = null,
    val skips: Long? = null,
    val completionRatePct: Double? = null,
    val impressionsChangePct: Double? = null,
    val clicksChangePct: Double? = null,
    val spendChangePct: Double? = null,
    val ctrChangePct: Double? = null,
    val cpaChangePct: Double? = null,
    val effectiveCpmChangePct: Double? = null,
    val completionRateChangePct: Double? = null,
)

/**
 * One daily-bucketed time-series point. The bucket is identified by [date] (YYYY-MM-DD string) or [ts]
 * (epoch Long); whichever the server sent is kept. [impressions] / [clicks] / [spendCents] are non-null.
 */
data class AdTimeSeriesPoint(
    val date: String? = null,
    val ts: Long? = null,
    val impressions: Long,
    val clicks: Long,
    val spendCents: Long,
)

/**
 * One breakdown row for a dimension. [key] is the grouping value (creative id / surface / targeting token).
 * [campaignName] is joined from the AND-363 campaign list (null when no name is known). [ctrPct] is ALREADY
 * a percentage (kept as-is).
 */
data class AdBreakdownEntry(
    val key: String? = null,
    val campaignName: String? = null,
    val impressions: Long,
    val clicks: Long,
    val spendCents: Long,
    val ctrPct: Double? = null,
)

/**
 * AND-368 - the dimension the breakdown groups by. The wire token is the lowercase [wire] value sent as the
 * `dimension` query param. CREATIVE is the default surface for the dashboard.
 */
enum class BreakdownDimension(val wire: String) {
    CREATIVE("creative"),
    SURFACE("surface"),
    TARGETING("targeting"),
}

/**
 * AND-368 - the selectable date-range presets. LAST_28 is the DEFAULT. [days] is the inclusive window length;
 * the range is computed by [DateRange.of] relative to a passed-in `today` (a clock seam so tests are
 * deterministic - there is no implicit Date.now in the pure helper).
 */
enum class DateRangePreset(val days: Int) {
    LAST_7(7),
    LAST_28(28),
    LAST_90(90),
}

/**
 * AND-368 - a concrete `from`..`to` window as YYYY-MM-DD strings (the format the wire expects). [from] is the
 * earliest day (inclusive), [to] is `today` (inclusive). Kept as plain strings so the repo passes them
 * straight to the query without re-formatting.
 */
data class DateRange(val from: String, val to: String) {
    companion object {
        private val WIRE_FORMAT: DateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd")

        /**
         * Computes the `from`..`to` window for [preset] ending on [today] (inclusive). A 7-day window ending
         * 2026-06-09 spans 2026-06-03..2026-06-09 (today minus 6 days through today). The `today` is passed
         * in (NOT read from a system clock) so the helper stays pure and unit-testable.
         */
        fun of(preset: DateRangePreset, today: LocalDate): DateRange {
            val from = today.minusDays((preset.days - 1).toLong())
            return DateRange(from = from.format(WIRE_FORMAT), to = today.format(WIRE_FORMAT))
        }
    }
}

/**
 * ADV-501/503 - ROAS (return on ad spend) report for an account: per-account [totals] plus a
 * per-[campaigns] breakdown. Sourced from the ad_billing ledger (GET /ui/ads/roas). MONEY = *_cents Long;
 * *Pct already a percentage; [roas] is a ratio (conversion value / spend).
 */
data class AdRoasReport(
    val accountId: String? = null,
    val days: Int? = null,
    val totals: AdCampaignRoas,
    val campaigns: List<AdCampaignRoas> = emptyList(),
)

/** ADV-501/503 - ROAS figures for one campaign (or the account total, [campaignId] null). */
data class AdCampaignRoas(
    val campaignId: String? = null,
    val impressions: Long = 0,
    val clicks: Long = 0,
    val conversions: Long = 0,
    val spendCents: Long = 0,
    val conversionValueCents: Long = 0,
    val ctrPct: Double = 0.0,
    val cpaCents: Double = 0.0,
    val roas: Double = 0.0,
)
