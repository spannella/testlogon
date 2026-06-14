package com.testlogon.android.data.analytics

import com.testlogon.android.data.earnings.toEpochDayOrNull

/**
 * AND-399 - framework-free analytics-dashboard domain models + DTO -> domain mappers. NO Compose /
 * android / java.time imports (the date helper toEpochDayOrNull is the shared JVM-safe one from
 * AND-252). All values arrive already computed by the backend; mappers only restructure and tag the
 * chart-point epoch day. Units are pinned per the spec (sections 5 / 16):
 *  - revenue / *_cents -> integer cents (Long)
 *  - watch_time_seconds -> integer seconds (Long)
 *  - top-content engagement_rate -> 0..1 fraction
 *  - audience percentage -> 0..100 number (NOT scaled)
 */

/** The four overview KPI tiles plus the optional currency. Revenue is integer cents. */
data class AnalyticsOverview(
    val periodViews: Long,
    val periodRevenueCents: Long,
    val periodNewSubscribers: Long,
    val totalSubscribers: Long,
    val currency: String,
)

/** One views/watch-time point. [dateEpochDay] is null for non-ISO (weekly/monthly) labels. */
data class ViewsPoint(
    val rawDate: String,
    val dateEpochDay: Long?,
    val views: Long,
    val uniqueViewers: Long,
    val watchTimeSeconds: Long,
)

/** One subscriber-growth point. */
data class SubscribersPoint(
    val rawDate: String,
    val dateEpochDay: Long?,
    val new: Long,
    val churned: Long,
    val net: Long,
    val total: Long,
)

/** A top-content breakdown row. [engagementRate] is a 0..1 fraction. */
data class TopContentRow(
    val contentId: String,
    val contentType: String,
    val title: String,
    val views: Long,
    val revenueCents: Long,
    val engagementRate: Double,
)

/** An audience breakdown row (country or device). [percentage] is a 0..100 number. */
data class AudienceRow(
    val label: String,
    val viewers: Long,
    val percentage: Double,
)

/**
 * The assembled dashboard. Any of the fan-out sections may be absent (partial success - section 7):
 * a null section means that endpoint failed and its UI surfaces an inline error/retry; the page still
 * renders from whichever sections succeeded.
 */
data class AnalyticsDashboard(
    val overview: AnalyticsOverview?,
    val views: List<ViewsPoint>,
    val subscribers: List<SubscribersPoint>,
    val topContent: List<TopContentRow>,
    val audienceCountries: List<AudienceRow>,
    val audienceDevices: List<AudienceRow>,
    /** True when the audience fan-out call failed (so the section can show inline error + retry). */
    val audienceFailed: Boolean = false,
    /** True when the top-content fan-out call failed. */
    val topContentFailed: Boolean = false,
) {
    /**
     * No KPI signal AND no series AND no rows -> the "no analytics in range" empty state. A dashboard
     * that parsed to all-zero / empty arrays is Empty, not Error (spec section 5.7 / AC-3).
     */
    val isEmpty: Boolean
        get() {
            val overviewEmpty = overview == null ||
                (overview.periodViews == 0L && overview.periodRevenueCents == 0L &&
                    overview.periodNewSubscribers == 0L && overview.totalSubscribers == 0L)
            return overviewEmpty && views.isEmpty() && subscribers.isEmpty() &&
                topContent.isEmpty() && audienceCountries.isEmpty() && audienceDevices.isEmpty()
        }

    companion object {
        val EMPTY = AnalyticsDashboard(
            overview = null,
            views = emptyList(),
            subscribers = emptyList(),
            topContent = emptyList(),
            audienceCountries = emptyList(),
            audienceDevices = emptyList(),
        )
    }
}

// ---- Mappers (DTO -> domain). Absent optionals already default per the backend schema. ----

internal fun AnalyticsOverviewDto.toDomain(): AnalyticsOverview = AnalyticsOverview(
    periodViews = periodViews,
    periodRevenueCents = periodRevenueCents,
    periodNewSubscribers = periodNewSubscribers,
    totalSubscribers = totalSubscribers,
    currency = currency.ifBlank { "USD" },
)

internal fun AnalyticsViewsPointDto.toDomain(): ViewsPoint = ViewsPoint(
    rawDate = date,
    dateEpochDay = date.toEpochDayOrNull(),
    views = views,
    uniqueViewers = uniqueViewers,
    watchTimeSeconds = watchTimeSeconds,
)

internal fun AnalyticsViewsDto.toDomain(): List<ViewsPoint> = timeSeries.map { it.toDomain() }

internal fun AnalyticsSubscribersPointDto.toDomain(): SubscribersPoint = SubscribersPoint(
    rawDate = date,
    dateEpochDay = date.toEpochDayOrNull(),
    new = new,
    churned = churned,
    net = net,
    total = total,
)

internal fun AnalyticsSubscribersDto.toDomain(): List<SubscribersPoint> = timeSeries.map { it.toDomain() }

internal fun AnalyticsTopContentItemDto.toDomain(): TopContentRow = TopContentRow(
    contentId = contentId,
    contentType = contentType,
    title = title,
    views = views,
    revenueCents = revenueCents,
    engagementRate = engagementRate,
)

internal fun AnalyticsTopContentDto.toDomain(): List<TopContentRow> = items.map { it.toDomain() }

internal fun AnalyticsCountryDto.toAudienceRow(): AudienceRow = AudienceRow(
    label = name.ifBlank { code },
    viewers = viewers,
    percentage = percentage,
)

internal fun AnalyticsDeviceDto.toAudienceRow(): AudienceRow = AudienceRow(
    label = type,
    viewers = viewers,
    percentage = percentage,
)
