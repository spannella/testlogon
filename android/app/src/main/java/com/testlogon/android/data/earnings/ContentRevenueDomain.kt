package com.testlogon.android.data.earnings

/**
 * AND-253 — framework-free per-content revenue domain models + total DTO -> domain mappers.
 * Money is integer cents end-to-end; `publishedAtEpochSec` is epoch seconds (0 == unknown).
 */
data class ContentRevenue(
    val contentId: String,
    val contentType: String,
    val title: String,
    val publishedAtEpochSec: Long,
    val tipsCents: Long,
    val unlocksCents: Long,
    val subscriptionsCents: Long,
    val adsCents: Long,
    val vodCents: Long,
    val totalCents: Long,
) {
    /** Display title with the spec fallback to the id when empty (FR-1). */
    val displayTitle: String get() = title.ifBlank { contentId }
}

data class ContentRevenuePage(
    val items: List<ContentRevenue>,
    val totalItems: Int,
    val totalRevenueCents: Long,
    val currency: String,
    val nextCursor: String?,
)

data class ContentRevenueSeriesPoint(
    val rawDate: String,
    val dateEpochDay: Long?,
    val tipsCents: Long,
    val unlocksCents: Long,
    val subscriptionsCents: Long,
    val adsCents: Long,
    val vodCents: Long,
    val totalCents: Long,
)

data class ContentRevenueDetail(
    val content: ContentRevenue,
    val currency: String,
    val series: List<ContentRevenueSeriesPoint>,
)

/** The known sort columns. `sort_by` is free-form server-side; we constrain to this superset. */
enum class RevenueSortKey(val apiValue: String) {
    TOTAL("total_cents"),
    TIPS("tips_cents"),
    UNLOCKS("unlocks_cents"),
    SUBSCRIPTIONS("subscriptions_cents"),
    ADS("ads_cents"),
    VOD("vod_cents"),
    PUBLISHED("published_at"),
}

enum class SortOrder(val apiValue: String) { ASC("asc"), DESC("desc") }

/** The active list query. Empty date strings are sent as null (no `from_date`/`to_date` keys). */
data class ContentRevenueQuery(
    val fromDate: String? = null,
    val toDate: String? = null,
    val contentType: String? = null,
    val sortBy: RevenueSortKey = RevenueSortKey.TOTAL,
    val sortOrder: SortOrder = SortOrder.DESC,
)

// ---- Mappers (DTO -> domain) ----

internal fun ContentRevenueItemDto.toDomain(): ContentRevenue = ContentRevenue(
    contentId = contentId,
    contentType = contentType,
    title = title,
    publishedAtEpochSec = publishedAt,
    tipsCents = tipsCents,
    unlocksCents = unlocksCents,
    subscriptionsCents = subscriptionsCents,
    adsCents = adsCents,
    vodCents = vodCents,
    totalCents = totalCents,
)

internal fun ContentRevenueListDto.toDomain(): ContentRevenuePage = ContentRevenuePage(
    items = items.map { it.toDomain() },
    totalItems = totalItems,
    totalRevenueCents = totalRevenueCents,
    currency = currency,
    nextCursor = nextCursor,
)

internal fun ContentRevenueTimeSeriesPointDto.toDomain(): ContentRevenueSeriesPoint =
    ContentRevenueSeriesPoint(
        rawDate = date,
        dateEpochDay = date.toEpochDayOrNull(),
        tipsCents = tipsCents,
        unlocksCents = unlocksCents,
        subscriptionsCents = subscriptionsCents,
        adsCents = adsCents,
        vodCents = vodCents,
        totalCents = totalCents,
    )

internal fun ContentRevenueDetailDto.toDomain(): ContentRevenueDetail = ContentRevenueDetail(
    content = ContentRevenue(
        contentId = contentId,
        contentType = contentType,
        title = title,
        publishedAtEpochSec = publishedAt,
        tipsCents = tipsCents,
        unlocksCents = unlocksCents,
        subscriptionsCents = subscriptionsCents,
        adsCents = adsCents,
        vodCents = vodCents,
        totalCents = totalCents,
    ),
    currency = currency,
    series = timeSeries.map { it.toDomain() },
)
