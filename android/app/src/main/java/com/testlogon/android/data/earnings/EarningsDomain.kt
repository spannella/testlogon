package com.testlogon.android.data.earnings

/**
 * AND-251 — framework-free earnings domain models + total DTO -> domain mappers.
 *
 * Conventions (matching this codebase + the spec gotchas):
 *  - Money is integer cents + ISO-4217 currency (the backend's `*_cents`). No BigDecimal/float here;
 *    the earnings surface is uniformly cents.
 *  - Series bucket dates are kept as a raw label String plus a parsed epoch-DAY Long (NOT
 *    java.time.LocalDate, which is API-26+) so this stays JVM-unit-testable. Non-parseable
 *    week/month labels (e.g. "2026-W18", "2026-05") degrade to dateEpochDay == null with the raw
 *    label preserved; mapping never throws.
 *  - Enums use an OTHER fallback for forward compatibility.
 *
 * Mapping is TOTAL: absent optionals default per the backend schema, unknown categories -> OTHER.
 */

/** Integer cents + ISO-4217 currency. */
data class EarningsMoney(val cents: Long, val currency: String)

data class EarningsSummary(
    val total: EarningsMoney,
    val transactionCount: Int,
    val breakdown: EarningsBreakdown,
    val series: List<EarningsSeriesPoint>,
)

data class EarningsBreakdown(
    val subscriptions: Long,
    val tips: Long,
    val unlocks: Long,
    val vodPurchases: Long,
    val other: Long,
    val currencyCode: String,
)

/**
 * One time-series bucket. [dateEpochDay] is days-since-1970 (null when [rawDate] is not a parseable
 * YYYY-MM-DD label); [rawDate] is always the verbatim backend label for display fallback.
 */
data class EarningsSeriesPoint(
    val rawDate: String,
    val dateEpochDay: Long?,
    val totalCents: Long,
    val tipsCents: Long,
    val subscriptionsCents: Long,
    val unlocksCents: Long,
    val vodPurchasesCents: Long,
    val otherCents: Long,
)

data class EarningsQuickStats(
    val today: EarningsMoney,
    val thisWeek: EarningsMoney,
    val thisMonth: EarningsMoney,
    val allTime: EarningsMoney,
    val pendingPayout: EarningsMoney,
)

enum class EarningsCategory {
    SUBSCRIPTION,
    TIP,
    UNLOCK,
    VOD_PURCHASE,
    OTHER,
    ;

    companion object {
        /** Lenient mapping of the free-form wire `category`; anything unknown -> [OTHER]. */
        fun from(raw: String?): EarningsCategory = when (raw?.lowercase()) {
            "subscription", "subscriptions" -> SUBSCRIPTION
            "tip", "tips" -> TIP
            "unlock", "unlocks" -> UNLOCK
            "vod_purchase", "vod_purchases", "vod" -> VOD_PURCHASE
            else -> OTHER
        }
    }
}

data class EarningsTransaction(
    val entryId: String,
    val timestampEpochSeconds: Long,
    val amount: EarningsMoney,
    val reason: String,
    val category: EarningsCategory,
    val rawCategory: String,
)

data class EarningsTransactionsPage(
    val items: List<EarningsTransaction>,
    val nextCursor: String?,
)

// ---- Mappers (DTO -> domain) ----

internal fun EarningsSummaryDto.toDomain(): EarningsSummary = EarningsSummary(
    total = EarningsMoney(totalCents, currency),
    transactionCount = transactionCount,
    breakdown = breakdown.toDomain(currency),
    series = timeSeries.map { it.toDomain() },
)

internal fun EarningsBreakdownDto.toDomain(currency: String): EarningsBreakdown = EarningsBreakdown(
    subscriptions = subscriptions,
    tips = tips,
    unlocks = unlocks,
    vodPurchases = vodPurchases,
    other = other,
    currencyCode = currency,
)

internal fun TimeSeriesPointDto.toDomain(): EarningsSeriesPoint = EarningsSeriesPoint(
    rawDate = date,
    dateEpochDay = date.toEpochDayOrNull(),
    totalCents = total,
    tipsCents = tips,
    subscriptionsCents = subscriptions,
    unlocksCents = unlocks,
    vodPurchasesCents = vodPurchases,
    otherCents = other,
)

internal fun EarningsQuickStatsDto.toDomain(): EarningsQuickStats = EarningsQuickStats(
    today = EarningsMoney(todayCents, currency),
    thisWeek = EarningsMoney(thisWeekCents, currency),
    thisMonth = EarningsMoney(thisMonthCents, currency),
    allTime = EarningsMoney(allTimeCents, currency),
    pendingPayout = EarningsMoney(pendingPayoutCents, currency),
)

internal fun EarningsTransactionDto.toDomain(): EarningsTransaction = EarningsTransaction(
    entryId = entryId,
    timestampEpochSeconds = ts,
    amount = EarningsMoney(amountCents, currency),
    reason = reason,
    category = EarningsCategory.from(category),
    rawCategory = category,
)

internal fun EarningsTransactionsDto.toDomain(): EarningsTransactionsPage = EarningsTransactionsPage(
    items = items.map { it.toDomain() },
    nextCursor = nextCursor,
)

/**
 * Parses a strict `YYYY-MM-DD` label into days-since-1970 (proleptic Gregorian), or null on any
 * failure (e.g. weekly "2026-W18" / monthly "2026-05" labels). No java.time -> safe in JVM-unit-tested
 * code and on API < 26.
 */
internal fun String?.toEpochDayOrNull(): Long? {
    if (this.isNullOrBlank()) return null
    val m = ISO_DATE.matchEntire(trim()) ?: return null
    return try {
        val (yS, moS, dS) = m.destructured
        val year = yS.toInt()
        val month = moS.toInt()
        val day = dS.toInt()
        if (month !in 1..12 || day !in 1..31) return null
        epochDay(year, month, day)
    } catch (_: Exception) {
        null
    }
}

private val ISO_DATE = Regex("""^(\d{4})-(\d{2})-(\d{2})$""")

/** Days from 1970-01-01 to y/m/d (proleptic Gregorian); mirrors java.time.LocalDate.toEpochDay. */
internal fun epochDay(year: Int, month: Int, day: Int): Long {
    var y = year.toLong()
    val m = month
    if (m <= 2) y -= 1
    val era = (if (y >= 0) y else y - 399) / 400
    val yoe = y - era * 400
    val mp = (m + 9) % 12
    val doy = (153 * mp + 2) / 5 + (day - 1)
    val doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
    return era * 146_097 + doe - 719_468
}
