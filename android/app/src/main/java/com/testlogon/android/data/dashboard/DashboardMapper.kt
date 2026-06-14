package com.testlogon.android.data.dashboard

import com.testlogon.android.core.model.ActiveBroadcast
import com.testlogon.android.core.model.Dashboard
import com.testlogon.android.core.model.EarningsBreakdown
import com.testlogon.android.core.model.Milestone
import com.testlogon.android.core.model.TopContentItem
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.TimeZone

/**
 * AND-065 — total DTO to domain mapper. Never throws: out-of-range/absent epoch numbers become
 * null, unparseable ISO strings become null, and absent collections are already empty (DTO
 * defaults). Timestamps are normalized to epoch milliseconds.
 *
 * NOTE: the wire epoch unit (seconds vs millis) is unverified; the contract types it only as a
 * number. We assume SECONDS and multiply to millis; switch off [epochSecondsToMillis] if a live
 * payload proves otherwise. Kept pure-Kotlin / java.text (no java.time) for minSdk-24 safety.
 */
fun DashboardSummaryDto.toDomain(): Dashboard = Dashboard(
    todayEarningsCents = todayEarningsCents,
    earningsBreakdown = earningsBreakdown.toDomain(),
    periodViews = periodViews,
    periodRevenueCents = periodRevenueCents,
    totalSubscribers = totalSubscribers,
    topContent = topContent.map {
        TopContentItem(it.contentId, it.contentType, it.title, it.views, it.revenueCents)
    },
    activeBroadcasts = activeBroadcasts.map {
        ActiveBroadcast(it.sessionId, it.status, it.name, it.startedAt.isoToMillisOrNull())
    },
    recentMilestones = recentMilestones.map { it.toDomain() },
    currency = currency,
    generatedAtMillis = generatedAt.epochSecondsToMillis(),
    warnings = warnings,
)

private fun DashboardEarningsBreakdownDto.toDomain() =
    EarningsBreakdown(subscriptions, tips, unlocks, vodPurchases, other)

private fun DashboardMilestoneDto.toDomain() = Milestone(
    milestoneId = milestoneId,
    metric = metric,
    threshold = threshold,
    currentValue = currentValue,
    formatted = formatted,
    achievedAtMillis = achievedAt.epochSecondsToMillis(),
    acknowledged = acknowledged,
)

/** generated_at / achieved_at are epoch SECONDS numbers on the wire → epoch millis. */
private fun Long?.epochSecondsToMillis(): Long? =
    this?.let { runCatching { Math.multiplyExact(it, 1000L) }.getOrNull() }

/**
 * active_broadcasts[].started_at is an ISO-8601 string (e.g. 2026-06-05T12:00:00Z). Parsed in UTC;
 * returns null on any parse failure. Avoids java.time for minSdk-24 safety.
 */
private fun String?.isoToMillisOrNull(): Long? {
    if (this.isNullOrBlank()) return null
    val patterns = listOf("yyyy-MM-dd'T'HH:mm:ss'Z'", "yyyy-MM-dd'T'HH:mm:ssXXX", "yyyy-MM-dd'T'HH:mm:ss")
    for (pattern in patterns) {
        val parsed = runCatching {
            SimpleDateFormat(pattern, Locale.US).apply { timeZone = TimeZone.getTimeZone("UTC") }
                .parse(this)
        }.getOrNull()
        if (parsed != null) return parsed.time
    }
    return null
}
