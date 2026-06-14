package com.testlogon.android.core.model

/**
 * AND-065 — immutable domain model for the creator dashboard summary.
 *
 * Mirrors the verified web contract `src/api/types.ts: DashboardSummary` (consumed via
 * `GET ui/dashboard/summary`) but carries no serialization annotations: the wire DTOs and the
 * DTO to domain mapper live in the app data layer, and only this type crosses up into the
 * ViewModel / UI (AND-068 / AND-066 / AND-069).
 *
 * Money fields are integer cents in [currency]. Timestamps are normalized to **epoch milliseconds**
 * ([generatedAt] from a unix-epoch number, broadcast/milestone times from their wire forms) so the
 * model stays pure-Kotlin and minSdk-24 safe (no java.time, matching the existing epoch-Long
 * convention used elsewhere). Null means absent/unparseable. [warnings] carries the backend's
 * partial-failure notices ("Some data sources are currently unavailable...").
 */
data class Dashboard(
    val todayEarningsCents: Long,
    val earningsBreakdown: EarningsBreakdown,
    val periodViews: Long,
    val periodRevenueCents: Long,
    val totalSubscribers: Long,
    val topContent: List<TopContentItem>,
    val activeBroadcasts: List<ActiveBroadcast>,
    val recentMilestones: List<Milestone>,
    val currency: String,
    val generatedAtMillis: Long?,
    val warnings: List<String>,
) {
    /**
     * "No renderable content" predicate (AND-068 §4.3): all activity lists empty AND every
     * headline metric zero. Drives the empty vs content branch in the ViewModel.
     */
    val isEmpty: Boolean
        get() = topContent.isEmpty() &&
            activeBroadcasts.isEmpty() &&
            recentMilestones.isEmpty() &&
            todayEarningsCents == 0L &&
            periodViews == 0L &&
            periodRevenueCents == 0L &&
            totalSubscribers == 0L
}

data class EarningsBreakdown(
    val subscriptions: Long,
    val tips: Long,
    val unlocks: Long,
    val vodPurchases: Long,
    val other: Long,
)

data class TopContentItem(
    val contentId: String,
    val contentType: String,
    val title: String,
    val views: Long,
    val revenueCents: Long,
)

data class ActiveBroadcast(
    val sessionId: String,
    val status: String,
    val name: String?,
    val startedAtMillis: Long?,
)

data class Milestone(
    val milestoneId: String,
    val metric: String,
    val threshold: Long,
    val currentValue: Long,
    val formatted: String,
    val achievedAtMillis: Long?,
    val acknowledged: Boolean,
)
