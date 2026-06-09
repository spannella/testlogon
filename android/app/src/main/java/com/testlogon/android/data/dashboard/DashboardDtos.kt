package com.testlogon.android.data.dashboard

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * AND-065 — wire DTOs for the creator dashboard summary.
 *
 * Shapes are the verified contract from `src/api/types.ts: DashboardSummary` and its nested
 * interfaces (consumed via `GET ui/dashboard/summary`). The OpenAPI 200 schema for this path is
 * untyped, so the frontend interface is authoritative. Money fields are integer cents;
 * `generated_at` / `achieved_at` / `refreshed_at` are unix-epoch NUMBERS (decoded as Long, converted
 * in the mapper); `active_broadcasts[].started_at` is an ISO-8601 string.
 *
 * All optionals default to Kotlin defaults; unknown keys are ignored by the shared converter.
 * Uses Moshi codegen (`@JsonClass(generateAdapter = true)`), consistent with the auth DTOs.
 */
@JsonClass(generateAdapter = true)
data class DashboardSummaryDto(
    @Json(name = "today_earnings_cents") val todayEarningsCents: Long = 0,
    @Json(name = "earnings_breakdown") val earningsBreakdown: DashboardEarningsBreakdownDto = DashboardEarningsBreakdownDto(),
    @Json(name = "period_views") val periodViews: Long = 0,
    @Json(name = "period_revenue_cents") val periodRevenueCents: Long = 0,
    @Json(name = "total_subscribers") val totalSubscribers: Long = 0,
    @Json(name = "top_content") val topContent: List<DashboardTopContentItemDto> = emptyList(),
    @Json(name = "active_broadcasts") val activeBroadcasts: List<DashboardActiveBroadcastDto> = emptyList(),
    @Json(name = "recent_milestones") val recentMilestones: List<DashboardMilestoneDto> = emptyList(),
    @Json(name = "currency") val currency: String = "USD",
    // generated_at is a unix-epoch number on the wire (types.ts: number), NOT an ISO string.
    @Json(name = "generated_at") val generatedAt: Long? = null,
    @Json(name = "warnings") val warnings: List<String> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class DashboardEarningsBreakdownDto(
    @Json(name = "subscriptions") val subscriptions: Long = 0,
    @Json(name = "tips") val tips: Long = 0,
    @Json(name = "unlocks") val unlocks: Long = 0,
    @Json(name = "vod_purchases") val vodPurchases: Long = 0,
    @Json(name = "other") val other: Long = 0,
)

@JsonClass(generateAdapter = true)
data class DashboardTopContentItemDto(
    @Json(name = "content_id") val contentId: String = "",
    @Json(name = "content_type") val contentType: String = "",
    @Json(name = "title") val title: String = "",
    @Json(name = "views") val views: Long = 0,
    @Json(name = "revenue_cents") val revenueCents: Long = 0,
)

@JsonClass(generateAdapter = true)
data class DashboardActiveBroadcastDto(
    @Json(name = "session_id") val sessionId: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "name") val name: String? = null,
    // ISO-8601 string per types.ts.
    @Json(name = "started_at") val startedAt: String? = null,
)

@JsonClass(generateAdapter = true)
data class DashboardMilestoneDto(
    @Json(name = "milestone_id") val milestoneId: String = "",
    @Json(name = "user_id") val userId: String = "",
    @Json(name = "metric") val metric: String = "",
    @Json(name = "threshold") val threshold: Long = 0,
    @Json(name = "current_value") val currentValue: Long = 0,
    @Json(name = "formatted") val formatted: String = "",
    // epoch number per types.ts.
    @Json(name = "achieved_at") val achievedAt: Long? = null,
    @Json(name = "acknowledged") val acknowledged: Boolean = false,
)

/** POST ui/dashboard/refresh response, per dashboard.ts: refreshDashboard. */
@JsonClass(generateAdapter = true)
data class RefreshAckDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "message") val message: String? = null,
    @Json(name = "refreshed_at") val refreshedAt: Long? = null,
)
