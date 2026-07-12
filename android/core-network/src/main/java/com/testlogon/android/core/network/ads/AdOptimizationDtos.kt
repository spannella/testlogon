package com.testlogon.android.core.network.ads

import com.squareup.moshi.Json

/**
 * Ad OPTIMIZATION transport DTOs (web parity: /ads/optimization -> ad_optimization.py, prefix
 * /ui/ads/optimization). Mirrors the backend service return shapes (recommendation projection, generate
 * result, apply/dismiss result, suggested-bid, budget-recommendation, optimization-config result).
 *
 * Reflective Moshi (no codegen): explicit @Json on every wire key. Timestamps are epoch-second Longs.
 * `details` is an opaque map (server-shaped per action). `optimization_config` is an opaque map.
 */

/** One recommendation row (matches the backend _rec_out projection). */
data class AdRecommendationDto(
    @Json(name = "recommendation_id") val recommendationId: String,
    @Json(name = "campaign_id") val campaignId: String = "",
    @Json(name = "account_id") val accountId: String = "",
    @Json(name = "action") val action: String = "",
    @Json(name = "creative_id") val creativeId: String? = null,
    @Json(name = "title") val title: String = "",
    @Json(name = "description") val description: String = "",
    @Json(name = "impact") val impact: String = "",
    @Json(name = "severity") val severity: String = "info",
    @Json(name = "details") val details: Map<String, Any?> = emptyMap(),
    @Json(name = "status") val status: String = "open",
    @Json(name = "created_at") val createdAt: Long = 0L,
    @Json(name = "updated_at") val updatedAt: Long = 0L,
    @Json(name = "applied_at") val appliedAt: Long? = null,
    @Json(name = "dismissed_at") val dismissedAt: Long? = null,
)

/** GET .../recommendations result wrapper. */
data class RecommendationListDto(
    @Json(name = "recommendations") val recommendations: List<AdRecommendationDto> = emptyList(),
)

/** POST .../generate result (subset used by the client: recommendations + campaign id). */
data class GenerateResultDto(
    @Json(name = "campaign_id") val campaignId: String? = null,
    @Json(name = "recommendations") val recommendations: List<AdRecommendationDto> = emptyList(),
    @Json(name = "generated_at") val generatedAt: Long? = null,
)

/** Generic ok/status result for apply / dismiss. */
data class OptimizationActionResultDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "status") val status: String = "",
)

/** GET .../suggested-bid result. */
data class SuggestedBidDto(
    @Json(name = "min_bid_cpm_cents") val minBidCpmCents: Long = 0L,
    @Json(name = "suggested_bid_cpm_cents") val suggestedBidCpmCents: Long = 0L,
    @Json(name = "max_bid_cpm_cents") val maxBidCpmCents: Long = 0L,
    @Json(name = "estimated_fill_rate") val estimatedFillRate: Double = 0.0,
    @Json(name = "competition_level") val competitionLevel: String = "medium",
)

/** GET .../budget-recommendation result. */
data class BudgetRecommendationDto(
    @Json(name = "estimated_daily_reach") val estimatedDailyReach: Long = 0L,
    @Json(name = "recommended_daily_budget_cents") val recommendedDailyBudgetCents: Long = 0L,
    @Json(name = "estimated_cpm_cents") val estimatedCpmCents: Long = 0L,
    @Json(name = "reach_per_dollar") val reachPerDollar: Double = 0.0,
)

/** PATCH .../optimization-config body. Only set fields are sent (nulls omitted). */
data class OptimizationConfigUpdateIn(
    @Json(name = "auto_optimize_enabled") val autoOptimizeEnabled: Boolean? = null,
    @Json(name = "ctr_threshold") val ctrThreshold: Double? = null,
    @Json(name = "auto_pause_min_impressions") val autoPauseMinImpressions: Int? = null,
    @Json(name = "roas_threshold") val roasThreshold: Double? = null,
    @Json(name = "budget_pace_alert_ratio") val budgetPaceAlertRatio: Double? = null,
)

/** PATCH .../optimization-config result. */
data class OptimizationConfigResultDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "auto_optimize_enabled") val autoOptimizeEnabled: Boolean = false,
    @Json(name = "optimization_config") val optimizationConfig: Map<String, Any?> = emptyMap(),
)
