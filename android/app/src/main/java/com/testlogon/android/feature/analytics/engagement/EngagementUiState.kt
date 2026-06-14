package com.testlogon.android.feature.analytics.engagement

import androidx.annotation.StringRes
import com.testlogon.android.R
import com.testlogon.android.data.analytics.Engagement

/**
 * AND-254 — selectable engagement period (the web selector offers 7/14/30/60/90 days). Each carries the
 * `period_days` query value and a stable label resource. Default is [D30].
 */
enum class EngagementPeriod(val days: Int, @StringRes val labelRes: Int) {
    D7(7, R.string.engagement_period_7d),
    D14(14, R.string.engagement_period_14d),
    D30(30, R.string.engagement_period_30d),
    D60(60, R.string.engagement_period_60d),
    D90(90, R.string.engagement_period_90d),
    ;

    companion object {
        val DEFAULT = D30
    }
}

/** Engagement chart presentation toggle (session-only). */
enum class EngagementChartType { LINE, BAR }

/**
 * AND-254 — single render-ready engagement state. A single immutable data class (mirroring
 * EarningsUiState) so the prior [engagement] can persist across refresh / period transitions while
 * [isRefreshing]. [phase] enumerates the mutually-exclusive top-level surfaces.
 */
data class EngagementUiState(
    val period: EngagementPeriod = EngagementPeriod.DEFAULT,
    val phase: Phase = Phase.Loading,
    val engagement: Engagement? = null,
    val chartType: EngagementChartType = EngagementChartType.LINE,
    val selectedPoint: Int? = null,
    val isRefreshing: Boolean = false,
    val errorMessage: String? = null,
) {
    enum class Phase { Loading, Content, Empty, Error, Offline }

    val canRetry: Boolean get() = phase == Phase.Error || phase == Phase.Offline
}
