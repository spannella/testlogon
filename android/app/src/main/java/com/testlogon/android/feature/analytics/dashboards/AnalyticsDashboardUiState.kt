package com.testlogon.android.feature.analytics.dashboards

import androidx.annotation.StringRes
import com.testlogon.android.R
import com.testlogon.android.data.analytics.AnalyticsDashboard
import com.testlogon.android.data.analytics.AnalyticsDashboardRange

/**
 * AND-399 - the selectable dashboard range, with a stable label resource for the chips. Mirrors the
 * data-layer [AnalyticsDashboardRange] (7 / 30 / 90 / 365, default 30 per the CORRECTED spec FR-2).
 */
enum class DashboardRangeOption(
    val range: AnalyticsDashboardRange,
    @StringRes val labelRes: Int,
) {
    LAST_7(AnalyticsDashboardRange.LAST_7, R.string.analytics_range_7d),
    LAST_30(AnalyticsDashboardRange.LAST_30, R.string.analytics_range_30d),
    LAST_90(AnalyticsDashboardRange.LAST_90, R.string.analytics_range_90d),
    LAST_365(AnalyticsDashboardRange.LAST_365, R.string.analytics_range_1y),
    ;

    companion object {
        val DEFAULT = LAST_30

        fun of(range: AnalyticsDashboardRange): DashboardRangeOption =
            entries.first { it.range == range }
    }
}

/**
 * AND-399 - single render-ready analytics-dashboard state (a single immutable data class, mirroring
 * EngagementUiState) so the prior [dashboard] persists across refresh / range transitions while
 * [isRefreshing]. [phase] enumerates the mutually-exclusive top-level surfaces; [isStale] marks a
 * cached snapshot shown after a refresh failure (FR-6).
 */
data class AnalyticsDashboardUiState(
    val range: DashboardRangeOption = DashboardRangeOption.DEFAULT,
    val phase: Phase = Phase.Loading,
    val dashboard: AnalyticsDashboard? = null,
    val isStale: Boolean = false,
    val isRefreshing: Boolean = false,
    val errorMessage: String? = null,
) {
    enum class Phase { Loading, Content, Empty, Error, Offline }

    val canRetry: Boolean get() = phase == Phase.Error || phase == Phase.Offline
}
