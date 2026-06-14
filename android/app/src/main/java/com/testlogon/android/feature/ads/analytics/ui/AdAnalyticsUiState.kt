package com.testlogon.android.feature.ads.analytics.ui

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ads.AdAnalyticsSummary
import com.testlogon.android.core.model.ads.AdBreakdownEntry
import com.testlogon.android.core.model.ads.AdTimeSeriesPoint
import com.testlogon.android.core.model.ads.DateRangePreset

/**
 * AND-368 - hoisted UI state for the READ-ONLY ad-analytics dashboard.
 *
 *  - [Loading] - the initial read is in flight.
 *  - [Content] - the KPI summary + time series + breakdown for the selected [range]. [isStale] marks cached
 *    data shown after a refresh failure; [isRefreshing] drives the pull-to-refresh spinner.
 *  - [Empty]   - the account / range produced no analytics data.
 *  - [Error]   - a fatal load problem (the first read failed with no cache); retryable.
 *
 * READ-ONLY: there are no mutation sub-states.
 */
sealed interface AdAnalyticsUiState {

    data object Loading : AdAnalyticsUiState

    /** The loaded dashboard. A refresh failure that has prior content keeps it here with [isStale] = true. */
    data class Content(
        val summary: AdAnalyticsSummary,
        val timeseries: List<AdTimeSeriesPoint>,
        val breakdown: List<AdBreakdownEntry>,
        val range: DateRangePreset,
        val isStale: Boolean = false,
        val isRefreshing: Boolean = false,
    ) : AdAnalyticsUiState

    /** The selected account / range has no analytics to show. Carries [range] so the chips stay rendered. */
    data class Empty(val range: DateRangePreset) : AdAnalyticsUiState

    /** A fatal, retryable load error. [range] is kept so a retry re-queries the same window. */
    data class Error(val error: ApiError, val range: DateRangePreset) : AdAnalyticsUiState
}
