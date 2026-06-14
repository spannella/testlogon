@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.ads.analytics.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Card
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.ads.AdAnalyticsSummary
import com.testlogon.android.core.model.ads.AdBreakdownEntry
import com.testlogon.android.core.model.ads.AdTimeSeriesPoint
import com.testlogon.android.core.model.ads.DateRangePreset
import com.testlogon.android.core.model.syndicates.formatCents
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.StaleBanner
import com.testlogon.android.feature.charts.ChartGeometryCore
import com.testlogon.android.feature.charts.SeriesChartType
import com.testlogon.android.feature.charts.TestLogonSeriesChart

/** AND-368 - stable testTags for the READ-ONLY ad-analytics dashboard. */
object AdAnalyticsTestTags {
    const val SCREEN = "ad_analytics_screen"
    const val LIST = "ad_analytics_list"
    const val EMPTY = "ad_analytics_empty"
    const val ERROR_RETRY = "ad_analytics_error_retry"
    const val CHART_SPEND = "ad_chart_spend"
    const val CHART_TRAFFIC = "ad_chart_traffic"

    /** Per-range chip tag (suffix is the preset name lowercased, e.g. ad_range_last_28). */
    fun rangeChip(preset: DateRangePreset): String = "ad_range_${preset.name.lowercase()}"

    /** Per-KPI tile tag (suffix is the metric key, e.g. ad_kpi_impressions). */
    fun kpi(name: String): String = "ad_kpi_$name"

    /** Per-breakdown-row tag (suffix is the row index). */
    fun breakdownRow(index: Int): String = "ad_breakdown_row_$index"
}

/** AND-368 - the user-facing label for a [DateRangePreset]. */
private fun DateRangePreset.labelRes(): Int = when (this) {
    DateRangePreset.LAST_7 -> R.string.ad_analytics_range_7
    DateRangePreset.LAST_28 -> R.string.ad_analytics_range_28
    DateRangePreset.LAST_90 -> R.string.ad_analytics_range_90
}

/**
 * AND-368 - route-level ad-analytics entry (reached from the More hub / an ads-accounts list downstream). The
 * VM reads {accountId} from SavedStateHandle. READ-ONLY dashboard: KPI tiles + time-series charts +
 * breakdown over a selectable date range.
 */
@Composable
fun AdAnalyticsRoute(
    onBack: () -> Unit,
    viewModel: AdAnalyticsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    AdAnalyticsScreen(
        state = state,
        onBack = onBack,
        onRangeChanged = viewModel::onRangeChanged,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::onRetry,
    )
}

/** AND-368 - stateless ad-analytics dashboard. */
@Composable
fun AdAnalyticsScreen(
    state: AdAnalyticsUiState,
    onBack: () -> Unit,
    onRangeChanged: (DateRangePreset) -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(AdAnalyticsTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.ad_analytics_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.ad_analytics_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            val selectedRange = state.selectedRange()
            RangeSelector(selected = selectedRange, onRangeChanged = onRangeChanged)
            when (state) {
                is AdAnalyticsUiState.Loading -> LoadingState()
                is AdAnalyticsUiState.Empty -> EmptyState(
                    title = stringResource(R.string.ad_analytics_empty_title),
                    body = stringResource(R.string.ad_analytics_empty_body),
                    modifier = Modifier.testTag(AdAnalyticsTestTags.EMPTY),
                )
                is AdAnalyticsUiState.Error -> ErrorState(
                    message = state.error.message,
                    onRetry = onRetry,
                    modifier = Modifier.testTag(AdAnalyticsTestTags.ERROR_RETRY),
                )
                is AdAnalyticsUiState.Content -> AdAnalyticsContent(
                    state = state,
                    onRefresh = onRefresh,
                    onRetry = onRetry,
                )
            }
        }
    }
}

/** The currently-selected preset across every state (Loading falls back to the default). */
private fun AdAnalyticsUiState.selectedRange(): DateRangePreset = when (this) {
    is AdAnalyticsUiState.Content -> range
    is AdAnalyticsUiState.Empty -> range
    is AdAnalyticsUiState.Error -> range
    AdAnalyticsUiState.Loading -> DateRangePreset.LAST_28
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun RangeSelector(
    selected: DateRangePreset,
    onRangeChanged: (DateRangePreset) -> Unit,
    modifier: Modifier = Modifier,
) {
    FlowRow(
        modifier = modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        DateRangePreset.entries.forEach { preset ->
            FilterChip(
                selected = preset == selected,
                onClick = { onRangeChanged(preset) },
                label = { Text(stringResource(preset.labelRes())) },
                modifier = Modifier.testTag(AdAnalyticsTestTags.rangeChip(preset)),
            )
        }
    }
}

@Composable
private fun AdAnalyticsContent(
    state: AdAnalyticsUiState.Content,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
) {
    PullToRefreshBox(
        isRefreshing = state.isRefreshing,
        onRefresh = onRefresh,
        modifier = Modifier.fillMaxSize(),
    ) {
        LazyColumn(
            modifier = Modifier.fillMaxSize().testTag(AdAnalyticsTestTags.LIST),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            item {
                StaleBanner(stale = state.isStale, refreshing = false, onRetry = onRetry)
            }
            item { KpiGrid(summary = state.summary) }
            item { SpendChartCard(timeseries = state.timeseries) }
            item { TrafficChartCard(timeseries = state.timeseries) }
            item {
                Text(
                    text = stringResource(R.string.ad_analytics_breakdown_header),
                    style = MaterialTheme.typography.titleMedium,
                )
            }
            if (state.breakdown.isEmpty()) {
                item {
                    Text(
                        text = stringResource(R.string.ad_analytics_breakdown_empty),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            } else {
                itemsIndexed(state.breakdown) { index, entry ->
                    BreakdownRow(index = index, entry = entry)
                }
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun KpiGrid(summary: AdAnalyticsSummary) {
    FlowRow(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        KpiTile(
            name = "impressions",
            label = stringResource(R.string.ad_analytics_kpi_impressions),
            value = summary.impressions.toString(),
            changePct = summary.impressionsChangePct,
        )
        KpiTile(
            name = "clicks",
            label = stringResource(R.string.ad_analytics_kpi_clicks),
            value = summary.clicks.toString(),
            changePct = summary.clicksChangePct,
        )
        KpiTile(
            name = "spend",
            label = stringResource(R.string.ad_analytics_kpi_spend),
            value = formatCents(summary.spendCents),
            changePct = summary.spendChangePct,
        )
        KpiTile(
            name = "ctr",
            label = stringResource(R.string.ad_analytics_kpi_ctr),
            value = formatPercent(summary.ctrPct),
            changePct = summary.ctrChangePct,
        )
        summary.cpaCents?.let {
            KpiTile(
                name = "cpa",
                label = stringResource(R.string.ad_analytics_kpi_cpa),
                value = formatCents(it),
                changePct = summary.cpaChangePct,
            )
        }
        summary.effectiveCpmCents?.let {
            KpiTile(
                name = "ecpm",
                label = stringResource(R.string.ad_analytics_kpi_ecpm),
                value = formatCents(it),
                changePct = summary.effectiveCpmChangePct,
            )
        }
        summary.completionRatePct?.let {
            KpiTile(
                name = "completion_rate",
                label = stringResource(R.string.ad_analytics_kpi_completion_rate),
                value = formatPercent(it),
                changePct = summary.completionRateChangePct,
            )
        }
    }
}

@Composable
private fun KpiTile(
    name: String,
    label: String,
    value: String,
    changePct: Double?,
) {
    Card(modifier = Modifier.testTag(AdAnalyticsTestTags.kpi(name))) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text = label,
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(text = value, style = MaterialTheme.typography.titleLarge)
            if (changePct != null) {
                Text(
                    text = formatChange(changePct),
                    style = MaterialTheme.typography.bodySmall,
                    color = if (changePct >= 0) {
                        MaterialTheme.colorScheme.primary
                    } else {
                        MaterialTheme.colorScheme.error
                    },
                )
            }
        }
    }
}

@Composable
private fun SpendChartCard(timeseries: List<AdTimeSeriesPoint>) {
    val geometry = remember(timeseries) {
        ChartGeometryCore.compute(timeseries.map { it.spendCents })
    }
    ElevatedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                text = stringResource(R.string.ad_analytics_chart_spend_title),
                style = MaterialTheme.typography.titleSmall,
            )
            if (geometry.isEmpty) {
                Text(
                    text = stringResource(R.string.ad_analytics_chart_no_data),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                TestLogonSeriesChart(
                    geometry = geometry,
                    chartType = SeriesChartType.LINE,
                    lineColor = MaterialTheme.colorScheme.primary,
                    gridColor = MaterialTheme.colorScheme.outlineVariant,
                    fillColor = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.35f),
                    selectedColor = MaterialTheme.colorScheme.tertiary,
                    selectedIndex = null,
                    onPointSelected = {},
                    modifier = Modifier.testTag(AdAnalyticsTestTags.CHART_SPEND),
                )
            }
        }
    }
}

@Composable
private fun TrafficChartCard(timeseries: List<AdTimeSeriesPoint>) {
    // Impressions vs clicks: clicks are far smaller, so the bars show clicks against the impression line.
    val impressionGeometry = remember(timeseries) {
        ChartGeometryCore.compute(timeseries.map { it.impressions })
    }
    val clickGeometry = remember(timeseries) {
        ChartGeometryCore.compute(timeseries.map { it.clicks })
    }
    ElevatedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                text = stringResource(R.string.ad_analytics_chart_traffic_title),
                style = MaterialTheme.typography.titleSmall,
            )
            if (impressionGeometry.isEmpty && clickGeometry.isEmpty) {
                Text(
                    text = stringResource(R.string.ad_analytics_chart_no_data),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                Text(
                    text = stringResource(R.string.ad_analytics_chart_impressions_label),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                TestLogonSeriesChart(
                    geometry = impressionGeometry,
                    chartType = SeriesChartType.LINE,
                    lineColor = MaterialTheme.colorScheme.primary,
                    gridColor = MaterialTheme.colorScheme.outlineVariant,
                    fillColor = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.35f),
                    selectedColor = MaterialTheme.colorScheme.tertiary,
                    selectedIndex = null,
                    onPointSelected = {},
                    modifier = Modifier.testTag(AdAnalyticsTestTags.CHART_TRAFFIC),
                )
                Text(
                    text = stringResource(R.string.ad_analytics_chart_clicks_label),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                TestLogonSeriesChart(
                    geometry = clickGeometry,
                    chartType = SeriesChartType.BAR,
                    lineColor = MaterialTheme.colorScheme.secondary,
                    gridColor = MaterialTheme.colorScheme.outlineVariant,
                    fillColor = MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.35f),
                    selectedColor = MaterialTheme.colorScheme.tertiary,
                    selectedIndex = null,
                    onPointSelected = {},
                )
            }
        }
    }
}

@Composable
private fun BreakdownRow(index: Int, entry: AdBreakdownEntry) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(AdAnalyticsTestTags.breakdownRow(index)),
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text(
                text = entry.campaignName
                    ?: entry.key
                    ?: stringResource(R.string.ad_analytics_breakdown_unknown),
                style = MaterialTheme.typography.bodyLarge,
            )
            Text(
                text = formatCents(entry.spendCents),
                style = MaterialTheme.typography.bodyLarge,
            )
        }
        val ctr = entry.ctrPct?.let { formatPercent(it) }
        val subtitle = listOfNotNull(
            stringResource(R.string.ad_analytics_breakdown_impressions, entry.impressions),
            stringResource(R.string.ad_analytics_breakdown_clicks, entry.clicks),
            ctr,
        ).joinToString(" • ")
        Text(
            text = subtitle,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        HorizontalDivider()
    }
}

/** Formats an already-percentage value (NO multiply by 100), e.g. 1.234 -> "1.23%". */
private fun formatPercent(pct: Double): String = "%.2f%%".format(pct)

/** Formats a period-over-period change percentage with a sign, e.g. 4.5 -> "+4.50%". */
private fun formatChange(pct: Double): String {
    val sign = if (pct >= 0) "+" else ""
    return "$sign%.2f%%".format(pct)
}
