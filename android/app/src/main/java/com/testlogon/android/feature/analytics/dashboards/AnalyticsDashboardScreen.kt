@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.testlogon.android.feature.analytics.dashboards

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.CloudOff
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.analytics.AnalyticsDashboard
import com.testlogon.android.data.analytics.AudienceRow
import com.testlogon.android.data.analytics.SubscribersPoint
import com.testlogon.android.data.analytics.TopContentRow
import com.testlogon.android.data.analytics.ViewsPoint
import com.testlogon.android.data.analytics.formatCents
import com.testlogon.android.data.analytics.formatCount
import com.testlogon.android.data.analytics.formatFractionPercent
import com.testlogon.android.data.analytics.formatPercentNumber
import com.testlogon.android.data.analytics.formatWatchTime
import com.testlogon.android.feature.charts.ChartGeometryCore
import com.testlogon.android.feature.charts.SeriesChartType
import com.testlogon.android.feature.charts.TestLogonSeriesChart

/** AND-399 - stable testTags for the analytics-dashboards screen. */
object AnalyticsDashboardTestTags {
    const val SCREEN = "analytics_dashboard_screen"
    const val CONTENT = "analytics_dashboard_content"
    const val LOADING = "analytics_dashboard_loading"
    const val EMPTY = "analytics_dashboard_empty"
    const val ERROR = "analytics_dashboard_error"
    const val OFFLINE = "analytics_dashboard_offline"
    const val STALE_BANNER = "analytics_dashboard_stale"
    const val RANGE_PREFIX = "analytics_dashboard_range_"
    const val KPI_PREFIX = "analytics_dashboard_kpi_"
    const val VIEWS_CHART = "analytics_dashboard_views_chart"
    const val SUBS_CHART = "analytics_dashboard_subs_chart"
    const val TOP_CONTENT_PREFIX = "analytics_dashboard_top_"
    const val AUDIENCE_PREFIX = "analytics_dashboard_audience_"
}

/** AND-399 - route-level analytics-dashboards entry (reachable from the More hub). */
@Composable
fun AnalyticsDashboardRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: AnalyticsDashboardViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    AnalyticsDashboardScreen(
        state = state,
        onBack = onBack,
        onRangeSelected = viewModel::onRangeSelected,
        onRefresh = viewModel::onRefresh,
        onRetry = viewModel::onRetry,
        modifier = modifier,
    )
}

@Composable
fun AnalyticsDashboardScreen(
    state: AnalyticsDashboardUiState,
    onBack: () -> Unit,
    onRangeSelected: (DashboardRangeOption) -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(AnalyticsDashboardTestTags.SCREEN),
        topBar = {
            androidx.compose.material3.TopAppBar(
                title = { Text(stringResource(R.string.analytics_dashboard_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("analytics_dashboard_back")) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (state.phase) {
                AnalyticsDashboardUiState.Phase.Loading ->
                    LoadingState(
                        message = stringResource(R.string.analytics_dashboard_loading),
                        modifier = Modifier.testTag(AnalyticsDashboardTestTags.LOADING),
                    )

                AnalyticsDashboardUiState.Phase.Error ->
                    ErrorState(
                        message = state.errorMessage ?: stringResource(R.string.analytics_dashboard_error_generic),
                        onRetry = onRetry,
                        modifier = Modifier.testTag(AnalyticsDashboardTestTags.ERROR),
                    )

                AnalyticsDashboardUiState.Phase.Offline ->
                    EmptyState(
                        title = stringResource(R.string.analytics_dashboard_offline_title),
                        body = stringResource(R.string.analytics_dashboard_offline_body),
                        actionLabel = stringResource(R.string.action_retry),
                        onAction = onRetry,
                        modifier = Modifier.testTag(AnalyticsDashboardTestTags.OFFLINE),
                    )

                AnalyticsDashboardUiState.Phase.Empty ->
                    Column(Modifier.fillMaxSize()) {
                        RangeSelector(selected = state.range, onSelect = onRangeSelected)
                        EmptyState(
                            title = stringResource(R.string.analytics_dashboard_empty_title),
                            body = stringResource(R.string.analytics_dashboard_empty_body),
                            modifier = Modifier.testTag(AnalyticsDashboardTestTags.EMPTY),
                        )
                    }

                AnalyticsDashboardUiState.Phase.Content -> {
                    val dashboard = state.dashboard
                    if (dashboard == null) {
                        EmptyState(
                            title = stringResource(R.string.analytics_dashboard_empty_title),
                            modifier = Modifier.testTag(AnalyticsDashboardTestTags.EMPTY),
                        )
                    } else {
                        DashboardContent(
                            state = state,
                            dashboard = dashboard,
                            onRangeSelected = onRangeSelected,
                            onRefresh = onRefresh,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun DashboardContent(
    state: AnalyticsDashboardUiState,
    dashboard: AnalyticsDashboard,
    onRangeSelected: (DashboardRangeOption) -> Unit,
    onRefresh: () -> Unit,
) {
    PullToRefreshBox(
        isRefreshing = state.isRefreshing,
        onRefresh = onRefresh,
        modifier = Modifier.fillMaxSize(),
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(16.dp)
                .testTag(AnalyticsDashboardTestTags.CONTENT),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            if (state.isStale) StaleBanner()
            RangeSelector(selected = state.range, onSelect = onRangeSelected)
            dashboard.overview?.let { overview ->
                KpiTileRow(
                    views = overview.periodViews,
                    revenueCents = overview.periodRevenueCents,
                    currency = overview.currency,
                    newSubscribers = overview.periodNewSubscribers,
                    totalSubscribers = overview.totalSubscribers,
                )
            }
            ViewsChartCard(points = dashboard.views)
            SubscribersChartCard(points = dashboard.subscribers)
            TopContentSection(rows = dashboard.topContent, failed = dashboard.topContentFailed, onRetry = onRefresh)
            AudienceSection(
                countries = dashboard.audienceCountries,
                devices = dashboard.audienceDevices,
                failed = dashboard.audienceFailed,
                onRetry = onRefresh,
            )
        }
    }
}

@Composable
private fun StaleBanner() {
    Surface(
        color = MaterialTheme.colorScheme.secondaryContainer,
        contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
        modifier = Modifier
            .fillMaxWidth()
            .testTag(AnalyticsDashboardTestTags.STALE_BANNER),
    ) {
        Row(
            Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Icon(Icons.Outlined.CloudOff, contentDescription = null, modifier = Modifier.size(20.dp))
            Text(
                text = stringResource(R.string.analytics_dashboard_stale_banner),
                style = MaterialTheme.typography.bodyMedium,
            )
        }
    }
}

@Composable
private fun RangeSelector(
    selected: DashboardRangeOption,
    onSelect: (DashboardRangeOption) -> Unit,
    modifier: Modifier = Modifier,
) {
    FlowRow(
        modifier = modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        DashboardRangeOption.entries.forEach { option ->
            FilterChip(
                selected = option == selected,
                onClick = { onSelect(option) },
                label = { Text(stringResource(option.labelRes)) },
                modifier = Modifier
                    .testTag(AnalyticsDashboardTestTags.RANGE_PREFIX + option.range.apiKey)
                    .semantics { role = Role.Tab },
            )
        }
    }
}

@Composable
private fun KpiTileRow(
    views: Long,
    revenueCents: Long,
    currency: String,
    newSubscribers: Long,
    totalSubscribers: Long,
) {
    FlowRow(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        KpiTile(
            tag = "views",
            label = stringResource(R.string.analytics_kpi_views),
            value = formatCount(views),
        )
        KpiTile(
            tag = "revenue",
            label = stringResource(R.string.analytics_kpi_revenue),
            value = formatCents(revenueCents, currency),
        )
        KpiTile(
            tag = "new_subscribers",
            label = stringResource(R.string.analytics_kpi_new_subscribers),
            value = formatCount(newSubscribers),
        )
        KpiTile(
            tag = "total_subscribers",
            label = stringResource(R.string.analytics_kpi_total_subscribers),
            value = formatCount(totalSubscribers),
        )
    }
}

@Composable
private fun KpiTile(tag: String, label: String, value: String) {
    val cd = stringResource(R.string.analytics_kpi_cd, label, value)
    ElevatedCard(
        modifier = Modifier
            .testTag(AnalyticsDashboardTestTags.KPI_PREFIX + tag)
            .clearAndSetSemantics { contentDescription = cd },
    ) {
        Column(
            Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text = label,
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(text = value, style = MaterialTheme.typography.titleLarge)
        }
    }
}

@Composable
private fun ViewsChartCard(points: List<ViewsPoint>) {
    val geometry = remember(points) { ChartGeometryCore.compute(points.map { it.views }) }
    val totalViews = points.sumOf { it.views }
    val totalWatch = points.sumOf { it.watchTimeSeconds }
    val summary = stringResource(
        R.string.analytics_views_chart_cd,
        formatCount(totalViews),
        formatWatchTime(totalWatch),
    )
    ElevatedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(stringResource(R.string.analytics_views_chart_title), style = MaterialTheme.typography.titleSmall)
            // The Canvas is not screen-reader accessible: expose a text-equivalent summary node (section 9).
            Text(
                text = stringResource(R.string.analytics_views_chart_subtitle, formatWatchTime(totalWatch)),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.clearAndSetSemantics { contentDescription = summary },
            )
            if (geometry.isEmpty) {
                Text(
                    text = stringResource(R.string.analytics_chart_no_data),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                // Small windows render as bars; longer windows as a line (spec FR-4).
                val chartType = if (points.size <= SMALL_WINDOW) SeriesChartType.BAR else SeriesChartType.LINE
                TestLogonSeriesChart(
                    geometry = geometry,
                    chartType = chartType,
                    lineColor = MaterialTheme.colorScheme.primary,
                    gridColor = MaterialTheme.colorScheme.outlineVariant,
                    fillColor = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.35f),
                    selectedColor = MaterialTheme.colorScheme.tertiary,
                    selectedIndex = null,
                    onPointSelected = {},
                    modifier = Modifier.testTag(AnalyticsDashboardTestTags.VIEWS_CHART),
                )
            }
        }
    }
}

@Composable
private fun SubscribersChartCard(points: List<SubscribersPoint>) {
    val geometry = remember(points) { ChartGeometryCore.compute(points.map { it.total }) }
    val netChange = points.lastOrNull()?.total?.minus(points.firstOrNull()?.total ?: 0L) ?: 0L
    val summary = stringResource(
        R.string.analytics_subs_chart_cd,
        formatCount(points.lastOrNull()?.total ?: 0L),
        formatCount(netChange),
    )
    ElevatedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(stringResource(R.string.analytics_subs_chart_title), style = MaterialTheme.typography.titleSmall)
            Text(
                text = stringResource(R.string.analytics_subs_chart_subtitle),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.clearAndSetSemantics { contentDescription = summary },
            )
            if (geometry.isEmpty) {
                Text(
                    text = stringResource(R.string.analytics_chart_no_data),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                TestLogonSeriesChart(
                    geometry = geometry,
                    chartType = SeriesChartType.LINE,
                    lineColor = MaterialTheme.colorScheme.tertiary,
                    gridColor = MaterialTheme.colorScheme.outlineVariant,
                    fillColor = MaterialTheme.colorScheme.tertiaryContainer.copy(alpha = 0.35f),
                    selectedColor = MaterialTheme.colorScheme.primary,
                    selectedIndex = null,
                    onPointSelected = {},
                    modifier = Modifier.testTag(AnalyticsDashboardTestTags.SUBS_CHART),
                )
            }
        }
    }
}

@Composable
private fun TopContentSection(rows: List<TopContentRow>, failed: Boolean, onRetry: () -> Unit) {
    ElevatedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(stringResource(R.string.analytics_top_content_title), style = MaterialTheme.typography.titleSmall)
            when {
                failed -> SectionError(onRetry)
                rows.isEmpty() -> SectionEmpty(stringResource(R.string.analytics_top_content_empty))
                else -> rows.forEachIndexed { index, row ->
                    val secondary = stringResource(
                        R.string.analytics_top_content_secondary,
                        formatCount(row.views),
                        formatFractionPercent(row.engagementRate),
                    )
                    BreakdownRow(
                        tag = AnalyticsDashboardTestTags.TOP_CONTENT_PREFIX + index,
                        label = row.title.ifBlank { row.contentType },
                        value = secondary,
                    )
                }
            }
        }
    }
}

@Composable
private fun AudienceSection(
    countries: List<AudienceRow>,
    devices: List<AudienceRow>,
    failed: Boolean,
    onRetry: () -> Unit,
) {
    ElevatedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(stringResource(R.string.analytics_audience_title), style = MaterialTheme.typography.titleSmall)
            when {
                failed -> SectionError(onRetry)
                countries.isEmpty() && devices.isEmpty() ->
                    SectionEmpty(stringResource(R.string.analytics_audience_empty))
                else -> {
                    if (countries.isNotEmpty()) {
                        Text(
                            stringResource(R.string.analytics_audience_countries),
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        countries.forEachIndexed { index, row ->
                            BreakdownRow(
                                tag = AnalyticsDashboardTestTags.AUDIENCE_PREFIX + "country_" + index,
                                label = row.label,
                                value = formatPercentNumber(row.percentage),
                            )
                        }
                    }
                    if (devices.isNotEmpty()) {
                        Text(
                            stringResource(R.string.analytics_audience_devices),
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        devices.forEachIndexed { index, row ->
                            BreakdownRow(
                                tag = AnalyticsDashboardTestTags.AUDIENCE_PREFIX + "device_" + index,
                                label = row.label,
                                value = formatPercentNumber(row.percentage),
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun BreakdownRow(tag: String, label: String, value: String) {
    Row(
        Modifier
            .fillMaxWidth()
            .testTag(tag)
            .clearAndSetSemantics { contentDescription = "$label, $value" },
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(label, style = MaterialTheme.typography.bodyMedium)
        Text(value, style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
private fun SectionEmpty(message: String) {
    Text(
        text = message,
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

@Composable
private fun SectionError(onRetry: () -> Unit) {
    Row(
        Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = stringResource(R.string.analytics_section_error),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.error,
        )
        TextButton(onClick = onRetry) { Text(stringResource(R.string.action_retry)) }
    }
}

private const val SMALL_WINDOW = 14
