@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.testlogon.android.feature.analytics.engagement

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.ArrowDownward
import androidx.compose.material.icons.outlined.ArrowUpward
import androidx.compose.material.icons.outlined.BarChart
import androidx.compose.material.icons.outlined.Remove
import androidx.compose.material.icons.outlined.ShowChart
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.analytics.Engagement
import com.testlogon.android.data.analytics.EngagementMetrics
import com.testlogon.android.data.analytics.EngagementTrendPoint
import com.testlogon.android.data.analytics.Trend
import com.testlogon.android.feature.charts.ChartGeometryCore
import com.testlogon.android.feature.charts.SeriesChartType
import com.testlogon.android.feature.charts.TestLogonSeriesChart

/** AND-254 — stable testTags for the engagement-rate screen. */
object EngagementTestTags {
    const val SCREEN = "engagement_screen"
    const val CONTENT = "engagement_content"
    const val LOADING = "engagement_loading"
    const val EMPTY = "engagement_empty"
    const val ERROR = "engagement_error"
    const val OFFLINE = "engagement_offline"
    const val HEADLINE = "engagement_headline"
    const val TREND_CHIP = "engagement_trend_chip"
    const val CHART = "engagement_chart"
    const val PERIOD_PREFIX = "engagement_period_"
    const val CHART_TOGGLE = "engagement_chart_toggle"
    const val ROW_PREFIX = "engagement_row_"
}

/** AND-254 — route-level engagement-rate entry (reachable from the More hub). */
@Composable
fun EngagementRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: EngagementViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    EngagementScreen(
        state = state,
        onBack = onBack,
        onPeriodSelected = viewModel::onPeriodSelected,
        onChartTypeToggled = viewModel::onChartTypeToggled,
        onPointSelected = viewModel::onPointSelected,
        onRefresh = viewModel::onRefresh,
        onRetry = viewModel::onRetry,
        modifier = modifier,
    )
}

@Composable
fun EngagementScreen(
    state: EngagementUiState,
    onBack: () -> Unit,
    onPeriodSelected: (EngagementPeriod) -> Unit,
    onChartTypeToggled: () -> Unit,
    onPointSelected: (Int?) -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(EngagementTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.engagement_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("engagement_back")) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
                actions = {
                    IconButton(
                        onClick = onChartTypeToggled,
                        modifier = Modifier.testTag(EngagementTestTags.CHART_TOGGLE),
                    ) {
                        val isLine = state.chartType == EngagementChartType.LINE
                        Icon(
                            imageVector = if (isLine) Icons.Outlined.BarChart else Icons.Outlined.ShowChart,
                            contentDescription = stringResource(
                                if (isLine) R.string.engagement_chart_show_bars else R.string.engagement_chart_show_line,
                            ),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (state.phase) {
                EngagementUiState.Phase.Loading ->
                    LoadingState(
                        message = stringResource(R.string.engagement_loading),
                        modifier = Modifier.testTag(EngagementTestTags.LOADING),
                    )

                EngagementUiState.Phase.Error ->
                    ErrorState(
                        message = state.errorMessage ?: stringResource(R.string.engagement_error_generic),
                        onRetry = onRetry,
                        modifier = Modifier.testTag(EngagementTestTags.ERROR),
                    )

                EngagementUiState.Phase.Offline ->
                    EmptyState(
                        title = stringResource(R.string.engagement_offline_title),
                        body = stringResource(R.string.engagement_offline_body),
                        actionLabel = stringResource(R.string.action_retry),
                        onAction = onRetry,
                        modifier = Modifier.testTag(EngagementTestTags.OFFLINE),
                    )

                EngagementUiState.Phase.Empty ->
                    Column(Modifier.fillMaxSize()) {
                        PeriodSelector(selected = state.period, onSelect = onPeriodSelected)
                        EmptyState(
                            title = stringResource(R.string.engagement_empty_title),
                            body = stringResource(R.string.engagement_empty_body),
                            modifier = Modifier.testTag(EngagementTestTags.EMPTY),
                        )
                    }

                EngagementUiState.Phase.Content -> {
                    val engagement = state.engagement
                    if (engagement == null) {
                        EmptyState(
                            title = stringResource(R.string.engagement_empty_title),
                            modifier = Modifier.testTag(EngagementTestTags.EMPTY),
                        )
                    } else {
                        EngagementContent(
                            state = state,
                            engagement = engagement,
                            onPeriodSelected = onPeriodSelected,
                            onPointSelected = onPointSelected,
                            onRefresh = onRefresh,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun EngagementContent(
    state: EngagementUiState,
    engagement: Engagement,
    onPeriodSelected: (EngagementPeriod) -> Unit,
    onPointSelected: (Int?) -> Unit,
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
                .testTag(EngagementTestTags.CONTENT),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            PeriodSelector(selected = state.period, onSelect = onPeriodSelected)
            EngagementHeadlineCard(metrics = engagement.metrics)
            EngagementTrendCard(
                trend = engagement.trend,
                chartType = state.chartType,
                selectedIndex = state.selectedPoint,
                onPointSelected = onPointSelected,
            )
            EngagementBreakdown(metrics = engagement.metrics)
        }
    }
}

@Composable
private fun PeriodSelector(
    selected: EngagementPeriod,
    onSelect: (EngagementPeriod) -> Unit,
    modifier: Modifier = Modifier,
) {
    FlowRow(
        modifier = modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        EngagementPeriod.entries.forEach { period ->
            FilterChip(
                selected = period == selected,
                onClick = { onSelect(period) },
                label = { Text(stringResource(period.labelRes)) },
                modifier = Modifier.testTag(EngagementTestTags.PERIOD_PREFIX + period.days),
            )
        }
    }
}

@Composable
private fun EngagementHeadlineCard(metrics: EngagementMetrics) {
    val rateText = formatEngagementPercent(metrics.engagementRateDisplay)
    val deltaText = formatEngagementDelta(metrics.trendDeltaDisplay)
    val trendDescription = stringResource(trendLabelRes(metrics.trend))
    val headlineCd = stringResource(R.string.engagement_headline_cd, rateText, trendDescription, deltaText)
    ElevatedCard(Modifier.fillMaxWidth()) {
        Column(
            Modifier
                .padding(16.dp)
                .clearAndSetSemantics { contentDescription = headlineCd },
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                text = stringResource(R.string.engagement_headline_label),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    text = rateText,
                    style = MaterialTheme.typography.headlineMedium,
                    modifier = Modifier.testTag(EngagementTestTags.HEADLINE),
                )
                TrendChip(trend = metrics.trend, deltaText = deltaText)
            }
        }
    }
}

@Composable
private fun TrendChip(trend: Trend, deltaText: String) {
    val icon: ImageVector = when (trend) {
        Trend.UP -> Icons.Outlined.ArrowUpward
        Trend.DOWN -> Icons.Outlined.ArrowDownward
        else -> Icons.Outlined.Remove
    }
    AssistChip(
        onClick = {},
        enabled = false,
        label = { Text(deltaText) },
        leadingIcon = { Icon(icon, contentDescription = null) },
        colors = AssistChipDefaults.assistChipColors(),
        modifier = Modifier.testTag(EngagementTestTags.TREND_CHIP),
    )
}

@Composable
private fun EngagementTrendCard(
    trend: List<EngagementTrendPoint>,
    chartType: EngagementChartType,
    selectedIndex: Int?,
    onPointSelected: (Int?) -> Unit,
) {
    // Plot the rate in basis points (integer) so the zero-anchored geometry stays divide-free.
    val geometry = remember(trend) {
        ChartGeometryCore.compute(trend.map { it.engagementRateBps.toLong() })
    }
    ElevatedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                text = stringResource(R.string.engagement_trend_title),
                style = MaterialTheme.typography.titleSmall,
            )
            if (geometry.isEmpty) {
                Text(
                    text = stringResource(R.string.engagement_trend_no_data),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                TestLogonSeriesChart(
                    geometry = geometry,
                    chartType = when (chartType) {
                        EngagementChartType.LINE -> SeriesChartType.LINE
                        EngagementChartType.BAR -> SeriesChartType.BAR
                    },
                    lineColor = MaterialTheme.colorScheme.primary,
                    gridColor = MaterialTheme.colorScheme.outlineVariant,
                    fillColor = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.35f),
                    selectedColor = MaterialTheme.colorScheme.tertiary,
                    selectedIndex = selectedIndex,
                    onPointSelected = onPointSelected,
                    modifier = Modifier.testTag(EngagementTestTags.CHART),
                )
                val selected = selectedIndex?.let { trend.getOrNull(it) }
                if (selected != null) {
                    Text(
                        text = "${selected.rawDate}: " + formatEngagementPercent(selected.engagementRate),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            }
        }
    }
}

@Composable
private fun EngagementBreakdown(metrics: EngagementMetrics) {
    ElevatedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                text = stringResource(R.string.engagement_breakdown_title),
                style = MaterialTheme.typography.titleSmall,
            )
            MetricRow("likes", stringResource(R.string.engagement_row_likes), metrics.likes)
            MetricRow("comments", stringResource(R.string.engagement_row_comments), metrics.comments)
            MetricRow("shares", stringResource(R.string.engagement_row_shares), metrics.shares)
            MetricRow("tips", stringResource(R.string.engagement_row_tips), metrics.tips)
            MetricRow("total", stringResource(R.string.engagement_row_total), metrics.totalInteractions)
            MetricRow("followers", stringResource(R.string.engagement_row_followers), metrics.followerCount)
            MetricRow("posts", stringResource(R.string.engagement_row_posts), metrics.postsInPeriod)
        }
    }
}

@Composable
private fun MetricRow(tag: String, label: String, value: Int) {
    val valueText = formatEngagementCount(value)
    Row(
        Modifier
            .fillMaxWidth()
            .testTag(EngagementTestTags.ROW_PREFIX + tag)
            .clearAndSetSemantics { contentDescription = "$label, $valueText" },
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(label, style = MaterialTheme.typography.bodyMedium)
        Text(valueText, style = MaterialTheme.typography.bodyMedium)
    }
}

private fun trendLabelRes(trend: Trend): Int = when (trend) {
    Trend.UP -> R.string.engagement_trend_up
    Trend.DOWN -> R.string.engagement_trend_down
    Trend.FLAT -> R.string.engagement_trend_flat
    Trend.UNKNOWN -> R.string.engagement_trend_unknown
}
