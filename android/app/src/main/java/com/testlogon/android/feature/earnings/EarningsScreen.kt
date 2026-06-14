@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.testlogon.android.feature.earnings

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
import androidx.compose.material.icons.outlined.BarChart
import androidx.compose.material.icons.outlined.ShowChart
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
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
import com.testlogon.android.core.ui.state.OfflineBanner
import com.testlogon.android.data.earnings.EarningsDashboard
import com.testlogon.android.data.earnings.EarningsRange
import com.testlogon.android.feature.earnings.chart.EarningsChartCanvas
import com.testlogon.android.feature.earnings.chart.EarningsChartGeometry

/** AND-252 — stable testTags for the earnings dashboard screen. */
object EarningsTestTags {
    const val SCREEN = "earnings_screen"
    const val CONTENT = "earnings_content"
    const val LOADING = "earnings_loading"
    const val EMPTY = "earnings_empty"
    const val ERROR = "earnings_error"
    const val OFFLINE = "earnings_offline"
    const val CHART = "earnings_chart"
    const val RANGE_PREFIX = "earnings_range_"
    const val CHART_TOGGLE = "earnings_chart_toggle"
    const val STALE_BANNER = "earnings_stale_banner"
    const val PER_CONTENT_LINK = "earnings_per_content_link"
}

/** AND-252 — route-level earnings dashboard entry (reachable from the More hub). */
@Composable
fun EarningsRoute(
    onBack: () -> Unit,
    onOpenPerContent: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: EarningsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is EarningsEffect.ShowMessage ->
                    snackbarHostState.showSnackbar(context.getString(effect.resId))
            }
        }
    }

    EarningsScreen(
        state = state,
        onBack = onBack,
        onRangeSelected = viewModel::onRangeSelected,
        onChartTypeToggled = viewModel::onChartTypeToggled,
        onPointSelected = viewModel::onPointSelected,
        onRefresh = viewModel::onRefresh,
        onRetry = viewModel::onRetry,
        onOpenPerContent = onOpenPerContent,
        snackbarHostState = snackbarHostState,
        modifier = modifier,
    )
}

@Composable
fun EarningsScreen(
    state: EarningsUiState,
    onBack: () -> Unit,
    onRangeSelected: (EarningsRange) -> Unit,
    onChartTypeToggled: () -> Unit,
    onPointSelected: (Int?) -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onOpenPerContent: () -> Unit,
    modifier: Modifier = Modifier,
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
) {
    Scaffold(
        modifier = modifier.testTag(EarningsTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.earnings_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("earnings_back")) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
                actions = {
                    IconButton(onClick = onChartTypeToggled, modifier = Modifier.testTag(EarningsTestTags.CHART_TOGGLE)) {
                        val isLine = state.chartType == ChartType.LINE
                        Icon(
                            imageVector = if (isLine) Icons.Outlined.BarChart else Icons.Outlined.ShowChart,
                            contentDescription = stringResource(
                                if (isLine) R.string.earnings_chart_show_bars else R.string.earnings_chart_show_line,
                            ),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (state.phase) {
                EarningsUiState.Phase.Loading ->
                    LoadingState(
                        message = stringResource(R.string.earnings_loading),
                        modifier = Modifier.testTag(EarningsTestTags.LOADING),
                    )

                EarningsUiState.Phase.Error ->
                    ErrorState(
                        message = state.errorMessage ?: stringResource(R.string.earnings_error_generic),
                        onRetry = onRetry,
                        modifier = Modifier.testTag(EarningsTestTags.ERROR),
                    )

                EarningsUiState.Phase.Offline ->
                    EmptyState(
                        title = stringResource(R.string.earnings_offline_title),
                        body = stringResource(R.string.earnings_offline_body),
                        actionLabel = stringResource(R.string.action_retry),
                        onAction = onRetry,
                        modifier = Modifier.testTag(EarningsTestTags.OFFLINE),
                    )

                EarningsUiState.Phase.Empty ->
                    Column(Modifier.fillMaxSize()) {
                        RangeSelector(selected = state.range, onSelect = onRangeSelected)
                        EmptyState(
                            title = stringResource(R.string.earnings_empty_title),
                            body = stringResource(R.string.earnings_empty_body),
                            modifier = Modifier.testTag(EarningsTestTags.EMPTY),
                        )
                    }

                EarningsUiState.Phase.Content -> {
                    val dashboard = state.dashboard
                    if (dashboard == null) {
                        EmptyState(
                            title = stringResource(R.string.earnings_empty_title),
                            modifier = Modifier.testTag(EarningsTestTags.EMPTY),
                        )
                    } else {
                        EarningsContent(
                            state = state,
                            dashboard = dashboard,
                            onRangeSelected = onRangeSelected,
                            onPointSelected = onPointSelected,
                            onRefresh = onRefresh,
                            onOpenPerContent = onOpenPerContent,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun EarningsContent(
    state: EarningsUiState,
    dashboard: EarningsDashboard,
    onRangeSelected: (EarningsRange) -> Unit,
    onPointSelected: (Int?) -> Unit,
    onRefresh: () -> Unit,
    onOpenPerContent: () -> Unit,
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
                .testTag(EarningsTestTags.CONTENT),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            if (state.isStale) {
                OfflineBanner(
                    message = stringResource(R.string.earnings_stale_banner),
                    modifier = Modifier.testTag(EarningsTestTags.STALE_BANNER),
                )
            }

            RangeSelector(selected = state.range, onSelect = onRangeSelected)

            TotalsRow(quickStats = dashboard.quickStats, periodTotal = dashboard.summary.total)

            EarningsChartCard(
                series = dashboard.summary.series,
                chartType = state.chartType,
                selectedIndex = state.selectedPoint,
                currency = dashboard.currency,
                onPointSelected = onPointSelected,
            )

            BreakdownList(breakdown = dashboard.summary.breakdown)

            TextButton(
                onClick = onOpenPerContent,
                modifier = Modifier.testTag(EarningsTestTags.PER_CONTENT_LINK),
            ) {
                Text(stringResource(R.string.earnings_per_content_cta))
            }
        }
    }
}

@Composable
private fun RangeSelector(
    selected: EarningsRange,
    onSelect: (EarningsRange) -> Unit,
    modifier: Modifier = Modifier,
) {
    FlowRow(
        modifier = modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        EarningsRange.entries.forEach { range ->
            FilterChip(
                selected = range == selected,
                onClick = { onSelect(range) },
                label = { Text(rangeLabel(range)) },
                modifier = Modifier.testTag(EarningsTestTags.RANGE_PREFIX + range.apiKey),
            )
        }
    }
}

@Composable
private fun rangeLabel(range: EarningsRange): String = when (range) {
    EarningsRange.D7 -> stringResource(R.string.earnings_range_7d)
    EarningsRange.D30 -> stringResource(R.string.earnings_range_30d)
    EarningsRange.D90 -> stringResource(R.string.earnings_range_90d)
    EarningsRange.Y1 -> stringResource(R.string.earnings_range_1y)
    EarningsRange.ALL -> stringResource(R.string.earnings_range_all)
}

@Composable
private fun TotalsRow(
    quickStats: com.testlogon.android.data.earnings.EarningsQuickStats,
    periodTotal: com.testlogon.android.data.earnings.EarningsMoney,
) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            KpiCard(
                label = stringResource(R.string.earnings_kpi_all_time),
                value = formatEarningsMoney(quickStats.allTime.cents, quickStats.allTime.currency),
                modifier = Modifier.weight(1f),
            )
            KpiCard(
                label = stringResource(R.string.earnings_kpi_period),
                value = formatEarningsMoney(periodTotal.cents, periodTotal.currency),
                modifier = Modifier.weight(1f),
            )
        }
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            KpiCard(
                label = stringResource(R.string.earnings_kpi_this_month),
                value = formatEarningsMoney(quickStats.thisMonth.cents, quickStats.thisMonth.currency),
                modifier = Modifier.weight(1f),
            )
            KpiCard(
                label = stringResource(R.string.earnings_kpi_pending),
                value = formatEarningsMoney(quickStats.pendingPayout.cents, quickStats.pendingPayout.currency),
                modifier = Modifier.weight(1f),
            )
        }
    }
}

@Composable
private fun KpiCard(label: String, value: String, modifier: Modifier = Modifier) {
    val cd = "$label: $value"
    androidx.compose.material3.ElevatedCard(modifier = modifier.clearAndSetSemantics { contentDescription = cd }) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                text = label,
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(text = value, style = MaterialTheme.typography.titleMedium)
        }
    }
}

@Composable
private fun EarningsChartCard(
    series: List<com.testlogon.android.data.earnings.EarningsSeriesPoint>,
    chartType: ChartType,
    selectedIndex: Int?,
    currency: String,
    onPointSelected: (Int?) -> Unit,
) {
    val geometry = remember(series) { EarningsChartGeometry.compute(series.map { it.totalCents }) }
    androidx.compose.material3.ElevatedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                text = stringResource(R.string.earnings_chart_title),
                style = MaterialTheme.typography.titleSmall,
            )
            if (geometry.isEmpty) {
                Text(
                    text = stringResource(R.string.earnings_chart_no_data),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                EarningsChartCanvas(
                    geometry = geometry,
                    chartType = chartType,
                    lineColor = MaterialTheme.colorScheme.primary,
                    gridColor = MaterialTheme.colorScheme.outlineVariant,
                    fillColor = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.35f),
                    selectedColor = MaterialTheme.colorScheme.tertiary,
                    selectedIndex = selectedIndex,
                    onPointSelected = onPointSelected,
                    modifier = Modifier.testTag(EarningsTestTags.CHART),
                )
                val selected = selectedIndex?.let { series.getOrNull(it) }
                if (selected != null) {
                    Text(
                        text = "${selected.rawDate}: " +
                            formatEarningsMoney(selected.totalCents, currency),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            }
        }
    }
}

@Composable
private fun BreakdownList(breakdown: com.testlogon.android.data.earnings.EarningsBreakdown) {
    val rows = remember(breakdown) { breakdown.toRows() }
    if (rows.isEmpty()) return
    androidx.compose.material3.ElevatedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                text = stringResource(R.string.earnings_breakdown_title),
                style = MaterialTheme.typography.titleSmall,
            )
            rows.forEach { row ->
                val label = sourceLabel(row.source)
                val amount = formatEarningsMoney(row.cents, breakdown.currencyCode)
                Row(
                    Modifier
                        .fillMaxWidth()
                        .clearAndSetSemantics { contentDescription = "$label, $amount, ${row.sharePct}%" },
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(label, style = MaterialTheme.typography.bodyMedium)
                    Text(
                        text = "$amount  ·  ${row.sharePct}%",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            }
        }
    }
}

@Composable
private fun sourceLabel(source: EarningsSource): String = when (source) {
    EarningsSource.SUBSCRIPTIONS -> stringResource(R.string.earnings_source_subscriptions)
    EarningsSource.TIPS -> stringResource(R.string.earnings_source_tips)
    EarningsSource.UNLOCKS -> stringResource(R.string.earnings_source_unlocks)
    EarningsSource.VOD_PURCHASES -> stringResource(R.string.earnings_source_vod_purchases)
    EarningsSource.OTHER -> stringResource(R.string.earnings_source_other)
}
