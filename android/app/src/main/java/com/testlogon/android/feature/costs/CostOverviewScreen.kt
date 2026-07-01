@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.costs

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.BarChart
import androidx.compose.material.icons.outlined.NotificationsActive
import androidx.compose.material.icons.outlined.Savings
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.OfflineBanner
import com.testlogon.android.data.costs.CostOverview
import com.testlogon.android.data.costs.formatCents

@Composable
fun CostOverviewRoute(
    onBack: () -> Unit,
    onSessionExpired: () -> Unit,
    onOpenBreakdown: () -> Unit,
    onOpenBudgets: () -> Unit,
    onOpenAlerts: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: CostOverviewViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    androidx.compose.runtime.LaunchedEffect(state.phase) {
        if (state.phase == CostsPhase.SessionExpired) onSessionExpired()
    }
    Scaffold(
        modifier = modifier.testTag(CostsTestTags.OVERVIEW_SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.costs_overview_title)) },
                navigationIcon = { CostsBackIcon(onBack, "costs_overview_back") },
            )
        },
    ) { padding ->
        Column(modifier = Modifier.padding(padding).fillMaxSize()) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedButton(onClick = onOpenBreakdown, modifier = Modifier.weight(1f)) {
                    Icon(Icons.Outlined.BarChart, null, modifier = Modifier.size(18.dp))
                    Text(stringResource(R.string.costs_breakdown), modifier = Modifier.padding(start = 4.dp))
                }
                OutlinedButton(onClick = onOpenBudgets, modifier = Modifier.weight(1f)) {
                    Icon(Icons.Outlined.Savings, null, modifier = Modifier.size(18.dp))
                    Text(stringResource(R.string.costs_budgets), modifier = Modifier.padding(start = 4.dp))
                }
                OutlinedButton(onClick = onOpenAlerts, modifier = Modifier.weight(1f)) {
                    Icon(Icons.Outlined.NotificationsActive, null, modifier = Modifier.size(18.dp))
                    Text(stringResource(R.string.costs_alerts), modifier = Modifier.padding(start = 4.dp))
                }
            }
            CostsPhaseScaffold(state.phase, state.errorMessage, viewModel::onRetry) {
                PullToRefreshBox(
                    isRefreshing = state.isRefreshing,
                    onRefresh = viewModel::onRefresh,
                    modifier = Modifier.fillMaxSize(),
                ) {
                    if (state.phase == CostsPhase.Empty) {
                        EmptyState(
                            title = stringResource(R.string.costs_empty_title),
                            body = stringResource(R.string.costs_empty_body),
                            modifier = Modifier.testTag(CostsTestTags.EMPTY),
                        )
                    } else {
                        OverviewContent(
                            overview = state.overview,
                            isStale = state.isStale,
                            onOpenAlerts = onOpenAlerts,
                            onRetry = viewModel::onRetry,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun OverviewContent(
    overview: CostOverview?,
    isStale: Boolean,
    onOpenAlerts: () -> Unit,
    onRetry: () -> Unit,
) {
    val ov = overview ?: return
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (isStale) item { OfflineBanner(onRetry = onRetry) }
        if (ov.unacknowledgedAlerts > 0) {
            item {
                Card(
                    modifier = Modifier.fillMaxWidth().testTag(CostsTestTags.ALERT_BANNER),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(16.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            text = stringResource(R.string.costs_unacked_alerts, ov.unacknowledgedAlerts),
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.Medium,
                        )
                        OutlinedButton(onClick = onOpenAlerts) {
                            Text(stringResource(R.string.costs_view_alerts))
                        }
                    }
                }
            }
        }
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                SummaryTile(stringResource(R.string.costs_today), ov.today.totalCents, Modifier.weight(1f), "summary_today")
                SummaryTile(stringResource(R.string.costs_this_week), ov.weekCents, Modifier.weight(1f), "summary_week")
                SummaryTile(stringResource(R.string.costs_this_month), ov.monthCents, Modifier.weight(1f), "summary_month")
            }
        }
        item {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    SectionHeader(stringResource(R.string.costs_by_agent_type_today))
                    if (ov.today.byAgentType.isEmpty()) {
                        Text(
                            stringResource(R.string.costs_no_spend_today),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    } else {
                        ov.today.byAgentType.forEach { (type, cents) ->
                            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                Text(type, style = MaterialTheme.typography.bodyMedium)
                                Text(formatCents(cents), style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium)
                            }
                        }
                    }
                }
            }
        }
        item {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    SectionHeader(stringResource(R.string.costs_weekly_trend))
                    if (ov.weeks.isEmpty()) {
                        Text(
                            stringResource(R.string.costs_no_cost_data),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    } else {
                        ov.weeks.takeLast(8).forEach { w ->
                            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                Text(w.weekStart, style = MaterialTheme.typography.bodySmall)
                                Text(formatCents(w.totalCents), style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.Medium)
                            }
                        }
                    }
                }
            }
        }
        if (ov.optimizations.isNotEmpty()) {
            item { SectionHeader(stringResource(R.string.costs_optimizations)) }
            items(ov.optimizations, key = { it.title }) { opt ->
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(opt.title, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                        Text(opt.description, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        if (opt.potentialSavingsCents > 0) {
                            Text(
                                stringResource(R.string.costs_potential_savings, formatCents(opt.potentialSavingsCents)),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.primary,
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun SummaryTile(label: String, cents: Long, modifier: Modifier, tag: String) {
    Card(modifier = modifier.testTag(tag)) {
        Column(Modifier.padding(12.dp)) {
            Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(formatCents(cents), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
        }
    }
}
