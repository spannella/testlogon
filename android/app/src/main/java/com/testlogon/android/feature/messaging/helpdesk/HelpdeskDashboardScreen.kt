@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.testlogon.android.feature.messaging.helpdesk

import android.text.format.DateUtils
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.helpdesk.HelpdeskMetrics
import com.testlogon.android.data.messaging.helpdesk.HelpdeskQueueItem

/** AND-377 — stable testTags for the helpdesk dashboard. */
object HelpdeskDashboardTestTags {
    const val SCREEN = "helpdesk_dashboard_screen"
    const val LOADING = "helpdesk_dashboard_loading"
    const val CONTENT = "helpdesk_dashboard_content"
    const val EMPTY = "helpdesk_dashboard_empty"
    const val ACCESS_DENIED = "helpdesk_dashboard_access_denied"
    const val ERROR = "helpdesk_dashboard_error"
    const val RETRY = "helpdesk_dashboard_retry"
    const val STALE_BANNER = "helpdesk_dashboard_stale_banner"
    const val METRICS_GRID = "helpdesk_dashboard_metrics_grid"
    const val METRIC_CARD = "helpdesk_dashboard_metric_card"
    const val VIEW_FULL_QUEUE = "helpdesk_dashboard_view_full_queue"
    const val PREVIEW_ROW = "helpdesk_dashboard_preview_row"
}

/**
 * AND-377 — route-level helpdesk agent dashboard. Renders the derived metric grid + an embedded queue
 * preview for agents (queue 200); non-agents (queue 403) see [HelpdeskDashboardUiState.AccessDenied].
 * "View full queue" invokes [onOpenFullQueue]; a preview row invokes [onOpenConversation].
 */
@Composable
fun HelpdeskDashboardScreen(
    onOpenFullQueue: () -> Unit,
    onOpenConversation: (conversationId: String) -> Unit,
    viewModel: HelpdeskDashboardViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val isRefreshing by viewModel.isRefreshing.collectAsStateWithLifecycle()
    val queuePreview by viewModel.queuePreview.collectAsStateWithLifecycle()

    Scaffold(
        modifier = Modifier.testTag(HelpdeskDashboardTestTags.SCREEN),
        topBar = { TopAppBar(title = { Text(stringResource(R.string.helpdesk_dashboard_title)) }) },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (val s = state) {
                HelpdeskDashboardUiState.Loading ->
                    Box(Modifier.fillMaxSize(), Alignment.Center) {
                        CircularProgressIndicator(Modifier.testTag(HelpdeskDashboardTestTags.LOADING))
                    }
                HelpdeskDashboardUiState.AccessDenied ->
                    CenteredMessage(
                        text = stringResource(R.string.helpdesk_dashboard_access_denied),
                        tag = HelpdeskDashboardTestTags.ACCESS_DENIED,
                    )
                HelpdeskDashboardUiState.Empty ->
                    PullToRefreshBox(
                        isRefreshing = isRefreshing,
                        onRefresh = viewModel::refresh,
                        modifier = Modifier.fillMaxSize(),
                    ) {
                        CenteredMessage(
                            text = stringResource(R.string.helpdesk_dashboard_empty),
                            tag = HelpdeskDashboardTestTags.EMPTY,
                        )
                    }
                is HelpdeskDashboardUiState.Error ->
                    Column(
                        Modifier.fillMaxSize().padding(24.dp).testTag(HelpdeskDashboardTestTags.ERROR),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.Center,
                    ) {
                        Text(s.message, style = MaterialTheme.typography.bodyLarge)
                        Spacer(Modifier.size(12.dp))
                        if (s.retryable) {
                            TextButton(
                                onClick = viewModel::retry,
                                modifier = Modifier.testTag(HelpdeskDashboardTestTags.RETRY),
                            ) {
                                Text(stringResource(R.string.action_retry))
                            }
                        }
                    }
                is HelpdeskDashboardUiState.Content ->
                    PullToRefreshBox(
                        isRefreshing = isRefreshing,
                        onRefresh = viewModel::refresh,
                        modifier = Modifier.fillMaxSize(),
                    ) {
                        DashboardContent(
                            content = s,
                            queuePreview = queuePreview,
                            onOpenFullQueue = onOpenFullQueue,
                            onOpenConversation = onOpenConversation,
                        )
                    }
            }
        }
    }
}

@Composable
private fun DashboardContent(
    content: HelpdeskDashboardUiState.Content,
    queuePreview: List<HelpdeskQueueItem>,
    onOpenFullQueue: () -> Unit,
    onOpenConversation: (String) -> Unit,
) {
    LazyColumn(
        Modifier.fillMaxSize().testTag(HelpdeskDashboardTestTags.CONTENT),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (content.isStale) {
            item { StaleBanner(content.cachedAtEpochSeconds) }
        }
        item { MetricsGrid(content.metrics) }
        item {
            Row(
                Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = stringResource(R.string.helpdesk_dashboard_queue_section),
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.weight(1f),
                )
                TextButton(
                    onClick = onOpenFullQueue,
                    modifier = Modifier.testTag(HelpdeskDashboardTestTags.VIEW_FULL_QUEUE),
                ) {
                    Text(stringResource(R.string.helpdesk_dashboard_view_full_queue))
                }
            }
        }
        if (queuePreview.isEmpty()) {
            item {
                Text(
                    text = stringResource(R.string.helpdesk_queue_empty),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        } else {
            items(queuePreview, key = { it.conversationId }) { item ->
                PreviewRow(item = item, onClick = { onOpenConversation(item.conversationId) })
            }
        }
    }
}

@Composable
private fun MetricsGrid(metrics: HelpdeskMetrics) {
    val dash = stringResource(R.string.helpdesk_dashboard_metric_none)
    FlowRow(
        modifier = Modifier.fillMaxWidth().testTag(HelpdeskDashboardTestTags.METRICS_GRID),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        MetricCard(
            label = stringResource(R.string.helpdesk_dashboard_metric_open),
            value = metrics.openCount.toString(),
            delta = metrics.deltas["open"],
        )
        MetricCard(
            label = stringResource(R.string.helpdesk_dashboard_metric_unassigned),
            value = metrics.unassignedCount.toString(),
            delta = metrics.deltas["unassigned"],
        )
        MetricCard(
            label = stringResource(R.string.helpdesk_dashboard_metric_assigned_me),
            value = metrics.assignedToMeCount.toString(),
            delta = metrics.deltas["assigned_to_me"],
        )
        MetricCard(
            label = stringResource(R.string.helpdesk_dashboard_metric_sla),
            value = metrics.slaAtRiskCount.toString(),
            delta = metrics.deltas["sla_at_risk"],
        )
        // Time/throughput metrics: no client source in Q1 mode -> render as a dash, never crash.
        MetricCard(
            label = stringResource(R.string.helpdesk_dashboard_metric_avg_first_response),
            value = metrics.avgFirstResponseSeconds?.let(::formatDuration) ?: dash,
            delta = null,
        )
        MetricCard(
            label = stringResource(R.string.helpdesk_dashboard_metric_avg_resolution),
            value = metrics.avgResolutionSeconds?.let(::formatDuration) ?: dash,
            delta = null,
        )
        MetricCard(
            label = stringResource(R.string.helpdesk_dashboard_metric_resolved_me_today),
            value = metrics.resolvedByMeToday?.toString() ?: dash,
            delta = metrics.deltas["resolved_by_me_today"],
        )
    }
}

@Composable
private fun MetricCard(label: String, value: String, delta: Int?) {
    val deltaText = delta?.let {
        if (it >= 0) {
            stringResource(R.string.helpdesk_dashboard_delta_up, it)
        } else {
            stringResource(R.string.helpdesk_dashboard_delta_down, -it)
        }
    }
    val cd = if (deltaText != null) {
        stringResource(R.string.helpdesk_dashboard_card_cd_with_delta, label, value, deltaText)
    } else {
        stringResource(R.string.helpdesk_dashboard_card_cd, label, value)
    }
    Card(
        modifier = Modifier
            .size(width = 160.dp, height = 96.dp)
            .testTag(HelpdeskDashboardTestTags.METRIC_CARD)
            .clearAndSetSemantics { contentDescription = cd },
    ) {
        Column(Modifier.padding(12.dp)) {
            Text(
                text = label,
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
            Spacer(Modifier.size(4.dp))
            Text(text = value, style = MaterialTheme.typography.headlineSmall)
            deltaText?.let {
                Text(
                    text = it,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.primary,
                )
            }
        }
    }
}

@Composable
private fun StaleBanner(cachedAtEpochSeconds: Long?) {
    val relative = cachedAtEpochSeconds?.takeIf { it > 0L }?.let {
        DateUtils.getRelativeTimeSpanString(
            it * 1000L,
            System.currentTimeMillis(),
            DateUtils.MINUTE_IN_MILLIS,
        ).toString()
    }
    val text = if (relative != null) {
        stringResource(R.string.helpdesk_dashboard_stale_updated, relative)
    } else {
        stringResource(R.string.helpdesk_dashboard_stale)
    }
    Card(Modifier.fillMaxWidth().testTag(HelpdeskDashboardTestTags.STALE_BANNER)) {
        Text(
            text = text,
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.padding(12.dp),
        )
    }
}

@Composable
private fun PreviewRow(item: HelpdeskQueueItem, onClick: () -> Unit) {
    Column(
        Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(vertical = 8.dp)
            .testTag(HelpdeskDashboardTestTags.PREVIEW_ROW),
    ) {
        Text(
            text = item.title ?: stringResource(R.string.helpdesk_queue_untitled),
            style = MaterialTheme.typography.titleSmall,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
        item.preview?.let {
            Text(
                text = it,
                style = MaterialTheme.typography.bodySmall,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun CenteredMessage(text: String, tag: String) {
    Box(Modifier.fillMaxSize().testTag(tag), Alignment.Center) {
        Text(text, style = MaterialTheme.typography.bodyLarge)
    }
}

/** Format a duration in seconds as `Xm` or `Xh Ym` (spec FR-2). Pure; safe for non-Composable use. */
private fun formatDuration(seconds: Long): String {
    val totalMinutes = seconds / 60L
    val hours = totalMinutes / 60L
    val minutes = totalMinutes % 60L
    return if (hours > 0L) "${hours}h ${minutes}m" else "${minutes}m"
}
