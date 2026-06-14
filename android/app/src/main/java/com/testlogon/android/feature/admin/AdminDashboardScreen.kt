@file:OptIn(
    androidx.compose.material3.ExperimentalMaterial3Api::class,
    androidx.compose.foundation.layout.ExperimentalLayoutApi::class,
)

package com.testlogon.android.feature.admin

import android.text.format.DateUtils
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.ErrorOutline
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.Warning
import androidx.compose.material3.Card
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.admin.AdminAlert
import com.testlogon.android.core.model.admin.AdminDashboard
import com.testlogon.android.core.model.admin.AdminMetric
import com.testlogon.android.core.model.admin.AlertSeverity
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.StaleBanner
import com.testlogon.android.data.admin.METRIC_TOTAL_JOBS
import com.testlogon.android.data.admin.METRIC_UNHEALTHY_JOBS
import com.testlogon.android.data.admin.METRIC_WEBHOOK_DEAD_LETTER
import com.testlogon.android.data.admin.METRIC_WEBHOOK_DELIVERIES
import com.testlogon.android.data.admin.METRIC_WEBHOOK_ENABLED
import com.testlogon.android.data.admin.METRIC_WEBHOOK_ENDPOINTS
import com.testlogon.android.data.admin.METRIC_WEBHOOK_FAILED
import com.testlogon.android.data.admin.METRIC_WEBHOOK_SUCCESS

/** AND-403 - stable testTags for the read-only admin dashboard screen (UI tests assert presence + ABSENCE). */
object AdminDashboardTestTags {
    const val SCREEN = "admin_dashboard_screen"
    const val REFRESH = "admin_dashboard_refresh"
    const val METRICS = "admin_dashboard_metrics"
    const val ALERTS = "admin_dashboard_alerts"
    const val EMPTY = "admin_dashboard_empty"
    const val FORBIDDEN = "admin_dashboard_forbidden"
    const val ERROR_RETRY = "admin_dashboard_error_retry"
    const val NO_ALERTS = "admin_dashboard_no_alerts"

    fun metric(key: String) = "admin_metric_$key"
    fun alert(id: String) = "admin_alert_$id"
}

/**
 * AND-403 - route-level entry for the READ-ONLY admin dashboard. Collects the state and wires Refresh / Retry /
 * Back. Role gating is enforced by the ViewModel (verified non-admin -> Forbidden, no fetch) + the backend 403;
 * the navigation layer registers this route in the authenticated graph and the screen self-gates on Forbidden
 * (the established admin-screen pattern - cf. helpdesk dashboard / billing config). There is NO mutation
 * affordance anywhere (AC-3).
 */
@Composable
fun AdminDashboardRoute(
    onBack: () -> Unit,
    viewModel: AdminDashboardViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    AdminDashboardScreen(
        state = state,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
        onBack = onBack,
    )
}

/** AND-403 - stateless read-only admin dashboard: metric tiles + alerts list, with loading/empty/error/403. */
@Composable
fun AdminDashboardScreen(
    state: AdminDashboardUiState,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(AdminDashboardTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.admin_dashboard_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.admin_dashboard_back),
                        )
                    }
                },
                actions = {
                    // Refresh is the ONLY top-bar action (read-only surface - no acknowledge/dismiss/edit).
                    if (state is AdminDashboardUiState.Content) {
                        IconButton(
                            onClick = onRefresh,
                            modifier = Modifier.testTag(AdminDashboardTestTags.REFRESH),
                        ) {
                            Icon(
                                Icons.Outlined.Refresh,
                                contentDescription = stringResource(R.string.admin_dashboard_refresh),
                            )
                        }
                    }
                },
            )
        },
    ) { padding ->
        val isRefreshing = (state as? AdminDashboardUiState.Content)?.isRefreshing == true
        PullToRefreshBox(
            isRefreshing = isRefreshing,
            onRefresh = onRefresh,
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            when (state) {
                is AdminDashboardUiState.Loading -> LoadingState()

                is AdminDashboardUiState.Empty ->
                    EmptyState(
                        modifier = Modifier.testTag(AdminDashboardTestTags.EMPTY),
                        title = stringResource(R.string.admin_dashboard_empty_title),
                        body = stringResource(R.string.admin_dashboard_empty_body),
                        imageVector = Icons.Outlined.Security,
                    )

                is AdminDashboardUiState.Forbidden ->
                    EmptyState(
                        modifier = Modifier.testTag(AdminDashboardTestTags.FORBIDDEN),
                        title = stringResource(R.string.admin_dashboard_forbidden_title),
                        body = stringResource(R.string.admin_dashboard_forbidden_body),
                        imageVector = Icons.Outlined.Lock,
                        actionLabel = stringResource(R.string.admin_dashboard_back),
                        onAction = onBack,
                    )

                is AdminDashboardUiState.Error ->
                    ErrorState(
                        modifier = Modifier.testTag(AdminDashboardTestTags.ERROR_RETRY),
                        message = errorMessage(state.error),
                        onRetry = onRetry,
                    )

                is AdminDashboardUiState.Content ->
                    AdminDashboardContent(state = state, onRetry = onRetry)
            }
        }
    }
}

@Composable
private fun errorMessage(error: AdminUiError): String = stringResource(
    when (error.type) {
        AdminErrorType.AUTH -> R.string.admin_dashboard_error_auth
        AdminErrorType.SERVER -> R.string.admin_dashboard_error_server
        AdminErrorType.NETWORK -> R.string.admin_dashboard_error_network
    },
)

@Composable
private fun AdminDashboardContent(
    state: AdminDashboardUiState.Content,
    onRetry: () -> Unit,
) {
    val dashboard = state.dashboard
    Column(modifier = Modifier.fillMaxSize()) {
        StaleBanner(stale = state.isStale, refreshing = false, onRetry = onRetry)
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            if (dashboard.metrics.isNotEmpty()) {
                item(key = "metrics_header") {
                    SectionHeader(stringResource(R.string.admin_dashboard_metrics_title))
                }
                item(key = "metrics_grid") { MetricsGrid(dashboard.metrics) }
            }
            item(key = "alerts_header") {
                SectionHeader(stringResource(R.string.admin_dashboard_alerts_title))
            }
            if (dashboard.alerts.isEmpty()) {
                item(key = "alerts_empty") {
                    Text(
                        text = stringResource(R.string.admin_dashboard_no_alerts),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.testTag(AdminDashboardTestTags.NO_ALERTS),
                    )
                }
            } else {
                items(items = dashboard.alerts, key = { it.id }) { alert ->
                    AlertRow(alert)
                }
            }
        }
    }
}

@Composable
private fun SectionHeader(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.titleMedium,
        modifier = Modifier.semantics { heading() },
    )
}

@Composable
private fun MetricsGrid(metrics: List<AdminMetric>) {
    FlowRow(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(AdminDashboardTestTags.METRICS),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        metrics.forEach { metric -> MetricTile(metric) }
    }
}

@Composable
private fun MetricTile(metric: AdminMetric) {
    val label = metricLabel(metric)
    val cd = stringResource(R.string.admin_metric_content_description, label, metric.value)
    Card(
        modifier = Modifier
            .widthIn(min = 140.dp)
            .heightIn(min = 48.dp)
            .testTag(AdminDashboardTestTags.metric(metric.key))
            .semantics(mergeDescendants = true) { contentDescription = cd },
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text = metric.value,
                style = MaterialTheme.typography.headlineSmall,
            )
            Text(
                text = label,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            metric.trend?.let {
                Text(it, style = MaterialTheme.typography.labelSmall)
            }
        }
    }
}

/** Maps a stable metric key to a localised tile label, falling back to the domain English label. */
@Composable
private fun metricLabel(metric: AdminMetric): String {
    val res = when (metric.key) {
        METRIC_TOTAL_JOBS -> R.string.admin_metric_total_jobs
        METRIC_UNHEALTHY_JOBS -> R.string.admin_metric_unhealthy_jobs
        METRIC_WEBHOOK_ENDPOINTS -> R.string.admin_metric_webhook_endpoints
        METRIC_WEBHOOK_ENABLED -> R.string.admin_metric_webhook_enabled
        METRIC_WEBHOOK_DELIVERIES -> R.string.admin_metric_webhook_deliveries
        METRIC_WEBHOOK_SUCCESS -> R.string.admin_metric_webhook_success
        METRIC_WEBHOOK_FAILED -> R.string.admin_metric_webhook_failed
        METRIC_WEBHOOK_DEAD_LETTER -> R.string.admin_metric_webhook_dead_letter
        else -> null
    }
    return res?.let { stringResource(it) } ?: metric.label
}

/**
 * AND-403 - one read-only alert row. Severity is conveyed by ICON + a text LABEL + a Material 3 color (NEVER
 * colour alone - AND-403 §9 / AC-4). A merged contentDescription announces severity label + title + source +
 * relative time (AND-403 §9). There is NO acknowledge / dismiss / resolve affordance (read-only - AC-3).
 */
@Composable
private fun AlertRow(alert: AdminAlert) {
    val severityLabel = stringResource(severityLabelRes(alert.severity))
    val relativeTime = alert.createdAtEpochSeconds?.let { relativeTime(it) }
    val sourceText = alert.source?.let { stringResource(R.string.admin_alert_source, it) }
    val cd = buildAlertContentDescription(severityLabel, alert.title, sourceText, relativeTime)

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .testTag(AdminDashboardTestTags.alert(alert.id))
            .semantics(mergeDescendants = true) { contentDescription = cd },
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Icon(
                imageVector = severityIcon(alert.severity),
                contentDescription = null, // announced via the merged row description
                tint = severityColor(alert.severity),
            )
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Text(
                    text = alert.title,
                    style = MaterialTheme.typography.titleSmall,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    // Severity TEXT label so severity is not colour-only.
                    Text(
                        text = severityLabel,
                        style = MaterialTheme.typography.labelMedium,
                        color = severityColor(alert.severity),
                    )
                    sourceText?.let {
                        Text(
                            text = it,
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
                alert.message?.let {
                    Text(
                        text = it,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 3,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
                relativeTime?.let {
                    Text(
                        text = it,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}

private fun buildAlertContentDescription(
    severityLabel: String,
    title: String,
    source: String?,
    relativeTime: String?,
): String = buildString {
    append(severityLabel)
    append(": ")
    append(title)
    source?.let { append(", "); append(it) }
    relativeTime?.let { append(", "); append(it) }
}

/** Locale-aware relative time (e.g. "5 minutes ago") from an epoch-SECONDS timestamp (AND-403 §9). */
private fun relativeTime(epochSeconds: Long): String = DateUtils.getRelativeTimeSpanString(
    epochSeconds * 1000L,
    System.currentTimeMillis(),
    DateUtils.MINUTE_IN_MILLIS,
).toString()

private fun severityLabelRes(severity: AlertSeverity): Int = when (severity) {
    AlertSeverity.CRITICAL -> R.string.admin_severity_critical
    AlertSeverity.WARNING -> R.string.admin_severity_warning
    AlertSeverity.INFO -> R.string.admin_severity_info
    AlertSeverity.UNKNOWN -> R.string.admin_severity_unknown
}

private fun severityIcon(severity: AlertSeverity): ImageVector = when (severity) {
    AlertSeverity.CRITICAL -> Icons.Outlined.ErrorOutline
    AlertSeverity.WARNING -> Icons.Outlined.Warning
    AlertSeverity.INFO -> Icons.Outlined.Info
    AlertSeverity.UNKNOWN -> Icons.Outlined.Info
}

@Composable
private fun severityColor(severity: AlertSeverity): Color = when (severity) {
    AlertSeverity.CRITICAL -> MaterialTheme.colorScheme.error
    AlertSeverity.WARNING -> MaterialTheme.colorScheme.tertiary
    AlertSeverity.INFO -> MaterialTheme.colorScheme.primary
    AlertSeverity.UNKNOWN -> MaterialTheme.colorScheme.onSurfaceVariant
}
