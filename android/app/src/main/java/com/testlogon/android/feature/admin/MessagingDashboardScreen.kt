@file:OptIn(
    androidx.compose.material3.ExperimentalMaterial3Api::class,
    androidx.compose.foundation.layout.ExperimentalLayoutApi::class,
)

package com.testlogon.android.feature.admin

import android.text.format.DateUtils
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
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
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.ErrorOutline
import androidx.compose.material.icons.outlined.HelpOutline
import androidx.compose.material.icons.outlined.Inbox
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.MarkEmailRead
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material.icons.outlined.Schedule
import androidx.compose.material.icons.outlined.WarningAmber
import androidx.compose.material3.Card
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
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
import com.testlogon.android.core.model.admin.DashboardChannel
import com.testlogon.android.core.model.admin.DashboardMetricCard
import com.testlogon.android.core.model.admin.DeliveryActivity
import com.testlogon.android.core.model.admin.DeliveryStatus
import com.testlogon.android.core.model.admin.MessagingDashboard
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.StaleBanner
import com.testlogon.android.data.admin.METRIC_MSG_BOUNCED
import com.testlogon.android.data.admin.METRIC_MSG_DELIVERED
import com.testlogon.android.data.admin.METRIC_MSG_DELIVERY_RATE
import com.testlogon.android.data.admin.METRIC_MSG_FAILED
import com.testlogon.android.data.admin.METRIC_MSG_SEGMENTS
import com.testlogon.android.data.admin.METRIC_MSG_SENT
import com.testlogon.android.data.admin.METRIC_MSG_SUPPRESSED

/** AND-404 - stable testTags for the read-only email/SMS delivery dashboards (UI tests assert presence + ABSENCE). */
object MessagingDashboardTestTags {
    const val SCREEN = "messaging_dashboard_screen"
    const val REFRESH = "messaging_dashboard_refresh"
    const val LOADING = "dashboard_loading"
    const val CONTENT = "dashboard_content"
    const val METRICS = "dashboard_metrics"
    const val ACTIVITY = "dashboard_activity"
    const val EMPTY = "dashboard_empty"
    const val ERROR = "dashboard_error"
    const val FORBIDDEN = "dashboard_forbidden"
    const val STALE_BANNER = "dashboard_stale_banner"
    const val ACTIVITY_NOTICE = "dashboard_activity_notice"
    const val ACTIVITY_FOOTER = "dashboard_activity_footer"

    fun metric(key: String) = "dashboard_metric_$key"
    fun activityRow(key: String) = "dashboard_activity_$key"
}

/**
 * AND-404 - route entry for the EMAIL delivery dashboard. The channel is passed as a nav arg consumed by the VM
 * via SavedStateHandle; role gating is enforced by the VM (verified non-admin -> Forbidden, no fetch) + the
 * backend 403. There is NO mutation affordance anywhere (read-only - AC2).
 */
@Composable
fun EmailDashboardRoute(
    onBack: () -> Unit,
    viewModel: MessagingDashboardViewModel = hiltViewModel(),
) {
    DashboardRouteContent(
        title = stringResource(R.string.admin_email_dashboard_title),
        viewModel = viewModel,
        onBack = onBack,
    )
}

/** AND-404 - route entry for the SMS delivery dashboard (same generic VM, channel via nav arg). */
@Composable
fun SmsDashboardRoute(
    onBack: () -> Unit,
    viewModel: MessagingDashboardViewModel = hiltViewModel(),
) {
    DashboardRouteContent(
        title = stringResource(R.string.admin_sms_dashboard_title),
        viewModel = viewModel,
        onBack = onBack,
    )
}

@Composable
private fun DashboardRouteContent(
    title: String,
    viewModel: MessagingDashboardViewModel,
    onBack: () -> Unit,
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    MessagingDashboardScreen(
        title = title,
        channel = viewModel.channel,
        state = state,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
        onBack = onBack,
    )
}

/** AND-404 - stateless read-only delivery dashboard: metric tiles + recent-activity list, with all five states. */
@Composable
fun MessagingDashboardScreen(
    title: String,
    channel: DashboardChannel,
    state: MessagingDashboardUiState,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(MessagingDashboardTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(title) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.admin_dashboard_back),
                        )
                    }
                },
                actions = {
                    // Refresh is the ONLY top-bar action (read-only surface - no resend/suppress/edit).
                    if (state is MessagingDashboardUiState.Content) {
                        IconButton(
                            onClick = onRefresh,
                            modifier = Modifier.testTag(MessagingDashboardTestTags.REFRESH),
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
        val isRefreshing = (state as? MessagingDashboardUiState.Content)?.isRefreshing == true
        PullToRefreshBox(
            isRefreshing = isRefreshing,
            onRefresh = onRefresh,
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            when (state) {
                is MessagingDashboardUiState.Loading ->
                    LoadingState(modifier = Modifier.testTag(MessagingDashboardTestTags.LOADING))

                is MessagingDashboardUiState.Empty ->
                    EmptyState(
                        modifier = Modifier.testTag(MessagingDashboardTestTags.EMPTY),
                        title = stringResource(R.string.admin_dashboard_empty_title),
                        body = stringResource(R.string.admin_messaging_dashboard_empty_body),
                        imageVector = Icons.Outlined.Inbox,
                    )

                is MessagingDashboardUiState.Forbidden ->
                    EmptyState(
                        modifier = Modifier.testTag(MessagingDashboardTestTags.FORBIDDEN),
                        title = stringResource(R.string.admin_dashboard_forbidden_title),
                        body = stringResource(R.string.admin_dashboard_forbidden_body),
                        imageVector = Icons.Outlined.Lock,
                        actionLabel = stringResource(R.string.admin_dashboard_back),
                        onAction = onBack,
                    )

                is MessagingDashboardUiState.Error ->
                    ErrorState(
                        modifier = Modifier.testTag(MessagingDashboardTestTags.ERROR),
                        message = errorMessage(state.error),
                        onRetry = onRetry,
                    )

                is MessagingDashboardUiState.Content ->
                    DashboardContent(channel = channel, state = state, onRetry = onRetry)
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
private fun DashboardContent(
    channel: DashboardChannel,
    state: MessagingDashboardUiState.Content,
    onRetry: () -> Unit,
) {
    val dashboard = state.dashboard
    Column(modifier = Modifier.fillMaxSize().testTag(MessagingDashboardTestTags.CONTENT)) {
        StaleBanner(
            stale = state.isStale,
            refreshing = false,
            onRetry = onRetry,
            modifier = Modifier.testTag(MessagingDashboardTestTags.STALE_BANNER),
        )
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            item(key = "metrics_header") {
                SectionHeader(stringResource(R.string.admin_dashboard_metrics_title))
            }
            item(key = "metrics_grid") { MetricsGrid(dashboard.metrics) }

            item(key = "activity_header") {
                SectionHeader(stringResource(R.string.admin_messaging_dashboard_activity_title))
            }
            if (dashboard.activityFailed) {
                item(key = "activity_notice") {
                    InlineNotice(stringResource(R.string.admin_messaging_dashboard_activity_unavailable))
                }
            } else if (dashboard.activity.isEmpty()) {
                item(key = "activity_empty") {
                    Text(
                        text = stringResource(R.string.admin_messaging_dashboard_no_activity),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            } else {
                items(items = dashboard.activity, key = { it.key }) { row ->
                    ActivityRow(channel = channel, row = row)
                }
                item(key = "activity_footer") {
                    Text(
                        text = stringResource(
                            R.string.admin_messaging_dashboard_activity_footer,
                            dashboard.activity.size,
                        ),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.testTag(MessagingDashboardTestTags.ACTIVITY_FOOTER),
                    )
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
private fun InlineNotice(text: String) {
    Surface(
        color = MaterialTheme.colorScheme.tertiaryContainer,
        contentColor = MaterialTheme.colorScheme.onTertiaryContainer,
        modifier = Modifier
            .fillMaxWidth()
            .testTag(MessagingDashboardTestTags.ACTIVITY_NOTICE),
    ) {
        Row(
            modifier = Modifier.padding(12.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Icon(Icons.Outlined.WarningAmber, contentDescription = null)
            Text(text = text, style = MaterialTheme.typography.bodyMedium)
        }
    }
}

@Composable
private fun MetricsGrid(metrics: List<DashboardMetricCard>) {
    FlowRow(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(MessagingDashboardTestTags.METRICS),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        metrics.forEach { metric -> MetricTile(metric) }
    }
}

@Composable
private fun MetricTile(metric: DashboardMetricCard) {
    val label = metricLabel(metric)
    val cd = stringResource(R.string.admin_metric_content_description, label, metric.value)
    Card(
        modifier = Modifier
            .widthIn(min = 140.dp)
            .heightIn(min = 48.dp)
            .testTag(MessagingDashboardTestTags.metric(metric.key))
            .semantics(mergeDescendants = true) { contentDescription = cd },
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text = metric.value,
                style = if (metric.emphasis) {
                    MaterialTheme.typography.headlineMedium
                } else {
                    MaterialTheme.typography.headlineSmall
                },
            )
            Text(
                text = label,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

/** Maps a stable metric key to a localised tile label, falling back to the domain English label. */
@Composable
private fun metricLabel(metric: DashboardMetricCard): String {
    val res = when (metric.key) {
        METRIC_MSG_SENT -> R.string.admin_messaging_metric_sent
        METRIC_MSG_DELIVERED -> R.string.admin_messaging_metric_delivered
        METRIC_MSG_BOUNCED -> R.string.admin_messaging_metric_bounced
        METRIC_MSG_FAILED -> R.string.admin_messaging_metric_failed
        METRIC_MSG_SUPPRESSED -> R.string.admin_messaging_metric_suppressed
        METRIC_MSG_SEGMENTS -> R.string.admin_messaging_metric_segments
        METRIC_MSG_DELIVERY_RATE -> R.string.admin_messaging_metric_delivery_rate
        else -> null
    }
    return res?.let { stringResource(it) } ?: metric.label
}

/**
 * AND-404 - one INERT (read-only) recent-delivery row. Status is conveyed by ICON + a text LABEL + a Material 3
 * color (NEVER colour alone - AND-404 §9). A merged contentDescription announces masked recipient + status +
 * detail + relative time. There is NO onClick / resend / suppress affordance (read-only - AC2 / TC-13). The
 * recipient is already masked by the mapper - full PII never reaches the UI (§8).
 */
@Composable
private fun ActivityRow(channel: DashboardChannel, row: DeliveryActivity) {
    val statusLabel = stringResource(statusLabelRes(row.status))
    val relativeTime = row.createdAtEpochSeconds?.let { relativeTime(it) }
    val cd = buildString {
        append(row.maskedRecipient)
        append(", ")
        append(statusLabel)
        row.detail?.let { append(", "); append(it) }
        relativeTime?.let { append(", "); append(it) }
    }
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .testTag(MessagingDashboardTestTags.activityRow(row.key))
            .semantics(mergeDescendants = true) { contentDescription = cd },
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Icon(
                imageVector = statusIcon(row.status),
                contentDescription = null, // announced via the merged row description
                tint = statusColor(row.status),
            )
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Text(
                    text = row.maskedRecipient,
                    style = MaterialTheme.typography.titleSmall,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    // Status TEXT label so status is not colour-only.
                    Text(
                        text = statusLabel,
                        style = MaterialTheme.typography.labelMedium,
                        color = statusColor(row.status),
                    )
                    relativeTime?.let {
                        Text(
                            text = it,
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
                row.detail?.let {
                    Text(
                        text = it,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }
        }
    }
}

/** Locale-aware relative time (e.g. "5 minutes ago") from an epoch-SECONDS timestamp (AND-404 §6/§9). */
private fun relativeTime(epochSeconds: Long): String = DateUtils.getRelativeTimeSpanString(
    epochSeconds * 1000L,
    System.currentTimeMillis(),
    DateUtils.MINUTE_IN_MILLIS,
).toString()

private fun statusLabelRes(status: DeliveryStatus): Int = when (status) {
    DeliveryStatus.DELIVERED -> R.string.admin_delivery_status_delivered
    DeliveryStatus.SENT -> R.string.admin_delivery_status_sent
    DeliveryStatus.PENDING -> R.string.admin_delivery_status_pending
    DeliveryStatus.BOUNCED -> R.string.admin_delivery_status_bounced
    DeliveryStatus.FAILED -> R.string.admin_delivery_status_failed
    DeliveryStatus.UNKNOWN -> R.string.admin_delivery_status_unknown
}

private fun statusIcon(status: DeliveryStatus): ImageVector = when (status) {
    DeliveryStatus.DELIVERED -> Icons.Outlined.CheckCircle
    DeliveryStatus.SENT -> Icons.Outlined.MarkEmailRead
    DeliveryStatus.PENDING -> Icons.Outlined.Schedule
    DeliveryStatus.BOUNCED -> Icons.Outlined.WarningAmber
    DeliveryStatus.FAILED -> Icons.Outlined.ErrorOutline
    DeliveryStatus.UNKNOWN -> Icons.Outlined.HelpOutline
}

@Composable
private fun statusColor(status: DeliveryStatus): Color = when (status) {
    DeliveryStatus.DELIVERED -> MaterialTheme.colorScheme.primary
    DeliveryStatus.SENT -> MaterialTheme.colorScheme.primary
    DeliveryStatus.PENDING -> MaterialTheme.colorScheme.tertiary
    DeliveryStatus.BOUNCED -> MaterialTheme.colorScheme.tertiary
    DeliveryStatus.FAILED -> MaterialTheme.colorScheme.error
    DeliveryStatus.UNKNOWN -> MaterialTheme.colorScheme.onSurfaceVariant
}
