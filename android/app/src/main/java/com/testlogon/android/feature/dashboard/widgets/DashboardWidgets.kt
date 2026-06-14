@file:OptIn(androidx.compose.foundation.layout.ExperimentalLayoutApi::class)

package com.testlogon.android.feature.dashboard.widgets

import android.text.format.DateUtils
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Campaign
import androidx.compose.material.icons.outlined.EmojiEvents
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.Person
import androidx.compose.material.icons.outlined.Apps
import androidx.compose.material.icons.outlined.Devices
import androidx.compose.material3.Card
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.testlogon.android.R
import com.testlogon.android.core.model.Dashboard
import com.testlogon.android.core.model.Milestone
import com.testlogon.android.core.ui.input.TlButton
import com.testlogon.android.core.ui.input.TlButtonVariant
import com.testlogon.android.feature.dashboard.DashboardTestTags
import com.testlogon.android.feature.dashboard.QuickLink
import java.text.NumberFormat
import java.util.Currency
import java.util.Locale

private const val MAX_HIGHLIGHTS = 5

/** Summary / KPI card: earnings, views, subscribers from the top-level summary fields. */
@Composable
fun SummaryWidget(dashboard: Dashboard, modifier: Modifier = Modifier) {
    Card(modifier = modifier.fillMaxWidth().testTag(DashboardTestTags.SUMMARY_WIDGET)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(
                text = stringResource(R.string.dashboard_summary_title),
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.semantics { heading() },
            )
            KpiRow(
                label = stringResource(R.string.dashboard_kpi_today_earnings),
                value = formatCents(dashboard.todayEarningsCents, dashboard.currency),
            )
            KpiRow(
                label = stringResource(R.string.dashboard_kpi_period_views),
                value = formatCount(dashboard.periodViews),
            )
            KpiRow(
                label = stringResource(R.string.dashboard_kpi_subscribers),
                value = formatCount(dashboard.totalSubscribers),
            )
            KpiRow(
                label = stringResource(R.string.dashboard_kpi_period_revenue),
                value = formatCents(dashboard.periodRevenueCents, dashboard.currency),
            )
        }
    }
}

@Composable
private fun KpiRow(label: String, value: String) {
    val cd = "$label: $value"
    Row(
        modifier = Modifier.fillMaxWidth().clearAndSetSemantics { contentDescription = cd },
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(label, style = MaterialTheme.typography.bodyMedium)
        Text(value, style = MaterialTheme.typography.titleSmall)
    }
}

/**
 * Recent highlights card: maps `recent_milestones` (and falls back to `active_broadcasts`) into a
 * bounded list, capped at [MAX_HIGHLIGHTS]. An overflow link routes to the full activity area.
 */
@Composable
fun HighlightsWidget(
    dashboard: Dashboard,
    onSeeAll: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Card(modifier = modifier.fillMaxWidth().testTag(DashboardTestTags.HIGHLIGHTS_WIDGET)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                text = stringResource(R.string.dashboard_highlights_title),
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.semantics { heading() },
            )
            val milestones = dashboard.recentMilestones.take(MAX_HIGHLIGHTS)
            if (milestones.isEmpty() && dashboard.activeBroadcasts.isEmpty()) {
                Text(
                    text = stringResource(R.string.dashboard_highlights_empty),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                milestones.forEach { MilestoneRow(it) }
                dashboard.activeBroadcasts.take(MAX_HIGHLIGHTS - milestones.size).forEach { b ->
                    HighlightRow(
                        icon = Icons.Outlined.Campaign,
                        title = b.name ?: stringResource(R.string.dashboard_broadcast_default_title),
                        subtitle = b.status,
                    )
                }
                TlButton(
                    text = stringResource(R.string.dashboard_highlights_see_all),
                    onClick = onSeeAll,
                    variant = TlButtonVariant.Text,
                    modifier = Modifier.testTag("dashboard_highlights_see_all"),
                )
            }
        }
    }
}

@Composable
private fun MilestoneRow(milestone: Milestone) {
    val subtitle = milestone.achievedAtMillis?.let {
        DateUtils.getRelativeTimeSpanString(
            it,
            System.currentTimeMillis(),
            DateUtils.MINUTE_IN_MILLIS,
        ).toString()
    } ?: milestone.metric
    HighlightRow(icon = Icons.Outlined.EmojiEvents, title = milestone.formatted, subtitle = subtitle)
}

@Composable
private fun HighlightRow(icon: ImageVector, title: String, subtitle: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .semantics { contentDescription = "$title, $subtitle" },
        verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Icon(icon, contentDescription = null)
        Column {
            Text(title, style = MaterialTheme.typography.bodyMedium)
            Text(
                subtitle,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

/** Quick-links card: a client-defined static set of shortcut buttons. */
@Composable
fun QuickLinksWidget(
    onQuickLink: (QuickLink) -> Unit,
    modifier: Modifier = Modifier,
) {
    Card(modifier = modifier.fillMaxWidth().testTag(DashboardTestTags.QUICK_LINKS_WIDGET)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(
                text = stringResource(R.string.dashboard_quick_links_title),
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.semantics { heading() },
            )
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                QuickLinkButton(QuickLink.Profile, Icons.Outlined.Person, R.string.dashboard_quick_link_profile, onQuickLink)
                QuickLinkButton(QuickLink.Sessions, Icons.Outlined.Devices, R.string.dashboard_quick_link_sessions, onQuickLink)
                QuickLinkButton(QuickLink.Settings, Icons.Outlined.Settings, R.string.dashboard_quick_link_settings, onQuickLink)
                QuickLinkButton(QuickLink.More, Icons.Outlined.Apps, R.string.dashboard_quick_link_more, onQuickLink)
            }
        }
    }
}

@Composable
private fun QuickLinkButton(
    link: QuickLink,
    icon: ImageVector,
    labelRes: Int,
    onQuickLink: (QuickLink) -> Unit,
) {
    TlButton(
        text = stringResource(labelRes),
        onClick = { onQuickLink(link) },
        variant = TlButtonVariant.Secondary,
        leadingIcon = icon,
        modifier = Modifier.testTag("dashboard_quick_link_${link.name.lowercase(Locale.ROOT)}"),
    )
}

private fun formatCents(cents: Long, currencyCode: String): String {
    val formatter = NumberFormat.getCurrencyInstance(Locale.getDefault())
    runCatching { formatter.currency = Currency.getInstance(currencyCode) }
    return formatter.format(cents / 100.0)
}

private fun formatCount(value: Long): String =
    NumberFormat.getIntegerInstance(Locale.getDefault()).format(value)
