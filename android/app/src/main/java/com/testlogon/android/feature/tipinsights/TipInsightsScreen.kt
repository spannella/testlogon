@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.tipinsights

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Card
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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.OfflineBanner
import com.testlogon.android.data.tipinsights.TipInsights
import com.testlogon.android.data.tipinsights.TipSurfaceBreakdown
import com.testlogon.android.data.tipinsights.TipTopSupporter
import com.testlogon.android.data.tipinsights.TipTransaction
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** TIPX-D3/D4 — stable testTags for the tip insights screen. */
object TipInsightsTestTags {
    const val SCREEN = "tip_insights_screen"
    const val CONTENT = "tip_insights_content"
    const val LOADING = "tip_insights_loading"
    const val ERROR = "tip_insights_error"
    const val NET_TOTAL = "tip_insights_net_total"
    const val SENT_TOTAL = "tip_insights_sent_total"
    const val PERIOD_PREFIX = "tip_insights_period_"
}

private val SURFACE_LABELS = mapOf(
    "post" to "Post tips",
    "message" to "Message tips",
    "comment" to "Comment tips",
    "broadcast" to "Broadcast tips",
    "video" to "Video tips",
    "post_react" to "Post reaction tips",
    "message_react" to "Message reaction tips",
    "video_comment" to "Video comment tips",
    "profile" to "Direct creator tips",
    "other" to "Other tips",
)

private fun surfaceLabel(key: String): String =
    SURFACE_LABELS[key] ?: key.replace('_', ' ').replaceFirstChar { it.uppercase() }

private fun formatCents(cents: Long): String = "$%.2f".format(cents / 100.0)

private fun formatDate(tsSeconds: Long): String {
    if (tsSeconds <= 0) return ""
    return SimpleDateFormat("MMM d, yyyy", Locale.getDefault()).format(Date(tsSeconds * 1000))
}

/** TIPX-D3/D4 — route-level tip insights entry (reachable from the More hub). */
@Composable
fun TipInsightsRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: TipInsightsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    TipInsightsScreen(
        state = state,
        onBack = onBack,
        onPeriodSelected = viewModel::onPeriodSelected,
        onRefresh = viewModel::onRefresh,
        onRetry = viewModel::onRetry,
        modifier = modifier,
    )
}

@Composable
fun TipInsightsScreen(
    state: TipInsightsUiState,
    onBack: () -> Unit,
    onPeriodSelected: (TipInsightsPeriod) -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(TipInsightsTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Tip insights") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        when (state.phase) {
            TipInsightsUiState.Phase.Loading -> LoadingState(
                modifier = Modifier.padding(padding).testTag(TipInsightsTestTags.LOADING),
            )
            TipInsightsUiState.Phase.Error -> ErrorState(
                message = state.errorMessage ?: "Couldn't load tip insights.",
                onRetry = onRetry,
                modifier = Modifier.padding(padding).testTag(TipInsightsTestTags.ERROR),
            )
            TipInsightsUiState.Phase.Content -> {
                val insights = state.insights
                if (insights == null) {
                    EmptyState(title = "No tip data", modifier = Modifier.padding(padding))
                    return@Scaffold
                }
                PullToRefreshBox(
                    isRefreshing = state.isRefreshing,
                    onRefresh = onRefresh,
                    modifier = Modifier.padding(padding).fillMaxSize(),
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .verticalScroll(rememberScrollState())
                            .padding(16.dp)
                            .testTag(TipInsightsTestTags.CONTENT),
                        verticalArrangement = Arrangement.spacedBy(16.dp),
                    ) {
                        if (state.isOffline) OfflineBanner(onRetry = onRetry)
                        PeriodSelector(state.period, onPeriodSelected)
                        ReceivedCard(insights)
                        TopSupportersCard(insights.received.topSupporters)
                        BreakdownCard(insights.received.bySurface)
                        SentCard(insights)
                    }
                }
            }
        }
    }
}

@Composable
private fun PeriodSelector(selected: TipInsightsPeriod, onSelected: (TipInsightsPeriod) -> Unit) {
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        TipInsightsPeriod.entries.forEach { period ->
            val label = when (period) {
                TipInsightsPeriod.D7 -> "7 days"
                TipInsightsPeriod.D30 -> "30 days"
                TipInsightsPeriod.ALL -> "All time"
            }
            FilterChip(
                selected = period == selected,
                onClick = { onSelected(period) },
                label = { Text(label) },
                modifier = Modifier.testTag(TipInsightsTestTags.PERIOD_PREFIX + period.apiValue),
            )
        }
    }
}

@Composable
private fun ReceivedCard(insights: TipInsights) {
    val r = insights.received
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Tips received", style = MaterialTheme.typography.titleMedium)
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                StatColumn(formatCents(r.totalNetCents), "Net received", TipInsightsTestTags.NET_TOTAL)
                StatColumn(r.tipCount.toString(), "Tips", null)
                StatColumn(r.uniqueTippers.toString(), "Tippers", null)
            }
            Text(
                "Net of the platform fee, across all tip types. Reversed tips are excluded — this " +
                    "matches your earnings and leaderboard totals.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun TopSupportersCard(supporters: List<TipTopSupporter>) {
    if (supporters.isEmpty()) return
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text("Top supporters", style = MaterialTheme.typography.titleMedium)
            supporters.take(10).forEachIndexed { index, s ->
                Row(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text("${index + 1}. ${s.displayName}", style = MaterialTheme.typography.bodyMedium)
                    Text(formatCents(s.totalCents), style = MaterialTheme.typography.bodyMedium)
                }
            }
        }
    }
}

@Composable
private fun BreakdownCard(rows: List<TipSurfaceBreakdown>) {
    if (rows.isEmpty()) return
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text("By surface", style = MaterialTheme.typography.titleMedium)
            rows.forEach { row ->
                Row(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Text(surfaceLabel(row.surface), style = MaterialTheme.typography.bodyMedium)
                    Text(
                        "${row.count} (${formatCents(row.totalCents)})",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            }
        }
    }
}

@Composable
private fun SentCard(insights: TipInsights) {
    val s = insights.sentSummary
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Tips sent", style = MaterialTheme.typography.titleMedium)
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                StatColumn(formatCents(s.totalSentCents), "Total sent", TipInsightsTestTags.SENT_TOTAL)
                StatColumn(s.tipCount.toString(), "Tips", null)
                StatColumn(s.uniqueRecipients.toString(), "Creators", null)
            }
            if (insights.sentReceipts.isEmpty()) {
                Text(
                    "You haven't sent any tips yet.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                HorizontalDivider()
                insights.sentReceipts.take(20).forEach { receipt ->
                    SentReceiptRow(receipt)
                }
            }
        }
    }
}

@Composable
private fun SentReceiptRow(receipt: TipTransaction) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(receipt.counterpartyDisplayName, style = MaterialTheme.typography.bodyMedium)
            Text(
                "${surfaceLabel(receipt.surface).lowercase()} · ${formatDate(receipt.ts)}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Column(horizontalAlignment = Alignment.End) {
            Text(formatCents(receipt.amountCents), style = MaterialTheme.typography.bodyMedium)
            if (receipt.platformFeeCents > 0) {
                Text(
                    "fee ${formatCents(receipt.platformFeeCents)}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun StatColumn(value: String, label: String, tag: String?) {
    val base = Modifier
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        modifier = if (tag != null) base.testTag(tag) else base,
    ) {
        Text(value, style = MaterialTheme.typography.headlineSmall, textAlign = TextAlign.Center)
        Text(
            label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}
