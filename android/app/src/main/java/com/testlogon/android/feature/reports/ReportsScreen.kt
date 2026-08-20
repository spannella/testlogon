@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.reports

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import java.util.Locale

/** Green/red for PnL, matching the PnL/markets/portfolio convention. */
private val UpColor = Color(0xFF16A34A)
private val DownColor = Color(0xFFDC2626)

@Composable
fun ReportsRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: ReportsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    ReportsScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onPeriod = viewModel::setPeriod,
        modifier = modifier,
    )
}

@Composable
fun ReportsScreen(
    state: ReportsUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onPeriod: (ReportPeriod) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.fillMaxSize(),
        topBar = {
            TopAppBar(
                title = { Text("Export & reporting") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(onClick = onRefresh) {
                        Icon(Icons.Filled.Refresh, contentDescription = "Refresh")
                    }
                },
            )
        },
    ) { padding ->
        when {
            state.loading -> LoadingBlock(Modifier.padding(padding))
            state.unavailable -> MessageBlock(
                title = "Not available",
                body = "Reporting isn't available on this deployment yet.",
                modifier = Modifier.padding(padding),
            )
            state.error != null -> MessageBlock(
                title = "Couldn't load",
                body = state.error,
                modifier = Modifier.padding(padding),
            )
            else -> ReportsContent(state, onPeriod, Modifier.padding(padding))
        }
    }
}

@Composable
private fun ReportsContent(state: ReportsUiState, onPeriod: (ReportPeriod) -> Unit, modifier: Modifier) {
    val context = LocalContext.current
    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item { PeriodChips(state.period, onPeriod) }
        item {
            if (state.isEmpty) {
                Card(Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(16.dp)) {
                        Text("No activity in this period", style = MaterialTheme.typography.titleSmall)
                        Spacer(Modifier.height(4.dp))
                        Text(
                            "Pick a wider period, or trade to populate reports. You can still export an empty report (headers only).",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            } else {
                StatsHeader(state.stats)
            }
        }
        val exports = state.exports
        if (exports != null) {
            item {
                Text(
                    "Exports",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.padding(top = 8.dp),
                )
            }
            item {
                ExportCard(
                    title = "Trade history",
                    subtitle = "Every fill: time / symbol / side / price / qty / fee / notional.",
                    onExport = { shareReportCsv(context, exports.tradeHistoryCsv, exports.tradeHistoryName) },
                )
            }
            item {
                ExportCard(
                    title = "PnL summary",
                    subtitle = "Per-symbol realized / fees / volume / trades + totals.",
                    onExport = { shareReportCsv(context, exports.pnlSummaryCsv, exports.pnlSummaryName) },
                )
            }
            item {
                ExportCard(
                    title = "Account statement",
                    subtitle = "Period balances, open position, and realized roll-up.",
                    onExport = { shareReportCsv(context, exports.accountStatementCsv, exports.accountStatementName) },
                )
            }
        }
    }
}

@Composable
private fun PeriodChips(selected: ReportPeriod, onPeriod: (ReportPeriod) -> Unit) {
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        ReportPeriod.entries.forEach { p ->
            FilterChip(
                selected = p == selected,
                onClick = { onPeriod(p) },
                label = { Text(p.label) },
            )
        }
    }
}

@Composable
private fun StatsHeader(stats: ReportStats?) {
    if (stats == null) return
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.primaryContainer,
            ),
        ) {
            Column(Modifier.padding(16.dp)) {
                Text(
                    "Net realized (period)",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onPrimaryContainer,
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    text = signed(stats.netRealized),
                    fontSize = 28.sp,
                    fontWeight = FontWeight.Bold,
                    fontFamily = FontFamily.Monospace,
                    color = if (stats.isProfit) UpColor else DownColor,
                )
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            StatCard("Fills", stats.fillCount.toString(), Modifier.weight(1f))
            StatCard("Trades", stats.tradeCount.toString(), Modifier.weight(1f))
        }
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            StatCard("Fees", stats.totalFees.toString(), Modifier.weight(1f))
            StatCard("Volume", stats.volume.toString(), Modifier.weight(1f))
        }
    }
}

@Composable
private fun StatCard(label: String, value: String, modifier: Modifier) {
    Card(modifier = modifier) {
        Column(Modifier.padding(14.dp)) {
            Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.height(6.dp))
            Text(value, fontSize = 18.sp, fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace)
        }
    }
}

@Composable
private fun ExportCard(title: String, subtitle: String, onExport: () -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Text(title, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(4.dp))
            Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.height(12.dp))
            Button(onClick = onExport) {
                Icon(Icons.Filled.Share, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("Export CSV")
            }
        }
    }
}

@Composable
private fun LoadingBlock(modifier: Modifier) {
    Box(modifier = modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            CircularProgressIndicator()
            Spacer(Modifier.height(12.dp))
            Text("Loading reports…", style = MaterialTheme.typography.bodyMedium)
        }
    }
}

@Composable
private fun MessageBlock(title: String, body: String, modifier: Modifier) {
    Box(modifier = modifier.fillMaxSize().padding(32.dp), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(title, style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(6.dp))
            Text(body, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

/** Signed integer display: a leading '+' for non-negative, grouped thousands. */
private fun signed(v: Long): String {
    val grouped = String.format(Locale.US, "%,d", Math.abs(v))
    return if (v >= 0) "+$grouped" else "-$grouped"
}
