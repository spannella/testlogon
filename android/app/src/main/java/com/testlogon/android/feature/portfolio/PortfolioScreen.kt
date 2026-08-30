@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.portfolio

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.feature.tradingdocs.ReportRequestSection
import com.testlogon.android.feature.tradingdocs.ReportRequestViewModel
import com.testlogon.android.feature.tradingdocs.ReportSubmissionState

/** Green/red for uPnL, independent of the app theme (matches the markets convention). */
private val PnlUp = Color(0xFF16A34A)
private val PnlDown = Color(0xFFDC2626)

@Composable
fun PortfolioRoute(
    onBack: () -> Unit,
    onOpenTradingDocs: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: PortfolioViewModel = hiltViewModel(),
    reportViewModel: ReportRequestViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val submission by reportViewModel.submission.collectAsStateWithLifecycle()
    PortfolioScreen(
        state = state,
        submission = submission,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onGenerateReport = reportViewModel::generate,
        onOpenTradingDocs = {
            reportViewModel.reset()
            onOpenTradingDocs()
        },
        modifier = modifier,
    )
}

@Composable
fun PortfolioScreen(
    state: PortfolioUiState,
    submission: ReportSubmissionState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onGenerateReport: (type: String, periodStart: Long?, periodEnd: Long?, taxYear: Int?) -> Unit,
    onOpenTradingDocs: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.fillMaxSize(),
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("Portfolio")
                        if (state.paper) {
                            Spacer(Modifier.width(8.dp))
                            PortfolioPaperBadge()
                        }
                    }
                },
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
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item { TotalEquityHeader(state) }

            item {
                ReportRequestSection(
                    submission = submission,
                    onGenerate = onGenerateReport,
                    onViewDocuments = onOpenTradingDocs,
                )
            }

            if (state.anyLoading && state.cards.all { it.loading }) {
                item { LoadingBlock() }
            } else if (state.allEmpty) {
                item { EmptyBlock() }
            }

            items(count = state.cards.size, key = { state.cards[it].venue.name }) { i ->
                VenueCardView(state.cards[i])
            }

            if (state.positions.isNotEmpty()) {
                item {
                    Text(
                        "Open positions",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                        modifier = Modifier.padding(top = 8.dp),
                    )
                }
                items(count = state.positions.size, key = { "pos_" + state.positions[it].symbol + it }) { i ->
                    PositionCardView(state.positions[i])
                }
            }
        }
    }
}

@Composable
private fun TotalEquityHeader(state: PortfolioUiState) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
    ) {
        Column(Modifier.padding(16.dp)) {
            Text(
                if (state.priced) "Total equity (USD)" else "Total equity",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onPrimaryContainer,
            )
            Spacer(Modifier.height(4.dp))
            Text(
                text = if (state.priced) usd(state.totalEquityUsd) else fmt(state.totalEquity),
                fontSize = 30.sp,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.onPrimaryContainer,
            )
            Spacer(Modifier.height(4.dp))
            Text(
                if (state.priced) {
                    if (state.pricesStub) {
                        "USD-normalized equity - indicative (stub prices)."
                    } else {
                        "USD-normalized equity across readable sources."
                    }
                } else {
                    "Cross-venue snapshot (readable sources, source-native units)."
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onPrimaryContainer,
            )
        }
    }
}

@Composable
private fun VenueCardView(card: VenueCard) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    card.venue.label,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                )
                when {
                    card.loading -> CircularProgressIndicator(Modifier.height(18.dp), strokeWidth = 2.dp)
                    !card.unavailable -> Text(
                        fmt(card.equity),
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.SemiBold,
                    )
                    else -> {}
                }
            }
            Spacer(Modifier.height(8.dp))
            when {
                card.loading -> Text(
                    "Loading…",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                card.unavailable -> Text(
                    card.unavailableReason ?: "Unavailable.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                card.lines.isEmpty() -> Text(
                    "No holdings.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                else -> card.lines.forEach { line ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 2.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(line.label, style = MaterialTheme.typography.bodyMedium)
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            line.usdValue?.let { v ->
                                Text(
                                    "~" + usd(v),
                                    style = MaterialTheme.typography.labelSmall,
                                    fontFamily = FontFamily.Monospace,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                                Spacer(Modifier.width(8.dp))
                            }
                            Text(
                                line.value,
                                style = MaterialTheme.typography.bodyMedium,
                                fontFamily = FontFamily.Monospace,
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun PositionCardView(pos: PortfolioPosition) {
    val pnlColor = if (pos.isProfit) PnlUp else PnlDown
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(pos.symbol, fontWeight = FontWeight.SemiBold)
                Text(
                    (if (pos.isLong) "LONG " else "SHORT ") + pos.qty.toString(),
                    style = MaterialTheme.typography.bodyMedium,
                    fontFamily = FontFamily.Monospace,
                    color = if (pos.isLong) PnlUp else PnlDown,
                )
            }
            Spacer(Modifier.height(6.dp))
            HorizontalDivider()
            Spacer(Modifier.height(6.dp))
            PosStat("Entry", pos.entryPrice.toString())
            PosStat("Liq. price", if (pos.liquidationPrice > 0) pos.liquidationPrice.toString() else "--")
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 2.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text("Unrealized P&L", style = MaterialTheme.typography.bodyMedium)
                Text(
                    (if (pos.isProfit) "+" else "") + pos.unrealizedPnl.toString(),
                    style = MaterialTheme.typography.bodyMedium,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.SemiBold,
                    color = pnlColor,
                )
            }
        }
    }
}

@Composable
private fun PosStat(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 2.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(label, style = MaterialTheme.typography.bodyMedium)
        Text(value, style = MaterialTheme.typography.bodyMedium, fontFamily = FontFamily.Monospace)
    }
}

@Composable
private fun LoadingBlock() {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        CircularProgressIndicator()
        Spacer(Modifier.height(12.dp))
        Text("Loading your portfolio…", style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
private fun EmptyBlock() {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text("No holdings yet", style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(4.dp))
        Text(
            "Fund custody, spot, or margin to see them here.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

/** Compact number format: drop a trailing .0 for whole numbers. */
private fun fmt(v: Double): String =
    if (v == v.toLong().toDouble()) v.toLong().toString() else v.toString()

/** USD money format: '$' prefix, 2 decimals, grouped thousands (indicative reference value). */
private fun usd(v: Double): String = "$" + String.format(java.util.Locale.US, "%,.2f", v)


/** A small PAPER pill shown in the app bar when the portfolio reflects the shared paper account. */
@Composable
private fun PortfolioPaperBadge() {
    Surface(
        color = MaterialTheme.colorScheme.tertiaryContainer,
        contentColor = MaterialTheme.colorScheme.onTertiaryContainer,
        shape = MaterialTheme.shapes.small,
    ) {
        Text(
            "PAPER",
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
            style = MaterialTheme.typography.labelSmall,
            fontWeight = FontWeight.Bold,
        )
    }
}
