@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.taxreport

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
import androidx.compose.material3.AssistChip
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

/** Green/red for gains, matching the PnL / reports convention. */
private val UpColor = Color(0xFF16A34A)
private val DownColor = Color(0xFFDC2626)

@Composable
fun TaxReportRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: TaxReportViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    TaxReportScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onMethod = viewModel::setMethod,
        onYear = viewModel::setYear,
        modifier = modifier,
    )
}

@Composable
fun TaxReportScreen(
    state: TaxReportUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onMethod: (TaxLotMath.CostBasisMethod) -> Unit,
    onYear: (TaxYear) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.fillMaxSize(),
        topBar = {
            TopAppBar(
                title = { Text("Tax lots & gains") },
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
                title = "No trade history",
                body = "Trade history isn't available on this account yet, so there are no tax lots to report. Once you have fills, this screen computes realized gains and open lots.",
                modifier = Modifier.padding(padding),
            )
            state.error != null -> MessageBlock(
                title = "Couldn't load",
                body = state.error,
                modifier = Modifier.padding(padding),
            )
            else -> TaxReportContent(state, onMethod, onYear, Modifier.padding(padding))
        }
    }
}

@Composable
private fun TaxReportContent(
    state: TaxReportUiState,
    onMethod: (TaxLotMath.CostBasisMethod) -> Unit,
    onYear: (TaxYear) -> Unit,
    modifier: Modifier,
) {
    val context = LocalContext.current
    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (state.degraded) {
            item { DegradeBanner() }
        }
        item { MethodChips(state.method, onMethod) }
        item { YearChips(state.year, state.availableYears, onYear) }

        val summary = state.summary
        if (summary != null) {
            item { TotalsHeader(summary) }
        }

        // ---- Realized gains (by symbol) ----
        if (summary != null && summary.bySymbol.isNotEmpty()) {
            item { SectionTitle("Realized by symbol") }
            summary.bySymbol.forEach { s ->
                item { SymbolRealizedCard(s) }
            }
        }

        // ---- Realized lots ----
        if (state.realizedLots.isNotEmpty()) {
            item { SectionTitle("Realized lots (${state.realizedLots.size})") }
            state.realizedLots.forEach { r ->
                item { RealizedLotCard(r) }
            }
        }

        // ---- Unrealized (open lots vs mark) ----
        if (state.openLots.isNotEmpty()) {
            item { SectionTitle("Open lots / unrealized") }
            if (state.marksUnavailable) {
                item { UnpricedBanner() }
            }
            if (state.unrealized.isNotEmpty()) {
                state.unrealized.forEach { u ->
                    item { UnrealizedCard(u) }
                }
            } else {
                state.openLots.forEach { l ->
                    item { OpenLotCard(l) }
                }
            }
        }

        if (state.isEmpty) {
            item {
                Card(Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(16.dp)) {
                        Text("No lots in this period", style = MaterialTheme.typography.titleSmall)
                        Spacer(Modifier.height(4.dp))
                        Text(
                            "Pick a wider year, or trade to populate the report. Covers spot & margin fills (tokens / strategies are future work).",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
        }

        // ---- Export ----
        item { SectionTitle("Export") }
        item {
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp)) {
                    Text("Realized lots CSV", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                    Spacer(Modifier.height(4.dp))
                    Text(
                        "Every closed lot: symbol / close-time / qty / proceeds / cost-basis / fee / gain / holding-days / term.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(12.dp))
                    Button(onClick = { shareTaxLotsCsv(context, state.csv, state.csvName) }) {
                        Icon(Icons.Filled.Share, contentDescription = null)
                        Spacer(Modifier.width(8.dp))
                        Text("Share / Copy CSV")
                    }
                }
            }
        }
    }
}

@Composable
private fun MethodChips(selected: TaxLotMath.CostBasisMethod, onMethod: (TaxLotMath.CostBasisMethod) -> Unit) {
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        TaxLotMath.CostBasisMethod.entries.forEach { m ->
            FilterChip(
                selected = m == selected,
                onClick = { onMethod(m) },
                label = { Text(methodLabel(m)) },
            )
        }
    }
}

private fun methodLabel(m: TaxLotMath.CostBasisMethod): String = when (m) {
    TaxLotMath.CostBasisMethod.FIFO -> "FIFO"
    TaxLotMath.CostBasisMethod.LIFO -> "LIFO"
    TaxLotMath.CostBasisMethod.AVERAGE -> "Average"
}

@Composable
private fun YearChips(selected: TaxYear, years: List<TaxYear>, onYear: (TaxYear) -> Unit) {
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        years.forEach { y ->
            FilterChip(
                selected = y == selected,
                onClick = { onYear(y) },
                label = { Text(y.label) },
            )
        }
    }
}

@Composable
private fun DegradeBanner() {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer),
    ) {
        Column(Modifier.padding(14.dp)) {
            Text("Limited data", style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.onSecondaryContainer)
            Spacer(Modifier.height(4.dp))
            Text(
                "The trade-history feed returned little or nothing on this deployment. The report reflects only the fills that were available.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSecondaryContainer,
            )
        }
    }
}

@Composable
private fun UnpricedBanner() {
    Text(
        "Marks unavailable on this deployment — open lots show cost basis only (no market value).",
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

@Composable
private fun TotalsHeader(summary: TaxLotMath.RealizedSummary) {
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
        ) {
            Column(Modifier.padding(16.dp)) {
                Text(
                    "Total realized gain",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onPrimaryContainer,
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    text = signed(summary.totalGainCents),
                    fontSize = 28.sp,
                    fontWeight = FontWeight.Bold,
                    fontFamily = FontFamily.Monospace,
                    color = if (summary.totalGainCents >= 0) UpColor else DownColor,
                )
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            StatCard("Short-term", signed(summary.byTerm.shortCents), Modifier.weight(1f))
            StatCard("Long-term", signed(summary.byTerm.longCents), Modifier.weight(1f))
        }
    }
}

@Composable
private fun SymbolRealizedCard(s: TaxLotMath.SymbolRealized) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(14.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(s.symbol, fontWeight = FontWeight.SemiBold)
                Text(
                    signed(s.gainCents),
                    fontFamily = FontFamily.Monospace,
                    color = if (s.gainCents >= 0) UpColor else DownColor,
                    fontWeight = FontWeight.SemiBold,
                )
            }
            Spacer(Modifier.height(4.dp))
            Text(
                "Proceeds ${s.proceedsCents}  •  Cost ${s.costBasisCents}  •  Fees ${s.feeCents}  •  ${s.lotCount} lots",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun RealizedLotCard(r: TaxLotMath.RealizedLot) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(14.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                Text("${r.symbol}  ×${r.qty}", fontWeight = FontWeight.SemiBold)
                AssistChip(onClick = {}, label = { Text(if (r.term == TaxLotMath.Term.LONG) "LONG" else "SHORT") })
            }
            Spacer(Modifier.height(4.dp))
            Text(
                "Gain ${signed(r.gainCents)}  •  ${r.holdingDays}d held",
                style = MaterialTheme.typography.bodyMedium,
                fontFamily = FontFamily.Monospace,
                color = if (r.gainCents >= 0) UpColor else DownColor,
            )
            Text(
                "Proceeds ${r.proceedsCents}  •  Cost ${r.costBasisCents}  •  Fee ${r.feeCents}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            val closed = TaxLotMath.formatTs(r.closeTs)
            if (closed.isNotEmpty()) {
                Text(closed, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

@Composable
private fun UnrealizedCard(u: TaxLotMath.UnrealizedRow) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(14.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text("${u.symbol}  ×${u.qty}", fontWeight = FontWeight.SemiBold)
                Text(
                    signed(u.unrealizedCents),
                    fontFamily = FontFamily.Monospace,
                    color = if (u.unrealizedCents >= 0) UpColor else DownColor,
                    fontWeight = FontWeight.SemiBold,
                )
            }
            Spacer(Modifier.height(4.dp))
            Text(
                "Cost ${u.costBasisCents}  •  Market ${u.marketValueCents}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun OpenLotCard(l: TaxLotMath.OpenLot) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(14.dp)) {
            Text("${l.symbol}  ×${l.qty}", fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(4.dp))
            Text(
                "Cost basis ${l.costBasisCents}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            val opened = TaxLotMath.formatTs(l.openTs)
            if (opened.isNotEmpty()) {
                Text("Opened $opened", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

@Composable
private fun SectionTitle(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.titleMedium,
        fontWeight = FontWeight.SemiBold,
        modifier = Modifier.padding(top = 8.dp),
    )
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
private fun LoadingBlock(modifier: Modifier) {
    Box(modifier = modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            CircularProgressIndicator()
            Spacer(Modifier.height(12.dp))
            Text("Computing tax lots…", style = MaterialTheme.typography.bodyMedium)
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
