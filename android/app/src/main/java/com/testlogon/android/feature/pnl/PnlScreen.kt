@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.pnl

import androidx.compose.foundation.Canvas
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
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
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
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import java.util.Locale

/** Green/red for PnL, independent of the app theme (matches the markets/portfolio convention). */
private val PnlUp = Color(0xFF16A34A)
private val PnlDown = Color(0xFFDC2626)

@Composable
fun PnlRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: PnlViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    PnlScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        modifier = modifier,
    )
}

@Composable
fun PnlScreen(
    state: PnlUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.fillMaxSize(),
        topBar = {
            TopAppBar(
                title = { Text("PnL & performance") },
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
                body = "Performance analytics aren't available on this deployment yet.",
                modifier = Modifier.padding(padding),
            )
            state.error != null -> MessageBlock(
                title = "Couldn't load",
                body = state.error,
                modifier = Modifier.padding(padding),
            )
            state.isEmpty -> MessageBlock(
                title = "No trading activity yet",
                body = "Your realized PnL, fees, and equity curve will appear here once you trade.",
                modifier = Modifier.padding(padding),
            )
            else -> PnlContent(state, Modifier.padding(padding))
        }
    }
}

@Composable
private fun PnlContent(state: PnlUiState, modifier: Modifier) {
    val stats = state.stats ?: return
    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item { NetRealizedHeader(stats) }
        item { EquityCurveCard(state.equityCurve) }
        item { StatCardsGrid(stats) }
        if (state.bySymbol.isNotEmpty()) {
            item {
                Text(
                    "By symbol",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.padding(top = 8.dp),
                )
            }
            item { SymbolHeaderRow() }
            items(count = state.bySymbol.size, key = { "sym_" + state.bySymbol[it].symbol + it }) { i ->
                SymbolRowView(state.bySymbol[i])
            }
        }
    }
}

@Composable
private fun NetRealizedHeader(stats: PnlStats) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
    ) {
        Column(Modifier.padding(16.dp)) {
            Text(
                "Net realized PnL",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onPrimaryContainer,
            )
            Spacer(Modifier.height(4.dp))
            Text(
                text = signed(stats.netRealized),
                fontSize = 30.sp,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace,
                color = if (stats.isRealizedProfit) PnlUp else PnlDown,
            )
            Spacer(Modifier.height(4.dp))
            Text(
                "Realized net of fees, funding, and liquidations (raw units).",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onPrimaryContainer,
            )
        }
    }
}

@Composable
private fun EquityCurveCard(points: List<EquityCurvePoint>) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Text(
                "Equity curve",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
            )
            Spacer(Modifier.height(12.dp))
            if (points.size < 2) {
                Text(
                    "Not enough activity to plot a curve yet.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                val line = if (points.last().cumulative >= 0) PnlUp else PnlDown
                val grid = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.25f)
                EquityCanvas(points, line, grid)
                Spacer(Modifier.height(8.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Text(
                        "start " + signed(points.first().cumulative),
                        style = MaterialTheme.typography.labelSmall,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Text(
                        "now " + signed(points.last().cumulative),
                        style = MaterialTheme.typography.labelSmall,
                        fontFamily = FontFamily.Monospace,
                        color = if (points.last().cumulative >= 0) PnlUp else PnlDown,
                    )
                }
            }
        }
    }
}

/**
 * Self-contained equity-curve Canvas (no library). Cumulative values can be NEGATIVE, so the y-range
 * spans [min(0,minVal) .. max(0,maxVal)] and a zero baseline is drawn where the running total crosses
 * zero. x is evenly spaced by index (chronological order), matching the app's existing chart approach.
 */
@Composable
private fun EquityCanvas(points: List<EquityCurvePoint>, lineColor: Color, gridColor: Color) {
    Canvas(
        modifier = Modifier
            .fillMaxWidth()
            .height(160.dp),
    ) {
        val n = points.size
        if (n < 2) return@Canvas
        val values = points.map { it.cumulative }
        val minV = minOf(0L, values.min())
        val maxV = maxOf(0L, values.max())
        val span = (maxV - minV).coerceAtLeast(1L).toFloat()
        val w = size.width
        val h = size.height

        fun px(i: Int): Float = if (n == 1) 0f else w * i.toFloat() / (n - 1).toFloat()
        fun py(v: Long): Float = h - ((v - minV).toFloat() / span) * h

        // Zero baseline (only when zero is inside the visible range).
        if (minV < 0L && maxV > 0L) {
            val zeroY = py(0L)
            drawLine(gridColor, Offset(0f, zeroY), Offset(w, zeroY), strokeWidth = 1f)
        }

        // Filled area under the curve (down to the zero baseline / clamped range bottom).
        val baseY = py(0L).coerceIn(0f, h)
        val fill = Path().apply {
            moveTo(px(0), baseY)
            points.forEachIndexed { i, p -> lineTo(px(i), py(p.cumulative)) }
            lineTo(px(n - 1), baseY)
            close()
        }
        drawPath(fill, lineColor.copy(alpha = 0.12f))

        // The line itself.
        val path = Path().apply {
            moveTo(px(0), py(points[0].cumulative))
            for (i in 1 until n) lineTo(px(i), py(points[i].cumulative))
        }
        drawPath(path, lineColor, style = Stroke(width = 3f))
    }
}

@Composable
private fun StatCardsGrid(stats: PnlStats) {
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            StatCard("Unrealized PnL", signed(stats.unrealized), if (stats.isUnrealizedProfit) PnlUp else PnlDown, Modifier.weight(1f))
            StatCard("Total fees", stats.totalFees.toString(), MaterialTheme.colorScheme.onSurface, Modifier.weight(1f))
        }
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            StatCard(
                "Win rate",
                if (stats.closingTradeCount > 0) stats.winRatePercent.toString() + "%" else "--",
                MaterialTheme.colorScheme.onSurface,
                Modifier.weight(1f),
                sub = stats.closingTradeCount.toString() + " closing",
            )
            StatCard("Trades", stats.tradeCount.toString(), MaterialTheme.colorScheme.onSurface, Modifier.weight(1f))
        }
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            StatCard("Volume", stats.volume.toString(), MaterialTheme.colorScheme.onSurface, Modifier.weight(1f))
            StatCard(
                "Funding",
                signed(stats.fundingTotal),
                if (stats.fundingTotal >= 0) PnlUp else PnlDown,
                Modifier.weight(1f),
            )
        }
    }
}

@Composable
private fun StatCard(label: String, value: String, valueColor: Color, modifier: Modifier, sub: String? = null) {
    Card(modifier = modifier) {
        Column(Modifier.padding(14.dp)) {
            Text(
                label,
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(6.dp))
            Text(
                value,
                fontSize = 20.sp,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace,
                color = valueColor,
            )
            if (sub != null) {
                Spacer(Modifier.height(2.dp))
                Text(
                    sub,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun SymbolHeaderRow() {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text("Symbol", style = MaterialTheme.typography.labelSmall, modifier = Modifier.weight(1.4f), color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text("Realized", style = MaterialTheme.typography.labelSmall, modifier = Modifier.weight(1f), color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text("Vol", style = MaterialTheme.typography.labelSmall, modifier = Modifier.weight(1f), color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text("Fees", style = MaterialTheme.typography.labelSmall, modifier = Modifier.weight(0.8f), color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text("#", style = MaterialTheme.typography.labelSmall, modifier = Modifier.weight(0.4f), color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun SymbolRowView(row: SymbolRow) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 12.dp, vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    row.symbol,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.weight(1.4f),
                )
                Text(
                    signed(row.realized),
                    style = MaterialTheme.typography.bodyMedium,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.SemiBold,
                    color = if (row.isProfit) PnlUp else PnlDown,
                    modifier = Modifier.weight(1f),
                )
                Text(row.volume.toString(), style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace, modifier = Modifier.weight(1f))
                Text(row.fees.toString(), style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace, modifier = Modifier.weight(0.8f))
                Text(row.tradeCount.toString(), style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace, modifier = Modifier.weight(0.4f))
            }
            HorizontalDivider()
        }
    }
}

@Composable
private fun LoadingBlock(modifier: Modifier) {
    Box(modifier = modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            CircularProgressIndicator()
            Spacer(Modifier.height(12.dp))
            Text("Loading performance…", style = MaterialTheme.typography.bodyMedium)
        }
    }
}

@Composable
private fun MessageBlock(title: String, body: String, modifier: Modifier) {
    Box(modifier = modifier.fillMaxSize().padding(32.dp), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(title, style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(6.dp))
            Text(
                body,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

/** Signed integer display: a leading '+' for non-negative, grouped thousands. */
private fun signed(v: Long): String {
    val grouped = String.format(Locale.US, "%,d", Math.abs(v))
    return if (v >= 0) "+$grouped" else "-$grouped"
}
