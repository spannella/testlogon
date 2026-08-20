@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.analysis

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.exchange.Candle
import com.testlogon.android.data.exchange.HistoryBar
import com.testlogon.android.data.exchange.Instrument
import com.testlogon.android.feature.markets.MARKET_CLASS_TABS
import com.testlogon.android.feature.markets.MarketClassTab
import com.testlogon.android.feature.markets.chart.CandlestickChart
import com.testlogon.android.feature.markets.matchesTab
import com.testlogon.android.feature.markets.ui.MarketColors
import com.testlogon.android.feature.markets.ui.MarketSurface
import kotlin.math.abs

/**
 * Analysis workbench route: symbol + class filter + range select, a history chart (degrading to the
 * recent window with a banner), a stats panel, a multi-symbol normalized overlay + correlation grid,
 * and a fast/slow MA-cross backtest runner. Read-only research surface over the market-data feeds.
 */
@Composable
fun MarketAnalysisRoute(
    onBack: () -> Unit,
    viewModel: MarketAnalysisViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    MarketSurface {
        Column(modifier = Modifier.fillMaxSize().statusBarsPadding()) {
            AnalysisHeader(onBack = onBack)
            Box(modifier = Modifier.fillMaxSize()) {
                when (state.phase) {
                    MarketAnalysisUiState.Phase.Loading -> LoadingState(message = "Loading analysis")
                    MarketAnalysisUiState.Phase.Empty -> EmptyState(
                        title = "No markets",
                        body = "No instruments are available to analyze right now.",
                    )
                    MarketAnalysisUiState.Phase.Error -> ErrorState(
                        message = state.errorMessage ?: "Something went wrong.",
                        onRetry = viewModel::onRetry,
                    )
                    MarketAnalysisUiState.Phase.Content -> AnalysisContent(
                        state = state,
                        onSelectSymbol = viewModel::onSelectSymbol,
                        onSelectClassTab = viewModel::onSelectClassTab,
                        onSelectRange = viewModel::onSelectRange,
                        onToggleCompare = viewModel::onToggleCompare,
                        onBacktestParams = viewModel::onBacktestParams,
                    )
                }
            }
        }
    }
}

@Composable
private fun AnalysisHeader(onBack: () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 4.dp, vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        IconButton(onClick = onBack) {
            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back", tint = MarketColors.TextPrimary)
        }
        Text(
            "Analysis",
            color = MarketColors.TextPrimary,
            fontSize = 20.sp,
            fontWeight = FontWeight.SemiBold,
            modifier = Modifier.padding(start = 4.dp),
        )
    }
}

@Composable
private fun AnalysisContent(
    state: MarketAnalysisUiState,
    onSelectSymbol: (Int) -> Unit,
    onSelectClassTab: (MarketClassTab) -> Unit,
    onSelectRange: (AnalysisRange) -> Unit,
    onToggleCompare: (Int) -> Unit,
    onBacktestParams: (Int, Int) -> Unit,
) {
    val filtered = state.instruments.filter { matchesTab(it, isPrediction = false, tab = state.classTab) }
    LazyColumn(
        modifier = Modifier.fillMaxSize().testTag("analysis_content"),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(bottom = 24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item { ClassTabRow(state.classTab, onSelectClassTab) }
        item {
            SymbolChips(
                instruments = filtered,
                selectedId = state.selectedSymbolId,
                label = "Symbol",
                onSelect = onSelectSymbol,
            )
        }
        item { RangeRow(state.range, onSelectRange) }

        if (state.degraded) {
            item { DegradedBanner() }
        }

        item { SectionTitle("Price history") }
        item {
            val candles = barsToCandles(state.primary?.bars.orEmpty())
            if (candles.isEmpty()) {
                EmptyHint("No bars for this range.")
            } else {
                CandlestickChart(
                    candles = candles,
                    priceScaler = state.selectedInstrument?.priceScaler ?: 1L,
                    showTimeframes = false,
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp),
                )
            }
        }

        item { SectionTitle("Statistics") }
        item { StatsPanel(state.primary?.stats) }

        item { SectionTitle("Compare (normalized overlay)") }
        item {
            SymbolChips(
                instruments = filtered.filter { it.symbolId != state.selectedSymbolId },
                selectedId = null,
                selectedSet = state.compareSymbolIds,
                label = "Add to compare",
                onSelect = onToggleCompare,
            )
        }
        item { CompareOverlay(state) }

        if (state.correlation.isNotEmpty()) {
            item { SectionTitle("Correlation") }
            item { CorrelationGrid(state) }
        }

        item { SectionTitle("MA-cross backtest") }
        item { BacktestPanel(state.backtest, onBacktestParams) }
    }
}

@Composable
private fun ClassTabRow(selected: MarketClassTab, onSelect: (MarketClassTab) -> Unit) {
    LazyRow(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        items(MARKET_CLASS_TABS) { tab ->
            FilterChip(
                selected = tab.label == selected.label,
                onClick = { onSelect(tab) },
                label = { Text(tab.label) },
                modifier = Modifier.testTag("class_tab_${tab.label}"),
            )
        }
    }
}

@Composable
private fun SymbolChips(
    instruments: List<Instrument>,
    selectedId: Int?,
    label: String,
    onSelect: (Int) -> Unit,
    selectedSet: Set<Int> = emptySet(),
) {
    Column(modifier = Modifier.padding(horizontal = 8.dp)) {
        Text(label, color = MarketColors.TextSecondary, fontSize = 12.sp)
        Spacer(Modifier.height(4.dp))
        LazyRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            items(instruments) { inst ->
                val on = inst.symbolId == selectedId || inst.symbolId in selectedSet
                FilterChip(
                    selected = on,
                    onClick = { onSelect(inst.symbolId) },
                    label = { Text(inst.symbol) },
                    modifier = Modifier.testTag("symbol_chip_${inst.symbol}"),
                )
            }
        }
    }
}

@Composable
private fun RangeRow(selected: AnalysisRange, onSelect: (AnalysisRange) -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        AnalysisRange.entries.forEach { r ->
            FilterChip(
                selected = r == selected,
                onClick = { onSelect(r) },
                label = { Text(r.label) },
                modifier = Modifier.testTag("range_chip_${r.label}"),
            )
        }
    }
}

@Composable
private fun DegradedBanner() {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 8.dp)
            .clip(RoundedCornerShape(8.dp))
            .background(MarketColors.DownPill)
            .padding(horizontal = 12.dp, vertical = 8.dp)
            .testTag("degraded_banner"),
    ) {
        Text(
            "Recent window only — long-range history pending backend (/md/history).",
            color = MarketColors.TextPrimary,
            fontSize = 12.sp,
        )
    }
}

@Composable
private fun SectionTitle(text: String) {
    Text(
        text,
        color = MarketColors.TextPrimary,
        fontSize = 15.sp,
        fontWeight = FontWeight.SemiBold,
        modifier = Modifier.padding(horizontal = 12.dp),
    )
}

@Composable
private fun EmptyHint(text: String) {
    Text(text, color = MarketColors.TextSecondary, fontSize = 13.sp, modifier = Modifier.padding(horizontal = 12.dp))
}

@Composable
private fun StatsPanel(stats: SymbolStats?) {
    if (stats == null) {
        EmptyHint("Not enough data for statistics.")
        return
    }
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 8.dp)
            .clip(RoundedCornerShape(10.dp))
            .background(MarketColors.Surface)
            .padding(12.dp)
            .testTag("stats_panel"),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        StatRow("Period return", pct(stats.periodReturnPct), signColor(stats.periodReturnPct))
        StatRow("Cumulative return", pct(stats.cumulativeReturnPct), signColor(stats.cumulativeReturnPct))
        StatRow("Volatility (ann.)", pct(stats.annualizedVolPct), MarketColors.TextPrimary)
        StatRow("Max drawdown", pct(stats.maxDrawdownPct?.let { -it }), MarketColors.Down)
        StatRow("High", num(stats.high), MarketColors.TextPrimary)
        StatRow("Low", num(stats.low), MarketColors.TextPrimary)
        StatRow("Avg volume", num(stats.avgVolume), MarketColors.TextPrimary)
        StatRow("Total volume", num(stats.totalVolume), MarketColors.TextPrimary)
    }
}

@Composable
private fun StatRow(label: String, value: String, valueColor: Color) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(label, color = MarketColors.TextSecondary, fontSize = 13.sp)
        Text(value, color = valueColor, fontSize = 13.sp, fontFamily = FontFamily.Monospace)
    }
}

@Composable
private fun CompareOverlay(state: MarketAnalysisUiState) {
    val primary = state.primary
    if (primary == null || primary.closes.size < 2) {
        EmptyHint("Select a symbol with data to overlay.")
        return
    }
    val series = listOf(primary) + state.compareSeries
    val normalized = series.map { it.instrument.symbol to MarketStats.normalizeToBase(it.closes) }
        .filter { it.second.size >= 2 }
    if (normalized.isEmpty()) {
        EmptyHint("No overlay data.")
        return
    }
    val palette = listOf(MarketColors.Accent, MarketColors.Up, MarketColors.Down, Color(0xFFF0B90B), Color(0xFF6C8CFF))
    Column(modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp)) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(180.dp)
                .clip(RoundedCornerShape(10.dp))
                .background(MarketColors.Surface)
                .padding(8.dp)
                .testTag("compare_overlay"),
        ) {
            val allVals = normalized.flatMap { it.second }
            val minV = allVals.min()
            val maxV = allVals.max()
            val span = (maxV - minV).takeIf { it > 0.0 } ?: 1.0
            Canvas(modifier = Modifier.fillMaxSize()) {
                normalized.forEachIndexed { idx, (_, vals) ->
                    val color = palette[idx % palette.size]
                    val stepX = if (vals.size > 1) size.width / (vals.size - 1) else size.width
                    for (i in 1 until vals.size) {
                        val x0 = stepX * (i - 1)
                        val x1 = stepX * i
                        val y0 = size.height - ((vals[i - 1] - minV) / span).toFloat() * size.height
                        val y1 = size.height - ((vals[i] - minV) / span).toFloat() * size.height
                        drawLine(color, Offset(x0, y0), Offset(x1, y1), strokeWidth = 2.5f, cap = StrokeCap.Round)
                    }
                }
            }
        }
        Spacer(Modifier.height(6.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.horizontalScroll(rememberScrollState())) {
            normalized.forEachIndexed { idx, (sym, _) ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(modifier = Modifier.width(12.dp).height(3.dp).background(palette[idx % palette.size]))
                    Spacer(Modifier.width(4.dp))
                    Text(sym, color = MarketColors.TextSecondary, fontSize = 12.sp)
                }
            }
        }
    }
}

@Composable
private fun CorrelationGrid(state: MarketAnalysisUiState) {
    val symbols = (listOf(state.primary) + state.compareSeries)
        .mapNotNull { it?.instrument?.symbol }
    val byKey = state.correlation.associateBy { it.rowSymbol to it.colSymbol }
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 8.dp)
            .clip(RoundedCornerShape(10.dp))
            .background(MarketColors.Surface)
            .padding(8.dp)
            .horizontalScroll(rememberScrollState())
            .testTag("correlation_grid"),
    ) {
        // Header row.
        Row {
            CorrCell("", header = true)
            symbols.forEach { CorrCell(it, header = true) }
        }
        symbols.forEach { rowSym ->
            Row {
                CorrCell(rowSym, header = true)
                symbols.forEach { colSym ->
                    val r = byKey[rowSym to colSym]?.r
                    CorrCell(r?.let { String.format("%.2f", it) } ?: "--", corr = r)
                }
            }
        }
    }
}

@Composable
private fun CorrCell(text: String, header: Boolean = false, corr: Double? = null) {
    val bg = when {
        header -> Color.Transparent
        corr == null -> MarketColors.SurfaceAlt
        corr >= 0 -> MarketColors.UpFill
        else -> MarketColors.DownFill
    }
    Box(
        modifier = Modifier
            .width(54.dp)
            .height(30.dp)
            .background(bg),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text,
            color = if (header) MarketColors.TextSecondary else MarketColors.TextPrimary,
            fontSize = 11.sp,
            fontFamily = FontFamily.Monospace,
        )
    }
}

@Composable
private fun BacktestPanel(state: BacktestState, onParams: (Int, Int) -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 8.dp)
            .clip(RoundedCornerShape(10.dp))
            .background(MarketColors.Surface)
            .padding(12.dp)
            .testTag("backtest_panel"),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        StepperRow("Fast SMA", state.fast) { onParams(it.coerceIn(1, state.slow - 1), state.slow) }
        StepperRow("Slow SMA", state.slow) { onParams(state.fast, it.coerceIn(state.fast + 1, 200)) }
        val result = state.result
        if (result == null || result.trades == 0) {
            EmptyHint("Not enough bars (or no crossover) to backtest.")
        } else {
            StatRow("Total return", pct(result.totalReturn * 100.0), signColor(result.totalReturn * 100.0))
            StatRow("Win rate", pct(result.winRate * 100.0), MarketColors.TextPrimary)
            StatRow("Trades", result.trades.toString(), MarketColors.TextPrimary)
            Spacer(Modifier.height(2.dp))
            EquityCurve(result.equityCurve)
        }
    }
}

@Composable
private fun StepperRow(label: String, value: Int, onChange: (Int) -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(label, color = MarketColors.TextSecondary, fontSize = 13.sp)
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            StepButton("-") { onChange(value - 1) }
            Text(value.toString(), color = MarketColors.TextPrimary, fontSize = 14.sp, fontFamily = FontFamily.Monospace)
            StepButton("+") { onChange(value + 1) }
        }
    }
}

@Composable
private fun StepButton(text: String, onClick: () -> Unit) {
    Box(
        modifier = Modifier
            .width(32.dp)
            .height(32.dp)
            .clip(RoundedCornerShape(6.dp))
            .background(MarketColors.SurfaceAlt)
            .testTag("step_$text"),
        contentAlignment = Alignment.Center,
    ) {
        androidx.compose.material3.TextButton(onClick = onClick, modifier = Modifier.fillMaxSize()) {
            Text(text, color = MarketColors.TextPrimary, fontSize = 16.sp)
        }
    }
}

@Composable
private fun EquityCurve(curve: List<Double>) {
    if (curve.size < 2) return
    val minV = curve.min()
    val maxV = curve.max()
    val span = (maxV - minV).takeIf { it > 0.0 } ?: 1.0
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(120.dp)
            .clip(RoundedCornerShape(8.dp))
            .background(MarketColors.SurfaceAlt)
            .padding(6.dp)
            .testTag("equity_curve"),
    ) {
        Canvas(modifier = Modifier.fillMaxSize()) {
            val stepX = if (curve.size > 1) size.width / (curve.size - 1) else size.width
            val up = curve.last() >= curve.first()
            val color = if (up) MarketColors.Up else MarketColors.Down
            for (i in 1 until curve.size) {
                val x0 = stepX * (i - 1)
                val x1 = stepX * i
                val y0 = size.height - ((curve[i - 1] - minV) / span).toFloat() * size.height
                val y1 = size.height - ((curve[i] - minV) / span).toFloat() * size.height
                drawLine(color, Offset(x0, y0), Offset(x1, y1), strokeWidth = 2.5f, cap = StrokeCap.Round)
            }
        }
    }
}

/** Adapt the workbench's [HistoryBar]s (second timestamps) into [Candle]s for the shared chart. */
private fun barsToCandles(bars: List<HistoryBar>): List<Candle> = bars.map {
    Candle(
        tsStartNs = it.ts * 1_000_000_000L,
        open = it.open,
        high = it.high,
        low = it.low,
        close = it.close,
        volume = it.volume,
        trades = 0L,
    )
}

private fun signColor(pct: Double?): Color = when {
    pct == null -> MarketColors.TextPrimary
    pct >= 0 -> MarketColors.Up
    else -> MarketColors.Down
}

private fun pct(v: Double?): String = if (v == null) "--" else String.format("%+.2f%%", v)

private fun num(v: Double?): String = when {
    v == null -> "--"
    abs(v) >= 1000 -> String.format("%,.0f", v)
    else -> String.format("%.2f", v)
}
