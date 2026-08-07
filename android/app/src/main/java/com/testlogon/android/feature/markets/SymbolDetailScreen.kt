@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.markets

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.exchange.Aggressor
import com.testlogon.android.data.exchange.Candle
import com.testlogon.android.data.exchange.Trade
import com.testlogon.android.feature.markets.book.BookStyle
import com.testlogon.android.feature.markets.book.OrderBookL2
import com.testlogon.android.feature.markets.chart.CandlestickChart
import com.testlogon.android.feature.markets.chart.ChartDrawing
import com.testlogon.android.feature.markets.chart.ChartType
import com.testlogon.android.feature.markets.chart.DrawingTool
import com.testlogon.android.feature.markets.chart.Oscillator
import com.testlogon.android.feature.markets.chart.Timeframe
import com.testlogon.android.feature.markets.trade.TradeTicket
import com.testlogon.android.feature.markets.ui.MarketColors
import com.testlogon.android.feature.markets.ui.MarketSurface
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

// Display scaler for raw integer prices/qty. All instruments use a scaler of 1 today.
private const val PRICE_SCALER = 1L

@Composable
fun SymbolDetailRoute(
    onBack: () -> Unit,
    viewModel: SymbolDetailViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    MarketSurface {
        Column(modifier = Modifier.fillMaxSize().statusBarsPadding()) {
            DetailTopBar(title = state.symbolName.ifBlank { "Symbol" }, live = state.live, onBack = onBack)
            Box(modifier = Modifier.fillMaxSize()) {
                when (state.phase) {
                    SymbolDetailUiState.Phase.Loading -> LoadingState(message = "Loading market data")
                    SymbolDetailUiState.Phase.Error -> ErrorState(
                        message = state.errorMessage ?: "Could not load market data.",
                        onRetry = viewModel::onRetry,
                    )
                    SymbolDetailUiState.Phase.Content -> SymbolDetailContent(
                        state = state,
                        onTimeframe = { viewModel.setInterval(it.seconds) },
                        onSetTool = viewModel::setTool,
                        onCommitDrawing = viewModel::addDrawing,
                        onClearDrawings = viewModel::clearDrawings,
                    )
                }
            }
        }
    }
}

@Composable
private fun DetailTopBar(title: String, live: Boolean, onBack: () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(start = 4.dp, end = 16.dp, top = 4.dp, bottom = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        IconButton(onClick = onBack) {
            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back", tint = MarketColors.TextPrimary)
        }
        Text(title, color = MarketColors.TextPrimary, fontWeight = FontWeight.Bold, fontSize = 18.sp)
        if (live) {
            Spacer(Modifier.width(8.dp))
            Box(
                modifier = Modifier
                    .clip(RoundedCornerShape(4.dp))
                    .background(MarketColors.UpPill)
                    .padding(horizontal = 6.dp, vertical = 2.dp),
            ) {
                Text("LIVE", color = MarketColors.Up, fontSize = 10.sp, fontWeight = FontWeight.Bold)
            }
        }
    }
}

@Composable
private fun SymbolDetailContent(
    state: SymbolDetailUiState,
    onTimeframe: (Timeframe) -> Unit,
    onSetTool: (DrawingTool) -> Unit,
    onCommitDrawing: (ChartDrawing) -> Unit,
    onClearDrawings: () -> Unit,
) {
    val selectedTf = Timeframe.entries.firstOrNull { it.seconds == state.intervalSec } ?: Timeframe.M1
    var chartType by remember { mutableStateOf(ChartType.CANDLES) }
    var oscillator by remember { mutableStateOf(Oscillator.NONE) }
    var bookStyle by remember { mutableStateOf(BookStyle.LADDER) }
    var tab by remember { mutableStateOf(DetailTab.CHART) }
    LazyColumn(
        modifier = Modifier.fillMaxSize().testTag("symbol_detail"),
        contentPadding = PaddingValues(bottom = 24.dp),
    ) {
        item { TickerHeader(state) }
        item { DetailTabBar(selected = tab, onSelect = { tab = it }) }
        when (tab) {
            DetailTab.CHART -> item {
                TimeframeBar(selected = selectedTf, onTimeframe = onTimeframe)
                Row(
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    OscillatorToggle(selected = oscillator, onSelect = { oscillator = it })
                    ChartTypeToggle(selected = chartType, onSelect = { chartType = it })
                }
                CandlestickChart(
                    candles = state.candles,
                    priceScaler = PRICE_SCALER,
                    selected = selectedTf,
                    chartType = chartType,
                    oscillator = oscillator,
                    drawings = state.drawings,
                    activeTool = state.activeTool,
                    onCommitDrawing = onCommitDrawing,
                    onTimeframeSelected = onTimeframe,
                    showTimeframes = false,
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp),
                )
                DrawingToolbar(
                    active = state.activeTool,
                    hasDrawings = state.drawings.isNotEmpty(),
                    onSetTool = onSetTool,
                    onClear = onClearDrawings,
                )
            }

            DetailTab.BOOK -> item {
                OrderBookHeader(style = bookStyle, onStyle = { bookStyle = it })
                OrderBookL2(
                    book = state.orderBook,
                    priceScaler = PRICE_SCALER,
                    style = bookStyle,
                    lastUp = lastTradeUp(state.trades),
                    modifier = Modifier.padding(horizontal = 12.dp),
                )
            }

            DetailTab.TRADES -> {
                item {
                    TradesPressureBar(state.trades)
                    TradesHeader()
                }
                items(state.trades.take(120)) { trade -> TradeRow(trade) }
                if (state.trades.isEmpty()) {
                    item {
                        Text(
                            "No trades yet.",
                            color = MarketColors.TextFaint,
                            fontSize = 12.sp,
                            modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                        )
                    }
                }
            }

            DetailTab.TRADE -> item {
                TradeTicket(lastPrice = state.candles.lastOrNull()?.close)
            }
        }
    }
}

@Composable
private fun TickerHeader(state: SymbolDetailUiState) {
    val candles = state.candles
    val last = candles.lastOrNull()
    val lastPrice = last?.let { it.close.toDouble() / PRICE_SCALER } ?: state.orderBook?.mid
    // 24h-style window stats over the loaded candles.
    val firstOpen = candles.firstOrNull()?.open?.toDouble()?.div(PRICE_SCALER)
    val hi = candles.maxOfOrNull { it.high }?.toDouble()?.div(PRICE_SCALER)
    val lo = candles.minOfOrNull { it.low }?.toDouble()?.div(PRICE_SCALER)
    val vol = candles.sumOf { it.volume }
    val absChange = if (firstOpen != null && lastPrice != null) lastPrice - firstOpen else null
    val pct = if (firstOpen != null && firstOpen != 0.0 && absChange != null) absChange / firstOpen * 100.0 else null
    val up = (pct ?: 0.0) >= 0.0
    val moveColor = if (up) MarketColors.Up else MarketColors.Down

    Column(modifier = Modifier.fillMaxWidth().padding(start = 16.dp, end = 16.dp, top = 4.dp, bottom = 12.dp)) {
        Text(
            text = lastPrice?.let { formatPrice(it) } ?: "--",
            color = moveColor,
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.Bold,
            fontSize = 34.sp,
        )
        Spacer(Modifier.height(2.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            val sign = if (up) "+" else ""
            Text(
                text = absChange?.let { sign + formatPrice(it) } ?: "--",
                color = moveColor,
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.SemiBold,
                fontSize = 14.sp,
            )
            Spacer(Modifier.width(10.dp))
            Text(
                text = pct?.let { sign + String.format("%.2f%%", it) } ?: "--",
                color = moveColor,
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.SemiBold,
                fontSize = 14.sp,
            )
        }
        Spacer(Modifier.height(14.dp))
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(10.dp))
                .background(MarketColors.Surface)
                .border(1.dp, MarketColors.Border, RoundedCornerShape(10.dp))
                .padding(vertical = 10.dp, horizontal = 12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            StatCell("24h High", hi?.let { formatPrice(it) } ?: "--")
            StatCell("24h Low", lo?.let { formatPrice(it) } ?: "--")
            StatCell("24h Vol", if (vol > 0) formatCompact(vol) else "--")
        }
    }
}

@Composable
private fun StatCell(label: String, value: String) {
    Column(horizontalAlignment = Alignment.Start) {
        Text(label, color = MarketColors.TextFaint, fontSize = 10.sp)
        Spacer(Modifier.height(2.dp))
        Text(value, color = MarketColors.TextPrimary, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Medium, fontSize = 13.sp)
    }
}

@Composable
private fun TimeframeBar(selected: Timeframe, onTimeframe: (Timeframe) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 4.dp),
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Timeframe.entries.forEach { tf ->
            val sel = tf == selected
            Box(
                modifier = Modifier
                    .clip(RoundedCornerShape(6.dp))
                    .background(if (sel) MarketColors.SurfaceAlt else Color.Transparent)
                    .clickable { onTimeframe(tf) }
                    .testTag("tf_chip_${tf.label}")
                    .padding(horizontal = 12.dp, vertical = 6.dp),
            ) {
                Text(
                    text = tf.label,
                    color = if (sel) MarketColors.Accent else MarketColors.TextSecondary,
                    fontWeight = if (sel) FontWeight.Bold else FontWeight.Normal,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 12.sp,
                )
            }
        }
    }
}

@Composable
private fun OscillatorToggle(selected: Oscillator, onSelect: (Oscillator) -> Unit) {
    Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
        listOf(Oscillator.RSI, Oscillator.MACD).forEach { osc ->
            val sel = osc == selected
            Box(
                modifier = Modifier
                    .clip(RoundedCornerShape(6.dp))
                    .background(if (sel) MarketColors.SurfaceAlt else Color.Transparent)
                    .clickable { onSelect(if (sel) Oscillator.NONE else osc) }
                    .testTag("osc_${osc.name}")
                    .padding(horizontal = 8.dp, vertical = 6.dp),
            ) {
                Text(
                    text = osc.label,
                    color = if (sel) MarketColors.Accent else MarketColors.TextSecondary,
                    fontWeight = if (sel) FontWeight.Bold else FontWeight.Normal,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.sp,
                )
            }
        }
    }
}

@Composable
private fun ChartTypeToggle(selected: ChartType, onSelect: (ChartType) -> Unit) {
    Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
        ChartType.entries.forEach { ct ->
            val sel = ct == selected
            Box(
                modifier = Modifier
                    .clip(RoundedCornerShape(6.dp))
                    .background(if (sel) MarketColors.SurfaceAlt else Color.Transparent)
                    .clickable { onSelect(ct) }
                    .testTag("charttype_${ct.name}")
                    .padding(horizontal = 8.dp, vertical = 6.dp),
            ) {
                Text(
                    text = ct.label,
                    color = if (sel) MarketColors.Accent else MarketColors.TextSecondary,
                    fontWeight = if (sel) FontWeight.Bold else FontWeight.Normal,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.sp,
                )
            }
        }
    }
}

@Composable
private fun DrawingToolbar(
    active: DrawingTool,
    hasDrawings: Boolean,
    onSetTool: (DrawingTool) -> Unit,
    onClear: () -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 2.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Text(
            text = "Draw",
            color = MarketColors.TextFaint,
            fontSize = 11.sp,
            fontFamily = FontFamily.Monospace,
        )
        listOf(DrawingTool.HLINE, DrawingTool.TREND, DrawingTool.FIB, DrawingTool.RECT).forEach { tool ->
            val sel = tool == active
            Box(
                modifier = Modifier
                    .clip(RoundedCornerShape(6.dp))
                    .background(if (sel) MarketColors.SurfaceAlt else Color.Transparent)
                    .clickable { onSetTool(tool) }
                    .testTag("draw_${tool.name}")
                    .padding(horizontal = 8.dp, vertical = 6.dp),
            ) {
                Text(
                    text = tool.label,
                    color = if (sel) MarketColors.Accent else MarketColors.TextSecondary,
                    fontWeight = if (sel) FontWeight.Bold else FontWeight.Normal,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.sp,
                )
            }
        }
        Spacer(Modifier.weight(1f))
        if (hasDrawings) {
            Text(
                text = "Clear",
                color = MarketColors.Down,
                fontFamily = FontFamily.Monospace,
                fontSize = 11.sp,
                modifier = Modifier
                    .clip(RoundedCornerShape(6.dp))
                    .clickable { onClear() }
                    .testTag("draw_clear")
                    .padding(horizontal = 8.dp, vertical = 6.dp),
            )
        }
    }
}

/** Top-level panel selector for the symbol detail: Chart / Book / Trades. */
private enum class DetailTab(val label: String) { CHART("Chart"), BOOK("Book"), TRADES("Trades"), TRADE("Order") }

@Composable
private fun DetailTabBar(selected: DetailTab, onSelect: (DetailTab) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 6.dp)
            .clip(RoundedCornerShape(10.dp))
            .background(MarketColors.Surface)
            .border(1.dp, MarketColors.Border, RoundedCornerShape(10.dp))
            .padding(3.dp),
        horizontalArrangement = Arrangement.spacedBy(3.dp),
    ) {
        DetailTab.entries.forEach { t ->
            val sel = t == selected
            Box(
                modifier = Modifier
                    .weight(1f)
                    .clip(RoundedCornerShape(8.dp))
                    .background(if (sel) MarketColors.SurfaceAlt else Color.Transparent)
                    .clickable { onSelect(t) }
                    .testTag("detailtab_${t.name}")
                    .padding(vertical = 8.dp),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    text = t.label,
                    color = if (sel) MarketColors.Accent else MarketColors.TextSecondary,
                    fontWeight = if (sel) FontWeight.Bold else FontWeight.Normal,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 13.sp,
                )
            }
        }
    }
}

/** Buy/sell pressure bar over the recent trade window (green = taker buys, red = taker sells). */
@Composable
private fun TradesPressureBar(trades: List<Trade>) {
    val recent = trades.take(120)
    val buyVol = recent.filter { it.aggressor == Aggressor.BUY }.sumOf { it.qty }
    val sellVol = recent.filter { it.aggressor == Aggressor.SELL }.sumOf { it.qty }
    val total = (buyVol + sellVol).coerceAtLeast(1L)
    val buyFrac = (buyVol.toFloat() / total).coerceIn(0f, 1f)
    Column(modifier = Modifier.fillMaxWidth().padding(start = 12.dp, end = 12.dp, top = 16.dp, bottom = 4.dp)) {
        Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.SpaceBetween) {
            Text("Buy ${String.format("%.0f", buyFrac * 100)}%", color = MarketColors.Up, fontFamily = FontFamily.Monospace, fontSize = 11.sp)
            Text("Trades", color = MarketColors.TextPrimary, fontWeight = FontWeight.Bold, fontSize = 14.sp)
            Text("${String.format("%.0f", (1f - buyFrac) * 100)}% Sell", color = MarketColors.Down, fontFamily = FontFamily.Monospace, fontSize = 11.sp)
        }
        Spacer(Modifier.height(6.dp))
        Row(modifier = Modifier.fillMaxWidth().height(6.dp).clip(RoundedCornerShape(3.dp))) {
            Box(modifier = Modifier.weight(buyFrac.coerceIn(0.001f, 0.999f)).fillMaxHeight().background(MarketColors.Up))
            Box(modifier = Modifier.weight((1f - buyFrac).coerceIn(0.001f, 0.999f)).fillMaxHeight().background(MarketColors.Down))
        }
    }
}

@Composable
private fun OrderBookHeader(style: BookStyle, onStyle: (BookStyle) -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(start = 12.dp, end = 12.dp, top = 20.dp, bottom = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = "Order Book",
            color = MarketColors.TextPrimary,
            fontWeight = FontWeight.Bold,
            fontSize = 14.sp,
            modifier = Modifier.weight(1f),
        )
        Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
            BookStyle.entries.forEach { s ->
                val sel = s == style
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .background(if (sel) MarketColors.SurfaceAlt else Color.Transparent)
                        .clickable { onStyle(s) }
                        .testTag("bookstyle_${s.name}")
                        .padding(horizontal = 10.dp, vertical = 5.dp),
                ) {
                    Text(
                        text = s.label,
                        color = if (sel) MarketColors.Accent else MarketColors.TextSecondary,
                        fontWeight = if (sel) FontWeight.Bold else FontWeight.Normal,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
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
        color = MarketColors.TextPrimary,
        fontWeight = FontWeight.Bold,
        fontSize = 14.sp,
        modifier = Modifier.padding(start = 12.dp, end = 12.dp, top = 20.dp, bottom = 8.dp),
    )
}

@Composable
private fun TradesHeader() {
    Row(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 2.dp),
    ) {
        Text("Price", color = MarketColors.TextSecondary, fontFamily = FontFamily.Monospace, fontSize = 11.sp, modifier = Modifier.weight(1.2f))
        Text("Size", color = MarketColors.TextSecondary, fontFamily = FontFamily.Monospace, fontSize = 11.sp, modifier = Modifier.weight(1f))
        Text("Time", color = MarketColors.TextSecondary, fontFamily = FontFamily.Monospace, fontSize = 11.sp, textAlign = androidx.compose.ui.text.style.TextAlign.End, modifier = Modifier.weight(1f))
    }
}

private val tapeTimeFormat = SimpleDateFormat("HH:mm:ss", Locale.US)

@Composable
private fun TradeRow(trade: Trade) {
    val color = when (trade.aggressor) {
        Aggressor.BUY -> MarketColors.Up
        Aggressor.SELL -> MarketColors.Down
        Aggressor.UNKNOWN -> MarketColors.TextSecondary
    }
    val arrow = when (trade.aggressor) {
        Aggressor.BUY -> "^ "
        Aggressor.SELL -> "v "
        Aggressor.UNKNOWN -> ""
    }
    Row(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 1.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = arrow + formatPrice(trade.price.toDouble()),
            color = color,
            fontFamily = FontFamily.Monospace,
            fontSize = 12.sp,
            modifier = Modifier.weight(1.2f),
        )
        Text(
            text = trade.qty.toString(),
            color = MarketColors.TextPrimary,
            fontFamily = FontFamily.Monospace,
            fontSize = 12.sp,
            modifier = Modifier.weight(1f),
        )
        Text(
            text = tapeTimeFormat.format(Date(trade.tsNs / 1_000_000L)),
            color = MarketColors.TextFaint,
            fontFamily = FontFamily.Monospace,
            fontSize = 12.sp,
            textAlign = androidx.compose.ui.text.style.TextAlign.End,
            modifier = Modifier.weight(1f),
        )
    }
}

/** Direction of the most recent print, used to color the mid price in the book. Null when unknown. */
private fun lastTradeUp(trades: List<Trade>): Boolean? = when (trades.firstOrNull()?.aggressor) {
    Aggressor.BUY -> true
    Aggressor.SELL -> false
    else -> null
}

/** Compact large-number format for volume (e.g. 12.3K, 1.2M). */
private fun formatCompact(v: Long): String = when {
    v >= 1_000_000_000L -> String.format("%.2fB", v / 1_000_000_000.0)
    v >= 1_000_000L -> String.format("%.2fM", v / 1_000_000.0)
    v >= 1_000L -> String.format("%.2fK", v / 1_000.0)
    else -> v.toString()
}
