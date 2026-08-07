@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.markets

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
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
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.exchange.Aggressor
import com.testlogon.android.data.exchange.Candle
import com.testlogon.android.data.exchange.OrderBook
import com.testlogon.android.data.exchange.OrderBookLevel
import com.testlogon.android.data.exchange.Trade
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.math.abs

private val UpColor = Color(0xFF16A34A)
private val DownColor = Color(0xFFDC2626)

@Composable
fun SymbolDetailRoute(
    onBack: () -> Unit,
    viewModel: SymbolDetailViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(state.symbolName.ifBlank { "Symbol" }) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Box(modifier = Modifier.fillMaxSize().padding(padding)) {
            when (state.phase) {
                SymbolDetailUiState.Phase.Loading -> LoadingState(message = "Loading market data")
                SymbolDetailUiState.Phase.Error -> ErrorState(
                    message = state.errorMessage ?: "Could not load market data.",
                    onRetry = viewModel::onRetry,
                )
                SymbolDetailUiState.Phase.Content -> SymbolDetailContent(state)
            }
        }
    }
}

@Composable
private fun SymbolDetailContent(state: SymbolDetailUiState) {
    LazyColumn(
        modifier = Modifier.fillMaxSize().testTag("symbol_detail"),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(20.dp),
    ) {
        item {
            SectionHeader("Price")
            CandlestickChart(
                candles = state.candles,
                modifier = Modifier.fillMaxWidth().height(220.dp).testTag("candle_chart"),
            )
        }
        item {
            SectionHeader("Order book")
            OrderBookLadder(book = state.orderBook)
        }
        item {
            SectionHeader("Recent trades")
        }
        items(state.trades.take(40)) { trade ->
            TradeRow(trade)
        }
        if (state.trades.isEmpty()) {
            item { Text("No trades yet.", style = MaterialTheme.typography.bodySmall) }
        }
    }
}

@Composable
private fun SectionHeader(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.titleMedium,
        fontWeight = FontWeight.SemiBold,
        modifier = Modifier.padding(bottom = 8.dp),
    )
}

@Composable
private fun CandlestickChart(candles: List<Candle>, modifier: Modifier = Modifier) {
    if (candles.isEmpty()) {
        Box(modifier = modifier, contentAlignment = Alignment.Center) {
            Text("No candles.", style = MaterialTheme.typography.bodySmall)
        }
        return
    }
    val window = candles.takeLast(60)
    val minLow = window.minOf { it.low }
    val maxHigh = window.maxOf { it.high }
    val range = (maxHigh - minLow).coerceAtLeast(1)

    Canvas(modifier = modifier) {
        val n = window.size
        val slot = size.width / n
        val bodyWidth = (slot * 0.6f).coerceAtLeast(1f)

        fun yOf(price: Long): Float =
            size.height * (1f - ((price - minLow).toFloat() / range.toFloat()))

        window.forEachIndexed { index, c ->
            val cx = slot * index + slot / 2f
            val up = c.close >= c.open
            val color = if (up) UpColor else DownColor

            drawLine(
                color = color,
                start = Offset(cx, yOf(c.high)),
                end = Offset(cx, yOf(c.low)),
                strokeWidth = 2f,
            )

            val yOpen = yOf(c.open)
            val yClose = yOf(c.close)
            val top = minOf(yOpen, yClose)
            val bodyHeight = abs(yClose - yOpen).coerceAtLeast(2f)
            drawRect(
                color = color,
                topLeft = Offset(cx - bodyWidth / 2f, top),
                size = Size(bodyWidth, bodyHeight),
            )
        }
    }
}

@Composable
private fun OrderBookLadder(book: OrderBook?) {
    if (book == null || (book.asks.isEmpty() && book.bids.isEmpty())) {
        Text("No order book.", style = MaterialTheme.typography.bodySmall)
        return
    }
    val maxQty = (book.asks + book.bids).maxOfOrNull { it.qty }?.coerceAtLeast(1) ?: 1
    Column(modifier = Modifier.fillMaxWidth().testTag("order_book")) {
        book.asks.take(10).reversed().forEach { level ->
            LadderRow(level = level, maxQty = maxQty, color = DownColor, alignEnd = true)
        }
        val spread = book.spread
        Row(
            modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
            horizontalArrangement = Arrangement.Center,
        ) {
            Text(
                text = "Spread " + (spread?.let { formatPrice(it.toDouble()) } ?: "-"),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontFamily = FontFamily.Monospace,
            )
        }
        book.bids.take(10).forEach { level ->
            LadderRow(level = level, maxQty = maxQty, color = UpColor, alignEnd = false)
        }
    }
}

@Composable
private fun LadderRow(
    level: OrderBookLevel,
    maxQty: Long,
    color: Color,
    alignEnd: Boolean,
) {
    val fraction = (level.qty.toFloat() / maxQty.toFloat()).coerceIn(0f, 1f)
    Box(modifier = Modifier.fillMaxWidth().height(24.dp)) {
        Box(
            modifier = Modifier
                .fillMaxWidth(fraction)
                .height(24.dp)
                .align(if (alignEnd) Alignment.CenterEnd else Alignment.CenterStart)
                .background(color.copy(alpha = 0.15f)),
        )
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = formatPrice(level.price.toDouble()),
                style = MaterialTheme.typography.bodySmall,
                color = color,
                fontFamily = FontFamily.Monospace,
            )
            Text(
                text = level.qty.toString(),
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
            )
        }
    }
}

private val tapeTimeFormat = SimpleDateFormat("HH:mm:ss", Locale.US)

@Composable
private fun TradeRow(trade: Trade) {
    val color = when (trade.aggressor) {
        Aggressor.BUY -> UpColor
        Aggressor.SELL -> DownColor
        Aggressor.UNKNOWN -> MaterialTheme.colorScheme.onSurface
    }
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = formatPrice(trade.price.toDouble()),
            style = MaterialTheme.typography.bodySmall,
            color = color,
            fontFamily = FontFamily.Monospace,
        )
        Text(
            text = trade.qty.toString(),
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
        )
        Text(
            text = tapeTimeFormat.format(Date(trade.tsNs / 1_000_000L)),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            fontFamily = FontFamily.Monospace,
        )
    }
}
