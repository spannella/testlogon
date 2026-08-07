@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.markets

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
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
import com.testlogon.android.data.exchange.Trade
import com.testlogon.android.feature.markets.book.OrderBookL2
import com.testlogon.android.feature.markets.chart.CandlestickChart
import com.testlogon.android.feature.markets.chart.Timeframe
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private val UpColor = Color(0xFF16A34A)
private val DownColor = Color(0xFFDC2626)

// Display scaler for raw integer prices/qty. All instruments use a scaler of 1 today, so this is an
// identity divide; the seam is honoured so a non-1 scaler would flow through unchanged.
private const val PRICE_SCALER = 1L

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
                SymbolDetailUiState.Phase.Content -> SymbolDetailContent(
                    state = state,
                    onTimeframe = { viewModel.setInterval(it.seconds) },
                )
            }
        }
    }
}

@Composable
private fun SymbolDetailContent(
    state: SymbolDetailUiState,
    onTimeframe: (Timeframe) -> Unit,
) {
    val selectedTf = Timeframe.entries.firstOrNull { it.seconds == state.intervalSec } ?: Timeframe.M1
    LazyColumn(
        modifier = Modifier.fillMaxSize().testTag("symbol_detail"),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(20.dp),
    ) {
        item {
            SectionHeader("Price")
            CandlestickChart(
                candles = state.candles,
                priceScaler = PRICE_SCALER,
                selected = selectedTf,
                onTimeframeSelected = onTimeframe,
                modifier = Modifier.fillMaxWidth(),
            )
        }
        item {
            SectionHeader(if (state.live) "Order book (LIVE)" else "Order book")
            OrderBookL2(book = state.orderBook, priceScaler = PRICE_SCALER)
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
