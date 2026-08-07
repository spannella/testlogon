@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.markets

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Card
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
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState

/**
 * Markets (VIEW-ONLY) list route. Shows the tradable instruments with a live-polled last price and
 * best bid/ask; a row taps through to the per-symbol detail (chart / order book / trades).
 */
@Composable
fun MarketsRoute(
    onBack: () -> Unit,
    onOpenSymbol: (symbolId: Int) -> Unit,
    viewModel: MarketsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Markets") },
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
                MarketsUiState.Phase.Loading -> LoadingState(message = "Loading markets…")
                MarketsUiState.Phase.Empty -> EmptyState(
                    title = "No markets",
                    body = "No instruments are available right now.",
                )
                MarketsUiState.Phase.Error -> ErrorState(
                    message = state.errorMessage ?: "Something went wrong.",
                    onRetry = viewModel::onRetry,
                )
                MarketsUiState.Phase.Content -> MarketsList(
                    rows = state.rows,
                    onOpenSymbol = onOpenSymbol,
                )
            }
        }
    }
}

@Composable
private fun MarketsList(
    rows: List<MarketRow>,
    onOpenSymbol: (Int) -> Unit,
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize().testTag("markets_list"),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(12.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        items(rows, key = { it.instrument.symbolId }) { row ->
            MarketRowCard(row = row, onClick = { onOpenSymbol(row.instrument.symbolId) })
        }
    }
}

@Composable
private fun MarketRowCard(row: MarketRow, onClick: () -> Unit) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag("market_row_${row.instrument.symbolId}")
            .clickable(onClick = onClick),
    ) {
        Column(modifier = Modifier.fillMaxWidth().padding(16.dp)) {
            androidx.compose.foundation.layout.Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = row.instrument.symbol,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                )
                Text(
                    text = row.lastPrice?.let { formatPrice(it) } ?: "—",
                    style = MaterialTheme.typography.titleMedium,
                    fontFamily = FontFamily.Monospace,
                )
            }
            androidx.compose.foundation.layout.Row(
                modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
                horizontalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Text(
                    text = "Bid " + (row.bestBid?.let { formatPrice(it.toDouble()) } ?: "—"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.primary,
                    fontFamily = FontFamily.Monospace,
                )
                Text(
                    text = "Ask " + (row.bestAsk?.let { formatPrice(it.toDouble()) } ?: "—"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                    fontFamily = FontFamily.Monospace,
                )
            }
        }
    }
}

/** Locale-agnostic grouped price format (no currency symbol; instruments are already quote-named). */
internal fun formatPrice(value: Double): String {
    val whole = value == value.toLong().toDouble()
    return if (whole) String.format("%,d", value.toLong()) else String.format("%,.2f", value)
}
