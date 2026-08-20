@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.testlogon.android.feature.paper

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.RestartAlt
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.Button
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.data.exchange.OrderSide
import com.testlogon.android.feature.markets.trade.OrderMath
import com.testlogon.android.feature.paper.PaperEngine.PaperOrderType
import java.util.Locale

private val Up = Color(0xFF16A34A)
private val Down = Color(0xFFDC2626)

@Composable
fun PaperRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: PaperViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    PaperScreen(
        state = state,
        onBack = onBack,
        onSelectSymbol = viewModel::onSelectSymbol,
        onSideChange = viewModel::onSideChange,
        onTypeChange = viewModel::onTypeChange,
        onQtyChange = viewModel::onQtyChange,
        onLimitPriceChange = viewModel::onLimitPriceChange,
        onSubmit = viewModel::onSubmit,
        onCancelOrder = viewModel::onCancelOrder,
        onReset = viewModel::onReset,
        onConsumeToast = viewModel::consumeToast,
        modifier = modifier,
    )
}

@Composable
fun PaperScreen(
    state: PaperUiState,
    onBack: () -> Unit,
    onSelectSymbol: (Int) -> Unit,
    onSideChange: (OrderSide) -> Unit,
    onTypeChange: (PaperOrderType) -> Unit,
    onQtyChange: (String) -> Unit,
    onLimitPriceChange: (String) -> Unit,
    onSubmit: () -> Unit,
    onCancelOrder: (String) -> Unit,
    onReset: () -> Unit,
    onConsumeToast: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbar = remember { SnackbarHostState() }
    var confirmReset by remember { mutableStateOf(false) }

    LaunchedEffect(state.toast) {
        state.toast?.let {
            snackbar.showSnackbar(it)
            onConsumeToast()
        }
    }

    Scaffold(
        modifier = modifier.fillMaxSize(),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text("Paper Trading") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(onClick = { confirmReset = true }) {
                        Icon(Icons.Filled.RestartAlt, contentDescription = "Reset paper account")
                    }
                },
            )
        },
    ) { padding ->
        if (state.loading) {
            Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
                CircularProgressIndicator()
            }
            return@Scaffold
        }
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(padding),
            contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item { PaperBanner() }
            item {
                SymbolAndPrice(state = state, onSelectSymbol = onSelectSymbol)
            }
            item { AccountPanel(state) }
            item {
                OrderTicket(
                    state = state,
                    onSideChange = onSideChange,
                    onTypeChange = onTypeChange,
                    onQtyChange = onQtyChange,
                    onLimitPriceChange = onLimitPriceChange,
                    onSubmit = onSubmit,
                )
            }
            item { SectionHeader("Positions") }
            if (state.positions.isEmpty()) {
                item { EmptyRow("No open positions") }
            } else {
                items(state.positions, key = { it.symbolId }) { PositionRow(it) }
            }
            item { SectionHeader("Working orders") }
            if (state.workingOrders.isEmpty()) {
                item { EmptyRow("No working orders") }
            } else {
                items(state.workingOrders, key = { it.id }) { WorkingOrderRow(it, onCancelOrder) }
            }
            item { SectionHeader("Fill history") }
            if (state.fills.isEmpty()) {
                item { EmptyRow("No fills yet") }
            } else {
                items(state.fills) { FillRow(it) }
            }
        }
    }

    if (confirmReset) {
        AlertDialog(
            onDismissRequest = { confirmReset = false },
            title = { Text("Reset paper account?") },
            text = { Text("This clears all simulated positions, orders, fills, and PnL, and restores the starting balance. This cannot be undone.") },
            confirmButton = {
                TextButton(onClick = { confirmReset = false; onReset() }) { Text("Reset") }
            },
            dismissButton = { TextButton(onClick = { confirmReset = false }) { Text("Cancel") } },
        )
    }
}

@Composable
private fun PaperBanner() {
    Surface(
        color = MaterialTheme.colorScheme.tertiaryContainer,
        shape = MaterialTheme.shapes.medium,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Text(
            "PAPER — simulated trading, not real funds",
            style = MaterialTheme.typography.labelLarge,
            fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.onTertiaryContainer,
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 10.dp),
        )
    }
}

@Composable
private fun SymbolAndPrice(state: PaperUiState, onSelectSymbol: (Int) -> Unit) {
    var expanded by remember { mutableStateOf(false) }
    val selected = state.selectedSymbol
    Card(Modifier.fillMaxWidth()) {
        Row(
            Modifier.fillMaxWidth().padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            ExposedDropdownMenuBox(expanded = expanded, onExpandedChange = { expanded = it }) {
                OutlinedTextField(
                    value = selected?.symbol ?: "Select symbol",
                    onValueChange = {},
                    readOnly = true,
                    label = { Text("Symbol") },
                    trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
                    modifier = Modifier.menuAnchor().width(190.dp),
                )
                ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
                    state.symbols.forEach { s ->
                        DropdownMenuItem(
                            text = { Text(s.symbol) },
                            onClick = { expanded = false; onSelectSymbol(s.symbolId) },
                        )
                    }
                }
            }
            Column(horizontalAlignment = Alignment.End) {
                Text("Mark", style = MaterialTheme.typography.labelSmall)
                Text(
                    state.markPrice?.let { fmt(it) } ?: "—",
                    style = MaterialTheme.typography.titleLarge,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Bold,
                )
            }
        }
    }
}

@Composable
private fun AccountPanel(state: PaperUiState) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            StatLine("Starting balance", fmt(state.startingCash))
            StatLine("Cash", fmt(state.cash))
            StatLine("Equity", fmt(state.equity), if (state.isEquityUp) Up else Down)
            HorizontalDivider(Modifier.padding(vertical = 4.dp))
            StatLine("Realized PnL", signed(state.realizedPnl), pnlColor(state.realizedPnl))
            StatLine("Unrealized PnL", signed(state.unrealizedPnl), pnlColor(state.unrealizedPnl))
            StatLine("Total PnL", signed(state.totalPnl), pnlColor(state.totalPnl), bold = true)
        }
    }
}

@Composable
private fun StatLine(label: String, value: String, color: Color? = null, bold: Boolean = false) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, style = MaterialTheme.typography.bodyMedium)
        Text(
            value,
            style = MaterialTheme.typography.bodyMedium,
            fontFamily = FontFamily.Monospace,
            fontWeight = if (bold) FontWeight.Bold else FontWeight.Normal,
            color = color ?: MaterialTheme.colorScheme.onSurface,
        )
    }
}

@Composable
private fun OrderTicket(
    state: PaperUiState,
    onSideChange: (OrderSide) -> Unit,
    onTypeChange: (PaperOrderType) -> Unit,
    onQtyChange: (String) -> Unit,
    onLimitPriceChange: (String) -> Unit,
    onSubmit: () -> Unit,
) {
    val ticket = state.ticket
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("New paper order", style = MaterialTheme.typography.titleMedium)
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(selected = ticket.side == OrderSide.BUY, onClick = { onSideChange(OrderSide.BUY) }, label = { Text("Buy") })
                FilterChip(selected = ticket.side == OrderSide.SELL, onClick = { onSideChange(OrderSide.SELL) }, label = { Text("Sell") })
                Spacer(Modifier.width(8.dp))
                FilterChip(selected = ticket.type == PaperOrderType.MARKET, onClick = { onTypeChange(PaperOrderType.MARKET) }, label = { Text("Market") })
                FilterChip(selected = ticket.type == PaperOrderType.LIMIT, onClick = { onTypeChange(PaperOrderType.LIMIT) }, label = { Text("Limit") })
            }
            OutlinedTextField(
                value = ticket.qtyInput,
                onValueChange = onQtyChange,
                label = { Text("Quantity") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                modifier = Modifier.fillMaxWidth(),
            )
            if (ticket.type == PaperOrderType.LIMIT) {
                OutlinedTextField(
                    value = ticket.limitPriceInput,
                    onValueChange = onLimitPriceChange,
                    label = { Text("Limit price") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            // Reuse OrderMath for the notional preview at the effective price.
            val price = if (ticket.type == PaperOrderType.LIMIT) ticket.limitPrice else state.markPrice
            val notional = OrderMath.notional(price, ticket.qty)
            Text(
                "Est. notional: " + (notional?.let { fmt(it) } ?: "—"),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Button(
                onClick = onSubmit,
                enabled = ticket.isValid() && state.markPrice != null,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    (if (ticket.side == OrderSide.BUY) "Buy" else "Sell") + " " +
                        (if (ticket.type == PaperOrderType.MARKET) "market" else "limit") + " (paper)",
                )
            }
        }
    }
}

@Composable
private fun PositionRow(row: PaperPositionRow) {
    Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors()) {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column {
                Text(row.symbol, fontWeight = FontWeight.Bold)
                Text(
                    (if (row.isLong) "Long " else "Short ") + Math.abs(row.qty) + " @ " + fmt(row.avgEntry),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Column(horizontalAlignment = Alignment.End) {
                Text("Mark " + (row.mark?.let { fmt(it) } ?: "—"), style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
                Text(
                    signed(row.unrealized),
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Bold,
                    color = pnlColor(row.unrealized),
                )
            }
        }
    }
}

@Composable
private fun WorkingOrderRow(row: PaperOrderRow, onCancel: (String) -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Row(
            Modifier.fillMaxWidth().padding(start = 16.dp, top = 4.dp, bottom = 4.dp, end = 4.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column {
                Text(row.symbol, fontWeight = FontWeight.Bold)
                Text(
                    (if (row.side == OrderSide.BUY) "Buy" else "Sell") + " " + row.qty +
                        (row.limitPrice?.let { " limit @ " + fmt(it) } ?: ""),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            IconButton(onClick = { onCancel(row.id) }) {
                Icon(Icons.Filled.Close, contentDescription = "Cancel order")
            }
        }
    }
}

@Composable
private fun FillRow(row: PaperFillRow) {
    Row(
        Modifier.fillMaxWidth().padding(vertical = 6.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(
            row.symbol + "  " + (if (row.side == OrderSide.BUY) "Buy" else "Sell"),
            style = MaterialTheme.typography.bodyMedium,
            color = if (row.side == OrderSide.BUY) Up else Down,
        )
        Text(
            row.qty.toString() + " @ " + fmt(row.price),
            style = MaterialTheme.typography.bodyMedium,
            fontFamily = FontFamily.Monospace,
        )
    }
}

@Composable
private fun SectionHeader(title: String) {
    Text(
        title,
        style = MaterialTheme.typography.titleMedium,
        fontWeight = FontWeight.Bold,
        modifier = Modifier.padding(top = 8.dp),
    )
}

@Composable
private fun EmptyRow(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(vertical = 4.dp),
    )
}

@Composable
private fun pnlColor(v: Long): Color = if (v >= 0) Up else Down

private fun fmt(ticks: Long): String = "$" + String.format(Locale.US, "%,d", ticks)

private fun signed(ticks: Long): String =
    (if (ticks >= 0) "+" else "-") + "$" + String.format(Locale.US, "%,d", Math.abs(ticks))
