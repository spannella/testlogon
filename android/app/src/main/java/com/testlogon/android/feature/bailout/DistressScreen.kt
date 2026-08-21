@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.bailout

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.bailout.DistressPosition
import com.testlogon.android.data.bailout.HealthZone

/**
 * Margin distress overview: the caller's distressed-but-solvent positions, each with a 3-zone health
 * meter + buffer readout and, when eligible, a distress banner with ordered actions (Add margin /
 * Reduce position -> existing flows, then "Open bailout auction"). Server-authoritative; degrades to an
 * honest empty state on 404. Tapping a position with an existing auction opens the auction screen.
 */
@Composable
fun DistressRoute(
    onBack: () -> Unit,
    onOpenAuction: (symbolId: Int) -> Unit,
    onBrowseBailouts: () -> Unit,
    onAddMargin: () -> Unit,
    onReducePosition: (symbolId: Int) -> Unit,
    viewModel: DistressViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbar = remember { SnackbarHostState() }

    LaunchedEffect(state.actionMessage) {
        state.actionMessage?.let {
            snackbar.showSnackbar(it)
            viewModel.consumeActionMessage()
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Margin distress") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        when (state.phase) {
            DistressUiState.Phase.Loading -> LoadingState(message = "Checking your positions")
            DistressUiState.Phase.Error -> ErrorState(
                message = state.errorMessage ?: "Something went wrong.",
                onRetry = viewModel::onRetry,
                modifier = Modifier.padding(padding),
            )
            DistressUiState.Phase.Content -> DistressContent(
                state = state,
                modifier = Modifier.padding(padding),
                onOpenAuction = onOpenAuction,
                onBrowseBailouts = onBrowseBailouts,
                onAddMargin = onAddMargin,
                onReducePosition = onReducePosition,
                onOpenBailout = viewModel::openBailout,
            )
        }
    }
}

@Composable
private fun DistressContent(
    state: DistressUiState,
    modifier: Modifier = Modifier,
    onOpenAuction: (Int) -> Unit,
    onBrowseBailouts: () -> Unit,
    onAddMargin: () -> Unit,
    onReducePosition: (Int) -> Unit,
    onOpenBailout: (symbolId: Int, maxShareBps: Int) -> Unit,
) {
    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
            ) {
                Column(Modifier.padding(16.dp)) {
                    Text(
                        "A distressed but still-solvent margin position can raise rescue capital via a pre-emptive bailout auction - avoiding the forced-liquidation penalty. Once equity falls to maintenance it is too late (that is liquidation).",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    Spacer(Modifier.height(8.dp))
                    OutlinedButton(
                        onClick = onBrowseBailouts,
                        modifier = Modifier.fillMaxWidth().testTag("distress_browse_bailouts"),
                    ) { Text("Browse open bailouts (rescue others)") }
                }
            }
        }

        if (state.positions.isEmpty()) {
            item { EmptyDistress() }
        } else {
            items(state.positions.size, key = { "d_" + state.positions[it].symbolId + it }) { i ->
                DistressPositionCard(
                    pos = state.positions[i],
                    inFlight = state.actionInFlight,
                    onOpenAuction = onOpenAuction,
                    onAddMargin = onAddMargin,
                    onReducePosition = onReducePosition,
                    onOpenBailout = onOpenBailout,
                )
            }
        }
    }
}

@Composable
private fun DistressPositionCard(
    pos: DistressPosition,
    inFlight: Boolean,
    onOpenAuction: (Int) -> Unit,
    onAddMargin: () -> Unit,
    onReducePosition: (Int) -> Unit,
    onOpenBailout: (Int, Int) -> Unit,
) {
    val solvent = pos.equityCents > pos.maintenanceCents
    val zone = BailoutMath.healthZone(pos.bufferBps, pos.dangerBps, solvent)
    var showOpen by remember { mutableStateOf(false) }

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(pos.symbol.ifBlank { "Symbol ${pos.symbolId}" }, fontWeight = FontWeight.SemiBold)
                Text(
                    "${pos.side.label()} ${pos.qty}",
                    style = MaterialTheme.typography.bodyMedium,
                    color = zone.color,
                )
            }
            Spacer(Modifier.height(10.dp))
            HealthMeter(zone = zone, bufferBps = pos.bufferBps, dangerBps = pos.dangerBps)
            Spacer(Modifier.height(10.dp))
            HorizontalDivider()
            Spacer(Modifier.height(6.dp))
            BailoutKeyValueRow("Mark", pos.markPrice.toString())
            BailoutKeyValueRow("Liq. price", if (pos.liqPrice > 0) pos.liqPrice.toString() else "--")
            BailoutKeyValueRow("Equity", BailoutMath.formatCents(pos.equityCents))
            BailoutKeyValueRow("Maintenance", BailoutMath.formatCents(pos.maintenanceCents))
            BailoutKeyValueRow("Volatility", BailoutMath.formatBps(pos.volatilityBps))

            if (zone == HealthZone.LIQUIDATION) {
                Spacer(Modifier.height(8.dp))
                Text(
                    "Equity is at/below maintenance - a pre-emptive bailout is no longer possible; this is liquidation territory.",
                    style = MaterialTheme.typography.bodySmall,
                    color = HealthZone.LIQUIDATION.color,
                )
                return@Column
            }

            if (pos.auctionId != null) {
                Spacer(Modifier.height(10.dp))
                Button(
                    onClick = { onOpenAuction(pos.symbolId) },
                    modifier = Modifier.fillMaxWidth().testTag("distress_view_auction"),
                ) { Text("View bailout auction") }
                return@Column
            }

            if (pos.eligible && pos.inBand) {
                Spacer(Modifier.height(10.dp))
                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = HealthZone.DISTRESS.color.copy(alpha = 0.15f),
                    ),
                ) {
                    Column(Modifier.padding(12.dp)) {
                        Text(
                            "This position is in the distress band. To avoid forced liquidation:",
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.SemiBold,
                        )
                        Spacer(Modifier.height(8.dp))
                        OutlinedButton(
                            onClick = onAddMargin,
                            modifier = Modifier.fillMaxWidth().testTag("distress_add_margin"),
                        ) { Text("1 - Add margin") }
                        Spacer(Modifier.height(6.dp))
                        OutlinedButton(
                            onClick = { onReducePosition(pos.symbolId) },
                            modifier = Modifier.fillMaxWidth().testTag("distress_reduce"),
                        ) { Text("2 - Reduce position") }
                        Spacer(Modifier.height(6.dp))
                        Button(
                            onClick = { showOpen = true },
                            enabled = !inFlight,
                            modifier = Modifier.fillMaxWidth().testTag("distress_open_bailout"),
                        ) { Text("3 - Open bailout auction") }
                        Spacer(Modifier.height(4.dp))
                        Text(
                            "A bailout raises rescue capital from others for a slice of this position - no forced-liquidation penalty.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            } else {
                Spacer(Modifier.height(8.dp))
                Text(
                    "In the danger band but not currently eligible to open a bailout (server-gated).",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }

    if (showOpen) {
        OpenBailoutDialog(
            pos = pos,
            onConfirm = { maxShareBps -> showOpen = false; onOpenBailout(pos.symbolId, maxShareBps) },
            onDismiss = { showOpen = false },
        )
    }
}

@Composable
private fun OpenBailoutDialog(
    pos: DistressPosition,
    onConfirm: (Int) -> Unit,
    onDismiss: () -> Unit,
) {
    var pctText by remember { mutableStateOf("20") }
    val maxShareBps = pctText.trim().toDoubleOrNull()?.let { (it * 100).toInt() }?.takeIf { it in 1..10_000 }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Open bailout auction") },
        text = {
            Column {
                Text(
                    "Offer up to this % of the position-share to rescuers. The auction clears at the single least-dilutive share needed to raise the rescue capital.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = pctText,
                    onValueChange = { pctText = it.filter { c -> c.isDigit() || c == '.' } },
                    label = { Text("Max position-share %") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
                    modifier = Modifier.fillMaxWidth().testTag("open_max_share"),
                )
                Spacer(Modifier.height(8.dp))
                BailoutKeyValueRow("Position", "${pos.side.label()} ${pos.qty} ${pos.symbol}")
                BailoutKeyValueRow("If mark hits", "${pos.liqPrice} -> auto-cancel -> liquidation")
            }
        },
        confirmButton = {
            Button(
                onClick = { maxShareBps?.let(onConfirm) },
                enabled = maxShareBps != null,
                modifier = Modifier.testTag("open_bailout_confirm"),
            ) { Text("Open auction") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun EmptyDistress() {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(24.dp)) {
            Text("No positions in distress", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(4.dp))
            Text(
                "None of your margin positions are in the volatility-scaled danger band right now. (If the margin-distress backend is still pending, this stays empty rather than guessing.)",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
