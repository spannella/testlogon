@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.strategies

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.StarBorder
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
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
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.strategies.Strategy

/**
 * STRATEGY DETAIL + invest/redeem. Shows the NAV, holdings, dual-fee schedule + the pooled-NAV
 * assumption note, the caller's investor position, and (for the creator) the accrued-fee view. Invest
 * validates min-size + capacity and is gated behind a money-safety confirm; Redeem respects the
 * position held and the strategy's redemption policy. Every read degrades to an honest empty/pending
 * state on 404.
 */
@Composable
fun StrategyDetailRoute(
    onBack: () -> Unit,
    onEdit: (strategyId: String) -> Unit,
    onPaperRun: (strategyId: String) -> Unit,
    viewModel: StrategyDetailViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val watched by viewModel.isWatched.collectAsStateWithLifecycle()
    val snackbar = remember { SnackbarHostState() }
    var showInvest by remember { mutableStateOf(false) }
    var showRedeem by remember { mutableStateOf(false) }

    LaunchedEffect(state.actionMessage) {
        state.actionMessage?.let {
            snackbar.showSnackbar(it)
            viewModel.consumeActionMessage()
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Strategy") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(onClick = viewModel::toggleWatch, modifier = Modifier.testTag("strategy_watch_toggle")) {
                        Icon(
                            imageVector = if (watched) Icons.Filled.Star else Icons.Filled.StarBorder,
                            contentDescription = if (watched) "Remove from watchlist" else "Add to watchlist",
                        )
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        Box(modifier = Modifier.fillMaxSize().padding(padding)) {
            when (state.phase) {
                StrategyDetailUiState.Phase.Loading -> LoadingState(message = "Loading strategy")
                StrategyDetailUiState.Phase.Error -> ErrorState(
                    message = state.errorMessage ?: "Something went wrong.",
                    onRetry = viewModel::onRetry,
                )
                StrategyDetailUiState.Phase.Content ->
                    if (state.strategy == null) {
                        EmptyState(
                            title = "Strategy unavailable",
                            body = "This strategy isn't available yet (the backend is pending). Check back once strategies are live.",
                        )
                    } else {
                        DetailContent(
                            state = state,
                            onInvest = { showInvest = true },
                            onRedeem = { showRedeem = true },
                            onEdit = { onEdit(state.strategyId) },
                            onPaperRun = { onPaperRun(state.strategyId) },
                        )
                    }
            }
        }
    }

    val s = state.strategy
    if (showInvest && s != null) {
        InvestDialog(state = state, strategy = s, onDismiss = { showInvest = false }, onConfirm = { cents ->
            showInvest = false
            viewModel.confirmInvest(cents)
        }, viewModel = viewModel)
    }
    if (showRedeem && s != null) {
        RedeemDialog(state = state, strategy = s, onDismiss = { showRedeem = false }, onConfirm = { units ->
            showRedeem = false
            viewModel.confirmRedeem(units)
        })
    }
}

@Composable
private fun DetailContent(
    state: StrategyDetailUiState,
    onInvest: () -> Unit,
    onRedeem: () -> Unit,
    onEdit: () -> Unit,
    onPaperRun: () -> Unit,
) {
    val s = state.strategy ?: return
    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
    ) {
        Row {
            Text(s.name.ifBlank { "(unnamed)" }, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
            StrategyStatusPill(s.status.label())
        }
        if (s.description.isNotBlank()) {
            Spacer(Modifier.height(4.dp))
            Text(s.description, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }

        Spacer(Modifier.height(16.dp))
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(14.dp)) {
                Text("Fund", style = MaterialTheme.typography.labelLarge)
                Spacer(Modifier.height(6.dp))
                StrategyKeyValueRow("NAV / unit", StrategyMath.formatNav(state.navPerUnitCents), emphasize = true)
                StrategyKeyValueRow("AUM", (state.nav?.aumCents ?: s.aumCents)?.let { StrategyMath.formatCents(it) } ?: "—")
                StrategyKeyValueRow("Investors", (s.investorCount ?: 0).toString())
                StrategyKeyValueRow("Inception return", (state.nav?.inceptionReturnBps ?: s.inceptionReturnBps)?.let { StrategyMath.formatBps(it) } ?: "—")
                StrategyKeyValueRow("Capacity remaining", s.capacityRemainingCents?.let { StrategyMath.formatCents(it) } ?: "Uncapped")
                StrategyKeyValueRow("Kind / rebalance", "${s.kind.label()} · ${s.rebalance.label()}")
            }
        }

        Spacer(Modifier.height(12.dp))
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(14.dp)) {
                Text("Basket", style = MaterialTheme.typography.labelLarge)
                Spacer(Modifier.height(6.dp))
                if (state.holdings.isNotEmpty()) {
                    state.holdings.forEach { h ->
                        StrategyKeyValueRow(
                            symbolName(h.symbolId),
                            "target ${StrategyMath.formatBps(h.targetWeightBps)} · actual ${StrategyMath.formatBps(h.actualWeightBps)}",
                        )
                    }
                } else if (s.legs.isNotEmpty()) {
                    s.legs.forEach { leg ->
                        StrategyKeyValueRow(symbolName(leg.symbolId), StrategyMath.formatBps(leg.weightBps))
                    }
                } else {
                    Text("No legs defined.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }

        Spacer(Modifier.height(12.dp))
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(14.dp)) {
                Text("Fees & policy", style = MaterialTheme.typography.labelLarge)
                Spacer(Modifier.height(6.dp))
                StrategyKeyValueRow("Management fee", "${StrategyMath.formatBps(s.mgmtFeeBps)} / yr on AUM")
                StrategyKeyValueRow("Performance fee", "${StrategyMath.formatBps(s.perfFeeBps)} on profit" + if (s.highWaterMark) " (high-water mark)" else "")
                StrategyKeyValueRow("Min investment", StrategyMath.formatCents(s.minInvestmentCents))
                StrategyKeyValueRow("Redemption", s.redemption.type.label() + (s.redemption.noticeDays?.let { " · $it-day notice" } ?: ""))
            }
        }

        // Pooled-NAV assumption note (flippable label).
        Spacer(Modifier.height(12.dp))
        Surface(
            color = MaterialTheme.colorScheme.surfaceVariant,
            shape = MaterialTheme.shapes.small,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(
                "Assumption: this is a POOLED fund with NAV units — you subscribe/redeem at NAV and own units (not copy/replication).",
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(10.dp),
            )
        }

        // Investor position (only when the caller holds units).
        state.position?.takeIf { it.units > 0 }?.let { pos ->
            Spacer(Modifier.height(12.dp))
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Text("Your position", style = MaterialTheme.typography.labelLarge)
                    Spacer(Modifier.height(6.dp))
                    StrategyKeyValueRow("Units", String.format("%.4f", pos.units / 1_000_000.0))
                    StrategyKeyValueRow("NAV / unit", StrategyMath.formatNav(pos.navPerUnit))
                    StrategyKeyValueRow("Invested", StrategyMath.formatCents(pos.investedCents))
                    StrategyKeyValueRow("Current value", StrategyMath.formatCents(pos.currentValueCents), emphasize = true)
                    StrategyKeyValueRow("Unrealized P&L", StrategyMath.formatCents(pos.unrealizedPnlCents))
                    StrategyKeyValueRow("Fees paid", StrategyMath.formatCents(pos.feesPaidCents))
                }
            }
        }

        // Creator-view fee accrual.
        state.fees?.let { fees ->
            Spacer(Modifier.height(12.dp))
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Text("Fee accrual (creator view)", style = MaterialTheme.typography.labelLarge)
                    Spacer(Modifier.height(6.dp))
                    StrategyKeyValueRow("Mgmt fees accrued", StrategyMath.formatCents(fees.mgmtFeesAccruedCents))
                    StrategyKeyValueRow("Perf fees accrued", StrategyMath.formatCents(fees.perfFeesAccruedCents))
                    StrategyKeyValueRow("High-water mark", StrategyMath.formatNav(fees.highWaterMark))
                }
            }
        }

        Spacer(Modifier.height(16.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.fillMaxWidth()) {
            Button(onClick = onInvest, enabled = !state.actionInFlight, modifier = Modifier.weight(1f).testTag("detail_invest")) { Text("Invest") }
            OutlinedButton(
                onClick = onRedeem,
                enabled = !state.actionInFlight && (state.position?.units ?: 0L) > 0L,
                modifier = Modifier.weight(1f).testTag("detail_redeem"),
            ) { Text("Redeem") }
        }
        Spacer(Modifier.height(8.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.fillMaxWidth()) {
            OutlinedButton(onClick = onPaperRun, modifier = Modifier.weight(1f).testTag("detail_paperrun")) { Text("Paper-run / backtest") }
            OutlinedButton(onClick = onEdit, modifier = Modifier.weight(1f).testTag("detail_edit")) { Text("Edit") }
        }
        Spacer(Modifier.height(24.dp))
    }
}

@Composable
private fun InvestDialog(
    state: StrategyDetailUiState,
    strategy: Strategy,
    onDismiss: () -> Unit,
    onConfirm: (amountCents: Long) -> Unit,
    viewModel: StrategyDetailViewModel,
) {
    var amountText by remember { mutableStateOf((strategy.minInvestmentCents / 100.0).let { if (it <= 0) "" else it.toString() }) }
    val cents = amountText.trim().toDoubleOrNull()?.let { Math.round(it * 100.0) } ?: 0L
    val validationError = if (cents > 0L) viewModel.investValidationError(cents) else "Enter an amount."
    val units = if (cents > 0L) viewModel.estimatedUnits(cents) else 0.0

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Invest in ${strategy.name}") },
        text = {
            Column {
                OutlinedTextField(
                    value = amountText,
                    onValueChange = { amountText = it.filter { c -> c.isDigit() || c == '.' } },
                    label = { Text("Amount ($)") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
                    modifier = Modifier.fillMaxWidth().testTag("invest_amount"),
                )
                Spacer(Modifier.height(8.dp))
                StrategyKeyValueRow("NAV / unit", StrategyMath.formatNav(state.navPerUnitCents))
                StrategyKeyValueRow("Est. units", String.format("%.4f", units))
                StrategyKeyValueRow("Min investment", StrategyMath.formatCents(strategy.minInvestmentCents))
                StrategyKeyValueRow("Capacity remaining", strategy.capacityRemainingCents?.let { StrategyMath.formatCents(it) } ?: "Uncapped")
                if (validationError != null) {
                    Spacer(Modifier.height(6.dp))
                    Text(validationError, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall, modifier = Modifier.testTag("invest_error"))
                } else {
                    Spacer(Modifier.height(6.dp))
                    Text(
                        "This charges your account ${StrategyMath.formatCents(cents)} now and issues units at NAV.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        },
        confirmButton = {
            Button(
                onClick = { onConfirm(cents) },
                enabled = validationError == null,
                modifier = Modifier.testTag("invest_confirm"),
            ) { Text("Confirm & invest") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun RedeemDialog(
    state: StrategyDetailUiState,
    strategy: Strategy,
    onDismiss: () -> Unit,
    onConfirm: (units: Long) -> Unit,
) {
    val heldUnits = (state.position?.units ?: 0L) / 1_000_000.0
    var unitsText by remember { mutableStateOf("") }
    val units = unitsText.trim().toLongOrNull() ?: 0L
    val proceeds = StrategyMath.proceedsForUnits(units * 1_000_000L, state.navPerUnitCents)
    val valid = units > 0L && units <= heldUnits.toLong()

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Redeem units") },
        text = {
            Column {
                Text("You hold ${String.format("%.4f", heldUnits)} units.", style = MaterialTheme.typography.bodyMedium)
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = unitsText,
                    onValueChange = { unitsText = it.filter { c -> c.isDigit() } },
                    label = { Text("Units to redeem (whole)") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.fillMaxWidth().testTag("redeem_units"),
                )
                Spacer(Modifier.height(8.dp))
                StrategyKeyValueRow("Est. proceeds", StrategyMath.formatCents(proceeds), emphasize = true)
                StrategyKeyValueRow("Redemption policy", strategy.redemption.type.label())
                strategy.redemption.noticeDays?.let { StrategyKeyValueRow("Notice", "$it days") }
                strategy.redemption.lockupDays?.takeIf { it > 0 }?.let { StrategyKeyValueRow("Lockup", "$it days") }
            }
        },
        confirmButton = {
            Button(onClick = { onConfirm(units) }, enabled = valid, modifier = Modifier.testTag("redeem_confirm")) { Text("Redeem") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}
