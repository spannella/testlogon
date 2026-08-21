@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.bailout

import androidx.compose.foundation.layout.Column
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
import com.testlogon.android.data.bailout.BailoutAuction
import com.testlogon.android.data.bailout.BailoutStatus
import com.testlogon.android.data.bailout.HealthZone

/**
 * One pre-emptive bailout auction: capital-needed target, rescuer bid list, a "Bail out" rescue-bid
 * form (capital -> position-share) behind a money-safety confirm, the indicative clearing share
 * (pure [BailoutMath]), a live "if mark hits {liqPrice} first -> cancels -> liquidation" warning, and
 * an owner Clear. Reads degrade on 404. The screen self-detects owner vs rescuer from ownerSub when
 * available, else shows both affordances defensively (server enforces authority).
 */
@Composable
fun BailoutAuctionRoute(
    onBack: () -> Unit,
    viewModel: BailoutAuctionViewModel = hiltViewModel(),
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
                title = { Text("Bailout auction") },
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
            BailoutAuctionUiState.Phase.Loading -> LoadingState(message = "Loading auction")
            BailoutAuctionUiState.Phase.Error -> ErrorState(
                message = state.errorMessage ?: "Something went wrong.",
                onRetry = viewModel::onRetry,
                modifier = Modifier.padding(padding),
            )
            BailoutAuctionUiState.Phase.Content -> AuctionContent(
                state = state,
                modifier = Modifier.padding(padding),
                onBid = viewModel::placeBid,
                onClear = viewModel::clear,
            )
        }
    }
}

@Composable
private fun AuctionContent(
    state: BailoutAuctionUiState,
    modifier: Modifier = Modifier,
    onBid: (capitalCents: Long, shareBps: Int) -> Unit,
    onClear: () -> Unit,
) {
    val auction = state.auction
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
    ) {
        if (auction == null) {
            BailoutSectionCard(title = "No auction") {
                Text(
                    "There is no open bailout auction for this position. If the margin-distress backend is still pending, this stays empty rather than guessing.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            return
        }

        // Live liquidation warning (pre-emptive auctions auto-cancel if the mark reaches the liq price).
        if (auction.status == BailoutStatus.OPEN) {
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = HealthZone.LIQUIDATION.color.copy(alpha = 0.12f),
                ),
            ) {
                Column(Modifier.padding(14.dp)) {
                    Text(
                        "Pre-emptive only",
                        style = MaterialTheme.typography.labelLarge,
                        color = HealthZone.LIQUIDATION.color,
                        fontWeight = FontWeight.SemiBold,
                    )
                    Spacer(Modifier.height(4.dp))
                    Text(
                        "If the mark hits ${auction.liqPrice} first, the position breaches maintenance: this auction auto-cancels and normal liquidation proceeds. Mark now: ${auction.markPrice}.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
            Spacer(Modifier.height(12.dp))
        }

        BailoutSectionCard(title = "Target") {
            BailoutKeyValueRow("Status", auction.status.label(), emphasize = true)
            BailoutKeyValueRow("Position", "${auction.side.label()} ${auction.qty}")
            BailoutKeyValueRow("Capital needed", BailoutMath.formatCents(auction.capitalNeededCents))
            BailoutKeyValueRow("Max share offered", BailoutMath.formatBps(auction.maxShareBps))
            auction.raisedCents?.let { BailoutKeyValueRow("Raised", BailoutMath.formatCents(it)) }
            auction.clearingShareBps?.let {
                BailoutKeyValueRow("Clearing share", BailoutMath.formatBps(it), emphasize = true)
            }
        }
        Spacer(Modifier.height(12.dp))

        // Indicative single-clearing-share preview from the sealed rescuer bids (pure BailoutMath).
        val bids = remember(auction.rescuers) {
            auction.rescuers.map { BailoutMath.BailoutBid(it.capitalCents, it.shareBps) }
        }
        if (auction.status == BailoutStatus.OPEN && bids.isNotEmpty()) {
            val summary = remember(bids, auction.capitalNeededCents) {
                BailoutMath.clearingSummary(bids, auction.capitalNeededCents)
            }
            BailoutSectionCard(title = "Indicative clearing (from ${bids.size} rescuers)") {
                BailoutKeyValueRow(
                    "Would give up",
                    summary.clearingShareBps?.let { BailoutMath.formatBps(it) } ?: "n/a",
                )
                BailoutKeyValueRow("Would raise", BailoutMath.formatCents(summary.raisedCents))
                BailoutKeyValueRow(
                    "Funded",
                    if (summary.fullyFunded) "fully" else "partial (short of target)",
                )
            }
            Spacer(Modifier.height(12.dp))
        }

        if (auction.rescuers.isNotEmpty()) {
            BailoutSectionCard(title = "Rescuers") {
                auction.rescuers.forEach { r ->
                    BailoutKeyValueRow(
                        shortSub(r.sub),
                        "${BailoutMath.formatCents(r.capitalCents)} -> ${BailoutMath.formatBps(r.shareBps)}",
                    )
                }
            }
            Spacer(Modifier.height(12.dp))
        }

        when (auction.status) {
            BailoutStatus.OPEN -> {
                RescueBidForm(
                    auction = auction,
                    inFlight = state.actionInFlight,
                    onBid = onBid,
                )
                Spacer(Modifier.height(12.dp))
                OwnerClear(inFlight = state.actionInFlight, onClear = onClear)
            }
            else -> BailoutSectionCard(title = "Closed") {
                Text(
                    "Auction ${auction.status.label().lowercase()} - bidding closed.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun RescueBidForm(
    auction: BailoutAuction,
    inFlight: Boolean,
    onBid: (Long, Int) -> Unit,
) {
    var capitalText by remember { mutableStateOf("") }
    var shareText by remember { mutableStateOf("") }
    var showConfirm by remember { mutableStateOf(false) }

    val capitalCents = capitalText.trim().toDoubleOrNull()?.let { (it * 100).toLong() }?.takeIf { it > 0 }
    val shareBps = shareText.trim().toDoubleOrNull()?.let { (it * 100).toInt() }?.takeIf { it in 1..auction.maxShareBps }

    BailoutSectionCard(title = "Bail out (inject rescue capital)") {
        Text(
            "Inject capital in return for a slice of the position (and its uPnL). You give up share only up to the single clearing rate if filled.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(8.dp))
        OutlinedTextField(
            value = capitalText,
            onValueChange = { capitalText = it.filter { c -> c.isDigit() || c == '.' } },
            label = { Text("Capital ($)") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
            modifier = Modifier.fillMaxWidth().testTag("rescue_capital"),
        )
        Spacer(Modifier.height(8.dp))
        OutlinedTextField(
            value = shareText,
            onValueChange = { shareText = it.filter { c -> c.isDigit() || c == '.' } },
            label = { Text("Share asked % (<= ${BailoutMath.formatBps(auction.maxShareBps)})") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
            modifier = Modifier.fillMaxWidth().testTag("rescue_share"),
        )
        Spacer(Modifier.height(10.dp))
        OutlinedButton(
            onClick = { showConfirm = true },
            enabled = !inFlight && capitalCents != null && shareBps != null,
            modifier = Modifier.fillMaxWidth().testTag("rescue_submit"),
        ) { Text("Bail out") }
    }

    if (showConfirm && capitalCents != null && shareBps != null) {
        AlertDialog(
            onDismissRequest = { showConfirm = false },
            title = { Text("Confirm rescue bid") },
            text = {
                Column {
                    BailoutKeyValueRow("Capital", BailoutMath.formatCents(capitalCents))
                    BailoutKeyValueRow("Share asked", BailoutMath.formatBps(shareBps))
                    HorizontalDivider(Modifier.padding(vertical = 6.dp))
                    Text(
                        "Sealed rescue bid - you pay this capital and receive up to the clearing position-share if filled. Auto-cancels (no fill) if the position liquidates first.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = { showConfirm = false; onBid(capitalCents, shareBps) },
                    modifier = Modifier.testTag("rescue_confirm"),
                ) { Text("Bail out") }
            },
            dismissButton = { TextButton(onClick = { showConfirm = false }) { Text("Cancel") } },
        )
    }
}

@Composable
private fun OwnerClear(inFlight: Boolean, onClear: () -> Unit) {
    var showConfirm by remember { mutableStateOf(false) }
    BailoutSectionCard(title = "Owner: clear") {
        Text(
            "If you are the position owner, clear the auction at the single least-dilutive clearing share once enough rescue capital is bid.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(8.dp))
        Button(
            onClick = { showConfirm = true },
            enabled = !inFlight,
            modifier = Modifier.fillMaxWidth().testTag("owner_clear"),
        ) { Text("Clear auction (single share)") }
    }

    if (showConfirm) {
        AlertDialog(
            onDismissRequest = { showConfirm = false },
            title = { Text("Clear the auction?") },
            text = {
                Text(
                    "All accepted rescue bids fill at one clearing position-share (the least total share needed to raise the capital). This closes bidding.",
                    style = MaterialTheme.typography.bodySmall,
                )
            },
            confirmButton = {
                Button(
                    onClick = { showConfirm = false; onClear() },
                    modifier = Modifier.testTag("owner_clear_confirm"),
                ) { Text("Clear") }
            },
            dismissButton = { TextButton(onClick = { showConfirm = false }) { Text("Cancel") } },
        )
    }
}
