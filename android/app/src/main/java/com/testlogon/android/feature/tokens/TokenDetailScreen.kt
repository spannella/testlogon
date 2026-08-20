@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.tokens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Divider
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
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.tokens.AuctionStatus
import com.testlogon.android.data.tokens.Token
import com.testlogon.android.data.tokens.TokenAuction
import com.testlogon.android.data.tokens.TokenCapTable
import com.testlogon.android.data.tokens.TokenRevenue
import com.testlogon.android.data.tokens.TokenUpkeep
import com.testlogon.android.data.tokens.UpkeepStatus

/**
 * Token detail: cap table, revenue (distributions + my claimable + Claim), upkeep (fees-this-month vs
 * $100 + amount due + my pro-rata share + status incl. FROZEN + Pay + shortfall-assumption label), and
 * an issuer-only List/IPO launcher + auction panel (bids, place-bid for non-issuers, clearing price,
 * issuer Clear). Every read degrades to an honest pending/empty state on 404.
 */
@Composable
fun TokenDetailRoute(
    onBack: () -> Unit,
    viewModel: TokenDetailViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbar = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()

    LaunchedEffect(state.actionMessage) {
        state.actionMessage?.let {
            snackbar.showSnackbar(it)
            viewModel.consumeActionMessage()
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(state.token?.ticker?.ifBlank { "Token" } ?: "Token") },
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
            TokenDetailUiState.Phase.Loading -> LoadingState(message = "Loading token")
            TokenDetailUiState.Phase.Error -> ErrorState(
                message = state.errorMessage ?: "Something went wrong.",
                onRetry = viewModel::onRetry,
                modifier = Modifier.padding(padding),
            )
            TokenDetailUiState.Phase.Content -> TokenDetailContent(
                state = state,
                modifier = Modifier.padding(padding),
                onList = viewModel::listIpo,
                onBid = viewModel::placeBid,
                onClear = viewModel::clearAuction,
                onClaim = viewModel::claimRevenue,
                onPayUpkeep = viewModel::payUpkeep,
            )
        }
    }
}

@Composable
private fun TokenDetailContent(
    state: TokenDetailUiState,
    modifier: Modifier = Modifier,
    onList: (offeredPctBps: Int, reservePrice: Long, closeTs: Long) -> Unit,
    onBid: (qty: Long, limitPrice: Long) -> Unit,
    onClear: () -> Unit,
    onClaim: () -> Unit,
    onPayUpkeep: () -> Unit,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        HeaderCard(token = state.token, isIssuer = state.isIssuer)
        CapTableSection(capTable = state.capTable)
        RevenueSection(revenue = state.revenue, onClaim = onClaim, inFlight = state.actionInFlight)
        UpkeepSection(upkeep = state.upkeep, onPay = onPayUpkeep, inFlight = state.actionInFlight)
        AuctionSection(
            token = state.token,
            auction = state.auction,
            isIssuer = state.isIssuer,
            inFlight = state.actionInFlight,
            onList = onList,
            onBid = onBid,
            onClear = onClear,
        )
        Spacer(Modifier.height(8.dp))
    }
}

@Composable
private fun SectionCard(title: String, content: @Composable () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(14.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(8.dp))
            content()
        }
    }
}

@Composable
private fun HeaderCard(token: Token?, isIssuer: Boolean) {
    SectionCard(title = token?.name?.ifBlank { "Creator token" } ?: "Creator token") {
        if (token == null) {
            Text(
                "This token isn't available yet (backend pending).",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            return@SectionCard
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(token.ticker, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
            Spacer(Modifier.width(8.dp))
            TokenStatusPill(token.status.label())
            if (isIssuer) {
                Spacer(Modifier.width(8.dp))
                TokenStatusPill("You issued this")
            }
        }
        Spacer(Modifier.height(8.dp))
        TokenKeyValueRow("Total supply", token.totalSupply.toString())
        TokenKeyValueRow("Revenue share", TokenMath.formatBps(token.revenueShareBps), emphasize = true)
        token.offeredPctBps?.let { TokenKeyValueRow("Listed slice", TokenMath.formatBps(it)) }
        token.clearingPrice?.let { TokenKeyValueRow("Clearing price", TokenMath.formatCents(it)) }
    }
}

@Composable
private fun CapTableSection(capTable: TokenCapTable?) {
    SectionCard(title = "Cap table") {
        if (capTable == null || (capTable.holders.isEmpty() && capTable.creatorPctBps == 0)) {
            Text(
                "No cap-table data yet. On mint the creator holds 100% of supply.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            return@SectionCard
        }
        TokenKeyValueRow("Creator", TokenMath.formatBps(capTable.creatorPctBps), emphasize = true)
        if (capTable.holders.isNotEmpty()) {
            Divider(modifier = Modifier.padding(vertical = 6.dp))
            capTable.holders.forEach { h ->
                TokenKeyValueRow(
                    label = shortSub(h.sub),
                    value = "${h.qty}  ·  ${TokenMath.formatBps(h.pctBps)}",
                )
            }
        }
    }
}

@Composable
private fun RevenueSection(revenue: TokenRevenue?, onClaim: () -> Unit, inFlight: Boolean) {
    SectionCard(title = "Revenue") {
        if (revenue == null) {
            Text(
                "No revenue data yet (backend pending).",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            return@SectionCard
        }
        TokenKeyValueRow("My holding", "${revenue.myQty}  ·  ${TokenMath.formatBps(revenue.myPctBps)}")
        TokenKeyValueRow("My claimable", TokenMath.formatCents(revenue.myClaimable), emphasize = true)
        Spacer(Modifier.height(8.dp))
        if (revenue.distributions.isEmpty()) {
            Text(
                "No distributions yet. Holders receive pro-rata payouts of the creator's revenue share.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else {
            Text("Distributions", style = MaterialTheme.typography.labelLarge)
            revenue.distributions.forEach { d ->
                TokenKeyValueRow(
                    label = "${d.source.ifBlank { "revenue" }} · ${TokenMath.formatCents(d.perTokenAmount)}/tok",
                    value = TokenMath.formatCents(d.totalAmount),
                )
            }
        }
        Spacer(Modifier.height(10.dp))
        Button(
            onClick = onClaim,
            enabled = !inFlight && revenue.myClaimable > 0L,
            modifier = Modifier.fillMaxWidth().testTag("token_claim"),
        ) { Text("Claim ${TokenMath.formatCents(revenue.myClaimable)}") }
    }
}

@Composable
private fun UpkeepSection(upkeep: TokenUpkeep?, onPay: () -> Unit, inFlight: Boolean) {
    var showConfirm by remember { mutableStateOf(false) }
    SectionCard(title = "Book upkeep") {
        if (upkeep == null) {
            Text(
                "No upkeep data yet (backend pending).",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            return@SectionCard
        }
        if (upkeep.status == UpkeepStatus.FROZEN) {
            Surface(
                color = MaterialTheme.colorScheme.errorContainer,
                contentColor = MaterialTheme.colorScheme.onErrorContainer,
                shape = MaterialTheme.shapes.small,
                modifier = Modifier.fillMaxWidth().testTag("upkeep_frozen_banner"),
            ) {
                Text(
                    "Book FROZEN for non-payment. Pay upkeep to restore trading (reversible).",
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.padding(10.dp),
                )
            }
            Spacer(Modifier.height(8.dp))
        }
        upkeep.month.takeIf { it.isNotBlank() }?.let { TokenKeyValueRow("Month", it) }
        TokenKeyValueRow("Fees this month", TokenMath.formatCents(upkeep.feesGenerated))
        TokenKeyValueRow(
            "Threshold",
            TokenMath.formatCents(upkeep.threshold.takeIf { it > 0 } ?: TokenMath.UPKEEP_THRESHOLD_CENTS),
        )
        TokenKeyValueRow("Amount due (book)", TokenMath.formatCents(upkeep.amountDue), emphasize = true)
        TokenKeyValueRow("My pro-rata share", TokenMath.formatCents(upkeep.myShare), emphasize = true)
        TokenKeyValueRow("Status", upkeep.status.label())
        Spacer(Modifier.height(6.dp))
        // ASSUMPTION LABEL (flippable later): the charge is modelled as a SHORTFALL top-up, not a flat fee.
        Surface(
            color = MaterialTheme.colorScheme.surfaceVariant,
            shape = MaterialTheme.shapes.small,
            modifier = Modifier.fillMaxWidth().testTag("upkeep_assumption_label"),
        ) {
            Text(
                "Assumption: SHORTFALL model — amountDue = max(0, \$100 − trading fees this month); \$0 once monthly fees ≥ \$100. (Flippable to a flat \$100 later.)",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(10.dp),
            )
        }
        Spacer(Modifier.height(10.dp))
        Button(
            onClick = { showConfirm = true },
            enabled = !inFlight && upkeep.myShare > 0L,
            modifier = Modifier.fillMaxWidth().testTag("upkeep_pay"),
        ) { Text("Pay my share ${TokenMath.formatCents(upkeep.myShare)}") }
    }

    if (showConfirm && upkeep != null) {
        MoneyConfirmDialog(
            title = "Confirm upkeep payment",
            lines = listOf(
                "Action" to "Pay book upkeep (my pro-rata share)",
                "Month" to upkeep.month.ifBlank { "current" },
                "My share" to TokenMath.formatCents(upkeep.myShare),
            ),
            footnote = "This charges your account ${TokenMath.formatCents(upkeep.myShare)} now.",
            confirmLabel = "Pay",
            confirmTag = "upkeep_pay_confirm",
            onConfirm = { showConfirm = false; onPay() },
            onDismiss = { showConfirm = false },
        )
    }
}

@Composable
private fun AuctionSection(
    token: Token?,
    auction: TokenAuction?,
    isIssuer: Boolean,
    inFlight: Boolean,
    onList: (Int, Long, Long) -> Unit,
    onBid: (Long, Long) -> Unit,
    onClear: () -> Unit,
) {
    SectionCard(title = "Listing / IPO") {
        val totalSupply = token?.totalSupply ?: 0L
        if (auction == null) {
            // No auction yet: issuer sees the List launcher; others see a pending note.
            if (isIssuer) {
                Text(
                    "List a slice of supply via a single-clearing-price IPO auction (sealed bids clear at one price).",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(10.dp))
                ListLauncher(totalSupply = totalSupply, inFlight = inFlight, onList = onList)
            } else {
                Text(
                    "Not listed yet. When the issuer lists, you'll be able to place a sealed IPO bid here.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            return@SectionCard
        }

        val offeredQty = TokenMath.bpsToQty(auction.offeredPctBps, totalSupply)
        TokenKeyValueRow("Status", auction.status.label())
        TokenKeyValueRow("Offered", "${TokenMath.formatBps(auction.offeredPctBps)}  ($offeredQty tok)")
        TokenKeyValueRow("Reserve", TokenMath.formatCents(auction.reservePrice))
        auction.clearingPrice?.let { TokenKeyValueRow("Clearing price", TokenMath.formatCents(it), emphasize = true) }
        auction.filledQty?.let { TokenKeyValueRow("Filled", "$it tok") }

        // Local single-clearing-price preview computed from the sealed bids (pure TokenMath).
        val summary = remember(auction.bids, offeredQty, auction.reservePrice) {
            TokenMath.clearingSummary(auction.bids, offeredQty, auction.reservePrice)
        }
        if (auction.status == AuctionStatus.OPEN && auction.bids.isNotEmpty()) {
            Divider(modifier = Modifier.padding(vertical = 6.dp))
            Text("Indicative clearing (from ${auction.bids.size} bids)", style = MaterialTheme.typography.labelLarge)
            TokenKeyValueRow(
                "Would clear at",
                summary.clearingPrice?.let { TokenMath.formatCents(it) } ?: "below reserve",
            )
            TokenKeyValueRow("Would fill", "${summary.filledQty} tok · ${summary.clearedBids} bids")
        }

        if (auction.bids.isNotEmpty()) {
            Divider(modifier = Modifier.padding(vertical = 6.dp))
            Text("Bids", style = MaterialTheme.typography.labelLarge)
            auction.bids.forEach { b ->
                TokenKeyValueRow(shortSub(b.sub), "${b.qty} @ ${TokenMath.formatCents(b.limitPrice)}")
            }
        }

        Spacer(Modifier.height(10.dp))
        if (isIssuer) {
            if (auction.status == AuctionStatus.OPEN) {
                IssuerClear(inFlight = inFlight, onClear = onClear)
            }
        } else if (auction.status == AuctionStatus.OPEN) {
            BidPanel(inFlight = inFlight, onBid = onBid)
        } else {
            Text(
                "Auction ${auction.status.label().lowercase()} — bidding closed.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun ListLauncher(
    totalSupply: Long,
    inFlight: Boolean,
    onList: (Int, Long, Long) -> Unit,
) {
    var pctText by remember { mutableStateOf("20") }
    var reserveText by remember { mutableStateOf("1.00") }
    var showConfirm by remember { mutableStateOf(false) }

    val offeredBps = pctText.trim().toDoubleOrNull()?.let { (it * 100).toInt() }?.takeIf { it in 1..10_000 }
    val reserveCents = reserveText.trim().toDoubleOrNull()?.let { (it * 100).toLong() }?.takeIf { it >= 0 }
    // Default close: 7 days out (epoch seconds), a stable client default the backend can override.
    val closeTs = remember { (System.currentTimeMillis() / 1000L) + 7L * 24 * 3600 }

    OutlinedTextField(
        value = pctText,
        onValueChange = { pctText = it.filter { c -> c.isDigit() || c == '.' } },
        label = { Text("Offer % of supply") },
        singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = androidx.compose.ui.text.input.KeyboardType.Decimal),
        modifier = Modifier.fillMaxWidth().testTag("list_pct"),
    )
    Spacer(Modifier.height(8.dp))
    OutlinedTextField(
        value = reserveText,
        onValueChange = { reserveText = it.filter { c -> c.isDigit() || c == '.' } },
        label = { Text("Reserve price ($/token)") },
        singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = androidx.compose.ui.text.input.KeyboardType.Decimal),
        modifier = Modifier.fillMaxWidth().testTag("list_reserve"),
    )
    offeredBps?.let {
        Spacer(Modifier.height(4.dp))
        Text(
            "= ${TokenMath.bpsToQty(it, totalSupply)} tokens",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
    Spacer(Modifier.height(10.dp))
    Button(
        onClick = { showConfirm = true },
        enabled = !inFlight && offeredBps != null && reserveCents != null,
        modifier = Modifier.fillMaxWidth().testTag("list_submit"),
    ) { Text("List IPO") }

    if (showConfirm && offeredBps != null && reserveCents != null) {
        MoneyConfirmDialog(
            title = "Confirm IPO listing",
            lines = listOf(
                "Offer" to "${TokenMath.formatBps(offeredBps)} (${TokenMath.bpsToQty(offeredBps, totalSupply)} tok)",
                "Reserve" to TokenMath.formatCents(reserveCents),
                "Type" to "Single-clearing-price auction",
            ),
            footnote = "Sealed bids clear at ONE price; all fills at that price.",
            confirmLabel = "List",
            confirmTag = "list_confirm",
            onConfirm = { showConfirm = false; onList(offeredBps, reserveCents, closeTs) },
            onDismiss = { showConfirm = false },
        )
    }
}

@Composable
private fun IssuerClear(inFlight: Boolean, onClear: () -> Unit) {
    var showConfirm by remember { mutableStateOf(false) }
    Button(
        onClick = { showConfirm = true },
        enabled = !inFlight,
        modifier = Modifier.fillMaxWidth().testTag("auction_clear"),
    ) { Text("Clear auction (single price)") }

    if (showConfirm) {
        MoneyConfirmDialog(
            title = "Clear the auction?",
            lines = listOf("Action" to "Clear at the single clearing price"),
            footnote = "All accepted bids fill at one clearing price. This closes bidding.",
            confirmLabel = "Clear",
            confirmTag = "auction_clear_confirm",
            onConfirm = { showConfirm = false; onClear() },
            onDismiss = { showConfirm = false },
        )
    }
}

@Composable
private fun BidPanel(inFlight: Boolean, onBid: (Long, Long) -> Unit) {
    var qtyText by remember { mutableStateOf("") }
    var priceText by remember { mutableStateOf("") }
    var showConfirm by remember { mutableStateOf(false) }

    val qty = qtyText.trim().toLongOrNull()?.takeIf { it > 0 }
    val priceCents = priceText.trim().toDoubleOrNull()?.let { (it * 100).toLong() }?.takeIf { it > 0 }

    Text("Place a sealed bid", style = MaterialTheme.typography.labelLarge)
    Spacer(Modifier.height(6.dp))
    OutlinedTextField(
        value = qtyText,
        onValueChange = { qtyText = it.filter { c -> c.isDigit() } },
        label = { Text("Quantity") },
        singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = androidx.compose.ui.text.input.KeyboardType.Number),
        modifier = Modifier.fillMaxWidth().testTag("bid_qty"),
    )
    Spacer(Modifier.height(8.dp))
    OutlinedTextField(
        value = priceText,
        onValueChange = { priceText = it.filter { c -> c.isDigit() || c == '.' } },
        label = { Text("Limit price ($/token)") },
        singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = androidx.compose.ui.text.input.KeyboardType.Decimal),
        modifier = Modifier.fillMaxWidth().testTag("bid_price"),
    )
    Spacer(Modifier.height(10.dp))
    OutlinedButton(
        onClick = { showConfirm = true },
        enabled = !inFlight && qty != null && priceCents != null,
        modifier = Modifier.fillMaxWidth().testTag("bid_submit"),
    ) { Text("Place bid") }

    if (showConfirm && qty != null && priceCents != null) {
        MoneyConfirmDialog(
            title = "Confirm bid",
            lines = listOf(
                "Quantity" to qty.toString(),
                "Limit price" to TokenMath.formatCents(priceCents),
                "Max cost" to TokenMath.formatCents(qty * priceCents),
            ),
            footnote = "Sealed bid — you pay the single clearing price if filled (≤ your limit).",
            confirmLabel = "Place bid",
            confirmTag = "bid_confirm",
            onConfirm = { showConfirm = false; onBid(qty, priceCents) },
            onDismiss = { showConfirm = false },
        )
    }
}

@Composable
private fun MoneyConfirmDialog(
    title: String,
    lines: List<Pair<String, String>>,
    footnote: String,
    confirmLabel: String,
    confirmTag: String,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column {
                lines.forEach { (l, v) -> TokenKeyValueRow(l, v) }
                Spacer(Modifier.height(6.dp))
                Text(
                    footnote,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        },
        confirmButton = {
            Button(onClick = onConfirm, modifier = Modifier.testTag(confirmTag)) { Text(confirmLabel) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

/** Compact holder id for the cap table / bids (keeps rows readable). */
private fun shortSub(sub: String): String =
    if (sub.length <= 10) sub.ifBlank { "—" } else sub.take(6) + "…" + sub.takeLast(4)
