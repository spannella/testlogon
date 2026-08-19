@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.custody

import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.ScrollableTabRow
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.data.custody.CustodyAssets
import com.testlogon.android.data.custody.CustodyBalance
import com.testlogon.android.data.custody.BridgeDirection
import com.testlogon.android.data.custody.CustodyBridgeResult
import com.testlogon.android.data.custody.CustodySubAccount
import com.testlogon.android.data.custody.CustodySubAccounts
import com.testlogon.android.data.custody.SubAccountTransferResult
import com.testlogon.android.data.custody.CustodyDeposit
import com.testlogon.android.data.custody.CustodyDeposits
import com.testlogon.android.data.custody.DepositStatus
import com.testlogon.android.data.custody.CustodyWithdrawResult
import com.testlogon.android.data.custody.WithdrawStatus

/** Route-level Custody entry (reached from the More -> Wallet hub). */
@Composable
fun CustodyRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: CustodyViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    CustodyScreen(
        state = state,
        onBack = onBack,
        viewModel = viewModel,
        modifier = modifier,
    )
}

@Composable
fun CustodyScreen(
    state: CustodyUiState,
    onBack: () -> Unit,
    viewModel: CustodyViewModel,
    modifier: Modifier = Modifier,
) {
    val tabs = remember {
        listOf(
            CustodyTab.BALANCES,
            CustodyTab.SUBACCOUNTS,
            CustodyTab.TRANSFER,
            CustodyTab.DEPOSIT,
            CustodyTab.WITHDRAW,
            CustodyTab.ACTIVITY,
            CustodyTab.APPROVALS,
        )
    }
    val selectedIndex = tabs.indexOf(state.tab).let { if (it < 0) 0 else it }

    Scaffold(
        modifier = modifier,
        topBar = {
            TopAppBar(
                title = { Text("Custody") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            ScrollableTabRow(selectedTabIndex = selectedIndex, edgePadding = 8.dp) {
                tabs.forEach { tab ->
                    Tab(
                        selected = tab == state.tab,
                        onClick = { viewModel.onTabSelected(tab) },
                        text = { Text(tab.title()) },
                    )
                }
            }
            when (state.tab) {
                CustodyTab.BALANCES -> BalancesTab(state, viewModel)
                CustodyTab.SUBACCOUNTS -> SubAccountsTab(state, viewModel)
                CustodyTab.TRANSFER -> TransferTab(state, viewModel)
                CustodyTab.DEPOSIT -> DepositTab(state, viewModel)
                CustodyTab.WITHDRAW -> WithdrawTab(state, viewModel)
                CustodyTab.ACTIVITY -> UnavailableTab(
                    "Activity",
                    "Withdrawal history is not exposed by this backend. Submit a withdrawal from the Withdraw tab to see its immediate result.",
                )
                CustodyTab.APPROVALS -> UnavailableTab(
                    "Approvals & Audit",
                    "Approvals and the audit trail are handled inside the custody gateway and are not exposed to this app.",
                )
            }
        }
    }
}

private fun CustodyTab.title(): String = when (this) {
    CustodyTab.BALANCES -> "Balances"
    CustodyTab.SUBACCOUNTS -> "Sub-accounts"
    CustodyTab.TRANSFER -> "Transfer"
    CustodyTab.DEPOSIT -> "Deposit"
    CustodyTab.WITHDRAW -> "Withdraw"
    CustodyTab.ACTIVITY -> "Activity"
    CustodyTab.APPROVALS -> "Approvals & Audit"
}

// ---------------- Balances ----------------

@Composable
private fun BalancesTab(state: CustodyUiState, viewModel: CustodyViewModel) {
    val b = state.balances
    when {
        b.loading && b.data == null -> LoadingBox()
        b.error != null && b.data == null -> ErrorBox(b.error) { viewModel.loadBalance() }
        b.data == null -> EmptyBox("No custody vault yet.")
        else -> {
            val data = b.data
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                item {
                    VaultHeader(vaultShort = data.vaultShort, tier = data.tier)
                }
                items(data.rows, key = { it.key }) { row ->
                    BalanceCard(
                        row = row,
                        onDeposit = {
                            viewModel.onDepositAssetSelected(row.key)
                            viewModel.onTabSelected(CustodyTab.DEPOSIT)
                        },
                        onWithdraw = {
                            viewModel.onWithdrawAssetSelected(row.key)
                            viewModel.onTabSelected(CustodyTab.WITHDRAW)
                        },
                    )
                }
            }
        }
    }
}

@Composable
private fun VaultHeader(vaultShort: String, tier: String) {
    Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Text(
            "Vault ${vaultShort.ifBlank { "—" }}",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            fontFamily = FontFamily.Monospace,
            modifier = Modifier.weight(1f),
        )
        Text(
            "Tier: $tier",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun BalanceCard(row: CustodyBalance, onDeposit: () -> Unit, onWithdraw: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(modifier = Modifier.weight(1f)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(row.symbol, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                        if (!row.known) {
                            Spacer(Modifier.width(8.dp))
                            Box(
                                modifier = Modifier
                                    .background(MaterialTheme.colorScheme.surfaceVariant, RoundedCornerShape(50))
                                    .padding(horizontal = 8.dp, vertical = 2.dp),
                            ) {
                                Text("Unknown", style = MaterialTheme.typography.labelSmall)
                            }
                        }
                    }
                    Text(
                        "${row.asset.name} · ${row.asset.chainName}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Column(horizontalAlignment = Alignment.End) {
                    Text(row.amountText, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    Text(row.symbol, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            Spacer(Modifier.height(12.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = onDeposit, enabled = row.known, modifier = Modifier.weight(1f)) {
                    Text("Deposit")
                }
                Button(onClick = onWithdraw, enabled = row.known && row.amount > 0.0, modifier = Modifier.weight(1f)) {
                    Text("Withdraw")
                }
            }
        }
    }
}

// ---------------- Deposit ----------------

@Composable
private fun DepositTab(state: CustodyUiState, viewModel: CustodyViewModel) {
    val assets = CustodyAssets.ALL
    val clipboard = LocalClipboardManager.current
    val selected = CustodyAssets.findAsset(state.deposit.selectedKey)
    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("Select asset", style = MaterialTheme.typography.labelLarge)
        Row(modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            assets.forEach { asset ->
                FilterChip(
                    selected = asset.symbol == state.deposit.selectedKey,
                    onClick = { viewModel.onDepositAssetSelected(asset.symbol) },
                    label = { Text(asset.symbol) },
                )
            }
        }
        val addr = state.deposit.address
        when {
            selected == null -> HintText("Choose an asset to see its deposit address.")
            addr.loading -> LoadingBox()
            addr.error != null -> ErrorBox(addr.error) {
                viewModel.onDepositAssetSelected(selected.symbol)
            }
            addr.data != null -> {
                val data = addr.data
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(
                        modifier = Modifier.fillMaxWidth().padding(16.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                    ) {
                        if (data.address.isNotBlank()) {
                            QrCodeImage(content = data.address)
                            Spacer(Modifier.height(12.dp))
                        }
                        Text(
                            data.address.ifBlank { "No address returned" },
                            style = MaterialTheme.typography.bodyMedium,
                            fontFamily = FontFamily.Monospace,
                        )
                        Spacer(Modifier.height(8.dp))
                        OutlinedButton(
                            onClick = { clipboard.setText(AnnotatedString(data.address)) },
                            enabled = data.address.isNotBlank(),
                        ) {
                            Icon(Icons.Filled.ContentCopy, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(8.dp))
                            Text("Copy address")
                        }
                    }
                }
                WarningCard(
                    "Per-chain address — send only ${selected.symbol} on ${selected.chainName} " +
                        "(chain ${selected.chainId}). Sending another asset or using the wrong network may cause permanent loss.",
                )
                MetadataCard(family = data.family, derivation = data.derivation, domain = data.domain)
            }
        }
        DepositsSection(state.deposit.deposits, onRetry = viewModel::loadDeposits)
    }
}

@Composable
private fun MetadataCard(family: String?, derivation: String?, domain: String?) {
    if (family == null && derivation == null && domain == null) return
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
    ) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            family?.let { DetailRow("Family", it) }
            derivation?.let { DetailRow("Derivation", it) }
            domain?.let { DetailRow("Domain", it) }
        }
    }
}

// ---------------- Withdraw ----------------

@Composable
private fun WithdrawTab(state: CustodyUiState, viewModel: CustodyViewModel) {
    val funded = state.fundedRows.filter { it.known }
    val w = state.withdraw
    var showConfirm by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        if (funded.isEmpty()) {
            HintText("You have no funded assets to withdraw.")
            if (w.result != null) {
                WithdrawResultCard(w.result) { viewModel.clearWithdrawResult() }
            }
            return@Column
        }
        Text("Asset", style = MaterialTheme.typography.labelLarge)
        Row(modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            funded.forEach { row ->
                FilterChip(
                    selected = row.key == w.selectedKey,
                    onClick = { viewModel.onWithdrawAssetSelected(row.key) },
                    label = { Text(row.symbol) },
                )
            }
        }
        val row = state.rowFor(w.selectedKey)
        if (row != null) {
            Text(
                "Available: ${row.amountText} ${row.symbol} on ${row.asset.chainName} (chain ${row.asset.chainId})",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        OutlinedTextField(
            value = w.amount,
            onValueChange = viewModel::onAmountChanged,
            label = { Text("Amount") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
            trailingIcon = {
                TextButton(onClick = { viewModel.onMax() }, enabled = row != null) { Text("Max") }
            },
        )
        OutlinedTextField(
            value = w.destination,
            onValueChange = viewModel::onDestinationChanged,
            label = { Text("Destination address (to)") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        if (row != null) {
            val tokenLabel = if (row.asset.isNative) "native" else row.asset.token
            Text(
                "Token: $tokenLabel",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        OutlinedTextField(
            value = w.tokenOverride,
            onValueChange = viewModel::onTokenOverrideChanged,
            label = { Text("Token override (advanced, ERC-20 address)") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        if (w.submitError != null) {
            Text(w.submitError, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
        }
        Button(
            onClick = {
                val err = viewModel.validateWithdraw()
                if (err == null) showConfirm = true else viewModel.onAmountChanged(w.amount)
            },
            enabled = !w.submitting && row != null,
            modifier = Modifier.fillMaxWidth(),
        ) {
            if (w.submitting) {
                CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
                Spacer(Modifier.width(8.dp))
            }
            Text("Review withdrawal")
        }

        if (w.result != null) {
            WithdrawResultCard(w.result) { viewModel.clearWithdrawResult() }
        }
    }

    if (showConfirm) {
        val row = state.rowFor(w.selectedKey)
        val token = viewModel.effectiveToken()
        AlertDialog(
            onDismissRequest = { showConfirm = false },
            title = { Text("Confirm withdrawal") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    ConfirmRow("Asset", row?.symbol ?: "—")
                    ConfirmRow("Chain", row?.let { "${it.asset.chainName} (${it.asset.chainId})" } ?: "—")
                    ConfirmRow("Amount", "${w.amount} ${row?.symbol ?: ""}")
                    ConfirmRow("Token", token)
                    ConfirmRow("To", w.destination)
                    Spacer(Modifier.height(4.dp))
                    Text(
                        "Double-check the address, chain and token. On-chain transfers cannot be reversed.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            },
            confirmButton = {
                Button(onClick = {
                    showConfirm = false
                    viewModel.submitWithdraw()
                }) { Text("Confirm & submit") }
            },
            dismissButton = { TextButton(onClick = { showConfirm = false }) { Text("Cancel") } },
        )
    }
}

@Composable
private fun ConfirmRow(label: String, value: String) {
    Row(modifier = Modifier.fillMaxWidth()) {
        Text("$label:", modifier = Modifier.width(72.dp), color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall)
        Text(value, style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.Medium)
    }
}

@Composable
private fun WithdrawResultCard(r: CustodyWithdrawResult, onDismiss: () -> Unit) {
    val (container, content) = when (r.status) {
        WithdrawStatus.SIGNED -> MaterialTheme.colorScheme.secondaryContainer to MaterialTheme.colorScheme.onSecondaryContainer
        WithdrawStatus.PENDING_APPROVAL -> MaterialTheme.colorScheme.tertiaryContainer to MaterialTheme.colorScheme.onTertiaryContainer
        WithdrawStatus.BLOCKED, WithdrawStatus.REJECTED, WithdrawStatus.ERROR ->
            MaterialTheme.colorScheme.errorContainer to MaterialTheme.colorScheme.onErrorContainer
        else -> MaterialTheme.colorScheme.surfaceVariant to MaterialTheme.colorScheme.onSurfaceVariant
    }
    Card(modifier = Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = container, contentColor = content)) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            when (r.status) {
                WithdrawStatus.SIGNED -> {
                    Text("Signed ✓", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    r.digest?.let { Text("Digest: ${it.short()}", fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall) }
                    r.signature?.let { Text("Sig: ${it.short()}", fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall) }
                    r.withdrawalId?.let { Text("ID: $it", style = MaterialTheme.typography.bodySmall) }
                }
                WithdrawStatus.PENDING_APPROVAL -> {
                    Text("Pending approval", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    Text("This is a governed withdrawal and is awaiting approval inside the custody gateway.")
                    r.intentId?.let { Text("Intent: $it", fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall) }
                }
                WithdrawStatus.BLOCKED -> {
                    Text("Blocked", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    Text(r.reason ?: "This withdrawal was blocked by policy.")
                    r.category?.let { Text("Category: $it", style = MaterialTheme.typography.bodySmall) }
                }
                WithdrawStatus.REJECTED -> {
                    Text("Rejected", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    Text(r.reason ?: "This withdrawal was rejected.")
                    r.category?.let { Text("Category: $it", style = MaterialTheme.typography.bodySmall) }
                }
                WithdrawStatus.ERROR -> {
                    Text("Error", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    Text(r.reason ?: "The gateway could not process this withdrawal.")
                }
                else -> {
                    Text(r.status.label, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    r.reason?.let { Text(it) }
                }
            }
            TextButton(onClick = onDismiss) { Text("Done") }
        }
    }
}

// ---------------- Unavailable (Activity / Approvals) ----------------

@Composable
private fun UnavailableTab(title: String, explanation: String) {
    Column(
        modifier = Modifier.fillMaxSize().padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Spacer(Modifier.height(24.dp))
        Icon(
            Icons.Filled.Info,
            contentDescription = null,
            modifier = Modifier.size(40.dp),
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
        Text("Not available on this backend", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(
            explanation,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.fillMaxWidth(),
        )
    }
}

// ---------------- shared bits ----------------

@Composable
private fun DepositsSection(deposits: Async<CustodyDeposits>, onRetry: () -> Unit) {
    Spacer(Modifier.height(4.dp))
    HorizontalDivider()
    Spacer(Modifier.height(12.dp))
    Text("Recent incoming transfers", style = MaterialTheme.typography.labelLarge)
    Spacer(Modifier.height(8.dp))
    val data = deposits.data
    when {
        deposits.loading && data == null -> LoadingBox()
        deposits.error != null && data == null -> ErrorBox(deposits.error, onRetry)
        data == null || data.unavailable ->
            HintText("Deposit scanning isn't available on this backend yet.")
        data.isEmpty ->
            HintText("No incoming transfers detected yet.")
        else -> Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            data.rows.forEach { DepositRow(it) }
        }
    }
}

@Composable
private fun DepositRow(d: CustodyDeposit) {
    val clipboard = LocalClipboardManager.current
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
    ) {
        Column(modifier = Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = if (d.amount.isNotBlank()) "+${d.amount} ${d.asset}" else d.asset,
                    style = MaterialTheme.typography.titleSmall,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.SemiBold,
                )
                DepositStatusChip(d.status)
            }
            Text("${d.chainName} · ${relativeTime(d.timestampMs)}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            if (d.txHash.isNotBlank()) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(d.txShort, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
                    IconButton(onClick = { clipboard.setText(AnnotatedString(d.txHash)) }, modifier = Modifier.size(28.dp)) {
                        Icon(Icons.Filled.ContentCopy, contentDescription = "Copy tx hash", modifier = Modifier.size(16.dp))
                    }
                }
            }
        }
    }
}

@Composable
private fun DepositStatusChip(status: DepositStatus) {
    val (bg, fg) = when (status) {
        DepositStatus.CREDITED -> MaterialTheme.colorScheme.primaryContainer to MaterialTheme.colorScheme.onPrimaryContainer
        DepositStatus.DUPLICATE -> MaterialTheme.colorScheme.surface to MaterialTheme.colorScheme.onSurfaceVariant
        DepositStatus.UNKNOWN -> MaterialTheme.colorScheme.secondaryContainer to MaterialTheme.colorScheme.onSecondaryContainer
    }
    Box(
        modifier = Modifier.clip(RoundedCornerShape(6.dp)).background(bg).padding(horizontal = 8.dp, vertical = 3.dp),
    ) {
        Text(status.label, style = MaterialTheme.typography.labelSmall, color = fg)
    }
}

/** Coarse relative time ("just now" / "5m ago" / "3h ago" / "2d ago") from an epoch-ms timestamp. */
private fun relativeTime(timestampMs: Long?): String {
    if (timestampMs == null || timestampMs <= 0L) return "—"
    val deltaMs = System.currentTimeMillis() - timestampMs
    if (deltaMs < 0L) return "just now"
    val mins = deltaMs / 60000L
    return when {
        mins < 1L -> "just now"
        mins < 60L -> "${mins}m ago"
        mins < 1440L -> "${mins / 60L}h ago"
        else -> "${mins / 1440L}d ago"
    }
}

@Composable
private fun DetailRow(label: String, value: String) {
    Row(modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
        Text("$label:", modifier = Modifier.width(96.dp), color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall)
        Text(value, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
    }
}

@Composable
private fun WarningCard(text: String) {
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer, contentColor = MaterialTheme.colorScheme.onErrorContainer), modifier = Modifier.fillMaxWidth()) {
        Row(modifier = Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Filled.Warning, contentDescription = null, modifier = Modifier.size(20.dp))
            Spacer(Modifier.width(8.dp))
            Text(text, style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun LoadingBox() {
    Box(modifier = Modifier.fillMaxWidth().padding(32.dp), contentAlignment = Alignment.Center) {
        CircularProgressIndicator()
    }
}

@Composable
private fun ErrorBox(message: String, onRetry: () -> Unit) {
    Column(modifier = Modifier.fillMaxWidth().padding(24.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(message, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium)
        Button(onClick = onRetry) { Text("Retry") }
    }
}

@Composable
private fun EmptyBox(message: String) {
    Box(modifier = Modifier.fillMaxSize().padding(32.dp), contentAlignment = Alignment.Center) {
        Text(message, color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
private fun HintText(text: String) {
    Text(text, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
}

// short hash/address display helper.
private fun String.short(): String = if (length <= 16) this else "${take(8)}…${takeLast(6)}"

// ---------------- Sub-accounts ----------------

@Composable
private fun SubAccountsTab(state: CustodyUiState, viewModel: CustodyViewModel) {
    val sa = state.subAccounts
    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text("Create sub-account", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                Text(
                    "A named vault under your base vault. Letters, digits, _ and - only.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                OutlinedTextField(
                    value = sa.newLabel,
                    onValueChange = viewModel::onNewSubAccountLabelChanged,
                    label = { Text("Label") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag("subaccount_label"),
                )
                if (sa.createError != null) {
                    Text(sa.createError, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                }
                Button(
                    onClick = { viewModel.createSubAccount() },
                    enabled = !sa.creating && sa.newLabel.isNotBlank(),
                    modifier = Modifier.fillMaxWidth().testTag("subaccount_create"),
                ) {
                    if (sa.creating) {
                        CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
                        Spacer(Modifier.width(8.dp))
                    }
                    Text("Create sub-account")
                }
            }
        }

        val list = sa.list
        when {
            list.loading && list.data == null -> LoadingBox()
            list.error != null && list.data == null -> ErrorBox(list.error) { viewModel.loadSubAccounts() }
            list.data == null || list.data.unavailable -> UnavailableCard(
                "Sub-accounts are not available on this backend yet. Creating one will start working once the gateway route is deployed.",
            )
            else -> {
                val data = list.data
                Text("Base vault: ${data.defaultVault.short().ifBlank { "—" }}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, fontFamily = FontFamily.Monospace)
                if (data.subAccounts.isEmpty()) {
                    EmptyBox("No sub-accounts yet.")
                } else {
                    data.subAccounts.forEach { sub -> SubAccountCard(sub) }
                }
            }
        }
    }
}

@Composable
private fun SubAccountCard(sub: CustodySubAccount) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(sub.displayLabel, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f))
                Text("Tier: ${sub.tier}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Text(sub.idShort, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, fontFamily = FontFamily.Monospace)
            val funded = sub.funded()
            if (funded.isEmpty()) {
                Text("No balances", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(top = 6.dp))
            } else {
                Spacer(Modifier.height(6.dp))
                funded.forEach { row ->
                    Row(modifier = Modifier.fillMaxWidth().padding(vertical = 1.dp)) {
                        Text(row.symbol, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
                        Text(row.amountText, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium)
                    }
                }
            }
        }
    }
}

// ---------------- Transfer ----------------

@Composable
private fun TransferTab(state: CustodyUiState, viewModel: CustodyViewModel) {
    val t = state.transfer
    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(20.dp),
    ) {
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text("Custody ↔ Trading bridge", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    BridgeDirection.entries.forEach { d ->
                        FilterChip(
                            selected = d == t.direction,
                            onClick = { if (d != t.direction) viewModel.onBridgeDirectionToggle() },
                            label = { Text(d.label) },
                            modifier = Modifier.testTag("bridge_dir_${d.name}"),
                        )
                    }
                }
                OutlinedTextField(
                    value = t.bridgeAssetText,
                    onValueChange = viewModel::onBridgeAssetChanged,
                    label = { Text("Engine asset id") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag("bridge_asset"),
                )
                OutlinedTextField(
                    value = t.bridgeAmountText,
                    onValueChange = viewModel::onBridgeAmountChanged,
                    label = { Text("Amount (integer)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag("bridge_amount"),
                )
                if (t.bridgeError != null) {
                    Text(t.bridgeError, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                }
                Button(
                    onClick = { viewModel.submitBridgeTransfer() },
                    enabled = t.canBridge,
                    modifier = Modifier.fillMaxWidth().testTag("bridge_submit"),
                ) {
                    if (t.bridgeSubmitting) {
                        CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
                        Spacer(Modifier.width(8.dp))
                    }
                    Text("Transfer")
                }
                t.bridgeResult?.let { r -> BridgeResultCard(r) { viewModel.clearBridgeResult() } }
            }
        }

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text("Between sub-accounts", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                val labels = viewModel.subAccountLabels()
                Text("From", style = MaterialTheme.typography.labelMedium)
                VaultChips(labels = labels, selected = t.fromLabel, onSelect = viewModel::onFromLabelChanged, tagPrefix = "from")
                Text("To", style = MaterialTheme.typography.labelMedium)
                VaultChips(labels = labels, selected = t.toLabel, onSelect = viewModel::onToLabelChanged, tagPrefix = "to")
                OutlinedTextField(
                    value = t.subAsset,
                    onValueChange = viewModel::onSubAssetChanged,
                    label = { Text("Asset (e.g. ETH)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag("sub_asset"),
                )
                OutlinedTextField(
                    value = t.subAmountText,
                    onValueChange = viewModel::onSubAmountChanged,
                    label = { Text("Amount") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag("sub_amount"),
                )
                if (t.subError != null) {
                    Text(t.subError, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                }
                Button(
                    onClick = { viewModel.submitSubAccountTransfer() },
                    enabled = t.canSubTransfer,
                    modifier = Modifier.fillMaxWidth().testTag("sub_submit"),
                ) {
                    if (t.subSubmitting) {
                        CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
                        Spacer(Modifier.width(8.dp))
                    }
                    Text("Move")
                }
                t.subResult?.let { r -> SubTransferResultCard(r) { viewModel.clearSubTransferResult() } }
            }
        }
    }
}

@Composable
private fun VaultChips(labels: List<String>, selected: String, onSelect: (String) -> Unit, tagPrefix: String) {
    Row(modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        labels.forEach { lbl ->
            val display = if (lbl.isBlank()) "Base vault" else lbl
            FilterChip(
                selected = lbl == selected,
                onClick = { onSelect(lbl) },
                label = { Text(display) },
                modifier = Modifier.testTag("vault_${tagPrefix}_${if (lbl.isBlank()) "base" else lbl}"),
            )
        }
    }
}

@Composable
private fun BridgeResultCard(r: CustodyBridgeResult, onDismiss: () -> Unit) {
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant), modifier = Modifier.fillMaxWidth().testTag("bridge_result")) {
        Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(if (r.ok) "Submitted" else "Rejected", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f))
                if (r.simulated) SimulatedChip()
            }
            r.direction?.let { DetailRow("Direction", it.label) }
            r.asset?.let { DetailRow("Asset id", it.toString()) }
            r.amount?.let { DetailRow("Amount", it.toString()) }
            if (r.direction == BridgeDirection.TO_TRADING) {
                DetailRow("Trading credited", if (r.tradingCredited) "yes" else "no")
            }
            r.note?.let {
                Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            TextButton(onClick = onDismiss, modifier = Modifier.align(Alignment.End)) { Text("Dismiss") }
        }
    }
}

@Composable
private fun SubTransferResultCard(r: SubAccountTransferResult, onDismiss: () -> Unit) {
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant), modifier = Modifier.fillMaxWidth().testTag("sub_result")) {
        Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(if (r.ok) "Submitted" else "Rejected", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f))
                if (r.simulated) SimulatedChip()
            }
            r.from?.let { DetailRow("From", it.short()) }
            r.to?.let { DetailRow("To", it.short()) }
            r.asset?.let { DetailRow("Asset", it) }
            r.amount?.let { DetailRow("Amount", it) }
            r.note?.let {
                Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            TextButton(onClick = onDismiss, modifier = Modifier.align(Alignment.End)) { Text("Dismiss") }
        }
    }
}

/** Honest "not settled" marker shown whenever a transfer response carries stub:true. */
@Composable
private fun SimulatedChip() {
    Box(
        modifier = Modifier
            .background(MaterialTheme.colorScheme.tertiaryContainer, RoundedCornerShape(50))
            .padding(horizontal = 10.dp, vertical = 3.dp)
            .testTag("simulated_chip"),
    ) {
        Text(
            "Simulated · not settled",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onTertiaryContainer,
            fontWeight = FontWeight.Medium,
        )
    }
}

@Composable
private fun UnavailableCard(text: String) {
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant), modifier = Modifier.fillMaxWidth()) {
        Row(modifier = Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Filled.Info, contentDescription = null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.width(10.dp))
            Text(text, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
