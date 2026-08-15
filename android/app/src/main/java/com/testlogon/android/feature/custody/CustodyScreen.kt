@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.custody

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Verified
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Badge
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
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
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.data.custody.CustodyAsset
import com.testlogon.android.data.custody.CustodyAuditEntry
import com.testlogon.android.data.custody.CustodyDeposit
import com.testlogon.android.data.custody.CustodyWithdrawal
import com.testlogon.android.data.custody.CustodyWithdrawalResult
import com.testlogon.android.data.custody.WithdrawalStatus
import kotlinx.coroutines.delay

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
    val tabs = remember(state.approvals.isOfficer) {
        buildList {
            add(CustodyTab.BALANCES)
            add(CustodyTab.DEPOSIT)
            add(CustodyTab.WITHDRAW)
            add(CustodyTab.ACTIVITY)
            if (state.approvals.isOfficer) add(CustodyTab.APPROVALS)
        }
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
                CustodyTab.DEPOSIT -> DepositTab(state, viewModel)
                CustodyTab.WITHDRAW -> WithdrawTab(state, viewModel)
                CustodyTab.ACTIVITY -> ActivityTab(state, viewModel)
                CustodyTab.APPROVALS -> ApprovalsTab(state, viewModel)
            }
        }
    }
}

private fun CustodyTab.title(): String = when (this) {
    CustodyTab.BALANCES -> "Balances"
    CustodyTab.DEPOSIT -> "Deposit"
    CustodyTab.WITHDRAW -> "Withdraw"
    CustodyTab.ACTIVITY -> "Activity"
    CustodyTab.APPROVALS -> "Approvals"
}

// ---------------- Balances ----------------

@Composable
private fun BalancesTab(state: CustodyUiState, viewModel: CustodyViewModel) {
    val a = state.assets
    when {
        a.loading && a.data == null -> LoadingBox()
        a.error != null && a.data == null -> ErrorBox(a.error) { viewModel.loadAssets() }
        a.data.isNullOrEmpty() -> EmptyBox("No custody assets yet.")
        else -> LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            items(a.data, key = { it.key }) { asset ->
                AssetCard(
                    asset = asset,
                    onDeposit = {
                        viewModel.onTabSelected(CustodyTab.DEPOSIT)
                        viewModel.onDepositAssetSelected(asset.key)
                    },
                    onWithdraw = {
                        viewModel.onTabSelected(CustodyTab.WITHDRAW)
                        viewModel.onWithdrawAssetSelected(asset.key)
                    },
                )
            }
        }
    }
}

@Composable
private fun AssetCard(asset: CustodyAsset, onDeposit: () -> Unit, onWithdraw: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(asset.symbol, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    Text(
                        "${asset.name} · ${asset.network}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Column(horizontalAlignment = Alignment.End) {
                    Text(asset.balanceText, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    Text(asset.symbol, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            Spacer(Modifier.height(12.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = onDeposit, enabled = asset.addressAvailable, modifier = Modifier.weight(1f)) {
                    Text("Deposit")
                }
                Button(onClick = onWithdraw, enabled = asset.balance > 0.0, modifier = Modifier.weight(1f)) {
                    Text("Withdraw")
                }
            }
        }
    }
}

// ---------------- Deposit ----------------

@Composable
private fun DepositTab(state: CustodyUiState, viewModel: CustodyViewModel) {
    val assets = state.assets.data.orEmpty().filter { it.addressAvailable }
    val clipboard = LocalClipboardManager.current
    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("Select asset", style = MaterialTheme.typography.labelLarge)
        AssetChipRow(
            assets = assets,
            selectedKey = state.deposit.selectedKey,
            onSelect = { viewModel.onDepositAssetSelected(it) },
        )
        val addr = state.deposit.address
        when {
            state.deposit.selectedKey == null -> HintText("Choose an asset to see its deposit address.")
            addr.loading -> LoadingBox()
            addr.error != null -> ErrorBox(addr.error) {
                state.deposit.selectedKey?.let { viewModel.onDepositAssetSelected(it) }
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
                            data.address,
                            style = MaterialTheme.typography.bodyMedium,
                            fontFamily = FontFamily.Monospace,
                        )
                        Spacer(Modifier.height(8.dp))
                        OutlinedButton(onClick = {
                            clipboard.setText(AnnotatedString(data.address))
                        }) {
                            Icon(Icons.Filled.ContentCopy, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(8.dp))
                            Text("Copy address")
                        }
                        if (!data.memo.isNullOrBlank()) {
                            Spacer(Modifier.height(12.dp))
                            LabeledValue("Memo / tag (required)", data.memo, copyable = true, clipboardText = data.memo)
                        }
                    }
                }
                WarningCard("Send only ${data.asset} on ${data.network}. Sending any other asset or using the wrong network may cause permanent loss.")
            }
        }

        HorizontalDivider()
        Text("Recent deposits", style = MaterialTheme.typography.titleSmall)
        val dep = state.deposit.deposits
        when {
            dep.loading && dep.data == null -> LoadingBox()
            dep.data.isNullOrEmpty() -> HintText("No deposits observed yet.")
            else -> dep.data.forEach { DepositRow(it) }
        }
    }
}

@Composable
private fun DepositRow(d: CustodyDeposit) {
    Card(modifier = Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
        Row(modifier = Modifier.fillMaxWidth().padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f)) {
                Text("${d.amountText} ${d.asset}", fontWeight = FontWeight.Medium)
                Text("${d.chain} · ${d.confirmations} confirmations", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            StatusPill(d.status)
        }
    }
}

// ---------------- Withdraw ----------------

@Composable
private fun WithdrawTab(state: CustodyUiState, viewModel: CustodyViewModel) {
    val funded = state.fundedAssets
    val w = state.withdraw
    var showConfirm by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        if (funded.isEmpty()) {
            HintText("You have no funded assets to withdraw.")
            return@Column
        }
        Text("Asset", style = MaterialTheme.typography.labelLarge)
        AssetChipRow(assets = funded, selectedKey = w.selectedKey, onSelect = { viewModel.onWithdrawAssetSelected(it) })
        val asset = state.assetFor(w.selectedKey)
        if (asset != null) {
            Text(
                "Available: ${asset.balanceText} ${asset.symbol} on ${asset.network}",
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
                TextButton(onClick = { viewModel.onMax() }, enabled = asset != null) { Text("Max") }
            },
        )
        OutlinedTextField(
            value = w.destination,
            onValueChange = viewModel::onDestinationChanged,
            label = { Text("Destination address") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = w.memo,
            onValueChange = viewModel::onMemoChanged,
            label = { Text("Memo / tag (optional)") },
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
            enabled = !w.submitting && asset != null,
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
        val asset = state.assetFor(w.selectedKey)
        AlertDialog(
            onDismissRequest = { showConfirm = false },
            title = { Text("Confirm withdrawal") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    ConfirmRow("Asset", asset?.symbol ?: "—")
                    ConfirmRow("Network", asset?.network ?: "—")
                    ConfirmRow("Amount", "${w.amount} ${asset?.symbol ?: ""}")
                    ConfirmRow("Destination", w.destination)
                    if (w.memo.isNotBlank()) ConfirmRow("Memo", w.memo)
                    Spacer(Modifier.height(4.dp))
                    Text(
                        "Double-check the address and network. On-chain transfers cannot be reversed.",
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
        Text("$label:", modifier = Modifier.width(96.dp), color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall)
        Text(value, style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.Medium)
    }
}

@Composable
private fun WithdrawResultCard(r: CustodyWithdrawalResult, onDismiss: () -> Unit) {
    val (container, content) = when (r.status) {
        WithdrawalStatus.SIGNED -> MaterialTheme.colorScheme.secondaryContainer to MaterialTheme.colorScheme.onSecondaryContainer
        WithdrawalStatus.PENDING_APPROVAL -> MaterialTheme.colorScheme.tertiaryContainer to MaterialTheme.colorScheme.onTertiaryContainer
        WithdrawalStatus.BLOCKED, WithdrawalStatus.REJECTED -> MaterialTheme.colorScheme.errorContainer to MaterialTheme.colorScheme.onErrorContainer
        else -> MaterialTheme.colorScheme.surfaceVariant to MaterialTheme.colorScheme.onSurfaceVariant
    }
    Card(modifier = Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = container, contentColor = content)) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            when (r.status) {
                WithdrawalStatus.SIGNED -> {
                    Text("Signed ✓", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    r.digest?.let { Text("Digest: ${it.short()}", fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall) }
                    r.signature?.let { Text("Sig: ${it.short()}", fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall) }
                }
                WithdrawalStatus.PENDING_APPROVAL -> {
                    Text("Pending approval", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    Text("${r.approvals ?: 0} of ${r.approvalsRequired ?: 0} approvals collected.")
                }
                WithdrawalStatus.BLOCKED -> {
                    Text("Blocked", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    Text(r.reason ?: "This withdrawal was blocked by policy.")
                }
                WithdrawalStatus.REJECTED -> {
                    Text("Rejected", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    Text(r.reason ?: "This withdrawal was rejected.")
                }
                else -> {
                    Text(r.status.label, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                }
            }
            Text("${r.amountText} ${r.asset} -> ${r.destination.short()}", style = MaterialTheme.typography.bodySmall)
            TextButton(onClick = onDismiss) { Text("Done") }
        }
    }
}

// ---------------- Activity ----------------

@Composable
private fun ActivityTab(state: CustodyUiState, viewModel: CustodyViewModel) {
    // Drive polling from the screen: re-fetch every 5s while any row is non-terminal, stop otherwise.
    // Bounded loop tied to composition (leaves when the tab/screen leaves).
    LaunchedEffect(Unit) {
        while (true) {
            val keepGoing = viewModel.pollActivityOnce()
            if (!keepGoing) break
            delay(5_000)
        }
    }
    val act = state.activity
    Column(modifier = Modifier.fillMaxSize()) {
        Row(modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            Text("Withdrawals", style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
            IconButton(onClick = { viewModel.loadActivity() }) {
                Icon(Icons.Filled.Refresh, contentDescription = "Refresh")
            }
        }
        when {
            act.loading && act.data == null -> LoadingBox()
            act.error != null && act.data == null -> ErrorBox(act.error) { viewModel.loadActivity() }
            act.data.isNullOrEmpty() -> EmptyBox("No withdrawals yet.")
            else -> LazyColumn(
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                items(act.data, key = { it.id }) { wd -> WithdrawalCard(wd) }
            }
        }
    }
}

@Composable
private fun WithdrawalCard(wd: CustodyWithdrawal) {
    var expanded by remember { mutableStateOf(false) }
    Card(modifier = Modifier.fillMaxWidth().clickable { expanded = !expanded }) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("${wd.amountText} ${wd.asset}", fontWeight = FontWeight.SemiBold)
                    Text("-> ${wd.recipient.short()}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                StatusPill(wd.status.label)
            }
            if (wd.status == WithdrawalStatus.PENDING_APPROVAL && wd.approvalsRequired > 0) {
                Spacer(Modifier.height(8.dp))
                Text("${wd.approvalsCount} of ${wd.approvalsRequired} approvals", style = MaterialTheme.typography.bodySmall)
                LinearProgressIndicator(
                    progress = { (wd.approvalsCount.toFloat() / wd.approvalsRequired).coerceIn(0f, 1f) },
                    modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
                )
            }
            if (expanded) {
                Spacer(Modifier.height(8.dp))
                HorizontalDivider()
                Spacer(Modifier.height(8.dp))
                DetailRow("Network", wd.network)
                DetailRow("Recipient", wd.recipient)
                wd.digest?.let { DetailRow("Digest", it.short()) }
                wd.signature?.let { DetailRow("Signature", it.short()) }
                wd.reason?.let { DetailRow("Reason", it) }
                wd.category?.let { DetailRow("Category", it) }
                TimelockCountdown(wd.timelockUntilMs)
            }
        }
    }
}

@Composable
private fun TimelockCountdown(untilMs: Long?) {
    if (untilMs == null || untilMs <= 0L) return
    var now by remember { mutableStateOf(System.currentTimeMillis()) }
    LaunchedEffect(untilMs) {
        while (true) {
            now = System.currentTimeMillis()
            if (now >= untilMs) break
            delay(1_000)
        }
    }
    val remaining = (untilMs - now).coerceAtLeast(0L)
    val text = if (remaining <= 0L) "Timelock elapsed" else "Timelock: ${formatDuration(remaining)}"
    DetailRow("Timelock", text)
}

// ---------------- Approvals & Audit ----------------

@Composable
private fun ApprovalsTab(state: CustodyUiState, viewModel: CustodyViewModel) {
    val ap = state.approvals
    if (!ap.isOfficer) {
        EmptyBox("Approvals are available to custody officers only.")
        return
    }
    Column(modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("Pending queue", style = MaterialTheme.typography.titleSmall)
        val q = ap.queue
        when {
            q.loading && q.data == null -> LoadingBox()
            q.error != null && q.data == null -> ErrorBox(q.error) { viewModel.loadApprovals() }
            q.data.isNullOrEmpty() -> HintText("Nothing awaiting approval.")
            else -> q.data.forEach { wd ->
                ApprovalCard(
                    wd = wd,
                    actioning = wd.id in ap.actioning,
                    message = ap.actionMessages[wd.id],
                    onApprove = { viewModel.approve(wd.id) },
                    onRelease = { viewModel.release(wd.id) },
                )
            }
        }

        HorizontalDivider()
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Audit trail", style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
            TextButton(onClick = { viewModel.verifyAudit() }) {
                Icon(Icons.Filled.Verified, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(4.dp))
                Text("Verify")
            }
        }
        val au = ap.audit
        au.data?.let { audit ->
            if (audit.verifiedOk != null) {
                val ok = audit.verifiedOk
                AssistChip(
                    onClick = {},
                    label = { Text(if (ok) "Chain verified (${audit.verifiedCount ?: audit.entries.size} entries)" else "Verification FAILED") },
                    leadingIcon = { Icon(if (ok) Icons.Filled.Verified else Icons.Filled.Warning, contentDescription = null, modifier = Modifier.size(18.dp)) },
                )
            }
        }
        when {
            au.loading && au.data == null -> LoadingBox()
            au.error != null && au.data == null -> ErrorBox(au.error) { viewModel.loadAudit() }
            au.data == null || au.data.entries.isEmpty() -> HintText("No audit entries.")
            else -> au.data.entries.forEach { AuditRow(it) }
        }
    }
}

@Composable
private fun ApprovalCard(
    wd: CustodyWithdrawal,
    actioning: Boolean,
    message: String?,
    onApprove: () -> Unit,
    onRelease: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("${wd.amountText} ${wd.asset}", fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f))
                StatusPill(wd.status.label)
            }
            Text("-> ${wd.recipient.short()}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text("${wd.approvalsCount} of ${wd.approvalsRequired} approvals", style = MaterialTheme.typography.bodySmall)
            wd.reason?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
            if (message != null) {
                Text(message, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary)
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = onApprove, enabled = !actioning, modifier = Modifier.weight(1f)) { Text("Approve") }
                Button(onClick = onRelease, enabled = !actioning, modifier = Modifier.weight(1f)) { Text("Release") }
            }
        }
    }
}

@Composable
private fun AuditRow(e: CustodyAuditEntry) {
    Card(modifier = Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("#${e.seq} ${e.action}", fontWeight = FontWeight.Medium, modifier = Modifier.weight(1f))
                Text(e.hash.short(), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            if (e.detail.isNotBlank()) {
                Text(e.detail, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

// ---------------- shared bits ----------------

@Composable
private fun AssetChipRow(assets: List<CustodyAsset>, selectedKey: String?, onSelect: (String) -> Unit) {
    Row(modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        assets.forEach { asset ->
            FilterChip(
                selected = asset.key == selectedKey,
                onClick = { onSelect(asset.key) },
                label = { Text(asset.symbol) },
            )
        }
    }
}

@Composable
private fun LabeledValue(label: String, value: String, copyable: Boolean = false, clipboardText: String = value) {
    val clipboard = LocalClipboardManager.current
    Column(modifier = Modifier.fillMaxWidth()) {
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(value, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
            if (copyable) {
                IconButton(onClick = { clipboard.setText(AnnotatedString(clipboardText)) }) {
                    Icon(Icons.Filled.ContentCopy, contentDescription = "Copy", modifier = Modifier.size(18.dp))
                }
            }
        }
    }
}

@Composable
private fun DetailRow(label: String, value: String) {
    Row(modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
        Text("$label:", modifier = Modifier.width(96.dp), color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall)
        Text(value, style = MaterialTheme.typography.bodySmall, fontFamily = if (label in setOf("Digest", "Signature")) FontFamily.Monospace else FontFamily.Default)
    }
}

@Composable
private fun StatusPill(status: String) {
    val color = when (status.lowercase()) {
        "signed", "settled" -> MaterialTheme.colorScheme.secondaryContainer
        "pending approval", "screening", "broadcast" -> MaterialTheme.colorScheme.tertiaryContainer
        "blocked", "rejected" -> MaterialTheme.colorScheme.errorContainer
        else -> MaterialTheme.colorScheme.surfaceVariant
    }
    Box(
        modifier = Modifier
            .background(color, RoundedCornerShape(50))
            .padding(horizontal = 10.dp, vertical = 4.dp),
    ) {
        Text(status, style = MaterialTheme.typography.labelSmall)
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

private fun formatDuration(ms: Long): String {
    val totalSec = ms / 1000
    val h = totalSec / 3600
    val m = (totalSec % 3600) / 60
    val s = totalSec % 60
    return if (h > 0) "%dh %02dm %02ds".format(h, m, s) else "%dm %02ds".format(m, s)
}
