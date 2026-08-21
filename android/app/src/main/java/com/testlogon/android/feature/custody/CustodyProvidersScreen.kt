@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.custody

import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Info
import androidx.compose.material3.AssistChip
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
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.data.custody.CustodyProvider
import com.testlogon.android.data.custody.CustodyVault
import com.testlogon.android.data.custody.ProviderStatusDetail
import com.testlogon.android.data.custody.WithdrawalApproval
import com.testlogon.android.feature.custody.CustodyProviderFormat.ProviderKind
import com.testlogon.android.feature.custody.CustodyProviderFormat.Severity
import com.testlogon.android.feature.custody.CustodyProviderFormat.StepState

/** Route-level entry for the external custody-provider surface (reached from Custody / More). */
@Composable
fun CustodyProvidersRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: CustodyProvidersViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    CustodyProvidersScreen(state = state, onBack = onBack, viewModel = viewModel, modifier = modifier)
}

@Composable
fun CustodyProvidersScreen(
    state: ProvidersUiState,
    onBack: () -> Unit,
    viewModel: CustodyProvidersViewModel,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier,
        topBar = {
            TopAppBar(
                title = { Text("Custody providers") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(20.dp),
        ) {
            Text(
                "Back your custody with a qualified custodian (Fireblocks, BitGo) or the internal MPC gateway. " +
                    "Provider credentials are held server-side; this screen only initiates the connection and shows status.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            ProvidersSection(state, viewModel)
            HorizontalDivider()
            VaultsSection(state, viewModel)
            HorizontalDivider()
            ApprovalSection(state, viewModel)
        }
    }
}

// ---------------- Providers ----------------

@Composable
private fun ProvidersSection(state: ProvidersUiState, viewModel: CustodyProvidersViewModel) {
    Text("Providers", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
    val p = state.providers
    when {
        p.loading && p.data == null -> ProvLoading()
        p.error != null && p.data == null -> ProvError(p.error) { viewModel.loadProviders() }
        p.data == null || p.data.unavailable || p.data.isEmpty ->
            PendingBackendCard("Provider integration pending backend. When the custody edge exposes the provider routes, Internal / Fireblocks / BitGo will appear here to connect.")
        else -> Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
            state.providerList.forEach { prov ->
                ProviderCard(
                    provider = prov,
                    status = state.statuses[prov.id],
                    inFlight = prov.id in state.actionInFlight,
                    error = state.actionErrors[prov.id],
                    onConnect = { viewModel.connect(prov.id, prov.name.ifBlank { null }) },
                    onDisconnect = { viewModel.disconnect(prov.id) },
                    onLoadStatus = { viewModel.loadProviderStatus(prov.id) },
                )
            }
        }
    }
}

@Composable
private fun ProviderCard(
    provider: CustodyProvider,
    status: ProviderStatusUi?,
    inFlight: Boolean,
    error: String?,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
    onLoadStatus: () -> Unit,
) {
    val kind = ProviderKind.from(provider.kind)
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        provider.displayName.ifBlank { CustodyProviderFormat.kindLabel(kind) },
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                    )
                    Text(
                        CustodyProviderFormat.kindLabel(kind) + if (CustodyProviderFormat.isExternal(kind)) " · Qualified custodian" else "",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                SeverityBadge(CustodyProviderFormat.statusBadge(provider.status))
            }

            if (provider.features.isNotEmpty()) {
                Row(
                    modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    provider.features.forEach { f ->
                        AssistChip(onClick = {}, label = { Text(f, style = MaterialTheme.typography.labelSmall) })
                    }
                }
            }

            // Live status probe (attestation / reconciliation / pending approvals).
            when {
                status?.loading == true -> Text("Checking status…", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                status?.error != null -> Text(status.error, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                status?.data != null -> ProviderStatusDetailView(status.data)
            }

            if (error != null) {
                Text(error, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
            }

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = onLoadStatus, modifier = Modifier.weight(1f)) { Text("Status") }
                if (provider.connected) {
                    Button(onClick = onDisconnect, enabled = !inFlight, modifier = Modifier.weight(1f)) {
                        if (inFlight) SmallSpinnerOnPrimary()
                        Text("Disconnect")
                    }
                } else {
                    Button(onClick = onConnect, enabled = !inFlight, modifier = Modifier.weight(1f)) {
                        if (inFlight) SmallSpinnerOnPrimary()
                        Text("Connect")
                    }
                }
            }
        }
    }
}

@Composable
private fun ProviderStatusDetailView(d: ProviderStatusDetail) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            SeverityDot(CustodyProviderFormat.attestationSeverity(d.balancesAttested))
            Spacer(Modifier.width(6.dp))
            Text(CustodyProviderFormat.attestationLabel(d.balancesAttested), style = MaterialTheme.typography.bodySmall)
        }
        d.lastReconciledTs?.let {
            Text("Last reconciled: $it", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, fontFamily = FontFamily.Monospace)
        }
        d.pendingApprovals?.let {
            Text("Pending approvals: $it", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

// ---------------- Vaults (per-vault provider) ----------------

@Composable
private fun VaultsSection(state: ProvidersUiState, viewModel: CustodyProvidersViewModel) {
    Text("Vaults", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
    Text(
        "Choose which custodian backs each vault.",
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    val v = state.vaults
    when {
        v.loading && v.data == null -> ProvLoading()
        v.error != null && v.data == null -> ProvError(v.error) { viewModel.loadVaults() }
        v.data == null || v.data.unavailable || v.data.isEmpty ->
            PendingBackendCard("Vault provider selection pending backend. Your vaults and their backing custodian will appear here once the route is deployed.")
        else -> Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
            v.data.vaults.forEach { vault ->
                VaultCard(
                    vault = vault,
                    inFlight = vault.vault in state.vaultChangeInFlight,
                    error = state.vaultChangeErrors[vault.vault],
                    onSelectProvider = { viewModel.setVaultProvider(vault.vault, it) },
                )
            }
        }
    }
}

@Composable
private fun VaultCard(
    vault: CustodyVault,
    inFlight: Boolean,
    error: String?,
    onSelectProvider: (String) -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(vault.displayLabel, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    Text(vault.vaultShort, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, fontFamily = FontFamily.Monospace)
                }
                val kind = ProviderKind.from(vault.provider)
                SeverityBadge(
                    CustodyProviderFormat.Badge(
                        CustodyProviderFormat.kindLabel(kind),
                        if (CustodyProviderFormat.isExternal(kind)) Severity.GOOD else Severity.NEUTRAL,
                    ),
                )
            }
            Text("Backing provider", style = MaterialTheme.typography.labelMedium)
            Row(
                modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                PROVIDER_KIND_CHOICES.forEach { (wire, label) ->
                    FilterChip(
                        selected = vault.provider.equals(wire, ignoreCase = true),
                        enabled = !inFlight,
                        onClick = { if (!vault.provider.equals(wire, ignoreCase = true)) onSelectProvider(wire) },
                        label = { Text(label) },
                    )
                }
            }
            if (inFlight) {
                Text("Updating…", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            if (error != null) {
                Text(error, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

private val PROVIDER_KIND_CHOICES: List<Pair<String, String>> = listOf(
    "internal" to "Internal",
    "fireblocks" to "Fireblocks",
    "bitgo" to "BitGo",
)

// ---------------- Withdrawal approval stepper ----------------

@Composable
private fun ApprovalSection(state: ProvidersUiState, viewModel: CustodyProvidersViewModel) {
    Text("Withdrawal approval", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
    Text(
        "Look up the multi-sig approval progress of a provider-backed withdrawal.",
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    val a = state.approval
    OutlinedTextField(
        value = a.withdrawalId,
        onValueChange = viewModel::onApprovalIdChanged,
        label = { Text("Withdrawal id") },
        singleLine = true,
        modifier = Modifier.fillMaxWidth(),
    )
    if (a.error != null) {
        Text(a.error, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
    }
    Button(onClick = { viewModel.lookupApproval() }, enabled = !a.loading, modifier = Modifier.fillMaxWidth()) {
        if (a.loading) SmallSpinnerOnPrimary()
        Text("Check approval")
    }
    a.data?.let { ApprovalCard(it) }
}

@Composable
private fun ApprovalCard(approval: WithdrawalApproval) {
    if (approval.unavailable) {
        PendingBackendCard("Approval tracking isn't available for this withdrawal on this backend.")
        return
    }
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            val status = CustodyProviderFormat.ApprovalStatus.from(approval.status)
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("Quorum", modifier = Modifier.weight(1f), style = MaterialTheme.typography.labelLarge)
                Text(
                    CustodyProviderFormat.quorumLabel(approval.collected, approval.quorum),
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                )
            }
            // Stepper.
            CustodyProviderFormat.stepper(status).forEach { step ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    StepDot(step.state)
                    Spacer(Modifier.width(10.dp))
                    Text(
                        step.label,
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = if (step.state == StepState.CURRENT) FontWeight.SemiBold else FontWeight.Normal,
                        color = when (step.state) {
                            StepState.REJECTED -> MaterialTheme.colorScheme.error
                            StepState.UPCOMING -> MaterialTheme.colorScheme.onSurfaceVariant
                            else -> MaterialTheme.colorScheme.onSurface
                        },
                    )
                }
            }
            if (approval.approvals.isNotEmpty()) {
                HorizontalDivider()
                Text("Approvers", style = MaterialTheme.typography.labelLarge)
                approval.approvals.forEach { ap ->
                    Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                        Text(ap.approver, modifier = Modifier.weight(1f), style = MaterialTheme.typography.bodySmall)
                        if (ap.at.isNotBlank()) {
                            Text(ap.at, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, fontFamily = FontFamily.Monospace)
                        }
                    }
                }
            }
        }
    }
}

// ---------------- shared bits ----------------

@Composable
private fun SeverityBadge(badge: CustodyProviderFormat.Badge) {
    val color = severityColor(badge.severity)
    Box(
        modifier = Modifier
            .background(color.copy(alpha = 0.15f), RoundedCornerShape(50))
            .padding(horizontal = 10.dp, vertical = 4.dp),
    ) {
        Text(badge.label, style = MaterialTheme.typography.labelSmall, color = color, fontWeight = FontWeight.SemiBold)
    }
}

@Composable
private fun SeverityDot(severity: Severity) {
    Box(modifier = Modifier.size(10.dp).background(severityColor(severity), CircleShape))
}

@Composable
private fun StepDot(state: StepState) {
    val color = when (state) {
        StepState.DONE -> severityColor(Severity.GOOD)
        StepState.CURRENT -> MaterialTheme.colorScheme.primary
        StepState.REJECTED -> MaterialTheme.colorScheme.error
        StepState.UPCOMING -> MaterialTheme.colorScheme.outline
    }
    Box(modifier = Modifier.size(12.dp).background(color, CircleShape))
}

@Composable
private fun severityColor(severity: Severity): Color = when (severity) {
    Severity.GOOD -> Color(0xFF2E7D32)
    Severity.WARN -> Color(0xFFED6C02)
    Severity.BAD -> MaterialTheme.colorScheme.error
    Severity.NEUTRAL -> MaterialTheme.colorScheme.onSurfaceVariant
}

@Composable
private fun SmallSpinnerOnPrimary() {
    CircularProgressIndicator(modifier = Modifier.size(16.dp).padding(end = 0.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
    Spacer(Modifier.width(8.dp))
}

@Composable
private fun PendingBackendCard(text: String) {
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant), modifier = Modifier.fillMaxWidth()) {
        Row(modifier = Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Filled.Info, contentDescription = null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.width(10.dp))
            Text(text, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun ProvLoading() {
    Box(modifier = Modifier.fillMaxWidth().padding(32.dp), contentAlignment = Alignment.Center) {
        CircularProgressIndicator()
    }
}

@Composable
private fun ProvError(message: String, onRetry: () -> Unit) {
    Column(modifier = Modifier.fillMaxWidth().padding(24.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(message, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium)
        Button(onClick = onRetry) { Text("Retry") }
    }
}
