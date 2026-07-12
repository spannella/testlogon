@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.infrabilling

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Paid
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.infrabilling.BillingLedgerEntryDto
import com.testlogon.android.data.infrabilling.ComputeSpendSnapshot
import com.testlogon.android.data.infrabilling.ResourceBreakdownEntryDto
import com.testlogon.android.feature.infracommon.centsToUsd
import com.testlogon.android.feature.infracommon.infraErrorMessage

object ComputeBillingTestTags {
    const val SCREEN = "billing_screen"
    const val CONTENT = "billing_content"
    const val FORBIDDEN = "billing_forbidden"
    const val ERROR_RETRY = "billing_error_retry"
    const val SET_BUDGET = "billing_set_budget"
    const val BUDGET_FIELD = "billing_budget_field"
    const val BUDGET_CONFIRM = "billing_budget_confirm"
    fun resource(id: String) = "billing_resource_$id"
    fun ledger(id: String) = "billing_ledger_$id"
}

@Composable
fun ComputeBillingRoute(
    onBack: () -> Unit,
    viewModel: ComputeBillingViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    ComputeBillingScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
        onSetBudget = viewModel::setBudget,
        onMessageShown = viewModel::clearMessage,
    )
}

@Composable
fun ComputeBillingScreen(
    state: BillingUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onSetBudget: (Double) -> Unit,
    onMessageShown: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbar = remember { SnackbarHostState() }
    var showBudget by remember { mutableStateOf(false) }

    LaunchedEffect(state.message, state.transientError) {
        val msg = state.message ?: state.transientError?.let { infraErrorMessage(it) }
        if (msg != null) {
            snackbar.showSnackbar(msg)
            onMessageShown()
        }
    }

    Scaffold(
        modifier = modifier.testTag(ComputeBillingTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text("Compute spend") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        val isRefreshing = (state.data as? BillingDataState.Content)?.isRefreshing == true
        PullToRefreshBox(
            isRefreshing = isRefreshing,
            onRefresh = onRefresh,
            modifier = Modifier.fillMaxSize().padding(padding),
        ) {
            when (val d = state.data) {
                is BillingDataState.Loading -> LoadingState()
                is BillingDataState.Forbidden -> EmptyState(
                    modifier = Modifier.testTag(ComputeBillingTestTags.FORBIDDEN),
                    title = "Not authorised",
                    body = "You do not have access to compute billing.",
                    imageVector = Icons.Outlined.Lock,
                    actionLabel = "Back",
                    onAction = onBack,
                )
                is BillingDataState.Error -> ErrorState(
                    modifier = Modifier.testTag(ComputeBillingTestTags.ERROR_RETRY),
                    message = infraErrorMessage(d.type),
                    onRetry = onRetry,
                )
                is BillingDataState.Content -> BillingContent(
                    snapshot = d.snapshot,
                    onSetBudget = { showBudget = true },
                )
            }
        }
    }

    val content = state.data as? BillingDataState.Content
    if (showBudget && content != null) {
        BudgetDialog(
            currentCents = content.snapshot.budget.budgetMonthlyCents,
            busy = state.busy,
            onDismiss = { showBudget = false },
            onConfirm = { dollars ->
                onSetBudget(dollars)
                showBudget = false
            },
        )
    }
}

@Composable
private fun BillingContent(snapshot: ComputeSpendSnapshot, onSetBudget: () -> Unit) {
    LazyColumn(
        modifier = Modifier.fillMaxSize().testTag(ComputeBillingTestTags.CONTENT),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        item { SummaryCard(snapshot) }
        item {
            OutlinedButton(
                onClick = onSetBudget,
                modifier = Modifier.fillMaxWidth().testTag(ComputeBillingTestTags.SET_BUDGET),
            ) { Text("Set monthly budget") }
        }
        if (snapshot.resources.isNotEmpty()) {
            item { Text("Resources", style = MaterialTheme.typography.titleMedium) }
            items(items = snapshot.resources, key = { it.resourceId }) { ResourceRow(it) }
        }
        if (snapshot.history.isNotEmpty()) {
            item { Text("Recent charges", style = MaterialTheme.typography.titleMedium) }
            items(items = snapshot.history, key = { it.entryId }) { LedgerRow(it) }
        }
    }
}

@Composable
private fun SummaryCard(snapshot: ComputeSpendSnapshot) {
    val s = snapshot.spending
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Icon(Icons.Outlined.Paid, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                Text(s.month.ifBlank { "This month" }, style = MaterialTheme.typography.titleMedium)
            }
            Text(centsToUsd(s.totalCents), style = MaterialTheme.typography.headlineMedium)
            if (s.budgetCents > 0) {
                val pct = (s.budgetPct / 100.0).toFloat().coerceIn(0f, 1f)
                LinearProgressIndicator(progress = { pct }, modifier = Modifier.fillMaxWidth())
                Text(
                    "${"%.0f".format(s.budgetPct)}% of ${centsToUsd(s.budgetCents)} budget",
                    style = MaterialTheme.typography.bodySmall,
                    color = if (s.budgetPct >= 100) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Stat("EC2", centsToUsd(s.ec2TotalCents))
                Stat("K8s", centsToUsd(s.k8sTotalCents))
                Stat("Resources", "${s.resourceCount}")
            }
        }
    }
}

@Composable
private fun Stat(label: String, value: String) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(value, style = MaterialTheme.typography.titleSmall)
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun ResourceRow(entry: ResourceBreakdownEntryDto) {
    Card(modifier = Modifier.fillMaxWidth().testTag(ComputeBillingTestTags.resource(entry.resourceId))) {
        Row(
            modifier = Modifier.padding(16.dp).fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(entry.resourceLabel.ifBlank { entry.resourceId }, style = MaterialTheme.typography.titleSmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(
                    "${entry.resourceType.uppercase()} · ${entry.instanceTypeOrPreset} · ${"%.0f".format(entry.totalMinutes)} min",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Text(centsToUsd(entry.totalCents), style = MaterialTheme.typography.titleSmall)
        }
    }
}

@Composable
private fun LedgerRow(entry: BillingLedgerEntryDto) {
    Card(modifier = Modifier.fillMaxWidth().testTag(ComputeBillingTestTags.ledger(entry.entryId))) {
        Row(
            modifier = Modifier.padding(12.dp).fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(entry.resourceLabel.ifBlank { entry.resourceType }, style = MaterialTheme.typography.bodyMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(
                    "${entry.event} · ${"%.0f".format(entry.durationMinutes)} min",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Text(centsToUsd(entry.amountCents), style = MaterialTheme.typography.bodyMedium)
        }
    }
}

@Composable
private fun BudgetDialog(
    currentCents: Long,
    busy: Boolean,
    onDismiss: () -> Unit,
    onConfirm: (Double) -> Unit,
) {
    var value by remember { mutableStateOf(if (currentCents > 0) "%.2f".format(currentCents / 100.0) else "") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Monthly budget") },
        text = {
            OutlinedTextField(
                value = value,
                onValueChange = { value = it.filter { c -> c.isDigit() || c == '.' } },
                label = { Text("Amount (USD)") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
                modifier = Modifier.fillMaxWidth().testTag(ComputeBillingTestTags.BUDGET_FIELD),
            )
        },
        confirmButton = {
            TextButton(
                onClick = { value.toDoubleOrNull()?.let(onConfirm) },
                enabled = !busy && (value.toDoubleOrNull() ?: 0.0) >= 1.0,
                modifier = Modifier.testTag(ComputeBillingTestTags.BUDGET_CONFIRM),
            ) { Text("Save") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}
