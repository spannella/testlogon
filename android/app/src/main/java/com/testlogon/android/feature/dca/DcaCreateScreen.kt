@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class, androidx.compose.foundation.layout.ExperimentalLayoutApi::class)

package com.testlogon.android.feature.dca

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
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
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DatePicker
import androidx.compose.material3.DatePickerDialog
import androidx.compose.material3.Divider
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.rememberDatePickerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.data.dca.DcaFrequency

/**
 * Create a DCA / recurring-buy plan: pick a target across the three markets (exchange symbol / creator
 * token / strategy fund), set the USD amount + cadence + start (optional end / total budget), funded from
 * the USD cash wallet. Submit is gated by the pure [DcaSchedule.validatePlan] and a money-safety confirm
 * that shows a schedule preview (the next runs). Explicit that scheduled buys run server-side.
 */
@Composable
fun DcaCreateRoute(
    onBack: () -> Unit,
    onCreated: (String) -> Unit,
    onAddCash: () -> Unit,
    viewModel: DcaCreateViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    var showConfirm by remember { mutableStateOf(false) }
    var showStartPicker by remember { mutableStateOf(false) }
    var showEndPicker by remember { mutableStateOf(false) }

    LaunchedEffect(state.createdPlanId) {
        state.createdPlanId?.let(onCreated)
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("New recurring buy") },
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
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
        ) {
            // ---- Target ----
            Text("What to buy", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))
            if (state.loadingTargets) {
                CircularProgressIndicator(modifier = Modifier.height(22.dp), strokeWidth = 2.dp)
            } else {
                TargetGroup("Markets", state.symbols, state.selectedTarget, viewModel::onSelectTarget)
                TargetGroup("Creator tokens", state.tokens, state.selectedTarget, viewModel::onSelectTarget)
                TargetGroup("Strategies", state.strategies, state.selectedTarget, viewModel::onSelectTarget)
                if (state.symbols.isEmpty() && state.tokens.isEmpty() && state.strategies.isEmpty()) {
                    Text(
                        "No investable targets are available right now.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.testTag("dca_no_targets"),
                    )
                }
            }
            state.selectedTarget?.let {
                Spacer(Modifier.height(4.dp))
                Text("Selected: ${it.label}", style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Bold, modifier = Modifier.testTag("dca_selected_target"))
            }

            Spacer(Modifier.height(16.dp))
            Divider()
            Spacer(Modifier.height(16.dp))

            // ---- Amount ----
            Text("Amount per buy", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = state.amountText,
                onValueChange = viewModel::onAmountText,
                label = { Text("Amount (USD)") },
                prefix = { Text("$") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
                supportingText = { Text("Minimum ${DcaFormat.formatCentsUsd(DcaFormat.MIN_AMOUNT_CENTS)}.") },
                modifier = Modifier.fillMaxWidth().testTag("dca_amount"),
            )

            Spacer(Modifier.height(16.dp))

            // ---- Frequency ----
            Text("How often", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FrequencyChip("Daily", state.frequency == DcaFrequency.DAILY) { viewModel.onFrequency(DcaFrequency.DAILY) }
                FrequencyChip("Weekly", state.frequency == DcaFrequency.WEEKLY) { viewModel.onFrequency(DcaFrequency.WEEKLY) }
                FrequencyChip("Monthly", state.frequency == DcaFrequency.MONTHLY) { viewModel.onFrequency(DcaFrequency.MONTHLY) }
            }

            if (state.frequency == DcaFrequency.WEEKLY) {
                Spacer(Modifier.height(8.dp))
                Text("Day of week", style = MaterialTheme.typography.labelLarge)
                FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    (1..7).forEach { d ->
                        FilterChip(
                            selected = state.dayOfWeek == d,
                            onClick = { viewModel.onDayOfWeek(d) },
                            label = { Text(DcaFormat.dayOfWeekLabel(d).take(3)) },
                            modifier = Modifier.testTag("dca_dow_$d"),
                        )
                    }
                }
            }
            if (state.frequency == DcaFrequency.MONTHLY) {
                Spacer(Modifier.height(8.dp))
                Text("Day of month (1–28)", style = MaterialTheme.typography.labelLarge)
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = { viewModel.onDayOfMonth(state.dayOfMonth - 1) }, enabled = state.dayOfMonth > 1) { Text("−") }
                    Text("${state.dayOfMonth}", style = MaterialTheme.typography.titleMedium, modifier = Modifier.testTag("dca_dom_value"))
                    OutlinedButton(onClick = { viewModel.onDayOfMonth(state.dayOfMonth + 1) }, enabled = state.dayOfMonth < 28) { Text("+") }
                }
                Text("Days after the 28th are capped at the 28th so no month is skipped.", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }

            Spacer(Modifier.height(16.dp))

            // ---- Start / End ----
            Text("Start", style = MaterialTheme.typography.titleMedium)
            OutlinedButton(onClick = { showStartPicker = true }, modifier = Modifier.testTag("dca_start_btn")) {
                Text("Starts ${DcaFormat.formatDate(state.startTs)}")
            }

            Spacer(Modifier.height(8.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Switch(checked = state.endEnabled, onCheckedChange = viewModel::onEndEnabled, modifier = Modifier.testTag("dca_end_switch"))
                Spacer(Modifier.height(0.dp))
                Text("  Set an end date", style = MaterialTheme.typography.bodyMedium)
            }
            if (state.endEnabled) {
                OutlinedButton(onClick = { showEndPicker = true }) {
                    Text("Ends ${DcaFormat.formatDate(state.endTs ?: 0L)}")
                }
            }

            Spacer(Modifier.height(8.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Switch(checked = state.budgetEnabled, onCheckedChange = viewModel::onBudgetEnabled, modifier = Modifier.testTag("dca_budget_switch"))
                Text("  Cap total budget", style = MaterialTheme.typography.bodyMedium)
            }
            if (state.budgetEnabled) {
                OutlinedTextField(
                    value = state.budgetText,
                    onValueChange = viewModel::onBudgetText,
                    label = { Text("Total budget (USD)") },
                    prefix = { Text("$") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
                    modifier = Modifier.fillMaxWidth().testTag("dca_budget_amount"),
                )
            }

            Spacer(Modifier.height(16.dp))
            Divider()
            Spacer(Modifier.height(12.dp))

            // ---- Funding ----
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.padding(14.dp)) {
                    Text("Funded from your USD cash balance", style = MaterialTheme.typography.titleSmall)
                    if (state.walletAvailable) {
                        Text("Balance ${DcaFormat.formatCentsUsd(state.walletBalanceCents)}", style = MaterialTheme.typography.bodyMedium)
                    } else {
                        Text("Cash balance unavailable on this account.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    TextButton(onClick = onAddCash, modifier = Modifier.testTag("dca_add_cash")) { Text("Add cash") }
                }
            }

            (state.validation as? DcaSchedule.Validation.Invalid)?.let {
                Spacer(Modifier.height(8.dp))
                Text(it.reason, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall, modifier = Modifier.testTag("dca_validation"))
            }
            state.errorMessage?.let {
                Spacer(Modifier.height(8.dp))
                Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.testTag("dca_create_error"))
            }

            Spacer(Modifier.height(16.dp))
            Button(
                onClick = { showConfirm = true },
                enabled = state.canPreview && !state.submitting,
                modifier = Modifier.fillMaxWidth().testTag("dca_review_btn"),
            ) {
                if (state.submitting) CircularProgressIndicator(modifier = Modifier.height(18.dp), strokeWidth = 2.dp)
                else Text("Review & schedule")
            }
            Spacer(Modifier.height(24.dp))
        }
    }

    // ---- schedule preview + money-safety confirm ----
    if (showConfirm) {
        val preview = state.toPreviewPlan()
        val runs = preview?.let { DcaSchedule.upcomingRuns(it, it.startTs, 5) }.orEmpty()
        AlertDialog(
            onDismissRequest = { showConfirm = false },
            title = { Text("Confirm recurring buy") },
            text = {
                Column {
                    ConfirmRow("Buy", state.selectedTarget?.label ?: "—", emphasize = true)
                    ConfirmRow("Amount", DcaFormat.formatCentsUsd(state.amountCents ?: 0L))
                    ConfirmRow("Cadence", DcaFormat.frequencyLabel(state.frequency, state.dayOfWeek, state.dayOfMonth))
                    ConfirmRow("Funding", "USD cash balance")
                    if (state.budgetEnabled) ConfirmRow("Total budget", DcaFormat.formatCentsUsd(state.budgetCents ?: 0L))
                    Spacer(Modifier.height(8.dp))
                    Text("Next runs", style = MaterialTheme.typography.labelLarge)
                    if (runs.isEmpty()) {
                        Text("No upcoming runs for these settings.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                    } else {
                        runs.forEachIndexed { i, ms ->
                            Text("${i + 1}. ${DcaFormat.formatDateWithDow(ms)}", style = MaterialTheme.typography.bodySmall, modifier = Modifier.testTag("dca_preview_$i"))
                        }
                    }
                    Spacer(Modifier.height(8.dp))
                    Text(
                        "Scheduling this creates a plan that runs automatically on the server. Each run charges your USD cash balance for the buy amount.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = { showConfirm = false; viewModel.confirmCreate() },
                    enabled = runs.isNotEmpty(),
                    modifier = Modifier.testTag("dca_confirm_btn"),
                ) { Text("Schedule") }
            },
            dismissButton = { TextButton(onClick = { showConfirm = false }) { Text("Cancel") } },
        )
    }

    if (showStartPicker) {
        val pickerState = rememberDatePickerState(initialSelectedDateMillis = state.startTs.takeIf { it > 0 })
        DatePickerDialog(
            onDismissRequest = { showStartPicker = false },
            confirmButton = {
                TextButton(onClick = {
                    pickerState.selectedDateMillis?.let(viewModel::onStartTs)
                    showStartPicker = false
                }) { Text("OK") }
            },
            dismissButton = { TextButton(onClick = { showStartPicker = false }) { Text("Cancel") } },
        ) { DatePicker(state = pickerState) }
    }

    if (showEndPicker) {
        val pickerState = rememberDatePickerState(initialSelectedDateMillis = state.endTs)
        DatePickerDialog(
            onDismissRequest = { showEndPicker = false },
            confirmButton = {
                TextButton(onClick = {
                    pickerState.selectedDateMillis?.let(viewModel::onEndTs)
                    showEndPicker = false
                }) { Text("OK") }
            },
            dismissButton = { TextButton(onClick = { showEndPicker = false }) { Text("Cancel") } },
        ) { DatePicker(state = pickerState) }
    }
}

@Composable
private fun TargetGroup(
    title: String,
    options: List<DcaTargetOption>,
    selected: DcaTargetOption?,
    onSelect: (DcaTargetOption) -> Unit,
) {
    if (options.isEmpty()) return
    Text(title, style = MaterialTheme.typography.labelLarge, modifier = Modifier.padding(top = 8.dp))
    FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        options.take(30).forEach { opt ->
            FilterChip(
                selected = selected?.kind == opt.kind && selected.id == opt.id,
                onClick = { onSelect(opt) },
                label = { Text(opt.label) },
                modifier = Modifier.testTag("dca_target_${opt.kind.wire}_${opt.id}"),
            )
        }
    }
}

@Composable
private fun FrequencyChip(label: String, selected: Boolean, onClick: () -> Unit) {
    FilterChip(selected = selected, onClick = onClick, label = { Text(label) }, modifier = Modifier.testTag("dca_freq_$label"))
}

@Composable
private fun ConfirmRow(label: String, value: String, emphasize: Boolean = false) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(label, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.bodyMedium, fontWeight = if (emphasize) FontWeight.Bold else FontWeight.Normal)
    }
}
