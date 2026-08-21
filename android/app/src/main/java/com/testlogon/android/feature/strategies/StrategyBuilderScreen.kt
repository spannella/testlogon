@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class, androidx.compose.foundation.layout.ExperimentalLayoutApi::class)

package com.testlogon.android.feature.strategies

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
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
import com.testlogon.android.data.strategies.RebalanceRule
import com.testlogon.android.data.strategies.RedemptionType
import com.testlogon.android.data.strategies.StrategyKind

/**
 * The STRATEGY BUILDER form. Define name/description/kind, a basket leg editor (add symbols + set
 * weights with a live 100% check), the rebalance cadence, and the fund params (min investment, max
 * AUM, management + performance fee with a high-water-mark toggle, redemption policy). "Save draft"
 * persists a draft; "Publish" is gated behind a money-safety confirm and only enabled for a valid
 * 100% basket.
 */
@Composable
fun StrategyBuilderRoute(
    onBack: () -> Unit,
    onSaved: (strategyId: String) -> Unit,
    viewModel: StrategyBuilderViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    var showPublishConfirm by remember { mutableStateOf(false) }

    LaunchedEffect(state.savedStrategyId) {
        state.savedStrategyId?.let { id ->
            viewModel.consumeSaved()
            onSaved(id)
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(if (state.editingId != null) "Edit strategy" else "Create strategy") },
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
            Text(
                "Define a basket following a simple rule set. Others can paper-trade and backtest it, then invest at NAV.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(16.dp))

            OutlinedTextField(
                value = state.name,
                onValueChange = viewModel::onName,
                label = { Text("Strategy name") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth().testTag("builder_name"),
            )
            Spacer(Modifier.height(12.dp))
            OutlinedTextField(
                value = state.description,
                onValueChange = viewModel::onDescription,
                label = { Text("Description") },
                modifier = Modifier.fillMaxWidth().testTag("builder_desc"),
            )
            Spacer(Modifier.height(12.dp))

            SectionLabel("Kind")
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                StrategyKind.entries.filter { it != StrategyKind.UNKNOWN }.forEach { k ->
                    FilterChip(
                        selected = state.kind == k,
                        onClick = { viewModel.onKind(k) },
                        label = { Text(k.label()) },
                    )
                }
            }

            Spacer(Modifier.height(16.dp))
            LegEditor(state = state, viewModel = viewModel)

            Spacer(Modifier.height(16.dp))
            SectionLabel("Rebalance cadence")
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                RebalanceRule.entries.filter { it != RebalanceRule.UNKNOWN }.forEach { r ->
                    FilterChip(
                        selected = state.rebalance == r,
                        onClick = { viewModel.onRebalance(r) },
                        label = { Text(r.label()) },
                    )
                }
            }
            if (state.rebalance == RebalanceRule.THRESHOLD) {
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = state.thresholdPctText,
                    onValueChange = viewModel::onThreshold,
                    label = { Text("Drift threshold %") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
                    modifier = Modifier.fillMaxWidth().testTag("builder_threshold"),
                )
            }

            Spacer(Modifier.height(16.dp))
            SectionLabel("Fund parameters")
            OutlinedTextField(
                value = state.minInvestmentText,
                onValueChange = viewModel::onMinInvestment,
                label = { Text("Min investment ($)") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
                modifier = Modifier.fillMaxWidth().testTag("builder_min"),
            )
            Spacer(Modifier.height(12.dp))
            OutlinedTextField(
                value = state.maxAumText,
                onValueChange = viewModel::onMaxAum,
                label = { Text("Max total AUM / capacity ($)") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
                modifier = Modifier.fillMaxWidth().testTag("builder_maxaum"),
            )
            Spacer(Modifier.height(12.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedTextField(
                    value = state.mgmtFeePctText,
                    onValueChange = viewModel::onMgmtFee,
                    label = { Text("Mgmt fee % (AUM/yr)") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
                    modifier = Modifier.weight(1f).testTag("builder_mgmtfee"),
                )
                OutlinedTextField(
                    value = state.perfFeePctText,
                    onValueChange = viewModel::onPerfFee,
                    label = { Text("Perf fee % (profit)") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
                    modifier = Modifier.weight(1f).testTag("builder_perffee"),
                )
            }
            Spacer(Modifier.height(8.dp))
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("High-water mark", style = MaterialTheme.typography.bodyLarge)
                    Text(
                        "Performance fee only on new profit above the prior peak NAV.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Switch(checked = state.highWaterMark, onCheckedChange = viewModel::onHighWaterMark, modifier = Modifier.testTag("builder_hwm"))
            }

            Spacer(Modifier.height(16.dp))
            SectionLabel("Redemption / profit-taking policy")
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                RedemptionType.entries.filter { it != RedemptionType.UNKNOWN }.forEach { t ->
                    FilterChip(
                        selected = state.redemptionType == t,
                        onClick = { viewModel.onRedemptionType(t) },
                        label = { Text(t.label()) },
                    )
                }
            }
            if (state.redemptionType == RedemptionType.NOTICE) {
                Spacer(Modifier.height(8.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    OutlinedTextField(
                        value = state.noticeDaysText,
                        onValueChange = viewModel::onNoticeDays,
                        label = { Text("Notice days") },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        modifier = Modifier.weight(1f),
                    )
                    OutlinedTextField(
                        value = state.lockupDaysText,
                        onValueChange = viewModel::onLockupDays,
                        label = { Text("Lockup days") },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        modifier = Modifier.weight(1f),
                    )
                }
            }

            state.errorMessage?.let {
                Spacer(Modifier.height(12.dp))
                Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.testTag("builder_error"))
            }

            Spacer(Modifier.height(20.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.fillMaxWidth()) {
                OutlinedButton(
                    onClick = { viewModel.save(thenPublish = false) },
                    enabled = state.canSave,
                    modifier = Modifier.weight(1f).testTag("builder_save_draft"),
                ) { Text("Save draft") }
                Button(
                    onClick = { showPublishConfirm = true },
                    enabled = state.canSave,
                    modifier = Modifier.weight(1f).testTag("builder_publish"),
                ) {
                    if (state.submitting) CircularProgressIndicator(modifier = Modifier.height(18.dp), strokeWidth = 2.dp)
                    else Text("Publish")
                }
            }
            Spacer(Modifier.height(24.dp))
        }
    }

    if (showPublishConfirm) {
        AlertDialog(
            onDismissRequest = { showPublishConfirm = false },
            title = { Text("Confirm publish") },
            text = {
                Column {
                    StrategyKeyValueRow("Action", "Publish investable strategy")
                    StrategyKeyValueRow("Name", state.name)
                    StrategyKeyValueRow("Legs", "${state.legs.size}")
                    StrategyKeyValueRow("Min investment", "$" + state.minInvestmentText.ifBlank { "0" })
                    StrategyKeyValueRow("Max AUM", "$" + state.maxAumText.ifBlank { "0" })
                    StrategyKeyValueRow("Mgmt fee", state.mgmtFeePctText + "% / yr")
                    StrategyKeyValueRow("Perf fee", state.perfFeePctText + "%", emphasize = true)
                    Spacer(Modifier.height(6.dp))
                    Text(
                        "Publishing makes this a live, investable POOLED fund. Others can subscribe real capital at NAV. You are responsible for its management.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        showPublishConfirm = false
                        viewModel.save(thenPublish = true)
                    },
                    modifier = Modifier.testTag("builder_publish_confirm"),
                ) { Text("Publish now") }
            },
            dismissButton = { TextButton(onClick = { showPublishConfirm = false }) { Text("Cancel") } },
        )
    }
}

@Composable
private fun LegEditor(state: StrategyBuilderUiState, viewModel: StrategyBuilderViewModel) {
    SectionLabel("Basket legs")
    val chosen = state.legs.map { it.symbolId }.toSet()
    val addable = state.availableSymbols.filter { it.symbolId !in chosen }
    if (addable.isNotEmpty()) {
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            addable.forEach { inst ->
                AssistChip(
                    onClick = { viewModel.addLeg(inst.symbolId) },
                    label = { Text("+ ${inst.symbol}") },
                    modifier = Modifier.testTag("builder_addleg_${inst.symbolId}"),
                )
            }
        }
        Spacer(Modifier.height(8.dp))
    }
    if (state.legs.isEmpty()) {
        Text(
            "Add at least one symbol and set target weights that total 100%.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    } else {
        state.legs.forEach { leg ->
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
                Text(symbolName(leg.symbolId), style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Medium, modifier = Modifier.width(96.dp))
                OutlinedTextField(
                    value = leg.weightPctText,
                    onValueChange = { viewModel.onLegWeight(leg.symbolId, it) },
                    label = { Text("Weight %") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
                    modifier = Modifier.weight(1f).testTag("builder_legweight_${leg.symbolId}"),
                )
                IconButton(onClick = { viewModel.removeLeg(leg.symbolId) }) {
                    Icon(Icons.Filled.Close, contentDescription = "Remove leg")
                }
            }
        }
        Spacer(Modifier.height(4.dp))
        val total = state.totalWeightBps
        val valid = state.weightsValid
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
            Text(
                "Total weight: ${StrategyMath.formatBps(total)}" + if (valid) " ✓" else " (must be 100%)",
                color = if (valid) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.weight(1f).testTag("builder_weight_total"),
            )
            TextButton(onClick = { viewModel.equalizeWeights() }) { Text("Equalize") }
        }
    }
}

@Composable
private fun SectionLabel(text: String) {
    Text(text, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold, modifier = Modifier.padding(bottom = 6.dp))
}
