@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.testlogon.android.feature.workflow

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle

/** WFL — stable testTags for the workflow-rules admin surface. */
object WorkflowRulesTestTags {
    const val SCREEN = "workflow_rules_screen"
    const val RETRY = "workflow_rules_retry"
    const val FAB_CREATE = "workflow_rules_fab_create"
    const val DRIP_ENTRY = "workflow_rules_drip_entry"
    const val CREATE_SUBMIT = "workflow_rule_create_submit"

    fun row(ruleId: String): String = "workflow_rule_row_$ruleId"
    fun toggle(ruleId: String): String = "workflow_rule_toggle_$ruleId"
    fun runs(ruleId: String): String = "workflow_rule_runs_$ruleId"
    fun delete(ruleId: String): String = "workflow_rule_delete_$ruleId"
}

@Composable
fun WorkflowRulesRoute(
    onBack: () -> Unit,
    onOpenRuns: (String) -> Unit,
    onOpenDrip: () -> Unit,
    viewModel: WorkflowRulesViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    WorkflowRulesScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::load,
        onToggle = viewModel::toggleEnabled,
        onDelete = viewModel::delete,
        onOpenRuns = onOpenRuns,
        onOpenDrip = onOpenDrip,
        onCreate = viewModel::createRule,
        onMessageShown = viewModel::consumeMessage,
    )
}

@Composable
fun WorkflowRulesScreen(
    state: WorkflowRulesUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onToggle: (WorkflowRule) -> Unit,
    onDelete: (String) -> Unit,
    onOpenRuns: (String) -> Unit,
    onOpenDrip: () -> Unit,
    onCreate: (String, String, WorkflowTargetModule, WorkflowTriggerType, Boolean, () -> Unit) -> Unit,
    onMessageShown: () -> Unit,
) {
    val snackbar = remember { SnackbarHostState() }
    var showCreate by rememberSaveable { mutableStateOf(false) }

    val message = (state as? WorkflowRulesUiState.Content)?.message
    LaunchedEffect(message) {
        if (message != null) {
            snackbar.showSnackbar(message)
            onMessageShown()
        }
    }

    Scaffold(
        modifier = Modifier.testTag(WorkflowRulesTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text("Workflow rules") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    TextButton(
                        onClick = onOpenDrip,
                        modifier = Modifier.testTag(WorkflowRulesTestTags.DRIP_ENTRY),
                    ) { Text("Drip") }
                },
            )
        },
        floatingActionButton = {
            if (state is WorkflowRulesUiState.Content || state is WorkflowRulesUiState.Empty) {
                FloatingActionButton(
                    onClick = { showCreate = true },
                    modifier = Modifier.testTag(WorkflowRulesTestTags.FAB_CREATE),
                ) { Icon(Icons.Filled.Add, contentDescription = "New rule") }
            }
        },
    ) { padding ->
        Box(Modifier.padding(padding).fillMaxSize()) {
            when (state) {
                is WorkflowRulesUiState.Loading ->
                    CircularProgressIndicator(Modifier.align(Alignment.Center))

                is WorkflowRulesUiState.Unavailable ->
                    Text(
                        "Workflow automation isn't enabled for this account.",
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.align(Alignment.Center).padding(24.dp),
                    )

                is WorkflowRulesUiState.Empty ->
                    Text(
                        "No workflow rules configured. Tap + to create one.",
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.align(Alignment.Center).padding(24.dp),
                    )

                is WorkflowRulesUiState.Error -> Column(
                    modifier = Modifier.align(Alignment.Center),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text(state.error.message, style = MaterialTheme.typography.bodyMedium)
                    Button(onClick = onRetry, modifier = Modifier.testTag(WorkflowRulesTestTags.RETRY)) {
                        Text("Retry")
                    }
                }

                is WorkflowRulesUiState.Content -> PullToRefreshBox(
                    isRefreshing = state.isRefreshing,
                    onRefresh = onRefresh,
                ) {
                    LazyColumn(
                        modifier = Modifier.fillMaxSize().padding(horizontal = 16.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        item(key = "header") {
                            Text(
                                text = "${state.rules.size} rules • ${state.enabledCount} enabled",
                                style = MaterialTheme.typography.titleSmall,
                                modifier = Modifier.padding(top = 12.dp, bottom = 4.dp),
                            )
                        }
                        items(state.rules, key = { it.ruleId }) { rule ->
                            RuleRow(
                                rule = rule,
                                busy = state.busyRuleId == rule.ruleId,
                                onToggle = { onToggle(rule) },
                                onRuns = { onOpenRuns(rule.ruleId) },
                                onDelete = { onDelete(rule.ruleId) },
                            )
                        }
                    }
                }
            }
        }
    }

    if (showCreate) {
        CreateRuleDialog(
            onDismiss = { showCreate = false },
            onSubmit = { name, desc, module, trigger, enabled ->
                onCreate(name, desc, module, trigger, enabled) { showCreate = false }
            },
        )
    }
}

@Composable
private fun RuleRow(
    rule: WorkflowRule,
    busy: Boolean,
    onToggle: () -> Unit,
    onRuns: () -> Unit,
    onDelete: () -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth().testTag(WorkflowRulesTestTags.row(rule.ruleId)),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(rule.name, style = MaterialTheme.typography.titleMedium)
            rule.description.takeIf { it.isNotBlank() }?.let {
                Text(it, style = MaterialTheme.typography.bodyMedium)
            }
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                AssistChip(onClick = {}, label = { Text(if (rule.enabled) "Enabled" else "Disabled") })
                AssistChip(onClick = {}, label = { Text(moduleLabel(rule.targetModule)) })
                AssistChip(onClick = {}, label = { Text(triggerLabel(rule.triggerType)) })
            }
            Text(
                "${rule.conditionCount} conditions • ${rule.actionCount} actions",
                style = MaterialTheme.typography.bodySmall,
            )
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(
                    onClick = onToggle,
                    enabled = !busy,
                    modifier = Modifier.testTag(WorkflowRulesTestTags.toggle(rule.ruleId)),
                ) { Text(WorkflowRuleMath.toggleLabel(rule.enabled)) }
                OutlinedButton(
                    onClick = onRuns,
                    enabled = !busy,
                    modifier = Modifier.testTag(WorkflowRulesTestTags.runs(rule.ruleId)),
                ) { Text("Runs") }
                TextButton(
                    onClick = onDelete,
                    enabled = !busy,
                    modifier = Modifier.testTag(WorkflowRulesTestTags.delete(rule.ruleId)),
                ) { Text("Delete") }
            }
        }
    }
}

@Composable
private fun CreateRuleDialog(
    onDismiss: () -> Unit,
    onSubmit: (String, String, WorkflowTargetModule, WorkflowTriggerType, Boolean) -> Unit,
) {
    var name by rememberSaveable { mutableStateOf("") }
    var description by rememberSaveable { mutableStateOf("") }
    var module by remember { mutableStateOf(WorkflowTargetModule.TICKET) }
    var trigger by remember { mutableStateOf(WorkflowTriggerType.ON_SAVE) }
    var enabled by rememberSaveable { mutableStateOf(false) }

    val canSubmit = WorkflowRuleMath.canSubmitCreate(name, module, trigger)

    androidx.compose.material3.AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = {
            Button(
                onClick = { onSubmit(name, description, module, trigger, enabled) },
                enabled = canSubmit,
                modifier = Modifier.testTag(WorkflowRulesTestTags.CREATE_SUBMIT),
            ) { Text("Create") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
        title = { Text("New workflow rule") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("Name") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = description,
                    onValueChange = { description = it },
                    label = { Text("Description") },
                    modifier = Modifier.fillMaxWidth(),
                )
                EnumDropdown(
                    label = "Target module",
                    options = WorkflowRuleMath.TARGET_MODULES,
                    selected = module,
                    optionLabel = ::moduleLabel,
                    onSelect = { module = it },
                )
                EnumDropdown(
                    label = "Trigger",
                    options = WorkflowRuleMath.TRIGGER_TYPES,
                    selected = trigger,
                    optionLabel = ::triggerLabel,
                    onSelect = { trigger = it },
                )
                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalArrangement = Arrangement.Center,
                ) {
                    Text("Enabled", style = MaterialTheme.typography.bodyMedium)
                    Switch(checked = enabled, onCheckedChange = { enabled = it })
                }
            }
        },
    )
}

@Composable
private fun <T> EnumDropdown(
    label: String,
    options: List<T>,
    selected: T,
    optionLabel: (T) -> String,
    onSelect: (T) -> Unit,
) {
    var expanded by remember { mutableStateOf(false) }
    ExposedDropdownMenuBox(expanded = expanded, onExpandedChange = { expanded = it }) {
        OutlinedTextField(
            value = optionLabel(selected),
            onValueChange = {},
            readOnly = true,
            label = { Text(label) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier.fillMaxWidth().menuAnchor(),
        )
        ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            options.forEach { option ->
                DropdownMenuItem(
                    text = { Text(optionLabel(option)) },
                    onClick = {
                        onSelect(option)
                        expanded = false
                    },
                )
            }
        }
    }
}

internal fun moduleLabel(m: WorkflowTargetModule): String = when (m) {
    WorkflowTargetModule.TICKET -> "Ticket"
    WorkflowTargetModule.CONTACT -> "Contact"
    WorkflowTargetModule.ORDER -> "Order"
    WorkflowTargetModule.SUBSCRIPTION -> "Subscription"
    WorkflowTargetModule.LEAD -> "Lead"
    WorkflowTargetModule.UNKNOWN -> "—"
}

internal fun triggerLabel(t: WorkflowTriggerType): String = when (t) {
    WorkflowTriggerType.ON_SAVE -> "On save"
    WorkflowTriggerType.ON_SCHEDULE -> "On schedule"
    WorkflowTriggerType.ON_TIME_ELAPSED -> "On time elapsed"
    WorkflowTriggerType.UNKNOWN -> "—"
}
