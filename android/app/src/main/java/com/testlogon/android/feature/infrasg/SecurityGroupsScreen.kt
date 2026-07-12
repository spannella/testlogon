@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.infrasg

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.AddCircleOutline
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.material3.rememberModalBottomSheetState
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
import com.testlogon.android.data.infrasg.SecurityGroupDto
import com.testlogon.android.data.infrasg.SecurityRuleDto
import com.testlogon.android.data.infrasg.SecurityRuleReq
import com.testlogon.android.feature.infracommon.infraErrorMessage

object SecurityGroupsTestTags {
    const val SCREEN = "sg_screen"
    const val LIST = "sg_list"
    const val EMPTY = "sg_empty"
    const val FORBIDDEN = "sg_forbidden"
    const val ERROR_RETRY = "sg_error_retry"
    const val CREATE_OPEN = "sg_create_open"
    const val CREATE_NAME = "sg_create_name"
    const val CREATE_CONFIRM = "sg_create_confirm"
    const val DETAIL_SHEET = "sg_detail_sheet"
    const val ADD_RULE = "sg_add_rule"
    const val RULE_CONFIRM = "sg_rule_confirm"
    const val RULE_PORT_FROM = "sg_rule_port_from"
    const val RULE_SOURCE = "sg_rule_source"
    const val DELETE_GROUP = "sg_delete_group"
    fun row(id: String) = "sg_row_$id"
    fun ruleRow(id: String) = "sg_rule_$id"
    fun ruleEdit(id: String) = "sg_rule_edit_$id"
    fun ruleRemove(id: String) = "sg_rule_remove_$id"
}

private val PROTOCOLS = listOf("tcp", "udp", "icmp", "all")
private val DIRECTIONS = listOf("inbound", "outbound")

@Composable
fun SecurityGroupsRoute(
    onBack: () -> Unit,
    viewModel: SecurityGroupsViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    SecurityGroupsScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
        onSelect = viewModel::select,
        onCreate = viewModel::createGroup,
        onDeleteGroup = viewModel::deleteGroup,
        onAddRule = viewModel::addRule,
        onUpdateRule = viewModel::updateRule,
        onRemoveRule = viewModel::removeRule,
        onMessageShown = viewModel::clearMessage,
    )
}

@Composable
fun SecurityGroupsScreen(
    state: SgUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onSelect: (String?) -> Unit,
    onCreate: (String, String) -> Unit,
    onDeleteGroup: (String) -> Unit,
    onAddRule: (String, SecurityRuleReq) -> Unit,
    onUpdateRule: (String, String, SecurityRuleReq) -> Unit,
    onRemoveRule: (String, String) -> Unit,
    onMessageShown: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbar = remember { SnackbarHostState() }
    var showCreate by remember { mutableStateOf(false) }
    var ruleEditor by remember { mutableStateOf<SecurityRuleDto?>(null) }
    var showAddRule by remember { mutableStateOf(false) }

    LaunchedEffect(state.message, state.transientError) {
        val msg = state.message ?: state.transientError?.let { infraErrorMessage(it) }
        if (msg != null) {
            snackbar.showSnackbar(msg)
            onMessageShown()
        }
    }

    Scaffold(
        modifier = modifier.testTag(SecurityGroupsTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text("Security groups") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(
                        onClick = { showCreate = true },
                        enabled = state.data !is SgDataState.Forbidden,
                        modifier = Modifier.testTag(SecurityGroupsTestTags.CREATE_OPEN),
                    ) {
                        Icon(Icons.Outlined.AddCircleOutline, contentDescription = "Create group")
                    }
                },
            )
        },
    ) { padding ->
        val isRefreshing = (state.data as? SgDataState.Content)?.isRefreshing == true
        PullToRefreshBox(
            isRefreshing = isRefreshing,
            onRefresh = onRefresh,
            modifier = Modifier.fillMaxSize().padding(padding),
        ) {
            when (val d = state.data) {
                is SgDataState.Loading -> LoadingState()
                is SgDataState.Empty -> EmptyState(
                    modifier = Modifier.testTag(SecurityGroupsTestTags.EMPTY),
                    title = "No security groups",
                    body = "Create a security group to control instance traffic.",
                    imageVector = Icons.Outlined.Shield,
                    actionLabel = "Create",
                    onAction = { showCreate = true },
                )
                is SgDataState.Forbidden -> EmptyState(
                    modifier = Modifier.testTag(SecurityGroupsTestTags.FORBIDDEN),
                    title = "Not authorised",
                    body = "You do not have access to security groups.",
                    imageVector = Icons.Outlined.Lock,
                    actionLabel = "Back",
                    onAction = onBack,
                )
                is SgDataState.Error -> ErrorState(
                    modifier = Modifier.testTag(SecurityGroupsTestTags.ERROR_RETRY),
                    message = infraErrorMessage(d.type),
                    onRetry = onRetry,
                )
                is SgDataState.Content -> LazyColumn(
                    modifier = Modifier.fillMaxSize().testTag(SecurityGroupsTestTags.LIST),
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    items(items = d.groups, key = { it.sgId }) { g ->
                        SgRow(group = g, onClick = { onSelect(g.sgId) })
                    }
                }
            }
        }
    }

    val selected = state.selected
    if (selected != null) {
        val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
        ModalBottomSheet(
            onDismissRequest = { onSelect(null) },
            sheetState = sheetState,
            modifier = Modifier.testTag(SecurityGroupsTestTags.DETAIL_SHEET),
        ) {
            SgDetail(
                group = selected,
                busy = state.busy,
                onAddRule = { showAddRule = true },
                onEditRule = { ruleEditor = it },
                onRemoveRule = { onRemoveRule(selected.sgId, it) },
                onDeleteGroup = { onDeleteGroup(selected.sgId) },
            )
        }
    }

    if (showCreate) {
        CreateGroupDialog(
            busy = state.busy,
            onDismiss = { showCreate = false },
            onConfirm = { name, desc ->
                onCreate(name, desc)
                showCreate = false
            },
        )
    }

    if (showAddRule && selected != null) {
        RuleEditorDialog(
            existing = null,
            busy = state.busy,
            onDismiss = { showAddRule = false },
            onConfirm = { req ->
                onAddRule(selected.sgId, req)
                showAddRule = false
            },
        )
    }

    ruleEditor?.let { rule ->
        if (selected != null) {
            RuleEditorDialog(
                existing = rule,
                busy = state.busy,
                onDismiss = { ruleEditor = null },
                onConfirm = { req ->
                    onUpdateRule(selected.sgId, rule.ruleId, req)
                    ruleEditor = null
                },
            )
        }
    }
}

@Composable
private fun SgRow(group: SecurityGroupDto, onClick: () -> Unit) {
    Card(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth().testTag(SecurityGroupsTestTags.row(group.sgId)),
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(
                    group.name.ifBlank { group.sgId },
                    style = MaterialTheme.typography.titleSmall,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                if (group.isDefault) {
                    Text("default", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.primary)
                }
            }
            if (group.description.isNotBlank()) {
                Text(group.description, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 2, overflow = TextOverflow.Ellipsis)
            }
            Text(
                "${group.rules.size} rules · ${group.associatedInstances.size} instances",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun SgDetail(
    group: SecurityGroupDto,
    busy: Boolean,
    onAddRule: () -> Unit,
    onEditRule: (SecurityRuleDto) -> Unit,
    onRemoveRule: (String) -> Unit,
    onDeleteGroup: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp)
            .padding(bottom = 24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(group.name.ifBlank { group.sgId }, style = MaterialTheme.typography.titleLarge)
        if (group.description.isNotBlank()) {
            Text(group.description, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
            Text("Rules (${group.rules.size})", style = MaterialTheme.typography.titleSmall)
            OutlinedButton(
                onClick = onAddRule,
                enabled = !busy,
                modifier = Modifier.testTag(SecurityGroupsTestTags.ADD_RULE),
            ) { Text("Add rule") }
        }
        Column(
            modifier = Modifier.heightIn(max = 320.dp).verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            if (group.rules.isEmpty()) {
                Text("No rules.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            group.rules.forEach { rule ->
                RuleRow(rule = rule, busy = busy, onEdit = { onEditRule(rule) }, onRemove = { onRemoveRule(rule.ruleId) })
            }
        }
        if (!group.isDefault) {
            OutlinedButton(
                onClick = onDeleteGroup,
                enabled = !busy,
                modifier = Modifier.fillMaxWidth().testTag(SecurityGroupsTestTags.DELETE_GROUP),
            ) { Text("Delete group") }
        }
    }
}

@Composable
private fun RuleRow(rule: SecurityRuleDto, busy: Boolean, onEdit: () -> Unit, onRemove: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth().testTag(SecurityGroupsTestTags.ruleRow(rule.ruleId))) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(
                "${rule.direction} · ${rule.protocol} ${portLabel(rule)}",
                style = MaterialTheme.typography.labelLarge,
            )
            Text("Source: ${rule.source}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            if (rule.description.isNotBlank()) {
                Text(rule.description, style = MaterialTheme.typography.bodySmall)
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(onClick = onEdit, enabled = !busy, modifier = Modifier.testTag(SecurityGroupsTestTags.ruleEdit(rule.ruleId))) { Text("Edit") }
                TextButton(onClick = onRemove, enabled = !busy, modifier = Modifier.testTag(SecurityGroupsTestTags.ruleRemove(rule.ruleId))) { Text("Remove") }
            }
        }
    }
}

private fun portLabel(rule: SecurityRuleDto): String =
    if (rule.protocol == "icmp" || rule.protocol == "all") ""
    else if (rule.portFrom == rule.portTo) "${rule.portFrom}"
    else "${rule.portFrom}-${rule.portTo}"

@Composable
private fun CreateGroupDialog(busy: Boolean, onDismiss: () -> Unit, onConfirm: (String, String) -> Unit) {
    var name by remember { mutableStateOf("") }
    var desc by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Create security group") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("Name") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag(SecurityGroupsTestTags.CREATE_NAME),
                )
                OutlinedTextField(
                    value = desc,
                    onValueChange = { desc = it },
                    label = { Text("Description (optional)") },
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = { if (name.isNotBlank()) onConfirm(name, desc) },
                enabled = !busy && name.isNotBlank(),
                modifier = Modifier.testTag(SecurityGroupsTestTags.CREATE_CONFIRM),
            ) { Text("Create") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun RuleEditorDialog(
    existing: SecurityRuleDto?,
    busy: Boolean,
    onDismiss: () -> Unit,
    onConfirm: (SecurityRuleReq) -> Unit,
) {
    var protocol by remember { mutableStateOf(existing?.protocol?.takeIf { it in PROTOCOLS } ?: "tcp") }
    var direction by remember { mutableStateOf(existing?.direction?.takeIf { it in DIRECTIONS } ?: "inbound") }
    var portFrom by remember { mutableStateOf(existing?.portFrom?.takeIf { it > 0 }?.toString() ?: "") }
    var portTo by remember { mutableStateOf(existing?.portTo?.takeIf { it > 0 }?.toString() ?: "") }
    var source by remember { mutableStateOf(existing?.source ?: "0.0.0.0/0") }
    var description by remember { mutableStateOf(existing?.description ?: "") }
    val portable = protocol == "tcp" || protocol == "udp"

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(if (existing == null) "Add rule" else "Edit rule") },
        text = {
            Column(
                modifier = Modifier.heightIn(max = 420.dp).verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text("Protocol", style = MaterialTheme.typography.labelMedium)
                ChipRow(options = PROTOCOLS, selected = protocol, onSelect = { protocol = it })
                Text("Direction", style = MaterialTheme.typography.labelMedium)
                ChipRow(options = DIRECTIONS, selected = direction, onSelect = { direction = it })
                if (portable) {
                    OutlinedTextField(
                        value = portFrom,
                        onValueChange = { portFrom = it.filter(Char::isDigit) },
                        label = { Text("Port from") },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        modifier = Modifier.fillMaxWidth().testTag(SecurityGroupsTestTags.RULE_PORT_FROM),
                    )
                    OutlinedTextField(
                        value = portTo,
                        onValueChange = { portTo = it.filter(Char::isDigit) },
                        label = { Text("Port to (blank = same)") },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
                OutlinedTextField(
                    value = source,
                    onValueChange = { source = it },
                    label = { Text("Source (CIDR or sg id)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag(SecurityGroupsTestTags.RULE_SOURCE),
                )
                OutlinedTextField(
                    value = description,
                    onValueChange = { description = it },
                    label = { Text("Description (optional)") },
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    val from = portFrom.toIntOrNull() ?: 0
                    val to = portTo.toIntOrNull() ?: from
                    onConfirm(
                        SecurityRuleReq(
                            protocol = protocol,
                            portFrom = if (portable) from else 0,
                            portTo = if (portable) to else 0,
                            source = source.trim(),
                            direction = direction,
                            description = description.trim(),
                        ),
                    )
                },
                enabled = !busy && source.isNotBlank(),
                modifier = Modifier.testTag(SecurityGroupsTestTags.RULE_CONFIRM),
            ) { Text(if (existing == null) "Add" else "Save") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun ChipRow(options: List<String>, selected: String, onSelect: (String) -> Unit) {
    Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
        options.forEach { o ->
            Row(
                modifier = Modifier
                    .selectable(selected = selected == o, onClick = { onSelect(o) })
                    .padding(end = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RadioButton(selected = selected == o, onClick = { onSelect(o) })
                Text(o)
            }
        }
    }
}
