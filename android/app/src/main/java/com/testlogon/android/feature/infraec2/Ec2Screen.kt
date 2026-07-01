@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.infraec2

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.AddCircleOutline
import androidx.compose.material.icons.outlined.Cloud
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
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
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.infraec2.Ec2Action
import com.testlogon.android.data.infraec2.Ec2AmiDto
import com.testlogon.android.data.infraec2.Ec2InstanceDto
import com.testlogon.android.data.infraec2.Ec2InstanceTypeDto
import com.testlogon.android.feature.infracommon.InfraDropdown
import com.testlogon.android.feature.infracommon.infraErrorMessage
import com.testlogon.android.feature.infracommon.statusColor

object Ec2TestTags {
    const val SCREEN = "ec2_screen"
    const val LIST = "ec2_list"
    const val EMPTY = "ec2_empty"
    const val FORBIDDEN = "ec2_forbidden"
    const val ERROR_RETRY = "ec2_error_retry"
    const val LAUNCH_FAB = "ec2_launch_open"
    const val LAUNCH_LABEL = "ec2_launch_label"
    const val LAUNCH_TYPE = "ec2_launch_type"
    const val LAUNCH_AMI = "ec2_launch_ami"
    const val LAUNCH_CONFIRM = "ec2_launch_confirm"
    fun row(id: String) = "ec2_row_$id"
    fun action(id: String) = "ec2_action_$id"
}

@Composable
fun Ec2Route(
    onBack: () -> Unit,
    viewModel: Ec2ViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    Ec2Screen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
        onLaunch = viewModel::launch,
        onAction = viewModel::performAction,
        onMessageShown = viewModel::clearMessage,
    )
}

@Composable
fun Ec2Screen(
    state: Ec2UiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onLaunch: (String, String, String, String?, String?) -> Unit,
    onAction: (String, Ec2Action) -> Unit,
    onMessageShown: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbar = remember { SnackbarHostState() }
    var showLaunch by remember { mutableStateOf(false) }
    var actionTarget by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(state.message, state.transientError) {
        val msg = state.message ?: state.transientError?.let { infraErrorMessage(it) }
        if (msg != null) {
            snackbar.showSnackbar(msg)
            onMessageShown()
        }
    }

    Scaffold(
        modifier = modifier.testTag(Ec2TestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text("EC2 instances") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(
                        onClick = { showLaunch = true },
                        enabled = state.reference != null && state.data !is Ec2DataState.Forbidden,
                        modifier = Modifier.testTag(Ec2TestTags.LAUNCH_FAB),
                    ) {
                        Icon(Icons.Outlined.AddCircleOutline, contentDescription = "Launch instance")
                    }
                },
            )
        },
    ) { padding ->
        val isRefreshing = (state.data as? Ec2DataState.Content)?.isRefreshing == true
        PullToRefreshBox(
            isRefreshing = isRefreshing,
            onRefresh = onRefresh,
            modifier = Modifier.fillMaxSize().padding(padding),
        ) {
            when (val d = state.data) {
                is Ec2DataState.Loading -> LoadingState()
                is Ec2DataState.Empty -> EmptyState(
                    modifier = Modifier.testTag(Ec2TestTags.EMPTY),
                    title = "No instances",
                    body = "Launch a cloud instance to get started.",
                    imageVector = Icons.Outlined.Cloud,
                    actionLabel = if (state.reference != null) "Launch" else null,
                    onAction = if (state.reference != null) ({ showLaunch = true }) else null,
                )
                is Ec2DataState.Forbidden -> EmptyState(
                    modifier = Modifier.testTag(Ec2TestTags.FORBIDDEN),
                    title = "Not authorised",
                    body = "You do not have access to cloud instances.",
                    imageVector = Icons.Outlined.Lock,
                    actionLabel = "Back",
                    onAction = onBack,
                )
                is Ec2DataState.Error -> ErrorState(
                    modifier = Modifier.testTag(Ec2TestTags.ERROR_RETRY),
                    message = infraErrorMessage(d.type),
                    onRetry = onRetry,
                )
                is Ec2DataState.Content -> LazyColumn(
                    modifier = Modifier.fillMaxSize().testTag(Ec2TestTags.LIST),
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    items(items = d.instances, key = { it.instanceId }) { inst ->
                        Ec2Row(
                            instance = inst,
                            inFlight = state.actionInFlightId == inst.instanceId,
                            actionsEnabled = state.actionInFlightId == null,
                            onActions = { actionTarget = inst.instanceId },
                        )
                    }
                }
            }
        }
    }

    if (showLaunch && state.reference != null) {
        LaunchDialog(
            types = state.reference.types,
            amis = state.reference.amis,
            inFlight = state.launchInFlight,
            onDismiss = { showLaunch = false },
            onConfirm = { label, type, ami ->
                onLaunch(label, type, ami, null, null)
                showLaunch = false
            },
        )
    }

    actionTarget?.let { id ->
        val inst = (state.data as? Ec2DataState.Content)?.instances?.firstOrNull { it.instanceId == id }
        ActionDialog(
            status = inst?.status.orEmpty(),
            onDismiss = { actionTarget = null },
            onAction = { action ->
                onAction(id, action)
                actionTarget = null
            },
        )
    }
}

@Composable
private fun Ec2Row(
    instance: Ec2InstanceDto,
    inFlight: Boolean,
    actionsEnabled: Boolean,
    onActions: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().testTag(Ec2TestTags.row(instance.instanceId))) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                instance.label.ifBlank { instance.instanceId },
                style = MaterialTheme.typography.titleSmall,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                AssistChip(
                    onClick = {},
                    enabled = false,
                    label = { Text(instance.status.ifBlank { "-" }) },
                    colors = AssistChipDefaults.assistChipColors(
                        disabledLabelColor = statusColor(instance.status),
                    ),
                )
                Text(instance.instanceType, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            if (instance.amiName.isNotBlank()) {
                Text(instance.amiName, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            instance.publicIp.takeIf { it.isNotBlank() }?.let {
                Text("Public IP: $it", style = MaterialTheme.typography.bodySmall)
            }
            instance.privateIp.takeIf { it.isNotBlank() }?.let {
                Text("Private IP: $it", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            if (inFlight) {
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) { CircularProgressIndicator() }
            } else if (!instance.status.equals("terminated", ignoreCase = true)) {
                OutlinedButton(
                    onClick = onActions,
                    enabled = actionsEnabled,
                    modifier = Modifier.fillMaxWidth().testTag(Ec2TestTags.action(instance.instanceId)),
                ) { Text("Actions") }
            }
        }
    }
}

@Composable
private fun LaunchDialog(
    types: List<Ec2InstanceTypeDto>,
    amis: List<Ec2AmiDto>,
    inFlight: Boolean,
    onDismiss: () -> Unit,
    onConfirm: (String, String, String) -> Unit,
) {
    var label by remember { mutableStateOf("") }
    var type by remember { mutableStateOf(types.firstOrNull()) }
    var ami by remember { mutableStateOf(amis.firstOrNull()) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Launch instance") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedTextField(
                    value = label,
                    onValueChange = { label = it },
                    label = { Text("Label") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag(Ec2TestTags.LAUNCH_LABEL),
                )
                InfraDropdown(
                    label = "Instance type",
                    options = types,
                    selected = type,
                    labelFor = { "${it.instanceType} (${it.vcpu} vCPU, ${it.memoryGb} GB)" },
                    onSelect = { type = it },
                    fieldTestTag = Ec2TestTags.LAUNCH_TYPE,
                )
                InfraDropdown(
                    label = "AMI",
                    options = amis,
                    selected = ami,
                    labelFor = { it.name.ifBlank { it.amiId } },
                    onSelect = { ami = it },
                    fieldTestTag = Ec2TestTags.LAUNCH_AMI,
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    val t = type
                    val a = ami
                    if (label.isNotBlank() && t != null && a != null) onConfirm(label, t.instanceType, a.amiId)
                },
                enabled = !inFlight && label.isNotBlank() && type != null && ami != null,
                modifier = Modifier.testTag(Ec2TestTags.LAUNCH_CONFIRM),
            ) { Text(if (inFlight) "Launching…" else "Launch") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun ActionDialog(
    status: String,
    onDismiss: () -> Unit,
    onAction: (Ec2Action) -> Unit,
) {
    val running = status.equals("running", ignoreCase = true)
    val stopped = status.equals("stopped", ignoreCase = true)
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Instance actions") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                if (!running) {
                    Button(onClick = { onAction(Ec2Action.START) }, modifier = Modifier.fillMaxWidth()) { Text("Start") }
                }
                if (running) {
                    Button(onClick = { onAction(Ec2Action.STOP) }, modifier = Modifier.fillMaxWidth()) { Text("Stop") }
                    OutlinedButton(onClick = { onAction(Ec2Action.REBOOT) }, modifier = Modifier.fillMaxWidth()) { Text("Reboot") }
                }
                if (stopped || running) {
                    OutlinedButton(onClick = { onAction(Ec2Action.TERMINATE) }, modifier = Modifier.fillMaxWidth()) { Text("Terminate") }
                }
            }
        },
        confirmButton = {},
        dismissButton = { TextButton(onClick = onDismiss) { Text("Close") } },
    )
}
