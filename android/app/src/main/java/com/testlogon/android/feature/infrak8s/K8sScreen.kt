@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.infrak8s

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
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.AddCircleOutline
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Memory
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.infrak8s.K8sImageDto
import com.testlogon.android.data.infrak8s.K8sPodDto
import com.testlogon.android.data.infrak8s.K8sPresetDto
import com.testlogon.android.feature.infracommon.InfraDropdown
import com.testlogon.android.feature.infracommon.infraErrorMessage
import com.testlogon.android.feature.infracommon.statusColor

object K8sTestTags {
    const val SCREEN = "k8s_screen"
    const val LIST = "k8s_list"
    const val EMPTY = "k8s_empty"
    const val FORBIDDEN = "k8s_forbidden"
    const val ERROR_RETRY = "k8s_error_retry"
    const val LAUNCH_OPEN = "k8s_launch_open"
    const val LAUNCH_LABEL = "k8s_launch_label"
    const val LAUNCH_IMAGE = "k8s_launch_image"
    const val LAUNCH_PRESET = "k8s_launch_preset"
    const val LAUNCH_CONFIRM = "k8s_launch_confirm"
    const val LOGS_DIALOG = "k8s_logs_dialog"
    fun row(id: String) = "k8s_row_$id"
    fun logs(id: String) = "k8s_logs_$id"
    fun terminate(id: String) = "k8s_terminate_$id"
}

@Composable
fun K8sRoute(
    onBack: () -> Unit,
    viewModel: K8sViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    K8sScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
        onLaunch = viewModel::launch,
        onTerminate = viewModel::terminate,
        onOpenLogs = viewModel::openLogs,
        onCloseLogs = viewModel::closeLogs,
        onMessageShown = viewModel::clearMessage,
    )
}

@Composable
fun K8sScreen(
    state: K8sUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onLaunch: (String, String, String) -> Unit,
    onTerminate: (String) -> Unit,
    onOpenLogs: (String) -> Unit,
    onCloseLogs: () -> Unit,
    onMessageShown: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbar = remember { SnackbarHostState() }
    var showLaunch by remember { mutableStateOf(false) }

    LaunchedEffect(state.message, state.transientError) {
        val msg = state.message ?: state.transientError?.let { infraErrorMessage(it) }
        if (msg != null) {
            snackbar.showSnackbar(msg)
            onMessageShown()
        }
    }

    Scaffold(
        modifier = modifier.testTag(K8sTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text("Containers (K8s)") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(
                        onClick = { showLaunch = true },
                        enabled = state.reference != null && state.data !is K8sDataState.Forbidden,
                        modifier = Modifier.testTag(K8sTestTags.LAUNCH_OPEN),
                    ) {
                        Icon(Icons.Outlined.AddCircleOutline, contentDescription = "Deploy pod")
                    }
                },
            )
        },
    ) { padding ->
        val isRefreshing = (state.data as? K8sDataState.Content)?.isRefreshing == true
        PullToRefreshBox(
            isRefreshing = isRefreshing,
            onRefresh = onRefresh,
            modifier = Modifier.fillMaxSize().padding(padding),
        ) {
            when (val d = state.data) {
                is K8sDataState.Loading -> LoadingState()
                is K8sDataState.Empty -> EmptyState(
                    modifier = Modifier.testTag(K8sTestTags.EMPTY),
                    title = "No pods",
                    body = "Deploy a container to get started.",
                    imageVector = Icons.Outlined.Memory,
                    actionLabel = if (state.reference != null) "Deploy" else null,
                    onAction = if (state.reference != null) ({ showLaunch = true }) else null,
                )
                is K8sDataState.Forbidden -> EmptyState(
                    modifier = Modifier.testTag(K8sTestTags.FORBIDDEN),
                    title = "Not authorised",
                    body = "You do not have access to containers.",
                    imageVector = Icons.Outlined.Lock,
                    actionLabel = "Back",
                    onAction = onBack,
                )
                is K8sDataState.Error -> ErrorState(
                    modifier = Modifier.testTag(K8sTestTags.ERROR_RETRY),
                    message = infraErrorMessage(d.type),
                    onRetry = onRetry,
                )
                is K8sDataState.Content -> LazyColumn(
                    modifier = Modifier.fillMaxSize().testTag(K8sTestTags.LIST),
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    items(items = d.pods, key = { it.podId }) { pod ->
                        K8sRow(
                            pod = pod,
                            inFlight = state.actionInFlightId == pod.podId,
                            actionsEnabled = state.actionInFlightId == null,
                            onLogs = { onOpenLogs(pod.podId) },
                            onTerminate = { onTerminate(pod.podId) },
                        )
                    }
                }
            }
        }
    }

    if (showLaunch && state.reference != null) {
        DeployDialog(
            images = state.reference.images,
            presets = state.reference.presets,
            inFlight = state.launchInFlight,
            onDismiss = { showLaunch = false },
            onConfirm = { label, image, preset ->
                onLaunch(label, image, preset)
                showLaunch = false
            },
        )
    }

    state.logs?.let { logsState ->
        LogsDialog(logsState = logsState, onDismiss = onCloseLogs)
    }
}

@Composable
private fun K8sRow(
    pod: K8sPodDto,
    inFlight: Boolean,
    actionsEnabled: Boolean,
    onLogs: () -> Unit,
    onTerminate: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().testTag(K8sTestTags.row(pod.podId))) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                pod.label.ifBlank { pod.k8sPodName.ifBlank { pod.podId } },
                style = MaterialTheme.typography.titleSmall,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                AssistChip(
                    onClick = {},
                    enabled = false,
                    label = { Text(pod.status.ifBlank { "-" }) },
                    colors = AssistChipDefaults.assistChipColors(disabledLabelColor = statusColor(pod.status)),
                )
                Text(pod.preset, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Text(
                pod.imageDisplayName.ifBlank { pod.image },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                "${pod.cpuMillicores}m CPU / ${pod.memoryMb} MB",
                style = MaterialTheme.typography.bodySmall,
            )
            pod.podIp.takeIf { it.isNotBlank() }?.let {
                Text("Pod IP: $it", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            if (inFlight) {
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) { CircularProgressIndicator() }
            } else {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                    OutlinedButton(
                        onClick = onLogs,
                        enabled = actionsEnabled,
                        modifier = Modifier.testTag(K8sTestTags.logs(pod.podId)),
                    ) { Text("Logs") }
                    if (!pod.status.equals("terminated", ignoreCase = true)) {
                        OutlinedButton(
                            onClick = onTerminate,
                            enabled = actionsEnabled,
                            modifier = Modifier.testTag(K8sTestTags.terminate(pod.podId)),
                        ) { Text("Terminate") }
                    }
                }
            }
        }
    }
}

@Composable
private fun DeployDialog(
    images: List<K8sImageDto>,
    presets: List<K8sPresetDto>,
    inFlight: Boolean,
    onDismiss: () -> Unit,
    onConfirm: (String, String, String) -> Unit,
) {
    var label by remember { mutableStateOf("") }
    var image by remember { mutableStateOf(images.firstOrNull()) }
    var preset by remember { mutableStateOf(presets.firstOrNull()) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Deploy pod") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedTextField(
                    value = label,
                    onValueChange = { label = it },
                    label = { Text("Label") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag(K8sTestTags.LAUNCH_LABEL),
                )
                InfraDropdown(
                    label = "Image",
                    options = images,
                    selected = image,
                    labelFor = { it.displayName.ifBlank { it.image } },
                    onSelect = { image = it },
                    fieldTestTag = K8sTestTags.LAUNCH_IMAGE,
                )
                InfraDropdown(
                    label = "Preset",
                    options = presets,
                    selected = preset,
                    labelFor = { "${it.preset} (${it.cpuMillicores}m / ${it.memoryMb} MB)" },
                    onSelect = { preset = it },
                    fieldTestTag = K8sTestTags.LAUNCH_PRESET,
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    val i = image
                    val p = preset
                    if (label.isNotBlank() && i != null && p != null) onConfirm(label, i.image, p.preset)
                },
                enabled = !inFlight && label.isNotBlank() && image != null && preset != null,
                modifier = Modifier.testTag(K8sTestTags.LAUNCH_CONFIRM),
            ) { Text(if (inFlight) "Deploying…" else "Deploy") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun LogsDialog(logsState: K8sLogsState, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        modifier = Modifier.testTag(K8sTestTags.LOGS_DIALOG),
        title = { Text("Pod logs") },
        text = {
            when (logsState) {
                is K8sLogsState.Loading -> Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.Center,
                ) { CircularProgressIndicator() }
                is K8sLogsState.Error -> Text(infraErrorMessage(logsState.type))
                is K8sLogsState.Loaded -> {
                    if (logsState.lines.isEmpty()) {
                        Text("No log output.", color = MaterialTheme.colorScheme.onSurfaceVariant)
                    } else {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .heightIn(max = 360.dp)
                                .verticalScroll(rememberScrollState()),
                        ) {
                            logsState.lines.forEach { line ->
                                Text(
                                    line,
                                    style = MaterialTheme.typography.bodySmall,
                                    fontFamily = FontFamily.Monospace,
                                )
                            }
                        }
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text("Close") } },
    )
}
