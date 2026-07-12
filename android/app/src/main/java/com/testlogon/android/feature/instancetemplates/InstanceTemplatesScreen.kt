@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.instancetemplates

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
import androidx.compose.material.icons.outlined.Dashboard
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
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
import com.testlogon.android.data.instancetemplates.TemplateDto
import com.testlogon.android.feature.infracommon.infraErrorMessage

object TemplatesTestTags {
    const val SCREEN = "templates_screen"
    const val LIST = "templates_list"
    const val EMPTY = "templates_empty"
    const val FORBIDDEN = "templates_forbidden"
    const val DISABLED = "templates_disabled"
    const val ERROR_RETRY = "templates_error_retry"
    const val LAUNCH_CONFIRM = "templates_launch_confirm"
    fun row(id: String) = "templates_row_$id"
    fun apply(id: String) = "templates_apply_$id"
    fun clone(id: String) = "templates_clone_$id"
    fun delete(id: String) = "templates_delete_$id"
}

@Composable
fun InstanceTemplatesRoute(
    onBack: () -> Unit,
    viewModel: InstanceTemplatesViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    InstanceTemplatesScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
        onLaunch = viewModel::launch,
        onClone = viewModel::clone,
        onDelete = viewModel::delete,
        onDismissLaunch = viewModel::dismissLaunchResult,
        onMessageShown = viewModel::clearMessage,
    )
}

@Composable
fun InstanceTemplatesScreen(
    state: TemplatesUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onLaunch: (String, String) -> Unit,
    onClone: (String, String) -> Unit,
    onDelete: (String) -> Unit,
    onDismissLaunch: () -> Unit,
    onMessageShown: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbar = remember { SnackbarHostState() }
    var applyTarget by remember { mutableStateOf<TemplateDto?>(null) }
    var cloneTarget by remember { mutableStateOf<TemplateDto?>(null) }
    var deleteTarget by remember { mutableStateOf<TemplateDto?>(null) }

    LaunchedEffect(state.message, state.transientError) {
        val msg = state.message ?: state.transientError?.let { infraErrorMessage(it) }
        if (msg != null) { snackbar.showSnackbar(msg); onMessageShown() }
    }

    Scaffold(
        modifier = modifier.testTag(TemplatesTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text("Instance templates") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        val isRefreshing = (state.data as? TemplatesDataState.Content)?.isRefreshing == true
        PullToRefreshBox(
            isRefreshing = isRefreshing,
            onRefresh = onRefresh,
            modifier = Modifier.fillMaxSize().padding(padding),
        ) {
            when (val d = state.data) {
                is TemplatesDataState.Loading -> LoadingState()
                is TemplatesDataState.Empty -> EmptyState(
                    modifier = Modifier.testTag(TemplatesTestTags.EMPTY),
                    title = "No templates",
                    body = "Instance templates capture a reusable launch config.",
                    imageVector = Icons.Outlined.Dashboard,
                )
                is TemplatesDataState.Disabled -> EmptyState(
                    modifier = Modifier.testTag(TemplatesTestTags.DISABLED),
                    title = "Templates disabled",
                    body = "Instance templates are turned off for this environment.",
                    imageVector = Icons.Outlined.Lock,
                    actionLabel = "Back",
                    onAction = onBack,
                )
                is TemplatesDataState.Forbidden -> EmptyState(
                    modifier = Modifier.testTag(TemplatesTestTags.FORBIDDEN),
                    title = "Not authorised",
                    body = "You do not have access to instance templates.",
                    imageVector = Icons.Outlined.Lock,
                    actionLabel = "Back",
                    onAction = onBack,
                )
                is TemplatesDataState.Error -> ErrorState(
                    modifier = Modifier.testTag(TemplatesTestTags.ERROR_RETRY),
                    message = infraErrorMessage(d.type),
                    onRetry = onRetry,
                )
                is TemplatesDataState.Content -> LazyColumn(
                    modifier = Modifier.fillMaxSize().testTag(TemplatesTestTags.LIST),
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    items(items = d.templates, key = { it.templateId }) { t ->
                        TemplateRow(
                            template = t,
                            inFlight = state.actionInFlightId == t.templateId,
                            actionsEnabled = state.actionInFlightId == null,
                            onApply = { applyTarget = t },
                            onClone = { cloneTarget = t },
                            onDelete = { deleteTarget = t },
                        )
                    }
                }
            }
        }
    }

    applyTarget?.let { t ->
        var label by remember(t.templateId) { mutableStateOf(t.name) }
        AlertDialog(
            onDismissRequest = { applyTarget = null },
            title = { Text("Launch from template") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Launch \"${t.name}\" (${t.target.uppercase()})", style = MaterialTheme.typography.bodyMedium)
                    OutlinedTextField(
                        value = label,
                        onValueChange = { label = it },
                        label = { Text("Label") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
            },
            confirmButton = {
                TextButton(
                    onClick = { onLaunch(t.templateId, label); applyTarget = null },
                    modifier = Modifier.testTag(TemplatesTestTags.LAUNCH_CONFIRM),
                ) { Text("Launch") }
            },
            dismissButton = { TextButton(onClick = { applyTarget = null }) { Text("Cancel") } },
        )
    }

    cloneTarget?.let { t ->
        var newName by remember(t.templateId) { mutableStateOf("${t.name} copy") }
        AlertDialog(
            onDismissRequest = { cloneTarget = null },
            title = { Text("Clone template") },
            text = {
                OutlinedTextField(
                    value = newName,
                    onValueChange = { newName = it },
                    label = { Text("New name") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            },
            confirmButton = { TextButton(onClick = { onClone(t.templateId, newName); cloneTarget = null }) { Text("Clone") } },
            dismissButton = { TextButton(onClick = { cloneTarget = null }) { Text("Cancel") } },
        )
    }

    deleteTarget?.let { t ->
        AlertDialog(
            onDismissRequest = { deleteTarget = null },
            title = { Text("Delete template?") },
            text = { Text("Delete \"${t.name}\"?") },
            confirmButton = { TextButton(onClick = { onDelete(t.templateId); deleteTarget = null }) { Text("Delete") } },
            dismissButton = { TextButton(onClick = { deleteTarget = null }) { Text("Cancel") } },
        )
    }

    state.launchResult?.let { r ->
        AlertDialog(
            onDismissRequest = onDismissLaunch,
            title = { Text("Launched") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("Target: ${r.target.uppercase()}", style = MaterialTheme.typography.bodySmall)
                    r.instance?.let {
                        Text("Instance: ${it.label.ifBlank { it.instanceId }}", style = MaterialTheme.typography.bodySmall)
                        Text("Status: ${it.status}", style = MaterialTheme.typography.bodySmall)
                        if (it.publicIp.isNotBlank()) Text("Public IP: ${it.publicIp}", style = MaterialTheme.typography.bodySmall)
                    }
                    r.pod?.let {
                        Text("Pod: ${it.label.ifBlank { it.podId }}", style = MaterialTheme.typography.bodySmall)
                        Text("Image: ${it.image}", style = MaterialTheme.typography.bodySmall)
                    }
                }
            },
            confirmButton = { TextButton(onClick = onDismissLaunch) { Text("Done") } },
        )
    }
}

@Composable
private fun TemplateRow(
    template: TemplateDto,
    inFlight: Boolean,
    actionsEnabled: Boolean,
    onApply: () -> Unit,
    onClone: () -> Unit,
    onDelete: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().testTag(TemplatesTestTags.row(template.templateId))) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                template.name.ifBlank { template.templateId },
                style = MaterialTheme.typography.titleSmall,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                AssistChip(onClick = {}, enabled = false, label = { Text(template.target.uppercase()) })
                AssistChip(onClick = {}, enabled = false, label = { Text(template.category) })
                if (template.isSystem) AssistChip(onClick = {}, enabled = false, label = { Text("system") })
            }
            if (template.description.isNotBlank()) {
                Text(template.description, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 2, overflow = TextOverflow.Ellipsis)
            }
            val spec = if (template.target == "k8s") template.k8sImage else template.instanceType
            if (spec.isNotBlank()) {
                Text(spec, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            if (inFlight) {
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) { CircularProgressIndicator() }
            } else {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(
                        onClick = onApply,
                        enabled = actionsEnabled,
                        modifier = Modifier.testTag(TemplatesTestTags.apply(template.templateId)),
                    ) { Text("Apply") }
                    OutlinedButton(
                        onClick = onClone,
                        enabled = actionsEnabled,
                        modifier = Modifier.testTag(TemplatesTestTags.clone(template.templateId)),
                    ) { Text("Clone") }
                    if (!template.isSystem) {
                        OutlinedButton(
                            onClick = onDelete,
                            enabled = actionsEnabled,
                            modifier = Modifier.testTag(TemplatesTestTags.delete(template.templateId)),
                        ) { Text("Delete") }
                    }
                }
            }
        }
    }
}
