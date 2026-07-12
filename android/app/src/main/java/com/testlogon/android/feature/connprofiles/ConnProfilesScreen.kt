@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.connprofiles

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
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.SettingsEthernet
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
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.connprofiles.ConnProfileDto
import com.testlogon.android.data.connprofiles.CreateConnProfileReq
import com.testlogon.android.data.connprofiles.UpdateConnProfileReq
import com.testlogon.android.feature.infracommon.InfraDropdown
import com.testlogon.android.feature.infracommon.infraErrorMessage

object ConnProfilesTestTags {
    const val SCREEN = "connprofiles_screen"
    const val LIST = "connprofiles_list"
    const val EMPTY = "connprofiles_empty"
    const val FORBIDDEN = "connprofiles_forbidden"
    const val ERROR_RETRY = "connprofiles_error_retry"
    const val ADD = "connprofiles_add_open"
    const val FORM_LABEL = "connprofiles_form_label"
    const val FORM_HOST = "connprofiles_form_host"
    const val FORM_CONFIRM = "connprofiles_form_confirm"
    fun row(id: String) = "connprofiles_row_$id"
    fun connect(id: String) = "connprofiles_connect_$id"
    fun edit(id: String) = "connprofiles_edit_$id"
    fun delete(id: String) = "connprofiles_delete_$id"
}

@Composable
fun ConnProfilesRoute(
    onBack: () -> Unit,
    viewModel: ConnProfilesViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    ConnProfilesScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
        onCreate = viewModel::create,
        onUpdate = viewModel::update,
        onDelete = viewModel::delete,
        onQuickConnect = viewModel::quickConnect,
        onDismissQuickConnect = viewModel::dismissQuickConnect,
        onMessageShown = viewModel::clearMessage,
    )
}

@Composable
fun ConnProfilesScreen(
    state: ConnProfilesUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onCreate: (CreateConnProfileReq) -> Unit,
    onUpdate: (String, UpdateConnProfileReq) -> Unit,
    onDelete: (String) -> Unit,
    onQuickConnect: (String) -> Unit,
    onDismissQuickConnect: () -> Unit,
    onMessageShown: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbar = remember { SnackbarHostState() }
    var showCreate by remember { mutableStateOf(false) }
    var editTarget by remember { mutableStateOf<ConnProfileDto?>(null) }
    var deleteTarget by remember { mutableStateOf<ConnProfileDto?>(null) }
    val clipboard = LocalClipboardManager.current

    LaunchedEffect(state.message, state.transientError) {
        val msg = state.message ?: state.transientError?.let { infraErrorMessage(it) }
        if (msg != null) { snackbar.showSnackbar(msg); onMessageShown() }
    }

    Scaffold(
        modifier = modifier.testTag(ConnProfilesTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text("Connection profiles") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(
                        onClick = { showCreate = true },
                        enabled = state.data !is ConnProfilesDataState.Forbidden,
                        modifier = Modifier.testTag(ConnProfilesTestTags.ADD),
                    ) { Icon(Icons.Outlined.Add, contentDescription = "New profile") }
                },
            )
        },
    ) { padding ->
        val isRefreshing = (state.data as? ConnProfilesDataState.Content)?.isRefreshing == true
        PullToRefreshBox(
            isRefreshing = isRefreshing,
            onRefresh = onRefresh,
            modifier = Modifier.fillMaxSize().padding(padding),
        ) {
            when (val d = state.data) {
                is ConnProfilesDataState.Loading -> LoadingState()
                is ConnProfilesDataState.Empty -> EmptyState(
                    modifier = Modifier.testTag(ConnProfilesTestTags.EMPTY),
                    title = "No connection profiles",
                    body = "Save SSH/VNC connection details for one-tap quick-connect.",
                    imageVector = Icons.Outlined.SettingsEthernet,
                    actionLabel = "New profile",
                    onAction = { showCreate = true },
                )
                is ConnProfilesDataState.Forbidden -> EmptyState(
                    modifier = Modifier.testTag(ConnProfilesTestTags.FORBIDDEN),
                    title = "Not authorised",
                    body = "You do not have access to connection profiles.",
                    imageVector = Icons.Outlined.Lock,
                    actionLabel = "Back",
                    onAction = onBack,
                )
                is ConnProfilesDataState.Error -> ErrorState(
                    modifier = Modifier.testTag(ConnProfilesTestTags.ERROR_RETRY),
                    message = infraErrorMessage(d.type),
                    onRetry = onRetry,
                )
                is ConnProfilesDataState.Content -> LazyColumn(
                    modifier = Modifier.fillMaxSize().testTag(ConnProfilesTestTags.LIST),
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    items(items = d.profiles, key = { it.profileId }) { p ->
                        ConnProfileRow(
                            profile = p,
                            inFlight = state.actionInFlightId == p.profileId,
                            actionsEnabled = state.actionInFlightId == null,
                            onConnect = { onQuickConnect(p.profileId) },
                            onEdit = { editTarget = p },
                            onDelete = { deleteTarget = p },
                        )
                    }
                }
            }
        }
    }

    if (showCreate) {
        ProfileFormDialog(
            existing = null,
            mutating = state.mutating,
            onDismiss = { showCreate = false },
            onSubmitCreate = { onCreate(it); showCreate = false },
            onSubmitUpdate = { _, _ -> },
        )
    }

    editTarget?.let { p ->
        ProfileFormDialog(
            existing = p,
            mutating = state.mutating,
            onDismiss = { editTarget = null },
            onSubmitCreate = { },
            onSubmitUpdate = { id, req -> onUpdate(id, req); editTarget = null },
        )
    }

    deleteTarget?.let { p ->
        AlertDialog(
            onDismissRequest = { deleteTarget = null },
            title = { Text("Delete profile?") },
            text = { Text("Delete \"${p.label}\"?") },
            confirmButton = { TextButton(onClick = { onDelete(p.profileId); deleteTarget = null }) { Text("Delete") } },
            dismissButton = { TextButton(onClick = { deleteTarget = null }) { Text("Cancel") } },
        )
    }

    state.quickConnect?.let { qc ->
        val cmd = qc.bastion?.sshCommand?.takeIf { it.isNotBlank() }
            ?: buildString {
                append(if (qc.protocol == "vnc") "vnc://" else "ssh ")
                if (qc.protocol != "vnc" && qc.username.isNotBlank()) append("${qc.username}@")
                append(qc.hostname)
                if (qc.protocol != "vnc" && qc.port != 22) append(" -p ${qc.port}")
            }
        AlertDialog(
            onDismissRequest = onDismissQuickConnect,
            title = { Text("Quick connect") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(qc.label, style = MaterialTheme.typography.titleSmall)
                    Text("${qc.protocol.uppercase()} - ${qc.hostname}:${qc.port}", style = MaterialTheme.typography.bodySmall)
                    if (qc.username.isNotBlank()) Text("User: ${qc.username}", style = MaterialTheme.typography.bodySmall)
                    if (qc.authMethod.isNotBlank()) Text("Auth: ${qc.authMethod}", style = MaterialTheme.typography.bodySmall)
                    qc.bastion?.let { Text("Bastion: ${it.totalHops} hop(s)", style = MaterialTheme.typography.bodySmall) }
                    Text(cmd, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary)
                    Text(
                        "The interactive terminal opens on desktop. Copy the command to connect from your SSH client.",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            },
            confirmButton = { TextButton(onClick = { clipboard.setText(AnnotatedString(cmd)) }) { Text("Copy command") } },
            dismissButton = { TextButton(onClick = onDismissQuickConnect) { Text("Close") } },
        )
    }
}

@Composable
private fun ConnProfileRow(
    profile: ConnProfileDto,
    inFlight: Boolean,
    actionsEnabled: Boolean,
    onConnect: () -> Unit,
    onEdit: () -> Unit,
    onDelete: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().testTag(ConnProfilesTestTags.row(profile.profileId))) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                profile.label.ifBlank { profile.profileId },
                style = MaterialTheme.typography.titleSmall,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                AssistChip(onClick = {}, enabled = false, label = { Text(profile.protocol.uppercase()) })
                if (profile.isFavorite) AssistChip(onClick = {}, enabled = false, label = { Text("favorite") })
            }
            val target = profile.hostname.ifBlank { profile.instanceId }
            if (target.isNotBlank()) {
                Text(
                    "${if (profile.username.isNotBlank()) "${profile.username}@" else ""}$target:${profile.port}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (inFlight) {
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) { CircularProgressIndicator() }
            } else {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(
                        onClick = onConnect,
                        enabled = actionsEnabled,
                        modifier = Modifier.testTag(ConnProfilesTestTags.connect(profile.profileId)),
                    ) { Text("Connect") }
                    OutlinedButton(
                        onClick = onEdit,
                        enabled = actionsEnabled,
                        modifier = Modifier.testTag(ConnProfilesTestTags.edit(profile.profileId)),
                    ) { Text("Edit") }
                    OutlinedButton(
                        onClick = onDelete,
                        enabled = actionsEnabled,
                        modifier = Modifier.testTag(ConnProfilesTestTags.delete(profile.profileId)),
                    ) { Text("Delete") }
                }
            }
        }
    }
}

@Composable
private fun ProfileFormDialog(
    existing: ConnProfileDto?,
    mutating: Boolean,
    onDismiss: () -> Unit,
    onSubmitCreate: (CreateConnProfileReq) -> Unit,
    onSubmitUpdate: (String, UpdateConnProfileReq) -> Unit,
) {
    val isEdit = existing != null
    var label by remember { mutableStateOf(existing?.label ?: "") }
    var protocol by remember { mutableStateOf(existing?.protocol ?: "ssh") }
    var hostname by remember { mutableStateOf(existing?.hostname ?: "") }
    var portText by remember { mutableStateOf((existing?.port ?: 22).toString()) }
    var username by remember { mutableStateOf(existing?.username ?: "") }
    var isFavorite by remember { mutableStateOf(existing?.isFavorite ?: false) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(if (isEdit) "Edit profile" else "New profile") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedTextField(
                    value = label,
                    onValueChange = { label = it },
                    label = { Text("Label") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag(ConnProfilesTestTags.FORM_LABEL),
                )
                if (!isEdit) {
                    InfraDropdown(
                        label = "Protocol",
                        options = listOf("ssh", "vnc"),
                        selected = protocol,
                        labelFor = { it.uppercase() },
                        onSelect = { protocol = it },
                        fieldTestTag = "connprofiles_form_protocol",
                    )
                }
                OutlinedTextField(
                    value = hostname,
                    onValueChange = { hostname = it },
                    label = { Text("Hostname") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag(ConnProfilesTestTags.FORM_HOST),
                )
                OutlinedTextField(
                    value = portText,
                    onValueChange = { portText = it.filter { c -> c.isDigit() }.take(5) },
                    label = { Text("Port") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = username,
                    onValueChange = { username = it },
                    label = { Text("Username") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Text("Favorite", style = MaterialTheme.typography.bodyMedium)
                    androidx.compose.material3.Switch(checked = isFavorite, onCheckedChange = { isFavorite = it })
                }
            }
        },
        confirmButton = {
            val port = portText.toIntOrNull() ?: 22
            TextButton(
                onClick = {
                    if (isEdit) {
                        onSubmitUpdate(
                            existing!!.profileId,
                            UpdateConnProfileReq(
                                label = label.trim(),
                                hostname = hostname.trim(),
                                port = port,
                                username = username.trim(),
                                isFavorite = isFavorite,
                            ),
                        )
                    } else {
                        onSubmitCreate(
                            CreateConnProfileReq(
                                label = label.trim(),
                                protocol = protocol,
                                hostname = hostname.trim().ifBlank { null },
                                port = port,
                                username = username.trim().ifBlank { null },
                                isFavorite = isFavorite,
                            ),
                        )
                    }
                },
                enabled = !mutating && label.isNotBlank(),
                modifier = Modifier.testTag(ConnProfilesTestTags.FORM_CONFIRM),
            ) { Text(if (mutating) "Saving..." else "Save") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}
