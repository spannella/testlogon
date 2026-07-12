@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.sshbastion

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
import androidx.compose.material.icons.outlined.Hub
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
import com.testlogon.android.data.sshbastion.BastionHopReq
import com.testlogon.android.data.sshbastion.BastionPathDto
import com.testlogon.android.data.sshbastion.CreateBastionPathReq
import com.testlogon.android.feature.infracommon.infraErrorMessage

object SshBastionTestTags {
    const val SCREEN = "sshbastion_screen"
    const val LIST = "sshbastion_list"
    const val EMPTY = "sshbastion_empty"
    const val FORBIDDEN = "sshbastion_forbidden"
    const val ERROR_RETRY = "sshbastion_error_retry"
    const val ADD = "sshbastion_add_open"
    const val FORM_LABEL = "sshbastion_form_label"
    const val FORM_JUMP_HOST = "sshbastion_form_jump_host"
    const val FORM_TARGET_HOST = "sshbastion_form_target_host"
    const val FORM_CONFIRM = "sshbastion_form_confirm"
    fun row(id: String) = "sshbastion_row_$id"
    fun resolve(id: String) = "sshbastion_resolve_$id"
    fun delete(id: String) = "sshbastion_delete_$id"
}

@Composable
fun SshBastionRoute(
    onBack: () -> Unit,
    viewModel: SshBastionViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    SshBastionScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
        onCreate = viewModel::create,
        onResolve = viewModel::resolve,
        onDelete = viewModel::delete,
        onDismissResolved = viewModel::dismissResolved,
        onMessageShown = viewModel::clearMessage,
    )
}

@Composable
fun SshBastionScreen(
    state: SshBastionUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onCreate: (CreateBastionPathReq) -> Unit,
    onResolve: (String) -> Unit,
    onDelete: (String) -> Unit,
    onDismissResolved: () -> Unit,
    onMessageShown: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbar = remember { SnackbarHostState() }
    var showCreate by remember { mutableStateOf(false) }
    var deleteTarget by remember { mutableStateOf<BastionPathDto?>(null) }
    val clipboard = LocalClipboardManager.current

    LaunchedEffect(state.message, state.transientError) {
        val msg = state.message ?: state.transientError?.let { infraErrorMessage(it) }
        if (msg != null) { snackbar.showSnackbar(msg); onMessageShown() }
    }

    Scaffold(
        modifier = modifier.testTag(SshBastionTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text("SSH bastion paths") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(
                        onClick = { showCreate = true },
                        enabled = state.data !is SshBastionDataState.Forbidden,
                        modifier = Modifier.testTag(SshBastionTestTags.ADD),
                    ) { Icon(Icons.Outlined.Add, contentDescription = "New path") }
                },
            )
        },
    ) { padding ->
        val isRefreshing = (state.data as? SshBastionDataState.Content)?.isRefreshing == true
        PullToRefreshBox(
            isRefreshing = isRefreshing,
            onRefresh = onRefresh,
            modifier = Modifier.fillMaxSize().padding(padding),
        ) {
            when (val d = state.data) {
                is SshBastionDataState.Loading -> LoadingState()
                is SshBastionDataState.Empty -> EmptyState(
                    modifier = Modifier.testTag(SshBastionTestTags.EMPTY),
                    title = "No bastion paths",
                    body = "Define a jump-host chain to reach hosts behind a bastion.",
                    imageVector = Icons.Outlined.Hub,
                    actionLabel = "New path",
                    onAction = { showCreate = true },
                )
                is SshBastionDataState.Forbidden -> EmptyState(
                    modifier = Modifier.testTag(SshBastionTestTags.FORBIDDEN),
                    title = "Not authorised",
                    body = "You do not have access to bastion paths.",
                    imageVector = Icons.Outlined.Lock,
                    actionLabel = "Back",
                    onAction = onBack,
                )
                is SshBastionDataState.Error -> ErrorState(
                    modifier = Modifier.testTag(SshBastionTestTags.ERROR_RETRY),
                    message = infraErrorMessage(d.type),
                    onRetry = onRetry,
                )
                is SshBastionDataState.Content -> LazyColumn(
                    modifier = Modifier.fillMaxSize().testTag(SshBastionTestTags.LIST),
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    items(items = d.paths, key = { it.pathId }) { p ->
                        BastionPathRow(
                            path = p,
                            inFlight = state.actionInFlightId == p.pathId,
                            actionsEnabled = state.actionInFlightId == null,
                            onResolve = { onResolve(p.pathId) },
                            onDelete = { deleteTarget = p },
                        )
                    }
                }
            }
        }
    }

    if (showCreate) {
        BastionFormDialog(
            mutating = state.mutating,
            onDismiss = { showCreate = false },
            onSubmit = { onCreate(it); showCreate = false },
        )
    }

    deleteTarget?.let { p ->
        AlertDialog(
            onDismissRequest = { deleteTarget = null },
            title = { Text("Delete path?") },
            text = { Text("Delete \"${p.label}\"?") },
            confirmButton = { TextButton(onClick = { onDelete(p.pathId); deleteTarget = null }) { Text("Delete") } },
            dismissButton = { TextButton(onClick = { deleteTarget = null }) { Text("Cancel") } },
        )
    }

    state.resolved?.let { r ->
        AlertDialog(
            onDismissRequest = onDismissResolved,
            title = { Text("Resolved chain") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(r.label, style = MaterialTheme.typography.titleSmall)
                    Text("${r.totalHops} hop(s)", style = MaterialTheme.typography.bodySmall)
                    if (r.proxyJump.isNotBlank()) {
                        Text("ProxyJump: ${r.proxyJump}", style = MaterialTheme.typography.bodySmall)
                    }
                    if (r.sshCommand.isNotBlank()) {
                        Text(r.sshCommand, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary)
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    val text = r.sshConfig.ifBlank { r.sshCommand }
                    clipboard.setText(AnnotatedString(text))
                }) { Text("Copy config") }
            },
            dismissButton = { TextButton(onClick = onDismissResolved) { Text("Close") } },
        )
    }
}

@Composable
private fun BastionPathRow(
    path: BastionPathDto,
    inFlight: Boolean,
    actionsEnabled: Boolean,
    onResolve: () -> Unit,
    onDelete: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().testTag(SshBastionTestTags.row(path.pathId))) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                path.label.ifBlank { path.pathId },
                style = MaterialTheme.typography.titleSmall,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            AssistChip(onClick = {}, enabled = false, label = { Text("${path.totalHops} hop(s)") })
            if (path.description.isNotBlank()) {
                Text(path.description, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            val chain = path.hops.joinToString(" -> ") { it.hostname.ifBlank { it.label } }
            if (chain.isNotBlank()) {
                Text(chain, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 2, overflow = TextOverflow.Ellipsis)
            }
            if (inFlight) {
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) { CircularProgressIndicator() }
            } else {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(
                        onClick = onResolve,
                        enabled = actionsEnabled,
                        modifier = Modifier.testTag(SshBastionTestTags.resolve(path.pathId)),
                    ) { Text("Resolve") }
                    OutlinedButton(
                        onClick = onDelete,
                        enabled = actionsEnabled,
                        modifier = Modifier.testTag(SshBastionTestTags.delete(path.pathId)),
                    ) { Text("Delete") }
                }
            }
        }
    }
}

@Composable
private fun BastionFormDialog(
    mutating: Boolean,
    onDismiss: () -> Unit,
    onSubmit: (CreateBastionPathReq) -> Unit,
) {
    var label by remember { mutableStateOf("") }
    var description by remember { mutableStateOf("") }
    var jumpHost by remember { mutableStateOf("") }
    var jumpUser by remember { mutableStateOf("") }
    var targetHost by remember { mutableStateOf("") }
    var targetUser by remember { mutableStateOf("") }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("New bastion path") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedTextField(
                    value = label,
                    onValueChange = { label = it },
                    label = { Text("Label") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag(SshBastionTestTags.FORM_LABEL),
                )
                OutlinedTextField(
                    value = description,
                    onValueChange = { description = it },
                    label = { Text("Description (optional)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Text("Jump host (bastion)", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
                OutlinedTextField(
                    value = jumpHost,
                    onValueChange = { jumpHost = it },
                    label = { Text("Jump hostname") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag(SshBastionTestTags.FORM_JUMP_HOST),
                )
                OutlinedTextField(
                    value = jumpUser,
                    onValueChange = { jumpUser = it },
                    label = { Text("Jump username") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Text("Target host", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
                OutlinedTextField(
                    value = targetHost,
                    onValueChange = { targetHost = it },
                    label = { Text("Target hostname") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag(SshBastionTestTags.FORM_TARGET_HOST),
                )
                OutlinedTextField(
                    value = targetUser,
                    onValueChange = { targetUser = it },
                    label = { Text("Target username") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        },
        confirmButton = {
            val valid = label.isNotBlank() && targetHost.isNotBlank() && targetUser.isNotBlank()
            TextButton(
                onClick = {
                    val jumps = if (jumpHost.isNotBlank()) {
                        listOf(BastionHopReq(hostname = jumpHost.trim(), username = jumpUser.trim(), label = "bastion"))
                    } else emptyList()
                    onSubmit(
                        CreateBastionPathReq(
                            label = label.trim(),
                            description = description.trim(),
                            jumpHops = jumps,
                            target = BastionHopReq(hostname = targetHost.trim(), username = targetUser.trim(), label = "target"),
                        ),
                    )
                },
                enabled = !mutating && valid,
                modifier = Modifier.testTag(SshBastionTestTags.FORM_CONFIRM),
            ) { Text(if (mutating) "Saving..." else "Create") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}
