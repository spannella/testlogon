@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.sshkeys

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
import androidx.compose.material.icons.outlined.VpnKey
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
import androidx.compose.material3.TabRow
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
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
import com.testlogon.android.data.sshkeys.SshKeyDto
import com.testlogon.android.feature.infracommon.InfraDropdown
import com.testlogon.android.feature.infracommon.infraErrorMessage

object SshKeysTestTags {
    const val SCREEN = "sshkeys_screen"
    const val LIST = "sshkeys_list"
    const val EMPTY = "sshkeys_empty"
    const val FORBIDDEN = "sshkeys_forbidden"
    const val ERROR_RETRY = "sshkeys_error_retry"
    const val ADD = "sshkeys_add_open"
    const val FORM_LABEL = "sshkeys_form_label"
    const val FORM_PEM = "sshkeys_form_pem"
    const val FORM_CONFIRM = "sshkeys_form_confirm"
    fun row(id: String) = "sshkeys_row_$id"
    fun show(id: String) = "sshkeys_show_$id"
    fun delete(id: String) = "sshkeys_delete_$id"
}

@Composable
fun SshKeysRoute(
    onBack: () -> Unit,
    viewModel: SshKeysViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    SshKeysScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
        onGenerate = viewModel::generate,
        onUpload = viewModel::upload,
        onDelete = viewModel::delete,
        onShowPublicKey = viewModel::showPublicKey,
        onDismissPublicKey = viewModel::dismissPublicKey,
        onMessageShown = viewModel::clearMessage,
    )
}

@Composable
fun SshKeysScreen(
    state: SshKeysUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onGenerate: (String, String, Int) -> Unit,
    onUpload: (String, String, String?) -> Unit,
    onDelete: (String) -> Unit,
    onShowPublicKey: (String) -> Unit,
    onDismissPublicKey: () -> Unit,
    onMessageShown: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbar = remember { SnackbarHostState() }
    var showForm by remember { mutableStateOf(false) }
    var deleteTarget by remember { mutableStateOf<SshKeyDto?>(null) }
    val clipboard = LocalClipboardManager.current

    LaunchedEffect(state.message, state.transientError) {
        val msg = state.message ?: state.transientError?.let { infraErrorMessage(it) }
        if (msg != null) { snackbar.showSnackbar(msg); onMessageShown() }
    }

    Scaffold(
        modifier = modifier.testTag(SshKeysTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text("SSH keys") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(
                        onClick = { showForm = true },
                        enabled = state.data !is SshKeysDataState.Forbidden,
                        modifier = Modifier.testTag(SshKeysTestTags.ADD),
                    ) { Icon(Icons.Outlined.Add, contentDescription = "Add key") }
                },
            )
        },
    ) { padding ->
        val isRefreshing = (state.data as? SshKeysDataState.Content)?.isRefreshing == true
        PullToRefreshBox(
            isRefreshing = isRefreshing,
            onRefresh = onRefresh,
            modifier = Modifier.fillMaxSize().padding(padding),
        ) {
            when (val d = state.data) {
                is SshKeysDataState.Loading -> LoadingState()
                is SshKeysDataState.Empty -> EmptyState(
                    modifier = Modifier.testTag(SshKeysTestTags.EMPTY),
                    title = "No SSH keys",
                    body = "Generate a new key pair or import an existing private key.",
                    imageVector = Icons.Outlined.VpnKey,
                    actionLabel = "Add key",
                    onAction = { showForm = true },
                )
                is SshKeysDataState.Forbidden -> EmptyState(
                    modifier = Modifier.testTag(SshKeysTestTags.FORBIDDEN),
                    title = "Not authorised",
                    body = "You do not have access to SSH keys.",
                    imageVector = Icons.Outlined.Lock,
                    actionLabel = "Back",
                    onAction = onBack,
                )
                is SshKeysDataState.Error -> ErrorState(
                    modifier = Modifier.testTag(SshKeysTestTags.ERROR_RETRY),
                    message = infraErrorMessage(d.type),
                    onRetry = onRetry,
                )
                is SshKeysDataState.Content -> LazyColumn(
                    modifier = Modifier.fillMaxSize().testTag(SshKeysTestTags.LIST),
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    items(items = d.keys, key = { it.keyId }) { key ->
                        SshKeyRow(
                            key = key,
                            inFlight = state.actionInFlightId == key.keyId,
                            actionsEnabled = state.actionInFlightId == null,
                            onShow = { onShowPublicKey(key.keyId) },
                            onDelete = { deleteTarget = key },
                        )
                    }
                }
            }
        }
    }

    if (showForm) {
        AddKeyDialog(
            mutating = state.mutating,
            onDismiss = { showForm = false },
            onGenerate = { label, type, bits -> onGenerate(label, type, bits); showForm = false },
            onUpload = { label, pem, pass -> onUpload(label, pem, pass); showForm = false },
        )
    }

    deleteTarget?.let { key ->
        AlertDialog(
            onDismissRequest = { deleteTarget = null },
            title = { Text("Delete key?") },
            text = { Text("Delete \"${key.label}\"? This cannot be undone.") },
            confirmButton = {
                TextButton(onClick = { onDelete(key.keyId); deleteTarget = null }) { Text("Delete") }
            },
            dismissButton = { TextButton(onClick = { deleteTarget = null }) { Text("Cancel") } },
        )
    }

    state.publicKey?.let { pk ->
        AlertDialog(
            onDismissRequest = onDismissPublicKey,
            title = { Text("Public key") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(pk.publicKeyFingerprint, style = MaterialTheme.typography.labelMedium)
                    Text(pk.publicKeyOpenssh, style = MaterialTheme.typography.bodySmall)
                }
            },
            confirmButton = {
                TextButton(onClick = { clipboard.setText(AnnotatedString(pk.publicKeyOpenssh)) }) { Text("Copy") }
            },
            dismissButton = { TextButton(onClick = onDismissPublicKey) { Text("Close") } },
        )
    }
}

@Composable
private fun SshKeyRow(
    key: SshKeyDto,
    inFlight: Boolean,
    actionsEnabled: Boolean,
    onShow: () -> Unit,
    onDelete: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().testTag(SshKeysTestTags.row(key.keyId))) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                key.label.ifBlank { key.keyId },
                style = MaterialTheme.typography.titleSmall,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                AssistChip(onClick = {}, enabled = false, label = { Text("${key.keyType} ${key.keyBits}") })
                if (key.passphraseProtected) {
                    AssistChip(onClick = {}, enabled = false, label = { Text("passphrase") })
                }
            }
            if (key.publicKeyFingerprint.isNotBlank()) {
                Text(
                    key.publicKeyFingerprint,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Text(
                "Used ${key.useCount} time(s) - ${key.associatedHosts.size} host(s)",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (inFlight) {
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) { CircularProgressIndicator() }
            } else {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(
                        onClick = onShow,
                        enabled = actionsEnabled,
                        modifier = Modifier.testTag(SshKeysTestTags.show(key.keyId)),
                    ) { Text("Public key") }
                    OutlinedButton(
                        onClick = onDelete,
                        enabled = actionsEnabled,
                        modifier = Modifier.testTag(SshKeysTestTags.delete(key.keyId)),
                    ) { Text("Delete") }
                }
            }
        }
    }
}

@Composable
private fun AddKeyDialog(
    mutating: Boolean,
    onDismiss: () -> Unit,
    onGenerate: (String, String, Int) -> Unit,
    onUpload: (String, String, String?) -> Unit,
) {
    var tab by remember { mutableIntStateOf(0) }
    var label by remember { mutableStateOf("") }
    // generate
    var keyType by remember { mutableStateOf("ed25519") }
    var keyBits by remember { mutableIntStateOf(4096) }
    // upload
    var pem by remember { mutableStateOf("") }
    var passphrase by remember { mutableStateOf("") }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Add SSH key") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                TabRow(selectedTabIndex = tab) {
                    Tab(selected = tab == 0, onClick = { tab = 0 }, text = { Text("Generate") })
                    Tab(selected = tab == 1, onClick = { tab = 1 }, text = { Text("Import") })
                }
                OutlinedTextField(
                    value = label,
                    onValueChange = { label = it },
                    label = { Text("Label") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag(SshKeysTestTags.FORM_LABEL),
                )
                if (tab == 0) {
                    InfraDropdown(
                        label = "Key type",
                        options = listOf("ed25519", "rsa"),
                        selected = keyType,
                        labelFor = { it },
                        onSelect = { keyType = it },
                        fieldTestTag = "sshkeys_form_type",
                    )
                    if (keyType == "rsa") {
                        InfraDropdown(
                            label = "Key bits",
                            options = listOf(2048, 4096, 8192),
                            selected = keyBits,
                            labelFor = { it.toString() },
                            onSelect = { keyBits = it },
                            fieldTestTag = "sshkeys_form_bits",
                        )
                    }
                } else {
                    OutlinedTextField(
                        value = pem,
                        onValueChange = { pem = it },
                        label = { Text("Private key (PEM)") },
                        minLines = 3,
                        maxLines = 6,
                        modifier = Modifier.fillMaxWidth().testTag(SshKeysTestTags.FORM_PEM),
                    )
                    OutlinedTextField(
                        value = passphrase,
                        onValueChange = { passphrase = it },
                        label = { Text("Passphrase (optional)") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
            }
        },
        confirmButton = {
            val valid = label.isNotBlank() && (tab == 0 || pem.isNotBlank())
            TextButton(
                onClick = {
                    if (tab == 0) onGenerate(label, keyType, if (keyType == "rsa") keyBits else 4096)
                    else onUpload(label, pem, passphrase)
                },
                enabled = !mutating && valid,
                modifier = Modifier.testTag(SshKeysTestTags.FORM_CONFIRM),
            ) { Text(if (mutating) "Working..." else if (tab == 0) "Generate" else "Import") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}
