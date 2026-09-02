@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.files.mounts

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material.icons.outlined.Edit
import androidx.compose.material.icons.outlined.Sync
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
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
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.feature.files.mounts.data.FileMount
import kotlinx.coroutines.flow.collectLatest

/** FM-MOUNTS stable testTags for the Mounts management screen. */
object MountsTestTags {
    const val SCREEN = "mounts_screen"
    const val LIST = "mounts_list"
    const val EMPTY = "mounts_empty"
    const val UNAVAILABLE = "mounts_unavailable"
    const val ROW = "mount_row"
    const val ADD = "mounts_add"
    const val EDITOR = "mounts_editor"
    const val SAVE = "mounts_editor_save"
}

/**
 * FM-MOUNTS - route wrapper: collects the list + editor state, wires the snackbar event channel, and
 * delegates to the stateless [MountsScreen].
 */
@Composable
fun MountsRoute(
    onBack: () -> Unit,
    viewModel: MountsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val editor by viewModel.editor.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }

    LaunchedEffect(viewModel) {
        viewModel.events.collectLatest { event ->
            when (event) {
                is MountsEvent.Message -> snackbarHostState.showSnackbar(event.text)
            }
        }
    }

    MountsScreen(
        state = state,
        editor = editor,
        snackbarHostState = snackbarHostState,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::refresh,
        onAdd = viewModel::openAdd,
        onEdit = viewModel::openEdit,
        onValidate = viewModel::validate,
        onDelete = viewModel::delete,
        onEditorMountPath = viewModel::onMountPathChanged,
        onEditorBucket = viewModel::onBucketChanged,
        onEditorPrefix = viewModel::onPrefixChanged,
        onEditorMode = viewModel::onModeChanged,
        onEditorAuthRef = viewModel::onAuthRefChanged,
        onEditorStatus = viewModel::onStatusChanged,
        onEditorSave = viewModel::save,
        onEditorDismiss = viewModel::closeEditor,
    )
}

@Composable
fun MountsScreen(
    state: MountsUiState,
    editor: MountEditorState,
    snackbarHostState: SnackbarHostState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onAdd: () -> Unit,
    onEdit: (FileMount) -> Unit,
    onValidate: (FileMount) -> Unit,
    onDelete: (FileMount) -> Unit,
    onEditorMountPath: (String) -> Unit,
    onEditorBucket: (String) -> Unit,
    onEditorPrefix: (String) -> Unit,
    onEditorMode: (String) -> Unit,
    onEditorAuthRef: (String) -> Unit,
    onEditorStatus: (String) -> Unit,
    onEditorSave: () -> Unit,
    onEditorDismiss: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(MountsTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Storage mounts") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
        floatingActionButton = {
            if (state.available && state.errorMessage == null) {
                FloatingActionButton(onClick = onAdd, modifier = Modifier.testTag(MountsTestTags.ADD)) {
                    Icon(Icons.Outlined.Add, contentDescription = "Add mount")
                }
            }
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when {
                state.isLoading && state.isEmpty ->
                    LoadingState(message = "Loading mounts…")

                state.errorMessage != null ->
                    ErrorState(message = state.errorMessage, onRetry = onRetry)

                !state.available ->
                    EmptyState(
                        title = "Storage mounts unavailable",
                        body = "Mount management is not enabled in this environment.",
                        modifier = Modifier.testTag(MountsTestTags.UNAVAILABLE),
                    )

                state.isEmpty ->
                    EmptyState(
                        title = "No storage mounts",
                        body = "Add a storage provider to mount external buckets into your files.",
                        actionLabel = "Add mount",
                        onAction = onAdd,
                        modifier = Modifier.testTag(MountsTestTags.EMPTY),
                    )

                else -> PullToRefreshBox(
                    isRefreshing = state.isRefreshing,
                    onRefresh = onRefresh,
                    modifier = Modifier.fillMaxSize(),
                ) {
                    LazyColumn(modifier = Modifier.fillMaxSize().testTag(MountsTestTags.LIST)) {
                        items(items = state.mounts, key = { it.id }) { mount ->
                            MountRow(
                                mount = mount,
                                onEdit = { onEdit(mount) },
                                onValidate = { onValidate(mount) },
                                onDelete = { onDelete(mount) },
                            )
                        }
                    }
                }
            }
        }
    }

    if (editor.visible) {
        MountEditorDialog(
            editor = editor,
            onMountPath = onEditorMountPath,
            onBucket = onEditorBucket,
            onPrefix = onEditorPrefix,
            onMode = onEditorMode,
            onAuthRef = onEditorAuthRef,
            onStatus = onEditorStatus,
            onSave = onEditorSave,
            onDismiss = onEditorDismiss,
        )
    }
}

@Composable
private fun MountRow(
    mount: FileMount,
    onEdit: () -> Unit,
    onValidate: () -> Unit,
    onDelete: () -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 6.dp)
            .testTag(MountsTestTags.ROW),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(mount.mountPath, style = MaterialTheme.typography.titleMedium)
            Text(
                text = "${mount.provider} · ${mount.bucket}${mount.prefix?.let { "/$it" } ?: ""}",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                text = "${mountModeLabel(mount.mode)} · ${mountStatusLabel(mount.status)}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            mount.lastError?.let {
                Text(
                    text = it,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
            Row(
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                horizontalArrangement = Arrangement.End,
            ) {
                IconButton(onClick = onValidate) {
                    Icon(Icons.Outlined.Sync, contentDescription = "Test connection")
                }
                IconButton(onClick = onEdit) {
                    Icon(Icons.Outlined.Edit, contentDescription = "Edit mount")
                }
                IconButton(onClick = onDelete) {
                    Icon(Icons.Outlined.Delete, contentDescription = "Remove mount")
                }
            }
        }
    }
}

@Composable
private fun MountEditorDialog(
    editor: MountEditorState,
    onMountPath: (String) -> Unit,
    onBucket: (String) -> Unit,
    onPrefix: (String) -> Unit,
    onMode: (String) -> Unit,
    onAuthRef: (String) -> Unit,
    onStatus: (String) -> Unit,
    onSave: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        modifier = Modifier.testTag(MountsTestTags.EDITOR),
        title = { Text(if (editor.isEditing) "Edit mount" else "Add mount") },
        confirmButton = {
            TextButton(
                onClick = onSave,
                enabled = !editor.saving,
                modifier = Modifier.testTag(MountsTestTags.SAVE),
            ) { Text(if (editor.isEditing) "Save" else "Add") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss, enabled = !editor.saving) { Text("Cancel") }
        },
        text = {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedTextField(
                    value = editor.mountPath,
                    onValueChange = onMountPath,
                    label = { Text("Mount path") },
                    singleLine = true,
                    isError = editor.errors.errorFor(MountField.MOUNT_PATH) != null,
                    supportingText = { editor.errors.errorFor(MountField.MOUNT_PATH)?.let { Text(it) } },
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = editor.bucket,
                    onValueChange = onBucket,
                    label = { Text("Bucket") },
                    singleLine = true,
                    isError = editor.errors.errorFor(MountField.BUCKET) != null,
                    supportingText = { editor.errors.errorFor(MountField.BUCKET)?.let { Text(it) } },
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = editor.prefix,
                    onValueChange = onPrefix,
                    label = { Text("Prefix (optional)") },
                    singleLine = true,
                    isError = editor.errors.errorFor(MountField.PREFIX) != null,
                    supportingText = { editor.errors.errorFor(MountField.PREFIX)?.let { Text(it) } },
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = editor.authRef,
                    onValueChange = onAuthRef,
                    label = { Text("Credential reference") },
                    singleLine = true,
                    isError = editor.errors.errorFor(MountField.AUTH_REF) != null,
                    supportingText = { editor.errors.errorFor(MountField.AUTH_REF)?.let { Text(it) } },
                    modifier = Modifier.fillMaxWidth(),
                )
                EnumDropdown(
                    label = "Access mode",
                    value = editor.mode,
                    options = MOUNT_MODES,
                    optionLabel = ::mountModeLabel,
                    onSelected = onMode,
                )
                EnumDropdown(
                    label = "Status",
                    value = editor.status,
                    options = MOUNT_STATUSES,
                    optionLabel = ::mountStatusLabel,
                    onSelected = onStatus,
                )
            }
        },
    )
}

@Composable
private fun EnumDropdown(
    label: String,
    value: String,
    options: List<String>,
    optionLabel: (String) -> String,
    onSelected: (String) -> Unit,
) {
    var expanded by remember { mutableStateOf(false) }
    ExposedDropdownMenuBox(expanded = expanded, onExpandedChange = { expanded = it }) {
        OutlinedTextField(
            value = optionLabel(value),
            onValueChange = {},
            readOnly = true,
            label = { Text(label) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier.fillMaxWidth().menuAnchor(),
        )
        ExposedDropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false },
        ) {
            options.forEach { option ->
                DropdownMenuItem(
                    text = { Text(optionLabel(option)) },
                    onClick = {
                        onSelected(option)
                        expanded = false
                    },
                )
            }
        }
    }
}
