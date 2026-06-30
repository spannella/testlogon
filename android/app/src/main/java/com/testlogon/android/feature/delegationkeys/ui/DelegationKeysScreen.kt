@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.delegationkeys.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material.icons.outlined.VpnKey
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
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
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.OfflineBanner
import com.testlogon.android.feature.delegationkeys.data.DelegationApiKey

/** Stable testTags for the delegation-API keys screen. */
object DelegationKeysTestTags {
    const val SCREEN = "delegation_keys_screen"
    const val TAB_MINE = "delegation_keys_tab_mine"
    const val TAB_CREATOR = "delegation_keys_tab_creator"
    const val CREATE_FAB = "delegation_keys_create_fab"
    const val EMPTY = "delegation_keys_empty"
    const val SECRET_DIALOG = "delegation_keys_secret_dialog"
    const val SECRET_COPY = "delegation_keys_secret_copy"
    const val CREATE_DIALOG = "delegation_keys_create_dialog"
    const val CREATE_LABEL = "delegation_keys_create_label"
    const val CREATE_SUBMIT = "delegation_keys_create_submit"

    fun row(id: String) = "delegation_key_row_$id"
    fun revoke(id: String) = "delegation_key_revoke_$id"
}

/** Route-level entry for the delegation-API keys screen. */
@Composable
fun DelegationKeysRoute(
    onBack: () -> Unit,
    viewModel: DelegationKeysViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val createForm by viewModel.createForm.collectAsStateWithLifecycle()
    DelegationKeysScreen(
        state = state,
        createForm = createForm,
        onBack = onBack,
        onRetry = viewModel::retry,
        onRefresh = viewModel::refresh,
        onSelectTab = viewModel::selectTab,
        onRevoke = viewModel::revoke,
        onDismissSecret = viewModel::dismissSecret,
        onOpenCreate = viewModel::openCreate,
        onDismissCreate = viewModel::dismissCreate,
        onLabelChange = viewModel::onLabelChange,
        onCreatorChange = viewModel::onCreatorChange,
        onTogglePermission = viewModel::onTogglePermission,
        onSubmitCreate = viewModel::submitCreate,
    )
}

@Composable
fun DelegationKeysScreen(
    state: DelegationKeysUiState,
    createForm: CreateDelegationKeyForm,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onRefresh: () -> Unit,
    onSelectTab: (DelegationKeysTab) -> Unit,
    onRevoke: (String) -> Unit,
    onDismissSecret: () -> Unit,
    onOpenCreate: () -> Unit,
    onDismissCreate: () -> Unit,
    onLabelChange: (String) -> Unit,
    onCreatorChange: (String) -> Unit,
    onTogglePermission: (String, Boolean) -> Unit,
    onSubmitCreate: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(DelegationKeysTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.delegation_keys_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.delegation_keys_back))
                    }
                },
            )
        },
        floatingActionButton = {
            if (state is DelegationKeysUiState.Content) {
                FloatingActionButton(
                    onClick = onOpenCreate,
                    modifier = Modifier.testTag(DelegationKeysTestTags.CREATE_FAB),
                ) {
                    Icon(Icons.Outlined.Add, contentDescription = stringResource(R.string.delegation_keys_create_title))
                }
            }
        },
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            when (state) {
                is DelegationKeysUiState.Loading -> LoadingState()
                is DelegationKeysUiState.Error -> ErrorState(message = state.message, onRetry = onRetry)
                is DelegationKeysUiState.Content -> ContentBody(
                    state = state,
                    onRefresh = onRefresh,
                    onRetry = onRetry,
                    onSelectTab = onSelectTab,
                    onRevoke = onRevoke,
                )
            }
        }
    }

    val secret = (state as? DelegationKeysUiState.Content)?.newSecret
    if (secret != null) {
        SecretDialog(secret = secret, onDismiss = onDismissSecret)
    }

    if (createForm.visible) {
        CreateDialog(
            form = createForm,
            onLabelChange = onLabelChange,
            onCreatorChange = onCreatorChange,
            onTogglePermission = onTogglePermission,
            onSubmit = onSubmitCreate,
            onDismiss = onDismissCreate,
        )
    }
}

@Composable
private fun ContentBody(
    state: DelegationKeysUiState.Content,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onSelectTab: (DelegationKeysTab) -> Unit,
    onRevoke: (String) -> Unit,
) {
    TabRow(selectedTabIndex = if (state.tab == DelegationKeysTab.MINE) 0 else 1) {
        Tab(
            selected = state.tab == DelegationKeysTab.MINE,
            onClick = { onSelectTab(DelegationKeysTab.MINE) },
            text = { Text(stringResource(R.string.delegation_keys_tab_mine)) },
            modifier = Modifier.testTag(DelegationKeysTestTags.TAB_MINE),
        )
        Tab(
            selected = state.tab == DelegationKeysTab.CREATOR,
            onClick = { onSelectTab(DelegationKeysTab.CREATOR) },
            text = { Text(stringResource(R.string.delegation_keys_tab_creator)) },
            modifier = Modifier.testTag(DelegationKeysTestTags.TAB_CREATOR),
        )
    }
    if (state.isStale) {
        OfflineBanner(onRetry = onRetry)
    }
    if (state.actionError != null) {
        Text(
            text = state.actionError,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.error,
            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
        )
    }
    val keys = if (state.tab == DelegationKeysTab.MINE) state.myKeys else state.creatorKeys
    PullToRefreshBox(
        isRefreshing = state.isRefreshing,
        onRefresh = onRefresh,
        modifier = Modifier.fillMaxSize(),
    ) {
        if (keys.isEmpty()) {
            EmptyState(
                modifier = Modifier.testTag(DelegationKeysTestTags.EMPTY),
                title = stringResource(
                    if (state.tab == DelegationKeysTab.MINE) {
                        R.string.delegation_keys_empty_mine
                    } else {
                        R.string.delegation_keys_empty_creator
                    },
                ),
                imageVector = Icons.Outlined.VpnKey,
            )
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                items(items = keys, key = { it.keyId }) { key ->
                    KeyRow(
                        key = key,
                        revoking = state.revokingId == key.keyId,
                        onRevoke = { onRevoke(key.keyId) },
                    )
                }
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun KeyRow(
    key: DelegationApiKey,
    revoking: Boolean,
    onRevoke: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().testTag(DelegationKeysTestTags.row(key.keyId))) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(
                    text = key.label.ifBlank { key.keyId },
                    style = MaterialTheme.typography.titleSmall,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = stringResource(R.string.delegation_keys_status_creator, key.status, key.creatorId),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    text = stringResource(
                        R.string.delegation_keys_meta,
                        key.prefix.ifBlank { "-" },
                        key.totalCalls,
                        key.rateLimitRpm,
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (key.permissions.isNotEmpty()) {
                    FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        key.permissions.forEach { perm ->
                            AssistChip(onClick = {}, label = { Text(perm, style = MaterialTheme.typography.labelSmall) })
                        }
                    }
                }
            }
            if (revoking) {
                CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(20.dp))
            } else {
                IconButton(onClick = onRevoke, modifier = Modifier.testTag(DelegationKeysTestTags.revoke(key.keyId))) {
                    Icon(
                        Icons.Outlined.Delete,
                        contentDescription = stringResource(R.string.delegation_keys_revoke),
                        tint = MaterialTheme.colorScheme.error,
                    )
                }
            }
        }
    }
}

@Composable
private fun CreateDialog(
    form: CreateDelegationKeyForm,
    onLabelChange: (String) -> Unit,
    onCreatorChange: (String) -> Unit,
    onTogglePermission: (String, Boolean) -> Unit,
    onSubmit: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        modifier = Modifier.testTag(DelegationKeysTestTags.CREATE_DIALOG),
        onDismissRequest = { if (!form.submitting) onDismiss() },
        title = { Text(stringResource(R.string.delegation_keys_create_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedTextField(
                    value = form.label,
                    onValueChange = onLabelChange,
                    singleLine = true,
                    label = { Text(stringResource(R.string.delegation_keys_create_label_field)) },
                    modifier = Modifier.fillMaxWidth().testTag(DelegationKeysTestTags.CREATE_LABEL),
                )
                CreatorSelector(form = form, onCreatorChange = onCreatorChange)
                Text(
                    text = stringResource(R.string.delegation_keys_permissions),
                    style = MaterialTheme.typography.labelLarge,
                )
                DelegationPermissions.ALL.forEach { perm ->
                    val allowed = form.creatorId.isBlank() || perm in form.allowedForSelected
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(
                            checked = perm in form.permissions,
                            enabled = allowed,
                            onCheckedChange = { checked -> onTogglePermission(perm, checked) },
                        )
                        Text(
                            text = perm,
                            style = MaterialTheme.typography.bodyMedium,
                            color = if (allowed) {
                                MaterialTheme.colorScheme.onSurface
                            } else {
                                MaterialTheme.colorScheme.onSurfaceVariant
                            },
                        )
                    }
                }
                val err = form.submitError
                if (err != null) {
                    Text(text = err, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                }
            }
        },
        confirmButton = {
            Button(
                onClick = onSubmit,
                enabled = form.canSubmit,
                modifier = Modifier.testTag(DelegationKeysTestTags.CREATE_SUBMIT),
            ) {
                if (form.submitting) {
                    CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                } else {
                    Text(stringResource(R.string.delegation_keys_create_submit))
                }
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss, enabled = !form.submitting) {
                Text(stringResource(R.string.delegation_keys_create_cancel))
            }
        },
    )
}

@Composable
private fun CreatorSelector(
    form: CreateDelegationKeyForm,
    onCreatorChange: (String) -> Unit,
) {
    var expanded by remember { mutableStateOf(false) }
    val selectedLabel = form.creators.firstOrNull { it.creatorId == form.creatorId }?.label
        ?: stringResource(R.string.delegation_keys_select_creator)
    ExposedDropdownMenuBox(expanded = expanded, onExpandedChange = { expanded = !expanded }) {
        OutlinedTextField(
            value = selectedLabel,
            onValueChange = {},
            readOnly = true,
            label = { Text(stringResource(R.string.delegation_keys_creator)) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier.fillMaxWidth().menuAnchor(),
        )
        ExposedDropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false },
        ) {
            form.creators.forEach { creator ->
                DropdownMenuItem(
                    text = { Text(creator.label) },
                    onClick = {
                        onCreatorChange(creator.creatorId)
                        expanded = false
                    },
                )
            }
        }
    }
}

@Composable
private fun SecretDialog(secret: String, onDismiss: () -> Unit) {
    val clipboard = LocalClipboardManager.current
    var copied by remember { mutableStateOf(false) }
    AlertDialog(
        modifier = Modifier.testTag(DelegationKeysTestTags.SECRET_DIALOG),
        onDismissRequest = onDismiss,
        icon = { Icon(Icons.Outlined.VpnKey, contentDescription = null) },
        title = { Text(stringResource(R.string.delegation_keys_secret_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(stringResource(R.string.delegation_keys_secret_warning))
                Card {
                    Text(
                        text = secret,
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.fillMaxWidth().padding(12.dp),
                    )
                }
                if (copied) {
                    Text(
                        text = stringResource(R.string.delegation_keys_secret_copied),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.primary,
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.delegation_keys_secret_done)) }
        },
        dismissButton = {
            TextButton(
                onClick = {
                    clipboard.setText(AnnotatedString(secret))
                    copied = true
                },
                modifier = Modifier.testTag(DelegationKeysTestTags.SECRET_COPY),
            ) {
                Icon(Icons.Outlined.ContentCopy, contentDescription = null, modifier = Modifier.size(18.dp))
                Text(stringResource(R.string.delegation_keys_secret_copy))
            }
        },
    )
}
