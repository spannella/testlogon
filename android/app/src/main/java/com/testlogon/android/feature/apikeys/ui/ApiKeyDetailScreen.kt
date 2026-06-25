@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.testlogon.android.feature.apikeys.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.Edit
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.feature.apikeys.data.ApiKeyCapabilities

/** Batch 8 (#17, #18) - stable testTags for the API-key detail screen. */
object ApiKeyDetailTestTags {
    const val SCREEN = "api_key_detail_screen"
    const val SAVE_CAPS = "api_key_detail_save_caps"
    const val ADD_ALLOW = "api_key_detail_add_allow"
    const val ADD_DENY = "api_key_detail_add_deny"
    const val CIDR_DIALOG = "api_key_detail_cidr_dialog"
    const val CIDR_FIELD = "api_key_detail_cidr_field"
    const val CIDR_CONFIRM = "api_key_detail_cidr_confirm"

    fun cap(id: String) = "api_key_detail_cap_${id.replace(':', '_')}"
}

@Composable
fun ApiKeyDetailRoute(
    onBack: () -> Unit,
    onNavigateToLogin: () -> Unit,
    viewModel: ApiKeyDetailViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is ApiKeysEffect.NavigateToLogin -> onNavigateToLogin()
                is ApiKeysEffect.CreateSucceeded -> Unit
            }
        }
    }

    ApiKeyDetailScreen(
        state = state,
        onBack = onBack,
        onToggleCapability = viewModel::toggleCapability,
        onSaveCapabilities = viewModel::saveCapabilities,
        onAddAllow = viewModel::addAllow,
        onEditAllow = viewModel::editAllow,
        onRemoveAllow = viewModel::removeAllow,
        onAddDeny = viewModel::addDeny,
        onEditDeny = viewModel::editDeny,
        onRemoveDeny = viewModel::removeDeny,
    )
}

@Composable
fun ApiKeyDetailScreen(
    state: ApiKeyDetailUiState,
    onBack: () -> Unit,
    onToggleCapability: (String) -> Unit,
    onSaveCapabilities: () -> Unit,
    onAddAllow: (String) -> Unit,
    onEditAllow: (String, String) -> Unit,
    onRemoveAllow: (String) -> Unit,
    onAddDeny: (String) -> Unit,
    onEditDeny: (String, String) -> Unit,
    onRemoveDeny: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    // null = closed; non-null = the dialog config (which list + optional value being edited).
    var dialog by remember { mutableStateOf<CidrDialog?>(null) }

    Scaffold(
        modifier = modifier.testTag(ApiKeyDetailTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = state.label.ifBlank { stringResource(R.string.api_keys_unnamed) },
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.api_keys_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when {
                state.loading -> CircularProgressIndicator(Modifier.align(Alignment.Center))
                state.loadError != null -> Text(
                    text = state.loadError,
                    modifier = Modifier.align(Alignment.Center).padding(24.dp),
                    style = MaterialTheme.typography.bodyLarge,
                )
                else -> Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .verticalScroll(rememberScrollState())
                        .padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(16.dp),
                ) {
                    if (state.prefix.isNotBlank()) {
                        Text(
                            text = state.prefix + "…",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }

                    CapabilitiesSection(
                        state = state,
                        onToggle = onToggleCapability,
                        onSave = onSaveCapabilities,
                    )

                    IpRulesSection(
                        title = stringResource(R.string.api_keys_ip_allow_title),
                        hint = stringResource(R.string.api_keys_ip_allow_hint),
                        cidrs = state.allowCidrs,
                        saving = state.savingIpRules,
                        addTestTag = ApiKeyDetailTestTags.ADD_ALLOW,
                        onAdd = { dialog = CidrDialog(deny = false, original = null) },
                        onEdit = { dialog = CidrDialog(deny = false, original = it) },
                        onRemove = onRemoveAllow,
                    )

                    IpRulesSection(
                        title = stringResource(R.string.api_keys_ip_deny_title),
                        hint = stringResource(R.string.api_keys_ip_deny_hint),
                        cidrs = state.denyCidrs,
                        saving = state.savingIpRules,
                        addTestTag = ApiKeyDetailTestTags.ADD_DENY,
                        onAdd = { dialog = CidrDialog(deny = true, original = null) },
                        onEdit = { dialog = CidrDialog(deny = true, original = it) },
                        onRemove = onRemoveDeny,
                    )

                    if (state.ipRuleError != null) {
                        Text(
                            text = state.ipRuleError,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error,
                        )
                    }
                }
            }
        }
    }

    dialog?.let { cfg ->
        CidrInputDialog(
            initial = cfg.original.orEmpty(),
            onDismiss = { dialog = null },
            onConfirm = { value ->
                when {
                    cfg.deny && cfg.original != null -> onEditDeny(cfg.original, value)
                    cfg.deny -> onAddDeny(value)
                    cfg.original != null -> onEditAllow(cfg.original, value)
                    else -> onAddAllow(value)
                }
                dialog = null
            },
        )
    }
}

private data class CidrDialog(val deny: Boolean, val original: String?)

@Composable
private fun CapabilitiesSection(
    state: ApiKeyDetailUiState,
    onToggle: (String) -> Unit,
    onSave: () -> Unit,
) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                text = stringResource(R.string.api_keys_caps_title),
                style = MaterialTheme.typography.titleMedium,
            )
            ApiKeyCapabilities.GROUPED.forEach { (group, caps) ->
                Text(
                    text = group,
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 4.dp),
                )
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    caps.forEach { cap ->
                        val selected = cap.id in state.editedCapabilities
                        FilterChip(
                            selected = selected,
                            onClick = { onToggle(cap.id) },
                            enabled = !state.savingCapabilities,
                            label = { Text(cap.action) },
                            leadingIcon = if (selected) {
                                { Icon(Icons.Filled.Check, contentDescription = null, modifier = Modifier.size(18.dp)) }
                            } else {
                                null
                            },
                            modifier = Modifier.testTag(ApiKeyDetailTestTags.cap(cap.id)),
                        )
                    }
                }
            }
            if (state.capabilityError != null) {
                Text(
                    text = state.capabilityError,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
            Button(
                onClick = onSave,
                enabled = state.capabilitiesDirty && !state.savingCapabilities,
                modifier = Modifier.testTag(ApiKeyDetailTestTags.SAVE_CAPS),
            ) {
                if (state.savingCapabilities) {
                    CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(18.dp))
                } else {
                    Text(stringResource(R.string.api_keys_caps_save))
                }
            }
        }
    }
}

@Composable
private fun IpRulesSection(
    title: String,
    hint: String,
    cidrs: List<String>,
    saving: Boolean,
    addTestTag: String,
    onAdd: () -> Unit,
    onEdit: (String) -> Unit,
    onRemove: (String) -> Unit,
) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(text = title, style = MaterialTheme.typography.titleMedium)
            Text(
                text = hint,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (cidrs.isEmpty()) {
                Text(
                    text = stringResource(R.string.api_keys_ip_none),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                cidrs.forEach { cidr ->
                    Row(
                        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Text(
                            text = cidr,
                            style = MaterialTheme.typography.bodyLarge,
                            modifier = Modifier.weight(1f),
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                        IconButton(onClick = { onEdit(cidr) }, enabled = !saving) {
                            Icon(
                                Icons.Outlined.Edit,
                                contentDescription = stringResource(R.string.api_keys_ip_edit),
                            )
                        }
                        IconButton(onClick = { onRemove(cidr) }, enabled = !saving) {
                            Icon(
                                Icons.Outlined.Close,
                                contentDescription = stringResource(R.string.api_keys_ip_remove),
                                tint = MaterialTheme.colorScheme.error,
                            )
                        }
                    }
                }
            }
            OutlinedButton(
                onClick = onAdd,
                enabled = !saving,
                modifier = Modifier.testTag(addTestTag),
            ) {
                Icon(Icons.Outlined.Add, contentDescription = null, modifier = Modifier.size(18.dp))
                Text(stringResource(R.string.api_keys_ip_add))
            }
        }
    }
}

@Composable
private fun CidrInputDialog(
    initial: String,
    onDismiss: () -> Unit,
    onConfirm: (String) -> Unit,
) {
    var value by remember { mutableStateOf(initial) }
    AlertDialog(
        modifier = Modifier.testTag(ApiKeyDetailTestTags.CIDR_DIALOG),
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.api_keys_ip_dialog_title)) },
        text = {
            OutlinedTextField(
                value = value,
                onValueChange = { value = it },
                singleLine = true,
                label = { Text(stringResource(R.string.api_keys_ip_dialog_label)) },
                placeholder = { Text("203.0.113.0/24") },
                modifier = Modifier.fillMaxWidth().testTag(ApiKeyDetailTestTags.CIDR_FIELD),
            )
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(value) },
                enabled = value.isNotBlank(),
                modifier = Modifier.testTag(ApiKeyDetailTestTags.CIDR_CONFIRM),
            ) {
                Text(stringResource(R.string.api_keys_ip_dialog_save))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.action_cancel)) }
        },
    )
}
