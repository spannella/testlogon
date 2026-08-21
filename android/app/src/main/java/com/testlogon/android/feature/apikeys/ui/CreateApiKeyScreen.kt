@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.apikeys.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Check
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.error
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Card
import androidx.compose.material3.TextButton
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import com.testlogon.android.feature.apikeys.data.ApiKeyCapabilities
import com.testlogon.android.feature.apikeys.data.Protocol
import com.testlogon.android.feature.apikeys.data.ProtocolCredentials
import com.testlogon.android.feature.apikeys.data.TradingCredentialsFormat

/** B-APIKEY (batch 7) - stable testTags for the create-API-key screen. */
object CreateApiKeyTestTags {
    const val SCREEN = "api_keys_create_screen"
    const val LABEL_FIELD = "api_keys_create_label"
    const val SCOPES_FIELD = "api_keys_create_scopes"
    const val EXPIRES_FIELD = "api_keys_create_expires"
    const val SUBMIT = "api_keys_create_submit"

    /** Per-capability chip tag (batch 8 #17). */
    fun capability(id: String) = "api_keys_cap_${id.replace(':', '_')}"

    /** MULTI-PROTOCOL: per-protocol toggle chip tag + the show-once created-credentials dialog. */
    const val PROTOCOLS_ROW = "api_keys_create_protocols"
    const val CREDS_DIALOG = "api_keys_create_creds_dialog"
    const val CREDS_DISMISS = "api_keys_create_creds_dismiss"
    fun protocol(p: Protocol) = "api_keys_protocol_${p.wire}"
}

/**
 * B-APIKEY (batch 7) - route-level entry for the create screen. Collects the form, wires CreateSucceeded to a
 * back-pop carrying the one-time secret (the list shows it once) and NavigateToLogin to the re-auth handoff.
 */
@Composable
fun CreateApiKeyRoute(
    onBack: () -> Unit,
    onCreated: (secret: String) -> Unit,
    onNavigateToLogin: () -> Unit,
    onCreatedShown: () -> Unit = onBack,
    viewModel: CreateApiKeyViewModel = hiltViewModel(),
) {
    val form by viewModel.form.collectAsStateWithLifecycle()

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is ApiKeysEffect.CreateSucceeded -> onCreated(effect.secret)
                // MULTI-PROTOCOL: secret already shown show-once here; just pop back + refresh the list.
                is ApiKeysEffect.CreateSucceededShown -> onCreatedShown()
                is ApiKeysEffect.NavigateToLogin -> onNavigateToLogin()
            }
        }
    }

    CreateApiKeyScreen(
        form = form,
        onBack = onBack,
        onLabelChange = viewModel::onLabelChange,
        onToggleCapability = viewModel::onToggleCapability,
        onToggleProtocol = viewModel::onToggleProtocol,
        onExpiresChange = viewModel::onExpiresChange,
        onSubmit = viewModel::submit,
        onDismissCredentials = viewModel::dismissCreatedCredentials,
    )
}

/** B-APIKEY (batch 7) - stateless create form (label + optional scopes + optional expiry-days + gated submit). */
@Composable
fun CreateApiKeyScreen(
    form: CreateApiKeyForm,
    onBack: () -> Unit,
    onLabelChange: (String) -> Unit,
    onToggleCapability: (String) -> Unit,
    onExpiresChange: (String) -> Unit,
    onSubmit: () -> Unit,
    onToggleProtocol: (Protocol) -> Unit = {},
    onDismissCredentials: () -> Unit = {},
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(CreateApiKeyTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.api_keys_create_title)) },
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
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            val labelError = form.labelError
            OutlinedTextField(
                value = form.label,
                onValueChange = onLabelChange,
                label = { Text(stringResource(R.string.api_keys_create_label_label)) },
                placeholder = { Text(stringResource(R.string.api_keys_create_label_placeholder)) },
                singleLine = true,
                isError = labelError != null,
                supportingText = {
                    if (labelError != null) Text(labelError)
                    else Text(stringResource(R.string.api_keys_create_label_hint))
                },
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next),
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(CreateApiKeyTestTags.LABEL_FIELD)
                    .then(if (labelError != null) Modifier.semantics { error(labelError) } else Modifier),
            )

            CapabilityMultiSelect(
                selected = form.selectedCapabilities,
                onToggle = onToggleCapability,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(CreateApiKeyTestTags.SCOPES_FIELD),
            )

            ProtocolMultiSelect(
                selected = form.selectedProtocols,
                gateway = form.gateway,
                errors = form.protocolErrors,
                onToggle = onToggleProtocol,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(CreateApiKeyTestTags.PROTOCOLS_ROW),
            )

            OutlinedTextField(
                value = form.expiresInDays,
                onValueChange = onExpiresChange,
                label = { Text(stringResource(R.string.api_keys_create_expires_label)) },
                placeholder = { Text(stringResource(R.string.api_keys_create_expires_placeholder)) },
                singleLine = true,
                supportingText = { Text(stringResource(R.string.api_keys_create_expires_hint)) },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number, imeAction = ImeAction.Done),
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(CreateApiKeyTestTags.EXPIRES_FIELD),
            )

            if (form.submitError != null) {
                Text(
                    text = form.submitError,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.error,
                )
            }

            Button(
                onClick = onSubmit,
                enabled = form.canSubmit && !form.submitting,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(CreateApiKeyTestTags.SUBMIT),
            ) {
                if (form.submitting) {
                    CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.heightIn(max = 20.dp))
                } else {
                    Text(stringResource(R.string.api_keys_create_submit))
                }
            }
        }
    }

    val creds = form.createdProtocolCredentials
    if (creds != null) {
        CreatedCredentialsDialog(
            apiSecret = form.createdApiSecret,
            creds = creds,
            onDismiss = onDismissCredentials,
        )
    }
}

/**
 * Batch 8 (#17) - labelled multi-select of the canonical capability catalog, grouped by product area, rendered
 * as toggleable [FilterChip]s. Selecting nothing -> the backend applies its default scopes.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun CapabilityMultiSelect(
    selected: Set<String>,
    onToggle: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier, verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            text = stringResource(R.string.api_keys_create_scopes_label),
            style = MaterialTheme.typography.titleSmall,
        )
        Text(
            text = stringResource(R.string.api_keys_create_scopes_hint),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
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
                    val isSelected = cap.id in selected
                    FilterChip(
                        selected = isSelected,
                        onClick = { onToggle(cap.id) },
                        label = { Text(cap.action) },
                        leadingIcon = if (isSelected) {
                            {
                                Icon(
                                    Icons.Filled.Check,
                                    contentDescription = null,
                                    modifier = Modifier.heightIn(max = 18.dp),
                                )
                            }
                        } else {
                            null
                        },
                        colors = FilterChipDefaults.filterChipColors(),
                        modifier = Modifier.testTag(CreateApiKeyTestTags.capability(cap.id)),
                    )
                }
            }
        }
    }
}

/**
 * MULTI-PROTOCOL — a toggle row of the four transport protocols (REST/WS/FIX/Binary) with a per-protocol
 * gateway-availability hint (from GET me/gateway/endpoints) and an inline scope-requirement error when the
 * selected protocol needs a scope the caller hasn't granted.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun ProtocolMultiSelect(
    selected: Set<Protocol>,
    gateway: com.testlogon.android.feature.apikeys.data.GatewayEndpoints?,
    errors: Map<Protocol, String>,
    onToggle: (Protocol) -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier, verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            text = stringResource(R.string.api_keys_protocols_label),
            style = MaterialTheme.typography.titleSmall,
        )
        Text(
            text = stringResource(R.string.api_keys_protocols_hint),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TradingCredentialsFormat.ALL_PROTOCOLS.forEach { protocol ->
                val isSelected = protocol in selected
                FilterChip(
                    selected = isSelected,
                    onClick = { onToggle(protocol) },
                    label = { Text(TradingCredentialsFormat.protocolLabel(protocol)) },
                    leadingIcon = if (isSelected) {
                        { Icon(Icons.Filled.Check, contentDescription = null, modifier = Modifier.heightIn(max = 18.dp)) }
                    } else {
                        null
                    },
                    colors = FilterChipDefaults.filterChipColors(),
                    modifier = Modifier.testTag(CreateApiKeyTestTags.protocol(protocol)),
                )
            }
        }
        // Per-protocol availability hint (degrades to "unknown" when the gateway endpoint is absent/404).
        TradingCredentialsFormat.ALL_PROTOCOLS.forEach { protocol ->
            val available: Boolean? = when (protocol) {
                Protocol.REST -> true
                Protocol.WS -> gateway?.wsEnabled
                Protocol.FIX -> gateway?.fixRunning
                Protocol.BINARY -> gateway?.binaryEnabled
            }
            val hint = when (available) {
                true -> stringResource(R.string.api_keys_protocol_hint_available)
                false -> stringResource(R.string.api_keys_protocol_hint_unavailable)
                null -> stringResource(R.string.api_keys_protocol_hint_unknown)
            }
            Text(
                text = "${TradingCredentialsFormat.protocolLabel(protocol)}: $hint",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        errors.values.forEach { message ->
            Text(
                text = message,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
            )
        }
    }
}

/**
 * MULTI-PROTOCOL — the SHOW-ONCE dialog surfacing the one-time API secret plus any provisioned WS/FIX/binary
 * credential material after a create. Dismissing pops back to the (refreshing) list without re-showing anything.
 */
@Composable
private fun CreatedCredentialsDialog(
    apiSecret: String?,
    creds: ProtocolCredentials,
    onDismiss: () -> Unit,
) {
    val clipboard = LocalClipboardManager.current
    AlertDialog(
        modifier = Modifier.testTag(CreateApiKeyTestTags.CREDS_DIALOG),
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.api_keys_created_creds_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    text = stringResource(R.string.api_keys_created_creds_warning),
                    style = MaterialTheme.typography.bodyMedium,
                )
                if (!apiSecret.isNullOrBlank()) {
                    SecretField(stringResource(R.string.api_keys_creds_api_secret), apiSecret, clipboard)
                }
                creds.wsToken?.let { SecretField(stringResource(R.string.api_keys_creds_ws_token), it, clipboard) }
                creds.fixUsername?.let { SecretField(stringResource(R.string.api_keys_creds_fix_username), it, clipboard) }
                creds.fixPassword?.let { SecretField(stringResource(R.string.api_keys_creds_fix_password), it, clipboard) }
                creds.binaryApiKey?.let { SecretField(stringResource(R.string.api_keys_creds_binary_api_key), it, clipboard) }
                creds.binarySecret?.let { SecretField(stringResource(R.string.api_keys_creds_binary_secret), it, clipboard) }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss, modifier = Modifier.testTag(CreateApiKeyTestTags.CREDS_DISMISS)) {
                Text(stringResource(R.string.api_keys_secret_done))
            }
        },
    )
}

/** A labelled monospace secret value with a Copy action. */
@Composable
private fun SecretField(
    label: String,
    value: String,
    clipboard: androidx.compose.ui.platform.ClipboardManager,
) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(text = label, style = MaterialTheme.typography.labelMedium)
            Text(
                text = value,
                style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
            )
            Spacer(Modifier.height(2.dp))
            AssistChip(
                onClick = { clipboard.setText(AnnotatedString(value)) },
                label = { Text(stringResource(R.string.api_keys_conn_copy)) },
            )
        }
    }
}
