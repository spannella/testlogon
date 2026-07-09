@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.settings.msgprivacy

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.feature.admessaging.ui.AdMessagePrefsSection

/** TIP-B4 (TIP-404) — route-level entry for the message-privacy (pay-to-message) settings screen. */
@Composable
fun MessagePrivacyRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: MessagePrivacyViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    MessagePrivacyScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::load,
        onRequireChanged = viewModel::onRequireChanged,
        onMinTipChanged = viewModel::onMinTipChanged,
        onSave = viewModel::save,
        onAllowlistInputChanged = viewModel::onAllowlistInputChanged,
        onAddAllowlist = viewModel::addAllowlist,
        onRemoveAllowlist = viewModel::removeAllowlist,
        modifier = modifier,
    )
}

@Composable
fun MessagePrivacyScreen(
    state: MessagePrivacyUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onRequireChanged: (Boolean) -> Unit,
    onMinTipChanged: (String) -> Unit,
    onSave: () -> Unit,
    onAllowlistInputChanged: (String) -> Unit,
    onAddAllowlist: () -> Unit,
    onRemoveAllowlist: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(MessagePrivacyTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Message Privacy") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        when (state) {
            MessagePrivacyUiState.Loading -> LoadingState(modifier = Modifier.padding(padding))
            is MessagePrivacyUiState.Error -> ErrorState(
                message = state.message,
                onRetry = onRetry,
                modifier = Modifier.padding(padding).testTag(MessagePrivacyTestTags.ERROR_RETRY),
            )
            is MessagePrivacyUiState.Content -> Content(
                state = state,
                padding = padding,
                onRequireChanged = onRequireChanged,
                onMinTipChanged = onMinTipChanged,
                onSave = onSave,
                onAllowlistInputChanged = onAllowlistInputChanged,
                onAddAllowlist = onAddAllowlist,
                onRemoveAllowlist = onRemoveAllowlist,
            )
        }
    }
}

@Composable
private fun Content(
    state: MessagePrivacyUiState.Content,
    padding: androidx.compose.foundation.layout.PaddingValues,
    onRequireChanged: (Boolean) -> Unit,
    onMinTipChanged: (String) -> Unit,
    onSave: () -> Unit,
    onAllowlistInputChanged: (String) -> Unit,
    onAddAllowlist: () -> Unit,
    onRemoveAllowlist: (String) -> Unit,
) {
    val busy = state.saving || state.mutatingAllowlist != null
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(padding)
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        // --- Pay-to-message gate ---
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("Require a tip to message", style = MaterialTheme.typography.titleMedium)
                Text(
                    "When on, a new person must attach a tip to send you their first message. The tip " +
                        "is credited to you as earnings (minus the platform fee) and is non-refundable. " +
                        "People you already talk to, mutual follows, and anyone on your allowlist can " +
                        "always message you for free.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Switch(
                        checked = state.requireTip,
                        onCheckedChange = onRequireChanged,
                        modifier = Modifier.testTag(MessagePrivacyTestTags.REQUIRE_SWITCH),
                    )
                    Text("Require a tip", modifier = Modifier.padding(start = 12.dp))
                }
                if (state.requireTip) {
                    OutlinedTextField(
                        value = state.minTipDollars,
                        onValueChange = onMinTipChanged,
                        label = { Text("Minimum tip ($)") },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
                        modifier = Modifier.fillMaxWidth().testTag(MessagePrivacyTestTags.MIN_TIP_INPUT),
                    )
                }
                state.formError?.let {
                    Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                }
                state.savedMessage?.let {
                    Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary)
                }
                Button(
                    onClick = onSave,
                    enabled = !busy,
                    modifier = Modifier.testTag(MessagePrivacyTestTags.SAVE_BUTTON),
                ) {
                    Text("Save")
                }
            }
        }

        // --- Tip-free allowlist ---
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("Tip-free allowlist", style = MaterialTheme.typography.titleMedium)
                Text(
                    "These people can always message you for free, even when a tip is required. Add by " +
                        "user id.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    OutlinedTextField(
                        value = state.allowlistInput,
                        onValueChange = onAllowlistInputChanged,
                        label = { Text("User id") },
                        singleLine = true,
                        modifier = Modifier.weight(1f).testTag(MessagePrivacyTestTags.ALLOWLIST_INPUT),
                    )
                    OutlinedButton(
                        onClick = onAddAllowlist,
                        enabled = !busy && state.allowlistInput.isNotBlank(),
                        modifier = Modifier.testTag(MessagePrivacyTestTags.ALLOWLIST_ADD),
                    ) {
                        Text("Add")
                    }
                }
                if (state.allowlist.isEmpty()) {
                    Text(
                        "No one on the allowlist yet.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                } else {
                    state.allowlist.forEachIndexed { index, userId ->
                        if (index > 0) HorizontalDivider()
                        Row(
                            modifier = Modifier.fillMaxWidth().testTag(MessagePrivacyTestTags.ALLOWLIST_ROW),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text(
                                userId,
                                style = MaterialTheme.typography.bodyMedium,
                                modifier = Modifier.weight(1f),
                            )
                            IconButton(
                                onClick = { onRemoveAllowlist(userId) },
                                enabled = !busy,
                                modifier = Modifier.testTag(MessagePrivacyTestTags.ALLOWLIST_REMOVE),
                            ) {
                                Icon(Icons.Filled.Close, contentDescription = "Remove")
                            }
                        }
                    }
                }
            }
        }

        // ADV2-E5 (F5+F6): per-user "Allow promotional messages" opt-out (self-contained VM).
        AdMessagePrefsSection()
    }
}
