@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.settings.callrate

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
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
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

/** Route-level entry for the call-rate (paid-calls) settings screen. */
@Composable
fun CallRateRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: CallRateViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    CallRateScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::load,
        onRateChanged = viewModel::onRateChanged,
        onMinBalanceChanged = viewModel::onMinBalanceChanged,
        onMaxDurationChanged = viewModel::onMaxDurationChanged,
        onEnabledChanged = viewModel::onEnabledChanged,
        onSave = viewModel::save,
        onDelete = viewModel::delete,
        modifier = modifier,
    )
}

@Composable
fun CallRateScreen(
    state: CallRateUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onRateChanged: (String) -> Unit,
    onMinBalanceChanged: (String) -> Unit,
    onMaxDurationChanged: (String) -> Unit,
    onEnabledChanged: (Boolean) -> Unit,
    onSave: () -> Unit,
    onDelete: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(CallRateTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Call Rate") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        when (state) {
            CallRateUiState.Loading -> LoadingState(modifier = Modifier.padding(padding))
            is CallRateUiState.Error -> ErrorState(
                message = state.message,
                onRetry = onRetry,
                modifier = Modifier.padding(padding).testTag(CallRateTestTags.ERROR_RETRY),
            )
            is CallRateUiState.Content -> Content(
                state = state,
                padding = padding,
                onRateChanged = onRateChanged,
                onMinBalanceChanged = onMinBalanceChanged,
                onMaxDurationChanged = onMaxDurationChanged,
                onEnabledChanged = onEnabledChanged,
                onSave = onSave,
                onDelete = onDelete,
            )
        }
    }
}

@Composable
private fun Content(
    state: CallRateUiState.Content,
    padding: androidx.compose.foundation.layout.PaddingValues,
    onRateChanged: (String) -> Unit,
    onMinBalanceChanged: (String) -> Unit,
    onMaxDurationChanged: (String) -> Unit,
    onEnabledChanged: (Boolean) -> Unit,
    onSave: () -> Unit,
    onDelete: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(padding)
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("Pay-Per-Minute Rate", style = MaterialTheme.typography.titleMedium)
                Text(
                    "Callers see this rate before initiating a call and are charged per minute. The platform " +
                        "retains a fee; the remainder is credited to your wallet.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                val numberKeyboard = KeyboardOptions(keyboardType = KeyboardType.Number)
                val decimalKeyboard = KeyboardOptions(keyboardType = KeyboardType.Decimal)
                OutlinedTextField(
                    value = state.rateDollars,
                    onValueChange = onRateChanged,
                    label = { Text("Rate ($/min)") },
                    singleLine = true,
                    keyboardOptions = decimalKeyboard,
                    modifier = Modifier.fillMaxWidth().testTag(CallRateTestTags.RATE_INPUT),
                )
                OutlinedTextField(
                    value = state.minBalanceMinutes,
                    onValueChange = onMinBalanceChanged,
                    label = { Text("Min balance (minutes)") },
                    singleLine = true,
                    keyboardOptions = numberKeyboard,
                    modifier = Modifier.fillMaxWidth().testTag(CallRateTestTags.MIN_BALANCE_INPUT),
                )
                OutlinedTextField(
                    value = state.maxDurationMinutes,
                    onValueChange = onMaxDurationChanged,
                    label = { Text("Max duration (minutes)") },
                    singleLine = true,
                    keyboardOptions = numberKeyboard,
                    modifier = Modifier.fillMaxWidth().testTag(CallRateTestTags.MAX_DURATION_INPUT),
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Switch(
                        checked = state.enabled,
                        onCheckedChange = onEnabledChanged,
                        modifier = Modifier.testTag(CallRateTestTags.ENABLED_SWITCH),
                    )
                    Text("Enabled", modifier = Modifier.padding(start = 12.dp))
                }
                state.formError?.let {
                    Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                }
                state.savedMessage?.let {
                    Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary)
                }
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    Button(
                        onClick = onSave,
                        enabled = !state.saving && !state.deleting,
                        modifier = Modifier.testTag(CallRateTestTags.SAVE_BUTTON),
                    ) {
                        Text(if (state.hasRate) "Save Changes" else "Enable Paid Calls")
                    }
                    if (state.hasRate) {
                        OutlinedButton(
                            onClick = onDelete,
                            enabled = !state.saving && !state.deleting,
                            modifier = Modifier.testTag(CallRateTestTags.DELETE_BUTTON),
                        ) {
                            Text("Disable Paid Calls")
                        }
                    }
                }
            }
        }
    }
}
