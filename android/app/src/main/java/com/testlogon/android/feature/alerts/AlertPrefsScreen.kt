@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.alerts

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
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material3.Card
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.input.TlButton
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.StaleBanner

/** Stable testTags for the alert preferences screen (AND-088). */
object AlertPrefsTestTags {
    const val SCREEN = "alert_prefs_screen"
    const val EMAIL_INPUT = "alert_email_input"
    const val EMAIL_ADD = "alert_email_add"
    const val SMS_INPUT = "alert_sms_input"
    const val SMS_ADD = "alert_sms_add"
    const val CODE_INPUT = "alert_code_input"
    const val VERIFY = "alert_verify"
    const val OPEN_TYPE_PREFS = "alert_open_type_prefs"
}

/** AND-088 — route-level Alert Preferences entry (from the Settings hub / More). */
@Composable
fun AlertPrefsRoute(
    onBack: () -> Unit,
    onOpenTypePreferences: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: AlertPrefsViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }

    LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is AlertPrefsEvent.Message -> snackbarHostState.showSnackbar(event.text)
            }
        }
    }

    AlertPrefsScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onBack = onBack,
        onRetry = viewModel::load,
        onOpenTypePreferences = onOpenTypePreferences,
        onEmailInputChanged = viewModel::onEmailInputChanged,
        onSmsInputChanged = viewModel::onSmsInputChanged,
        onCodeInputChanged = viewModel::onCodeInputChanged,
        onAddEmail = viewModel::addEmail,
        onAddSms = viewModel::addSms,
        onVerify = viewModel::verify,
        onResend = viewModel::resend,
        onCancelPending = viewModel::cancelPending,
        onRemoveEmail = viewModel::removeEmail,
        onRemoveSms = viewModel::removeSms,
        modifier = modifier,
    )
}

@Composable
fun AlertPrefsScreen(
    state: AlertPrefsUiState,
    snackbarHostState: SnackbarHostState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onOpenTypePreferences: () -> Unit,
    onEmailInputChanged: (String) -> Unit,
    onSmsInputChanged: (String) -> Unit,
    onCodeInputChanged: (String) -> Unit,
    onAddEmail: () -> Unit,
    onAddSms: () -> Unit,
    onVerify: () -> Unit,
    onResend: () -> Unit,
    onCancelPending: () -> Unit,
    onRemoveEmail: (String) -> Unit,
    onRemoveSms: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(AlertPrefsTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Alert preferences") },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("alert_prefs_back")) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        when {
            state.isLoading -> LoadingState(modifier = Modifier.padding(padding))
            state.error != null -> ErrorState(
                message = state.error,
                onRetry = onRetry,
                modifier = Modifier.padding(padding),
            )
            else -> Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .verticalScroll(rememberScrollState())
                    .padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                StaleBanner(stale = state.isStale, refreshing = false, onRetry = onRetry)

                if (state.pending != null) {
                    VerifySection(
                        sentTo = state.pending.sentTo,
                        code = state.codeInput,
                        busy = state.busy,
                        onCodeChanged = onCodeInputChanged,
                        onVerify = onVerify,
                        onResend = onResend,
                        onCancel = onCancelPending,
                    )
                }

                ChannelSection(
                    title = "Email alert targets",
                    targets = state.emails,
                    input = state.emailInput,
                    inputLabel = "Email address",
                    keyboardType = KeyboardType.Email,
                    inputTag = AlertPrefsTestTags.EMAIL_INPUT,
                    addTag = AlertPrefsTestTags.EMAIL_ADD,
                    addEnabled = state.emailInput.isNotBlank() && !state.busy && state.pending == null,
                    onInputChanged = onEmailInputChanged,
                    onAdd = onAddEmail,
                    onRemove = onRemoveEmail,
                )

                ChannelSection(
                    title = "SMS alert targets",
                    targets = state.smsNumbers,
                    input = state.smsInput,
                    inputLabel = "Phone number",
                    keyboardType = KeyboardType.Phone,
                    inputTag = AlertPrefsTestTags.SMS_INPUT,
                    addTag = AlertPrefsTestTags.SMS_ADD,
                    addEnabled = state.smsInput.isNotBlank() && !state.busy && state.pending == null,
                    onInputChanged = onSmsInputChanged,
                    onAdd = onAddSms,
                    onRemove = onRemoveSms,
                )

                Card(Modifier.fillMaxWidth()) {
                    ListItem(
                        headlineContent = { Text("Alert categories") },
                        supportingContent = { Text("Choose which events notify each channel.") },
                        trailingContent = {
                            TextButton(
                                onClick = onOpenTypePreferences,
                                modifier = Modifier.testTag(AlertPrefsTestTags.OPEN_TYPE_PREFS),
                            ) { Text("Open") }
                        },
                    )
                }
            }
        }
    }
}

@Composable
private fun VerifySection(
    sentTo: String,
    code: String,
    busy: Boolean,
    onCodeChanged: (String) -> Unit,
    onVerify: () -> Unit,
    onResend: () -> Unit,
    onCancel: () -> Unit,
) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Enter the 6-digit code", style = MaterialTheme.typography.titleMedium)
            Text(
                text = "We sent a code to $sentTo.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedTextField(
                value = code,
                onValueChange = onCodeChanged,
                label = { Text("Confirmation code") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                modifier = Modifier.fillMaxWidth().testTag(AlertPrefsTestTags.CODE_INPUT),
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TlButton(
                    text = "Verify",
                    onClick = onVerify,
                    enabled = code.trim().length >= 6 && !busy,
                    modifier = Modifier.testTag(AlertPrefsTestTags.VERIFY),
                )
                TextButton(onClick = onResend, enabled = !busy) { Text("Resend") }
                TextButton(onClick = onCancel, enabled = !busy) { Text("Cancel") }
            }
        }
    }
}

@Composable
private fun ChannelSection(
    title: String,
    targets: List<String>,
    input: String,
    inputLabel: String,
    keyboardType: KeyboardType,
    inputTag: String,
    addTag: String,
    addEnabled: Boolean,
    onInputChanged: (String) -> Unit,
    onAdd: () -> Unit,
    onRemove: (String) -> Unit,
) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium)
            if (targets.isEmpty()) {
                Text(
                    text = "No targets yet.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                targets.forEach { target ->
                    ListItem(
                        headlineContent = { Text(target) },
                        trailingContent = {
                            IconButton(onClick = { onRemove(target) }) {
                                Icon(Icons.Outlined.Delete, contentDescription = "Remove $target")
                            }
                        },
                    )
                }
            }
            OutlinedTextField(
                value = input,
                onValueChange = onInputChanged,
                label = { Text(inputLabel) },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = keyboardType),
                modifier = Modifier.fillMaxWidth().testTag(inputTag),
            )
            TlButton(
                text = "Add",
                onClick = onAdd,
                enabled = addEnabled,
                modifier = Modifier.testTag(addTag),
            )
        }
    }
}
