package com.testlogon.android.feature.auth.login

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.input.TlButton
import com.testlogon.android.core.ui.input.TlButtonVariant
import com.testlogon.android.core.ui.input.TlPasswordField
import com.testlogon.android.core.ui.input.TlTextField
import com.testlogon.android.data.auth.MfaFactor

/** Route-level Login entry, bound by the unauthenticated nav graph (AND-030). */
@Composable
fun LoginRoute(
    onNavigateToMfa: (challengeId: String, factors: List<MfaFactor>) -> Unit,
    onNavigateHome: () -> Unit,
    onRegister: () -> Unit,
    onRecovery: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: LoginViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is LoginEffect.NavigateToMfa -> onNavigateToMfa(effect.challengeId, effect.factors)
                LoginEffect.NavigateHome -> onNavigateHome()
            }
        }
    }

    LoginScreen(
        state = state,
        onEmailChange = viewModel::onEmailChange,
        onPasswordChange = viewModel::onPasswordChange,
        onTogglePasswordVisibility = viewModel::onTogglePasswordVisibility,
        onSubmit = viewModel::onSubmit,
        onDismissError = viewModel::onDismissError,
        onServerUrlChange = viewModel::onServerUrlChange,
        onRegister = onRegister,
        onRecovery = onRecovery,
        modifier = modifier,
    )
}

/** Stateless, previewable login screen (AND-030). */
@Composable
fun LoginScreen(
    state: LoginUiState,
    onEmailChange: (String) -> Unit,
    onPasswordChange: (String) -> Unit,
    onTogglePasswordVisibility: () -> Unit,
    onSubmit: () -> Unit,
    onDismissError: () -> Unit,
    onServerUrlChange: (String) -> Unit,
    onRegister: () -> Unit,
    onRecovery: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var showServerDialog by remember { mutableStateOf(false) }

    Scaffold(modifier = modifier.testTag("login_screen")) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(24.dp)
                .verticalScroll(rememberScrollState())
                .imePadding(),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(
                text = "Welcome back",
                style = MaterialTheme.typography.headlineMedium,
            )
            Text(
                text = "Sign in to your account to continue",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            if (state.error != null) {
                Text(
                    text = state.error,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier
                        .testTag("login_error")
                        .semantics { liveRegion = LiveRegionMode.Polite },
                )
                TextButton(onClick = onDismissError, modifier = Modifier.testTag("login_dismiss_error")) {
                    Text("Dismiss")
                }
            }

            TlTextField(
                value = state.email,
                onValueChange = onEmailChange,
                label = "Email",
                enabled = !state.isSubmitting,
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Email,
                    imeAction = ImeAction.Next,
                ),
                modifier = Modifier.testTag("login_email"),
            )

            TlPasswordField(
                value = state.password,
                onValueChange = onPasswordChange,
                label = "Password",
                enabled = !state.isSubmitting,
                imeAction = ImeAction.Done,
                onImeAction = { if (state.submitEnabled) onSubmit() },
                modifier = Modifier.testTag("login_password"),
            )

            TextButton(
                onClick = onRecovery,
                enabled = !state.isSubmitting,
                modifier = Modifier.align(Alignment.End).testTag("login_forgot_password"),
            ) {
                Text("Forgot password?")
            }

            TlButton(
                text = "Sign in",
                onClick = onSubmit,
                enabled = state.submitEnabled,
                loading = state.isSubmitting,
                modifier = Modifier.fillMaxWidth().testTag("login_submit"),
            )

            TlButton(
                text = "Don't have an account? Register",
                onClick = onRegister,
                variant = TlButtonVariant.Text,
                enabled = !state.isSubmitting,
                modifier = Modifier.fillMaxWidth().testTag("login_register"),
            )

            TextButton(
                onClick = { showServerDialog = true },
                enabled = !state.isSubmitting,
                modifier = Modifier.testTag("login_server_url"),
            ) {
                Text("Server: ${state.serverUrl}", style = MaterialTheme.typography.bodySmall)
            }
        }
    }

    if (showServerDialog) {
        ServerUrlDialog(
            current = state.serverUrl,
            onConfirm = {
                onServerUrlChange(it)
                showServerDialog = false
            },
            onDismiss = { showServerDialog = false },
        )
    }
}

@Composable
private fun ServerUrlDialog(
    current: String,
    onConfirm: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    var text by remember { mutableStateOf(current) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Server URL") },
        text = {
            OutlinedTextField(
                value = text,
                onValueChange = { text = it },
                singleLine = true,
                label = { Text("Base URL") },
                modifier = Modifier.fillMaxWidth().testTag("server_url_field"),
            )
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(text) }, modifier = Modifier.testTag("server_url_save")) {
                Text("Save")
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}
