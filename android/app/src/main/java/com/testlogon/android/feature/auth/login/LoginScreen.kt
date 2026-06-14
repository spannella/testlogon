package com.testlogon.android.feature.auth.login

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.model.LogoutReason
import com.testlogon.android.core.ui.input.TlButton
import com.testlogon.android.core.ui.input.TlButtonVariant
import com.testlogon.android.core.ui.input.TlPasswordField
import com.testlogon.android.core.ui.input.TlTextField
import com.testlogon.android.data.auth.MfaFactor
import com.testlogon.android.feature.auth.passkey.PasskeySignInButton
import com.testlogon.android.feature.auth.passkey.findActivity

/** Route-level Login entry, bound by the unauthenticated nav graph (AND-030). */
@Composable
fun LoginRoute(
    onNavigateToMfa: (challengeId: String, factors: List<MfaFactor>) -> Unit,
    onNavigateHome: () -> Unit,
    onRegister: () -> Unit,
    onRecovery: () -> Unit,
    onMagicLink: () -> Unit,
    onOpenServerSettings: () -> Unit,
    modifier: Modifier = Modifier,
    ssoCallbackUri: android.net.Uri? = null,
    viewModel: LoginViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val context = LocalContext.current

    // AND-063: forward an ACS callback deep-link to the VM exactly once per distinct URI.
    LaunchedEffect(ssoCallbackUri) {
        ssoCallbackUri?.let(viewModel::onSsoRedirect)
    }

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
        onDismissExpiry = viewModel::onDismissExpiry,
        onOpenServerSettings = onOpenServerSettings,
        onRegister = onRegister,
        onRecovery = onRecovery,
        onMagicLink = onMagicLink,
        onStartSso = { context.findActivity()?.let { viewModel.startSso(it) } },
        onPasskeySignIn = { activity -> viewModel.signInWithPasskey(activity) },
        modifier = modifier,
    )
}

/** Stateless, previewable login screen (AND-030/062/063). */
@Composable
@Suppress("LongParameterList")
fun LoginScreen(
    state: LoginUiState,
    onEmailChange: (String) -> Unit,
    onPasswordChange: (String) -> Unit,
    onTogglePasswordVisibility: () -> Unit,
    onSubmit: () -> Unit,
    onDismissError: () -> Unit,
    onDismissExpiry: () -> Unit,
    onOpenServerSettings: () -> Unit,
    onRegister: () -> Unit,
    onRecovery: () -> Unit,
    onMagicLink: () -> Unit,
    onStartSso: () -> Unit = {},
    onPasskeySignIn: (android.app.Activity) -> Unit = {},
    modifier: Modifier = Modifier,
) {
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

            if (state.expiryReason != null) {
                ExpiryBanner(reason = state.expiryReason, onDismiss = onDismissExpiry)
            }

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

            // AND-063: SSO-only tenants hide the password form entirely.
            if (!state.ssoOnly) {
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
            }

            // AND-063: SSO affordance — primary when sso_only, secondary alongside the password form.
            if (state.ssoOnly || state.ssoAvailable) {
                TlButton(
                    text = "Sign in with ${state.ssoProviderName}",
                    onClick = onStartSso,
                    variant = if (state.ssoOnly) TlButtonVariant.Primary else TlButtonVariant.Secondary,
                    enabled = !state.isSubmitting && !state.ssoBusy,
                    loading = state.ssoBusy,
                    modifier = Modifier.fillMaxWidth().testTag("login_sso"),
                )
            }

            // AND-062: passkey sign-in — hidden on unsupported devices, requires a non-blank username.
            PasskeySignInButton(
                enabled = state.passkeySignInEnabled,
                loading = state.passkeyBusy,
                supported = state.passkeySupported,
                onSignIn = onPasskeySignIn,
            )

            TlButton(
                text = "Sign in with a magic link",
                onClick = onMagicLink,
                variant = TlButtonVariant.Text,
                enabled = !state.isSubmitting,
                modifier = Modifier.fillMaxWidth().testTag("login_magic_link"),
            )

            TlButton(
                text = "Don't have an account? Register",
                onClick = onRegister,
                variant = TlButtonVariant.Text,
                enabled = !state.isSubmitting,
                modifier = Modifier.fillMaxWidth().testTag("login_register"),
            )

            TextButton(
                onClick = onOpenServerSettings,
                enabled = !state.isSubmitting,
                modifier = Modifier.testTag("login_server_url"),
            ) {
                Text("Server: ${state.serverUrl}", style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

@Composable
private fun ExpiryBanner(reason: LogoutReason, onDismiss: () -> Unit) {
    val message = when (reason) {
        LogoutReason.SESSION_EXPIRED -> "Your session expired. Please sign in again."
        LogoutReason.SESSION_REVOKED -> "Your session was revoked. Please sign in again."
        LogoutReason.USER_INITIATED -> "You were signed out."
        LogoutReason.UNKNOWN -> "Please sign in again."
    }
    Surface(
        color = MaterialTheme.colorScheme.errorContainer,
        contentColor = MaterialTheme.colorScheme.onErrorContainer,
        modifier = Modifier
            .fillMaxWidth()
            .testTag("login_expiry_banner")
            .semantics { liveRegion = LiveRegionMode.Polite },
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text(text = message, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
            TextButton(onClick = onDismiss, modifier = Modifier.testTag("login_expiry_dismiss")) {
                Text("Dismiss")
            }
        }
    }
}
