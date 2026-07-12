package com.testlogon.android.feature.auth.register

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
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
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
import com.testlogon.android.data.auth.EmailAvailability

/** Route-level Register entry, bound by the unauthenticated nav graph (AND-053). */
@Composable
fun RegisterRoute(
    onNavigateToConfirm: (
        email: String,
        deliveryMedium: String?,
        deliveryDestination: String?,
        enableSmsMfa: Boolean,
        enableTotpMfa: Boolean,
        phone: String?,
    ) -> Unit,
    onNavigateToLogin: () -> Unit,
    onNavigateHome: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: RegisterViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is RegisterEffect.GoToConfirm -> onNavigateToConfirm(
                    effect.email,
                    effect.deliveryMedium,
                    effect.deliveryDestination,
                    effect.enableSmsMfa,
                    effect.enableTotpMfa,
                    effect.phone,
                )
                RegisterEffect.GoToLoginSuccess -> onNavigateToLogin()
                RegisterEffect.GoToAppAuthenticated -> onNavigateHome()
            }
        }
    }

    RegisterScreen(
        state = state,
        onFullNameChange = viewModel::onFullNameChange,
        onEmailChange = viewModel::onEmailChange,
        onPasswordChange = viewModel::onPasswordChange,
        onConfirmChange = viewModel::onConfirmChange,
        onPhoneChange = viewModel::onPhoneChange,
        onToggleSmsMfa = viewModel::onToggleSmsMfa,
        onToggleTotpMfa = viewModel::onToggleTotpMfa,
        onTogglePasswordVisibility = viewModel::onTogglePasswordVisibility,
        onSubmit = viewModel::onSubmit,
        onDismissError = viewModel::onDismissError,
        onNavigateToLogin = onNavigateToLogin,
        modifier = modifier,
    )
}

/** Stateless, previewable register-start screen (AND-053). */
@Composable
fun RegisterScreen(
    state: RegisterUiState,
    onFullNameChange: (String) -> Unit,
    onEmailChange: (String) -> Unit,
    onPasswordChange: (String) -> Unit,
    onConfirmChange: (String) -> Unit,
    onPhoneChange: (String) -> Unit,
    onToggleSmsMfa: (Boolean) -> Unit,
    onToggleTotpMfa: (Boolean) -> Unit,
    onTogglePasswordVisibility: () -> Unit,
    onSubmit: () -> Unit,
    onDismissError: () -> Unit,
    onNavigateToLogin: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(modifier = modifier.testTag("register_screen")) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(24.dp)
                .verticalScroll(rememberScrollState())
                .imePadding(),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(text = "Register", style = MaterialTheme.typography.headlineMedium)
            Text(
                text = "Create your account to get started",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            if (state.formError != null) {
                Text(
                    text = state.formError,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier
                        .testTag("register_error")
                        .semantics { liveRegion = LiveRegionMode.Polite },
                )
                TextButton(onClick = onDismissError, modifier = Modifier.testTag("register_dismiss_error")) {
                    Text("Dismiss")
                }
            }

            TlTextField(
                value = state.fullName,
                onValueChange = onFullNameChange,
                label = "Full name",
                enabled = !state.isSubmitting,
                errorText = state.fullNameError?.let(::fieldErrorText),
                keyboardOptions = KeyboardOptions(
                    capitalization = androidx.compose.ui.text.input.KeyboardCapitalization.Words,
                    imeAction = ImeAction.Next,
                ),
                modifier = Modifier.testTag("register_full_name"),
            )

            TlTextField(
                value = state.email,
                onValueChange = onEmailChange,
                label = "Email",
                enabled = !state.isSubmitting,
                errorText = state.emailError?.let(::fieldErrorText) ?: emailAvailabilityError(state),
                helperText = emailAvailabilityHelper(state),
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Email,
                    imeAction = ImeAction.Next,
                ),
                modifier = Modifier.testTag("register_email"),
            )

            TlPasswordField(
                value = state.password,
                onValueChange = onPasswordChange,
                label = "Password",
                enabled = !state.isSubmitting,
                errorText = state.passwordError?.let(::fieldErrorText),
                imeAction = ImeAction.Next,
                modifier = Modifier.testTag("register_password"),
            )

            PasswordRequirements(password = state.password)

            TlPasswordField(
                value = state.confirm,
                onValueChange = onConfirmChange,
                label = "Confirm password",
                enabled = !state.isSubmitting,
                errorText = state.confirmError?.let(::fieldErrorText),
                imeAction = ImeAction.Done,
                onImeAction = { if (state.submitEnabled) onSubmit() },
                modifier = Modifier.testTag("register_confirm"),
            )

            Text(
                text = "Optional security upgrades",
                style = MaterialTheme.typography.labelLarge,
            )

            MfaToggleRow(
                label = "Authenticator app (TOTP)",
                checked = state.enableTotpMfa,
                enabled = !state.isSubmitting,
                onCheckedChange = onToggleTotpMfa,
                testTag = "register_mfa_totp",
            )
            MfaToggleRow(
                label = "Text message (SMS)",
                checked = state.enableSmsMfa,
                enabled = !state.isSubmitting,
                onCheckedChange = onToggleSmsMfa,
                testTag = "register_mfa_sms",
            )

            if (state.isPhoneRequired) {
                TlTextField(
                    value = state.phone,
                    onValueChange = onPhoneChange,
                    label = "Phone number",
                    enabled = !state.isSubmitting,
                    errorText = state.phoneError?.let(::fieldErrorText),
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.Phone,
                        imeAction = ImeAction.Next,
                    ),
                    modifier = Modifier.testTag("register_phone"),
                )
            }

            TlButton(
                text = "Request access",
                onClick = onSubmit,
                enabled = state.submitEnabled,
                loading = state.isSubmitting,
                modifier = Modifier.fillMaxWidth().testTag("register_submit"),
            )

            TlButton(
                text = "Back to sign in",
                onClick = onNavigateToLogin,
                variant = TlButtonVariant.Text,
                enabled = !state.isSubmitting,
                modifier = Modifier.fillMaxWidth().testTag("register_sign_in"),
            )
        }
    }
}

@Composable
private fun MfaToggleRow(
    label: String,
    checked: Boolean,
    enabled: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    testTag: String,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(text = label, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange,
            enabled = enabled,
            modifier = Modifier.testTag(testTag),
        )
    }
}

/** Live password-requirements checklist (web parity): each rule turns green as it is satisfied. */
@Composable
private fun PasswordRequirements(password: String) {
    val ok = Color(0xFF2E7D32)
    val rules = listOf(
        "At least 12 characters" to (password.length in 12..128),
        "A lowercase letter" to password.any { it.isLowerCase() },
        "An uppercase letter" to password.any { it.isUpperCase() },
        "A number" to password.any { it.isDigit() },
        "A special character" to password.any { !it.isLetterOrDigit() && !it.isWhitespace() },
    )
    Column(modifier = Modifier.fillMaxWidth().testTag("register_password_rules")) {
        rules.forEach { (label, met) ->
            val color = if (met) ok else MaterialTheme.colorScheme.onSurfaceVariant
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(vertical = 1.dp)) {
                Text(text = if (met) "✓" else "○", color = color, style = MaterialTheme.typography.bodySmall)
                Text(text = label, color = color, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(start = 8.dp))
            }
        }
    }
}

/** Maps a [RegisterFieldError] to user-facing copy (literal strings, matching login/MFA screens). */
private fun fieldErrorText(error: RegisterFieldError): String = when (error) {
    RegisterFieldError.Required -> "This field is required."
    RegisterFieldError.InvalidEmail -> "Enter a valid email address."
    RegisterFieldError.PolicyLength -> "Password must be 12–128 characters."
    RegisterFieldError.PolicyComplexity ->
        "Use upper- and lower-case letters, a number and a symbol."
    RegisterFieldError.PasswordMismatch -> "Passwords don't match."
    RegisterFieldError.InvalidPhone -> "Enter a valid phone number."
}

/** A taken email renders as a field error (AND-055 FR-7). */
private fun emailAvailabilityError(state: RegisterUiState): String? =
    if (state.emailTaken) "This email is already registered." else null

/** Non-error availability supporting text (checking / available) (AND-055 FR-5/FR-10). */
private fun emailAvailabilityHelper(state: RegisterUiState): String? = when {
    state.emailError != null || state.emailTaken -> null
    state.emailAvailability == EmailAvailability.Checking -> "Checking availability…"
    state.emailAvailability == EmailAvailability.Available -> "Email available"
    else -> null
}
