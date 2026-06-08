package com.testlogon.android.feature.auth.mfa

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.input.TlButton
import com.testlogon.android.core.ui.input.TlButtonVariant
import com.testlogon.android.core.ui.input.TlOtpField
import com.testlogon.android.core.ui.input.TlTextField
import com.testlogon.android.data.auth.MfaFactor

/** Route-level MFA entry, bound by the unauthenticated nav graph (AND-039). */
@Composable
fun MfaRoute(
    onNavigateHome: () -> Unit,
    onNavigateToLogin: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: MfaViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                MfaEffect.NavigateHome -> onNavigateHome()
                MfaEffect.NavigateToLogin -> onNavigateToLogin()
            }
        }
    }

    MfaScreen(
        state = state,
        onCodeChange = viewModel::onCodeChange,
        onRecoveryCodeChange = viewModel::onRecoveryCodeChange,
        onSubmit = viewModel::onSubmit,
        onResend = viewModel::onResend,
        onSwitchFactor = viewModel::onSwitchFactor,
        onOpenRecovery = viewModel::onOpenRecovery,
        onCloseRecovery = viewModel::onCloseRecovery,
        modifier = modifier,
    )
}

/** Stateless, previewable MFA screen (AND-039). */
@Composable
fun MfaScreen(
    state: MfaUiState,
    onCodeChange: (String) -> Unit,
    onRecoveryCodeChange: (String) -> Unit,
    onSubmit: () -> Unit,
    onResend: () -> Unit,
    onSwitchFactor: (MfaFactor) -> Unit,
    onOpenRecovery: () -> Unit,
    onCloseRecovery: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(modifier = modifier.testTag("mfa_screen")) { padding ->
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
                text = "Two-factor authentication",
                style = MaterialTheme.typography.headlineSmall,
            )
            Text(
                text = factorPrompt(state),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            if (state.sentTo.isNotEmpty()) {
                Text(
                    text = "Sent to ${state.sentTo.joinToString(", ")}",
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.testTag("mfa_sent_to"),
                )
            }

            if (state.error != null) {
                Text(
                    text = state.error,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier
                        .testTag("mfa_error")
                        .semantics { liveRegion = LiveRegionMode.Polite },
                )
            }

            if (state.recoveryMode) {
                TlTextField(
                    value = state.recoveryCode,
                    onValueChange = onRecoveryCodeChange,
                    label = "Recovery code",
                    enabled = !state.isVerifying,
                    modifier = Modifier.testTag("mfa_recovery_code"),
                )
            } else {
                TlOtpField(
                    value = state.code,
                    onValueChange = onCodeChange,
                    length = state.codeLength,
                    enabled = !state.isVerifying,
                    onCompleted = { if (!state.isVerifying) onSubmit() },
                    modifier = Modifier.testTag("mfa_otp"),
                )
            }

            TlButton(
                text = "Verify",
                onClick = onSubmit,
                enabled = state.canSubmit,
                loading = state.isVerifying,
                modifier = Modifier.fillMaxWidth().testTag("mfa_verify"),
            )

            if (!state.recoveryMode && state.needsBegin) {
                TlButton(
                    text = "Resend code",
                    onClick = onResend,
                    variant = TlButtonVariant.Text,
                    enabled = !state.isVerifying && !state.isSending,
                    modifier = Modifier.testTag("mfa_resend"),
                )
            }

            if (!state.recoveryMode && state.canSwitchFactor) {
                Text(
                    text = "Use a different method:",
                    style = MaterialTheme.typography.labelLarge,
                )
                state.remainingFactors
                    .filter { it != state.activeFactor }
                    .forEach { factor ->
                        TlButton(
                            text = factorLabel(factor),
                            onClick = { onSwitchFactor(factor) },
                            variant = TlButtonVariant.Secondary,
                            enabled = !state.isVerifying,
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag("mfa_switch_${factor.wire}"),
                        )
                    }
            }

            if (state.recoveryMode) {
                TlButton(
                    text = "Back to code entry",
                    onClick = onCloseRecovery,
                    variant = TlButtonVariant.Text,
                    enabled = !state.isVerifying,
                    modifier = Modifier.testTag("mfa_recovery_back"),
                )
            } else {
                TlButton(
                    text = "Use a recovery code",
                    onClick = onOpenRecovery,
                    variant = TlButtonVariant.Text,
                    enabled = !state.isVerifying,
                    modifier = Modifier.testTag("mfa_recovery_open"),
                )
            }
        }
    }
}

private fun factorPrompt(state: MfaUiState): String = when {
    state.recoveryMode -> "Enter one of your recovery codes."
    state.activeFactor == MfaFactor.Totp -> "Enter the code from your authenticator app."
    state.activeFactor == MfaFactor.Sms -> "Enter the code we texted you."
    state.activeFactor == MfaFactor.Email -> "Enter the code we emailed you."
    else -> "Enter your verification code."
}

private fun factorLabel(factor: MfaFactor): String = when (factor) {
    MfaFactor.Totp -> "Authenticator app"
    MfaFactor.Sms -> "Text message"
    MfaFactor.Email -> "Email"
    MfaFactor.Recovery -> "Recovery code"
    is MfaFactor.Unknown -> factor.raw
}
