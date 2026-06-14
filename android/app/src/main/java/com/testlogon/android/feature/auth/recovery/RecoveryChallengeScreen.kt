package com.testlogon.android.feature.auth.recovery

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
import com.testlogon.android.data.auth.RecoveryFactor

/** Route-level recovery-challenge entry, bound by the unauthenticated nav graph (AND-058). */
@Composable
fun RecoveryChallengeRoute(
    onVerified: (username: String, challengeId: String, code: String) -> Unit,
    onRestart: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: RecoveryChallengeViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is RecoveryChallengeEffect.Verified -> onVerified(effect.username, effect.challengeId, effect.code)
                RecoveryChallengeEffect.RestartRequired -> onRestart()
            }
        }
    }

    RecoveryChallengeScreen(
        state = state,
        onCodeChange = viewModel::onCodeChange,
        onSubmit = viewModel::onSubmit,
        onResend = viewModel::onResend,
        onSwitchFactor = viewModel::onSwitchFactor,
        modifier = modifier,
    )
}

/** Stateless, previewable recovery-challenge screen (AND-058). */
@Composable
fun RecoveryChallengeScreen(
    state: RecoveryChallengeUiState,
    onCodeChange: (String) -> Unit,
    onSubmit: () -> Unit,
    onResend: () -> Unit,
    onSwitchFactor: (RecoveryFactor) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(modifier = modifier.testTag("recovery_challenge_screen")) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(24.dp)
                .verticalScroll(rememberScrollState())
                .imePadding(),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(text = "Verify it's you", style = MaterialTheme.typography.headlineSmall)
            Text(
                text = factorPrompt(state),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            if (state.sentTo.isNotEmpty()) {
                Text(
                    text = "Sent to ${state.sentTo.joinToString(", ")}",
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.testTag("recovery_challenge_sent_to"),
                )
            }

            if (state.error != null) {
                Text(
                    text = state.error,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier
                        .testTag("recovery_challenge_error")
                        .semantics { liveRegion = LiveRegionMode.Assertive },
                )
            }

            if (state.isNumericFactor) {
                TlOtpField(
                    value = state.code,
                    onValueChange = onCodeChange,
                    length = state.codeLength,
                    enabled = !state.isVerifying,
                    onCompleted = { if (!state.isVerifying) onSubmit() },
                    modifier = Modifier.testTag("recovery_challenge_otp"),
                )
            } else {
                TlTextField(
                    value = state.code,
                    onValueChange = onCodeChange,
                    label = "Recovery code",
                    enabled = !state.isVerifying,
                    modifier = Modifier.testTag("recovery_challenge_recovery_code"),
                )
            }

            TlButton(
                text = "Verify",
                onClick = onSubmit,
                enabled = state.canSubmit,
                loading = state.isVerifying,
                modifier = Modifier.fillMaxWidth().testTag("recovery_challenge_verify"),
            )

            if (state.activeFactor.requiresBegin) {
                TlButton(
                    text = "Resend code",
                    onClick = onResend,
                    variant = TlButtonVariant.Text,
                    enabled = !state.isVerifying && !state.isSending,
                    modifier = Modifier.fillMaxWidth().testTag("recovery_challenge_resend"),
                )
            }

            if (state.canSwitchFactor) {
                Text(text = "Use a different method:", style = MaterialTheme.typography.labelLarge)
                state.factors
                    .filter { it != state.activeFactor }
                    .forEach { factor ->
                        TlButton(
                            text = factorLabel(factor),
                            onClick = { onSwitchFactor(factor) },
                            variant = TlButtonVariant.Secondary,
                            enabled = !state.isVerifying,
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag("recovery_challenge_switch_${factor.wire}"),
                        )
                    }
            }
        }
    }
}

private fun factorPrompt(state: RecoveryChallengeUiState): String = when (state.activeFactor) {
    RecoveryFactor.Totp -> "Enter the code from your authenticator app."
    RecoveryFactor.Sms -> "Enter the code we texted you."
    RecoveryFactor.Email -> "Enter the code we emailed you."
    RecoveryFactor.Recovery -> "Enter one of your recovery codes."
    is RecoveryFactor.Unknown -> "Enter your verification code."
}

private fun factorLabel(factor: RecoveryFactor): String = when (factor) {
    RecoveryFactor.Totp -> "Authenticator app"
    RecoveryFactor.Sms -> "Text message"
    RecoveryFactor.Email -> "Email"
    RecoveryFactor.Recovery -> "Recovery code"
    is RecoveryFactor.Unknown -> factor.raw
}
