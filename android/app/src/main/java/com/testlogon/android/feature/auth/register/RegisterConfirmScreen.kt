package com.testlogon.android.feature.auth.register

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
import com.testlogon.android.data.auth.MfaSetupHandoff

/** Route-level register-confirm entry, bound by the unauthenticated nav graph (AND-054). */
@Composable
fun RegisterConfirmRoute(
    onNavigateToLogin: (email: String) -> Unit,
    onNavigateHome: () -> Unit,
    onNavigateToMfaSetup: (handoff: MfaSetupHandoff) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: RegisterConfirmViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is RegisterConfirmEffect.GoToLogin -> onNavigateToLogin(effect.email)
                RegisterConfirmEffect.GoToApp -> onNavigateHome()
                is RegisterConfirmEffect.GoToMfaSetup -> onNavigateToMfaSetup(effect.handoff)
            }
        }
    }

    RegisterConfirmScreen(
        state = state,
        onCodeChange = viewModel::onCodeChange,
        onConfirm = viewModel::onConfirm,
        onResend = viewModel::onResend,
        onBack = onBack,
        modifier = modifier,
    )
}

/** Stateless, previewable register-confirm screen (AND-054). */
@Composable
fun RegisterConfirmScreen(
    state: RegisterConfirmUiState,
    onCodeChange: (String) -> Unit,
    onConfirm: () -> Unit,
    onResend: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(modifier = modifier.testTag("register_confirm_screen")) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(24.dp)
                .verticalScroll(rememberScrollState())
                .imePadding(),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(text = "Confirm your account", style = MaterialTheme.typography.headlineSmall)
            Text(
                text = deliveryHint(state),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            if (state.error != null) {
                Text(
                    text = state.error,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier
                        .testTag("register_confirm_error")
                        .semantics { liveRegion = LiveRegionMode.Assertive },
                )
            }

            if (state.transientMessage != null) {
                Text(
                    text = state.transientMessage,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier
                        .testTag("register_confirm_transient")
                        .semantics { liveRegion = LiveRegionMode.Polite },
                )
            }

            TlOtpField(
                value = state.code,
                onValueChange = onCodeChange,
                length = state.codeLength,
                enabled = !state.isSubmitting,
                onCompleted = { if (!state.isSubmitting) onConfirm() },
                modifier = Modifier.testTag("register_confirm_otp"),
            )

            TlButton(
                text = "Confirm",
                onClick = onConfirm,
                enabled = state.canConfirm,
                loading = state.isSubmitting,
                modifier = Modifier.fillMaxWidth().testTag("register_confirm_submit"),
            )

            TlButton(
                text = resendLabel(state),
                onClick = onResend,
                variant = TlButtonVariant.Text,
                enabled = state.canResend,
                loading = state.isResending,
                modifier = Modifier.fillMaxWidth().testTag("register_confirm_resend"),
            )

            TlButton(
                text = "Back",
                onClick = onBack,
                variant = TlButtonVariant.Text,
                enabled = !state.isSubmitting,
                modifier = Modifier.fillMaxWidth().testTag("register_confirm_back"),
            )
        }
    }
}

private fun deliveryHint(state: RegisterConfirmUiState): String {
    val medium = state.deliveryMedium ?: "email"
    val dest = state.deliveryDestination
    return if (dest != null) {
        "We sent a code via $medium to $dest."
    } else {
        "We sent a verification code via $medium."
    }
}

private fun resendLabel(state: RegisterConfirmUiState): String =
    if (state.resendCountdownSeconds > 0) {
        "Resend code (${state.resendCountdownSeconds}s)"
    } else {
        "Resend code"
    }
