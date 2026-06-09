package com.testlogon.android.feature.auth.recovery

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
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
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.input.TlButton
import com.testlogon.android.core.ui.input.TlButtonVariant
import com.testlogon.android.core.ui.input.TlTextField

/** Route-level recovery-start entry, bound by the unauthenticated nav graph (AND-057). */
@Composable
fun RecoveryStartRoute(
    onProceedToChallenge: (
        username: String,
        challengeId: String,
        factors: List<String>,
        delivery: DeliverySummary?,
    ) -> Unit,
    onBackToLogin: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: RecoveryStartViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is RecoveryStartEffect.ProceedToChallenge ->
                    onProceedToChallenge(effect.username, effect.challengeId, effect.requiredFactors, effect.delivery)
            }
        }
    }

    RecoveryStartScreen(
        state = state,
        onUsernameChange = viewModel::onUsernameChange,
        onContinue = viewModel::onContinue,
        onBackToLogin = onBackToLogin,
        modifier = modifier,
    )
}

/** Stateless, previewable recovery-start screen (AND-057). */
@Composable
fun RecoveryStartScreen(
    state: RecoveryStartUiState,
    onUsernameChange: (String) -> Unit,
    onContinue: () -> Unit,
    onBackToLogin: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(modifier = modifier.testTag("recovery_start_screen")) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(24.dp)
                .verticalScroll(rememberScrollState())
                .imePadding(),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(text = "Reset your password", style = MaterialTheme.typography.headlineSmall)

            val sent = state.sentConfirmation
            if (sent != null) {
                Text(
                    text = sentConfirmationText(sent),
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier
                        .testTag("recovery_start_sent")
                        .semantics { liveRegion = LiveRegionMode.Polite },
                )
                TlButton(
                    text = "Back to sign in",
                    onClick = onBackToLogin,
                    variant = TlButtonVariant.Text,
                    modifier = Modifier.fillMaxWidth().testTag("recovery_start_back"),
                )
                return@Column
            }

            Text(
                text = "Enter the username for the account you want to recover.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            if (state.error != null) {
                Text(
                    text = state.error,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier
                        .testTag("recovery_start_error")
                        .semantics { liveRegion = LiveRegionMode.Assertive },
                )
            }

            TlTextField(
                value = state.username,
                onValueChange = onUsernameChange,
                label = "Username or email",
                enabled = !state.isSubmitting,
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Email,
                    capitalization = KeyboardCapitalization.None,
                    imeAction = ImeAction.Go,
                ),
                modifier = Modifier.testTag("recovery_start_username"),
            )

            TlButton(
                text = "Continue",
                onClick = onContinue,
                enabled = state.canContinue,
                loading = state.isSubmitting,
                modifier = Modifier.fillMaxWidth().testTag("recovery_start_continue"),
            )

            TlButton(
                text = "Back to sign in",
                onClick = onBackToLogin,
                variant = TlButtonVariant.Text,
                enabled = !state.isSubmitting,
                modifier = Modifier.fillMaxWidth().testTag("recovery_start_back"),
            )
        }
    }
}

private fun sentConfirmationText(summary: DeliverySummary): String {
    val dest = summary.destinationMasked
    return if (dest != null) {
        "If an account exists, we've sent recovery instructions via ${summary.medium} to $dest."
    } else {
        "If an account exists, we've sent recovery instructions to your registered contact method."
    }
}
