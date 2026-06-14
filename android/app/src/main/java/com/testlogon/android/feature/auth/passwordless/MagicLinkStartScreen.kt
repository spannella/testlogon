package com.testlogon.android.feature.auth.passwordless

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

/** Route-level magic-link-start entry, bound by the unauthenticated nav graph (AND-060). */
@Composable
fun MagicLinkStartRoute(
    onBackToLogin: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: MagicLinkStartViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    MagicLinkStartScreen(
        state = state,
        onIdentifierChange = viewModel::onIdentifierChange,
        onSubmit = viewModel::onSubmit,
        onResend = viewModel::onResend,
        onChangeEmail = viewModel::onChangeEmail,
        onBackToLogin = onBackToLogin,
        modifier = modifier,
    )
}

/** Stateless, previewable magic-link-start screen (AND-060). */
@Composable
fun MagicLinkStartScreen(
    state: MagicLinkStartUiState,
    onIdentifierChange: (String) -> Unit,
    onSubmit: () -> Unit,
    onResend: () -> Unit,
    onChangeEmail: () -> Unit,
    onBackToLogin: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(modifier = modifier.testTag("magic_link_start_screen")) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(24.dp)
                .verticalScroll(rememberScrollState())
                .imePadding(),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            if (state.phase == MagicLinkPhase.Confirmation) {
                ConfirmationContent(
                    state = state,
                    onResend = onResend,
                    onChangeEmail = onChangeEmail,
                    onBackToLogin = onBackToLogin,
                )
            } else {
                EntryContent(
                    state = state,
                    onIdentifierChange = onIdentifierChange,
                    onSubmit = onSubmit,
                    onBackToLogin = onBackToLogin,
                )
            }
        }
    }
}

@Composable
private fun EntryContent(
    state: MagicLinkStartUiState,
    onIdentifierChange: (String) -> Unit,
    onSubmit: () -> Unit,
    onBackToLogin: () -> Unit,
) {
    val sending = state.phase == MagicLinkPhase.Sending

    Text(text = "Sign in with a link", style = MaterialTheme.typography.headlineSmall)
    Text(
        text = "Enter your username or email and we'll send you a one-time sign-in link.",
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )

    if (state.error != null) {
        Text(
            text = state.error,
            color = MaterialTheme.colorScheme.error,
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier
                .testTag("magic_link_start_error")
                .semantics { liveRegion = LiveRegionMode.Assertive },
        )
    }

    TlTextField(
        value = state.identifier,
        onValueChange = onIdentifierChange,
        label = "Username or email",
        enabled = !sending,
        keyboardOptions = KeyboardOptions(
            keyboardType = KeyboardType.Email,
            capitalization = KeyboardCapitalization.None,
            imeAction = ImeAction.Go,
        ),
        modifier = Modifier.testTag("magic_link_start_identifier"),
    )

    TlButton(
        text = "Send sign-in link",
        onClick = onSubmit,
        enabled = state.isSubmitEnabled,
        loading = sending,
        modifier = Modifier.fillMaxWidth().testTag("magic_link_start_submit"),
    )

    TlButton(
        text = "Back to sign in",
        onClick = onBackToLogin,
        variant = TlButtonVariant.Text,
        enabled = !sending,
        modifier = Modifier.fillMaxWidth().testTag("magic_link_start_back"),
    )
}

@Composable
private fun ConfirmationContent(
    state: MagicLinkStartUiState,
    onResend: () -> Unit,
    onChangeEmail: () -> Unit,
    onBackToLogin: () -> Unit,
) {
    Text(
        text = "Check your email",
        style = MaterialTheme.typography.headlineSmall,
        modifier = Modifier
            .testTag("magic_link_start_confirm_title")
            .semantics { liveRegion = LiveRegionMode.Assertive },
    )
    Text(
        text = "Open the link we sent to ${state.identifier} to finish signing in.",
        style = MaterialTheme.typography.bodyMedium,
        modifier = Modifier.testTag("magic_link_start_confirm_body"),
    )

    if (state.sentTo.isNotEmpty()) {
        Text(
            text = "Sent to: ${state.sentTo.joinToString(", ")}",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.testTag("magic_link_start_sent_to"),
        )
    }

    if (state.error != null) {
        Text(
            text = state.error,
            color = MaterialTheme.colorScheme.error,
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier
                .testTag("magic_link_start_error")
                .semantics { liveRegion = LiveRegionMode.Assertive },
        )
    }

    val resendLabel = if (state.resendSecondsLeft > 0) {
        "Resend in ${state.resendSecondsLeft}s"
    } else {
        "Resend link"
    }
    TlButton(
        text = resendLabel,
        onClick = onResend,
        enabled = state.canResend,
        modifier = Modifier
            .fillMaxWidth()
            .testTag("magic_link_start_resend")
            .semantics { liveRegion = LiveRegionMode.Polite },
    )

    TlButton(
        text = "Use a different email",
        onClick = onChangeEmail,
        variant = TlButtonVariant.Text,
        modifier = Modifier.fillMaxWidth().testTag("magic_link_start_change"),
    )

    TlButton(
        text = "Back to sign in",
        onClick = onBackToLogin,
        variant = TlButtonVariant.Text,
        modifier = Modifier.fillMaxWidth().testTag("magic_link_start_back"),
    )
}
