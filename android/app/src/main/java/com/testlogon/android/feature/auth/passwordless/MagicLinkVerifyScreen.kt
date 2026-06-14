package com.testlogon.android.feature.auth.passwordless

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.input.TlButton
import com.testlogon.android.core.ui.input.TlButtonVariant

/**
 * Route-level magic-link verify entry, bound by the unauthenticated nav graph + deep link (AND-061).
 *
 * The one-shot [MagicLinkVerifyEffect]s are consumed here and forwarded to the nav layer, which pops
 * the verify destination so the token cannot be replayed from the back stack.
 */
@Composable
fun MagicLinkVerifyRoute(
    onAuthenticated: () -> Unit,
    onMfaRequired: (challengeId: String, requiredFactors: List<String>) -> Unit,
    onRequestNewLink: () -> Unit,
    onUsePassword: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: MagicLinkVerifyViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    androidx.compose.runtime.LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                MagicLinkVerifyEffect.Authenticated -> onAuthenticated()
                is MagicLinkVerifyEffect.MfaRequired ->
                    onMfaRequired(effect.challengeId, effect.requiredFactors)
            }
        }
    }

    MagicLinkVerifyScreen(
        state = state,
        onRetry = viewModel::verify,
        onRequestNewLink = onRequestNewLink,
        onUsePassword = onUsePassword,
        modifier = modifier,
    )
}

/** Stateless, previewable magic-link verify screen (AND-061). */
@Composable
fun MagicLinkVerifyScreen(
    state: MagicLinkVerifyUiState,
    onRetry: () -> Unit,
    onRequestNewLink: () -> Unit,
    onUsePassword: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(modifier = modifier.testTag("magic_link_verify_screen")) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(24.dp)
                .verticalScroll(rememberScrollState()),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
        ) {
            when (state) {
                MagicLinkVerifyUiState.Verifying -> VerifyingContent()
                is MagicLinkVerifyUiState.Error ->
                    ErrorContent(
                        kind = state.kind,
                        onRetry = onRetry,
                        onRequestNewLink = onRequestNewLink,
                        onUsePassword = onUsePassword,
                    )
            }
        }
    }
}

@Composable
private fun VerifyingContent() {
    CircularProgressIndicator(
        modifier = Modifier
            .testTag("magic_link_verify_progress")
            .semantics {
                contentDescription = "Verifying your sign-in link"
                liveRegion = LiveRegionMode.Polite
            },
    )
    Text(text = "Verifying your sign-in link…", style = MaterialTheme.typography.bodyMedium)
}

@Composable
private fun ErrorContent(
    kind: MagicLinkError,
    onRetry: () -> Unit,
    onRequestNewLink: () -> Unit,
    onUsePassword: () -> Unit,
) {
    Text(
        text = errorTitle(kind),
        style = MaterialTheme.typography.headlineSmall,
        modifier = Modifier
            .testTag("magic_link_verify_error_title")
            .semantics { liveRegion = LiveRegionMode.Assertive },
    )
    Text(
        text = errorBody(kind),
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.testTag("magic_link_verify_error_body"),
    )

    if (kind == MagicLinkError.NETWORK || kind == MagicLinkError.SERVER) {
        // Transport / server errors are retryable with the SAME token (no auto-retry).
        TlButton(
            text = "Try again",
            onClick = onRetry,
            modifier = Modifier.fillMaxWidth().testTag("magic_link_verify_retry"),
        )
    }

    TlButton(
        text = "Request a new link",
        onClick = onRequestNewLink,
        modifier = Modifier.fillMaxWidth().testTag("magic_link_verify_new_link"),
    )

    TlButton(
        text = "Use password instead",
        onClick = onUsePassword,
        variant = TlButtonVariant.Text,
        modifier = Modifier.fillMaxWidth().testTag("magic_link_verify_use_password"),
    )
}

private fun errorTitle(kind: MagicLinkError): String = when (kind) {
    MagicLinkError.MISSING_TOKEN -> "Invalid sign-in link"
    MagicLinkError.EXPIRED -> "This link has expired"
    MagicLinkError.USED -> "This link was already used"
    MagicLinkError.INVALID -> "This link is no longer valid"
    MagicLinkError.NETWORK -> "Couldn't reach the server"
    MagicLinkError.SERVER -> "Something went wrong"
}

private fun errorBody(kind: MagicLinkError): String = when (kind) {
    MagicLinkError.MISSING_TOKEN -> "This sign-in link is missing its token. Request a new one to continue."
    MagicLinkError.EXPIRED -> "Sign-in links expire after a short time. Request a new one to continue."
    MagicLinkError.USED -> "This sign-in link can only be used once. Request a new one to continue."
    MagicLinkError.INVALID -> "This sign-in link may have expired or already been used. Request a new one to continue."
    MagicLinkError.NETWORK -> "Check your connection and try again."
    MagicLinkError.SERVER -> "Please try again in a moment."
}
