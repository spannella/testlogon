package com.testlogon.android.feature.auth

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.testlogon.android.core.ui.input.TlButton
import com.testlogon.android.core.ui.input.TlButtonVariant

/**
 * Placeholder unauthenticated screens (AND-023) still owned by later tickets.
 *
 * Login (AND-030/031) and MFA (AND-039/040) are now real screens; the placeholders below remain for
 * Register / Recovery / MagicLink. Each is stateless and takes only navigation lambdas.
 */

/**
 * MFA-enrollment handoff target (AND-056). The real enrollment screens are owned by AND-064; until
 * they land, the registration → MFA-setup handoff routes here so the flow is end-to-end testable.
 */
@Composable
fun MfaSetupPlaceholderScreen(
    factors: List<String>,
    smsPhone: String?,
    onContinue: () -> Unit,
    modifier: Modifier = Modifier,
) {
    PlaceholderScaffold(title = "Set up two-factor auth", testTag = "mfa_setup_screen", modifier = modifier) {
        TlButton(text = "Continue", onClick = onContinue, variant = TlButtonVariant.Text)
    }
}

@Composable
fun RecoveryPlaceholderScreen(onBack: () -> Unit, modifier: Modifier = Modifier) {
    PlaceholderScaffold(title = "Password recovery", testTag = "recovery_screen", modifier = modifier) {
        TlButton(text = "Back", onClick = onBack, variant = TlButtonVariant.Text)
    }
}

@Composable
fun MagicLinkPlaceholderScreen(onBack: () -> Unit, modifier: Modifier = Modifier) {
    PlaceholderScaffold(title = "Magic link", testTag = "magic_link_screen", modifier = modifier) {
        TlButton(text = "Back", onClick = onBack, variant = TlButtonVariant.Text)
    }
}

@Composable
private fun PlaceholderScaffold(
    title: String,
    testTag: String,
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit,
) {
    Column(
        modifier = modifier.fillMaxSize().padding(24.dp).testTag(testTag),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(12.dp, Alignment.CenterVertically),
    ) {
        Text(
            text = title,
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        content()
    }
}
