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
 * Placeholder unauthenticated screens (AND-023). Real UI is owned by E04/E05 (AND-026+).
 * Each is stateless and takes only navigation lambdas (never a NavController).
 */

@Composable
fun LoginPlaceholderScreen(
    onContinueToMfa: (challengeId: String) -> Unit,
    onRegister: () -> Unit,
    onRecovery: () -> Unit,
    onMagicLink: () -> Unit,
    modifier: Modifier = Modifier,
) {
    PlaceholderScaffold(title = "Login", testTag = "login_screen", modifier = modifier) {
        TlButton(
            text = "Continue to MFA",
            onClick = { onContinueToMfa("chg_placeholder") },
            modifier = Modifier.testTag("login_to_mfa_button"),
        )
        TlButton(text = "Register", onClick = onRegister, variant = TlButtonVariant.Secondary)
        TlButton(text = "Recover account", onClick = onRecovery, variant = TlButtonVariant.Text)
        TlButton(text = "Use magic link", onClick = onMagicLink, variant = TlButtonVariant.Text)
    }
}

@Composable
fun MfaPlaceholderScreen(
    challengeId: String,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    PlaceholderScaffold(title = "MFA", testTag = "mfa_screen", modifier = modifier) {
        Text("challengeId: $challengeId", modifier = Modifier.testTag("mfa_challenge_id"))
        TlButton(text = "Back", onClick = onBack, variant = TlButtonVariant.Text)
    }
}

@Composable
fun RegisterPlaceholderScreen(onBack: () -> Unit, modifier: Modifier = Modifier) {
    PlaceholderScaffold(title = "Register", testTag = "register_screen", modifier = modifier) {
        TlButton(text = "Back", onClick = onBack, variant = TlButtonVariant.Text)
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
