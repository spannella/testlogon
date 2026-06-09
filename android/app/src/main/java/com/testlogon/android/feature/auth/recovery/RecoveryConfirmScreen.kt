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
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.input.TlButton
import com.testlogon.android.core.ui.input.TlButtonVariant
import com.testlogon.android.core.ui.input.TlPasswordField

/** Route-level recovery-confirm entry, bound by the unauthenticated nav graph (AND-059). */
@Composable
fun RecoveryConfirmRoute(
    onSuccess: (username: String) -> Unit,
    onStartOver: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: RecoveryConfirmViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is RecoveryConfirmEffect.Success -> onSuccess(effect.username)
                RecoveryConfirmEffect.StartOver -> onStartOver()
            }
        }
    }

    RecoveryConfirmScreen(
        state = state,
        onNewPasswordChange = viewModel::onNewPasswordChange,
        onConfirmPasswordChange = viewModel::onConfirmPasswordChange,
        onSubmit = viewModel::onSubmit,
        onStartOver = viewModel::onStartOver,
        modifier = modifier,
    )
}

/** Stateless, previewable recovery-confirm screen (AND-059). */
@Composable
fun RecoveryConfirmScreen(
    state: RecoveryConfirmUiState,
    onNewPasswordChange: (String) -> Unit,
    onConfirmPasswordChange: (String) -> Unit,
    onSubmit: () -> Unit,
    onStartOver: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(modifier = modifier.testTag("recovery_confirm_screen")) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(24.dp)
                .verticalScroll(rememberScrollState())
                .imePadding(),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(text = "Set a new password", style = MaterialTheme.typography.headlineSmall)

            if (state.fatal != null) {
                Text(
                    text = fatalText(state.fatal),
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier
                        .testTag("recovery_confirm_fatal")
                        .semantics { liveRegion = LiveRegionMode.Assertive },
                )
                TlButton(
                    text = "Start over",
                    onClick = onStartOver,
                    modifier = Modifier.fillMaxWidth().testTag("recovery_confirm_start_over"),
                )
                return@Column
            }

            if (state.error != null) {
                Text(
                    text = state.error,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier
                        .testTag("recovery_confirm_error")
                        .semantics { liveRegion = LiveRegionMode.Assertive },
                )
            }

            TlPasswordField(
                value = state.newPassword,
                onValueChange = onNewPasswordChange,
                label = "New password",
                enabled = !state.isSubmitting,
                helperText = "12–128 chars with upper, lower, number and symbol.",
                imeAction = ImeAction.Next,
                modifier = Modifier.testTag("recovery_confirm_new_password"),
            )

            PasswordRulesChecklist(state.rules, modifier = Modifier.testTag("recovery_confirm_rules"))

            TlPasswordField(
                value = state.confirmPassword,
                onValueChange = onConfirmPasswordChange,
                label = "Confirm password",
                enabled = !state.isSubmitting,
                errorText = if (state.confirmPassword.isNotEmpty() && !state.passwordsMatch) {
                    "Passwords don't match."
                } else {
                    null
                },
                imeAction = ImeAction.Done,
                onImeAction = { if (state.isSubmitEnabled) onSubmit() },
                modifier = Modifier.testTag("recovery_confirm_confirm_password"),
            )

            TlButton(
                text = "Set password",
                onClick = onSubmit,
                enabled = state.isSubmitEnabled,
                loading = state.isSubmitting,
                modifier = Modifier.fillMaxWidth().testTag("recovery_confirm_submit"),
            )

            TlButton(
                text = "Start over",
                onClick = onStartOver,
                variant = TlButtonVariant.Text,
                enabled = !state.isSubmitting,
                modifier = Modifier.fillMaxWidth().testTag("recovery_confirm_start_over"),
            )
        }
    }
}

@Composable
private fun PasswordRulesChecklist(rules: PasswordRuleResults, modifier: Modifier = Modifier) {
    Column(modifier = modifier, verticalArrangement = Arrangement.spacedBy(2.dp)) {
        RuleRow(rules.minLength, "At least 12 characters")
        RuleRow(rules.hasUpper, "An uppercase letter")
        RuleRow(rules.hasLower, "A lowercase letter")
        RuleRow(rules.hasDigit, "A number")
        RuleRow(rules.hasSymbol, "A symbol")
    }
}

@Composable
private fun RuleRow(met: Boolean, label: String) {
    // Status is conveyed by text ("met"/"not met") + glyph, never color alone (a11y).
    val status = if (met) "met" else "not met"
    Text(
        text = "${if (met) "✓" else "•"} $label",
        style = MaterialTheme.typography.bodySmall,
        color = if (met) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.semantics { contentDescription = "$label: $status" },
    )
}

private fun fatalText(fatal: ConfirmFatal): String = when (fatal) {
    ConfirmFatal.MISSING_CONTEXT -> "Your recovery session is missing or has been lost. Please start over."
    ConfirmFatal.CHALLENGE_EXPIRED -> "Your recovery session has expired. Please start over."
}
