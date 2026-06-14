package com.testlogon.android.feature.profile

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.input.TlButton
import com.testlogon.android.core.ui.input.TlButtonVariant
import com.testlogon.android.feature.auth.passkey.AddPasskeySection

/**
 * Account / security actions surfaced on the Profile tab (AND-032): active sessions, two-factor
 * devices, register passkey, and logout. Rendered as an inline section beneath the own-profile view
 * (AND-071) rather than a full screen.
 */
@Composable
fun AccountActionsSection(
    modifier: Modifier = Modifier,
    onOpenSessions: () -> Unit = {},
    onOpenMfaDevices: () -> Unit = {},
    onOpenSettings: () -> Unit = {},
    viewModel: AccountActionsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    Column(
        modifier = modifier
            .fillMaxWidth()
            .testTag("account_actions_section"),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        HorizontalDivider()
        Text(
            text = stringResource(R.string.profile_account_section_title),
            style = MaterialTheme.typography.titleMedium,
        )
        Text(
            text = state.userSub?.let { stringResource(R.string.profile_signed_in_as, it) }
                ?: stringResource(R.string.profile_signed_in),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        TlButton(
            text = stringResource(R.string.profile_active_sessions),
            onClick = onOpenSessions,
            variant = TlButtonVariant.Secondary,
            modifier = Modifier.fillMaxWidth().testTag("profile_active_sessions"),
        )
        TlButton(
            text = stringResource(R.string.profile_two_factor),
            onClick = onOpenMfaDevices,
            variant = TlButtonVariant.Secondary,
            modifier = Modifier.fillMaxWidth().testTag("profile_mfa_devices"),
        )
        // AND-077: entry into the Settings hub from the Profile tab.
        TlButton(
            text = stringResource(R.string.profile_settings),
            onClick = onOpenSettings,
            variant = TlButtonVariant.Secondary,
            modifier = Modifier.fillMaxWidth().testTag("profile_settings"),
        )
        // AND-062: register-passkey entry, shown only when the device supports platform passkeys.
        AddPasskeySection()
        TlButton(
            text = stringResource(R.string.profile_log_out),
            onClick = viewModel::onLogout,
            variant = TlButtonVariant.Secondary,
            loading = state.loggingOut,
            modifier = Modifier.fillMaxWidth().testTag("profile_logout"),
        )
    }
}
