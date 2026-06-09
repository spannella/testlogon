package com.testlogon.android.feature.settings.account

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.outlined.Devices
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.NoAccounts
import androidx.compose.material.icons.outlined.RestartAlt
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.AccountState
import com.testlogon.android.core.model.AccountStatus
import com.testlogon.android.core.ui.state.LoadingState

/**
 * AND-082 — route-level Account settings entry. Navigation callbacks deep-link to destinations owned
 * by other tickets/epics; [onCloseAccount] only fires after the confirm gate.
 */
@Composable
fun AccountSettingsRoute(
    onBack: () -> Unit,
    onOpenSessions: () -> Unit,
    onOpenMfaDevices: () -> Unit,
    onOpenPrivacy: () -> Unit,
    onReactivate: () -> Unit,
    onCloseAccount: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: AccountSettingsViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    AccountSettingsScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::load,
        onOpenSessions = onOpenSessions,
        onOpenMfaDevices = onOpenMfaDevices,
        onOpenPrivacy = onOpenPrivacy,
        onReactivate = onReactivate,
        onRequestClose = { viewModel.requestDestructive(DestructiveAction.CLOSE_ACCOUNT) },
        onDismissConfirm = viewModel::dismissConfirm,
        onConfirmClose = {
            viewModel.dismissConfirm()
            onCloseAccount()
        },
        modifier = modifier,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AccountSettingsScreen(
    state: AccountUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onOpenSessions: () -> Unit,
    onOpenMfaDevices: () -> Unit,
    onOpenPrivacy: () -> Unit,
    onReactivate: () -> Unit,
    onRequestClose: () -> Unit,
    onDismissConfirm: () -> Unit,
    onConfirmClose: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag("account_settings_screen"),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.account_settings_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Outlined.ArrowBack,
                            contentDescription = stringResource(R.string.settings_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        when (state) {
            AccountUiState.Loading ->
                LoadingState(modifier = Modifier.padding(padding).testTag("account_loading"))

            is AccountUiState.Error ->
                Column(
                    modifier = Modifier.fillMaxSize().padding(padding).padding(24.dp),
                    verticalArrangement = Arrangement.spacedBy(16.dp),
                ) {
                    Text(state.message, modifier = Modifier.testTag("account_error"))
                    Button(onClick = onRetry, modifier = Modifier.testTag("account_retry")) {
                        Text(stringResource(R.string.media_prefs_retry))
                    }
                }

            is AccountUiState.Ready -> ReadyContent(
                state = state,
                padding = padding,
                onOpenSessions = onOpenSessions,
                onOpenMfaDevices = onOpenMfaDevices,
                onOpenPrivacy = onOpenPrivacy,
                onReactivate = onReactivate,
                onRequestClose = onRequestClose,
            )
        }

        if (state is AccountUiState.Ready && state.pendingConfirm == DestructiveAction.CLOSE_ACCOUNT) {
            CloseConfirmDialog(onConfirm = onConfirmClose, onDismiss = onDismissConfirm)
        }
    }
}

@Composable
private fun ReadyContent(
    state: AccountUiState.Ready,
    padding: androidx.compose.foundation.layout.PaddingValues,
    onOpenSessions: () -> Unit,
    onOpenMfaDevices: () -> Unit,
    onOpenPrivacy: () -> Unit,
    onReactivate: () -> Unit,
    onRequestClose: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(padding)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        StatusBanner(status = state.status)

        LinkRow(
            tag = "account_row_sessions",
            icon = Icons.Outlined.Devices,
            title = stringResource(R.string.account_row_sessions),
            onClick = onOpenSessions,
        )
        LinkRow(
            tag = "account_row_mfa",
            icon = Icons.Outlined.Security,
            title = stringResource(R.string.account_row_mfa),
            onClick = onOpenMfaDevices,
        )
        LinkRow(
            tag = "account_row_privacy",
            icon = Icons.Outlined.Lock,
            title = stringResource(R.string.account_row_privacy),
            onClick = onOpenPrivacy,
        )
        if (state.showReactivate) {
            LinkRow(
                tag = "account_row_reactivate",
                icon = Icons.Outlined.RestartAlt,
                title = stringResource(R.string.account_row_reactivate),
                onClick = onReactivate,
            )
        }
        if (state.showClose) {
            LinkRow(
                tag = "account_row_close",
                icon = Icons.Outlined.NoAccounts,
                title = stringResource(R.string.account_row_close),
                destructive = true,
                onClick = onRequestClose,
            )
        }
    }
}

@Composable
private fun StatusBanner(status: AccountStatus) {
    val (labelRes, container) = when (status.state) {
        AccountState.ACTIVE ->
            R.string.account_state_active to MaterialTheme.colorScheme.secondaryContainer
        AccountState.SUSPENDED ->
            R.string.account_state_suspended to MaterialTheme.colorScheme.errorContainer
        AccountState.CLOSURE_PENDING ->
            R.string.account_state_closure_pending to MaterialTheme.colorScheme.errorContainer
        AccountState.CLOSED ->
            R.string.account_state_closed to MaterialTheme.colorScheme.errorContainer
        AccountState.UNKNOWN ->
            R.string.account_state_unknown to MaterialTheme.colorScheme.surfaceVariant
    }
    Card(
        modifier = Modifier.fillMaxWidth().padding(16.dp).testTag("account_status_banner"),
        colors = CardDefaults.cardColors(containerColor = container),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                text = stringResource(R.string.account_status_label, stringResource(labelRes)),
                style = MaterialTheme.typography.titleMedium,
            )
            status.reason?.takeIf { it.isNotBlank() }?.let { reason ->
                Text(
                    text = stringResource(R.string.account_reason_label, reason),
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
            status.closedAtEpochSeconds?.let { closed ->
                Text(
                    text = stringResource(R.string.account_closed_at_label, closed.toString()),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun LinkRow(
    tag: String,
    icon: ImageVector,
    title: String,
    destructive: Boolean = false,
    onClick: () -> Unit,
) {
    val color = if (destructive) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface
    ListItem(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(tag)
            .clickable(onClick = onClick),
        headlineContent = { Text(title, color = color) },
        leadingContent = { Icon(icon, contentDescription = null, tint = color) },
    )
}

@Composable
private fun CloseConfirmDialog(onConfirm: () -> Unit, onDismiss: () -> Unit) {
    AlertDialog(
        modifier = Modifier.testTag("account_close_confirm"),
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.account_close_confirm_title)) },
        text = { Text(stringResource(R.string.account_close_confirm_body)) },
        confirmButton = {
            TextButton(onClick = onConfirm, modifier = Modifier.testTag("account_close_confirm_yes")) {
                Text(stringResource(R.string.account_close_confirm_continue))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss, modifier = Modifier.testTag("account_close_confirm_cancel")) {
                Text(stringResource(R.string.account_close_confirm_cancel))
            }
        },
    )
}
