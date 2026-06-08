package com.testlogon.android.feature.sessions

import android.text.format.DateUtils
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.input.TlButton
import com.testlogon.android.core.ui.input.TlButtonVariant
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.StaleBanner

/** Route-level Active Sessions entry, reachable from Profile (AND-043). */
@Composable
fun ActiveSessionsRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: ActiveSessionsViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    ActiveSessionsScreen(
        state = state,
        onRetry = viewModel::load,
        onRevoke = viewModel::requestRevoke,
        onRevokeOthers = viewModel::requestRevokeOthers,
        onConfirm = viewModel::confirm,
        onDismissConfirm = viewModel::dismissConfirm,
        onBack = onBack,
        modifier = modifier,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ActiveSessionsScreen(
    state: ActiveSessionsUiState,
    onRetry: () -> Unit,
    onRevoke: (String) -> Unit,
    onRevokeOthers: () -> Unit,
    onConfirm: () -> Unit,
    onDismissConfirm: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag("active_sessions_screen"),
        topBar = {
            TopAppBar(
                title = { Text("Active sessions") },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("sessions_back")) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            StaleBanner(
                stale = state.isStale,
                refreshing = state.isReconnecting,
                onRetry = onRetry,
                modifier = Modifier.testTag("sessions_stale_banner"),
            )
            when {
                state.isLoading && !state.loaded -> LoadingState()
                state.error != null && state.rows.isEmpty() ->
                    ErrorState(message = state.error, onRetry = onRetry)
                state.loaded && state.rows.isEmpty() ->
                    EmptyState(title = "No active sessions")
                else -> SessionsList(state, onRevoke, onRevokeOthers)
            }
        }
    }

    val confirm = state.confirm
    if (confirm != null) {
        val (title, body) = when (confirm) {
            is ConfirmTarget.RevokeOne -> "Sign out session?" to "This will end that session immediately."
            ConfirmTarget.RevokeOthers -> "Sign out all other sessions?" to
                "Every session except this device will be ended."
        }
        AlertDialog(
            onDismissRequest = onDismissConfirm,
            modifier = Modifier.testTag("sessions_confirm_dialog"),
            title = { Text(title) },
            text = { Text(body) },
            confirmButton = {
                TextButton(onClick = onConfirm, modifier = Modifier.testTag("sessions_confirm")) {
                    Text("Sign out")
                }
            },
            dismissButton = {
                TextButton(onClick = onDismissConfirm) { Text("Cancel") }
            },
        )
    }
}

@Composable
private fun SessionsList(
    state: ActiveSessionsUiState,
    onRevoke: (String) -> Unit,
    onRevokeOthers: () -> Unit,
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize().testTag("sessions_list"),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        items(state.rows, key = { it.info.sessionId }) { row ->
            SessionCard(row = row, onRevoke = onRevoke)
        }
        if (state.canRevokeOthers) {
            item {
                TlButton(
                    text = "Sign out all other sessions",
                    onClick = onRevokeOthers,
                    variant = TlButtonVariant.Secondary,
                    loading = state.revokingOthers,
                    modifier = Modifier.fillMaxWidth().testTag("sessions_revoke_others"),
                )
            }
        }
    }
}

@Composable
private fun SessionCard(row: SessionRow, onRevoke: (String) -> Unit) {
    val info = row.info
    val lastSeen = relativeTime(info.lastSeenAt)
    val cd = buildString {
        if (row.isCurrent) append("This device, ")
        append(info.userAgent).append(", ")
        append(info.ip).append(", last seen ").append(lastSeen)
        if (info.revoked) append(", revoked")
    }
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag("session_row_${info.sessionId}")
            .semantics { contentDescription = cd },
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(info.userAgent, style = MaterialTheme.typography.titleSmall)
            Text(
                text = "${info.ip} • last seen $lastSeen",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (row.isCurrent) {
                AssistChip(
                    onClick = {},
                    enabled = false,
                    label = { Text("This device") },
                    colors = AssistChipDefaults.assistChipColors(),
                    modifier = Modifier.testTag("session_current_badge_${info.sessionId}"),
                )
            } else if (info.revoked) {
                AssistChip(onClick = {}, enabled = false, label = { Text("Revoked") })
            } else {
                TlButton(
                    text = "Sign out",
                    onClick = { onRevoke(info.sessionId) },
                    variant = TlButtonVariant.Text,
                    modifier = Modifier.testTag("session_revoke_${info.sessionId}"),
                )
            }
        }
    }
}

private fun relativeTime(epochSeconds: Long): CharSequence =
    DateUtils.getRelativeTimeSpanString(
        epochSeconds * 1000L,
        System.currentTimeMillis(),
        DateUtils.MINUTE_IN_MILLIS,
    )
