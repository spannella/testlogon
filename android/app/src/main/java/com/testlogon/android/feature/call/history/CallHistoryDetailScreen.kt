@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.call.history

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Call
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.call.CallHistoryEntry
import com.testlogon.android.feature.call.incall.CallDurationFormatter

/** AND-303 — stable testTags for the call-history detail screen. */
object CallHistoryDetailTestTags {
    const val SCREEN = "call_history_detail"
    const val CALLBACK = "call_history_callback"
    const val DELETE = "call_history_delete"
}

/**
 * AND-303 — single call-history record route.
 *
 * Pops back via [onBack] once a delete succeeds. The "Call back" button is rendered DISABLED: the AND-295
 * invite (POST messaging/messages/calls/invite) needs a conversation_id, but a [CallHistoryEntry] (the
 * ui/calls history namespace CallRecordOut) carries no conversation_id — so per AC-2 there is no resolvable
 * conversation_id and the action is disabled (no request is ever issued). We deliberately do NOT fabricate
 * a conversation_id.
 */
@Composable
fun CallHistoryDetailRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: CallHistoryDetailViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    LaunchedEffect(state.deleted) {
        if (state.deleted) onBack()
    }
    CallHistoryDetailScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::load,
        onDelete = viewModel::delete,
        modifier = modifier,
    )
}

@Composable
fun CallHistoryDetailScreen(
    state: CallHistoryDetailUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onDelete: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(CallHistoryDetailTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.call_history_detail_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
                actions = {
                    IconButton(
                        onClick = onDelete,
                        enabled = state.entry != null && !state.isDeleting,
                        modifier = Modifier.testTag(CallHistoryDetailTestTags.DELETE),
                    ) {
                        Icon(
                            Icons.Outlined.Delete,
                            contentDescription = stringResource(R.string.call_history_delete),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when {
                state.isLoading && state.entry == null -> LoadingState()
                state.entry == null && state.error != null ->
                    ErrorState(message = state.error, onRetry = onRetry)
                state.entry != null -> CallHistoryDetailContent(state.entry)
            }
        }
    }
}

@Composable
private fun CallHistoryDetailContent(entry: CallHistoryEntry) {
    val durationText = if (entry.hasDuration) {
        CallDurationFormatter.format(entry.durationSeconds)
    } else {
        stringResource(R.string.call_history_duration_none)
    }
    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                DetailLine(
                    label = stringResource(entry.mode.labelRes()),
                    value = stringResource(entry.direction.labelRes()),
                )
                DetailLine(
                    label = stringResource(R.string.call_history_detail_started),
                    value = entry.createdAtEpochSeconds.toString(),
                )
                DetailLine(
                    label = stringResource(entry.status.labelRes()),
                    value = durationText,
                )
                DetailLine(
                    label = stringResource(R.string.call_history_detail_caller),
                    value = entry.callerId,
                )
                DetailLine(
                    label = stringResource(R.string.call_history_detail_callee),
                    value = entry.calleeId,
                )
            }
        }

        // AC-2: no resolvable conversation_id on a history record -> Call back is DISABLED (never issued).
        OutlinedButton(
            onClick = {},
            enabled = false,
            modifier = Modifier
                .fillMaxWidth()
                .testTag(CallHistoryDetailTestTags.CALLBACK),
        ) {
            Icon(Icons.Outlined.Call, contentDescription = null)
            Text(
                text = stringResource(R.string.call_history_callback),
                modifier = Modifier.padding(start = 8.dp),
            )
        }
        Text(
            text = stringResource(R.string.call_history_callback_unavailable),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun DetailLine(label: String, value: String) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(text = value, style = MaterialTheme.typography.bodyLarge)
    }
}
