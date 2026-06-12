package com.testlogon.android.feature.call.history

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.CallMade
import androidx.compose.material.icons.outlined.CallReceived
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.call.CallDirection
import com.testlogon.android.data.call.CallHistoryEntry

/** AND-296 — call-history list route (reached from More / messaging). */
@Composable
fun CallHistoryRoute(
    onBack: () -> Unit,
    onCallBack: (peerUserId: String) -> Unit,
    modifier: Modifier = Modifier,
    viewModel: CallHistoryViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    CallHistoryScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::load,
        onLoadMore = viewModel::loadMore,
        onRowClick = onCallBack,
        modifier = modifier,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CallHistoryScreen(
    state: CallHistoryUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onLoadMore: () -> Unit,
    onRowClick: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag("call_history_screen"),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.call_history_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        when {
            state.isLoading && state.entries.isEmpty() ->
                LoadingState(modifier = Modifier.fillMaxSize().padding(padding))
            state.error != null && state.entries.isEmpty() ->
                ErrorState(
                    message = state.error,
                    onRetry = onRetry,
                    modifier = Modifier.fillMaxSize().padding(padding),
                )
            state.loaded && state.entries.isEmpty() ->
                EmptyState(
                    title = stringResource(R.string.call_history_empty),
                    modifier = Modifier.fillMaxSize().padding(padding),
                )
            else -> LazyColumn(
                modifier = Modifier.fillMaxSize().padding(padding),
            ) {
                items(state.entries, key = { it.callId }) { entry ->
                    CallHistoryRow(entry = entry, onClick = { onRowClick(entry.peerId()) })
                    HorizontalDivider()
                }
                if (state.canLoadMore) {
                    item {
                        Text(
                            text = stringResource(R.string.call_history_load_more),
                            style = MaterialTheme.typography.labelLarge,
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable(onClick = onLoadMore)
                                .padding(16.dp)
                                .testTag("call_history_load_more"),
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun CallHistoryRow(entry: CallHistoryEntry, onClick: () -> Unit) {
    ListItem(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .testTag("call_history_row"),
        headlineContent = { Text(entry.peerId()) },
        supportingContent = {
            Text(
                text = stringResource(
                    R.string.call_history_subtitle,
                    entry.rawStatus,
                    entry.durationSeconds,
                ),
                style = MaterialTheme.typography.bodySmall,
            )
        },
        leadingContent = {
            val icon = if (entry.direction == CallDirection.INCOMING) {
                Icons.Outlined.CallReceived
            } else {
                Icons.Outlined.CallMade
            }
            Icon(icon, contentDescription = null)
        },
    )
}

/** The "other party" id from the local user's perspective (best-effort: callee for outgoing). */
private fun CallHistoryEntry.peerId(): String =
    if (direction == CallDirection.INCOMING) callerId else calleeId
