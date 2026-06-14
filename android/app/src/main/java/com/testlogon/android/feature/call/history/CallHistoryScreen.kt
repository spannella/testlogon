@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.call.history

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.CallMade
import androidx.compose.material.icons.outlined.CallReceived
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material.icons.outlined.Videocam
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.snapshotFlow
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
import com.testlogon.android.data.call.CallMode
import com.testlogon.android.data.call.CallStats
import com.testlogon.android.feature.call.incall.CallDurationFormatter
import kotlinx.coroutines.flow.distinctUntilChanged

/** AND-303 — stable testTags for the call-history list screen. */
object CallHistoryTestTags {
    const val SCREEN = "call_history_screen"
    const val LIST = "call_history_list"
    const val ROW = "call_history_row"
    const val EMPTY = "call_history_empty"
    const val ERROR = "call_history_error"
    const val STATS = "call_history_stats"
    const val APPEND_RETRY = "call_history_load_more"
    const val DELETE = "call_history_row_delete"
}

/**
 * AND-296/AND-303 — call-history list route (reached from More / messaging).
 *
 * Row tap opens the detail screen ([onOpenDetail]); "Call back" is intentionally NOT wired here because a
 * [CallHistoryEntry] carries no conversation_id (see [CallHistoryDetailScreen] for the disabled affordance).
 */
@Composable
fun CallHistoryRoute(
    onBack: () -> Unit,
    onOpenDetail: (callId: String) -> Unit,
    modifier: Modifier = Modifier,
    viewModel: CallHistoryViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    CallHistoryScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::load,
        onRefresh = viewModel::refresh,
        onLoadMore = viewModel::loadMore,
        onRetryLoadMore = viewModel::retryLoadMore,
        onOpenDetail = onOpenDetail,
        onDelete = viewModel::delete,
        modifier = modifier,
    )
}

@Composable
fun CallHistoryScreen(
    state: CallHistoryUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onRefresh: () -> Unit,
    onLoadMore: () -> Unit,
    onRetryLoadMore: () -> Unit,
    onOpenDetail: (String) -> Unit,
    onDelete: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(CallHistoryTestTags.SCREEN),
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
        Box(Modifier.fillMaxSize().padding(padding)) {
            when {
                state.isLoading && state.entries.isEmpty() && !state.isRefreshing ->
                    LoadingState()

                state.refreshError != null && state.entries.isEmpty() ->
                    ErrorState(
                        message = state.refreshError,
                        onRetry = onRetry,
                        modifier = Modifier.testTag(CallHistoryTestTags.ERROR),
                    )

                state.isEmpty ->
                    EmptyState(
                        title = stringResource(R.string.call_history_empty),
                        modifier = Modifier.testTag(CallHistoryTestTags.EMPTY),
                    )

                else -> CallHistoryList(
                    state = state,
                    onRefresh = onRefresh,
                    onLoadMore = onLoadMore,
                    onRetryLoadMore = onRetryLoadMore,
                    onOpenDetail = onOpenDetail,
                    onDelete = onDelete,
                )
            }
        }
    }
}

@Composable
private fun CallHistoryList(
    state: CallHistoryUiState,
    onRefresh: () -> Unit,
    onLoadMore: () -> Unit,
    onRetryLoadMore: () -> Unit,
    onOpenDetail: (String) -> Unit,
    onDelete: (String) -> Unit,
) {
    val listState = rememberLazyListState()

    // AND-303 — paging trigger: fetch the next page when the last item becomes visible. snapshotFlow keeps
    // this off the composition hot path; canLoadMore guards against re-firing while a page is in flight.
    // Re-keyed on entries.size so the collector never reads a stale list after an append.
    val canLoadMore = state.canLoadMore
    val entryCount = state.entries.size
    LaunchedEffect(listState, canLoadMore, entryCount) {
        if (!canLoadMore) return@LaunchedEffect
        snapshotFlow { listState.layoutInfo.visibleItemsInfo.lastOrNull()?.index ?: -1 }
            .distinctUntilChanged()
            .collect { lastVisible ->
                if (lastVisible >= entryCount - 1) {
                    onLoadMore()
                }
            }
    }

    PullToRefreshBox(
        isRefreshing = state.isRefreshing,
        onRefresh = onRefresh,
        modifier = Modifier.fillMaxSize(),
    ) {
        LazyColumn(
            state = listState,
            modifier = Modifier.fillMaxSize().testTag(CallHistoryTestTags.LIST),
        ) {
            state.stats?.let { stats ->
                item(key = "stats") { CallHistoryStatsCard(stats) }
            }
            items(state.entries, key = { it.callId }) { entry ->
                CallHistoryRow(
                    entry = entry,
                    onClick = { onOpenDetail(entry.callId) },
                    onDelete = { onDelete(entry.callId) },
                )
                HorizontalDivider()
            }
            if (state.appendError != null) {
                item(key = "append_error") {
                    Text(
                        text = stringResource(R.string.call_history_load_more_retry),
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.error,
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable(onClick = onRetryLoadMore)
                            .padding(16.dp)
                            .testTag(CallHistoryTestTags.APPEND_RETRY),
                    )
                }
            }
        }
    }
}

@Composable
private fun CallHistoryStatsCard(stats: CallStats) {
    Card(
        Modifier
            .fillMaxWidth()
            .padding(16.dp)
            .testTag(CallHistoryTestTags.STATS),
    ) {
        Column(
            Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text = stringResource(R.string.call_history_stats_total, stats.totalCalls),
                style = MaterialTheme.typography.titleMedium,
            )
            Text(
                text = stringResource(
                    R.string.call_history_stats_duration,
                    CallDurationFormatter.format(stats.totalDurationSeconds),
                ),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun CallHistoryRow(
    entry: CallHistoryEntry,
    onClick: () -> Unit,
    onDelete: () -> Unit,
) {
    val durationText = if (entry.hasDuration) {
        CallDurationFormatter.format(entry.durationSeconds)
    } else {
        stringResource(R.string.call_history_duration_none)
    }
    val statusText = stringResource(entry.status.labelRes())
    ListItem(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .testTag(CallHistoryTestTags.ROW),
        headlineContent = { Text(entry.peerId()) },
        supportingContent = {
            Text(
                text = "$statusText · $durationText",
                style = MaterialTheme.typography.bodySmall,
            )
        },
        leadingContent = {
            val icon = when {
                entry.mode == CallMode.VIDEO -> Icons.Outlined.Videocam
                entry.direction == CallDirection.INCOMING -> Icons.Outlined.CallReceived
                else -> Icons.Outlined.CallMade
            }
            Icon(icon, contentDescription = stringResource(entry.direction.labelRes()))
        },
        trailingContent = {
            IconButton(
                onClick = onDelete,
                modifier = Modifier.testTag(CallHistoryTestTags.DELETE),
            ) {
                Icon(
                    Icons.Outlined.Delete,
                    contentDescription = stringResource(R.string.call_history_delete),
                )
            }
        },
    )
}
