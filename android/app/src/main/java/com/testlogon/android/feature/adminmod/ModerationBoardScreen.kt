@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.adminmod

import android.text.format.DateUtils
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Block
import androidx.compose.material.icons.outlined.Checklist
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.Flag
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.derivedStateOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.adminmod.ModerationTicketDto

object ModerationBoardTestTags {
    const val SCREEN = "mod_board_screen"
    const val LIST = "mod_board_list"
    const val EMPTY = "mod_board_empty"
    const val FORBIDDEN = "mod_board_forbidden"
    const val ERROR_RETRY = "mod_board_error_retry"
    const val SELECT_TOGGLE = "mod_board_select_toggle"
    const val BULK_BAR = "mod_board_bulk_bar"
    const val BANS = "mod_board_bans"
    fun ticket(id: String) = "mod_ticket_$id"
    fun filter(status: String?) = "mod_filter_${status ?: "all"}"
    fun topicFilter(topic: String?) = "mod_topic_${topic ?: "all"}"
    fun bulk(action: String) = "mod_bulk_$action"
}

@Composable
fun ModerationBoardRoute(
    onBack: () -> Unit,
    onOpenTicket: (String) -> Unit,
    onOpenBans: () -> Unit = {},
    viewModel: ModerationBoardViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    ModerationBoardScreen(
        state = state,
        onBack = onBack,
        onOpenTicket = onOpenTicket,
        onOpenBans = onOpenBans,
        onSetFilter = viewModel::setFilter,
        onSetTopicFilter = viewModel::setTopicFilter,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
        onLoadMore = viewModel::loadMore,
        onToggleSelectionMode = viewModel::toggleSelectionMode,
        onToggleSelected = viewModel::toggleSelected,
        onRunBulk = viewModel::runBulk,
        onClearBulkMessage = viewModel::clearBulkMessage,
    )
}

@Composable
fun ModerationBoardScreen(
    state: ModerationBoardUiState,
    onBack: () -> Unit,
    onOpenTicket: (String) -> Unit,
    onOpenBans: () -> Unit,
    onSetFilter: (String?) -> Unit,
    onSetTopicFilter: (String?) -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onLoadMore: () -> Unit,
    onToggleSelectionMode: () -> Unit,
    onToggleSelected: (String) -> Unit,
    onRunBulk: (ModerationBulkAction) -> Unit,
    onClearBulkMessage: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val content = state as? ModerationBoardUiState.Content
    val activeStatus = when (state) {
        is ModerationBoardUiState.Content -> state.statusFilter
        is ModerationBoardUiState.Empty -> state.statusFilter
        else -> null
    }
    val activeTopic = when (state) {
        is ModerationBoardUiState.Content -> state.topicFilter
        is ModerationBoardUiState.Empty -> state.topicFilter
        else -> null
    }
    val snackbarHostState = remember { SnackbarHostState() }
    LaunchedEffect(content?.bulkMessage) {
        content?.bulkMessage?.let {
            snackbarHostState.showSnackbar(it)
            onClearBulkMessage()
        }
    }

    Scaffold(
        modifier = modifier.testTag(ModerationBoardTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text(if (content?.selectionMode == true) "${content.selectedIds.size} selected" else "Moderation board") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(onClick = onOpenBans, modifier = Modifier.testTag(ModerationBoardTestTags.BANS)) {
                        Icon(Icons.Outlined.Block, contentDescription = "Ban management")
                    }
                    if (content != null) {
                        IconButton(
                            onClick = onToggleSelectionMode,
                            modifier = Modifier.testTag(ModerationBoardTestTags.SELECT_TOGGLE),
                        ) {
                            Icon(
                                if (content.selectionMode) Icons.Outlined.Close else Icons.Outlined.Checklist,
                                contentDescription = if (content.selectionMode) "Cancel selection" else "Select tickets",
                            )
                        }
                    }
                },
            )
        },
        bottomBar = {
            if (content?.selectionMode == true && content.selectedIds.isNotEmpty()) {
                BulkActionBar(inFlight = content.bulkInFlight, onRunBulk = onRunBulk)
            }
        },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            FilterRow(active = activeStatus, onSetFilter = onSetFilter)
            TopicFilterRow(active = activeTopic, onSetTopicFilter = onSetTopicFilter)
            val isRefreshing = content?.isRefreshing == true
            PullToRefreshBox(
                isRefreshing = isRefreshing,
                onRefresh = onRefresh,
                modifier = Modifier.fillMaxSize(),
            ) {
                when (state) {
                    is ModerationBoardUiState.Loading -> LoadingState()
                    is ModerationBoardUiState.Empty -> EmptyState(
                        modifier = Modifier.testTag(ModerationBoardTestTags.EMPTY),
                        title = "No tickets",
                        body = "There are no moderation tickets in this queue.",
                        imageVector = Icons.Outlined.Flag,
                    )
                    is ModerationBoardUiState.Forbidden -> EmptyState(
                        modifier = Modifier.testTag(ModerationBoardTestTags.FORBIDDEN),
                        title = "Not authorised",
                        body = "You need content-moderation admin access to view this queue.",
                        imageVector = Icons.Outlined.Lock,
                        actionLabel = "Back",
                        onAction = onBack,
                    )
                    is ModerationBoardUiState.Error -> ErrorState(
                        modifier = Modifier.testTag(ModerationBoardTestTags.ERROR_RETRY),
                        message = adminOpsErrorMessage(state.type),
                        onRetry = onRetry,
                    )
                    is ModerationBoardUiState.Content -> TicketList(state, onOpenTicket, onToggleSelected, onLoadMore)
                }
            }
        }
    }
}

@Composable
private fun TicketList(
    content: ModerationBoardUiState.Content,
    onOpenTicket: (String) -> Unit,
    onToggleSelected: (String) -> Unit,
    onLoadMore: () -> Unit,
) {
    val listState = rememberLazyListState()
    // MODX-21: infinite scroll — request the next page when the tail becomes visible.
    val shouldLoadMore by remember {
        derivedStateOf {
            val last = listState.layoutInfo.visibleItemsInfo.lastOrNull()?.index ?: 0
            content.canPaginate && !content.isLoadingMore && last >= content.tickets.size - 3
        }
    }
    LaunchedEffect(shouldLoadMore) { if (shouldLoadMore) onLoadMore() }

    LazyColumn(
        state = listState,
        modifier = Modifier.fillMaxSize().testTag(ModerationBoardTestTags.LIST),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        items(items = content.tickets, key = { it.ticketId }) { t ->
            TicketRow(
                ticket = t,
                selectionMode = content.selectionMode,
                selected = t.ticketId in content.selectedIds,
                onClick = {
                    if (content.selectionMode) onToggleSelected(t.ticketId) else onOpenTicket(t.ticketId)
                },
            )
        }
        if (content.isLoadingMore) {
            item(key = "__loading_more__") {
                Row(Modifier.fillMaxWidth().padding(16.dp), horizontalArrangement = Arrangement.Center) {
                    CircularProgressIndicator()
                }
            }
        }
    }
}

@Composable
private fun BulkActionBar(inFlight: Boolean, onRunBulk: (ModerationBulkAction) -> Unit) {
    Surface(tonalElevation = 3.dp, modifier = Modifier.testTag(ModerationBoardTestTags.BULK_BAR)) {
        Row(
            modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(12.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            if (inFlight) {
                CircularProgressIndicator(modifier = Modifier.padding(end = 8.dp))
            }
            ModerationBulkAction.entries.forEach { action ->
                AssistChip(
                    onClick = { if (!inFlight) onRunBulk(action) },
                    label = { Text(action.label) },
                    modifier = Modifier.testTag(ModerationBoardTestTags.bulk(action.wire)),
                )
            }
        }
    }
}

@Composable
private fun FilterRow(active: String?, onSetFilter: (String?) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        MODERATION_STATUS_FILTERS.forEach { status ->
            FilterChip(
                selected = active == status,
                onClick = { onSetFilter(status) },
                label = { Text(status?.replace('_', ' ')?.replaceFirstChar { it.uppercase() } ?: "All") },
                modifier = Modifier.testTag(ModerationBoardTestTags.filter(status)),
            )
        }
    }
}

@Composable
private fun TopicFilterRow(active: String?, onSetTopicFilter: (String?) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 4.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        MODERATION_TOPIC_FILTERS.forEach { topic ->
            FilterChip(
                selected = active == topic,
                onClick = { onSetTopicFilter(topic) },
                label = { Text(topic?.replace('_', ' ')?.replaceFirstChar { it.uppercase() } ?: "Any reason") },
                modifier = Modifier.testTag(ModerationBoardTestTags.topicFilter(topic)),
            )
        }
    }
}

@Composable
private fun TicketRow(
    ticket: ModerationTicketDto,
    selectionMode: Boolean,
    selected: Boolean,
    onClick: () -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(ModerationBoardTestTags.ticket(ticket.ticketId))
            .clickable(onClick = onClick),
    ) {
        Row(modifier = Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            if (selectionMode) {
                Checkbox(checked = selected, onCheckedChange = { onClick() }, modifier = Modifier.padding(end = 8.dp))
            }
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Text(
                    text = ticket.contentType.ifBlank { "content" }.replace('_', ' '),
                    style = MaterialTheme.typography.titleSmall,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        text = ticket.status.ifBlank { "-" }.replace('_', ' '),
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.primary,
                    )
                    Text(
                        text = "Priority ${ticket.priority.ifBlank { "-" }}",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Text(
                        text = "${ticket.reportCount} reports",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                if (ticket.aggregatedTopics.isNotEmpty()) {
                    Text(
                        text = ticket.aggregatedTopics.joinToString(", "),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
                if (ticket.latestReportAt > 0L) {
                    Text(
                        text = relativeSeconds(ticket.latestReportAt),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}

internal fun relativeSeconds(epochSeconds: Long): String = DateUtils.getRelativeTimeSpanString(
    epochSeconds * 1000L,
    System.currentTimeMillis(),
    DateUtils.MINUTE_IN_MILLIS,
).toString()

internal fun adminOpsErrorMessage(type: AdminOpsErrorType): String = when (type) {
    AdminOpsErrorType.AUTH -> "Your session expired. Please sign in again."
    AdminOpsErrorType.SERVER -> "Something went wrong on the server. Try again."
    AdminOpsErrorType.NETWORK -> "You appear to be offline. Check your connection."
}
