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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Flag
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material3.Card
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
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
    fun ticket(id: String) = "mod_ticket_$id"
    fun filter(status: String?) = "mod_filter_${status ?: "all"}"
}

@Composable
fun ModerationBoardRoute(
    onBack: () -> Unit,
    onOpenTicket: (String) -> Unit,
    viewModel: ModerationBoardViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    ModerationBoardScreen(
        state = state,
        onBack = onBack,
        onOpenTicket = onOpenTicket,
        onSetFilter = viewModel::setFilter,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
    )
}

@Composable
fun ModerationBoardScreen(
    state: ModerationBoardUiState,
    onBack: () -> Unit,
    onOpenTicket: (String) -> Unit,
    onSetFilter: (String?) -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val activeFilter = when (state) {
        is ModerationBoardUiState.Content -> state.statusFilter
        is ModerationBoardUiState.Empty -> state.statusFilter
        else -> null
    }
    Scaffold(
        modifier = modifier.testTag(ModerationBoardTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Moderation board") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            FilterRow(active = activeFilter, onSetFilter = onSetFilter)
            val isRefreshing = (state as? ModerationBoardUiState.Content)?.isRefreshing == true
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
                    is ModerationBoardUiState.Content -> LazyColumn(
                        modifier = Modifier.fillMaxSize().testTag(ModerationBoardTestTags.LIST),
                        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        items(items = state.tickets, key = { it.ticketId }) { t ->
                            TicketRow(t, onClick = { onOpenTicket(t.ticketId) })
                        }
                    }
                }
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
private fun TicketRow(ticket: ModerationTicketDto, onClick: () -> Unit) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(ModerationBoardTestTags.ticket(ticket.ticketId))
            .clickable(onClick = onClick),
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
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
