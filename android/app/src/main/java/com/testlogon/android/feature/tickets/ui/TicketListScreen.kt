@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.tickets.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Receipt
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.paging.LoadState
import androidx.paging.compose.LazyPagingItems
import androidx.paging.compose.collectAsLazyPagingItems
import com.testlogon.android.R
import com.testlogon.android.core.model.tickets.Ticket
import com.testlogon.android.core.network.tickets.TicketConstants
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState

/** AND-372 - stable testTags for the ticket-list screen + its rows. */
object TicketListTestTags {
    const val SCREEN = "ticket_list_screen"
    const val EMPTY = "tickets_empty"
    const val ERROR_RETRY = "tickets_error_retry"

    fun row(ticketId: String) = "ticket_row_$ticketId"
}

/**
 * AND-372 - route-level entry for the ticket list within a space (screen 2). Collects the paged tickets + the
 * space title, wires the one-shot NavigateToLogin effect, and taps through to a ticket's thread.
 */
@Composable
fun TicketListRoute(
    onBack: () -> Unit,
    onOpenTicket: (String) -> Unit,
    onNavigateToLogin: () -> Unit,
    viewModel: TicketListViewModel = hiltViewModel(),
) {
    val tickets = viewModel.tickets.collectAsLazyPagingItems()
    val title by viewModel.spaceTitle.collectAsStateWithLifecycle()

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is TicketsEffect.NavigateToLogin -> onNavigateToLogin()
            }
        }
    }

    TicketListScreen(
        tickets = tickets,
        spaceTitle = title,
        onBack = onBack,
        onTicketClick = onOpenTicket,
    )
}

/** AND-372 - stateless READ-ONLY ticket list (subject + status label + updated time + owner/assignee). */
@Composable
fun TicketListScreen(
    tickets: LazyPagingItems<Ticket>,
    spaceTitle: String?,
    onBack: () -> Unit,
    onTicketClick: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(TicketListTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = {
                    Text(spaceTitle?.ifBlank { null } ?: stringResource(R.string.tickets_list_title))
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.tickets_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        val refresh = tickets.loadState.refresh
        PullToRefreshBox(
            isRefreshing = refresh is LoadState.Loading && tickets.itemCount > 0,
            onRefresh = { tickets.refresh() },
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            when {
                refresh is LoadState.Loading && tickets.itemCount == 0 ->
                    LoadingState()

                refresh is LoadState.Error && tickets.itemCount == 0 ->
                    ErrorState(
                        modifier = Modifier.testTag(TicketListTestTags.ERROR_RETRY),
                        message = stringResource(R.string.tickets_list_error),
                        onRetry = { tickets.retry() },
                    )

                tickets.itemCount == 0 ->
                    EmptyState(
                        modifier = Modifier.testTag(TicketListTestTags.EMPTY),
                        title = stringResource(R.string.tickets_list_empty_title),
                        body = stringResource(R.string.tickets_list_empty_body),
                        imageVector = Icons.Outlined.Receipt,
                    )

                else -> LazyColumn(modifier = Modifier.fillMaxSize()) {
                    items(
                        count = tickets.itemCount,
                        key = { index -> tickets[index]?.ticketId ?: "ticket_$index" },
                    ) { index ->
                        val ticket = tickets[index] ?: return@items
                        TicketRow(ticket = ticket, onClick = { onTicketClick(ticket.ticketId) })
                    }
                }
            }
        }
    }
}

@Composable
private fun TicketRow(
    ticket: Ticket,
    onClick: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .testTag(TicketListTestTags.row(ticket.ticketId))
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(
            modifier = Modifier
                .weight(1f)
                .padding(end = 12.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text = ticket.subject?.ifBlank { null }
                    ?: stringResource(R.string.tickets_subject_untitled),
                style = MaterialTheme.typography.titleSmall,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
            StatusBadge(ticket.status)
            val updated = relativeTime(ticket.updatedAt)
            if (updated.isNotBlank()) {
                Text(
                    text = stringResource(R.string.tickets_updated, updated),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            val attributedTo = ticket.assignedToSub?.ifBlank { null } ?: ticket.ownerSub?.ifBlank { null }
            if (attributedTo != null) {
                Text(
                    text = stringResource(R.string.tickets_owner, attributedTo),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun StatusBadge(status: String?) {
    AssistChip(
        onClick = {},
        enabled = false,
        label = { Text(statusLabel(status)) },
        colors = AssistChipDefaults.assistChipColors(),
    )
}

/**
 * AND-372 - the human status label. A recognized [TicketConstants.TicketStatus] uses a localized string; an
 * unknown value falls back to the RAW wire token (or a generic label when blank), forward-compat for any new
 * server status.
 */
@Composable
private fun statusLabel(status: String?): String = when (status) {
    TicketConstants.TicketStatus.OPEN -> stringResource(R.string.tickets_status_open)
    TicketConstants.TicketStatus.IN_PROGRESS -> stringResource(R.string.tickets_status_in_progress)
    TicketConstants.TicketStatus.WAITING_ON_USER -> stringResource(R.string.tickets_status_waiting_on_user)
    TicketConstants.TicketStatus.DONE -> stringResource(R.string.tickets_status_done)
    TicketConstants.TicketStatus.REOPENED -> stringResource(R.string.tickets_status_reopened)
    else -> status?.ifBlank { null } ?: stringResource(R.string.tickets_status_unknown)
}
