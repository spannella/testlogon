@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.tickets.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.ChatBubbleOutline
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
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
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.tickets.TicketMessage
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.StaleBanner

/** AND-372 - stable testTags for the ticket-thread screen + its message bubbles. */
object TicketThreadTestTags {
    const val SCREEN = "ticket_thread_screen"
    const val EMPTY = "tickets_empty"
    const val ERROR_RETRY = "tickets_error_retry"

    fun message(index: Int) = "ticket_msg_$index"
}

/**
 * AND-372 - route-level entry for the ticket thread (screen 3). Collects the state and wires the one-shot
 * NavigateToLogin effect to the re-auth handoff. READ-ONLY: there is NO composer (replying is AND-373).
 */
@Composable
fun TicketThreadRoute(
    onBack: () -> Unit,
    onNavigateToLogin: () -> Unit,
    viewModel: TicketThreadViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is TicketsEffect.NavigateToLogin -> onNavigateToLogin()
            }
        }
    }

    TicketThreadScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::onRetry,
    )
}

/**
 * AND-372 - stateless READ-ONLY ticket thread. Messages render oldest -> newest; a message whose sender_sub
 * equals the viewer's currentSub is visually distinguished (end-aligned, primary container). Auto-scrolls to the
 * newest message on first load. There is NO composer.
 */
@Composable
fun TicketThreadScreen(
    state: TicketThreadUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(TicketThreadTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(threadTitle(state)) },
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
        val isStale = (state as? TicketThreadUiState.Content)?.isStale == true
        PullToRefreshBox(
            isRefreshing = false,
            onRefresh = onRefresh,
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            when (state) {
                is TicketThreadUiState.Loading -> LoadingState()

                is TicketThreadUiState.Empty ->
                    EmptyState(
                        modifier = Modifier.testTag(TicketThreadTestTags.EMPTY),
                        title = stringResource(R.string.tickets_thread_empty_title),
                        body = stringResource(R.string.tickets_thread_empty_body),
                        imageVector = Icons.Outlined.ChatBubbleOutline,
                    )

                is TicketThreadUiState.Error ->
                    ErrorState(
                        modifier = Modifier.testTag(TicketThreadTestTags.ERROR_RETRY),
                        message = state.error.message,
                        onRetry = onRetry,
                    )

                is TicketThreadUiState.Content ->
                    ThreadBody(state = state, isStale = isStale, onRetry = onRetry)
            }
        }
    }
}

@Composable
private fun ThreadBody(
    state: TicketThreadUiState.Content,
    isStale: Boolean,
    onRetry: () -> Unit,
) {
    val messages = state.ticket.messages
    val listState = rememberLazyListState()

    // Auto-scroll to the newest (last) message on first load.
    LaunchedEffect(state.ticket.ticketId) {
        if (messages.isNotEmpty()) listState.scrollToItem(messages.lastIndex)
    }

    Column(modifier = Modifier.fillMaxSize()) {
        StaleBanner(stale = isStale, refreshing = false, onRetry = onRetry)
        LazyColumn(
            state = listState,
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            itemsIndexed(
                items = messages,
                key = { index, message -> message.messageId ?: "msg_$index" },
            ) { index, message ->
                MessageBubble(
                    message = message,
                    index = index,
                    isMine = message.senderSub != null && message.senderSub == state.currentSub,
                )
            }
        }
    }
}

@Composable
private fun MessageBubble(
    message: TicketMessage,
    index: Int,
    isMine: Boolean,
) {
    val alignment = if (isMine) Alignment.End else Alignment.Start
    val bubbleColor = if (isMine) {
        MaterialTheme.colorScheme.primaryContainer
    } else {
        MaterialTheme.colorScheme.surfaceVariant
    }
    val contentColor = if (isMine) {
        MaterialTheme.colorScheme.onPrimaryContainer
    } else {
        MaterialTheme.colorScheme.onSurfaceVariant
    }
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(TicketThreadTestTags.message(index)),
        horizontalAlignment = alignment,
    ) {
        Surface(
            color = bubbleColor,
            contentColor = contentColor,
            shape = MaterialTheme.shapes.medium,
            modifier = Modifier.widthIn(max = 300.dp),
        ) {
            Column(
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                verticalArrangement = Arrangement.spacedBy(2.dp),
            ) {
                Text(
                    text = message.senderSub?.ifBlank { null }
                        ?: stringResource(R.string.tickets_sender_unknown),
                    style = MaterialTheme.typography.labelMedium,
                )
                Text(
                    text = message.body?.ifBlank { null }
                        ?: stringResource(R.string.tickets_message_empty),
                    style = MaterialTheme.typography.bodyMedium,
                )
                val created = relativeTime(message.createdAt)
                if (created.isNotBlank()) {
                    Text(
                        text = created,
                        style = MaterialTheme.typography.labelSmall,
                    )
                }
            }
        }
    }
}

@Composable
private fun threadTitle(state: TicketThreadUiState): String {
    val subject = (state as? TicketThreadUiState.Content)?.ticket?.subject?.ifBlank { null }
    return subject ?: stringResource(R.string.tickets_thread_title)
}
