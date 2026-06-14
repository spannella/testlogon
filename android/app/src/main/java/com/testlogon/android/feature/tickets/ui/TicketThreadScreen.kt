@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.tickets.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.outlined.ChatBubbleOutline
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.tickets.TicketMessage
import com.testlogon.android.core.model.tickets.TicketSendState
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.StaleBanner

/** AND-372 / AND-373 - stable testTags for the ticket-thread screen, its bubbles + the reply composer. */
object TicketThreadTestTags {
    const val SCREEN = "ticket_thread_screen"
    const val EMPTY = "tickets_empty"
    const val ERROR_RETRY = "tickets_error_retry"

    // AND-373 composer tags.
    const val REPLY_INPUT = "ticket_reply_input"
    const val REPLY_SEND = "ticket_reply_send"
    const val REPLY_ERROR = "ticket_reply_error"
    const val REPLY_DISABLED_CAPTION = "ticket_reply_disabled_caption"

    fun message(index: Int) = "ticket_msg_$index"

    /** AND-373 - per-optimistic-message send-state indicator tag. */
    fun messageState(clientId: String) = "ticket_msg_state_$clientId"
}

/**
 * AND-372 / AND-373 - route-level entry for the ticket thread (screen 3). Collects the state and wires the
 * one-shot NavigateToLogin effect to the re-auth handoff. AND-373 adds the REPLY composer callbacks.
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
        onDraftChanged = viewModel::onDraftChanged,
        onSend = viewModel::onSend,
        onRetrySend = viewModel::onRetry,
    )
}

/**
 * AND-372 / AND-373 - stateless ticket thread. Messages render oldest -> newest; a message whose sender_sub
 * equals the viewer's currentSub is visually distinguished (end-aligned, primary container). AND-373 pins a
 * REPLY composer to the bottom (hidden / captioned when !canPost or terminal); optimistic messages render a
 * Sending / Failed affordance with an inline retry.
 */
@Composable
fun TicketThreadScreen(
    state: TicketThreadUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
    onDraftChanged: (String) -> Unit = {},
    onSend: () -> Unit = {},
    onRetrySend: (String) -> Unit = {},
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
        bottomBar = {
            val content = state as? TicketThreadUiState.Content
            if (content != null) {
                ReplyComposer(
                    composer = content.composer,
                    onDraftChanged = onDraftChanged,
                    onSend = onSend,
                )
            }
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
                    ThreadBody(
                        state = state,
                        isStale = isStale,
                        onRetry = onRetry,
                        onRetrySend = onRetrySend,
                    )
            }
        }
    }
}

@Composable
private fun ThreadBody(
    state: TicketThreadUiState.Content,
    isStale: Boolean,
    onRetry: () -> Unit,
    onRetrySend: (String) -> Unit,
) {
    val messages = state.ticket.messages
    val listState = rememberLazyListState()

    // Auto-scroll to the newest (last) message on first load + when a new one is appended.
    LaunchedEffect(messages.size) {
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
                key = { index, message -> message.clientId ?: message.messageId ?: "msg_$index" },
            ) { index, message ->
                MessageBubble(
                    message = message,
                    index = index,
                    isMine = message.senderSub != null && message.senderSub == state.currentSub,
                    onRetrySend = onRetrySend,
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
    onRetrySend: (String) -> Unit,
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
        SendStateAffordance(message = message, onRetrySend = onRetrySend)
    }
}

/**
 * AND-373 - the per-message Sending / Failed affordance, shown only for optimistic messages (those carrying a
 * clientId). A SENT message renders nothing extra. A FAILED message exposes an inline retry.
 */
@Composable
private fun SendStateAffordance(
    message: TicketMessage,
    onRetrySend: (String) -> Unit,
) {
    val clientId = message.clientId ?: return
    when (message.sendState) {
        TicketSendState.SENDING ->
            Text(
                text = stringResource(R.string.ticket_reply_sending),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.testTag(TicketThreadTestTags.messageState(clientId)),
            )

        TicketSendState.FAILED ->
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.testTag(TicketThreadTestTags.messageState(clientId)),
            ) {
                Text(
                    text = stringResource(R.string.ticket_reply_failed),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.error,
                )
                TextButton(onClick = { onRetrySend(clientId) }) {
                    Text(stringResource(R.string.ticket_reply_retry))
                }
            }

        TicketSendState.SENT -> Unit
    }
}

/**
 * AND-373 - the bottom REPLY composer. When the viewer cannot post (viewer / non-member or a terminal ticket)
 * the input is replaced by a read-only caption. The send button is enabled only per [ComposerState.sendEnabled];
 * a char counter appears near the limit; a general send error renders inline above the input.
 */
@Composable
private fun ReplyComposer(
    composer: ComposerState,
    onDraftChanged: (String) -> Unit,
    onSend: () -> Unit,
) {
    Surface(tonalElevation = 2.dp) {
        Column(modifier = Modifier.fillMaxWidth()) {
            HorizontalDivider()
            if (!composer.canPost) {
                Text(
                    text = stringResource(R.string.ticket_reply_disabled_caption),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp)
                        .testTag(TicketThreadTestTags.REPLY_DISABLED_CAPTION),
                )
                return@Column
            }

            composer.sendError?.let { error ->
                Text(
                    text = error,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 4.dp)
                        .testTag(TicketThreadTestTags.REPLY_ERROR),
                )
            }

            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 12.dp, vertical = 8.dp),
                verticalAlignment = Alignment.Bottom,
            ) {
                OutlinedTextField(
                    value = composer.draft,
                    onValueChange = onDraftChanged,
                    modifier = Modifier
                        .weight(1f)
                        .testTag(TicketThreadTestTags.REPLY_INPUT),
                    placeholder = { Text(stringResource(R.string.ticket_reply_placeholder)) },
                    maxLines = 5,
                    isError = composer.overLimit || composer.fieldError != null,
                    enabled = !composer.sending,
                    supportingText = {
                        ComposerSupportingText(composer = composer)
                    },
                )
                IconButton(
                    onClick = onSend,
                    enabled = composer.sendEnabled,
                    modifier = Modifier
                        .size(48.dp)
                        .testTag(TicketThreadTestTags.REPLY_SEND),
                ) {
                    if (composer.sending) {
                        CircularProgressIndicator(modifier = Modifier.size(24.dp))
                    } else {
                        Icon(
                            Icons.AutoMirrored.Filled.Send,
                            contentDescription = stringResource(R.string.ticket_reply_send_cd),
                        )
                    }
                }
            }
        }
    }
}

/** AND-373 - the composer supporting line: a field error (422) takes precedence over the char counter. */
@Composable
private fun ComposerSupportingText(composer: ComposerState) {
    val fieldError = composer.fieldError
    if (fieldError != null) {
        Text(
            text = fieldError,
            color = MaterialTheme.colorScheme.error,
            modifier = Modifier.testTag(TicketThreadTestTags.REPLY_ERROR),
        )
        return
    }
    Text(
        text = stringResource(
            R.string.ticket_reply_char_counter,
            composer.trimmedLength,
            composer.maxLength,
        ),
        textAlign = TextAlign.End,
        modifier = Modifier.fillMaxWidth(),
        color = if (composer.overLimit) {
            MaterialTheme.colorScheme.error
        } else {
            MaterialTheme.colorScheme.onSurfaceVariant
        },
    )
}

@Composable
private fun threadTitle(state: TicketThreadUiState): String {
    val subject = (state as? TicketThreadUiState.Content)?.ticket?.subject?.ifBlank { null }
    return subject ?: stringResource(R.string.tickets_thread_title)
}
