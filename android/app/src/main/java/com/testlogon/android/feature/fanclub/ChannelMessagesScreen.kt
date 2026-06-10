@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalFoundationApi::class)

package com.testlogon.android.feature.fanclub

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.paging.LoadState
import androidx.paging.compose.LazyPagingItems
import androidx.paging.compose.collectAsLazyPagingItems
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.fanclub.FanClubMessage
import com.testlogon.android.data.fanclub.FanClubReaction

/** AND-239 — stable testTags for the channel messages screen. */
object ChannelMessagesTestTags {
    const val SCREEN = "fanclub_messages_screen"
    const val LIST = "fanclub_messages_list"
    const val EMPTY = "fanclub_messages_empty"
    const val ERROR = "fanclub_messages_error"
    const val COMPOSER = "fanclub_messages_composer"
    const val SEND = "fanclub_messages_send"
    const val PENDING = "fanclub_message_pending"
    const val ROW = "fanclub_message_row"
}

/** AND-239 — default quick-reaction emoji set (the react endpoint is an assumed single-emoji toggle). */
private val QUICK_REACTIONS = listOf("👍", "❤️", "🔥", "😂")

/** AND-239 — route-level channel messages entry, reached from the AND-238 channels list. */
@Composable
fun ChannelMessagesRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: ChannelMessagesViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val messages = viewModel.pagedMessages.collectAsLazyPagingItems()
    val snackbarHostState = remember { SnackbarHostState() }

    LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is ChannelMessagesEvent.ShowMessage -> snackbarHostState.showSnackbar(event.message)
            }
        }
    }

    ChannelMessagesScreen(
        state = state,
        messages = messages,
        snackbarHostState = snackbarHostState,
        canDelete = viewModel::canDelete,
        onComposerChange = viewModel::onComposerChange,
        onSend = viewModel::onSend,
        onRetryPending = viewModel::onRetryPending,
        onToggleReaction = viewModel::onToggleReaction,
        onDelete = viewModel::onDelete,
        onRefresh = viewModel::onRefresh,
        onBack = onBack,
        modifier = modifier,
    )
}

@Composable
fun ChannelMessagesScreen(
    state: ChannelMessagesUiState,
    messages: LazyPagingItems<FanClubMessage>,
    snackbarHostState: SnackbarHostState,
    canDelete: (FanClubMessage) -> Boolean,
    onComposerChange: (String) -> Unit,
    onSend: () -> Unit,
    onRetryPending: (String) -> Unit,
    onToggleReaction: (messageId: String, emoji: String) -> Unit,
    onDelete: (messageId: String) -> Unit,
    onRefresh: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(ChannelMessagesTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(state.channelName ?: stringResource(R.string.fanclub_messages_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("fanclub_messages_back")) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
        bottomBar = {
            MessageComposer(
                text = state.composerText,
                canPost = state.canPost,
                onTextChange = onComposerChange,
                onSend = onSend,
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        val refreshState = messages.loadState.refresh
        val hasContent = messages.itemCount > 0 || state.pending.isNotEmpty()
        Box(Modifier.fillMaxSize().padding(padding)) {
            when {
                refreshState is LoadState.Loading && !hasContent ->
                    LoadingState(message = stringResource(R.string.fanclub_messages_loading))

                refreshState is LoadState.Error && !hasContent -> {
                    val message = (refreshState.error as? ChannelMessagesLoadException)?.message
                        ?: stringResource(R.string.fanclub_messages_error_generic)
                    ErrorState(
                        message = message,
                        onRetry = messages::retry,
                        modifier = Modifier.testTag(ChannelMessagesTestTags.ERROR),
                    )
                }

                refreshState is LoadState.NotLoading && !hasContent ->
                    EmptyState(
                        title = stringResource(R.string.fanclub_messages_empty),
                        modifier = Modifier.testTag(ChannelMessagesTestTags.EMPTY),
                    )

                else -> MessageList(
                    state = state,
                    messages = messages,
                    canDelete = canDelete,
                    onRetryPending = onRetryPending,
                    onToggleReaction = onToggleReaction,
                    onDelete = onDelete,
                )
            }
        }
    }
}

@Composable
private fun MessageList(
    state: ChannelMessagesUiState,
    messages: LazyPagingItems<FanClubMessage>,
    canDelete: (FanClubMessage) -> Boolean,
    onRetryPending: (String) -> Unit,
    onToggleReaction: (String, String) -> Unit,
    onDelete: (String) -> Unit,
) {
    // reverseLayout: index 0 is the bottom (newest). Pending sends sit below the newest server row.
    LazyColumn(
        modifier = Modifier.fillMaxSize().testTag(ChannelMessagesTestTags.LIST),
        reverseLayout = true,
    ) {
        items(count = state.pending.size, key = { index -> state.pending[index].localId }) { index ->
            // Render newest pending at the very bottom (reverse: iterate from the end).
            val pending = state.pending[state.pending.size - 1 - index]
            PendingBubble(pending = pending, onRetry = { onRetryPending(pending.localId) })
        }

        items(count = messages.itemCount, key = { index -> messages.peek(index)?.id ?: index }) { index ->
            val message = messages[index]
            if (message != null && message.id !in state.deletedIds) {
                MessageBubble(
                    message = message,
                    deletable = canDelete(message),
                    onToggleReaction = { emoji -> onToggleReaction(message.id, emoji) },
                    onDelete = { onDelete(message.id) },
                )
            }
        }

        if (messages.loadState.append is LoadState.Loading) {
            item {
                Box(Modifier.fillMaxWidth().padding(16.dp), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator(modifier = Modifier.size(24.dp))
                }
            }
        }
    }
}

@Composable
private fun PendingBubble(pending: MessageItemUi.Pending, onRetry: () -> Unit) {
    Surface(
        color = MaterialTheme.colorScheme.primaryContainer,
        contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 4.dp)
            .testTag(ChannelMessagesTestTags.PENDING),
    ) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(pending.text, style = MaterialTheme.typography.bodyMedium)
            val statusRes = when (pending.sendState) {
                SendState.Sending -> R.string.fanclub_message_sending
                SendState.Sent -> R.string.fanclub_message_sent
                SendState.Failed -> R.string.fanclub_message_failed
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    stringResource(statusRes),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (pending.sendState == SendState.Failed) {
                    TextButton(onClick = onRetry) { Text(stringResource(R.string.action_retry)) }
                }
            }
        }
    }
}

@Composable
private fun MessageBubble(
    message: FanClubMessage,
    deletable: Boolean,
    onToggleReaction: (String) -> Unit,
    onDelete: () -> Unit,
) {
    var menuOpen by remember { mutableStateOf(false) }
    var reactionPickerOpen by remember { mutableStateOf(false) }

    Surface(
        color = MaterialTheme.colorScheme.surface,
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 4.dp)
            .combinedClickable(
                onClick = { reactionPickerOpen = true },
                onLongClick = { if (deletable) menuOpen = true },
            )
            .testTag(ChannelMessagesTestTags.ROW),
    ) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                message.senderBadge?.badgeEmoji?.let { Text("$it ", style = MaterialTheme.typography.labelMedium) }
                Text(
                    text = message.senderDisplayName,
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.primary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            if (message.deleted) {
                Text(
                    stringResource(R.string.fanclub_message_deleted),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                Text(message.text, style = MaterialTheme.typography.bodyLarge)
            }
            if (message.reactions.isNotEmpty()) {
                ReactionRow(reactions = message.reactions, onToggle = onToggleReaction)
            }

            DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.fanclub_message_delete)) },
                    onClick = {
                        menuOpen = false
                        onDelete()
                    },
                )
            }
            DropdownMenu(expanded = reactionPickerOpen, onDismissRequest = { reactionPickerOpen = false }) {
                Row(Modifier.padding(horizontal = 8.dp)) {
                    QUICK_REACTIONS.forEach { emoji ->
                        TextButton(onClick = {
                            reactionPickerOpen = false
                            onToggleReaction(emoji)
                        }) { Text(emoji) }
                    }
                }
            }
        }
    }
}

@Composable
private fun ReactionRow(
    reactions: List<FanClubReaction>,
    onToggle: (String) -> Unit,
) {
    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        reactions.forEach { reaction ->
            val cd = stringResource(
                R.string.fanclub_reaction_cd,
                reaction.emoji,
                reaction.count,
            )
            Surface(
                color = if (reaction.reactedByMe) {
                    MaterialTheme.colorScheme.secondaryContainer
                } else {
                    MaterialTheme.colorScheme.surfaceVariant
                },
                modifier = Modifier
                    .combinedClickable(onClick = { onToggle(reaction.emoji) })
                    .clearAndSetSemantics { contentDescription = cd },
            ) {
                Text(
                    text = "${reaction.emoji} ${reaction.count}",
                    style = MaterialTheme.typography.labelMedium,
                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                )
            }
        }
    }
}

@Composable
private fun MessageComposer(
    text: String,
    canPost: Boolean,
    onTextChange: (String) -> Unit,
    onSend: () -> Unit,
) {
    Surface(tonalElevation = 2.dp) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .imePadding()
                .padding(horizontal = 12.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            OutlinedTextField(
                value = text,
                onValueChange = onTextChange,
                enabled = canPost,
                placeholder = {
                    Text(
                        if (canPost) {
                            stringResource(R.string.fanclub_composer_hint)
                        } else {
                            stringResource(R.string.fanclub_composer_disabled)
                        },
                    )
                },
                modifier = Modifier.weight(1f).testTag(ChannelMessagesTestTags.COMPOSER),
            )
            IconButton(
                onClick = onSend,
                enabled = canPost && text.isNotBlank(),
                modifier = Modifier.testTag(ChannelMessagesTestTags.SEND),
            ) {
                Icon(
                    Icons.AutoMirrored.Filled.Send,
                    contentDescription = stringResource(R.string.fanclub_message_send_cd),
                )
            }
        }
    }
}
