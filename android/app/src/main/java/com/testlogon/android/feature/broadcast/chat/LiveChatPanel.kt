package com.testlogon.android.feature.broadcast.chat

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.repeatOnLifecycle
import com.testlogon.android.R
import com.testlogon.android.data.broadcast.chat.ChatMessage
import com.testlogon.android.data.broadcast.chat.DeliveryState

/** AND-281 — stable testTags for the live-chat panel. */
object LiveChatTestTags {
    const val LIST = "live_chat_list"
    const val COMPOSER = "live_chat_composer"
    const val SEND = "live_chat_send"
    const val BANNER = "live_chat_banner"
}

/**
 * AND-281 — the live-chat panel composed into the AND-280 viewer. Subscribes to the SSE stream under
 * repeatOnLifecycle(STARTED) (connect when visible, disconnect when backgrounded). Reverse-scrolling
 * message list (newest at bottom), an optimistic composer, and a connection banner. The child VM is an
 * assisted-inject Hilt VM keyed by [sessionId].
 */
@Composable
fun LiveChatPanel(
    sessionId: String,
    modifier: Modifier = Modifier,
    viewModel: LiveChatViewModel = hiltViewModel<LiveChatViewModel, LiveChatViewModel.Factory>(
        key = "live_chat_$sessionId",
        creationCallback = { factory -> factory.create(sessionId) },
    ),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val lifecycleOwner = LocalLifecycleOwner.current

    LaunchedEffect(viewModel, lifecycleOwner) {
        lifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
            viewModel.onResumeStreaming()
        }
    }

    Surface(modifier = modifier, tonalElevation = 1.dp) {
        Column(modifier = Modifier.fillMaxWidth()) {
            when (state) {
                LiveChatUiState.Connecting -> ConnectionBanner(ConnectionStatus.RECONNECTING, onRetry = {})
                is LiveChatUiState.Error -> ConnectionBanner(ConnectionStatus.OFFLINE, onRetry = viewModel::retry)
                is LiveChatUiState.Content -> {
                    val content = state as LiveChatUiState.Content
                    if (content.connection != ConnectionStatus.LIVE) {
                        ConnectionBanner(content.connection, onRetry = viewModel::retry)
                    }
                    ChatMessageList(
                        messages = content.messages,
                        onRetrySend = viewModel::retrySend,
                        onAtBottomChanged = viewModel::onScrolledToBottom,
                        modifier = Modifier.fillMaxWidth().heightIn(max = 280.dp),
                    )
                    ChatComposer(
                        text = content.composerText,
                        canSend = content.canSend,
                        onTextChange = viewModel::onComposerTextChange,
                        onSend = viewModel::send,
                    )
                }
            }
        }
    }
}

@Composable
private fun ChatMessageList(
    messages: List<ChatMessage>,
    onRetrySend: (String) -> Unit,
    onAtBottomChanged: (Boolean) -> Unit,
    modifier: Modifier = Modifier,
) {
    if (messages.isEmpty()) {
        Box(
            modifier = modifier.padding(24.dp),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                text = stringResource(R.string.live_chat_empty),
                style = MaterialTheme.typography.bodyMedium,
                textAlign = TextAlign.Center,
            )
        }
        return
    }
    val listState = rememberLazyListState()
    // Reverse layout: render newest-last list reversed so the latest sits at the bottom.
    val reversed = messages.asReversed()
    LaunchedEffect(messages.size) {
        // Auto-scroll to the latest (index 0 in reverseLayout) when new messages arrive.
        listState.scrollToItem(0)
        onAtBottomChanged(true)
    }
    LazyColumn(
        state = listState,
        reverseLayout = true,
        modifier = modifier
            .semantics { liveRegion = LiveRegionMode.Polite }
            .testTag(LiveChatTestTags.LIST),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(8.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        items(reversed, key = { it.clientNonce ?: it.id }) { msg ->
            ChatRow(msg = msg, onRetrySend = onRetrySend)
        }
    }
}

@Composable
private fun ChatRow(msg: ChatMessage, onRetrySend: (String) -> Unit) {
    val failedLabel = stringResource(R.string.live_chat_message_failed)
    Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Column(modifier = Modifier.fillMaxWidth()) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = if (msg.isSelf) stringResource(R.string.live_chat_you) else msg.senderDisplayName,
                    style = MaterialTheme.typography.labelMedium,
                    color = if (msg.isSelf) {
                        MaterialTheme.colorScheme.primary
                    } else {
                        MaterialTheme.colorScheme.onSurfaceVariant
                    },
                )
                if (msg.isHost) {
                    Text(
                        text = stringResource(R.string.live_chat_host_badge),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.error,
                        modifier = Modifier
                            .padding(start = 6.dp)
                            .background(
                                MaterialTheme.colorScheme.errorContainer,
                                MaterialTheme.shapes.small,
                            )
                            .padding(horizontal = 4.dp),
                    )
                }
            }
            Text(
                text = msg.text.orEmpty(),
                style = MaterialTheme.typography.bodyMedium,
            )
            if (msg.deliveryState == DeliveryState.FAILED && msg.clientNonce != null) {
                Text(
                    text = failedLabel,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.error,
                    modifier = Modifier
                        .clickable { onRetrySend(msg.clientNonce) }
                        .semantics { role = Role.Button; contentDescription = failedLabel },
                )
            }
        }
    }
}

@Composable
private fun ChatComposer(
    text: String,
    canSend: Boolean,
    onTextChange: (String) -> Unit,
    onSend: () -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        OutlinedTextField(
            value = text,
            onValueChange = onTextChange,
            placeholder = { Text(stringResource(R.string.live_chat_composer_hint)) },
            singleLine = true,
            keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                imeAction = androidx.compose.ui.text.input.ImeAction.Send,
            ),
            keyboardActions = KeyboardActions(onSend = { if (canSend) onSend() }),
            modifier = Modifier
                .weight(1f)
                .testTag(LiveChatTestTags.COMPOSER),
        )
        val sendCd = stringResource(R.string.live_chat_send_cd)
        IconButton(
            onClick = onSend,
            enabled = canSend,
            modifier = Modifier
                .testTag(LiveChatTestTags.SEND)
                .semantics { role = Role.Button; contentDescription = sendCd },
        ) {
            Icon(Icons.AutoMirrored.Filled.Send, contentDescription = sendCd)
        }
    }
}

@Composable
private fun ConnectionBanner(status: ConnectionStatus, onRetry: () -> Unit) {
    val (labelRes, clickable) = when (status) {
        ConnectionStatus.LIVE -> R.string.live_chat_connecting to false
        ConnectionStatus.RECONNECTING -> R.string.live_chat_reconnecting to false
        ConnectionStatus.OFFLINE -> R.string.live_chat_offline to true
    }
    val label = stringResource(labelRes)
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surfaceVariant)
            .then(if (clickable) Modifier.clickable { onRetry() } else Modifier)
            .padding(8.dp)
            .semantics { liveRegion = LiveRegionMode.Assertive }
            .testTag(LiveChatTestTags.BANNER),
        contentAlignment = Alignment.Center,
    ) {
        Text(text = label, style = MaterialTheme.typography.labelMedium)
    }
}
