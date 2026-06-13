@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.delegates.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.network.delegates.DelegatedConversationOut
import com.testlogon.android.core.network.delegates.DelegatedPostOut

/** AND-360 - stable testTags for the delegate console demonstration screen. */
object DelegateConsoleTestTags {
    const val SCREEN = "delegate_console_screen"
    const val POST_INPUT = "delegate_console_post_input"
    const val POST_SUBMIT = "delegate_console_post_submit"
    const val MESSAGE_INPUT_PREFIX = "delegate_console_message_input_"
    const val MESSAGE_SUBMIT_PREFIX = "delegate_console_message_submit_"
    const val POST_ROW_PREFIX = "delegate_console_post_row_"
    const val CONVERSATION_ROW_PREFIX = "delegate_console_conversation_row_"
}

/**
 * AND-360 - route-level delegate console. Reachable from the More hub behind the managed-creator state. It
 * lists the managed creator's delegate feed posts + conversations and offers create-post / send-message
 * gated by feed_post / chat_respond, with the persistent banner - proving "a delegate can act in delegated
 * surfaces" WITHOUT touching the mature feed / messaging screens.
 */
@Composable
fun DelegateConsoleRoute(
    onBack: () -> Unit,
    viewModel: DelegateConsoleViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    DelegateConsoleScreen(
        state = state,
        onBack = onBack,
        onExit = viewModel::exit,
        onCreatePost = viewModel::createPost,
        onSendMessage = viewModel::sendMessage,
        onNoticeShown = viewModel::consumeNotice,
    )
}

/** AND-360 - stateless delegate console screen. */
@Composable
fun DelegateConsoleScreen(
    state: DelegateConsoleUiState,
    onBack: () -> Unit,
    onExit: () -> Unit,
    onCreatePost: (String) -> Unit,
    onSendMessage: (conversationId: String, text: String) -> Unit,
    onNoticeShown: () -> Unit,
) {
    val snackbarHostState = remember { SnackbarHostState() }
    val loadFailedMessage = stringResource(R.string.delegate_console_load_failed)
    val actionFailedMessage = stringResource(R.string.delegate_console_action_failed)

    LaunchedEffect(state.notice) {
        if (state.notice != null) {
            snackbarHostState.showSnackbar(actionFailedMessage)
            onNoticeShown()
        }
    }
    LaunchedEffect(state.loadFailed) {
        if (state.loadFailed) snackbarHostState.showSnackbar(loadFailedMessage)
    }

    Scaffold(
        modifier = Modifier.testTag(DelegateConsoleTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.delegate_console_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.delegate_console_back),
                        )
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            if (state.active) {
                DelegationBanner(creatorName = state.creatorName, onExit = onExit)
            }
            if (!state.active) {
                NotDelegateContent()
            } else {
                DelegateConsoleContent(
                    state = state,
                    onCreatePost = onCreatePost,
                    onSendMessage = onSendMessage,
                )
            }
        }
    }
}

@Composable
private fun NotDelegateContent() {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(
            stringResource(R.string.delegate_console_not_delegate_title),
            style = MaterialTheme.typography.titleMedium,
        )
        Text(
            stringResource(R.string.delegate_console_not_delegate_body),
            style = MaterialTheme.typography.bodyMedium,
        )
    }
}

@Composable
private fun DelegateConsoleContent(
    state: DelegateConsoleUiState,
    onCreatePost: (String) -> Unit,
    onSendMessage: (conversationId: String, text: String) -> Unit,
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        item {
            Text(
                stringResource(R.string.delegate_console_feed_heading),
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.padding(top = 12.dp),
            )
        }
        if (!state.canReadFeed) {
            item { Text(stringResource(R.string.delegate_console_no_feed_permission)) }
        } else {
            if (state.canPostFeed) {
                item { PostComposer(onCreatePost = onCreatePost) }
            }
            if (state.posts.isEmpty()) {
                item { Text(stringResource(R.string.delegate_console_feed_empty)) }
            } else {
                items(state.posts, key = { it.postId }) { post -> PostRow(post) }
            }
        }

        item { HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp)) }

        item {
            Text(
                stringResource(R.string.delegate_console_messages_heading),
                style = MaterialTheme.typography.titleMedium,
            )
        }
        if (!state.canReadChat) {
            item { Text(stringResource(R.string.delegate_console_no_chat_permission)) }
        } else if (state.conversations.isEmpty()) {
            item { Text(stringResource(R.string.delegate_console_messages_empty)) }
        } else {
            items(state.conversations, key = { it.conversationId }) { conversation ->
                ConversationRow(
                    conversation = conversation,
                    canRespond = state.canRespond,
                    onSendMessage = onSendMessage,
                )
            }
        }
    }
}

@Composable
private fun PostComposer(onCreatePost: (String) -> Unit) {
    var text by remember { mutableStateOf("") }
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        OutlinedTextField(
            value = text,
            onValueChange = { text = it },
            placeholder = { Text(stringResource(R.string.delegate_console_compose_post_hint)) },
            modifier = Modifier
                .weight(1f)
                .testTag(DelegateConsoleTestTags.POST_INPUT),
        )
        Button(
            onClick = {
                onCreatePost(text)
                text = ""
            },
            modifier = Modifier.testTag(DelegateConsoleTestTags.POST_SUBMIT),
        ) {
            Text(stringResource(R.string.delegate_console_post_action))
        }
    }
}

@Composable
private fun PostRow(post: DelegatedPostOut) {
    Column(modifier = Modifier.fillMaxWidth().testTag(DelegateConsoleTestTags.POST_ROW_PREFIX + post.postId)) {
        Text(post.text.orEmpty(), style = MaterialTheme.typography.bodyMedium)
        if (post.approvalStatus != null) {
            Text(
                stringResource(R.string.delegate_console_post_pending),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.tertiary,
            )
        }
    }
}

@Composable
private fun ConversationRow(
    conversation: DelegatedConversationOut,
    canRespond: Boolean,
    onSendMessage: (conversationId: String, text: String) -> Unit,
) {
    var text by remember(conversation.conversationId) { mutableStateOf("") }
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(DelegateConsoleTestTags.CONVERSATION_ROW_PREFIX + conversation.conversationId),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Text(
            conversation.title ?: conversation.conversationId,
            style = MaterialTheme.typography.bodyMedium,
        )
        conversation.lastMessagePreview?.let {
            Text(it, style = MaterialTheme.typography.bodySmall)
        }
        if (canRespond) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = text,
                    onValueChange = { text = it },
                    placeholder = { Text(stringResource(R.string.delegate_console_compose_message_hint)) },
                    modifier = Modifier
                        .weight(1f)
                        .testTag(DelegateConsoleTestTags.MESSAGE_INPUT_PREFIX + conversation.conversationId),
                )
                Button(
                    onClick = {
                        onSendMessage(conversation.conversationId, text)
                        text = ""
                    },
                    modifier = Modifier.testTag(
                        DelegateConsoleTestTags.MESSAGE_SUBMIT_PREFIX + conversation.conversationId,
                    ),
                ) {
                    Text(stringResource(R.string.delegate_console_send_action))
                }
            }
        }
    }
}
