package com.testlogon.android.feature.messaging.thread

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.ArrowDownward
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.feature.messaging.relativeTimeFromSeconds
import kotlinx.coroutines.launch

/** Stable testTags for the thread screen (AND-123 / AND-124). */
object ThreadTestTags {
    const val SCREEN = "thread_screen"
    const val LIST = "thread_list"
    const val MESSAGE = "thread_message"
    const val OWN_MESSAGE = "thread_message_own"
    const val COMPOSER = "thread_composer"
    const val SEND = "thread_send"
    const val SCROLL_TO_BOTTOM = "thread_scroll_to_bottom"
    const val RETRY = "thread_retry"
}

/** AND-123 — route-level thread, reached from the conversation list. */
@Composable
fun ThreadRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: ThreadViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val listState = rememberLazyListState()

    LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is ThreadEvent.ScrollToBottom -> listState.animateScrollToItem(0)
            }
        }
    }

    // Reverse pagination: when the last (oldest) visible item nears the end, load older history.
    val shouldLoadOlder by remember {
        derivedStateOf {
            val total = listState.layoutInfo.totalItemsCount
            val lastVisible = listState.layoutInfo.visibleItemsInfo.lastOrNull()?.index ?: 0
            total > 0 && lastVisible >= total - 3
        }
    }
    LaunchedEffect(shouldLoadOlder, state.messages.size) {
        if (shouldLoadOlder) viewModel.loadOlder()
    }

    ThreadScreen(
        state = state,
        listState = listState,
        onBack = onBack,
        onRetry = viewModel::retry,
        onDraftChange = viewModel::onDraftChange,
        onSend = viewModel::onSend,
        onRetrySend = viewModel::onRetry,
        modifier = modifier,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ThreadScreen(
    state: ThreadUiState,
    listState: androidx.compose.foundation.lazy.LazyListState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onDraftChange: (String) -> Unit,
    onSend: () -> Unit,
    onRetrySend: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(ThreadTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = state.title.ifBlank { stringResource(R.string.thread_default_title) },
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                },
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
        bottomBar = {
            MessageComposer(
                composer = state.composer,
                onDraftChange = onDraftChange,
                onSend = onSend,
            )
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when {
                state.isLoadingInitial && state.messages.isEmpty() -> LoadingState()
                state.errorMessage != null && state.messages.isEmpty() ->
                    ErrorState(message = state.errorMessage, onRetry = onRetry)
                state.messages.isEmpty() ->
                    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        Text(
                            stringResource(R.string.thread_empty),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                else -> ThreadList(state = state, listState = listState, onRetrySend = onRetrySend)
            }
        }
    }
}

@Composable
private fun ThreadList(
    state: ThreadUiState,
    listState: androidx.compose.foundation.lazy.LazyListState,
    onRetrySend: (String) -> Unit,
) {
    // reverseLayout: index 0 is the newest message at the visual bottom.
    val reversed = remember(state.messages) { state.messages.asReversed() }
    val scope = rememberCoroutineScope()
    val showFab by remember {
        derivedStateOf { listState.firstVisibleItemIndex > 2 }
    }

    Box(Modifier.fillMaxSize()) {
        LazyColumn(
            state = listState,
            reverseLayout = true,
            modifier = Modifier.fillMaxSize().testTag(ThreadTestTags.LIST),
        ) {
            items(reversed, key = { it.key }) { message ->
                MessageBubble(message = message, onRetry = { onRetrySend(message.key) })
            }
            if (state.isLoadingOlder) {
                item {
                    Box(
                        Modifier.fillMaxWidth().padding(16.dp),
                        contentAlignment = Alignment.Center,
                    ) {
                        CircularProgressIndicator(modifier = Modifier.size(24.dp))
                    }
                }
            }
        }
        if (showFab) {
            FloatingActionButton(
                onClick = { scope.launch { listState.animateScrollToItem(0) } },
                modifier = Modifier
                    .align(Alignment.BottomEnd)
                    .padding(16.dp)
                    .testTag(ThreadTestTags.SCROLL_TO_BOTTOM),
            ) {
                Icon(
                    Icons.Filled.ArrowDownward,
                    contentDescription = stringResource(R.string.thread_scroll_to_latest),
                )
            }
        }
    }
}

@Composable
private fun MessageBubble(message: ThreadMessageUi, onRetry: () -> Unit) {
    val alignment = if (message.isOwn) Alignment.End else Alignment.Start
    val bubbleColor = if (message.isOwn) {
        MaterialTheme.colorScheme.primaryContainer
    } else {
        MaterialTheme.colorScheme.surfaceVariant
    }
    val relative = remember(message.createdAtEpochSeconds) {
        relativeTimeFromSeconds(message.createdAtEpochSeconds)
    }
    val stateDesc = when {
        message.isFailed -> "Failed to send"
        message.isSending -> "Sending"
        else -> "Sent"
    }
    val tag = if (message.isOwn) ThreadTestTags.OWN_MESSAGE else ThreadTestTags.MESSAGE

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 4.dp),
        horizontalAlignment = alignment,
    ) {
        Surface(
            color = bubbleColor,
            shape = MaterialTheme.shapes.medium,
            modifier = Modifier
                .widthIn(max = 280.dp)
                .testTag(tag)
                .semantics { stateDescription = stateDesc },
        ) {
            Text(
                text = message.text,
                style = MaterialTheme.typography.bodyLarge,
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
            )
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            if (message.isFailed) {
                IconButton(
                    onClick = onRetry,
                    modifier = Modifier
                        .size(28.dp)
                        .testTag(ThreadTestTags.RETRY)
                        .semantics { contentDescription = "Retry sending message" },
                ) {
                    Icon(
                        Icons.Filled.ErrorOutline,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.error,
                        modifier = Modifier.size(16.dp),
                    )
                }
                Text(
                    text = stringResource(R.string.thread_send_failed),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.error,
                )
            } else {
                Text(
                    text = if (message.isSending) stringResource(R.string.thread_sending) else relative,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun MessageComposer(
    composer: ComposerState,
    onDraftChange: (String) -> Unit,
    onSend: () -> Unit,
) {
    Surface(tonalElevation = 2.dp) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .imePadding()
                .navigationBarsPadding()
                .padding(horizontal = 8.dp, vertical = 8.dp)
                .testTag(ThreadTestTags.COMPOSER),
            verticalAlignment = Alignment.Bottom,
        ) {
            OutlinedTextField(
                value = composer.draft,
                onValueChange = onDraftChange,
                modifier = Modifier.weight(1f),
                placeholder = { Text(stringResource(R.string.thread_composer_hint)) },
                isError = composer.overLimit,
                maxLines = 5,
                supportingText = if (composer.overLimit) {
                    { Text(stringResource(R.string.thread_composer_over_limit)) }
                } else {
                    null
                },
            )
            IconButton(
                onClick = onSend,
                enabled = composer.isSendEnabled,
                modifier = Modifier
                    .padding(start = 4.dp)
                    .size(48.dp)
                    .testTag(ThreadTestTags.SEND),
            ) {
                Icon(
                    Icons.AutoMirrored.Filled.Send,
                    contentDescription = stringResource(R.string.thread_send),
                    tint = if (composer.isSendEnabled) {
                        MaterialTheme.colorScheme.primary
                    } else {
                        MaterialTheme.colorScheme.onSurface.copy(alpha = 0.38f)
                    },
                )
            }
        }
    }
}
