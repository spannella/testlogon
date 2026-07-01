@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.agents.feedback.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.MarkChatRead
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
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
import com.testlogon.android.feature.agents.feedback.data.FeedbackRequest

/** AGENTS-BASICS - stable testTags for the feedback list. */
object FeedbackTestTags {
    const val SCREEN = "agent_feedback_screen"
    const val EMPTY = "agent_feedback_empty"
    const val ERROR_RETRY = "agent_feedback_error_retry"
    fun row(id: String) = "agent_feedback_row_$id"
    fun respondField(id: String) = "agent_feedback_respond_$id"
    fun respondSend(id: String) = "agent_feedback_send_$id"
    fun skip(id: String) = "agent_feedback_skip_$id"
}

@Composable
fun FeedbackRoute(
    onBack: () -> Unit,
    onNavigateToLogin: () -> Unit,
    viewModel: FeedbackViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is FeedbackEffect.NavigateToLogin -> onNavigateToLogin()
            }
        }
    }
    FeedbackScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::onRetry,
        onRespond = viewModel::respond,
        onSkip = viewModel::skip,
    )
}

@Composable
fun FeedbackScreen(
    state: FeedbackUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onRespond: (workerId: String, requestId: String, text: String) -> Unit,
    onSkip: (workerId: String, requestId: String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(FeedbackTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Agent feedback") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        val isRefreshing = (state as? FeedbackUiState.Content)?.isRefreshing == true
        PullToRefreshBox(
            isRefreshing = isRefreshing,
            onRefresh = onRefresh,
            modifier = Modifier.fillMaxSize().padding(padding),
        ) {
            when (state) {
                is FeedbackUiState.Loading -> LoadingState()
                is FeedbackUiState.Empty ->
                    EmptyState(
                        modifier = Modifier.testTag(FeedbackTestTags.EMPTY),
                        title = "No feedback requests",
                        body = "When a worker needs your input it will appear here to answer or skip.",
                        imageVector = Icons.Outlined.MarkChatRead,
                    )
                is FeedbackUiState.Error ->
                    ErrorState(
                        modifier = Modifier.testTag(FeedbackTestTags.ERROR_RETRY),
                        message = state.message,
                        onRetry = onRetry,
                    )
                is FeedbackUiState.Content ->
                    Column(Modifier.fillMaxSize()) {
                        if (state.actionError != null) {
                            Text(
                                text = state.actionError,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.error,
                                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
                            )
                        }
                        LazyColumn(
                            modifier = Modifier.fillMaxSize(),
                            contentPadding = PaddingValues(16.dp),
                            verticalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            items(items = state.items, key = { it.requestId }) { req ->
                                FeedbackCard(
                                    request = req,
                                    acting = state.actioningId == req.requestId,
                                    onRespond = { text -> onRespond(req.workerId, req.requestId, text) },
                                    onSkip = { onSkip(req.workerId, req.requestId) },
                                )
                            }
                        }
                    }
            }
        }
    }
}

@Composable
private fun FeedbackCard(
    request: FeedbackRequest,
    acting: Boolean,
    onRespond: (String) -> Unit,
    onSkip: () -> Unit,
) {
    var draft by rememberSaveable(request.requestId) { mutableStateOf("") }
    var showContext by remember(request.requestId) { mutableStateOf(false) }
    Card(modifier = Modifier.fillMaxWidth().testTag(FeedbackTestTags.row(request.requestId))) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(
                    text = request.ticketId.ifBlank { request.workerId.ifBlank { request.requestId } },
                    style = MaterialTheme.typography.titleSmall,
                    modifier = Modifier.weight(1f),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                AssistChip(onClick = {}, label = { Text(request.statusWire.ifBlank { "unknown" }) })
            }
            Text(text = request.question, style = MaterialTheme.typography.bodyMedium)
            if (request.detectedPattern.isNotBlank()) {
                Text(
                    text = "Pattern: ${request.detectedPattern}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (request.terminalContext.isNotBlank()) {
                TextButton(onClick = { showContext = !showContext }) {
                    Text(if (showContext) "Hide terminal context" else "Show terminal context")
                }
                if (showContext) {
                    Text(
                        text = request.terminalContext,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            if (request.isPending) {
                OutlinedTextField(
                    value = draft,
                    onValueChange = { draft = it },
                    label = { Text("Your response") },
                    modifier = Modifier.fillMaxWidth().testTag(FeedbackTestTags.respondField(request.requestId)),
                    enabled = !acting,
                    minLines = 2,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (acting) {
                        CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(20.dp))
                    } else {
                        OutlinedButton(
                            onClick = { onRespond(draft) },
                            enabled = draft.isNotBlank(),
                            modifier = Modifier.testTag(FeedbackTestTags.respondSend(request.requestId)),
                        ) { Text("Respond") }
                        TextButton(
                            onClick = onSkip,
                            modifier = Modifier.testTag(FeedbackTestTags.skip(request.requestId)),
                        ) { Text("Skip") }
                    }
                }
            } else if (request.responseText.isNotBlank()) {
                Text(
                    text = "Response: ${request.responseText}",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }
}
