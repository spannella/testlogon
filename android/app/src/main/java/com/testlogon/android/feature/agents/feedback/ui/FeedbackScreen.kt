@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.agents.feedback.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.MarkChatRead
import androidx.compose.material.icons.outlined.Terminal
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
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
    const val CREATE_FAB = "agent_feedback_create_fab"
    const val CREATE_DIALOG = "agent_feedback_create_dialog"
    const val CREATE_SUBMIT = "agent_feedback_create_submit"
    const val TERMINAL_DIALOG = "agent_feedback_terminal_dialog"
    fun row(id: String) = "agent_feedback_row_$id"
    fun respondField(id: String) = "agent_feedback_respond_$id"
    fun respondSend(id: String) = "agent_feedback_send_$id"
    fun skip(id: String) = "agent_feedback_skip_$id"
    fun terminal(id: String) = "agent_feedback_terminal_$id"
}

@Composable
fun FeedbackRoute(
    onBack: () -> Unit,
    onNavigateToLogin: () -> Unit,
    viewModel: FeedbackViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val dialogs by viewModel.dialogState.collectAsStateWithLifecycle()
    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is FeedbackEffect.NavigateToLogin -> onNavigateToLogin()
            }
        }
    }
    FeedbackScreen(
        state = state,
        dialogs = dialogs,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::onRetry,
        onRespond = viewModel::respond,
        onSkip = viewModel::skip,
        onOpenCreate = viewModel::openCreate,
        onDismissCreate = viewModel::dismissCreate,
        onSubmitCreate = viewModel::create,
        onOpenTerminal = viewModel::openTerminal,
        onDismissTerminal = viewModel::dismissTerminal,
    )
}

@Composable
fun FeedbackScreen(
    state: FeedbackUiState,
    dialogs: FeedbackDialogState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onRespond: (workerId: String, requestId: String, text: String) -> Unit,
    onSkip: (workerId: String, requestId: String) -> Unit,
    onOpenCreate: () -> Unit,
    onDismissCreate: () -> Unit,
    onSubmitCreate: (workerId: String, ticketId: String, question: String) -> Unit,
    onOpenTerminal: (workerId: String) -> Unit,
    onDismissTerminal: () -> Unit,
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
        floatingActionButton = {
            FloatingActionButton(
                onClick = onOpenCreate,
                modifier = Modifier.testTag(FeedbackTestTags.CREATE_FAB),
            ) { Icon(Icons.Outlined.Add, contentDescription = "New request") }
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
                                    onViewTerminal = { onOpenTerminal(req.workerId) },
                                )
                            }
                        }
                    }
            }
        }
    }

    dialogs.create?.let { CreateFeedbackDialog(it, onDismissCreate, onSubmitCreate) }
    dialogs.terminal?.let { TerminalLogDialog(it, onDismissTerminal) }
}

@Composable
private fun FeedbackCard(
    request: FeedbackRequest,
    acting: Boolean,
    onRespond: (String) -> Unit,
    onSkip: () -> Unit,
    onViewTerminal: () -> Unit,
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
                if (request.workerId.isNotBlank()) {
                    IconButton(
                        onClick = onViewTerminal,
                        modifier = Modifier.testTag(FeedbackTestTags.terminal(request.requestId)),
                    ) { Icon(Icons.Outlined.Terminal, contentDescription = "View terminal log") }
                }
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

@Composable
private fun CreateFeedbackDialog(
    state: CreateFeedbackState,
    onDismiss: () -> Unit,
    onSubmit: (workerId: String, ticketId: String, question: String) -> Unit,
) {
    var workerId by rememberSaveable { mutableStateOf("") }
    var ticketId by rememberSaveable { mutableStateOf("") }
    var question by rememberSaveable { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = { if (!state.submitting) onDismiss() },
        modifier = Modifier.testTag(FeedbackTestTags.CREATE_DIALOG),
        title = { Text("New feedback request") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = workerId,
                    onValueChange = { workerId = it },
                    label = { Text("Worker ID") },
                    singleLine = true,
                    enabled = !state.submitting,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = ticketId,
                    onValueChange = { ticketId = it },
                    label = { Text("Ticket ID") },
                    singleLine = true,
                    enabled = !state.submitting,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = question,
                    onValueChange = { question = it },
                    label = { Text("Question") },
                    enabled = !state.submitting,
                    minLines = 2,
                    modifier = Modifier.fillMaxWidth(),
                )
                if (state.error != null) {
                    Text(
                        text = state.error,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
        },
        confirmButton = {
            OutlinedButton(
                onClick = { onSubmit(workerId, ticketId, question) },
                enabled = !state.submitting &&
                    workerId.isNotBlank() && ticketId.isNotBlank() && question.isNotBlank(),
                modifier = Modifier.testTag(FeedbackTestTags.CREATE_SUBMIT),
            ) {
                if (state.submitting) {
                    CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(18.dp))
                } else {
                    Text("Create")
                }
            }
        },
        dismissButton = { TextButton(onClick = onDismiss, enabled = !state.submitting) { Text("Cancel") } },
    )
}

@Composable
private fun TerminalLogDialog(state: TerminalLogState, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        modifier = Modifier.testTag(FeedbackTestTags.TERMINAL_DIALOG),
        title = { Text("Terminal log") },
        text = {
            Column(
                modifier = Modifier.fillMaxWidth().heightIn(max = 320.dp).verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                when {
                    state.loading -> CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(24.dp))
                    state.error != null ->
                        Text(state.error, color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodySmall)
                    state.output == null || state.output.isEmpty ->
                        Text("No terminal output.", style = MaterialTheme.typography.bodySmall)
                    else -> Text(state.output.output, style = MaterialTheme.typography.bodySmall)
                }
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text("Close") } },
    )
}
