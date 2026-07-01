@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.adminmod

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Divider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
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
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.adminmod.ModerationTicketDetailDto
import kotlinx.coroutines.launch

object ModerationDetailArgs {
    const val TICKET_ID = "ticketId"
}

object ModerationDetailTestTags {
    const val SCREEN = "mod_detail_screen"
    const val CLAIM = "mod_detail_claim"
    const val NOTE = "mod_detail_note"
    const val DECIDE_REMOVE = "mod_detail_decide_remove"
    const val DECIDE_WARN = "mod_detail_decide_warn"
    const val DECIDE_BAN = "mod_detail_decide_ban"
    const val DECIDE_NONE = "mod_detail_decide_none"
    const val RESOLVE_REMOVED = "mod_detail_resolve_removed"
    const val RESOLVE_NONE = "mod_detail_resolve_none"
    const val FORBIDDEN = "mod_detail_forbidden"
}

@Composable
fun ModerationDetailRoute(
    onBack: () -> Unit,
    viewModel: ModerationDetailViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    ModerationDetailScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::retry,
        onClaim = viewModel::claim,
        onDecide = viewModel::decide,
        onResolve = viewModel::resolve,
        onMessageShown = viewModel::clearActionMessage,
    )
}

@Composable
fun ModerationDetailScreen(
    state: ModerationDetailUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onClaim: () -> Unit,
    onDecide: (String, String?) -> Unit,
    onResolve: (String, String, String?) -> Unit,
    onMessageShown: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbar = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    val content = state as? ModerationDetailUiState.Content

    LaunchedEffect(content?.actionMessage, content?.transientError) {
        val msg = content?.actionMessage ?: content?.transientError?.let { adminOpsErrorMessage(it) }
        if (msg != null) {
            scope.launch { snackbar.showSnackbar(msg) }
            onMessageShown()
        }
    }

    Scaffold(
        modifier = modifier.testTag(ModerationDetailTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text("Ticket") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        when (state) {
            is ModerationDetailUiState.Loading -> LoadingState(modifier = Modifier.padding(padding))
            is ModerationDetailUiState.Forbidden -> EmptyState(
                modifier = Modifier.padding(padding).testTag(ModerationDetailTestTags.FORBIDDEN),
                title = "Not authorised",
                body = "You need content-moderation admin access.",
                imageVector = Icons.Outlined.Lock,
                actionLabel = "Back",
                onAction = onBack,
            )
            is ModerationDetailUiState.Error -> ErrorState(
                modifier = Modifier.padding(padding),
                message = adminOpsErrorMessage(state.type),
                onRetry = onRetry,
            )
            is ModerationDetailUiState.Content -> DetailBody(
                state = state,
                modifier = Modifier.padding(padding),
                onClaim = onClaim,
                onDecide = onDecide,
                onResolve = onResolve,
            )
        }
    }
}

@Composable
private fun DetailBody(
    state: ModerationDetailUiState.Content,
    modifier: Modifier,
    onClaim: () -> Unit,
    onDecide: (String, String?) -> Unit,
    onResolve: (String, String, String?) -> Unit,
) {
    var note by remember { mutableStateOf("") }
    val d: ModerationTicketDetailDto = state.detail
    val t = d.ticket
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(t.contentType.ifBlank { "content" }.replace('_', ' '), style = MaterialTheme.typography.titleMedium)
        LabeledRow("Status", t.status.ifBlank { "-" }.replace('_', ' '))
        LabeledRow("Priority", t.priority.ifBlank { "-" })
        LabeledRow("Queue", t.queue.ifBlank { "-" })
        LabeledRow("Reports", t.reportCount.toString())
        t.assignedAdminUserId?.let { LabeledRow("Assigned", it) }
        if (t.aggregatedTopics.isNotEmpty()) LabeledRow("Topics", t.aggregatedTopics.joinToString(", "))

        d.offenderHistory?.let { h ->
            Divider()
            Text("Offender history", style = MaterialTheme.typography.titleSmall)
            LabeledRow("Total tickets", h.totalTickets.toString())
            LabeledRow("Open tickets", h.openTickets.toString())
            LabeledRow("Total reports", h.totalReports.toString())
        }

        if (d.linkedReports.isNotEmpty()) {
            Divider()
            Text("Linked reports (${d.linkedReports.size})", style = MaterialTheme.typography.titleSmall)
            d.linkedReports.forEach { r ->
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(r.topics.joinToString(", ").ifBlank { "report" }, style = MaterialTheme.typography.labelLarge)
                        if (r.reasonText.isNotBlank()) {
                            Text(r.reasonText, style = MaterialTheme.typography.bodySmall)
                        }
                        if (r.createdAt > 0L) {
                            Text(
                                relativeSeconds(r.createdAt),
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
            }
        }

        Divider()
        Text("Actions", style = MaterialTheme.typography.titleSmall)
        OutlinedTextField(
            value = note,
            onValueChange = { note = it },
            label = { Text("Note (optional)") },
            modifier = Modifier.fillMaxWidth().testTag(ModerationDetailTestTags.NOTE),
            enabled = !state.actionInFlight,
        )
        OutlinedButton(
            onClick = onClaim,
            enabled = !state.actionInFlight,
            modifier = Modifier.fillMaxWidth().testTag(ModerationDetailTestTags.CLAIM),
        ) { Text("Claim ticket") }

        Text("Decision", style = MaterialTheme.typography.labelLarge)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
            OutlinedButton(
                onClick = { onDecide("no_violation", note.ifBlank { null }) },
                enabled = !state.actionInFlight,
                modifier = Modifier.testTag(ModerationDetailTestTags.DECIDE_NONE),
            ) { Text("No violation") }
            OutlinedButton(
                onClick = { onDecide("warn", note.ifBlank { null }) },
                enabled = !state.actionInFlight,
                modifier = Modifier.testTag(ModerationDetailTestTags.DECIDE_WARN),
            ) { Text("Warn") }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
            OutlinedButton(
                onClick = { onDecide("remove", note.ifBlank { null }) },
                enabled = !state.actionInFlight,
                modifier = Modifier.testTag(ModerationDetailTestTags.DECIDE_REMOVE),
            ) { Text("Remove") }
            Button(
                onClick = { onDecide("ban", note.ifBlank { null }) },
                enabled = !state.actionInFlight,
                modifier = Modifier.testTag(ModerationDetailTestTags.DECIDE_BAN),
            ) { Text("Ban") }
        }

        Text("Resolve", style = MaterialTheme.typography.labelLarge)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
            OutlinedButton(
                onClick = { onResolve("no_violation", "none", note.ifBlank { null }) },
                enabled = !state.actionInFlight,
                modifier = Modifier.testTag(ModerationDetailTestTags.RESOLVE_NONE),
            ) { Text("Resolve: no violation") }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
            Button(
                onClick = { onResolve("content_removed", "warn", note.ifBlank { null }) },
                enabled = !state.actionInFlight,
                modifier = Modifier.testTag(ModerationDetailTestTags.RESOLVE_REMOVED),
            ) { Text("Resolve: content removed") }
        }

        if (state.actionInFlight) {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) {
                CircularProgressIndicator()
            }
        }
    }
}

@Composable
private fun LabeledRow(label: String, value: String) {
    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.bodyMedium)
    }
}
