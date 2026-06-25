@file:OptIn(
    androidx.compose.material3.ExperimentalMaterial3Api::class,
    androidx.compose.foundation.layout.ExperimentalLayoutApi::class,
)

package com.testlogon.android.feature.support.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.Send
import androidx.compose.material.icons.outlined.MoreVert
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.TextButton
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
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.feature.support.data.SupportTicketMessage

/**
 * B-SUP (batch 7) - one ticket: the messages thread + a reply composer (BOTH roles). For an ADMIN it also
 * shows the status controls (open/in_progress/waiting_on_user/done/reopened) wired to POST /tickets/{id}/status;
 * a USER never sees those controls (and the server would 403). The reply composer posts to /messages.
 */
@Composable
fun SupportTicketDetailRoute(
    onBack: () -> Unit,
    viewModel: SupportTicketDetailViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val ticket = state.ticket

    // B8 #15 — owner close/cancel confirmation. null = no dialog; "close"/"cancel" = pending action.
    var pendingAction by remember { mutableStateOf<String?>(null) }
    pendingAction?.let { action ->
        val isCancel = action == "cancel"
        AlertDialog(
            onDismissRequest = { pendingAction = null },
            title = { Text(if (isCancel) "Cancel this ticket?" else "Close this ticket?") },
            text = {
                Text(
                    if (isCancel) {
                        "Cancelling marks this request as withdrawn. You can always open a new ticket later."
                    } else {
                        "Closing marks this ticket as resolved. You can reopen it by replying if you still need help."
                    },
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    pendingAction = null
                    viewModel.closeTicket(action)
                }) { Text(if (isCancel) "Cancel ticket" else "Close ticket") }
            },
            dismissButton = {
                TextButton(onClick = { pendingAction = null }) { Text("Keep open") }
            },
        )
    }

    Scaffold(
        topBar = {
            androidx.compose.material3.TopAppBar(
                title = { Text(ticket?.subject?.ifBlank { "Ticket" } ?: "Ticket") },
                navigationIcon = { BackButton(onBack) },
                actions = {
                    if (state.canClose) {
                        var menuOpen by remember { mutableStateOf(false) }
                        IconButton(
                            onClick = { menuOpen = true },
                            modifier = Modifier.testTag(SupportTestTags.DETAIL_CLOSE),
                        ) {
                            Icon(Icons.Outlined.MoreVert, contentDescription = "Ticket actions")
                        }
                        DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                            DropdownMenuItem(
                                text = { Text("Close ticket (resolved)") },
                                onClick = { menuOpen = false; pendingAction = "close" },
                            )
                            DropdownMenuItem(
                                text = { Text("Cancel ticket") },
                                onClick = { menuOpen = false; pendingAction = "cancel" },
                                modifier = Modifier.testTag(SupportTestTags.DETAIL_CANCEL),
                            )
                        }
                    }
                },
            )
        },
        bottomBar = {
            if (ticket != null) {
                Surface(tonalElevation = 2.dp) {
                    Row(
                        Modifier.fillMaxWidth().padding(8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        OutlinedTextField(
                            value = state.reply,
                            onValueChange = viewModel::onReplyChange,
                            placeholder = { Text("Write a reply") },
                            maxLines = 4,
                            modifier = Modifier.weight(1f).testTag(SupportTestTags.DETAIL_REPLY),
                        )
                        IconButton(
                            onClick = viewModel::sendReply,
                            enabled = state.canSend,
                            modifier = Modifier.testTag(SupportTestTags.DETAIL_SEND),
                        ) {
                            if (state.sending) {
                                CircularProgressIndicator(Modifier.height(20.dp), strokeWidth = 2.dp)
                            } else {
                                Icon(Icons.AutoMirrored.Outlined.Send, contentDescription = "Send")
                            }
                        }
                    }
                }
            }
        },
    ) { p ->
        Box(Modifier.fillMaxSize().padding(p)) {
            when {
                state.loading ->
                    Box(Modifier.fillMaxSize(), Alignment.Center) { CircularProgressIndicator() }
                ticket == null ->
                    CenteredText(state.error ?: "Couldn't load this ticket.", "support_detail_error")
                else ->
                    LazyColumn(
                        Modifier.fillMaxSize(),
                        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
                        verticalArrangement = Arrangement.spacedBy(10.dp),
                    ) {
                        item {
                            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                StatusChip(ticket.status)
                                if (!ticket.caseNumber.isNullOrBlank()) {
                                    Text(ticket.caseNumber!!, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                }
                                if (!ticket.priority.isNullOrBlank()) {
                                    Text("Priority: ${ticket.priority}", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                }
                            }
                            if (state.isAdmin) {
                                Spacer(Modifier.height(8.dp))
                                Text("Set status", style = MaterialTheme.typography.labelLarge)
                                Spacer(Modifier.height(4.dp))
                                androidx.compose.foundation.layout.FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    viewModel.statusOptions.forEach { opt ->
                                        AssistChip(
                                            onClick = { viewModel.setStatus(opt) },
                                            enabled = !state.actionInFlight && ticket.rawStatus != opt,
                                            label = { Text(statusLabelFromWire(opt)) },
                                        )
                                    }
                                }
                                if (state.actionError != null) {
                                    Text(state.actionError!!, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                                }
                            }
                            Spacer(Modifier.height(8.dp))
                            HorizontalDivider()
                        }
                        items(ticket.messages, key = { it.messageId }) { m ->
                            MessageBubble(m)
                        }
                    }
            }
        }
    }
}

@Composable
private fun MessageBubble(message: SupportTicketMessage) {
    val fromAdmin = message.isFromAdmin
    val container = if (fromAdmin) MaterialTheme.colorScheme.secondaryContainer else MaterialTheme.colorScheme.primaryContainer
    Column(Modifier.fillMaxWidth()) {
        Surface(
            color = container,
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier.widthIn(max = 320.dp),
        ) {
            Column(Modifier.padding(12.dp)) {
                Text(
                    if (fromAdmin) "Support team" else "You",
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.SemiBold,
                )
                Spacer(Modifier.height(2.dp))
                Text(message.body, style = MaterialTheme.typography.bodyMedium)
                val rel = relativeTime(message.createdAt)
                if (rel.isNotBlank()) {
                    Spacer(Modifier.height(4.dp))
                    Text(rel, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
    }
}
