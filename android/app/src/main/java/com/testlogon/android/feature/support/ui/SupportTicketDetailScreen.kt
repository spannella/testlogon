@file:OptIn(
    androidx.compose.material3.ExperimentalMaterial3Api::class,
    androidx.compose.foundation.layout.ExperimentalLayoutApi::class,
)

package com.testlogon.android.feature.support.ui

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.Send
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.Image
import androidx.compose.material.icons.outlined.MoreVert
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import coil.compose.AsyncImage
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
    val keyboard = LocalSoftwareKeyboardController.current

    // Helpdesk #14 — pick an image to attach to the next reply.
    val imagePicker = rememberLauncherForActivityResult(
        ActivityResultContracts.GetContent(),
    ) { uri -> if (uri != null) viewModel.stageImage(uri) }

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
                    } else if (state.canReopen) {
                        // Helpdesk #17 — reopen action also in the top bar for discoverability.
                        IconButton(
                            onClick = viewModel::reopenTicket,
                            enabled = !state.reopening,
                            modifier = Modifier.testTag(SupportTestTags.DETAIL_REOPEN),
                        ) {
                            if (state.reopening) {
                                CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
                            } else {
                                Icon(Icons.Outlined.Refresh, contentDescription = "Reopen ticket")
                            }
                        }
                    }
                },
            )
        },
        // Helpdesk #15 — the composer is a Scaffold bottomBar with imePadding() so it rides ABOVE the
        // keyboard (was sitting too low / getting covered) and navigationBarsPadding() so it clears the nav
        // bar when the IME is closed.
        bottomBar = {
            when {
                ticket == null -> Unit
                // Helpdesk #17 — terminal ticket owned by the user: no composer, offer Reopen instead.
                !state.canReply && state.canReopen ->
                    ReopenBar(
                        reopening = state.reopening,
                        actionError = state.actionError,
                        onReopen = viewModel::reopenTicket,
                    )
                // Helpdesk #16 — terminal ticket (and not reopenable, e.g. an admin view): no composer.
                !state.canReply ->
                    Surface(tonalElevation = 2.dp) {
                        Text(
                            "This ticket is ${ticket.status.label().lowercase()} - replies are closed.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier
                                .fillMaxWidth()
                                .navigationBarsPadding()
                                .padding(16.dp)
                                .testTag(SupportTestTags.REPLIES_CLOSED),
                        )
                    }
                else ->
                    Surface(tonalElevation = 2.dp) {
                        Column(
                            Modifier
                                .fillMaxWidth()
                                .imePadding()
                                .navigationBarsPadding()
                                .padding(8.dp),
                        ) {
                            // Helpdesk #14 — staged image preview above the input.
                            val staged = state.stagedImageUrl
                            if (staged != null) {
                                Box(Modifier.padding(bottom = 6.dp)) {
                                    AsyncImage(
                                        model = staged,
                                        contentDescription = "Attached image",
                                        contentScale = ContentScale.Crop,
                                        modifier = Modifier.size(64.dp).clip(RoundedCornerShape(8.dp)),
                                    )
                                    IconButton(
                                        onClick = viewModel::clearStagedImage,
                                        modifier = Modifier.align(Alignment.TopEnd).size(24.dp),
                                    ) {
                                        Icon(Icons.Outlined.Close, contentDescription = "Remove image")
                                    }
                                }
                            }
                            Row(
                                Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(4.dp),
                            ) {
                                IconButton(
                                    onClick = { imagePicker.launch("image/*") },
                                    enabled = !state.uploadingImage && !state.sending,
                                    modifier = Modifier.testTag(SupportTestTags.DETAIL_ATTACH),
                                ) {
                                    if (state.uploadingImage) {
                                        CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
                                    } else {
                                        Icon(Icons.Outlined.Image, contentDescription = "Attach image")
                                    }
                                }
                                OutlinedTextField(
                                    value = state.reply,
                                    onValueChange = viewModel::onReplyChange,
                                    placeholder = { Text("Write a reply") },
                                    maxLines = 4,
                                    modifier = Modifier.weight(1f).testTag(SupportTestTags.DETAIL_REPLY),
                                )
                                IconButton(
                                    // Helpdesk #15 — dismiss the IME on send so the user isn't stuck in the box.
                                    onClick = { keyboard?.hide(); viewModel.sendReply() },
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

/**
 * Helpdesk #17 — shown in place of the reply composer for a terminal ticket owned by the user. Explains the
 * ticket is resolved/cancelled and offers a single Reopen action.
 */
@Composable
private fun ReopenBar(
    reopening: Boolean,
    actionError: String?,
    onReopen: () -> Unit,
) {
    Surface(tonalElevation = 2.dp) {
        Column(
            Modifier
                .fillMaxWidth()
                .navigationBarsPadding()
                .padding(12.dp),
        ) {
            Text(
                "This ticket is closed. Reopen it if you still need help.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (actionError != null) {
                Spacer(Modifier.height(4.dp))
                Text(actionError, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
            }
            Spacer(Modifier.height(8.dp))
            Button(
                onClick = onReopen,
                enabled = !reopening,
                modifier = Modifier.fillMaxWidth().testTag(SupportTestTags.DETAIL_REOPEN),
            ) {
                if (reopening) {
                    CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                } else {
                    Icon(Icons.Outlined.Refresh, contentDescription = null)
                    Text("  Reopen ticket")
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
                if (message.body.isNotBlank()) {
                    Spacer(Modifier.height(2.dp))
                    Text(message.body, style = MaterialTheme.typography.bodyMedium)
                }
                // Helpdesk #14 — render an attached image inline in the thread.
                val img = message.imageUrl
                if (img != null) {
                    Spacer(Modifier.height(6.dp))
                    AsyncImage(
                        model = img,
                        contentDescription = "Attached image",
                        contentScale = ContentScale.Crop,
                        modifier = Modifier.size(180.dp).clip(RoundedCornerShape(8.dp)),
                    )
                }
                val rel = relativeTime(message.createdAt)
                if (rel.isNotBlank()) {
                    Spacer(Modifier.height(4.dp))
                    Text(rel, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
    }
}
