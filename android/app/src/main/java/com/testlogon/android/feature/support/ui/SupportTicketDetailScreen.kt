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
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.feature.support.data.SupportTicketMessage

/**
 * B-SUP (batch 7) - one ticket: the messages thread + a reply composer (BOTH roles). For an ADMIN it also
 * shows the status controls wired to POST /tickets/{id}/status; a USER never sees those (the server 403s).
 *
 * B10 B-HELPMEDIA #5 - the reply composer can attach a LIST of images / videos / files (device pickers)
 * AND files from the in-app file manager; each message renders its media inline in the thread.
 */
@Composable
fun SupportTicketDetailRoute(
    onBack: () -> Unit,
    viewModel: SupportTicketDetailViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val ticket = state.ticket
    val keyboard = LocalSoftwareKeyboardController.current

    // B10 B-HELPMEDIA #5 - pickers for the reply attachments.
    val imagePicker = rememberLauncherForActivityResult(
        ActivityResultContracts.GetContent(),
    ) { uri -> if (uri != null) viewModel.addImage(uri) }
    val videoPicker = rememberLauncherForActivityResult(
        ActivityResultContracts.GetContent(),
    ) { uri -> if (uri != null) viewModel.addVideo(uri) }
    val filePicker = rememberLauncherForActivityResult(
        ActivityResultContracts.GetContent(),
    ) { uri -> if (uri != null) viewModel.addFile(uri) }

    var showFilePicker by remember { mutableStateOf(false) }
    if (showFilePicker) {
        FileManagerPickerDialog(
            onDismiss = { showFilePicker = false },
            onPick = { node -> showFilePicker = false; viewModel.addFileRef(node) },
        )
    }

    // B8 #15 - owner close/cancel confirmation. null = no dialog; "close"/"cancel" = pending action.
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
        bottomBar = {
            when {
                ticket == null -> Unit
                !state.canReply && state.canReopen ->
                    ReopenBar(
                        reopening = state.reopening,
                        actionError = state.actionError,
                        onReopen = viewModel::reopenTicket,
                    )
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
                            // B10 B-HELPMEDIA #5 - staged attachments strip above the input.
                            StagedMediaStrip(
                                media = state.media,
                                onRemove = viewModel::removeMedia,
                                modifier = Modifier.padding(bottom = 6.dp),
                            )
                            // B10 B-HELPMEDIA #5 - attach actions (image / video / file / Files).
                            AttachmentActions(
                                enabled = !state.sending && !state.mediaFull,
                                onImage = { imagePicker.launch("image/*") },
                                onVideo = { videoPicker.launch("video/*") },
                                onFile = { filePicker.launch("*/*") },
                                onFromFiles = { showFilePicker = true },
                                modifier = Modifier.padding(bottom = 6.dp),
                            )
                            Row(
                                Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(4.dp),
                            ) {
                                OutlinedTextField(
                                    value = state.reply,
                                    onValueChange = viewModel::onReplyChange,
                                    placeholder = { Text("Write a reply") },
                                    maxLines = 4,
                                    modifier = Modifier.weight(1f).testTag(SupportTestTags.DETAIL_REPLY),
                                )
                                IconButton(
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
                            if (state.actionError != null) {
                                Text(
                                    state.actionError!!,
                                    color = MaterialTheme.colorScheme.error,
                                    style = MaterialTheme.typography.bodySmall,
                                    modifier = Modifier.padding(top = 4.dp),
                                )
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
                // B10 B-HELPMEDIA #5 - render the full media list (images inline, videos/files as rows).
                if (message.media.isNotEmpty()) {
                    Spacer(Modifier.height(6.dp))
                    MessageMediaList(message.media)
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
