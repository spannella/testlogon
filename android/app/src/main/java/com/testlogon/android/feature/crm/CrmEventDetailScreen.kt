@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.crm

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
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
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.OfflineBanner
import com.testlogon.android.data.crm.CrmInvitee
import com.testlogon.android.data.crm.CrmPecMath
import com.testlogon.android.data.crm.CrmRegistration

object CrmEventDetailTestTags {
    const val SCREEN = "crm_event_detail_screen"
    const val LOADING = "crm_event_detail_loading"
    const val ERROR = "crm_event_detail_error"
    const val ADD_INVITEE = "crm_event_add_invitee"
    const val SEND_INVITES = "crm_event_send_invites"
    const val REGISTER = "crm_event_register"
}

@Composable
fun CrmEventDetailRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: CrmEventDetailViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    CrmEventDetailScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::onRetry,
        onUpdate = viewModel::updateEvent,
        onAddInvitee = viewModel::addInvitee,
        onRemoveInvitee = viewModel::removeInvitee,
        onBulkImport = viewModel::bulkImport,
        onSendInvitations = viewModel::sendInvitations,
        onRegister = viewModel::register,
        onRespond = viewModel::respond,
        onCheckIn = viewModel::checkIn,
        onCancelRegistration = viewModel::cancelRegistration,
        onClearActionFeedback = viewModel::clearActionFeedback,
        modifier = modifier,
    )
}

@Composable
fun CrmEventDetailScreen(
    state: CrmEventDetailUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onUpdate: (String?, String?, Int?) -> Unit,
    onAddInvitee: (String) -> Unit,
    onRemoveInvitee: (String) -> Unit,
    onBulkImport: (List<String>) -> Unit,
    onSendInvitations: () -> Unit,
    onRegister: () -> Unit,
    onRespond: (String, String) -> Unit,
    onCheckIn: (String) -> Unit,
    onCancelRegistration: (String) -> Unit,
    onClearActionFeedback: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var showEdit by remember { mutableStateOf(false) }
    var showAddInvitee by remember { mutableStateOf(false) }
    var showBulkImport by remember { mutableStateOf(false) }

    Scaffold(
        modifier = modifier.testTag(CrmEventDetailTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(state.event?.name?.ifBlank { "Event" } ?: "Event") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        when (state.phase) {
            CrmEventDetailUiState.Phase.Loading -> LoadingState(
                modifier = Modifier.padding(padding).testTag(CrmEventDetailTestTags.LOADING),
            )
            CrmEventDetailUiState.Phase.Error -> ErrorState(
                message = state.errorMessage ?: "Couldn't load this event.",
                onRetry = onRetry,
                modifier = Modifier.padding(padding).testTag(CrmEventDetailTestTags.ERROR),
            )
            CrmEventDetailUiState.Phase.Content -> {
                val event = state.event
                Column(
                    modifier = Modifier.padding(padding).fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    if (state.isOffline) OfflineBanner(onRetry = onRetry)
                    if (state.actionMessage != null) InfoBanner(state.actionMessage)
                    if (state.actionError != null) {
                        Text(state.actionError, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                    }

                    if (event != null) {
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                            val cap = state.capacity
                            AssistChip(
                                onClick = {},
                                label = {
                                    Text(CrmPecMath.capacityLabel(cap?.maxAttendance ?: event.maxAttendance, cap?.acceptedCount ?: 0))
                                },
                            )
                            if ((cap?.waitlistedCount ?: 0) > 0) {
                                AssistChip(onClick = {}, label = { Text("${cap?.waitlistedCount} waitlisted") })
                            }
                        }
                        if (event.description.isNotBlank()) LabeledValue("Description", event.description)
                        LabeledValue("Created", CrmPecMath.formatDate(event.createdAt))
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            OutlinedButton(onClick = { showEdit = true }) { Text("Edit") }
                            FilledTonalButton(
                                onClick = onRegister,
                                enabled = !state.actionInProgress,
                                modifier = Modifier.testTag(CrmEventDetailTestTags.REGISTER),
                            ) { Text("Register") }
                        }
                    }

                    // ── Invitees ──────────────────────────────────────────────
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text("Invitees (${state.invitees.size})", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                        Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                            TextButton(onClick = { showBulkImport = true }, enabled = !state.actionInProgress) { Text("Import") }
                            TextButton(
                                onClick = { showAddInvitee = true },
                                enabled = !state.actionInProgress,
                                modifier = Modifier.testTag(CrmEventDetailTestTags.ADD_INVITEE),
                            ) { Text("Add") }
                        }
                    }
                    if (state.canSendInvitations) {
                        FilledTonalButton(
                            onClick = onSendInvitations,
                            enabled = !state.actionInProgress,
                            modifier = Modifier.fillMaxWidth().testTag(CrmEventDetailTestTags.SEND_INVITES),
                        ) { Text("Send invitations (${state.pendingInviteCount} pending)") }
                    }
                    if (state.invitees.isEmpty()) {
                        Text("No invitees yet.", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    } else {
                        state.invitees.forEach { invitee ->
                            InviteeRow(invitee, enabled = !state.actionInProgress, onRemove = { onRemoveInvitee(invitee.inviteeSub) })
                        }
                    }

                    // ── Registrations / RSVP / check-in ───────────────────────
                    Text("Registrations (${state.registrations.size})", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    if (state.registrations.isEmpty()) {
                        Text("No registrations yet.", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    } else {
                        state.registrations.forEach { reg ->
                            RegistrationRow(
                                reg = reg,
                                enabled = !state.actionInProgress,
                                onAccept = { onRespond(reg.registrantSub, CrmPecMath.REG_ACCEPTED) },
                                onDecline = { onRespond(reg.registrantSub, CrmPecMath.REG_DECLINED) },
                                onCheckIn = { onCheckIn(reg.registrantSub) },
                                onCancel = { onCancelRegistration(reg.registrantSub) },
                            )
                        }
                    }
                }
            }
        }
    }

    if (showEdit && state.event != null) {
        EditEventSheet(
            initialName = state.event.name,
            initialDescription = state.event.description,
            initialMax = state.event.maxAttendance,
            submitting = state.actionInProgress,
            onDismiss = { showEdit = false; onClearActionFeedback() },
            onSubmit = { name, desc, maxAtt ->
                onUpdate(name, desc, maxAtt)
                showEdit = false
            },
        )
    }

    if (showAddInvitee) {
        SingleFieldSheet(
            title = "Add invitee",
            label = "User id (sub)",
            submitting = state.actionInProgress,
            onDismiss = { showAddInvitee = false; onClearActionFeedback() },
            onSubmit = { value -> onAddInvitee(value); showAddInvitee = false },
        )
    }

    if (showBulkImport) {
        SingleFieldSheet(
            title = "Bulk import invitees",
            label = "User ids (comma or newline separated)",
            singleLine = false,
            submitting = state.actionInProgress,
            onDismiss = { showBulkImport = false; onClearActionFeedback() },
            onSubmit = { value ->
                onBulkImport(value.split(',', '\n', ' '))
                showBulkImport = false
            },
        )
    }
}

@Composable
private fun InviteeRow(invitee: CrmInvitee, enabled: Boolean, onRemove: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(
                    (invitee.displayName ?: invitee.inviteeSub).ifBlank { "(unknown)" },
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.Medium,
                )
                Text(
                    CrmPecMath.inviteStatusLabel(invitee.inviteStatus),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            IconButton(onClick = onRemove, enabled = enabled) {
                Icon(Icons.Filled.Close, contentDescription = "Remove invitee")
            }
        }
    }
}

@Composable
private fun RegistrationRow(
    reg: CrmRegistration,
    enabled: Boolean,
    onAccept: () -> Unit,
    onDecline: () -> Unit,
    onCheckIn: () -> Unit,
    onCancel: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(horizontalArrangement = Arrangement.SpaceBetween, modifier = Modifier.fillMaxWidth()) {
                Text(reg.registrantSub.ifBlank { "(unknown)" }, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Medium)
                AssistChip(onClick = {}, label = { Text(CrmPecMath.registrationStatusLabel(reg.status)) })
            }
            if (reg.waitlistPosition != null && reg.waitlistPosition > 0) {
                Text(CrmPecMath.waitlistLabel(reg.waitlistPosition), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (CrmPecMath.canRespond(reg.status, reg.checkedInAt)) {
                    TextButton(onClick = onAccept, enabled = enabled) { Text("Accept") }
                    TextButton(onClick = onDecline, enabled = enabled) { Text("Decline") }
                }
                if (CrmPecMath.canCheckIn(reg.status, reg.checkedInAt)) {
                    TextButton(onClick = onCheckIn, enabled = enabled) { Text("Check in") }
                }
                if (CrmPecMath.isCheckedIn(reg.checkedInAt)) {
                    Text("Checked in", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
                }
                TextButton(onClick = onCancel, enabled = enabled) { Text("Cancel") }
            }
        }
    }
}

@Composable
private fun EditEventSheet(
    initialName: String,
    initialDescription: String,
    initialMax: Int?,
    submitting: Boolean,
    onDismiss: () -> Unit,
    onSubmit: (name: String?, description: String?, maxAttendance: Int?) -> Unit,
) {
    var name by remember { mutableStateOf(initialName) }
    var description by remember { mutableStateOf(initialDescription) }
    var maxAtt by remember { mutableStateOf(initialMax?.toString() ?: "") }

    AlertDialog(
        onDismissRequest = { if (!submitting) onDismiss() },
        title = { Text("Edit event") },
        text = {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedTextField(name, { name = it }, label = { Text("Name") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(description, { description = it }, label = { Text("Description") }, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(
                    maxAtt,
                    { input -> maxAtt = input.filter { it.isDigit() } },
                    label = { Text("Max attendance (optional)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        },
        confirmButton = {
            TextButton(enabled = !submitting, onClick = { onSubmit(name, description, maxAtt.toIntOrNull()) }) {
                if (submitting) CircularProgressIndicator(modifier = Modifier.size(18.dp)) else Text("Save")
            }
        },
        dismissButton = { TextButton(enabled = !submitting, onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun SingleFieldSheet(
    title: String,
    label: String,
    submitting: Boolean,
    singleLine: Boolean = true,
    onDismiss: () -> Unit,
    onSubmit: (String) -> Unit,
) {
    var value by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = { if (!submitting) onDismiss() },
        title = { Text(title) },
        text = {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedTextField(value, { value = it }, label = { Text(label) }, singleLine = singleLine, modifier = Modifier.fillMaxWidth())
            }
        },
        confirmButton = {
            TextButton(enabled = !submitting, onClick = { onSubmit(value) }) {
                if (submitting) CircularProgressIndicator(modifier = Modifier.size(18.dp)) else Text("Save")
            }
        },
        dismissButton = { TextButton(enabled = !submitting, onClick = onDismiss) { Text("Cancel") } },
    )
}
