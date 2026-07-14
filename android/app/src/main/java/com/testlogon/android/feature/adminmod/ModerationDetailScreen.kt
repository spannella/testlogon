@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.adminmod

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Divider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
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
import androidx.compose.ui.text.input.KeyboardType
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
    const val NOTE = "mod_detail_note"
    const val STATE_CHIP = "mod_detail_state"
    const val CONTENT = "mod_detail_content"
    const val DISMISS = "mod_detail_dismiss"
    const val CONFIRM = "mod_detail_confirm"
    const val REINSTATE = "mod_detail_reinstate"
    const val DELETE = "mod_detail_delete"
    const val BAN_PICKER = "mod_detail_ban_picker"
    const val BAN_CONFIRM = "mod_detail_ban_confirm"
    const val FORBIDDEN = "mod_detail_forbidden"
    const val POSTER_RESPONSE = "mod_detail_poster_response"
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
        onDismiss = viewModel::dismissCase,
        onConfirm = viewModel::confirmCase,
        onFinalCall = viewModel::finalCall,
        onMessageShown = viewModel::clearActionMessage,
    )
}

@Composable
fun ModerationDetailScreen(
    state: ModerationDetailUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit,
    onFinalCall: (action: String, note: String?, ban: Boolean, banDays: Int?) -> Unit,
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
                title = { Text("Case") },
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
                onDismiss = onDismiss,
                onConfirm = onConfirm,
                onFinalCall = onFinalCall,
            )
        }
    }
}

// Case states (moderation_case.py). Drive which actions are offered.
private const val ST_VISIBLE = "visible"
private const val ST_UNDER_REVIEW = "under_review"
private const val ST_HOLD = "hold"
private const val ST_AWAITING_FINAL = "awaiting_final"
private const val ST_DISMISSED = "dismissed"
private const val ST_REINSTATED = "reinstated"
private const val ST_DELETED = "deleted"

@Composable
private fun DetailBody(
    state: ModerationDetailUiState.Content,
    modifier: Modifier,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit,
    onFinalCall: (action: String, note: String?, ban: Boolean, banDays: Int?) -> Unit,
) {
    var note by remember { mutableStateOf("") }
    var showBanPicker by remember { mutableStateOf(false) }
    val d: ModerationTicketDetailDto = state.detail
    val t = d.ticket
    val caseState = d.caseState.ifBlank { if (t.status == "closed") ST_DISMISSED else ST_UNDER_REVIEW }
    val triage = caseState == ST_VISIBLE || caseState == ST_UNDER_REVIEW
    val onHold = caseState == ST_HOLD || caseState == ST_AWAITING_FINAL
    val terminal = caseState == ST_DISMISSED || caseState == ST_REINSTATED || caseState == ST_DELETED

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            t.contentType.ifBlank { "content" }.replace('_', ' '),
            style = MaterialTheme.typography.titleMedium,
        )

        // ---- Case state + hold countdown ----
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            AssistChip(
                onClick = {},
                enabled = false,
                label = { Text(caseStateLabel(caseState)) },
                colors = AssistChipDefaults.assistChipColors(
                    disabledLabelColor = MaterialTheme.colorScheme.onSecondaryContainer,
                    disabledContainerColor = MaterialTheme.colorScheme.secondaryContainer,
                ),
                modifier = Modifier.testTag(ModerationDetailTestTags.STATE_CHIP),
            )
            if (caseState == ST_HOLD && d.holdUntil != null) {
                AssistChip(onClick = {}, enabled = false, label = { Text(holdCountdown(d.holdUntil!!)) })
            }
        }

        LabeledRow("Priority", t.priority.ifBlank { "-" })
        LabeledRow("Queue", t.queue.ifBlank { "-" })
        LabeledRow("Reports", t.reportCount.toString())
        if (t.aggregatedTopics.isNotEmpty()) LabeledRow("Category", t.aggregatedTopics.joinToString(", "))
        d.ownerUserId?.takeIf { it.isNotBlank() }?.let { LabeledRow("Poster", it) }

        // ---- Content snapshot ----
        d.contentSnapshot?.let { snap ->
            Divider()
            Text("Reported content", style = MaterialTheme.typography.titleSmall)
            Card(modifier = Modifier.fillMaxWidth().testTag(ModerationDetailTestTags.CONTENT)) {
                Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    LabeledRow("Type", snap.kind.ifBlank { t.contentType }.replace('_', ' '))
                    snap.syndicateId?.takeIf { it.isNotBlank() }?.let { LabeledRow("Syndicate", it) }
                    LabeledRow("In store", if (snap.exists) "present" else "not found / removed")
                    if (snap.text.isNotBlank()) Text(snap.text, style = MaterialTheme.typography.bodyMedium)
                    if (snap.imageUrls.isNotEmpty()) LabeledRow("Images", snap.imageUrls.size.toString())
                    snap.authorUserId?.takeIf { it.isNotBlank() }?.let { LabeledRow("Author", it) }
                }
            }
        }

        // ---- Offender history (summary + violation records) ----
        d.offenderHistory?.let { h ->
            Divider()
            Text("Offender history", style = MaterialTheme.typography.titleSmall)
            LabeledRow("Prior tickets", h.totalTickets.toString())
            LabeledRow("Active enforcements", h.openTickets.toString())
            LabeledRow("Total reports", h.totalReports.toString())
        }
        if (d.priorEnforcement.isNotEmpty()) {
            Text("Violation history (${d.priorEnforcement.size})", style = MaterialTheme.typography.labelLarge)
            d.priorEnforcement.forEach { e ->
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(
                            "${e.enforcementType.ifBlank { "action" }} - ${e.status.ifBlank { "-" }}",
                            style = MaterialTheme.typography.labelLarge,
                        )
                        Text(banDurationLabel(e.enforcementType, e.durationDays), style = MaterialTheme.typography.bodySmall)
                        if (e.note.isNotBlank()) Text(e.note, style = MaterialTheme.typography.bodySmall)
                        if (e.createdAt > 0L) {
                            Text(
                                relativeSeconds(e.createdAt),
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
            }
        }

        // ---- Linked reports ----
        if (d.linkedReports.isNotEmpty()) {
            Divider()
            Text("Linked reports (${d.linkedReports.size})", style = MaterialTheme.typography.titleSmall)
            d.linkedReports.forEach { r ->
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(r.topics.joinToString(", ").ifBlank { "report" }, style = MaterialTheme.typography.labelLarge)
                        if (r.reasonText.isNotBlank()) Text(r.reasonText, style = MaterialTheme.typography.bodySmall)
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

        // ---- Poster response (MODX-14/C3): un-blind the final call ----
        d.posterResponse?.takeIf { it.isNotBlank() }?.let { resp ->
            Divider()
            Text("Poster response", style = MaterialTheme.typography.titleSmall)
            Card(
                modifier = Modifier.fillMaxWidth().testTag(ModerationDetailTestTags.POSTER_RESPONSE),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer),
            ) {
                Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(
                        "The poster submitted this defense during the review window — weigh it before the final call.",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSecondaryContainer,
                    )
                    Text(resp, style = MaterialTheme.typography.bodyMedium)
                    d.respondedAt?.takeIf { it > 0L }?.let {
                        Text(
                            relativeSeconds(it),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
        }

        // ---- Actions (gated by case state) ----
        Divider()
        Text("Actions", style = MaterialTheme.typography.titleSmall)

        if (terminal) {
            Text(
                "This case is closed (${caseStateLabel(caseState)}). No further action.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else {
            OutlinedTextField(
                value = note,
                onValueChange = { note = it },
                label = { Text("Note (optional)") },
                modifier = Modifier.fillMaxWidth().testTag(ModerationDetailTestTags.NOTE),
                enabled = !state.actionInFlight,
            )

            if (triage) {
                Text("Triage", style = MaterialTheme.typography.labelLarge)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                    OutlinedButton(
                        onClick = onDismiss,
                        enabled = !state.actionInFlight,
                        modifier = Modifier.testTag(ModerationDetailTestTags.DISMISS),
                    ) { Text("Dismiss (un-hide)") }
                    Button(
                        onClick = onConfirm,
                        enabled = !state.actionInFlight,
                        modifier = Modifier.testTag(ModerationDetailTestTags.CONFIRM),
                    ) { Text("Confirm violation") }
                }
            }

            if (onHold) {
                Text("Final call", style = MaterialTheme.typography.labelLarge)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                    OutlinedButton(
                        onClick = { onFinalCall("reinstate", note.ifBlank { null }, false, null) },
                        enabled = !state.actionInFlight,
                        modifier = Modifier.testTag(ModerationDetailTestTags.REINSTATE),
                    ) { Text("Reinstate") }
                    Button(
                        onClick = { showBanPicker = true },
                        enabled = !state.actionInFlight,
                        colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error),
                        modifier = Modifier.testTag(ModerationDetailTestTags.DELETE),
                    ) { Text("Delete + ban") }
                }
            }
        }

        if (state.actionInFlight) {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) {
                CircularProgressIndicator()
            }
        }
    }

    if (showBanPicker) {
        BanDurationDialog(
            onDismissRequest = { showBanPicker = false },
            onConfirm = { ban, banDays ->
                showBanPicker = false
                onFinalCall("delete", note.ifBlank { null }, ban, banDays)
            },
        )
    }
}

/** MOD-E2 ban-duration picker: 24h / 3d / 7d / 30d / Permanent / custom, plus delete-without-ban. */
@Composable
private fun BanDurationDialog(
    onDismissRequest: () -> Unit,
    onConfirm: (ban: Boolean, banDays: Int?) -> Unit,
) {
    // second == null -> no ban; 0 -> permanent; >0 -> fixed days; -1 -> custom sentinel
    val presets = listOf(
        "Delete only (no ban)" to null,
        "Ban 24 hours" to 1,
        "Ban 3 days" to 3,
        "Ban 7 days" to 7,
        "Ban 30 days" to 30,
        "Permanent ban" to 0,
        "Custom (days)" to -1,
    )
    var selected by remember { mutableStateOf(1) } // default: 24h
    var customDays by remember { mutableStateOf("") }
    val isCustom = presets[selected].second == -1
    val customValid = !isCustom || (customDays.toIntOrNull()?.let { it in 1..3650 } == true)

    AlertDialog(
        onDismissRequest = onDismissRequest,
        modifier = Modifier.testTag(ModerationDetailTestTags.BAN_PICKER),
        title = { Text("Delete content") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(
                    "Hard-deletes the content and records a violation. Optionally ban the poster.",
                    style = MaterialTheme.typography.bodySmall,
                )
                presets.forEachIndexed { i, (label, _) ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .selectable(selected = selected == i, onClick = { selected = i })
                            .padding(vertical = 4.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        RadioButton(selected = selected == i, onClick = { selected = i })
                        Text(label, style = MaterialTheme.typography.bodyMedium)
                    }
                }
                if (isCustom) {
                    OutlinedTextField(
                        value = customDays,
                        onValueChange = { customDays = it.filter(Char::isDigit).take(4) },
                        label = { Text("Days (1-3650)") },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
                if (presets[selected].second == 0) {
                    Text(
                        "Permanent bans require a senior moderator and dual approval.",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
        },
        confirmButton = {
            TextButton(
                enabled = customValid,
                onClick = {
                    val preset = presets[selected].second
                    val (ban, days) = when {
                        preset == null -> false to null
                        preset == -1 -> true to (customDays.toIntOrNull() ?: 1)
                        else -> true to preset
                    }
                    onConfirm(ban, days)
                },
                modifier = Modifier.testTag(ModerationDetailTestTags.BAN_CONFIRM),
            ) { Text("Delete") }
        },
        dismissButton = { TextButton(onClick = onDismissRequest) { Text("Cancel") } },
    )
}

private fun caseStateLabel(state: String): String = when (state) {
    ST_VISIBLE -> "Visible"
    ST_UNDER_REVIEW -> "Under review (hidden)"
    ST_HOLD -> "On 30-day hold (hidden)"
    ST_AWAITING_FINAL -> "Awaiting final call"
    ST_DISMISSED -> "Dismissed"
    ST_REINSTATED -> "Reinstated"
    ST_DELETED -> "Deleted"
    else -> state.replace('_', ' ').ifBlank { "-" }
}

private fun banDurationLabel(type: String, days: Int): String = when {
    type == "ban" && days <= 0 -> "Permanent ban"
    type == "ban" -> "Ban - $days day(s)"
    days > 0 -> "$days day(s)"
    else -> type.replace('_', ' ')
}

private fun holdCountdown(holdUntilEpochSeconds: Long): String {
    val remaining = holdUntilEpochSeconds - System.currentTimeMillis() / 1000L
    if (remaining <= 0L) return "Hold expired"
    val days = remaining / 86400L
    val hours = (remaining % 86400L) / 3600L
    return if (days > 0L) "Hold: ${days}d ${hours}h left" else "Hold: ${hours}h left"
}

@Composable
private fun LabeledRow(label: String, value: String) {
    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.bodyMedium)
    }
}
