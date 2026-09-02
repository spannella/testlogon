@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.crm

import androidx.compose.foundation.clickable
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
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.crm.CrmSalesMath
import com.testlogon.android.data.crm.Lead
import com.testlogon.android.data.crm.LeadActivity
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object CrmLeadDetailTestTags {
    const val SCREEN = "crm_lead_detail_screen"
    const val CONTENT = "crm_lead_detail_content"
    const val OVERFLOW = "crm_lead_detail_overflow"
}

private fun formatDate(tsSeconds: Long): String {
    if (tsSeconds <= 0) return "—"
    return SimpleDateFormat("MMM d, yyyy", Locale.getDefault()).format(Date(tsSeconds * 1000))
}

@Composable
fun LeadDetailRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: LeadDetailViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    LeadDetailScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::onRetry,
        onRecomputeScore = viewModel::recomputeScore,
        onLogActivity = viewModel::logActivity,
        onConvert = viewModel::convert,
        onAssign = viewModel::assign,
        onLoadDuplicates = viewModel::loadDuplicates,
        onMerge = viewModel::merge,
        onDelete = { viewModel.delete(onDeleted = onBack) },
        onClearActionMessage = viewModel::clearActionMessage,
        modifier = modifier,
    )
}

@Composable
fun LeadDetailScreen(
    state: LeadDetailUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onRecomputeScore: () -> Unit,
    onLogActivity: (type: String, subject: String, description: String) -> Unit,
    onConvert: (accountName: String?, createOpportunity: Boolean, opportunityName: String?) -> Unit,
    onAssign: (assigneeSub: String) -> Unit,
    onLoadDuplicates: () -> Unit,
    onMerge: (secondaryLeadId: String) -> Unit,
    onDelete: () -> Unit,
    onClearActionMessage: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbarHostState = remember { SnackbarHostState() }
    var showConvert by remember { mutableStateOf(false) }
    var showLog by remember { mutableStateOf(false) }
    var showAssign by remember { mutableStateOf(false) }
    var showMerge by remember { mutableStateOf(false) }
    var showDelete by remember { mutableStateOf(false) }
    var menuOpen by remember { mutableStateOf(false) }

    LaunchedEffect(state.actionMessage) {
        state.actionMessage?.let {
            snackbarHostState.showSnackbar(it)
            onClearActionMessage()
        }
    }

    Scaffold(
        modifier = modifier.testTag(CrmLeadDetailTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            androidx.compose.material3.TopAppBar(
                title = { Text(state.lead?.fullName ?: "Lead") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    if (state.lead != null) {
                        IconButton(
                            onClick = { menuOpen = true },
                            modifier = Modifier.testTag(CrmLeadDetailTestTags.OVERFLOW),
                        ) {
                            Icon(Icons.Filled.MoreVert, contentDescription = "More actions")
                        }
                        DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                            DropdownMenuItem(
                                text = { Text("Assign") },
                                enabled = !state.actionInProgress,
                                onClick = { menuOpen = false; showAssign = true },
                            )
                            DropdownMenuItem(
                                text = { Text("Find duplicates / merge") },
                                enabled = !state.actionInProgress,
                                onClick = {
                                    menuOpen = false
                                    onLoadDuplicates()
                                    showMerge = true
                                },
                            )
                            DropdownMenuItem(
                                text = { Text("Delete lead") },
                                enabled = !state.actionInProgress,
                                onClick = { menuOpen = false; showDelete = true },
                            )
                        }
                    }
                },
            )
        },
    ) { padding ->
        when (state.phase) {
            LeadDetailUiState.Phase.Loading -> LoadingState(modifier = Modifier.padding(padding))
            LeadDetailUiState.Phase.Error -> ErrorState(
                message = state.errorMessage ?: "Couldn't load lead.",
                onRetry = onRetry,
                modifier = Modifier.padding(padding),
            )
            LeadDetailUiState.Phase.Content -> {
                val lead = state.lead ?: return@Scaffold
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(padding)
                        .verticalScroll(rememberScrollState())
                        .padding(16.dp)
                        .testTag(CrmLeadDetailTestTags.CONTENT),
                    verticalArrangement = Arrangement.spacedBy(16.dp),
                ) {
                    LeadSummaryCard(lead)
                    if (!lead.isConverted) {
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(
                                enabled = !state.actionInProgress,
                                onClick = { showConvert = true },
                            ) { Text("Convert") }
                            OutlinedButton(
                                enabled = !state.actionInProgress,
                                onClick = onRecomputeScore,
                            ) { Text("Re-score") }
                        }
                    } else {
                        Text(
                            "Converted ${formatDate(lead.convertedAt ?: 0)}",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.primary,
                        )
                    }
                    ActivitiesCard(
                        activities = state.activities,
                        onAdd = { showLog = true },
                        enabled = !state.actionInProgress,
                    )
                    if (state.actionInProgress) {
                        CircularProgressIndicator()
                    }
                }
            }
        }
    }

    if (showConvert) {
        ConvertDialog(
            defaultName = state.lead?.company ?: state.lead?.fullName ?: "",
            onDismiss = { showConvert = false },
            onConfirm = { account, makeOpp, oppName ->
                onConvert(account, makeOpp, oppName)
                showConvert = false
            },
        )
    }
    if (showLog) {
        LogActivityDialog(
            onDismiss = { showLog = false },
            onConfirm = { type, subject, description ->
                onLogActivity(type, subject, description)
                showLog = false
            },
        )
    }
    if (showAssign) {
        AssignDialog(
            current = state.lead?.assignedTo.orEmpty(),
            onDismiss = { showAssign = false },
            onConfirm = { sub ->
                onAssign(sub)
                showAssign = false
            },
        )
    }
    if (showMerge) {
        MergeDialog(
            duplicates = state.duplicates,
            loading = state.duplicatesLoading,
            onDismiss = { showMerge = false },
            onConfirm = { secondaryId ->
                onMerge(secondaryId)
                showMerge = false
            },
        )
    }
    if (showDelete) {
        AlertDialog(
            onDismissRequest = { showDelete = false },
            title = { Text("Delete lead?") },
            text = { Text("This permanently removes ${state.lead?.fullName ?: "this lead"}.") },
            confirmButton = {
                TextButton(onClick = { showDelete = false; onDelete() }) { Text("Delete") }
            },
            dismissButton = { TextButton(onClick = { showDelete = false }) { Text("Cancel") } },
        )
    }
}

@Composable
private fun LeadSummaryCard(lead: Lead) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(lead.fullName, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
            InfoLine("Email", lead.email)
            lead.phone?.takeIf { it.isNotBlank() }?.let { InfoLine("Phone", it) }
            lead.company?.takeIf { it.isNotBlank() }?.let { InfoLine("Company", it) }
            lead.title?.takeIf { it.isNotBlank() }?.let { InfoLine("Title", it) }
            lead.leadSource?.takeIf { it.isNotBlank() }?.let { InfoLine("Source", it.replace('_', ' ')) }
            lead.assignedTo?.takeIf { it.isNotBlank() }?.let { InfoLine("Assigned to", it) }
            InfoLine("Status", lead.status.replace('_', ' '))
            InfoLine("Score", "${lead.score} (${bandLabel(lead.score)})")
            lead.description?.takeIf { it.isNotBlank() }?.let {
                HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
                Text(it, style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
}

private fun bandLabel(score: Int): String = when (CrmSalesMath.scoreBand(score)) {
    CrmSalesMath.LeadScoreBand.HOT -> "Hot"
    CrmSalesMath.LeadScoreBand.WARM -> "Warm"
    CrmSalesMath.LeadScoreBand.COLD -> "Cold"
}

@Composable
private fun InfoLine(label: String, value: String) {
    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
private fun ActivitiesCard(activities: List<LeadActivity>, onAdd: () -> Unit, enabled: Boolean) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text("Activity", style = MaterialTheme.typography.titleMedium)
                TextButton(enabled = enabled, onClick = onAdd) { Text("Log") }
            }
            if (activities.isEmpty()) {
                Text(
                    "No activity yet.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                activities.forEach { a ->
                    Column {
                        Text(
                            "${a.activityType.replace('_', ' ')} · ${formatDate(a.createdAt)}",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        a.subject?.takeIf { it.isNotBlank() }?.let {
                            Text(it, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium)
                        }
                        a.description?.takeIf { it.isNotBlank() }?.let {
                            Text(it, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ConvertDialog(
    defaultName: String,
    onDismiss: () -> Unit,
    onConfirm: (accountName: String?, createOpportunity: Boolean, opportunityName: String?) -> Unit,
) {
    var accountName by remember { mutableStateOf(defaultName) }
    var oppName by remember { mutableStateOf("") }
    var makeOpp by remember { mutableStateOf(true) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Convert lead") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(accountName, { accountName = it }, label = { Text("Account name") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text("Also create an opportunity")
                    androidx.compose.material3.Switch(checked = makeOpp, onCheckedChange = { makeOpp = it })
                }
                if (makeOpp) {
                    OutlinedTextField(oppName, { oppName = it }, label = { Text("Opportunity name (optional)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                }
            }
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(accountName, makeOpp, oppName) }) { Text("Convert") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun AssignDialog(
    current: String,
    onDismiss: () -> Unit,
    onConfirm: (assigneeSub: String) -> Unit,
) {
    var sub by remember { mutableStateOf(current) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Assign lead") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    "Enter the user id (sub) to assign this lead to.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                OutlinedTextField(
                    sub,
                    { sub = it },
                    label = { Text("Assignee user id") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        },
        confirmButton = {
            TextButton(enabled = sub.isNotBlank(), onClick = { onConfirm(sub) }) { Text("Assign") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun MergeDialog(
    duplicates: List<Lead>,
    loading: Boolean,
    onDismiss: () -> Unit,
    onConfirm: (secondaryLeadId: String) -> Unit,
) {
    var selectedId by remember { mutableStateOf<String?>(null) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Merge duplicate") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    "Pick a duplicate to merge into this lead. This lead stays as the primary; blank fields are backfilled from the duplicate.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                when {
                    loading -> CircularProgressIndicator()
                    duplicates.isEmpty() -> Text(
                        "No potential duplicates found.",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    else -> duplicates.forEach { d ->
                        Card(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { selectedId = d.leadId },
                            colors = if (d.leadId == selectedId) {
                                androidx.compose.material3.CardDefaults.cardColors(
                                    containerColor = MaterialTheme.colorScheme.secondaryContainer,
                                )
                            } else {
                                androidx.compose.material3.CardDefaults.cardColors()
                            },
                        ) {
                            Column(modifier = Modifier.padding(12.dp)) {
                                Text(d.fullName, fontWeight = FontWeight.Medium)
                                Text(
                                    listOfNotNull(d.company?.ifBlank { null }, d.email.ifBlank { null }).joinToString(" · "),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(
                enabled = selectedId != null,
                onClick = { selectedId?.let(onConfirm) },
            ) { Text("Merge") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

private val ACTIVITY_TYPES = listOf("note", "call", "task", "email")

@Composable
private fun LogActivityDialog(
    onDismiss: () -> Unit,
    onConfirm: (type: String, subject: String, description: String) -> Unit,
) {
    var type by remember { mutableStateOf("note") }
    var subject by remember { mutableStateOf("") }
    var description by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Log activity") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    ACTIVITY_TYPES.forEach { t ->
                        androidx.compose.material3.FilterChip(
                            selected = t == type,
                            onClick = { type = t },
                            label = { Text(t) },
                        )
                    }
                }
                OutlinedTextField(subject, { subject = it }, label = { Text("Subject") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(description, { description = it }, label = { Text("Notes") }, modifier = Modifier.fillMaxWidth())
            }
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(type, subject, description) }) { Text("Save") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}
