@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.crm

import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.OfflineBanner
import com.testlogon.android.data.crm.CampaignMath
import com.testlogon.android.data.crm.CrmAbResults
import com.testlogon.android.data.crm.CrmEmailTemplate
import com.testlogon.android.data.crm.CrmPecMath
import com.testlogon.android.data.crm.CrmWebLead

object CrmMarketingTestTags {
    const val EDITOR = "crm_campaign_editor"
    const val TEMPLATES = "crm_email_templates"
    const val LEADS = "crm_marketing_leads"
}

// ═══════════════════════════  Campaign editor  ═══════════════════════════

@Composable
fun CrmCampaignEditorRoute(
    onBack: () -> Unit,
    onSaved: (String) -> Unit,
    modifier: Modifier = Modifier,
    viewModel: CrmCampaignEditorViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    LaunchedEffect(state.savedCampaignId) {
        state.savedCampaignId?.let { onSaved(it); viewModel.consumeSaved() }
    }
    CrmCampaignEditorScreen(
        state = state,
        onBack = onBack,
        onName = viewModel::onName,
        onObjective = viewModel::onObjective,
        onBudget = viewModel::onBudget,
        onCampaignType = viewModel::onCampaignType,
        onContactLists = viewModel::onContactLists,
        onSegments = viewModel::onSegments,
        onTrackingCode = viewModel::onTrackingCode,
        onEmailTemplateId = viewModel::onEmailTemplateId,
        onSave = viewModel::save,
        onSend = viewModel::send,
        onPreview = viewModel::loadPreview,
        onDismissSendResult = viewModel::dismissSendResult,
        onDismissPreview = viewModel::dismissPreview,
        onRetry = viewModel::onRetry,
        modifier = modifier,
    )
}

@Composable
fun CrmCampaignEditorScreen(
    state: CrmCampaignEditorUiState,
    onBack: () -> Unit,
    onName: (String) -> Unit,
    onObjective: (String) -> Unit,
    onBudget: (String) -> Unit,
    onCampaignType: (String) -> Unit,
    onContactLists: (String) -> Unit,
    onSegments: (String) -> Unit,
    onTrackingCode: (String) -> Unit,
    onEmailTemplateId: (String) -> Unit,
    onSave: () -> Unit,
    onSend: (Boolean) -> Unit,
    onPreview: () -> Unit,
    onDismissSendResult: () -> Unit,
    onDismissPreview: () -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(CrmMarketingTestTags.EDITOR),
        topBar = {
            TopAppBar(
                title = { Text(if (state.isNew) "New campaign" else "Edit campaign") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        when (state.phase) {
            CrmCampaignEditorUiState.Phase.Loading -> LoadingState(modifier = Modifier.padding(padding))
            CrmCampaignEditorUiState.Phase.Error -> ErrorState(
                message = state.errorMessage ?: "Couldn't load this campaign.",
                onRetry = onRetry,
                modifier = Modifier.padding(padding),
            )
            CrmCampaignEditorUiState.Phase.Content -> Column(
                modifier = Modifier.padding(padding).fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                if (state.isOffline) OfflineBanner(onRetry = onRetry)
                OutlinedTextField(state.name, onName, label = { Text("Name") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(state.objective, onObjective, label = { Text("Objective (optional)") }, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(state.budget, onBudget, label = { Text("Budget ($)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                Text("Type", style = MaterialTheme.typography.labelMedium)
                Row(
                    modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    CampaignMath.CAMPAIGN_TYPES.forEach { t ->
                        FilterChip(
                            selected = t == state.campaignType,
                            onClick = { onCampaignType(t) },
                            label = { Text(CrmPecMath.campaignTypeLabel(t)) },
                        )
                    }
                }
                OutlinedTextField(state.contactListIdsRaw, onContactLists, label = { Text("Contact list IDs (comma-separated)") }, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(state.segmentIdsRaw, onSegments, label = { Text("Segment IDs (comma-separated)") }, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(state.emailTemplateId, onEmailTemplateId, label = { Text("Email template ID (optional)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(state.trackingCode, onTrackingCode, label = { Text("Tracking code (optional)") }, singleLine = true, modifier = Modifier.fillMaxWidth())

                if (state.formError != null) {
                    Text(state.formError, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                }

                Button(onClick = onSave, enabled = !state.saving, modifier = Modifier.fillMaxWidth()) {
                    if (state.saving) CircularProgressIndicator(modifier = Modifier.size(18.dp)) else Text(if (state.isNew) "Create" else "Save")
                }

                if (state.campaign != null) {
                    HorizontalDivider()
                    Text("Send & preview", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    val blocked = state.sendBlockedReason
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                        OutlinedButton(onClick = { onSend(true) }, enabled = !state.sending && state.canSend, modifier = Modifier.weight(1f)) {
                            Text("Dry run")
                        }
                        Button(onClick = { onSend(false) }, enabled = !state.sending && state.canSend, modifier = Modifier.weight(1f)) {
                            if (state.sending) CircularProgressIndicator(modifier = Modifier.size(18.dp)) else Text("Send")
                        }
                    }
                    if (blocked != null) {
                        Text(blocked, color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall)
                    }
                    OutlinedButton(onClick = onPreview, enabled = !state.previewLoading, modifier = Modifier.fillMaxWidth()) {
                        if (state.previewLoading) CircularProgressIndicator(modifier = Modifier.size(18.dp)) else Text("Preview email")
                    }
                }
            }
        }
    }

    val send = state.sendResult
    if (send != null) {
        AlertDialog(
            onDismissRequest = onDismissSendResult,
            title = { Text(if (send.dryRun) "Dry run" else "Send complete") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    LabeledValue("Resolved", send.totalResolved.toString())
                    LabeledValue("Sent", send.totalSent.toString())
                    LabeledValue("Skipped", send.totalSkipped.toString())
                }
            },
            confirmButton = { TextButton(onClick = onDismissSendResult) { Text("OK") } },
        )
    }

    val preview = state.preview
    if (preview != null) {
        AlertDialog(
            onDismissRequest = onDismissPreview,
            title = { Text("Email preview") },
            text = {
                Column(
                    modifier = Modifier.verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    LabeledValue("Subject", preview.subject.ifBlank { CrmPecMath.EM_DASH })
                    Text(preview.bodyText.ifBlank { "(no body)" }, style = MaterialTheme.typography.bodySmall)
                    if (preview.mergeVarsMissing.isNotEmpty()) {
                        Text(
                            "Missing: ${preview.mergeVarsMissing.joinToString(", ")}",
                            color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
            },
            confirmButton = { TextButton(onClick = onDismissPreview) { Text("Close") } },
        )
    }
}

// ═══════════════════════════  A/B results (shared)  ═══════════════════════════

@Composable
fun AbResultsSection(ab: CrmAbResults) {
    Text("A/B results", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
    val winner = CampaignMath.pickWinner(ab.variants.map { Triple(it.variantId, it.openRate, it.clickRate) })
    ab.variants.forEach { v ->
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(v.label.ifBlank { v.variantId.ifBlank { "Variant" } }, fontWeight = FontWeight.SemiBold)
                    if (winner != null && winner == v.variantId) {
                        AssistChip(onClick = {}, label = { Text("Winning") })
                    }
                }
                LabeledValue("Sent", v.sent.toString())
                LabeledValue("Opens", "${v.opens} (${CrmPecMath.formatRate(v.openRate)})")
                LabeledValue("Clicks", "${v.clicks} (${CrmPecMath.formatRate(v.clickRate)})")
            }
        }
    }
}

// ═══════════════════════════  Email templates  ═══════════════════════════

@Composable
fun CrmEmailTemplatesRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: CrmEmailTemplatesViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    CrmEmailTemplatesScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::onRefresh,
        onRetry = viewModel::onRetry,
        onOpenCreate = viewModel::openCreate,
        onOpenEdit = viewModel::openEdit,
        onDelete = viewModel::deleteTemplate,
        onCloseEditor = viewModel::closeEditor,
        onEditName = viewModel::onEditName,
        onEditSubject = viewModel::onEditSubject,
        onEditBody = viewModel::onEditBody,
        onSave = viewModel::saveTemplate,
        modifier = modifier,
    )
}

@Composable
fun CrmEmailTemplatesScreen(
    state: CrmEmailTemplatesUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onOpenCreate: () -> Unit,
    onOpenEdit: (CrmEmailTemplate) -> Unit,
    onDelete: (String) -> Unit,
    onCloseEditor: () -> Unit,
    onEditName: (String) -> Unit,
    onEditSubject: (String) -> Unit,
    onEditBody: (String) -> Unit,
    onSave: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(CrmMarketingTestTags.TEMPLATES),
        topBar = {
            TopAppBar(
                title = { Text("Email templates") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
        floatingActionButton = {
            if (state.phase == CrmEmailTemplatesUiState.Phase.Content && !state.moduleDisabled) {
                FloatingActionButton(onClick = onOpenCreate) {
                    Icon(Icons.Filled.Add, contentDescription = "New template")
                }
            }
        },
    ) { padding ->
        when (state.phase) {
            CrmEmailTemplatesUiState.Phase.Loading -> LoadingState(modifier = Modifier.padding(padding))
            CrmEmailTemplatesUiState.Phase.Error -> ErrorState(
                message = state.errorMessage ?: "Couldn't load templates.",
                onRetry = onRetry,
                modifier = Modifier.padding(padding),
            )
            CrmEmailTemplatesUiState.Phase.Content -> PullToRefreshBox(
                isRefreshing = state.isRefreshing,
                onRefresh = onRefresh,
                modifier = Modifier.padding(padding).fillMaxSize(),
            ) {
                Column(modifier = Modifier.fillMaxSize()) {
                    if (state.isOffline) OfflineBanner(onRetry = onRetry)
                    if (state.moduleDisabled) InfoBanner("The Marketing module is not enabled for this account.")
                    if (state.templates.isEmpty()) {
                        EmptyState(
                            title = if (state.moduleDisabled) "Templates unavailable" else "No templates yet",
                            body = if (state.moduleDisabled) null else "Create an HTML email template with the + button.",
                            modifier = Modifier.fillMaxSize(),
                        )
                    } else {
                        LazyColumn(
                            modifier = Modifier.fillMaxSize(),
                            contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            items(state.templates, key = { it.templateId }) { t ->
                                TemplateRow(
                                    template = t,
                                    deleting = state.busyDeleteId == t.templateId,
                                    onClick = { onOpenEdit(t) },
                                    onDelete = { onDelete(t.templateId) },
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    if (state.editorOpen) {
        AlertDialog(
            onDismissRequest = { if (!state.saving) onCloseEditor() },
            title = { Text(if (state.editing == null) "New template" else "Edit template") },
            text = {
                Column(
                    modifier = Modifier.verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    OutlinedTextField(state.editName, onEditName, label = { Text("Name") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                    OutlinedTextField(state.editSubject, onEditSubject, label = { Text("Subject") }, modifier = Modifier.fillMaxWidth())
                    OutlinedTextField(state.editBody, onEditBody, label = { Text("HTML body (use {{ var }})") }, modifier = Modifier.fillMaxWidth())
                    val vars = CampaignMath.extractTemplateVars(state.editSubject, state.editBody)
                    if (vars.isNotEmpty()) {
                        Text("Variables: ${vars.joinToString(", ")}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    if (state.formError != null) {
                        Text(state.formError, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                    }
                }
            },
            confirmButton = {
                TextButton(enabled = !state.saving, onClick = onSave) {
                    if (state.saving) CircularProgressIndicator(modifier = Modifier.size(18.dp)) else Text("Save")
                }
            },
            dismissButton = { TextButton(enabled = !state.saving, onClick = onCloseEditor) { Text("Cancel") } },
        )
    }
}

@Composable
private fun TemplateRow(
    template: CrmEmailTemplate,
    deleting: Boolean,
    onClick: () -> Unit,
    onDelete: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().clickable(onClick = onClick)) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(template.name.ifBlank { "(untitled)" }, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Text(template.subjectTemplate.ifBlank { CrmPecMath.EM_DASH }, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            AssistChip(onClick = onClick, label = { Text(CrmPecMath.campaignStatusLabel(template.status)) })
            IconButton(onClick = onDelete, enabled = !deleting) {
                if (deleting) CircularProgressIndicator(modifier = Modifier.size(18.dp))
                else Icon(Icons.Filled.Delete, contentDescription = "Delete")
            }
        }
    }
}

// ═══════════════════════════  Admin web-to-lead list  ═══════════════════════════

@Composable
fun CrmMarketingLeadsRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: CrmMarketingLeadsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    CrmMarketingLeadsScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::onRefresh,
        onRetry = viewModel::onRetry,
        modifier = modifier,
    )
}

@Composable
fun CrmMarketingLeadsScreen(
    state: CrmMarketingLeadsUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(CrmMarketingTestTags.LEADS),
        topBar = {
            TopAppBar(
                title = { Text("Web leads") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        when (state.phase) {
            CrmMarketingLeadsUiState.Phase.Loading -> LoadingState(modifier = Modifier.padding(padding))
            CrmMarketingLeadsUiState.Phase.Error -> ErrorState(
                message = state.errorMessage ?: "Couldn't load leads.",
                onRetry = onRetry,
                modifier = Modifier.padding(padding),
            )
            CrmMarketingLeadsUiState.Phase.Content -> PullToRefreshBox(
                isRefreshing = state.isRefreshing,
                onRefresh = onRefresh,
                modifier = Modifier.padding(padding).fillMaxSize(),
            ) {
                Column(modifier = Modifier.fillMaxSize()) {
                    if (state.isOffline) OfflineBanner(onRetry = onRetry)
                    if (state.forbidden) InfoBanner("Web leads can only be viewed by an administrator.")
                    if (state.moduleDisabled) InfoBanner("The Marketing module is not enabled for this account.")
                    if (state.leads.isEmpty()) {
                        EmptyState(
                            title = when {
                                state.forbidden -> "Not available"
                                state.moduleDisabled -> "Leads unavailable"
                                else -> "No web leads yet"
                            },
                            body = if (state.forbidden || state.moduleDisabled) null else "Captured web-to-lead submissions will appear here.",
                            modifier = Modifier.fillMaxSize(),
                        )
                    } else {
                        LazyColumn(
                            modifier = Modifier.fillMaxSize(),
                            contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            items(state.leads, key = { it.captureId }) { lead -> LeadRow(lead) }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun LeadRow(lead: CrmWebLead) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            val name = listOfNotNull(lead.firstName, lead.lastName).joinToString(" ").ifBlank { "(no name)" }
            Text(name, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            if (!lead.email.isNullOrBlank()) LabeledValue("Email", lead.email)
            if (!lead.company.isNullOrBlank()) LabeledValue("Company", lead.company)
            if (!lead.phone.isNullOrBlank()) LabeledValue("Phone", lead.phone)
            LabeledValue("Captured", CrmPecMath.formatDate(lead.createdAt))
        }
    }
}
