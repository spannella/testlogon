@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.testlogon.android.feature.adminemail

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.OfflineBanner
import com.testlogon.android.data.admin.email.CampaignTemplate
import com.testlogon.android.data.admin.email.EmailStats
import com.testlogon.android.data.admin.email.SuppressedEmail

object AdminEmailTestTags {
    const val SCREEN = "admin_email_screen"
    const val LOADING = "admin_email_loading"
    const val EMPTY = "admin_email_empty"
    const val ERROR = "admin_email_error"
    const val OFFLINE = "admin_email_offline"
    const val FORBIDDEN = "admin_email_forbidden"
    const val FAB = "admin_email_fab"
    const val TAB_PREFIX = "admin_email_tab_"
    const val TEMPLATE_PREFIX = "admin_email_template_"
    const val SUPPRESSED_PREFIX = "admin_email_suppressed_"
    const val CREATE_FORM = "admin_email_create_form"
    const val CREATE_SUBMIT = "admin_email_create_submit"
}

@Composable
fun AdminEmailRoute(
    onBack: () -> Unit,
    onSessionExpired: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: AdminEmailViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is AdminEmailEffect.ShowMessage ->
                    snackbarHostState.showSnackbar(context.getString(effect.resId))
                is AdminEmailEffect.ShowText ->
                    snackbarHostState.showSnackbar(effect.text)
            }
        }
    }
    LaunchedEffect(state.phase) {
        if (state.phase == AdminEmailUiState.Phase.SessionExpired) onSessionExpired()
    }

    AdminEmailScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onBack = onBack,
        onRefresh = viewModel::onRefresh,
        onRetry = viewModel::onRetry,
        onSelectTab = viewModel::onSelectTab,
        onOpenCreateTemplate = viewModel::onOpenCreateTemplate,
        onDismissCreateTemplate = viewModel::onDismissCreateTemplate,
        onTemplateNameChange = viewModel::onTemplateNameChange,
        onTemplateSubjectChange = viewModel::onTemplateSubjectChange,
        onTemplateBodyChange = viewModel::onTemplateBodyChange,
        onTemplateMergeFieldsChange = viewModel::onTemplateMergeFieldsChange,
        onSubmitCreateTemplate = viewModel::onSubmitCreateTemplate,
        onDeactivateTemplate = viewModel::onDeactivateTemplate,
        onUnsuppress = viewModel::onUnsuppress,
        modifier = modifier,
    )
}

@Composable
fun AdminEmailScreen(
    state: AdminEmailUiState,
    snackbarHostState: SnackbarHostState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onSelectTab: (AdminEmailTab) -> Unit,
    onOpenCreateTemplate: () -> Unit,
    onDismissCreateTemplate: () -> Unit,
    onTemplateNameChange: (String) -> Unit,
    onTemplateSubjectChange: (String) -> Unit,
    onTemplateBodyChange: (String) -> Unit,
    onTemplateMergeFieldsChange: (String) -> Unit,
    onSubmitCreateTemplate: () -> Unit,
    onDeactivateTemplate: (CampaignTemplate) -> Unit,
    onUnsuppress: (SuppressedEmail) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(AdminEmailTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Email admin") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
        floatingActionButton = {
            if (state.phase == AdminEmailUiState.Phase.Content && state.tab == AdminEmailTab.TEMPLATES) {
                Button(onClick = onOpenCreateTemplate, modifier = Modifier.testTag(AdminEmailTestTags.FAB)) {
                    Icon(Icons.Outlined.Add, contentDescription = null)
                    Text("New template")
                }
            }
        },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            if (state.phase == AdminEmailUiState.Phase.Content) {
                state.stats?.let { StatsHeader(it) }
                TabRow(selectedTabIndex = state.tab.ordinal) {
                    AdminEmailTab.entries.forEach { tab ->
                        Tab(
                            selected = state.tab == tab,
                            onClick = { onSelectTab(tab) },
                            text = { Text(tab.label) },
                            modifier = Modifier.testTag(AdminEmailTestTags.TAB_PREFIX + tab.name),
                        )
                    }
                }
            }

            when (state.phase) {
                AdminEmailUiState.Phase.Loading ->
                    LoadingState(modifier = Modifier.testTag(AdminEmailTestTags.LOADING))
                AdminEmailUiState.Phase.Forbidden ->
                    EmptyState(
                        title = "Admins only",
                        body = "You do not have access to email administration.",
                        imageVector = Icons.Outlined.Lock,
                        modifier = Modifier.testTag(AdminEmailTestTags.FORBIDDEN),
                    )
                AdminEmailUiState.Phase.Error ->
                    ErrorState(
                        message = "Something went wrong.",
                        onRetry = onRetry,
                        modifier = Modifier.testTag(AdminEmailTestTags.ERROR),
                    )
                AdminEmailUiState.Phase.Offline ->
                    OfflineBanner(onRetry = onRetry, modifier = Modifier.testTag(AdminEmailTestTags.OFFLINE))
                AdminEmailUiState.Phase.SessionExpired -> Unit
                AdminEmailUiState.Phase.Content ->
                    PullToRefreshBox(
                        isRefreshing = state.isRefreshing,
                        onRefresh = onRefresh,
                        modifier = Modifier.fillMaxSize(),
                    ) {
                        TabContent(
                            state = state,
                            onDeactivateTemplate = onDeactivateTemplate,
                            onUnsuppress = onUnsuppress,
                        )
                    }
            }
        }
    }

    if (state.createTemplate.isOpen) {
        CreateTemplateDialog(
            form = state.createTemplate,
            onDismiss = onDismissCreateTemplate,
            onNameChange = onTemplateNameChange,
            onSubjectChange = onTemplateSubjectChange,
            onBodyChange = onTemplateBodyChange,
            onMergeFieldsChange = onTemplateMergeFieldsChange,
            onSubmit = onSubmitCreateTemplate,
        )
    }
}

@Composable
private fun StatsHeader(stats: EmailStats) {
    Card(modifier = Modifier.fillMaxWidth().padding(16.dp)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                "Last ${stats.periodDays} days",
                style = MaterialTheme.typography.labelMedium,
            )
            Text(stats.summaryLabel, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Text(
                "Bounce ${stats.bounceRateLabel} · Complaint ${stats.complaintRateLabel}",
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

@Composable
private fun TabContent(
    state: AdminEmailUiState,
    onDeactivateTemplate: (CampaignTemplate) -> Unit,
    onUnsuppress: (SuppressedEmail) -> Unit,
) {
    if (state.isEmptyForTab) {
        val (title, body) = when (state.tab) {
            AdminEmailTab.TEMPLATES -> "No campaign templates" to "Create a template to reuse in campaigns."
            AdminEmailTab.SUPPRESSED -> "No suppressed addresses" to "Bounced/complained recipients appear here."
        }
        EmptyState(title = title, body = body, modifier = Modifier.testTag(AdminEmailTestTags.EMPTY))
        return
    }
    LazyColumn(
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        modifier = Modifier.fillMaxSize(),
    ) {
        when (state.tab) {
            AdminEmailTab.TEMPLATES -> items(state.templates, key = { it.id }) { t ->
                TemplateCard(t, busy = state.busyId == t.id, onDeactivate = onDeactivateTemplate)
            }
            AdminEmailTab.SUPPRESSED -> items(state.suppressed, key = { it.email }) { s ->
                SuppressedCard(s, busy = state.busyId == s.email, onUnsuppress = onUnsuppress)
            }
        }
    }
}

@Composable
private fun TemplateCard(
    template: CampaignTemplate,
    busy: Boolean,
    onDeactivate: (CampaignTemplate) -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().testTag(AdminEmailTestTags.TEMPLATE_PREFIX + template.id)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(template.name, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Text(template.subjectLabel, style = MaterialTheme.typography.bodyMedium)
            Text(template.mergeFieldsLabel, style = MaterialTheme.typography.bodySmall)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                AssistChip(onClick = {}, label = { Text(if (template.active) "active" else "inactive") })
                if (template.active) {
                    OutlinedButton(onClick = { onDeactivate(template) }, enabled = !busy) { Text("Deactivate") }
                }
            }
        }
    }
}

@Composable
private fun SuppressedCard(
    entry: SuppressedEmail,
    busy: Boolean,
    onUnsuppress: (SuppressedEmail) -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().testTag(AdminEmailTestTags.SUPPRESSED_PREFIX + entry.email)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(entry.email, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Text(entry.reasonLabel, style = MaterialTheme.typography.bodySmall)
            OutlinedButton(onClick = { onUnsuppress(entry) }, enabled = !busy) { Text("Unsuppress") }
        }
    }
}

@Composable
private fun CreateTemplateDialog(
    form: CreateTemplateFormState,
    onDismiss: () -> Unit,
    onNameChange: (String) -> Unit,
    onSubjectChange: (String) -> Unit,
    onBodyChange: (String) -> Unit,
    onMergeFieldsChange: (String) -> Unit,
    onSubmit: () -> Unit,
) {
    Dialog(onDismissRequest = onDismiss) {
        Card(modifier = Modifier.testTag(AdminEmailTestTags.CREATE_FORM)) {
            Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("New campaign template", style = MaterialTheme.typography.titleLarge)
                OutlinedTextField(
                    value = form.name,
                    onValueChange = onNameChange,
                    label = { Text("Name") },
                    singleLine = true,
                    enabled = !form.isSubmitting,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = form.subject,
                    onValueChange = onSubjectChange,
                    label = { Text("Subject") },
                    singleLine = true,
                    enabled = !form.isSubmitting,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = form.body,
                    onValueChange = onBodyChange,
                    label = { Text("Body") },
                    enabled = !form.isSubmitting,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = form.mergeFields,
                    onValueChange = onMergeFieldsChange,
                    label = { Text("Merge fields (comma separated)") },
                    singleLine = true,
                    enabled = !form.isSubmitting,
                    modifier = Modifier.fillMaxWidth(),
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.align(Alignment.End)) {
                    TextButton(onClick = onDismiss, enabled = !form.isSubmitting) { Text("Cancel") }
                    Button(
                        onClick = onSubmit,
                        enabled = form.canSubmit,
                        modifier = Modifier.testTag(AdminEmailTestTags.CREATE_SUBMIT),
                    ) { Text("Create") }
                }
            }
        }
    }
}
