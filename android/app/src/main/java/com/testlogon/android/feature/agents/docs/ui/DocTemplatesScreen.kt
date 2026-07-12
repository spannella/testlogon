@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.agents.docs.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
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
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.feature.agents.docs.data.DocTemplate

/** AGENTS-BASICS - stable testTags for the doc-templates screen. */
object DocTemplatesTestTags {
    const val SCREEN = "agent_doc_templates_screen"
    const val ERROR_RETRY = "agent_doc_templates_error_retry"
    const val NAME = "agent_doc_template_name"
    const val BODY = "agent_doc_template_body"
    const val CREATE = "agent_doc_template_create"
    fun row(id: String) = "agent_doc_template_row_$id"
    fun delete(id: String) = "agent_doc_template_delete_$id"
}

private val DOC_TYPES = listOf("api", "architecture", "user_guide", "adr", "readme")

@Composable
fun DocTemplatesRoute(
    onBack: () -> Unit,
    onNavigateToLogin: () -> Unit,
    viewModel: DocTemplatesViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is DocsEffect.NavigateToLogin -> onNavigateToLogin()
            }
        }
    }
    DocTemplatesScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::onRetry,
        onCreate = { name, type, body -> viewModel.create(name, type, body, emptyList()) },
        onDelete = viewModel::delete,
    )
}

@Composable
fun DocTemplatesScreen(
    state: DocTemplatesUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onCreate: (name: String, docType: String, body: String) -> Unit,
    onDelete: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(DocTemplatesTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Doc templates") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        val isRefreshing = (state as? DocTemplatesUiState.Content)?.isRefreshing == true
        PullToRefreshBox(
            isRefreshing = isRefreshing,
            onRefresh = onRefresh,
            modifier = Modifier.fillMaxSize().padding(padding),
        ) {
            when (state) {
                is DocTemplatesUiState.Loading -> LoadingState()
                is DocTemplatesUiState.Error ->
                    ErrorState(
                        modifier = Modifier.testTag(DocTemplatesTestTags.ERROR_RETRY),
                        message = state.message,
                        onRetry = onRetry,
                    )
                is DocTemplatesUiState.Content ->
                    LazyColumn(
                        modifier = Modifier.fillMaxSize(),
                        contentPadding = PaddingValues(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        if (state.actionError != null) {
                            item {
                                Text(
                                    text = state.actionError,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.error,
                                )
                            }
                        }
                        item { CreateTemplateForm(busy = state.busy, onCreate = onCreate) }
                        item { HorizontalDivider() }
                        if (state.templates.isEmpty()) {
                            item {
                                Text(
                                    "No templates yet.",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        } else {
                            items(items = state.templates, key = { it.templateId }) { template ->
                                TemplateRow(template = template, enabled = !state.busy, onDelete = { onDelete(template.templateId) })
                            }
                        }
                    }
            }
        }
    }
}

@Composable
private fun CreateTemplateForm(
    busy: Boolean,
    onCreate: (String, String, String) -> Unit,
) {
    var name by rememberSaveable { mutableStateOf("") }
    var body by rememberSaveable { mutableStateOf("") }
    var docType by rememberSaveable { mutableStateOf(DOC_TYPES.first()) }
    var expanded by remember { mutableStateOf(false) }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("New template", style = MaterialTheme.typography.titleMedium)
        OutlinedTextField(
            value = name,
            onValueChange = { name = it },
            label = { Text("Name") },
            modifier = Modifier.fillMaxWidth().testTag(DocTemplatesTestTags.NAME),
            enabled = !busy,
        )
        ExposedDropdownMenuBox(expanded = expanded, onExpandedChange = { if (!busy) expanded = it }) {
            OutlinedTextField(
                value = docType,
                onValueChange = {},
                readOnly = true,
                label = { Text("Doc type") },
                trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
                modifier = Modifier.menuAnchor().fillMaxWidth(),
                enabled = !busy,
            )
            ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
                DOC_TYPES.forEach { type ->
                    DropdownMenuItem(text = { Text(type) }, onClick = { docType = type; expanded = false })
                }
            }
        }
        OutlinedTextField(
            value = body,
            onValueChange = { body = it },
            label = { Text("Template body") },
            modifier = Modifier.fillMaxWidth().testTag(DocTemplatesTestTags.BODY),
            minLines = 3,
            enabled = !busy,
        )
        OutlinedButton(
            onClick = {
                onCreate(name, docType, body)
                name = ""; body = ""
            },
            enabled = !busy && name.isNotBlank() && body.isNotBlank(),
            modifier = Modifier.testTag(DocTemplatesTestTags.CREATE),
        ) {
            if (busy) {
                CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(18.dp))
            } else {
                Icon(Icons.Outlined.Add, contentDescription = null)
                Text(" Create template")
            }
        }
    }
}

@Composable
private fun TemplateRow(template: DocTemplate, enabled: Boolean, onDelete: () -> Unit) {
    Card(Modifier.fillMaxWidth().testTag(DocTemplatesTestTags.row(template.templateId))) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(
                    template.name.ifBlank { template.templateId },
                    style = MaterialTheme.typography.titleSmall,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    listOf(
                        template.docType,
                        template.requiredSections.size.takeIf { it > 0 }?.let { "$it sections" },
                    ).filterNotNull().filter { it.isNotBlank() }.joinToString(" · "),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            IconButton(
                onClick = onDelete,
                enabled = enabled,
                modifier = Modifier.testTag(DocTemplatesTestTags.delete(template.templateId)),
            ) {
                Icon(Icons.Outlined.Delete, contentDescription = "Delete", tint = MaterialTheme.colorScheme.error)
            }
        }
    }
}
