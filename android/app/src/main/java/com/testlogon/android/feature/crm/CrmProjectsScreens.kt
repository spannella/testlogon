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
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
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
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.OfflineBanner
import com.testlogon.android.data.crm.CrmProject
import com.testlogon.android.data.crm.CrmProjectTask
import com.testlogon.android.data.crm.CrmPecMath

object CrmProjectsTestTags {
    const val SCREEN = "crm_projects_screen"
    const val CONTENT = "crm_projects_content"
    const val LOADING = "crm_projects_loading"
    const val ERROR = "crm_projects_error"
    const val FAB = "crm_projects_fab"
    const val DETAIL = "crm_project_detail"
}

// ─── List ─────────────────────────────────────────────────────────────────────

@Composable
fun CrmProjectsRoute(
    onProjectClick: (String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: CrmProjectsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    CrmProjectsScreen(
        state = state,
        onProjectClick = onProjectClick,
        onBack = onBack,
        onRefresh = viewModel::onRefresh,
        onRetry = viewModel::onRetry,
        onCreate = viewModel::createProject,
        onClearCreateError = viewModel::clearCreateError,
        modifier = modifier,
    )
}

@Composable
fun CrmProjectsScreen(
    state: CrmProjectsUiState,
    onProjectClick: (String) -> Unit,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onCreate: (String, String?, String?, (String) -> Unit) -> Unit,
    onClearCreateError: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var showCreate by remember { mutableStateOf(false) }

    Scaffold(
        modifier = modifier.testTag(CrmProjectsTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Projects") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
        floatingActionButton = {
            FloatingActionButton(
                onClick = { showCreate = true },
                modifier = Modifier.testTag(CrmProjectsTestTags.FAB),
            ) { Icon(Icons.Filled.Add, contentDescription = "New project") }
        },
    ) { padding ->
        when (state.phase) {
            CrmProjectsUiState.Phase.Loading -> LoadingState(
                modifier = Modifier.padding(padding).testTag(CrmProjectsTestTags.LOADING),
            )
            CrmProjectsUiState.Phase.Error -> ErrorState(
                message = state.errorMessage ?: "Couldn't load projects.",
                onRetry = onRetry,
                modifier = Modifier.padding(padding).testTag(CrmProjectsTestTags.ERROR),
            )
            CrmProjectsUiState.Phase.Content -> PullToRefreshBox(
                isRefreshing = state.isRefreshing,
                onRefresh = onRefresh,
                modifier = Modifier.padding(padding).fillMaxSize(),
            ) {
                Column(modifier = Modifier.fillMaxSize()) {
                    if (state.isOffline) OfflineBanner(onRetry = onRetry)
                    if (state.moduleDisabled) InfoBanner("The Projects module is not enabled for this account.")
                    if (state.projects.isEmpty()) {
                        EmptyState(
                            title = if (state.moduleDisabled) "Projects unavailable" else "No projects yet",
                            body = if (state.moduleDisabled) null else "Tap + to create your first project.",
                            modifier = Modifier.fillMaxSize(),
                        )
                    } else {
                        LazyColumn(
                            modifier = Modifier.fillMaxSize().testTag(CrmProjectsTestTags.CONTENT),
                            contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            items(state.projects, key = { it.id }) { project ->
                                ProjectRow(project = project, onClick = { onProjectClick(project.id) })
                            }
                        }
                    }
                }
            }
        }
    }

    if (showCreate) {
        CreateProjectSheet(
            submitting = state.createSubmitting,
            error = state.createError,
            onDismiss = {
                showCreate = false
                onClearCreateError()
            },
            onSubmit = { name, desc, status ->
                onCreate(name, desc, status) { _ -> showCreate = false }
            },
        )
    }
}

@Composable
private fun ProjectRow(project: CrmProject, onClick: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth().clickable(onClick = onClick)) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(project.name.ifBlank { "(untitled)" }, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                val range = CrmPecMath.dateRange(project.startDate, project.endDate)
                if (range != CrmPecMath.EM_DASH) {
                    Text(range, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            AssistChip(onClick = onClick, label = { Text(CrmPecMath.projectStatusLabel(project.status)) })
        }
    }
}

// ─── Detail ───────────────────────────────────────────────────────────────────

@Composable
fun CrmProjectDetailRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: CrmProjectDetailViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    CrmProjectDetailScreen(state = state, onBack = onBack, onRetry = viewModel::onRetry, modifier = modifier)
}

@Composable
fun CrmProjectDetailScreen(
    state: CrmProjectDetailUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(CrmProjectsTestTags.DETAIL),
        topBar = {
            TopAppBar(
                title = { Text(state.project?.name?.ifBlank { "Project" } ?: "Project") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        when (state.phase) {
            CrmProjectDetailUiState.Phase.Loading -> LoadingState(modifier = Modifier.padding(padding))
            CrmProjectDetailUiState.Phase.Error -> ErrorState(
                message = state.errorMessage ?: "Couldn't load this project.",
                onRetry = onRetry,
                modifier = Modifier.padding(padding),
            )
            CrmProjectDetailUiState.Phase.Content -> {
                val project = state.project
                Column(
                    modifier = Modifier.padding(padding).fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    if (state.isOffline) OfflineBanner(onRetry = onRetry)
                    if (project != null) {
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            AssistChip(onClick = {}, label = { Text(CrmPecMath.projectStatusLabel(project.status)) })
                            AssistChip(onClick = {}, label = { Text("Priority ${project.priority}") })
                        }
                        LabeledValue("Dates", CrmPecMath.dateRange(project.startDate, project.endDate))
                        if (!project.description.isNullOrBlank()) {
                            LabeledValue("Description", project.description)
                        }
                    }
                    Text("Tasks", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    if (state.tasks.isEmpty()) {
                        Text("No tasks.", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    } else {
                        state.tasks.forEach { TaskRow(it) }
                    }
                }
            }
        }
    }
}

@Composable
private fun TaskRow(task: CrmProjectTask) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                (if (task.isMilestone) "◆ " else "") + task.name.ifBlank { "(untitled task)" },
                style = MaterialTheme.typography.bodyLarge,
                fontWeight = FontWeight.Medium,
            )
            val pct = CrmPecMath.clampPercent(task.percentComplete)
            LinearProgressIndicator(progress = { pct / 100f }, modifier = Modifier.fillMaxWidth())
            Text("$pct% · ${CrmPecMath.dateRange(task.startDate, task.endDate)}", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
internal fun LabeledValue(label: String, value: String) {
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.bodyMedium)
    }
}

// ─── Create sheet ───────────────────────────────────────────────────────────

@Composable
private fun CreateProjectSheet(
    submitting: Boolean,
    error: String?,
    onDismiss: () -> Unit,
    onSubmit: (name: String, description: String?, status: String?) -> Unit,
) {
    var name by remember { mutableStateOf("") }
    var description by remember { mutableStateOf("") }
    var status by remember { mutableStateOf(CrmPecMath.PROJECT_DRAFT) }

    AlertDialog(
        onDismissRequest = { if (!submitting) onDismiss() },
        title = { Text("New project") },
        text = {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedTextField(name, { name = it }, label = { Text("Name") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(description, { description = it }, label = { Text("Description (optional)") }, modifier = Modifier.fillMaxWidth())
                Text("Status", style = MaterialTheme.typography.labelMedium)
                Row(
                    modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    CrmPecMath.PROJECT_STATUSES.forEach { s ->
                        FilterChip(
                            selected = s == status,
                            onClick = { status = s },
                            label = { Text(CrmPecMath.projectStatusLabel(s)) },
                        )
                    }
                }
                if (error != null) {
                    Text(error, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                }
            }
        },
        confirmButton = {
            TextButton(enabled = !submitting, onClick = { onSubmit(name, description, status) }) {
                if (submitting) CircularProgressIndicator(modifier = Modifier.size(18.dp)) else Text("Create")
            }
        },
        dismissButton = { TextButton(enabled = !submitting, onClick = onDismiss) { Text("Cancel") } },
    )
}
