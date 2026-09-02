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
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
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
import com.testlogon.android.data.crm.CrmProjectMember
import com.testlogon.android.data.crm.CrmProjectTask
import com.testlogon.android.data.crm.CrmProjectTemplate
import com.testlogon.android.data.crm.CrmPecMath
import com.testlogon.android.data.crm.ProjectMath

object CrmProjectsTestTags {
    const val SCREEN = "crm_projects_screen"
    const val CONTENT = "crm_projects_content"
    const val LOADING = "crm_projects_loading"
    const val ERROR = "crm_projects_error"
    const val FAB = "crm_projects_fab"
    const val DETAIL = "crm_project_detail"
    const val TEMPLATES = "crm_projects_templates"
    const val TASK_FAB = "crm_project_task_fab"
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
        onLoadTemplates = viewModel::loadTemplates,
        onInstantiateTemplate = viewModel::instantiateTemplate,
        onDeleteTemplate = viewModel::deleteTemplate,
        onClearTemplateError = viewModel::clearTemplateError,
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
    onLoadTemplates: () -> Unit,
    onInstantiateTemplate: (String, String, (String) -> Unit) -> Unit,
    onDeleteTemplate: (String) -> Unit,
    onClearTemplateError: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var showCreate by remember { mutableStateOf(false) }
    var showTemplates by remember { mutableStateOf(false) }

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
                actions = {
                    TextButton(
                        onClick = {
                            showTemplates = true
                            onLoadTemplates()
                        },
                        modifier = Modifier.testTag(CrmProjectsTestTags.TEMPLATES),
                    ) { Text("Templates") }
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

    if (showTemplates) {
        TemplatesSheet(
            state = state,
            onDismiss = {
                showTemplates = false
                onClearTemplateError()
            },
            onInstantiate = { templateId, projectName ->
                onInstantiateTemplate(templateId, projectName) { id ->
                    showTemplates = false
                    onProjectClick(id)
                }
            },
            onDelete = onDeleteTemplate,
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
    CrmProjectDetailScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::onRetry,
        onCreateTask = viewModel::createTask,
        onSetTaskProgress = viewModel::setTaskProgress,
        onToggleMilestone = viewModel::toggleMilestone,
        onDeleteTask = viewModel::deleteTask,
        onMoveTaskUp = viewModel::moveTaskUp,
        onMoveTaskDown = viewModel::moveTaskDown,
        onAddMember = viewModel::addMember,
        onUpdateMemberRole = viewModel::updateMemberRole,
        onRemoveMember = viewModel::removeMember,
        onClearActionError = viewModel::clearActionError,
        modifier = modifier,
    )
}

@Composable
fun CrmProjectDetailScreen(
    state: CrmProjectDetailUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onCreateTask: (String, Boolean, String?) -> Unit,
    onSetTaskProgress: (String, Int) -> Unit,
    onToggleMilestone: (String, Boolean) -> Unit,
    onDeleteTask: (String) -> Unit,
    onMoveTaskUp: (Int) -> Unit,
    onMoveTaskDown: (Int) -> Unit,
    onAddMember: (String, String) -> Unit,
    onUpdateMemberRole: (String, String) -> Unit,
    onRemoveMember: (String) -> Unit,
    onClearActionError: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var showAddTask by remember { mutableStateOf(false) }
    var showAddMember by remember { mutableStateOf(false) }

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
        floatingActionButton = {
            if (state.phase == CrmProjectDetailUiState.Phase.Content) {
                FloatingActionButton(
                    onClick = { showAddTask = true },
                    modifier = Modifier.testTag(CrmProjectsTestTags.TASK_FAB),
                ) { Icon(Icons.Filled.Add, contentDescription = "New task") }
            }
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
                    if (state.actionError != null) InfoBanner(state.actionError)
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

                    // ── Milestones summary ──────────────────────────────────────
                    MilestonesSection(state)

                    // ── Workload ────────────────────────────────────────────────
                    WorkloadSection(state)

                    // ── Tasks board ─────────────────────────────────────────────
                    Text("Tasks", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    if (state.tasks.isEmpty()) {
                        Text("No tasks. Tap + to add one.", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    } else {
                        state.tasks.forEachIndexed { index, task ->
                            TaskRow(
                                task = task,
                                index = index,
                                total = state.tasks.size,
                                busy = state.actionBusy,
                                onSetProgress = { pct -> onSetTaskProgress(task.id, pct) },
                                onToggleMilestone = { onToggleMilestone(task.id, !task.isMilestone) },
                                onDelete = { onDeleteTask(task.id) },
                                onMoveUp = { onMoveTaskUp(index) },
                                onMoveDown = { onMoveTaskDown(index) },
                            )
                        }
                    }

                    // ── Members ─────────────────────────────────────────────────
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text("Members", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                        TextButton(onClick = { showAddMember = true }) { Text("Add") }
                    }
                    if (state.members.isEmpty()) {
                        Text("No members yet.", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    } else {
                        state.members.forEach { member ->
                            MemberRow(
                                member = member,
                                busy = state.actionBusy,
                                onSetRole = { role -> onUpdateMemberRole(member.userSub, role) },
                                onRemove = { onRemoveMember(member.userSub) },
                            )
                        }
                    }
                }
            }
        }
    }

    if (showAddTask) {
        AddTaskSheet(
            busy = state.actionBusy,
            error = state.actionError,
            onDismiss = {
                showAddTask = false
                onClearActionError()
            },
            onSubmit = { name, isMilestone, assignee ->
                onCreateTask(name, isMilestone, assignee)
                showAddTask = false
            },
        )
    }

    if (showAddMember) {
        AddMemberSheet(
            busy = state.actionBusy,
            error = state.actionError,
            onDismiss = {
                showAddMember = false
                onClearActionError()
            },
            onSubmit = { userSub, role ->
                onAddMember(userSub, role)
                showAddMember = false
            },
        )
    }
}

@Composable
private fun MilestonesSection(state: CrmProjectDetailUiState) {
    // Prefer the server summary; fall back to a client-derived roll-up (degrade-on-404).
    val server = state.milestones
    val derived = ProjectMath.milestoneSummary(state.tasks, System.currentTimeMillis() / 1000)
    val total = server?.totalMilestones ?: derived.total
    if (total == 0) return
    val overdue = server?.overdueCount ?: derived.overdue
    val onTrack = server?.onTrackCount ?: derived.onTrack
    val noDate = server?.noDateCount ?: derived.noDate
    Text("Milestones", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
    Row(modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        AssistChip(onClick = {}, label = { Text("$total total") })
        AssistChip(onClick = {}, label = { Text("$onTrack on track") })
        AssistChip(onClick = {}, label = { Text("$overdue overdue") })
        if (noDate > 0) AssistChip(onClick = {}, label = { Text("$noDate no date") })
    }
}

@Composable
private fun WorkloadSection(state: CrmProjectDetailUiState) {
    // Prefer the server workload entries; fall back to a client-derived aggregation.
    val serverEntries = state.workload?.entries
    val rows = if (!serverEntries.isNullOrEmpty()) {
        serverEntries.map { Triple(it.assigneeKey, it.taskCount, it.overdueCount) }
    } else {
        ProjectMath.workload(state.tasks, System.currentTimeMillis() / 1000)
            .map { Triple(it.assigneeKey, it.taskCount, it.overdueCount) }
    }
    if (rows.isEmpty()) return
    Text("Workload", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
    rows.forEach { (key, count, overdue) ->
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(ProjectMath.assigneeLabel(key), style = MaterialTheme.typography.bodyMedium)
            Text(
                if (overdue > 0) "$count tasks · $overdue overdue" else "$count tasks",
                style = MaterialTheme.typography.bodySmall,
                color = if (overdue > 0) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun TaskRow(
    task: CrmProjectTask,
    index: Int,
    total: Int,
    busy: Boolean,
    onSetProgress: (Int) -> Unit,
    onToggleMilestone: () -> Unit,
    onDelete: () -> Unit,
    onMoveUp: () -> Unit,
    onMoveDown: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    (if (task.isMilestone) "◆ " else "") + task.name.ifBlank { "(untitled task)" },
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.Medium,
                    modifier = Modifier.weight(1f),
                )
                IconButton(onClick = onMoveUp, enabled = !busy && index > 0) {
                    Icon(Icons.Filled.KeyboardArrowUp, contentDescription = "Move up")
                }
                IconButton(onClick = onMoveDown, enabled = !busy && index < total - 1) {
                    Icon(Icons.Filled.KeyboardArrowDown, contentDescription = "Move down")
                }
                IconButton(onClick = onDelete, enabled = !busy) {
                    Icon(Icons.Filled.Delete, contentDescription = "Delete task")
                }
            }
            val pct = CrmPecMath.clampPercent(task.percentComplete)
            LinearProgressIndicator(progress = { pct / 100f }, modifier = Modifier.fillMaxWidth())
            Text("$pct% · ${CrmPecMath.dateRange(task.startDate, task.endDate)}", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Row(modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                listOf(0, 25, 50, 75, 100).forEach { p ->
                    FilterChip(selected = pct == p, enabled = !busy, onClick = { onSetProgress(p) }, label = { Text("$p%") })
                }
                FilterChip(
                    selected = task.isMilestone,
                    enabled = !busy,
                    onClick = onToggleMilestone,
                    label = { Text("Milestone") },
                )
            }
        }
    }
}

@Composable
private fun MemberRow(
    member: CrmProjectMember,
    busy: Boolean,
    onSetRole: (String) -> Unit,
    onRemove: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(member.userSub, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
                IconButton(onClick = onRemove, enabled = !busy) {
                    Icon(Icons.Filled.Delete, contentDescription = "Remove member")
                }
            }
            Row(modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                ProjectMath.MEMBER_ROLES.forEach { role ->
                    FilterChip(
                        selected = member.role == role,
                        enabled = !busy,
                        onClick = { if (member.role != role) onSetRole(role) },
                        label = { Text(ProjectMath.memberRoleLabel(role)) },
                    )
                }
            }
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

// ─── Create project sheet ─────────────────────────────────────────────────────

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

// ─── Add task sheet ───────────────────────────────────────────────────────────

@Composable
private fun AddTaskSheet(
    busy: Boolean,
    error: String?,
    onDismiss: () -> Unit,
    onSubmit: (name: String, isMilestone: Boolean, assignee: String?) -> Unit,
) {
    var name by remember { mutableStateOf("") }
    var assignee by remember { mutableStateOf("") }
    var isMilestone by remember { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        title = { Text("New task") },
        text = {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedTextField(name, { name = it }, label = { Text("Task name") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(assignee, { assignee = it }, label = { Text("Assignee sub (optional)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                FilterChip(selected = isMilestone, onClick = { isMilestone = !isMilestone }, label = { Text("Milestone") })
                if (error != null) {
                    Text(error, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                }
            }
        },
        confirmButton = {
            TextButton(enabled = !busy, onClick = { onSubmit(name, isMilestone, assignee) }) {
                if (busy) CircularProgressIndicator(modifier = Modifier.size(18.dp)) else Text("Add")
            }
        },
        dismissButton = { TextButton(enabled = !busy, onClick = onDismiss) { Text("Cancel") } },
    )
}

// ─── Add member sheet ─────────────────────────────────────────────────────────

@Composable
private fun AddMemberSheet(
    busy: Boolean,
    error: String?,
    onDismiss: () -> Unit,
    onSubmit: (userSub: String, role: String) -> Unit,
) {
    var userSub by remember { mutableStateOf("") }
    var role by remember { mutableStateOf(ProjectMath.ROLE_MEMBER) }

    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        title = { Text("Add member") },
        text = {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedTextField(userSub, { userSub = it }, label = { Text("User sub") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                Text("Role", style = MaterialTheme.typography.labelMedium)
                Row(
                    modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    ProjectMath.MEMBER_ROLES.forEach { rr ->
                        FilterChip(selected = rr == role, onClick = { role = rr }, label = { Text(ProjectMath.memberRoleLabel(rr)) })
                    }
                }
                if (error != null) {
                    Text(error, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                }
            }
        },
        confirmButton = {
            TextButton(enabled = !busy, onClick = { onSubmit(userSub, role) }) {
                if (busy) CircularProgressIndicator(modifier = Modifier.size(18.dp)) else Text("Add")
            }
        },
        dismissButton = { TextButton(enabled = !busy, onClick = onDismiss) { Text("Cancel") } },
    )
}

// ─── Templates sheet ──────────────────────────────────────────────────────────

@Composable
private fun TemplatesSheet(
    state: CrmProjectsUiState,
    onDismiss: () -> Unit,
    onInstantiate: (templateId: String, projectName: String) -> Unit,
    onDelete: (String) -> Unit,
) {
    var selected by remember { mutableStateOf<CrmProjectTemplate?>(null) }
    var projectName by remember { mutableStateOf("") }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Project templates") },
        text = {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                when {
                    state.templatesLoading -> CircularProgressIndicator(modifier = Modifier.size(24.dp))
                    state.templatesModuleDisabled -> Text("Templates are not enabled for this account.", style = MaterialTheme.typography.bodyMedium)
                    state.templates.isEmpty() -> Text("No templates yet.", style = MaterialTheme.typography.bodyMedium)
                    else -> state.templates.forEach { t ->
                        val isSel = selected?.id == t.id
                        Card(
                            modifier = Modifier.fillMaxWidth().clickable {
                                selected = if (isSel) null else t
                                if (!isSel && projectName.isBlank()) projectName = t.name
                            },
                        ) {
                            Column(modifier = Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically,
                                ) {
                                    Text(t.name.ifBlank { "(untitled)" }, style = MaterialTheme.typography.bodyLarge, fontWeight = if (isSel) FontWeight.Bold else FontWeight.Medium)
                                    IconButton(onClick = { onDelete(t.id) }, enabled = !state.templateActionBusy) {
                                        Icon(Icons.Filled.Delete, contentDescription = "Delete template")
                                    }
                                }
                                Text(ProjectMath.templateSummaryLabel(t), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                        }
                    }
                }
                if (selected != null) {
                    OutlinedTextField(projectName, { projectName = it }, label = { Text("New project name") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                }
                if (state.templateError != null) {
                    Text(state.templateError, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                }
            }
        },
        confirmButton = {
            val sel = selected
            TextButton(
                enabled = sel != null && !state.templateActionBusy && projectName.isNotBlank(),
                onClick = { if (sel != null) onInstantiate(sel.id, projectName) },
            ) {
                if (state.templateActionBusy) CircularProgressIndicator(modifier = Modifier.size(18.dp)) else Text("Create project")
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Close") } },
    )
}
