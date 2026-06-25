@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.projects.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.outlined.Folder
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.foundation.layout.size
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.paging.LoadState
import androidx.paging.compose.LazyPagingItems
import androidx.paging.compose.collectAsLazyPagingItems
import kotlinx.coroutines.flow.collectLatest
import com.testlogon.android.R
import com.testlogon.android.core.model.projects.Project
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState

/** AND-374 - stable testTags for the projects-list screen + its rows. */
object ProjectsListTestTags {
    const val SCREEN = "projects_list_screen"
    const val EMPTY = "projects_empty"
    const val ERROR_RETRY = "projects_error_retry"
    const val CREATE_FAB = "projects_create_fab"
    const val CREATE_DIALOG = "project_create_dialog"
    const val CREATE_NAME = "project_create_name"
    const val CREATE_DESCRIPTION = "project_create_description"
    const val CREATE_TAGS = "project_create_tags"
    const val CREATE_SUBMIT = "project_create_submit"

    fun row(projectId: String) = "project_row_$projectId"
}

/**
 * AND-374 - route-level entry for the projects list (screen 1). Collects the paged projects and taps through to
 * a project's detail.
 */
@Composable
fun ProjectsListRoute(
    onBack: () -> Unit,
    onOpenProject: (String) -> Unit,
    viewModel: ProjectsListViewModel = hiltViewModel(),
) {
    val projects = viewModel.items.collectAsLazyPagingItems()
    val createState by viewModel.createState.collectAsStateWithLifecycle()
    LaunchedEffect(viewModel) {
        viewModel.refreshSignal.collectLatest { projects.refresh() }
    }
    LaunchedEffect(viewModel) {
        viewModel.created.collectLatest { id -> onOpenProject(id) }
    }
    ProjectsListScreen(
        projects = projects,
        createState = createState,
        onBack = onBack,
        onProjectClick = onOpenProject,
        onOpenCreate = viewModel::openCreate,
        onDismissCreate = viewModel::dismissCreate,
        onNameChange = viewModel::onNameChange,
        onDescriptionChange = viewModel::onDescriptionChange,
        onTagsChange = viewModel::onTagsChange,
        onSubmitCreate = viewModel::submitCreate,
    )
}

/** AND-374 - stateless projects list (name + description + tags + updated time). NO status / Drive chip. */
@Composable
fun ProjectsListScreen(
    projects: LazyPagingItems<Project>,
    onBack: () -> Unit,
    onProjectClick: (String) -> Unit,
    modifier: Modifier = Modifier,
    createState: CreateProjectFormState = CreateProjectFormState(),
    onOpenCreate: () -> Unit = {},
    onDismissCreate: () -> Unit = {},
    onNameChange: (String) -> Unit = {},
    onDescriptionChange: (String) -> Unit = {},
    onTagsChange: (String) -> Unit = {},
    onSubmitCreate: () -> Unit = {},
) {
    Scaffold(
        modifier = modifier.testTag(ProjectsListTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.projects_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.projects_back),
                        )
                    }
                },
            )
        },
        floatingActionButton = {
            FloatingActionButton(
                onClick = onOpenCreate,
                modifier = Modifier.testTag(ProjectsListTestTags.CREATE_FAB),
            ) {
                Icon(Icons.Filled.Add, contentDescription = stringResource(R.string.projects_create_title))
            }
        },
    ) { padding ->
        val refresh = projects.loadState.refresh
        PullToRefreshBox(
            isRefreshing = refresh is LoadState.Loading && projects.itemCount > 0,
            onRefresh = { projects.refresh() },
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            when {
                refresh is LoadState.Loading && projects.itemCount == 0 ->
                    LoadingState()

                refresh is LoadState.Error && projects.itemCount == 0 ->
                    ErrorState(
                        modifier = Modifier.testTag(ProjectsListTestTags.ERROR_RETRY),
                        message = stringResource(R.string.projects_error),
                        onRetry = { projects.retry() },
                    )

                projects.itemCount == 0 ->
                    EmptyState(
                        modifier = Modifier.testTag(ProjectsListTestTags.EMPTY),
                        title = stringResource(R.string.projects_empty),
                        body = stringResource(R.string.projects_empty_body),
                        imageVector = Icons.Outlined.Folder,
                    )

                else -> LazyColumn(modifier = Modifier.fillMaxSize()) {
                    items(
                        count = projects.itemCount,
                        key = { index -> projects[index]?.id ?: "project_$index" },
                    ) { index ->
                        val project = projects[index] ?: return@items
                        ProjectRow(project = project, onClick = { onProjectClick(project.id) })
                    }
                }
            }
        }

        if (createState.visible) {
            CreateProjectDialog(
                form = createState,
                onNameChange = onNameChange,
                onDescriptionChange = onDescriptionChange,
                onTagsChange = onTagsChange,
                onSubmit = onSubmitCreate,
                onDismiss = onDismissCreate,
            )
        }
    }
}

/** Batch-8 (#9) - the create-project dialog (name + optional description + comma-separated tags). */
@Composable
private fun CreateProjectDialog(
    form: CreateProjectFormState,
    onNameChange: (String) -> Unit,
    onDescriptionChange: (String) -> Unit,
    onTagsChange: (String) -> Unit,
    onSubmit: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        modifier = Modifier.testTag(ProjectsListTestTags.CREATE_DIALOG),
        onDismissRequest = { if (!form.submitting) onDismiss() },
        title = { Text(stringResource(R.string.projects_create_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedTextField(
                    value = form.name,
                    onValueChange = onNameChange,
                    singleLine = true,
                    isError = form.nameError != null,
                    label = { Text(stringResource(R.string.projects_create_name_label)) },
                    modifier = Modifier.fillMaxWidth().testTag(ProjectsListTestTags.CREATE_NAME),
                )
                OutlinedTextField(
                    value = form.description,
                    onValueChange = onDescriptionChange,
                    label = { Text(stringResource(R.string.projects_create_description_label)) },
                    modifier = Modifier.fillMaxWidth().testTag(ProjectsListTestTags.CREATE_DESCRIPTION),
                )
                OutlinedTextField(
                    value = form.tags,
                    onValueChange = onTagsChange,
                    singleLine = true,
                    label = { Text(stringResource(R.string.projects_create_tags_label)) },
                    modifier = Modifier.fillMaxWidth().testTag(ProjectsListTestTags.CREATE_TAGS),
                )
                val err = form.submitError
                if (err != null) {
                    Text(
                        text = err,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
        },
        confirmButton = {
            Button(
                onClick = onSubmit,
                enabled = form.isValid && !form.submitting,
                modifier = Modifier.testTag(ProjectsListTestTags.CREATE_SUBMIT),
            ) {
                if (form.submitting) {
                    CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                } else {
                    Text(stringResource(R.string.projects_create_submit))
                }
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss, enabled = !form.submitting) {
                Text(stringResource(R.string.projects_create_cancel))
            }
        },
    )
}

@Composable
private fun ProjectRow(
    project: Project,
    onClick: () -> Unit,
) {
    val updated = relativeTimeIso(project.updatedAt)
    val description = project.description
    val updatedLine = if (updated.isNotBlank()) {
        stringResource(R.string.projects_updated, updated)
    } else {
        ""
    }
    val rowDescription = buildString {
        append(project.name)
        if (!description.isNullOrBlank()) append(", $description")
        if (updatedLine.isNotBlank()) append(", $updatedLine")
    }
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .testTag(ProjectsListTestTags.row(project.id))
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp)
            .clearAndSetSemantics { contentDescription = rowDescription },
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Text(
            text = project.name.ifBlank { stringResource(R.string.projects_untitled) },
            style = MaterialTheme.typography.titleSmall,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
        )
        if (!description.isNullOrBlank()) {
            Text(
                text = description,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
        }
        if (project.tags.isNotEmpty()) {
            Text(
                text = project.tags.joinToString(" · "),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.primary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        if (updated.isNotBlank()) {
            Text(
                text = stringResource(R.string.projects_updated, updated),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
