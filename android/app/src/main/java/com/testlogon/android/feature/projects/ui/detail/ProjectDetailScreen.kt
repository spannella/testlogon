@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.projects.ui.detail

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.projects.Project
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.OfflineBanner
import com.testlogon.android.feature.projects.provider.CustomTabsProjectDriveTabLauncher
import com.testlogon.android.feature.projects.provider.ProjectDriveTabLauncher
import com.testlogon.android.feature.projects.ui.relativeTimeIso

/** AND-374 - stable testTags for the project-detail screen. */
object ProjectDetailTestTags {
    const val SCREEN = "project_detail_screen"
    const val CONTENT = "project_detail_content"
    const val ERROR_RETRY = "project_detail_error_retry"
    const val CONNECT_DRIVE = "project_connect_drive"
    const val DRIVE_CONNECTED = "project_drive_connected"
    const val STALE_BANNER = "project_detail_stale_banner"
}

/**
 * AND-374 - route-level entry for the project detail (screen 2). Collects the state, wires the one-shot effects
 * (Custom Tab launch via the injected [ProjectDriveTabLauncher], snackbar messages, re-auth handoff). The Drive
 * return deep link is delivered to the ViewModel by the Activity (via the dispatcher) - the screen only LAUNCHES
 * the Custom Tab.
 */
@Composable
fun ProjectDetailRoute(
    onBack: () -> Unit,
    onNavigateToLogin: () -> Unit,
    viewModel: ProjectDetailViewModel = hiltViewModel(),
    launcher: ProjectDriveTabLauncher = CustomTabsProjectDriveTabLauncher(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val context = LocalContext.current
    val snackbarHostState = remember { SnackbarHostState() }
    val launchFailed = stringResource(R.string.project_connect_no_browser)

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is ProjectDetailEffect.LaunchAuth -> {
                    val ok = launcher.launch(context, effect.url)
                    if (!ok) {
                        viewModel.onConnectCanceled()
                        snackbarHostState.showSnackbar(launchFailed)
                    }
                }
                is ProjectDetailEffect.ShowMessage -> snackbarHostState.showSnackbar(effect.message)
                ProjectDetailEffect.NavigateToLogin -> onNavigateToLogin()
            }
        }
    }

    ProjectDetailScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onBack = onBack,
        onRetry = viewModel::retry,
        onConnectDrive = viewModel::connectGoogleDrive,
    )
}

/** AND-374 - stateless project detail (name / description / tags / timestamps + Drive connection state). */
@Composable
fun ProjectDetailScreen(
    state: ProjectDetailUiState,
    snackbarHostState: SnackbarHostState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onConnectDrive: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(ProjectDetailTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = {
                    val title = (state as? ProjectDetailUiState.Content)?.project?.name?.ifBlank { null }
                    Text(title ?: stringResource(R.string.project_detail_title))
                },
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
    ) { padding ->
        when (state) {
            ProjectDetailUiState.Loading -> LoadingState(modifier = Modifier.padding(padding))

            is ProjectDetailUiState.Error -> ErrorState(
                modifier = Modifier
                    .padding(padding)
                    .testTag(ProjectDetailTestTags.ERROR_RETRY),
                message = state.message,
                onRetry = onRetry,
            )

            is ProjectDetailUiState.Content -> ProjectDetailContent(
                content = state,
                onConnectDrive = onConnectDrive,
                modifier = Modifier.padding(padding),
            )
        }
    }
}

@Composable
private fun ProjectDetailContent(
    content: ProjectDetailUiState.Content,
    onConnectDrive: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val project = content.project
    val description = project.description
    Column(
        modifier = modifier
            .fillMaxSize()
            .testTag(ProjectDetailTestTags.CONTENT)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (content.isStale) {
            OfflineBanner(
                modifier = Modifier.testTag(ProjectDetailTestTags.STALE_BANNER),
                message = stringResource(R.string.projects_offline_banner),
            )
        }
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                text = project.name.ifBlank { stringResource(R.string.projects_untitled) },
                style = MaterialTheme.typography.headlineSmall,
            )
            if (!description.isNullOrBlank()) {
                Text(text = description, style = MaterialTheme.typography.bodyLarge)
            }
            if (project.tags.isNotEmpty()) {
                Text(
                    text = project.tags.joinToString(" · "),
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.primary,
                )
            }
            ProjectTimestamps(project)
            DriveConnectionSection(
                connected = content.driveConnected,
                connecting = content.connecting,
                onConnectDrive = onConnectDrive,
            )
        }
    }
}

@Composable
private fun ProjectTimestamps(project: Project) {
    val created = relativeTimeIso(project.createdAt)
    val updated = relativeTimeIso(project.updatedAt)
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        if (created.isNotBlank()) {
            Text(
                text = stringResource(R.string.projects_created, created),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
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

@Composable
private fun DriveConnectionSection(
    connected: Boolean,
    connecting: Boolean,
    onConnectDrive: () -> Unit,
) {
    if (connected) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 48.dp)
                .testTag(ProjectDetailTestTags.DRIVE_CONNECTED),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Icon(Icons.Filled.CheckCircle, contentDescription = null)
            Text(
                text = stringResource(R.string.project_drive_connected),
                style = MaterialTheme.typography.bodyLarge,
            )
        }
    } else {
        Button(
            onClick = onConnectDrive,
            enabled = !connecting,
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 48.dp)
                .testTag(ProjectDetailTestTags.CONNECT_DRIVE),
        ) {
            if (connecting) {
                CircularProgressIndicator(
                    modifier = Modifier.heightIn(min = 20.dp).padding(end = 8.dp),
                    strokeWidth = 2.dp,
                )
            }
            Text(stringResource(R.string.project_connect_drive))
        }
    }
}
