@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.agents.workers.ui

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
import androidx.compose.material.icons.outlined.PlayArrow
import androidx.compose.material.icons.outlined.SmartToy
import androidx.compose.material.icons.outlined.Stop
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.feature.agents.workers.data.Worker

/** AGENTS-BASICS - stable testTags for the workers list. */
object WorkersListTestTags {
    const val SCREEN = "workers_list_screen"
    const val EMPTY = "workers_empty"
    const val ERROR_RETRY = "workers_error_retry"
    const val CREATE_FAB = "workers_create_fab"
    fun row(id: String) = "worker_row_$id"
}

@Composable
fun WorkersListRoute(
    onBack: () -> Unit,
    onCreate: () -> Unit,
    onOpenWorker: (String) -> Unit,
    onNavigateToLogin: () -> Unit,
    viewModel: WorkersListViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is WorkersEffect.NavigateToLogin -> onNavigateToLogin()
                else -> Unit
            }
        }
    }
    WorkersListScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::onRetry,
        onCreate = onCreate,
        onOpenWorker = onOpenWorker,
        onStart = viewModel::start,
        onStop = viewModel::stop,
    )
}

@Composable
fun WorkersListScreen(
    state: WorkersListUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onCreate: () -> Unit,
    onOpenWorker: (String) -> Unit,
    onStart: (String) -> Unit,
    onStop: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(WorkersListTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Workers") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
        floatingActionButton = {
            if (state is WorkersListUiState.Content || state is WorkersListUiState.Empty) {
                FloatingActionButton(
                    onClick = onCreate,
                    modifier = Modifier.testTag(WorkersListTestTags.CREATE_FAB),
                ) {
                    Icon(Icons.Outlined.Add, contentDescription = "Create worker")
                }
            }
        },
    ) { padding ->
        val isRefreshing = (state as? WorkersListUiState.Content)?.isRefreshing == true
        PullToRefreshBox(
            isRefreshing = isRefreshing,
            onRefresh = onRefresh,
            modifier = Modifier.fillMaxSize().padding(padding),
        ) {
            when (state) {
                is WorkersListUiState.Loading -> LoadingState()
                is WorkersListUiState.Empty ->
                    EmptyState(
                        modifier = Modifier.testTag(WorkersListTestTags.EMPTY),
                        title = "No workers yet",
                        body = "Provision an agent worker to start running tickets.",
                        imageVector = Icons.Outlined.SmartToy,
                        actionLabel = "Create worker",
                        onAction = onCreate,
                    )
                is WorkersListUiState.Error ->
                    ErrorState(
                        modifier = Modifier.testTag(WorkersListTestTags.ERROR_RETRY),
                        message = state.message,
                        onRetry = onRetry,
                    )
                is WorkersListUiState.Content ->
                    Column(Modifier.fillMaxSize()) {
                        if (state.actionError != null) {
                            Text(
                                text = state.actionError,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.error,
                                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
                            )
                        }
                        LazyColumn(
                            modifier = Modifier.fillMaxSize(),
                            contentPadding = PaddingValues(16.dp),
                            verticalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            items(items = state.items, key = { it.id }) { worker ->
                                WorkerRow(
                                    worker = worker,
                                    acting = state.actioningId == worker.id,
                                    onOpen = { onOpenWorker(worker.id) },
                                    onStart = { onStart(worker.id) },
                                    onStop = { onStop(worker.id) },
                                )
                            }
                        }
                    }
            }
        }
    }
}

@Composable
private fun WorkerRow(
    worker: Worker,
    acting: Boolean,
    onOpen: () -> Unit,
    onStart: () -> Unit,
    onStop: () -> Unit,
) {
    Card(
        onClick = onOpen,
        modifier = Modifier.fillMaxWidth().testTag(WorkersListTestTags.row(worker.id)),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(
                    text = worker.label.ifBlank { worker.id },
                    style = MaterialTheme.typography.titleSmall,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = listOf(worker.agentType, worker.tool).filter { it.isNotBlank() }.joinToString(" · "),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                AssistChip(
                    onClick = onOpen,
                    label = { Text(worker.statusWire.ifBlank { "unknown" }) },
                )
            }
            when {
                acting -> CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(20.dp))
                worker.canStop -> IconButton(onClick = onStop) {
                    Icon(Icons.Outlined.Stop, contentDescription = "Stop", tint = MaterialTheme.colorScheme.error)
                }
                worker.canStart -> IconButton(onClick = onStart) {
                    Icon(Icons.Outlined.PlayArrow, contentDescription = "Start")
                }
            }
        }
    }
}
