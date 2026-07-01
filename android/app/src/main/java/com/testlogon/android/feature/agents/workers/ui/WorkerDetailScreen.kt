@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.agents.workers.ui

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
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.feature.agents.workers.data.Worker

/** AGENTS-BASICS - stable testTags for the worker detail screen. */
object WorkerDetailTestTags {
    const val SCREEN = "worker_detail_screen"
    const val START = "worker_detail_start"
    const val STOP = "worker_detail_stop"
    const val TERMINATE = "worker_detail_terminate"
}

@Composable
fun WorkerDetailRoute(
    onBack: () -> Unit,
    onNavigateToLogin: () -> Unit,
    viewModel: WorkerDetailViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is WorkersEffect.NavigateToLogin -> onNavigateToLogin()
                is WorkersEffect.TerminateSucceeded -> onBack()
                else -> Unit
            }
        }
    }
    WorkerDetailScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::load,
        onStart = viewModel::start,
        onStop = viewModel::stop,
        onTerminate = viewModel::terminate,
    )
}

@Composable
fun WorkerDetailScreen(
    state: WorkerDetailUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onStart: () -> Unit,
    onStop: () -> Unit,
    onTerminate: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var confirmTerminate by remember { mutableStateOf(false) }
    Scaffold(
        modifier = modifier.testTag(WorkerDetailTestTags.SCREEN),
        topBar = {
            androidx.compose.material3.TopAppBar(
                title = { Text("Worker") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        when (state) {
            is WorkerDetailUiState.Loading -> LoadingState(modifier = Modifier.padding(padding))
            is WorkerDetailUiState.Error ->
                ErrorState(modifier = Modifier.padding(padding), message = state.message, onRetry = onRetry)
            is WorkerDetailUiState.Content ->
                WorkerDetailContent(
                    modifier = Modifier.padding(padding),
                    state = state,
                    onStart = onStart,
                    onStop = onStop,
                    onTerminate = { confirmTerminate = true },
                )
        }
    }

    if (confirmTerminate) {
        AlertDialog(
            onDismissRequest = { confirmTerminate = false },
            title = { Text("Terminate worker?") },
            text = { Text("This permanently destroys the worker instance. This cannot be undone.") },
            confirmButton = {
                TextButton(onClick = { confirmTerminate = false; onTerminate() }) { Text("Terminate") }
            },
            dismissButton = { TextButton(onClick = { confirmTerminate = false }) { Text("Cancel") } },
        )
    }
}

@Composable
private fun WorkerDetailContent(
    state: WorkerDetailUiState.Content,
    onStart: () -> Unit,
    onStop: () -> Unit,
    onTerminate: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val worker = state.worker
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(worker.label.ifBlank { worker.id }, style = MaterialTheme.typography.headlineSmall)
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Field("Status", worker.statusWire.ifBlank { "unknown" })
                Field("Agent type", worker.agentType)
                Field("Tool", listOf(worker.tool, worker.toolVersion).filter { it.isNotBlank() }.joinToString(" "))
                Field("Compute", listOf(worker.computeType, worker.instanceType).filter { it.isNotBlank() }.joinToString(" · "))
                if (worker.llmProvider.isNotBlank()) Field("LLM provider", worker.llmProvider)
                if (worker.publicIp.isNotBlank()) Field("Public IP", worker.publicIp)
                if (worker.repoUrl.isNotBlank()) Field("Repo", worker.repoUrl)
                if (worker.errorMessage.isNotBlank()) Field("Error", worker.errorMessage)
            }
        }

        if (state.actionError != null) {
            Text(state.actionError, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
        }

        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            if (state.actioning) {
                CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.padding(8.dp))
            } else {
                if (worker.canStart) {
                    Button(onClick = onStart, modifier = Modifier.testTag(WorkerDetailTestTags.START)) { Text("Start") }
                }
                if (worker.canStop) {
                    OutlinedButton(onClick = onStop, modifier = Modifier.testTag(WorkerDetailTestTags.STOP)) { Text("Stop") }
                }
                OutlinedButton(
                    onClick = onTerminate,
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error),
                    modifier = Modifier.testTag(WorkerDetailTestTags.TERMINATE),
                ) { Text("Terminate") }
            }
        }

        HorizontalDivider()
        Text("Provision log", style = MaterialTheme.typography.titleMedium)
        if (worker.provisionLog.isEmpty()) {
            Text("No provisioning steps recorded yet.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        } else {
            worker.provisionLog.forEach { step ->
                Card(Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text("${step.step} — ${step.status}", style = MaterialTheme.typography.labelLarge)
                        if (step.detail.isNotBlank()) {
                            Text(step.detail, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun Field(label: String, value: String) {
    if (value.isBlank()) return
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(label, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.weight(0.4f))
        Text(value, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(0.6f))
    }
}
