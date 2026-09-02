@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.workflow

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import java.time.ZoneId
import java.time.format.DateTimeFormatter

/** WFL — stable testTags for the run-history screen. */
object WorkflowRunsTestTags {
    const val SCREEN = "workflow_runs_screen"
    fun row(runId: String): String = "workflow_run_row_$runId"
}

@Composable
fun WorkflowRunsRoute(
    ruleId: String,
    onBack: () -> Unit,
    viewModel: WorkflowRunsViewModel = hiltViewModel(),
) {
    LaunchedEffect(ruleId) { viewModel.load(ruleId) }
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    WorkflowRunsScreen(state = state, onBack = onBack)
}

@Composable
fun WorkflowRunsScreen(state: WorkflowRunsUiState, onBack: () -> Unit) {
    Scaffold(
        modifier = Modifier.testTag(WorkflowRunsTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Run history") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Box(Modifier.padding(padding).fillMaxSize()) {
            when (state) {
                is WorkflowRunsUiState.Loading ->
                    CircularProgressIndicator(Modifier.align(Alignment.Center))

                is WorkflowRunsUiState.Unavailable ->
                    CenterText("Run history isn't available.")

                is WorkflowRunsUiState.Empty ->
                    CenterText("No runs recorded for this rule yet.")

                is WorkflowRunsUiState.Error ->
                    CenterText(state.error.message)

                is WorkflowRunsUiState.Content -> LazyColumn(
                    modifier = Modifier.fillMaxSize().padding(horizontal = 16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    items(state.runs, key = { it.runId }) { run -> RunRow(run) }
                }
            }
        }
    }
}

@Composable
private fun RunRow(run: WorkflowRun) {
    Card(modifier = Modifier.fillMaxWidth().testTag(WorkflowRunsTestTags.row(run.runId))) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(outcomeLabel(run.outcome), style = MaterialTheme.typography.titleMedium)
            Text(
                "${moduleLabel(run.targetModule)} • ${triggerLabel(run.triggerType)}",
                style = MaterialTheme.typography.bodyMedium,
            )
            run.startedAt?.let {
                Text(
                    "Started ${FORMATTER.format(it.atZone(ZoneId.systemDefault()))}",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            Text("${run.actionsFiredCount} actions fired", style = MaterialTheme.typography.bodySmall)
            run.errorMessage?.let {
                Text(
                    it,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
        }
    }
}

private val FORMATTER: DateTimeFormatter = DateTimeFormatter.ofPattern("MMM d, HH:mm")

private fun outcomeLabel(o: RunOutcome): String = when (o) {
    RunOutcome.MATCHED -> "Matched"
    RunOutcome.ERROR -> "Error"
    RunOutcome.SKIPPED -> "Skipped"
    RunOutcome.UNKNOWN -> "—"
}

@Composable
private fun androidx.compose.foundation.layout.BoxScope.CenterText(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.bodyMedium,
        modifier = Modifier.align(Alignment.Center).padding(24.dp),
    )
}
