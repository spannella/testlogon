@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.testlogon.android.feature.agents.fleet.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material3.Button
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
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.feature.agents.fleet.data.WorkerTemplate

/** AGENTS-BASICS - stable testTags for the fleet dashboard. */
object FleetDashboardTestTags {
    const val SCREEN = "fleet_dashboard_screen"
    const val ERROR_RETRY = "fleet_error_retry"
    const val START_ALL = "fleet_start_all"
    const val STOP_ALL = "fleet_stop_all"
}

@Composable
fun FleetDashboardRoute(
    onBack: () -> Unit,
    onNavigateToLogin: () -> Unit,
    viewModel: FleetViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is FleetEffect.NavigateToLogin -> onNavigateToLogin()
            }
        }
    }
    FleetDashboardScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::onRetry,
        onStartAll = viewModel::startAll,
        onStopAll = viewModel::stopAll,
        onCreateFromTemplate = viewModel::createFromTemplate,
        onDeleteTemplate = viewModel::deleteTemplate,
    )
}

@Composable
fun FleetDashboardScreen(
    state: FleetUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onStartAll: () -> Unit,
    onStopAll: () -> Unit,
    onCreateFromTemplate: (String) -> Unit,
    onDeleteTemplate: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(FleetDashboardTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Fleet") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        val isRefreshing = (state as? FleetUiState.Content)?.isRefreshing == true
        PullToRefreshBox(
            isRefreshing = isRefreshing,
            onRefresh = onRefresh,
            modifier = Modifier.fillMaxSize().padding(padding),
        ) {
            when (state) {
                is FleetUiState.Loading -> LoadingState()
                is FleetUiState.Error ->
                    ErrorState(modifier = Modifier.testTag(FleetDashboardTestTags.ERROR_RETRY), message = state.message, onRetry = onRetry)
                is FleetUiState.Content ->
                    FleetContent(
                        state = state,
                        onStartAll = onStartAll,
                        onStopAll = onStopAll,
                        onCreateFromTemplate = onCreateFromTemplate,
                        onDeleteTemplate = onDeleteTemplate,
                    )
            }
        }
    }
}

@Composable
private fun FleetContent(
    state: FleetUiState.Content,
    onStartAll: () -> Unit,
    onStopAll: () -> Unit,
    onCreateFromTemplate: (String) -> Unit,
    onDeleteTemplate: (String) -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        FlowRow(horizontalArrangement = Arrangement.spacedBy(12.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            MetricTile("Workers", state.status.totalWorkers.toString())
            MetricTile("Queue depth", state.status.queueDepth.toString())
            state.status.statusCounts.forEach { (status, count) ->
                MetricTile(status, count.toString())
            }
        }

        state.actionMessage?.let {
            Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary)
        }
        state.actionError?.let {
            Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        }

        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            if (state.bulkBusy) {
                CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.padding(8.dp))
            } else {
                Button(onClick = onStartAll, modifier = Modifier.testTag(FleetDashboardTestTags.START_ALL)) { Text("Start all") }
                OutlinedButton(onClick = onStopAll, modifier = Modifier.testTag(FleetDashboardTestTags.STOP_ALL)) { Text("Stop all") }
            }
        }

        state.capacity?.let { cap ->
            if (cap.recommendedAction.isNotBlank()) {
                Card(Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text("Capacity", style = MaterialTheme.typography.titleSmall)
                        Text(cap.recommendedAction, style = MaterialTheme.typography.bodyMedium)
                    }
                }
            }
        }

        HorizontalDivider()
        Text("Active workers", style = MaterialTheme.typography.titleMedium)
        if (state.status.workers.isEmpty()) {
            Text("No active workers.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        } else {
            state.status.workers.forEach { w ->
                Card(Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(w.label.ifBlank { w.id }, style = MaterialTheme.typography.titleSmall)
                        Text(
                            listOf(w.agentType, w.status, w.agentState).filter { it.isNotBlank() }.joinToString(" · "),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        if (w.currentTicketTitle.isNotBlank()) {
                            Text("Ticket: ${w.currentTicketTitle}", style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }
        }

        HorizontalDivider()
        Text("Templates", style = MaterialTheme.typography.titleMedium)
        if (state.templates.isEmpty()) {
            Text("No worker templates.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        } else {
            state.templates.forEach { t ->
                TemplateRow(
                    template = t,
                    busy = state.busyTemplateId == t.id,
                    onCreate = { onCreateFromTemplate(t.id) },
                    onDelete = { onDeleteTemplate(t.id) },
                )
            }
        }
    }
}

@Composable
private fun MetricTile(label: String, value: String) {
    Card(modifier = Modifier.width(150.dp)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(value, style = MaterialTheme.typography.headlineSmall)
            Text(label, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, textAlign = TextAlign.Start)
        }
    }
}

@Composable
private fun TemplateRow(
    template: WorkerTemplate,
    busy: Boolean,
    onCreate: () -> Unit,
    onDelete: () -> Unit,
) {
    Card(Modifier.fillMaxWidth()) {
        Row(Modifier.fillMaxWidth().padding(12.dp), verticalAlignment = androidx.compose.ui.Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(template.label.ifBlank { template.id }, style = MaterialTheme.typography.titleSmall)
                Text(
                    listOf(template.agentType, template.tool, template.instanceType).filter { it.isNotBlank() }.joinToString(" · "),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (busy) {
                CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.padding(4.dp))
            } else {
                Button(onClick = onCreate) { Text("Create") }
                IconButton(onClick = onDelete) {
                    Icon(Icons.Outlined.Delete, contentDescription = "Delete template", tint = MaterialTheme.colorScheme.error)
                }
            }
        }
    }
}
