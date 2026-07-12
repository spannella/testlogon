@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.agents.workers.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.outlined.SmartToy
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState

/**
 * AGENTS-BASICS (web-parity) - the AGENT-TYPES dashboard/picker that feeds the B4 type-config screens.
 *
 * There is no dedicated agent-types registry endpoint (web or backend); the canonical way to source a runtime
 * typeId is the WORKERS list, whose items carry an `agent_type`. This screen lists the caller's workers grouped
 * by agent_type (one card per worker) - tapping a worker opens the B4 AgentConfigDest keyed by
 * (agentType -> canonical config type, workerId -> the runtime typeId), so the previously manual-only typeId
 * TextField on AgentConfigsRoute now has a real workers-backed source. Reuses WorkersListViewModel (same GET).
 */
object AgentTypesDashboardTestTags {
    const val SCREEN = "agent_types_dashboard_screen"
    const val EMPTY = "agent_types_empty"
    fun row(id: String) = "agent_types_row_$id"
}

/**
 * Maps a worker's agent_type to a valid B4 AgentConfigType.typeName (coder/qa/devops/architect/pm). The config
 * screens only exist for those five; worker types like "reviewer"/"custom" fall back to the nearest config type.
 */
private fun canonicalConfigType(agentType: String): String = when (agentType.lowercase()) {
    "coder", "qa", "devops", "architect", "pm" -> agentType.lowercase()
    "reviewer" -> "qa"
    else -> "coder"
}

@Composable
fun AgentTypesDashboardRoute(
    onBack: () -> Unit,
    onOpenConfig: (agentType: String, typeId: String) -> Unit,
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

    Scaffold(
        modifier = Modifier.testTag(AgentTypesDashboardTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Agent types") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        when (val s = state) {
            is WorkersListUiState.Loading -> LoadingState(modifier = Modifier.padding(padding))
            is WorkersListUiState.Error ->
                ErrorState(modifier = Modifier.padding(padding), message = s.message, onRetry = viewModel::onRetry)
            is WorkersListUiState.Empty ->
                EmptyState(
                    modifier = Modifier.padding(padding).testTag(AgentTypesDashboardTestTags.EMPTY),
                    title = "No agent types yet",
                    body = "Provision a worker to register an agent type, then tune its per-type config here.",
                    imageVector = Icons.Outlined.SmartToy,
                )
            is WorkersListUiState.Content ->
                LazyColumn(
                    modifier = Modifier.fillMaxSize().padding(padding),
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    item {
                        Text(
                            "Tap a worker to open its per-type agent config (coder / QA / DevOps / architect / PM).",
                            style = MaterialTheme.typography.bodyMedium,
                        )
                    }
                    items(items = s.items, key = { it.id }) { worker ->
                        Card(
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag(AgentTypesDashboardTestTags.row(worker.id))
                                .clickable {
                                    // agentType feeds the canonical config-type; the worker id is the runtime typeId.
                                    // Non-config worker types (reviewer/custom) fall back to a valid config type.
                                    onOpenConfig(canonicalConfigType(worker.agentType), worker.id)
                                },
                        ) {
                            ListItem(
                                headlineContent = { Text(worker.label.ifBlank { worker.id }) },
                                supportingContent = {
                                    Text(
                                        listOf(worker.agentType, worker.statusWire).filter { it.isNotBlank() }
                                            .joinToString(" · "),
                                    )
                                },
                                trailingContent = {
                                    Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null)
                                },
                            )
                        }
                    }
                }
        }
    }
}
