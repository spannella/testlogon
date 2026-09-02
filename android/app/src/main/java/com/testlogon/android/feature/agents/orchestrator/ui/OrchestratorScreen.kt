@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.agents.orchestrator.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
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
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.feature.agents.orchestrator.data.AgentStatus
import com.testlogon.android.feature.agents.orchestrator.data.EligibleTicket
import com.testlogon.android.feature.agents.orchestrator.data.LoopAction

/** AGENT-ORCHESTRATOR - stable testTags for the orchestrator console. */
object OrchestratorTestTags {
    const val SCREEN = "orchestrator_screen"
    const val START = "orchestrator_start"
    const val PAUSE = "orchestrator_pause"
    const val RESUME = "orchestrator_resume"
    const val STOP = "orchestrator_stop"
    const val COMPLETE = "orchestrator_complete"
    const val RELEASE = "orchestrator_release"
    const val HEARTBEAT = "orchestrator_heartbeat"
}

@Composable
fun OrchestratorRoute(
    onBack: () -> Unit,
    onNavigateToLogin: () -> Unit,
    viewModel: OrchestratorViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is OrchestratorEffect.NavigateToLogin -> onNavigateToLogin()
            }
        }
    }
    OrchestratorScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::load,
        onStart = viewModel::start,
        onPause = viewModel::pause,
        onResume = viewModel::resume,
        onStop = viewModel::stop,
        onRelease = viewModel::release,
        onHeartbeat = viewModel::heartbeat,
        onComplete = { viewModel.complete(null, null) },
        onClaim = viewModel::claim,
        onReloadEligible = viewModel::loadEligible,
    )
}

@Composable
fun OrchestratorScreen(
    state: OrchestratorUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onStart: () -> Unit,
    onPause: () -> Unit,
    onResume: () -> Unit,
    onStop: () -> Unit,
    onRelease: () -> Unit,
    onHeartbeat: () -> Unit,
    onComplete: () -> Unit,
    onClaim: (String) -> Unit,
    onReloadEligible: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(OrchestratorTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Agent loop") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        when (state) {
            is OrchestratorUiState.Loading -> LoadingState(modifier = Modifier.padding(padding))
            is OrchestratorUiState.NoLoop ->
                EmptyState(
                    modifier = Modifier.padding(padding),
                    title = "No agent loop",
                    body = "This worker has no orchestrator record yet. Start the worker, then retry.",
                    actionLabel = "Retry",
                    onAction = onRetry,
                )
            is OrchestratorUiState.Error ->
                ErrorState(modifier = Modifier.padding(padding), message = state.message, onRetry = onRetry)
            is OrchestratorUiState.Content ->
                OrchestratorContent(
                    modifier = Modifier.padding(padding),
                    state = state,
                    onStart = onStart,
                    onPause = onPause,
                    onResume = onResume,
                    onStop = onStop,
                    onRelease = onRelease,
                    onHeartbeat = onHeartbeat,
                    onComplete = onComplete,
                    onClaim = onClaim,
                    onReloadEligible = onReloadEligible,
                )
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun OrchestratorContent(
    state: OrchestratorUiState.Content,
    onStart: () -> Unit,
    onPause: () -> Unit,
    onResume: () -> Unit,
    onStop: () -> Unit,
    onRelease: () -> Unit,
    onHeartbeat: () -> Unit,
    onComplete: () -> Unit,
    onClaim: (String) -> Unit,
    onReloadEligible: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val status = state.status
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(
            status.workerId.ifBlank { "Worker" },
            style = MaterialTheme.typography.headlineSmall,
        )
        Text(state.summary, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)

        StatusCard(status)

        state.notice?.let {
            Text(it, color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.bodySmall)
        }
        state.actionError?.let {
            Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
        }

        if (state.actioning != null) {
            CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.padding(8.dp))
        } else {
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (LoopAction.START in state.actions) {
                    Button(onClick = onStart, modifier = Modifier.testTag(OrchestratorTestTags.START)) { Text("Start") }
                }
                if (LoopAction.RESUME in state.actions) {
                    Button(onClick = onResume, modifier = Modifier.testTag(OrchestratorTestTags.RESUME)) { Text("Resume") }
                }
                if (LoopAction.PAUSE in state.actions) {
                    OutlinedButton(onClick = onPause, modifier = Modifier.testTag(OrchestratorTestTags.PAUSE)) { Text("Pause") }
                }
                if (LoopAction.STOP in state.actions) {
                    OutlinedButton(
                        onClick = onStop,
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error),
                        modifier = Modifier.testTag(OrchestratorTestTags.STOP),
                    ) { Text("Stop") }
                }
                if (LoopAction.HEARTBEAT in state.actions) {
                    TextButton(onClick = onHeartbeat, modifier = Modifier.testTag(OrchestratorTestTags.HEARTBEAT)) { Text("Heartbeat") }
                }
            }
        }

        HorizontalDivider()

        // ---- Active-ticket controls ----
        Text("Current ticket", style = MaterialTheme.typography.titleMedium)
        if (status.hasActiveTicket) {
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(status.currentTicketTitle.ifBlank { status.currentTicketId }, style = MaterialTheme.typography.bodyLarge)
                    if (status.currentTicketTitle.isNotBlank()) {
                        Text(status.currentTicketId, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
                    }
                    if (state.actioning == null) {
                        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            if (LoopAction.COMPLETE in state.actions) {
                                Button(onClick = onComplete, modifier = Modifier.testTag(OrchestratorTestTags.COMPLETE)) { Text("Complete") }
                            }
                            if (LoopAction.RELEASE in state.actions) {
                                OutlinedButton(onClick = onRelease, modifier = Modifier.testTag(OrchestratorTestTags.RELEASE)) { Text("Release") }
                            }
                        }
                    }
                }
            }
        } else {
            Text(
                "No ticket claimed. Pick one from the eligible queue below.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        HorizontalDivider()

        // ---- Eligible tickets ----
        Text("Eligible tickets", style = MaterialTheme.typography.titleMedium)
        when {
            state.eligibleLoading -> CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.padding(8.dp))
            state.eligible.isEmpty() ->
                Text(
                    "No eligible tickets right now.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            else -> state.eligible.forEach { ticket ->
                EligibleTicketRow(
                    ticket = ticket,
                    canClaim = LoopAction.CLAIM in state.actions && state.actioning == null,
                    onClaim = { onClaim(ticket.ticketId) },
                )
            }
        }
        TextButton(onClick = onReloadEligible) { Text("Refresh eligible") }
    }
}

@Composable
private fun StatusCard(status: AgentStatus) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Field("State", status.state.label)
            Field("Loop", if (status.loopRunning) "running" else "stopped")
            Field("Completed", status.ticketsCompleted.toString())
            Field("Failed", status.ticketsFailed.toString())
            if (!status.ticketFilter.isEmpty) {
                val f = status.ticketFilter
                val parts = buildList {
                    if (f.types.isNotEmpty()) add("types=${f.types.joinToString(",")}")
                    if (f.priorities.isNotEmpty()) add("prio=${f.priorities.joinToString(",")}")
                    if (f.tags.isNotEmpty()) add("tags=${f.tags.joinToString(",")}")
                }
                Field("Filter", parts.joinToString(" · "))
            }
        }
    }
}

@Composable
private fun EligibleTicketRow(
    ticket: EligibleTicket,
    canClaim: Boolean,
    onClaim: () -> Unit,
) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(ticket.title.ifBlank { ticket.ticketId }, style = MaterialTheme.typography.bodyLarge)
            val meta = listOf(ticket.type, ticket.priority).filter { it.isNotBlank() }.joinToString(" · ")
            if (meta.isNotBlank()) {
                Text(meta, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            if (canClaim) {
                Button(onClick = onClaim) { Text("Claim") }
            }
        }
    }
}

@Composable
private fun Field(label: String, value: String) {
    if (value.isBlank()) return
    androidx.compose.foundation.layout.Row(
        Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(label, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.weight(0.4f))
        Text(value, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(0.6f))
    }
}
